import asyncio
import base64
import re
import shlex
import subprocess
import sys

import pytest

from proxmox_mcp.tools import lxc_console


class FakeWebSocket:
    def __init__(self, received: str = ""):
        self.received = received
        self.responses: list[str] = []
        self.sent: list[str] = []
        self.closed = False

    async def send(self, data: str) -> None:
        self.sent.append(data)

    async def recv(self) -> str:
        if self.responses:
            return self.responses.pop(0)
        return self.received

    async def close(self) -> None:
        self.closed = True


class FakeClient:
    token = "PVEAPIToken=test!token=value"

    async def post(self, path: str, data=None):
        return {
            "data": {
                "ticket": "ticket",
                "port": 5900,
            }
        }


class LoginWebSocket(FakeWebSocket):
    def __init__(self):
        super().__init__()
        self.responses = ["OK", "\x1b[H\x1b[J", "ioBrokerCT login: ", "Pass", "word: "]

    async def recv(self) -> str:
        if self.responses:
            return self.responses.pop(0)
        marker = re.search(r"__PVE_LXC_LOGIN_OK_[0-9a-f]+__", self.sent[-1])
        assert marker is not None
        return marker.group(0)


def session(ws: FakeWebSocket, session_id: str = "session-1") -> lxc_console.ConsoleSession:
    return lxc_console.ConsoleSession(
        session_id=session_id,
        node="pve01",
        vmid=100,
        username="root",
        websocket=ws,
        lock=asyncio.Lock(),
        last_used=asyncio.get_running_loop().time(),
    )


async def test_login_refuses_read_only(monkeypatch):
    monkeypatch.setattr(lxc_console, "PROXMOX_READ_ONLY", True)
    with pytest.raises(PermissionError, match="Read-only"):
        await lxc_console.login(FakeClient(), "pve01", 100, "root", "op://homelab/lxc/password")


async def test_secret_ref_must_be_one_password_reference(monkeypatch):
    with pytest.raises(ValueError, match="op://"):
        await lxc_console.login(FakeClient(), "pve01", 100, "root", "plaintext-password")


async def test_login_uses_node_websocket_and_api_auth(monkeypatch):
    monkeypatch.setattr(lxc_console, "PROXMOX_HOST", "pve.example")
    monkeypatch.setattr(lxc_console, "PROXMOX_PORT", "8006")
    ws = LoginWebSocket()
    captured = {}

    async def connect(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return ws

    monkeypatch.setattr(lxc_console.websockets, "connect", connect)
    client = FakeClient()

    result = await lxc_console._login_console(client, "pve01", 100, "root", "password")

    assert captured["url"] == (
        "wss://pve.example:8006/api2/json/nodes/pve01/lxc/100/"
        "vncwebsocket?port=5900&vncticket=ticket"
    )
    assert captured["additional_headers"] == {"Authorization": client.token}
    assert captured["subprotocols"] == ["binary"]
    assert ws.sent[:5] == [
        "test!token:ticket\n",
        "1:80:24:",
        "0:1:\n",
        "0:5:root\n",
        "0:9:password\n",
    ]
    assert result is ws
    await ws.close()


async def test_terminal_input_uses_utf8_byte_length():
    ws = FakeWebSocket()

    await lxc_console._send_terminal_input(ws, "pä\n")

    assert ws.sent == ["0:4:pä\n"]


async def test_read_file_reads_telegraf_config_with_guest_script(monkeypatch, tmp_path):
    ws = FakeWebSocket()
    current = session(ws, "read-file-session")
    monkeypatch.setitem(lxc_console.sessions, current.session_id, current)
    content = b'[agent]\ninterval = "10s"\n'
    config_path = tmp_path / "telegraf.conf"
    config_path.write_bytes(content)
    captured = {}

    async def run_marked(_session, command):
        captured["command"] = command
        argv = shlex.split(command)
        completed = subprocess.run(
            [sys.executable, "-c", argv[2], *argv[3:]],
            capture_output=True,
            check=False,
            text=True,
        )
        return completed.stdout, completed.returncode

    monkeypatch.setattr(lxc_console, "_run_marked", run_marked)

    result = await lxc_console.read_file(current.session_id, str(config_path))

    argv = shlex.split(captured["command"])
    assert argv[:2] == ["python3", "-c"]
    compile(argv[2], "<lxc-read-file>", "exec")
    assert argv[3:] == [str(config_path), "0", "1048576"]
    assert result["encoding"] == "base64"
    assert base64.b64decode(result["data"]) == content


async def test_list_directory_builds_valid_python(monkeypatch):
    ws = FakeWebSocket()
    current = session(ws, "list-directory-session")
    monkeypatch.setitem(lxc_console.sessions, current.session_id, current)
    captured = {}

    async def run_marked(_session, command):
        captured["command"] = command
        return '{"entries":[],"truncated":false}', 0

    monkeypatch.setattr(lxc_console, "_run_marked", run_marked)

    await lxc_console.list_directory(current.session_id, "/etc/telegraf")

    argv = shlex.split(captured["command"])
    assert argv[:2] == ["python3", "-c"]
    compile(argv[2], "<lxc-list-directory>", "exec")
    assert argv[3:] == ["/etc/telegraf", "1000"]


async def test_exec_is_disabled_by_default(monkeypatch):
    monkeypatch.setattr(lxc_console, "EXEC_ENABLED", False)
    ws = FakeWebSocket()
    current = session(ws, "exec-session")
    lxc_console.sessions[current.session_id] = current
    with pytest.raises(PermissionError, match="disabled"):
        await lxc_console.console_exec("exec-session", "id")


async def test_logout_returns_confirmed_status():
    ws = FakeWebSocket("Debian login:")
    current = session(ws)
    lxc_console.sessions[current.session_id] = current

    result = await lxc_console.logout(current.session_id)

    assert result["status"] == "logged_out"
    assert result["login_prompt_confirmed"] is True
    assert ws.closed is True


async def test_marked_output_parses_exit_code(monkeypatch):
    ws = FakeWebSocket()
    current = session(ws)
    original_send = ws.send

    async def send(data: str) -> None:
        await original_send(data)
        start = re.search(r"__PVE_LXC_START_[0-9a-f]+__", data)
        end = re.search(r"__PVE_LXC_END_[0-9a-f]+__", data)
        if start and end:
            ws.responses = [
                f"{data}\r\r\n",
                f"\n{start.group(0)}\nhello\n{end.group(0)}7",
                "\n",
            ]

    monkeypatch.setattr(ws, "send", send)

    output, code = await lxc_console._run_marked(current, "printf hello")
    assert output == "hello"
    assert code == 7
