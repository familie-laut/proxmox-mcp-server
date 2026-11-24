import asyncio
import re

import pytest

from proxmox_mcp.tools import lxc_console


class FakeWebSocket:
    def __init__(self, received: str = ""):
        self.received = received
        self.sent: list[str] = []
        self.closed = False

    async def send(self, data: str) -> None:
        self.sent.append(data)

    async def recv(self) -> str:
        return self.received

    async def close(self) -> None:
        self.closed = True


class FakeClient:
    async def post(self, path: str, data=None):
        return {
            "ticket": "ticket",
            "port": 5900,
        }


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
            ws.received = f"\n{start.group(0)}\nhello\n{end.group(0)}7\n"

    monkeypatch.setattr(ws, "send", send)

    # Use a controlled response through the real receive path.
    ws.received = "\n__PVE_LXC_START_test__\nhello\n__PVE_LXC_END_test__7\n"
    output, code = await lxc_console._run_marked(current, "printf hello")
    assert output == "hello"
    assert code == 7
