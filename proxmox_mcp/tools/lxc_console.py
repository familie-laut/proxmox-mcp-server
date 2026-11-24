"""Logged-in LXC console sessions over the Proxmox terminal proxy."""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from ..client import (
    PROXMOX_HOST,
    PROXMOX_PORT,
    PROXMOX_READ_ONLY,
    PROXMOX_USER,
    ProxmoxClient,
    tls_verify,
)

try:
    import websockets
except ImportError:  # pragma: no cover - dependency is declared for normal installs
    websockets = None


EXEC_ENABLED = os.getenv("PROXMOX_LXC_EXEC", "false").lower() == "true"
SESSION_TIMEOUT = max(30, int(os.getenv("PROXMOX_LXC_SESSION_TIMEOUT", "900")))
OPERATION_TIMEOUT = max(5, int(os.getenv("PROXMOX_LXC_OPERATION_TIMEOUT", "30")))
MAX_OUTPUT = max(1024, int(os.getenv("PROXMOX_LXC_MAX_OUTPUT", "65536")))
MAX_FILE_LENGTH = max(1024, int(os.getenv("PROXMOX_LXC_MAX_FILE_LENGTH", "1048576")))


TOOLS = [
    {
        "name": "lxc_console_login",
        "description": "Log in to a running LXC console with an explicitly selected guest user.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "node": {"type": "string", "description": "Node name (e.g. pve01)"},
                "vmid": {"type": "integer", "description": "Container ID"},
                "username": {"type": "string", "description": "Guest username"},
                "secret_ref": {
                    "type": "string",
                    "description": "Local 1Password secret reference (e.g. op://homelab/lxc/password)",
                },
            },
            "required": ["node", "vmid", "username", "secret_ref"],
        },
    },
    {
        "name": "lxc_console_logout",
        "description": "Log out of an LXC console and close its session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Opaque console session ID"},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "lxc_list_directory",
        "description": "List a directory in an authenticated LXC console session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Opaque console session ID"},
                "path": {"type": "string", "description": "Absolute directory path"},
                "limit": {"type": "integer", "description": "Maximum entries (default 1000)"},
            },
            "required": ["session_id", "path"],
        },
    },
    {
        "name": "lxc_read_file",
        "description": "Read a bounded range from a file in an authenticated LXC console session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Opaque console session ID"},
                "path": {"type": "string", "description": "Absolute file path"},
                "offset": {"type": "integer", "description": "Byte offset (default 0)"},
                "length": {"type": "integer", "description": "Maximum bytes to read"},
            },
            "required": ["session_id", "path"],
        },
    },
    {
        "name": "lxc_console_exec",
        "description": "Run a bash command in an authenticated LXC console session (write-enabled).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Opaque console session ID"},
                "command": {"type": "string", "description": "Bash command to execute"},
            },
            "required": ["session_id", "command"],
        },
    },
]


def _normalize_terminal(data: str) -> str:
    return data.replace("\r\r\n", "\n").replace("\r\n", "\n").replace("\r", "\n")


@dataclass
class ConsoleSession:
    session_id: str
    node: str
    vmid: int
    username: str
    websocket: Any
    lock: asyncio.Lock
    last_used: float


sessions: dict[str, ConsoleSession] = {}
_sessions_lock = asyncio.Lock()


def _resolve_secret(ref: str) -> str:
    if not ref.startswith("op://"):
        raise ValueError("secret_ref must be a local 1Password reference starting with op://")
    op = shutil.which("op")
    if not op:
        raise ValueError("1Password CLI 'op' is not available to the MCP process")
    try:
        result = subprocess.run(
            [op, "read", "--no-newline", ref],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise ValueError("Timed out resolving the 1Password secret reference") from e
    if result.returncode != 0:
        raise ValueError("The 1Password secret is unavailable or the CLI is locked")
    if not result.stdout:
        raise ValueError("The 1Password secret reference resolved to an empty password")
    return result.stdout


async def _recv_until_any(
    websocket: Any,
    markers: tuple[str, ...],
    timeout: float,
    initial: str = "",
    wait_description: str = "the LXC console",
    reject_shell_prompt: bool = False,
) -> str:
    chunks = [initial] if initial else []
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        combined = "".join(chunks)
        lower = combined.lower()
        if any(marker.lower() in lower for marker in markers):
            return combined
        if reject_shell_prompt and _has_shell_prompt(combined):
            raise RuntimeError("The LXC console is already in a shell or another login is active")
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise TimeoutError(
                f"Timed out waiting for {wait_description} after receiving "
                f"{len(combined.encode('utf-8'))} bytes"
            )
        try:
            data = await asyncio.wait_for(websocket.recv(), timeout=remaining)
        except asyncio.TimeoutError as e:
            raise TimeoutError(
                f"Timed out waiting for {wait_description} after receiving "
                f"{len(combined.encode('utf-8'))} bytes"
            ) from e
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")
        chunks.append(_normalize_terminal(data))


async def _recv_until(websocket: Any, marker: str, timeout: float) -> str:
    return await _recv_until_any(websocket, (marker,), timeout)


async def _recv_until_command_end(
    websocket: Any,
    start: str,
    end: str,
    timeout: float,
) -> str:
    chunks: list[str] = []
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        combined = "".join(chunks)
        start_pos = combined.rfind(start)
        if start_pos >= 0:
            output = combined[start_pos + len(start) :]
            end_pos = output.rfind(end)
            if end_pos >= 0 and re.match(r"\d+\n", output[end_pos + len(end) :]):
                return combined

        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise TimeoutError("Timed out waiting for the LXC command to finish")
        try:
            data = await asyncio.wait_for(websocket.recv(), timeout=remaining)
        except asyncio.TimeoutError as e:
            raise TimeoutError("Timed out waiting for the LXC command to finish") from e
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")
        chunks.append(_normalize_terminal(data))


async def _recv_prompt(websocket: Any, timeout: float) -> str:
    return await _recv_until(websocket, "\n", timeout)


async def _send_terminal_input(websocket: Any, data: str) -> None:
    await websocket.send(f"0:{len(data.encode('utf-8'))}:{data}")


def _has_shell_prompt(output: str) -> bool:
    visible = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output).replace("\r", "")
    lines = visible.splitlines()
    return bool(lines and re.search(r"[#$]\s*$", lines[-1]))


def _websocket_headers(client: ProxmoxClient) -> dict[str, str]:
    if client.token:
        return {"Authorization": client.token}
    if client.ticket:
        return {"Cookie": f"PVEAuthCookie={client.ticket}"}
    return {}


def _terminal_auth_id(client: ProxmoxClient) -> str:
    if client.token:
        token = client.token.removeprefix("PVEAPIToken=")
        auth_id, separator, _ = token.partition("=")
        if separator and auth_id:
            return auth_id
        raise RuntimeError("Proxmox API token is malformed")
    if client.ticket:
        return PROXMOX_USER
    raise RuntimeError("Proxmox client is not authenticated")


async def _login_console(
    client: ProxmoxClient,
    node: str,
    vmid: int,
    username: str,
    password: str,
) -> Any:
    if websockets is None:
        raise RuntimeError("The Python 'websockets' package is not installed")
    data = await client.post(f"/nodes/{node}/lxc/{vmid}/termproxy")
    proxy = data.get("data") if isinstance(data, dict) else data
    if not isinstance(proxy, dict) or "ticket" not in proxy or "port" not in proxy:
        raise RuntimeError("Proxmox did not return a usable LXC terminal proxy")

    ticket = str(proxy["ticket"])
    port = int(proxy["port"])
    url = (
        f"wss://{PROXMOX_HOST}:{PROXMOX_PORT}/api2/json/nodes/{node}/lxc/{vmid}"
        f"/vncwebsocket?port={port}&vncticket={quote(ticket, safe='')}"
    )
    ws = await asyncio.wait_for(
        websockets.connect(
            url,
            additional_headers=_websocket_headers(client),
            subprotocols=["binary"],
            ssl=tls_verify(),
            open_timeout=OPERATION_TIMEOUT,
            ping_interval=20,
            ping_timeout=10,
        ),
        timeout=OPERATION_TIMEOUT,
    )
    try:
        await ws.send(f"{_terminal_auth_id(client)}:{ticket}\n")
        try:
            initial = await asyncio.wait_for(ws.recv(), timeout=OPERATION_TIMEOUT)
        except asyncio.TimeoutError as e:
            raise TimeoutError("Timed out waiting for Proxmox terminal handshake") from e
        if isinstance(initial, bytes):
            initial = initial.decode("utf-8", errors="replace")
        initial = _normalize_terminal(initial)
        if not initial.startswith("OK"):
            raise RuntimeError("Proxmox rejected the LXC terminal ticket")

        await ws.send("1:80:24:")
        terminal_output = initial[2:]
        if not any(marker in terminal_output.lower() for marker in ("login:", "username:")):
            try:
                first_output = await asyncio.wait_for(
                    ws.recv(),
                    timeout=min(2, OPERATION_TIMEOUT),
                )
            except asyncio.TimeoutError:
                first_output = ""
            if isinstance(first_output, bytes):
                first_output = first_output.decode("utf-8", errors="replace")
            terminal_output += _normalize_terminal(first_output)
        if not any(
            marker in terminal_output.lower() for marker in ("login:", "username:")
        ) and not _has_shell_prompt(terminal_output):
            await _send_terminal_input(ws, "\n")
        initial = await _recv_until_any(
            ws,
            ("login:", "username:"),
            OPERATION_TIMEOUT,
            terminal_output,
            "guest login prompt",
            reject_shell_prompt=True,
        )
        await _send_terminal_input(ws, f"{username}\n")
        try:
            await _recv_until_any(
                ws, ("password:",), OPERATION_TIMEOUT, wait_description="guest password prompt"
            )
        except TimeoutError as e:
            raise RuntimeError("The LXC console did not present a password prompt") from e

        await _send_terminal_input(ws, f"{password}\n")
        marker = f"__PVE_LXC_LOGIN_OK_{secrets.token_hex(12)}__"
        await _send_terminal_input(ws, f"printf '\\n{marker}\\n'\n")
        response = await _recv_until(ws, marker, OPERATION_TIMEOUT)
        if "login incorrect" in response.lower() or "authentication failure" in response.lower():
            raise RuntimeError("Guest login failed: invalid username or password")
        if marker not in response:
            raise RuntimeError("Guest login could not be confirmed")
        return ws
    except Exception:
        await ws.close()
        raise


async def _run_marked(session: ConsoleSession, command: str) -> tuple[str, int]:
    start = f"__PVE_LXC_START_{secrets.token_hex(12)}__"
    end = f"__PVE_LXC_END_{secrets.token_hex(12)}__"
    wrapped = f"printf '\\n{start}\\n'; {command}; rc=$?; printf '\\n{end}%s\\n' \"$rc\""
    async with session.lock:
        session.last_used = asyncio.get_running_loop().time()
        await _send_terminal_input(session.websocket, wrapped + "\n")
        response = await _recv_until_command_end(
            session.websocket,
            start,
            end,
            OPERATION_TIMEOUT,
        )

    response = _normalize_terminal(response)
    marker_pos = response.rfind(start)
    if marker_pos < 0:
        raise RuntimeError("The command output marker was incomplete")
    output = response[marker_pos + len(start) :]
    end_pos = output.rfind(end)
    if end_pos < 0:
        raise RuntimeError("The command end marker was incomplete")
    tail = output[end_pos + len(end) :].lstrip()
    output = output[:end_pos].replace("\n\n", "\n").strip("\n")
    exit_text = tail.splitlines()[0].strip() if tail else ""
    try:
        exit_code = int(exit_text)
    except ValueError as e:
        raise RuntimeError("The command exit code was incomplete") from e
    if len(output.encode("utf-8")) > MAX_OUTPUT:
        output = output.encode("utf-8")[:MAX_OUTPUT].decode("utf-8", errors="replace")
        output += "\n[output truncated]"
    return output, exit_code


async def _get_session(session_id: str) -> ConsoleSession:
    session = sessions.get(session_id)
    if not session:
        raise ValueError("Unknown or expired LXC console session")
    if asyncio.get_running_loop().time() - session.last_used > SESSION_TIMEOUT:
        sessions.pop(session_id, None)
        await session.websocket.close()
        raise TimeoutError("LXC console session expired")
    return session


async def login(
    client: ProxmoxClient,
    node: str,
    vmid: int,
    username: str,
    secret_ref: str,
) -> dict[str, Any]:
    if PROXMOX_READ_ONLY:
        raise PermissionError("Read-only mode blocks LXC console login")
    async with _sessions_lock:
        if any(s.node == node and s.vmid == vmid for s in sessions.values()):
            raise RuntimeError("An LXC console session is already active for this container")
    password = await asyncio.to_thread(_resolve_secret, secret_ref)
    try:
        websocket = await _login_console(client, node, vmid, username, password)
    finally:
        password = ""
    session_id = secrets.token_urlsafe(32)
    session = ConsoleSession(
        session_id=session_id,
        node=node,
        vmid=vmid,
        username=username,
        websocket=websocket,
        lock=asyncio.Lock(),
        last_used=asyncio.get_running_loop().time(),
    )
    async with _sessions_lock:
        sessions[session_id] = session
    return {
        "session_id": session_id,
        "node": node,
        "vmid": vmid,
        "username": username,
        "status": "logged_in",
    }


async def logout(session_id: str) -> dict[str, Any]:
    session = sessions.pop(session_id, None)
    if not session:
        raise ValueError("Unknown or expired LXC console session")
    confirmed = False
    try:
        await _send_terminal_input(session.websocket, "exit\n")
        response = await _recv_until(session.websocket, "login:", OPERATION_TIMEOUT)
        confirmed = "login:" in response.lower()
    except Exception:
        confirmed = False
    finally:
        await session.websocket.close()
    return {
        "session_id": session_id,
        "status": "logged_out" if confirmed else "closed_unconfirmed",
        "login_prompt_confirmed": confirmed,
    }


async def close_all() -> None:
    session_ids = list(sessions)
    for session_id in session_ids:
        try:
            await logout(session_id)
        except Exception:
            session = sessions.pop(session_id, None)
            if session:
                await session.websocket.close()


async def list_directory(session_id: str, path: str, limit: int = 1000) -> dict[str, Any]:
    session = await _get_session(session_id)
    limit = min(max(1, limit), 1000)
    script = (
        "import json, os, sys\n"
        "p=sys.argv[1]\n"
        "try:\n"
        " e=sorted(os.scandir(p), key=lambda x:x.name)\n"
        " print(json.dumps({'entries':[{'name':x.name,'type':'directory' if x.is_dir(follow_symlinks=False) else 'file'} for x in e[:int(sys.argv[2])]], 'truncated':len(e)>int(sys.argv[2])}))\n"
        "except Exception as ex:\n"
        " print(json.dumps({'error':type(ex).__name__+': '+str(ex)}))"
    )
    command = f"python3 -c {shlex.quote(script)} {shlex.quote(path)} {limit}"
    output, exit_code = await _run_marked(session, command)
    if exit_code != 0:
        raise RuntimeError(f"Directory operation failed with exit code {exit_code}")
    import json

    try:
        return json.loads(output)
    except json.JSONDecodeError as e:
        raise RuntimeError("The guest returned an invalid directory listing") from e


async def read_file(
    session_id: str, path: str, offset: int = 0, length: int | None = None
) -> dict[str, Any]:
    session = await _get_session(session_id)
    offset = max(0, offset)
    length = min(MAX_FILE_LENGTH, max(1, length or MAX_FILE_LENGTH))
    script = (
        "import base64, json, os, sys\n"
        "p=sys.argv[1]; o=int(sys.argv[2]); n=int(sys.argv[3])\n"
        "try:\n"
        " f=open(p,'rb'); f.seek(o); b=f.read(n+1); f.close(); "
        " more=len(b)>n; b=b[:n]; "
        " print(json.dumps({'base64':base64.b64encode(b).decode('ascii'),'offset':o,'length':len(b),'has_more':more}))\n"
        "except Exception as ex:\n"
        " print(json.dumps({'error':type(ex).__name__+': '+str(ex)}))"
    )
    command = f"python3 -c {shlex.quote(script)} {shlex.quote(path)} {offset} {length}"
    output, exit_code = await _run_marked(session, command)
    if exit_code != 0:
        raise RuntimeError(f"File operation failed with exit code {exit_code}")
    import json

    try:
        result = json.loads(output)
    except json.JSONDecodeError as e:
        raise RuntimeError("The guest returned an invalid file response") from e
    if "error" in result:
        raise RuntimeError(result["error"])
    result["encoding"] = "base64"
    result["data"] = result.pop("base64")
    return result


async def console_exec(session_id: str, command: str) -> dict[str, Any]:
    session = await _get_session(session_id)
    if not EXEC_ENABLED:
        raise PermissionError("LXC console exec is disabled; set PROXMOX_LXC_EXEC=true")
    if not command.strip():
        raise ValueError("command must not be empty")
    output, exit_code = await _run_marked(session, f"bash -lc {shlex.quote(command)}")
    return {"output": output, "exit_code": exit_code}


async def handle(name: str, args: dict[str, Any], client: ProxmoxClient) -> Any:
    if name == "lxc_console_login":
        return await login(
            client,
            str(args["node"]),
            int(args["vmid"]),
            str(args["username"]),
            str(args["secret_ref"]),
        )
    if name == "lxc_console_logout":
        return await logout(str(args["session_id"]))
    if name == "lxc_list_directory":
        return await list_directory(
            str(args["session_id"]),
            str(args["path"]),
            int(args.get("limit", 1000)),
        )
    if name == "lxc_read_file":
        return await read_file(
            str(args["session_id"]),
            str(args["path"]),
            int(args.get("offset", 0)),
            int(args["length"]) if "length" in args else None,
        )
    if name == "lxc_console_exec":
        return await console_exec(str(args["session_id"]), str(args["command"]))
    raise ValueError(f"Unknown LXC console tool: {name}")
