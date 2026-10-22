"""Check SDK input privacy through the installed console entry point and stdio."""

import asyncio
import os
import sys
from datetime import timedelta

import anyio
import pytest
from mcp import ClientSession, McpError, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.shared.message import SessionMessage

# Keep the installed entry point isolated from cwd, user imports and providers.
# Windows event-loop wakeup sockets still need local IPC, as in test_protocol.py.
GUARDED_ENTRY_POINT = """
import socket
from importlib.metadata import distribution

def forbid_connection(*args, **kwargs):
    raise AssertionError("Network access is forbidden in protocol tests")

original_connect = socket.socket.connect
original_connect_ex = socket.socket.connect_ex

def allow_local_ipc(original):
    def connect(sock, address):
        if isinstance(address, tuple) and address[0] in {"127.0.0.1", "::1"}:
            return original(sock, address)
        return forbid_connection()
    return connect

socket.create_connection = forbid_connection
socket.socket.connect = allow_local_ipc(original_connect)
socket.socket.connect_ex = allow_local_ipc(original_connect_ex)
entry = next(
    item for item in distribution("mcp-maintainer-tools").entry_points
    if item.group == "console_scripts" and item.name == "mcp-maintainer-tools"
)
entry.load()()
"""

EXPECTED_TOOLS = {
    "osv_query",
    "osv_batch",
    "osv_vuln",
    "nvd_cve",
    "kev_check",
    "epss",
    "depsdev_package",
}


@pytest.mark.parametrize("kind,diagnostic", [("prompt", "prompt"), ("response", "unrecognized")])
def test_installed_stdio_omits_private_protocol_values(kind, diagnostic, tmp_path, caplog):
    # A short synthetic value stays intact even in the default Rich log columns.
    marker = f"private-{kind}-wire-7"
    stderr_path = tmp_path / "stderr.txt"
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-I", "-c", GUARDED_ENTRY_POINT],
        cwd=tmp_path,
        env={
            "PYTHONNOUSERSITE": "1",
            # Preserve only the subprocess coverage settings used by CI.
            **{
                key: os.environ[key]
                for key in ("COVERAGE_PROCESS_CONFIG", "COVERAGE_PROCESS_START")
                if key in os.environ
            },
        },
    )

    async def exercise():
        with anyio.fail_after(20), stderr_path.open("w", encoding="utf-8") as stderr:
            async with stdio_client(parameters, errlog=stderr) as (read, write):
                async with ClientSession(
                    read, write, read_timeout_seconds=timedelta(seconds=5)
                ) as session:
                    initialized = await session.initialize()
                    assert initialized.serverInfo.name == "mcp-maintainer-tools"
                    if kind == "prompt":
                        # The same caller still receives the original SDK error.
                        with pytest.raises(McpError, match=f"Unknown prompt: {marker}"):
                            await session.get_prompt(marker)
                    else:
                        # Reach the warning without any outstanding server request.
                        await write.send(
                            SessionMessage(
                                message=types.JSONRPCMessage(
                                    types.JSONRPCResponse(jsonrpc="2.0", id=marker, result={})
                                )
                            )
                        )
                    await session.send_ping()
                    listed = await session.list_tools()
                    assert {tool.name for tool in listed.tools} == EXPECTED_TOOLS
                    assert len(listed.tools) == 7

    asyncio.run(exercise())
    stderr_text = stderr_path.read_text(encoding="utf-8")
    assert marker not in stderr_text
    # Rich can insert source columns into wrapped messages; the SDK's plain
    # StreamHandler omits severity labels. Unit tests check LogRecord.levelno.
    assert "omitted." in stderr_text
    assert diagnostic in stderr_text
    assert "Traceback" not in stderr_text
    assert "Failed to parse JSONRPC message from server" not in caplog.text
