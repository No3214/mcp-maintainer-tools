"""Exercise the installed console entry point over MCP stdio without network access."""

import asyncio
from datetime import timedelta
import json
import sys

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


# Loading the installed console entry point from an unrelated working directory
# also checks that this is a usable installed package, not a cwd-dependent import.
# Block socket connections before loading it: empty queries must need no network.
GUARDED_ENTRY_POINT = """
import socket
from importlib.metadata import distribution

def forbid_connection(*args, **kwargs):
    raise AssertionError("Network access is forbidden in protocol tests")

socket.create_connection = forbid_connection
socket.socket.connect = forbid_connection
socket.socket.connect_ex = forbid_connection
entry = next(
    item for item in distribution("mcp-maintainer-tools").entry_points
    if item.group == "console_scripts" and item.name == "mcp-maintainer-tools"
)
entry.load()()
"""

REQUIRED_PARAMETERS = {
    "osv_query": {"name", "version"},
    "osv_batch": {"packages"},
    "osv_vuln": {"vuln_id"},
    "nvd_cve": {"cve_id"},
    "kev_check": {"cve_ids"},
    "epss": {"cve_ids"},
    "depsdev_package": {"name"},
}

PARAMETER_TYPES = {
    "osv_query": {"name": "string", "version": "string", "ecosystem": "string"},
    "osv_batch": {"packages": "array"},
    "osv_vuln": {"vuln_id": "string"},
    "nvd_cve": {"cve_id": "string"},
    "kev_check": {"cve_ids": "array"},
    "epss": {"cve_ids": "array", "offset": "integer", "limit": "integer"},
    "depsdev_package": {"name": "string", "system": "string"},
}


def _structured_result(result):
    assert result.isError is False, result.content
    text = [item.text for item in result.content if item.type == "text"]
    assert len(text) == 1
    decoded = json.loads(text[0])
    assert isinstance(decoded, dict)
    if result.structuredContent is not None:
        assert decoded == result.structuredContent
    return decoded


def test_installed_stdio_contract_and_empty_queries(tmp_path):
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-c", GUARDED_ENTRY_POINT],
        cwd=tmp_path,
        env={"PYTHONNOUSERSITE": "1"},
    )

    async def exercise():
        with anyio.fail_after(20):
            async with stdio_client(parameters) as (read, write):
                async with ClientSession(
                    read, write, read_timeout_seconds=timedelta(seconds=5)
                ) as session:
                    initialized = await session.initialize()
                    assert initialized.serverInfo.name == "mcp-maintainer-tools"
                    assert initialized.capabilities.tools is not None

                    listed = await session.list_tools()
                    tools = {tool.name: tool for tool in listed.tools}
                    assert set(tools) == set(REQUIRED_PARAMETERS)
                    assert listed.nextCursor is None
                    for name, tool in tools.items():
                        assert tool.annotations is not None, name
                        assert tool.annotations.readOnlyHint is True, name
                        assert tool.annotations.destructiveHint is False, name
                        assert tool.annotations.idempotentHint is True, name
                        assert tool.annotations.openWorldHint is True, name
                        assert tool.inputSchema["type"] == "object", name
                        assert set(tool.inputSchema.get("required", [])) == REQUIRED_PARAMETERS[name], name
                        for parameter, kind in PARAMETER_TYPES[name].items():
                            assert tool.inputSchema["properties"][parameter]["type"] == kind, (name, parameter)
                        if tool.outputSchema is not None:
                            assert tool.outputSchema["type"] == "object", name

                    epss_schema = tools["epss"].inputSchema["properties"]
                    assert epss_schema["offset"]["default"] == 0
                    assert epss_schema["limit"]["default"] == 100
                    assert tools["osv_query"].inputSchema["properties"]["page_token"]["default"] is None

                    osv = _structured_result(await session.call_tool("osv_batch", {"packages": []}))
                    assert osv["provider"] == "OSV"
                    assert osv["source_url"] == "https://api.osv.dev/v1/querybatch"
                    assert osv["results"] == []

                    epss = _structured_result(await session.call_tool("epss", {"cve_ids": []}))
                    assert epss == {
                        "provider": "FIRST EPSS",
                        "source_url": "https://api.first.org/data/v1/epss",
                        "queried": False,
                        "data": [],
                        "total": 0,
                        "has_more": False,
                        "next_offset": None,
                    }

    asyncio.run(exercise())
