"""Exercise blocked providers, cancellation, and argument admission over real stdio."""

import asyncio
import json
import os
import sys
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from threading import Event, Lock, Thread

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp.exceptions import ToolError
from mcp.shared.exceptions import McpError

from mcp_maintainer_tools import server as s

# Only the external provider boundary is replaced. A file barrier lets the
# parent release synchronous work even when the child's event loop is blocked.
# The backstop also prevents a failed test from stranding a child process.
BLOCKED_PROVIDER_SERVER = """
import json
import sys
import time
from pathlib import Path
from urllib.parse import unquote

from mcp_maintainer_tools import server as s

barriers = Path(sys.argv[1])

def fake_get(url, *args, **kwargs):
    assert url.startswith(s.OSV + "/vulns/"), "Unexpected provider call"
    vuln_id = unquote(url.rsplit("/", 1)[1])
    assert vuln_id.startswith("BLOCK-"), "Unexpected vulnerability lookup"
    request_id = s.mcp.get_context().request_context.request_id
    (barriers / ("entered-" + vuln_id)).write_text(json.dumps(request_id))
    deadline = time.monotonic() + 15
    try:
        while not (barriers / "release-all").exists():
            if (barriers / ("release-" + vuln_id)).exists():
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Test provider release timed out")
            time.sleep(0.01)
        return {"id": vuln_id}
    finally:
        (barriers / ("finished-" + vuln_id)).touch()

def forbid_post(*args, **kwargs):
    raise AssertionError("Unexpected provider POST")

s.get = fake_get
s.post = forbid_post
s.main()
"""


@asynccontextmanager
async def _session(tmp_path):
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-c", BLOCKED_PROVIDER_SERVER, str(tmp_path)],
        cwd=tmp_path,
        env={
            "PYTHONNOUSERSITE": "1",
            "PYTHONPATH": str(Path(s.__file__).resolve().parent.parent),
            **{
                key: os.environ[key]
                for key in ("COVERAGE_PROCESS_CONFIG", "COVERAGE_PROCESS_START")
                if key in os.environ
            },
        },
    )
    with (tmp_path / "stderr.txt").open("w+") as stderr:
        async with stdio_client(parameters, errlog=stderr) as (read, write):
            async with ClientSession(
                read, write, read_timeout_seconds=timedelta(seconds=10)
            ) as session:
                await session.initialize()
                try:
                    yield session
                finally:
                    (tmp_path / "release-all").touch()


async def _wait_for_file(path):
    with anyio.fail_after(5):
        while not path.exists():
            await anyio.sleep(0.01)


async def _cancel(session, tmp_path, vuln_id):
    request_id = json.loads((tmp_path / ("entered-" + vuln_id)).read_text())
    await session.send_notification(
        types.ClientNotification(
            types.CancelledNotification(
                params=types.CancelledNotificationParams(requestId=request_id)
            )
        )
    )


def _data(result):
    assert result.isError is False, result.content
    return json.loads(result.content[0].text)


def test_stdio_services_unrelated_requests_while_provider_is_blocked(tmp_path):
    async def exercise():
        async with _session(tmp_path) as session:
            blocked = asyncio.create_task(session.call_tool("osv_vuln", {"vuln_id": "BLOCK-ONE"}))
            try:
                await _wait_for_file(tmp_path / "entered-BLOCK-ONE")
                with anyio.move_on_after(2) as responsive:
                    await session.send_ping()
                    listed = await session.list_tools()
                    assert len(listed.tools) == 7
                    empty = await session.call_tool("epss", {"cve_ids": []})
                    assert _data(empty)["queried"] is False
                assert not responsive.cancel_called, "Provider blocked unrelated MCP requests"
                assert not blocked.done()
            finally:
                (tmp_path / "release-all").touch()
                result = await blocked
                assert _data(result)["record"]["id"] == "BLOCK-ONE"

    asyncio.run(exercise())


def test_stdio_cancellation_does_not_wait_for_provider_or_emit_duplicate_response(tmp_path):
    async def exercise():
        async with _session(tmp_path) as session:
            blocked = asyncio.create_task(
                session.call_tool("osv_vuln", {"vuln_id": "BLOCK-CANCEL"})
            )
            try:
                await _wait_for_file(tmp_path / "entered-BLOCK-CANCEL")
                await _cancel(session, tmp_path, "BLOCK-CANCEL")
                with anyio.move_on_after(2) as responsive:
                    with pytest.raises(McpError, match="cancelled"):
                        await blocked
                assert not responsive.cancel_called, "MCP cancellation waited for provider"
                assert not (tmp_path / "finished-BLOCK-CANCEL").exists()
                await session.send_ping()
            finally:
                (tmp_path / "release-all").touch()
                await asyncio.gather(blocked, return_exceptions=True)
                await _wait_for_file(tmp_path / "finished-BLOCK-CANCEL")
            await session.send_ping()

    asyncio.run(exercise())
    assert "Request already responded to" not in (tmp_path / "stderr.txt").read_text()


def test_stdio_cancelled_workers_keep_capacity_until_the_provider_returns(tmp_path):
    async def exercise():
        async with _session(tmp_path) as session:
            ids = ["BLOCK-A", "BLOCK-B", "BLOCK-C", "BLOCK-D"]
            blocked = [
                asyncio.create_task(session.call_tool("osv_vuln", {"vuln_id": value}))
                for value in ids
            ]
            try:
                for value in ids:
                    await _wait_for_file(tmp_path / ("entered-" + value))
                with anyio.fail_after(2):
                    busy = await session.call_tool("osv_vuln", {"vuln_id": "BLOCK-EXCESS"})
                assert busy.isError is True
                assert "busy" in busy.content[0].text.lower()
                assert not (tmp_path / "entered-BLOCK-EXCESS").exists()
                for value in ids:
                    await _cancel(session, tmp_path, value)
                with anyio.fail_after(2):
                    cancelled = await asyncio.gather(*blocked, return_exceptions=True)
                assert all(isinstance(result, McpError) for result in cancelled)
                with anyio.fail_after(2):
                    busy = await session.call_tool("osv_vuln", {"vuln_id": "BLOCK-EXCESS"})
                assert busy.isError is True
                assert "busy" in busy.content[0].text.lower()
                assert not (tmp_path / "entered-BLOCK-EXCESS").exists()
                await session.send_ping()
            finally:
                (tmp_path / "release-all").touch()
                await asyncio.gather(*blocked, return_exceptions=True)
            with anyio.fail_after(2):
                while True:
                    recovered = await session.call_tool("epss", {"cve_ids": []})
                    if not recovered.isError:
                        break
                    assert "busy" in recovered.content[0].text.lower()
                    await anyio.sleep(0.01)
            assert _data(recovered)["queried"] is False

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "name,arguments",
    [
        ("osv_query", {"name": "example", "version": "1"}),
        ("osv_batch", {"packages": []}),
        ("osv_vuln", {"vuln_id": "EXAMPLE-1"}),
        ("nvd_cve", {"cve_id": "CVE-2021-44228"}),
        ("kev_check", {"cve_ids": []}),
        ("epss", {"cve_ids": []}),
        ("depsdev_package", {"name": "example"}),
    ],
)
def test_top_level_extra_arguments_fail_before_provider_calls(monkeypatch, name, arguments):
    def forbid(*args, **kwargs):
        raise AssertionError("Unexpected provider call")

    monkeypatch.setattr(s, "get", forbid)
    monkeypatch.setattr(s, "post", forbid)
    with pytest.raises(ToolError, match="Invalid tool arguments") as failure:
        asyncio.run(s.mcp.call_tool(name, {**arguments, "private-extra-key": "private-value"}))
    assert "private-extra-key" not in str(failure.value)
    assert "private-value" not in str(failure.value)


def test_all_tool_schemas_reject_top_level_extra_arguments():
    for tool in asyncio.run(s.mcp.list_tools()):
        assert tool.inputSchema.get("additionalProperties") is False, tool.name


def test_stdio_rejects_extra_fields_and_unknown_names_without_echoing_values(tmp_path):
    async def exercise():
        async with _session(tmp_path) as session:
            extra = await session.call_tool(
                "epss", {"cve_ids": [], "private-extra-key": "private-value"}
            )
            assert extra.isError is True
            assert "Invalid tool arguments" in extra.content[0].text
            assert "private" not in extra.content[0].text
            unknown = await session.call_tool("synthetic-private-unknown-tool", {})
            assert unknown.isError is True
            assert "synthetic-private-unknown-tool" not in unknown.content[0].text

    asyncio.run(exercise())
    stderr = (tmp_path / "stderr.txt").read_text()
    assert "synthetic-private-unknown-tool" not in stderr
    assert "private-extra-key" not in stderr
    assert "private-value" not in stderr


def test_raw_asyncio_cancellation_does_not_admit_replacement_workers(monkeypatch):
    release = Event()
    started = []
    lock = Lock()
    app = s.MaintainerMCP("cancellation-test")
    app.add_tool(s.osv_vuln)

    def fake_get(url, **_):
        with lock:
            started.append(url)
        assert release.wait(5), "Test provider release timed out"
        return {"id": url.rsplit("/", 1)[1]}

    monkeypatch.setattr(s, "get", fake_get)

    async def exercise():
        blocked = [
            asyncio.create_task(app.call_tool("osv_vuln", {"vuln_id": f"BLOCK-{i}"}))
            for i in range(4)
        ]
        try:
            with anyio.fail_after(2):
                while True:
                    with lock:
                        if len(started) == 4:
                            break
                    await anyio.sleep(0.01)
            for task in blocked:
                task.cancel()
            results = await asyncio.gather(*blocked, return_exceptions=True)
            assert all(isinstance(result, asyncio.CancelledError) for result in results)
            with pytest.raises(ToolError, match="busy"):
                await app.call_tool("osv_vuln", {"vuln_id": "BLOCK-EXCESS"})
            assert len(started) == 4
        finally:
            release.set()
            await asyncio.gather(*blocked, return_exceptions=True)
            app.shutdown_workers()

    asyncio.run(exercise())


@pytest.mark.parametrize("startup_failure", [False, True])
def test_main_closes_workers_idempotently_without_poisoning_other_instances(
    monkeypatch, startup_failure
):
    app = s.MaintainerMCP("shutdown-test")
    app.add_tool(s.epss)

    def run(**kwargs):
        if startup_failure:
            raise RuntimeError("Synthetic startup failure")

    monkeypatch.setattr(app, "run", run)
    monkeypatch.setattr(s, "mcp", app)
    if startup_failure:
        with pytest.raises(RuntimeError, match="Synthetic startup failure"):
            s.main()
    else:
        s.main()
    app.shutdown_workers()
    app.shutdown_workers()
    # Failed submission must release admission so it remains a shutdown error.
    for _ in range(5):
        with pytest.raises(ToolError, match="unavailable or shutting down"):
            asyncio.run(app.call_tool("epss", {"cve_ids": []}))
    replacement = s.MaintainerMCP("replacement-test")
    replacement.add_tool(s.epss)
    try:
        asyncio.run(replacement.call_tool("epss", {"cve_ids": []}))
    finally:
        replacement.shutdown_workers()


def test_thread_start_failure_cancels_unreturned_job_and_closes_admission(monkeypatch):
    app = s.MaintainerMCP("thread-start-failure-test")
    app.add_tool(s.osv_vuln)
    requests = []

    def fake_get(url, **_):
        requests.append(url)
        return {"id": url.rsplit("/", 1)[1]}

    def fail_start(thread):
        raise RuntimeError("synthetic-private-thread-start-failure")

    monkeypatch.setattr(s, "get", fake_get)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(Thread, "start", fail_start)
            with pytest.raises(ToolError, match="unavailable or shutting down") as failure:
                asyncio.run(app.call_tool("osv_vuln", {"vuln_id": "NEVER-EXECUTE"}))
            assert "synthetic-private" not in str(failure.value)
        # Restoring thread creation must not cause the previously failed call
        # to run from ThreadPoolExecutor's internal queue on a later submission.
        with pytest.raises(ToolError, match="unavailable or shutting down"):
            asyncio.run(app.call_tool("osv_vuln", {"vuln_id": "ALSO-REJECT"}))
        assert requests == []
    finally:
        app.shutdown_workers()
