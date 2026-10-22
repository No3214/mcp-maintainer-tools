"""Exercise installed module entry points from outside the source checkout."""

import subprocess
import sys
from importlib.metadata import version

from mcp_maintainer_tools import __version__


def _run(tmp_path, *args):
    return subprocess.run(
        [sys.executable, "-m", "mcp_maintainer_tools", *args],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_help_exits_without_starting_protocol(tmp_path):
    result = _run(tmp_path, "--help")
    assert result.returncode == 0
    assert "MCP stdio server" in result.stdout
    assert "--version" in result.stdout
    assert result.stderr == ""


def test_version_matches_installed_distribution(tmp_path):
    result = _run(tmp_path, "--version")
    assert result.returncode == 0
    assert result.stdout.strip() == f"mcp-maintainer-tools {version('mcp-maintainer-tools')}"
    assert version("mcp-maintainer-tools") == __version__
    assert result.stderr == ""


def test_unknown_option_fails_before_protocol_startup(tmp_path):
    result = _run(tmp_path, "--not-a-supported-option")
    assert result.returncode == 2
    assert result.stdout == ""
    assert "unrecognized arguments" in result.stderr
    assert "Traceback" not in result.stderr
