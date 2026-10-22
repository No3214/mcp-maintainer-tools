"""Command-line entry point; protocol traffic alone uses stdout during service."""

import argparse
from collections.abc import Sequence

from . import __version__


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="mcp-maintainer-tools",
        description="Read-only MCP tools for public vulnerability and package research.",
        epilog=(
            "With no arguments, start the MCP stdio server. An MCP client manages "
            "the process and sends tool calls over stdin/stdout. "
            "This command is not an interactive vulnerability scanner."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.parse_args(argv)

    # Keep informational CLI calls quick and independent of SDK initialization.
    from .server import main as run_server

    run_server()
