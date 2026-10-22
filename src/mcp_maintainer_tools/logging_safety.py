"""Sanitize known MCP SDK input logs without suppressing diagnostics.

This adapter covers the installed SDK's malformed request, notification,
stdio-message validation, unknown-tool, prompt-error and response-ID warning
paths. It is not a general secret scrubber: explicitly enabling arbitrary SDK
DEBUG logs may still expose incoming protocol messages.
"""

import logging
import os
from threading import Lock

import mcp.server.fastmcp.server as sdk_fastmcp
import mcp.server.lowlevel.server as sdk_server
import mcp.shared.session as sdk_session


def _source_path(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


_SESSION_SOURCE = _source_path(sdk_session.__file__)
_SERVER_SOURCE = _source_path(sdk_server.__file__)
_FASTMCP_SOURCE = _source_path(sdk_fastmcp.__file__)
_RULES = {
    _SESSION_SOURCE: (
        (
            "Failed to validate request:",
            "MCP rejected invalid request parameters; input values omitted.",
        ),
        ("Message that failed validation:", "MCP request validation details omitted."),
        (
            "Failed to validate notification:",
            "MCP rejected an invalid notification; input values omitted.",
        ),
        (
            "Response ID ",
            "MCP received an unrecognized response ID; input values omitted.",
        ),
    ),
    _SERVER_SOURCE: (
        (
            "Received exception from stream:",
            "MCP rejected an invalid stream message; input values omitted.",
        ),
        (
            "Tool '%s' not listed, no validation will be performed",
            "MCP received an unknown tool name; input values omitted.",
        ),
    ),
    _FASTMCP_SOURCE: (
        (
            "Error getting prompt ",
            "MCP rejected a prompt request; input values omitted.",
        ),
    ),
}


class _SDKValidationFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not isinstance(record.pathname, str) or not isinstance(record.msg, str):
            return True
        rules = _RULES.get(_source_path(record.pathname), ())
        for prefix, replacement in rules:
            if record.msg.startswith(prefix):
                record.msg = replacement
                record.args = ()
                record.exc_info = None
                record.exc_text = None
                record.stack_info = None
                # A previous formatter may already have cached this field.
                record.message = replacement
                break
        return True


_FILTER = _SDKValidationFilter()
_INSTALL_LOCK = Lock()


def install_sdk_log_safety() -> None:
    """Install idempotent filters before starting the official stdio server.

    The SDK emits session validation and response-ID warnings through the root
    logger, stream errors or unknown-tool warnings through its low-level server
    logger, and prompt errors through its FastMCP server logger. Attaching to
    these origins sanitizes records before any handlers see them, including
    handlers added later. Their levels, handlers, and unrelated records are
    unchanged.
    """
    with _INSTALL_LOCK:
        logging.getLogger().addFilter(_FILTER)
        logging.getLogger("mcp.server.lowlevel.server").addFilter(_FILTER)
        logging.getLogger("mcp.server.fastmcp.server").addFilter(_FILTER)
