"""Sanitize known MCP SDK validation logs without suppressing diagnostics.

This adapter covers the installed SDK's malformed request, notification and
stdio-message validation paths. It is not a general secret scrubber: explicitly
enabling arbitrary SDK DEBUG logs may still expose incoming protocol messages.
"""

import logging
import os
from threading import Lock

import mcp.server.lowlevel.server as sdk_server
import mcp.shared.session as sdk_session


def _source_path(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


_SESSION_SOURCE = _source_path(sdk_session.__file__)
_SERVER_SOURCE = _source_path(sdk_server.__file__)
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
    ),
    _SERVER_SOURCE: (
        (
            "Received exception from stream:",
            "MCP rejected an invalid stream message; input values omitted.",
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

    The SDK currently emits session validation warnings through the root logger
    and raw stream errors through its low-level server logger. Attaching to both
    origins sanitizes records before any handlers see them, including handlers
    added later. Their levels, handlers, and unrelated records are unchanged.
    """
    with _INSTALL_LOCK:
        logging.getLogger().addFilter(_FILTER)
        logging.getLogger("mcp.server.lowlevel.server").addFilter(_FILTER)
