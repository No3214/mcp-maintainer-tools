"""Exercise real SDK validation logging with in-memory protocol messages."""

import asyncio
import inspect
import logging
from types import SimpleNamespace

import pytest
from mcp import types
from mcp.server.fastmcp import FastMCP
from mcp.server.lowlevel.server import Server
from mcp.shared.message import SessionMessage
from mcp.shared.session import BaseSession

from mcp_maintainer_tools import logging_safety

MARKER = "synthetic-private-wire-argument"


class Incoming:
    def __init__(self, message):
        self.message = message

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    def __aiter__(self):
        return self.items()

    async def items(self):
        yield self.message


class Outgoing:
    def __init__(self):
        self.messages = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def send(self, item):
        self.messages.append(item)


@pytest.fixture(autouse=True)
def installed_filters():
    loggers = [
        logging.getLogger(),
        logging.getLogger("mcp.server.lowlevel.server"),
        logging.getLogger("mcp.server.fastmcp.server"),
    ]
    already_installed = [logging_safety._FILTER in logger.filters for logger in loggers]
    logging_safety.install_sdk_log_safety()
    yield
    for logger, was_installed in zip(loggers, already_installed, strict=True):
        if not was_installed:
            logger.removeFilter(logging_safety._FILTER)


@pytest.mark.parametrize(
    "payload,expected",
    [
        (
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "epss", "arguments": [MARKER]},
            },
            "invalid request parameters",
        ),
        (
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": {"private": MARKER}},
            },
            "invalid notification",
        ),
    ],
    ids=["request", "notification"],
)
def test_actual_sdk_receive_loop_sanitizes_invalid_input_logs(payload, expected, caplog):
    caplog.set_level(logging.DEBUG)
    message = SessionMessage(message=types.JSONRPCMessage.model_validate(payload))
    output = Outgoing()
    fake_session = SimpleNamespace(
        _read_stream=Incoming(message),
        _write_stream=output,
        _receive_request_type=types.ClientRequest,
        _receive_notification_type=types.ClientNotification,
        _response_streams={},
    )
    asyncio.run(BaseSession._receive_loop(fake_session))
    assert expected in caplog.text
    assert MARKER not in caplog.text
    assert MARKER not in str(output.messages)
    if "id" in payload:
        assert output.messages[0].message.root.error.code == -32602


def test_actual_sdk_invalid_json_stream_error_is_sanitized(caplog):
    caplog.set_level(logging.WARNING)
    try:
        types.JSONRPCMessage.model_validate_json('{"private":"' + MARKER + '"')
    except ValueError as caught:
        failure = caught

    notifications = []

    async def send_log_message(**kwargs):
        notifications.append(kwargs)

    fake_session = SimpleNamespace(send_log_message=send_log_message)
    asyncio.run(Server("logging-test")._handle_message(failure, fake_session, None))
    assert "invalid stream message" in caplog.text
    assert MARKER not in caplog.text
    assert MARKER not in str(notifications)
    assert notifications[0]["data"] == "Internal Server Error"


@pytest.mark.parametrize(
    "source,prefix,logger_name,level",
    [
        (logging_safety._SESSION_SOURCE, "Failed to validate request: %s", "root", logging.WARNING),
        (
            logging_safety._SESSION_SOURCE,
            "Failed to validate notification: %s",
            "root",
            logging.WARNING,
        ),
        (
            logging_safety._SERVER_SOURCE,
            "Received exception from stream: %s",
            "mcp.server.lowlevel.server",
            logging.WARNING,
        ),
        (
            inspect.getfile(FastMCP),
            "Error getting prompt %s",
            "mcp.server.fastmcp.server",
            logging.ERROR,
        ),
        (
            logging_safety._SESSION_SOURCE,
            "Response ID %r cannot be normalized to match pending requests",
            "root",
            logging.WARNING,
        ),
    ],
)
def test_validation_logs_clear_arguments_exception_and_stack_text(
    source, prefix, logger_name, level, caplog
):
    error = ValueError(MARKER)
    record = logging.LogRecord(
        logger_name,
        level,
        source,
        1,
        prefix,
        (MARKER,),
        (ValueError, error, None),
    )
    record.exc_text = MARKER
    record.stack_info = MARKER
    record.message = MARKER
    logging.getLogger(logger_name).handle(record)
    assert "input values omitted" in caplog.text
    assert MARKER not in caplog.text
    assert MARKER not in str(record.__dict__)
    assert record.levelno == level


def test_unrelated_diagnostics_and_non_sdk_messages_are_preserved(caplog):
    logging.warning("Maintenance diagnostic: %s", MARKER)
    logging.warning("Failed to validate request: %s", MARKER)
    assert f"Maintenance diagnostic: {MARKER}" in caplog.text
    assert f"Failed to validate request: {MARKER}" in caplog.text


@pytest.mark.parametrize(
    "source,message,logger_name",
    [
        (__file__, "Error getting prompt %s", "mcp.server.fastmcp.server"),
        (inspect.getfile(FastMCP), "Maintenance diagnostic: %s", "mcp.server.fastmcp.server"),
        (__file__, "Response ID %r cannot be normalized to match pending requests", "root"),
        (logging_safety._SESSION_SOURCE, "Maintenance diagnostic: %s", "root"),
    ],
    ids=["prompt-non-sdk", "prompt-unrelated", "response-non-sdk", "response-unrelated"],
)
def test_prompt_and_response_filters_preserve_unrelated_records(
    source, message, logger_name, caplog
):
    record = logging.LogRecord(logger_name, logging.WARNING, source, 1, message, (MARKER,), None)
    logging.getLogger(logger_name).handle(record)
    assert message % MARKER in caplog.text
    assert record.msg == message
    assert record.args == (MARKER,)
    assert record.levelno == logging.WARNING


def test_installation_is_idempotent_and_keeps_logging_configuration():
    loggers = [
        logging.getLogger(),
        logging.getLogger("mcp.server.lowlevel.server"),
        logging.getLogger("mcp.server.fastmcp.server"),
    ]
    before = [(logger.level, list(logger.handlers)) for logger in loggers]
    logging_safety.install_sdk_log_safety()
    logging_safety.install_sdk_log_safety()
    for logger, configuration in zip(loggers, before, strict=True):
        assert logger.filters.count(logging_safety._FILTER) == 1
        assert (logger.level, logger.handlers) == configuration
