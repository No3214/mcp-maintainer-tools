"""Unknown tool names must not reach the SDK's default warning diagnostics."""

import asyncio
import inspect
import logging

import pytest
from mcp.server.lowlevel.server import Server

from mcp_maintainer_tools import logging_safety

MARKER = "synthetic-private-unknown-tool"
SDK_WARNING = "Tool '%s' not listed, no validation will be performed"
SDK_LOGGER = "mcp.server.lowlevel.server"


@pytest.fixture(autouse=True)
def installed_filters():
    loggers = [logging.getLogger(), logging.getLogger(SDK_LOGGER)]
    already_installed = [logging_safety._FILTER in logger.filters for logger in loggers]
    logging_safety.install_sdk_log_safety()
    yield
    for logger, was_installed in zip(loggers, already_installed, strict=True):
        if not was_installed:
            logger.removeFilter(logging_safety._FILTER)


def test_actual_sdk_unknown_tool_warning_keeps_name_out_of_stderr(caplog, capsys):
    caplog.set_level(logging.WARNING)
    logger = logging.getLogger(SDK_LOGGER)
    stderr = logging.StreamHandler()
    logger.addHandler(stderr)
    try:
        result = asyncio.run(Server("logging-test")._get_cached_tool_definition(MARKER))
    finally:
        logger.removeHandler(stderr)
        stderr.close()
    assert result is None
    captured = capsys.readouterr().err
    assert MARKER not in captured
    assert MARKER not in caplog.text
    assert "unknown tool" in captured
    assert len(caplog.records) == 1
    assert caplog.records[0].levelno == logging.WARNING
    assert caplog.records[0].args == ()


def test_unknown_tool_warning_clears_cached_exception_and_argument_values(caplog):
    error = ValueError(MARKER)
    record = logging.LogRecord(
        SDK_LOGGER,
        logging.WARNING,
        inspect.getfile(Server),
        1,
        SDK_WARNING,
        (MARKER,),
        (ValueError, error, None),
    )
    record.exc_text = MARKER
    record.stack_info = MARKER
    record.message = MARKER
    logging.getLogger(SDK_LOGGER).handle(record)
    assert MARKER not in caplog.text
    assert MARKER not in str(record.__dict__)
    assert "unknown tool" in caplog.text
    assert record.levelno == logging.WARNING


@pytest.mark.parametrize(
    "source,message",
    [
        (__file__, SDK_WARNING),
        (inspect.getfile(Server), "Tool '%s' returned an empty result"),
    ],
    ids=["non-sdk-source", "unrelated-sdk-warning"],
)
def test_unknown_tool_filter_preserves_unrelated_diagnostics(source, message, caplog):
    record = logging.LogRecord(SDK_LOGGER, logging.WARNING, source, 1, message, (MARKER,), None)
    logging.getLogger(SDK_LOGGER).handle(record)
    assert message % MARKER in caplog.text
