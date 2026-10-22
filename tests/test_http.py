"""Regression tests for credential-safe HTTP errors and bounded requests."""

import logging
import traceback

import httpx
import pytest
import respx

from mcp_maintainer_tools import http


BASE = "https://upstream.example.test/resource"
URL_MARKER = "synthetic-private-url"
KEY_MARKER = "synthetic-query-credential"
HEADER_MARKER = "synthetic-header-credential"
BODY_MARKER = "synthetic-private-body"


@pytest.fixture(autouse=True)
def isolated_client(monkeypatch):
    monkeypatch.setattr(http, "_client", None)
    yield
    if http._client is not None:
        http._client.close()


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_http_errors_and_logs_do_not_disclose_request_or_response(method, caplog):
    caplog.set_level(logging.DEBUG)
    url = f"https://{URL_MARKER}.example.test/resource?api_key={KEY_MARKER}"
    with respx.mock as mock:
        route = mock.route(method=method, url=url).respond(401, text=BODY_MARKER)
        with pytest.raises(http.UpstreamError, match="HTTP 401") as caught:
            if method == "GET":
                http.get(url, headers={"Authorization": HEADER_MARKER})
            else:
                http.post(
                    url,
                    headers={"Authorization": HEADER_MARKER},
                    json={"private": BODY_MARKER},
                )
        assert route.call_count == 1

    displayed = "".join(traceback.format_exception(caught.value)) + caplog.text
    for marker in (URL_MARKER, KEY_MARKER, HEADER_MARKER, BODY_MARKER):
        assert marker not in str(caught.value)
        assert marker not in displayed
    assert caught.value.__suppress_context__ is True
    assert logging.getLogger("httpx").getEffectiveLevel() == logging.WARNING
    assert logging.getLogger("httpcore").getEffectiveLevel() == logging.WARNING


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_transport_exception_context_is_suppressed(method, caplog):
    caplog.set_level(logging.DEBUG)
    unsafe_message = f"{BASE}?key={KEY_MARKER} {HEADER_MARKER} {BODY_MARKER}"
    with respx.mock as mock:
        route = mock.route(method=method, url=BASE).mock(
            side_effect=httpx.ConnectError(unsafe_message)
        )
        with pytest.raises(http.UpstreamError) as caught:
            if method == "GET":
                http.get(BASE, retries=0)
            else:
                http.post(BASE, json={"private": BODY_MARKER})
        assert route.call_count == 1

    displayed = "".join(traceback.format_exception(caught.value)) + caplog.text
    assert caught.value.__suppress_context__ is True
    for marker in (BASE, KEY_MARKER, HEADER_MARKER, BODY_MARKER):
        assert marker not in displayed


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_invalid_json_does_not_disclose_body(method):
    with respx.mock as mock:
        mock.route(method=method, url=BASE).respond(200, text=BODY_MARKER)
        with pytest.raises(http.UpstreamError, match="not valid JSON") as caught:
            getattr(http, method.lower())(BASE)
    assert BODY_MARKER not in "".join(traceback.format_exception(caught.value))
    assert caught.value.__suppress_context__ is True


@pytest.mark.parametrize("method,status", [("GET", 302), ("POST", 307)])
def test_redirect_is_rejected_without_contacting_target(method, status):
    target = f"https://redirect.example.test/secret?key={KEY_MARKER}"
    with respx.mock(assert_all_called=False) as mock:
        source = mock.route(method=method, url=BASE).respond(
            status, headers={"Location": target}
        )
        destination = mock.route(url=target).respond(200, json={"ok": True})
        with pytest.raises(http.UpstreamError, match=f"HTTP {status}") as caught:
            getattr(http, method.lower())(BASE)
        assert source.call_count == 1
        assert destination.call_count == 0
        assert http.client().follow_redirects is False
    assert target not in str(caught.value)
    assert KEY_MARKER not in str(caught.value)


@pytest.mark.parametrize("status", [429, 502, 503, 504])
def test_get_retries_transient_status_then_returns_json(status, monkeypatch):
    waits = []
    monkeypatch.setattr(http.time, "sleep", waits.append)
    with respx.mock as mock:
        route = mock.get(BASE).mock(
            side_effect=[httpx.Response(status), httpx.Response(200, json={"ok": True})]
        )
        assert http.get(BASE) == {"ok": True}
        assert route.call_count == 2
    assert waits == [2]


def test_get_retries_transport_failure_then_succeeds(monkeypatch):
    waits = []
    monkeypatch.setattr(http.time, "sleep", waits.append)
    with respx.mock as mock:
        route = mock.get(BASE).mock(
            side_effect=[httpx.ReadTimeout(KEY_MARKER), httpx.Response(200, json=[])]
        )
        assert http.get(BASE) == []
        assert route.call_count == 2
    assert waits == [2]


@pytest.mark.parametrize("failure", ["status", "transport"])
def test_get_retry_count_is_capped_at_two(failure, monkeypatch):
    waits = []
    monkeypatch.setattr(http.time, "sleep", waits.append)
    with respx.mock as mock:
        route = mock.get(BASE)
        if failure == "status":
            route.respond(503, text=BODY_MARKER)
        else:
            route.mock(side_effect=httpx.ConnectError(KEY_MARKER))
        with pytest.raises(http.UpstreamError):
            http.get(BASE, retries=10000)
        assert route.call_count == 3
    assert waits == [2, 4]


@pytest.mark.parametrize("retries", [-1, 0])
def test_get_can_disable_retries(retries, monkeypatch):
    waits = []
    monkeypatch.setattr(http.time, "sleep", waits.append)
    with respx.mock as mock:
        route = mock.get(BASE).respond(503)
        with pytest.raises(http.UpstreamError):
            http.get(BASE, retries=retries)
        assert route.call_count == 1
    assert waits == []


def test_post_does_not_retry_transient_status(monkeypatch):
    waits = []
    monkeypatch.setattr(http.time, "sleep", waits.append)
    with respx.mock as mock:
        route = mock.post(BASE).respond(503)
        with pytest.raises(http.UpstreamError, match="HTTP 503"):
            http.post(BASE, json={"request": "could be a write"})
        assert route.call_count == 1
    assert waits == []


def test_get_as_text_preserves_success_response():
    with respx.mock as mock:
        mock.get(BASE).respond(200, text="public upstream text")
        assert http.get(BASE, as_text=True) == "public upstream text"
