"""Adversarial upstream responses must fail without unbounded reads or state."""

import gzip
import traceback

import httpx
import pytest
import respx

from mcp_maintainer_tools import http

BASE = "https://upstream.example.test/resource"


class RecordingStream(httpx.SyncByteStream):
    def __init__(self, chunks, on_chunk=None):
        self.chunks = chunks
        self.on_chunk = on_chunk
        self.reads = 0
        self.closed = False

    def __iter__(self):
        for chunk in self.chunks:
            self.reads += 1
            if self.on_chunk is not None:
                self.on_chunk(self.reads)
            yield chunk

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def isolated_client(monkeypatch):
    monkeypatch.setattr(http, "_client", None)
    monkeypatch.delenv("MCP_MAINTAINER_TOOLS_TRUST_ENV", raising=False)
    yield
    if http._client is not None:
        http._client.close()


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_oversized_content_length_is_rejected_before_body_is_read(method, monkeypatch):
    monkeypatch.setattr(http, "MAX_RESPONSE_BYTES", 64)
    stream = RecordingStream([b"private upstream body"])
    with respx.mock as mock:
        route = mock.route(method=method, url=BASE).respond(
            200, headers={"Content-Length": "65"}, stream=stream
        )
        with pytest.raises(http.UpstreamError, match="size limit"):
            getattr(http, method.lower())(BASE)
        assert route.call_count == 1
    assert stream.reads == 0
    assert stream.closed


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_chunked_body_stops_at_size_limit_and_closes(method, monkeypatch):
    monkeypatch.setattr(http, "MAX_RESPONSE_BYTES", 8)
    stream = RecordingStream([b"1234", b"5678", b"9", b"must not be read"])
    with respx.mock as mock:
        mock.route(method=method, url=BASE).respond(200, stream=stream)
        with pytest.raises(http.UpstreamError, match="size limit"):
            getattr(http, method.lower())(BASE)
    assert stream.reads == 3
    assert stream.closed


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_exact_body_size_limit_is_accepted(method, monkeypatch):
    body = b'{"x":1}'
    monkeypatch.setattr(http, "MAX_RESPONSE_BYTES", len(body))
    stream = RecordingStream([body[:3], body[3:]])
    with respx.mock as mock:
        mock.route(method=method, url=BASE).respond(200, stream=stream)
        assert getattr(http, method.lower())(BASE) == {"x": 1}
    assert stream.closed


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_unexpected_compression_is_rejected_without_decompression(method):
    stream = RecordingStream([gzip.compress(b"A" * 65_536)])
    with respx.mock as mock:
        route = mock.route(method=method, url=BASE).respond(
            200, headers={"Content-Encoding": "gzip"}, stream=stream
        )
        with pytest.raises(http.UpstreamError, match="content encoding"):
            getattr(http, method.lower())(BASE)
        assert route.calls[0].request.headers["Accept-Encoding"] == "identity"
    assert stream.reads == 0
    assert stream.closed


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_bad_status_body_is_not_read(method):
    stream = RecordingStream([b"private upstream body"])
    with respx.mock as mock:
        mock.route(method=method, url=BASE).respond(401, stream=stream)
        with pytest.raises(http.UpstreamError, match="HTTP 401"):
            getattr(http, method.lower())(BASE)
    assert stream.reads == 0
    assert stream.closed


def test_retry_response_is_closed_without_reading_its_body(monkeypatch):
    monkeypatch.setattr(http.time, "sleep", lambda _: None)
    first = RecordingStream([b"private upstream body"])
    second = RecordingStream([b'{"ok":true}'])
    with respx.mock as mock:
        route = mock.get(BASE).mock(
            side_effect=[
                httpx.Response(503, stream=first),
                httpx.Response(200, stream=second),
            ]
        )
        assert http.get(BASE) == {"ok": True}
        assert route.call_count == 2
    assert first.reads == 0
    assert first.closed and second.closed


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_partial_stream_transport_failure_is_closed_and_sanitized(method, monkeypatch):
    marker = "synthetic-private-partial-response"

    class BrokenStream(RecordingStream):
        def __iter__(self):
            yield b'{"private":'
            raise httpx.ReadError(marker)

    broken = BrokenStream([])
    monkeypatch.setattr(http.time, "sleep", lambda _: None)
    with respx.mock as mock:
        route = mock.route(method=method, url=BASE).respond(200, stream=broken)
        with pytest.raises(http.UpstreamError) as caught:
            if method == "GET":
                http.get(BASE, retries=0)
            else:
                http.post(BASE)
        assert route.call_count == 1
    assert broken.closed
    assert marker not in "".join(traceback.format_exception(caught.value))


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_stream_time_budget_is_checked_on_each_network_chunk(method, monkeypatch):
    clock = {"now": 0.0}
    monkeypatch.setattr(http, "monotonic", lambda: clock["now"])

    def advance(reads):
        if reads == 2:
            clock["now"] = http.MAX_RESPONSE_SECONDS + 1

    stream = RecordingStream([b'{"x":', b"1", b"}"], on_chunk=advance)
    with respx.mock as mock:
        route = mock.route(method=method, url=BASE).respond(200, stream=stream)
        with pytest.raises(http.UpstreamError, match="time limit"):
            getattr(http, method.lower())(BASE)
        assert route.call_count == 1
    assert stream.reads == 2
    assert stream.closed


@pytest.mark.parametrize(
    "body",
    [
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":-Infinity}',
        b'{"value":1e9999}',
        b'{"found":false,"found":true}',
        b"[" * 200 + b"0" + b"]" * 200,
    ],
    ids=["nan", "infinity", "negative-infinity", "float-overflow", "duplicate-key", "deep-nesting"],
)
def test_ambiguous_or_excessively_nested_json_is_rejected(body):
    with respx.mock as mock:
        mock.get(BASE).respond(200, content=body)
        with pytest.raises(http.UpstreamError, match="not valid JSON") as caught:
            http.get(BASE)
    assert caught.value.__suppress_context__
    assert body.decode() not in "".join(traceback.format_exception(caught.value))


def test_braces_and_escaped_quotes_inside_strings_are_not_nesting():
    expected = {"description": '[{\\"quoted\\"}] ' * 100}
    with respx.mock as mock:
        mock.get(BASE).respond(200, json=expected)
        assert http.get(BASE) == expected


def test_utf8_bom_is_accepted():
    with respx.mock as mock:
        mock.get(BASE).respond(200, content=b'\xef\xbb\xbf{"x":1}')
        assert http.get(BASE) == {"x": 1}


@pytest.mark.parametrize(
    "body",
    [
        b'{"text":"\\ud800"}',
        b'{"\\udfff":1}',
        b'{"record":[{"text":"\\udfff"}]}',
    ],
    ids=["value", "key", "nested-value"],
)
def test_lone_surrogates_are_rejected_before_mcp_serialization(body):
    with respx.mock as mock:
        mock.get(BASE).respond(200, content=body)
        with pytest.raises(http.UpstreamError, match="not valid JSON"):
            http.get(BASE)


def test_normal_unicode_and_valid_surrogate_pairs_are_preserved():
    with respx.mock as mock:
        mock.get(BASE).respond(200, content=b'{"text":"\\ud83d\\ude00 \\u0130zmir"}')
        assert http.get(BASE) == {"text": "\U0001f600 \u0130zmir"}


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize(
    "url",
    [
        "http://upstream.example.test/resource",
        "https://user:synthetic-private-password@upstream.example.test/resource",
    ],
)
def test_https_and_no_url_credentials_are_required_before_network(method, url):
    with respx.mock(assert_all_called=False) as mock:
        route = mock.route(method=method).respond(200, json={"ok": True})
        with pytest.raises(http.UpstreamError, match="HTTPS") as caught:
            getattr(http, method.lower())(url)
        assert route.call_count == 0
    assert "synthetic-private-password" not in "".join(traceback.format_exception(caught.value))


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_response_cookies_are_not_stored_or_sent_on_later_calls(method):
    with respx.mock as mock:
        route = mock.route(method=method, url=BASE).respond(
            200,
            json={"ok": True},
            headers={"Set-Cookie": "tracking=synthetic-private-cookie; Path=/; Secure"},
        )
        request = getattr(http, method.lower())
        assert request(BASE) == {"ok": True}
        assert request(BASE) == {"ok": True}
        assert "cookie" not in route.calls[1].request.headers
        assert list(http.client().cookies.jar) == []


@pytest.mark.parametrize("setting", [None, "false"])
def test_ambient_proxy_and_ca_configuration_is_not_used_without_opt_in(monkeypatch, setting):
    if setting is not None:
        monkeypatch.setenv("MCP_MAINTAINER_TOOLS_TRUST_ENV", setting)
    monkeypatch.setenv("HTTPS_PROXY", "http://synthetic-private-proxy.invalid:1234")
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/synthetic-private-cert.pem")
    with respx.mock as mock:
        mock.get(BASE).respond(200, json={"ok": True})
        assert http.get(BASE) == {"ok": True}
    assert http.client().trust_env is False


def test_explicit_opt_in_enables_standard_httpx_environment_configuration(monkeypatch):
    monkeypatch.setenv("MCP_MAINTAINER_TOOLS_TRUST_ENV", "true")
    monkeypatch.setenv("HTTPS_PROXY", "http://synthetic-private-proxy.invalid:1234")
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    with respx.mock as mock:
        mock.get(BASE).respond(200, json={"ok": True})
        assert http.get(BASE) == {"ok": True}
    assert http.client().trust_env is True
    assert http.client().follow_redirects is False
    assert http.client().headers["Accept-Encoding"] == "identity"


@pytest.mark.parametrize(
    "setting", ["", "TRUE", "1", "yes", " true", "false ", "private-config-marker"]
)
def test_invalid_environment_opt_in_is_rejected_without_echoing_value(monkeypatch, setting):
    monkeypatch.setenv("MCP_MAINTAINER_TOOLS_TRUST_ENV", setting)
    with pytest.raises(http.UpstreamError, match="MCP_MAINTAINER_TOOLS_TRUST_ENV") as caught:
        http.client()
    assert http._client is None
    if setting:
        assert setting not in str(caught.value)
    assert caught.value.__suppress_context__
    assert "private-config-marker" not in "".join(traceback.format_exception(caught.value))


def test_opted_in_invalid_ca_path_does_not_leak_configuration(monkeypatch):
    marker = "synthetic-private-ca-path"
    monkeypatch.setenv("MCP_MAINTAINER_TOOLS_TRUST_ENV", "true")
    monkeypatch.setenv("SSL_CERT_FILE", f"/nonexistent/{marker}.pem")
    with pytest.raises(http.UpstreamError, match="configuration failed") as caught:
        http.client()
    assert http._client is None
    assert marker not in "".join(traceback.format_exception(caught.value))


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_non_ascii_header_errors_are_sanitized(method):
    secret = "synthetic-private-key-\u0131"
    with pytest.raises(http.UpstreamError) as caught:
        getattr(http, method.lower())(BASE, headers={"apiKey": secret})
    assert secret not in "".join(traceback.format_exception(caught.value))


def test_boolean_retry_count_is_rejected():
    with pytest.raises(ValueError, match="integer"):
        http.get(BASE, retries=True)
