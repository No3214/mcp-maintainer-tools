"""Text responses must obey the HTTP helper's safe error and Unicode boundary."""

import traceback

import httpx
import pytest
import respx

from mcp_maintainer_tools import http

BASE = "https://upstream.example.test/resource"


@pytest.fixture(autouse=True)
def isolated_client(monkeypatch):
    monkeypatch.setattr(http, "_client", None)
    monkeypatch.delenv("MCP_MAINTAINER_TOOLS_TRUST_ENV", raising=False)
    yield
    if http._client is not None:
        http._client.close()


def test_non_text_charset_fails_with_a_safe_error_and_closes_response():
    marker = b"synthetic-private-response"
    with respx.mock as mock:
        route = mock.get(BASE).respond(
            200,
            headers={"Content-Type": "text/plain; charset=base64_codec"},
            stream=httpx.ByteStream(marker),
        )
        with pytest.raises(http.UpstreamError, match="not valid text") as caught:
            http.get(BASE, as_text=True)
        assert route.call_count == 1
        assert route.calls[0].response.is_closed
    assert marker.decode() not in "".join(traceback.format_exception(caught.value))
    assert caught.value.__suppress_context__


@pytest.mark.parametrize("charset", ["unicode_escape", "raw_unicode_escape"])
def test_text_codec_cannot_return_lone_surrogates(charset):
    with respx.mock as mock:
        mock.get(BASE).respond(
            200,
            headers={"Content-Type": f"text/plain; charset={charset}"},
            content=b"\\ud800",
        )
        with pytest.raises(http.UpstreamError, match="not valid text"):
            http.get(BASE, as_text=True)


def test_declared_text_encoding_preserves_non_ascii_and_non_bmp_characters():
    with respx.mock as mock:
        mock.get(BASE).respond(
            200,
            headers={"Content-Type": "text/plain; charset=utf-16-le"},
            content=b"0\x01z\x00m\x00i\x00r\x00 \x00=\xd8\x00\xde",
        )
        assert http.get(BASE, as_text=True) == "İzmir 😀"
