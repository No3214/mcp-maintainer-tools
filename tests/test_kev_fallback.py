"""CISA availability fallback must preserve provenance and fail closed on bad data."""

import httpx
import pytest
import respx

from mcp_maintainer_tools import http
from mcp_maintainer_tools import server as s

CVE = "CVE-2021-44228"
CVE2 = "CVE-2024-3094"


@pytest.fixture(autouse=True)
def isolated_client(monkeypatch):
    monkeypatch.setattr(http, "_client", None)
    monkeypatch.delenv("MCP_MAINTAINER_TOOLS_TRUST_ENV", raising=False)
    monkeypatch.setattr(http.time, "sleep", lambda _: None)
    yield
    if http._client is not None:
        http._client.close()


def catalog():
    return {
        "catalogVersion": "2026.10.22",
        "dateReleased": "2026-10-22T00:00:00Z",
        "count": 1,
        "vulnerabilities": [{"cveID": CVE, "requiredAction": "See vendor advisory"}],
    }


def assert_mirror_result(result):
    assert result["source_url"] == s.KEV_MIRROR
    assert result["canonical_source_url"] == s.KEV
    assert result["fallback_used"] is True
    assert result["queried"] is True and result["retrieved_at"]
    assert result["catalog_version"] == "2026.10.22"
    assert result["date_released"] == "2026-10-22T00:00:00Z"
    assert result["hits"][CVE]["requiredAction"] == "See vendor advisory"
    assert result["not_in_kev"] == [CVE2]


@pytest.mark.parametrize("status", [403, 404, 408, 429, 500, 502, 503, 504, 599])
def test_availability_status_uses_only_official_fixed_mirror(status):
    with respx.mock as mock:
        primary = mock.get(s.KEV).respond(status)
        mirror = mock.get(s.KEV_MIRROR).respond(200, json=catalog())
        result = s.kev_check([CVE, CVE2])
        assert primary.call_count == (3 if status in http.RETRYABLE_STATUSES else 1)
        assert mirror.call_count == 1
        assert all(not call.request.url.query for call in mock.calls)
        assert all(not call.request.content for call in mock.calls)
    assert_mirror_result(result)


@pytest.mark.parametrize("error_type", [httpx.ConnectError, httpx.ReadTimeout])
def test_exhausted_get_transport_failure_uses_mirror(error_type):
    with respx.mock as mock:
        primary = mock.get(s.KEV).mock(side_effect=error_type("synthetic-private-network-error"))
        mirror = mock.get(s.KEV_MIRROR).respond(200, json=catalog())
        result = s.kev_check([CVE, CVE2])
        assert primary.call_count == 3 and mirror.call_count == 1
    assert_mirror_result(result)


def test_primary_success_does_not_contact_mirror():
    with respx.mock(assert_all_called=False) as mock:
        primary = mock.get(s.KEV).respond(200, json=catalog())
        mirror = mock.get(s.KEV_MIRROR).respond(200, json=catalog())
        result = s.kev_check([CVE])
        assert primary.call_count == 1 and mirror.call_count == 0
    assert result["source_url"] == result["canonical_source_url"] == s.KEV
    assert result["fallback_used"] is False
    assert result["queried"] is True and result["retrieved_at"]


def test_empty_query_does_not_contact_either_source():
    with respx.mock as mock:
        result = s.kev_check([])
        assert len(mock.calls) == 0
    assert result == {
        "provider": "CISA KEV",
        "source_url": s.KEV,
        "canonical_source_url": s.KEV,
        "fallback_used": False,
        "queried": False,
        "hits": {},
        "not_in_kev": [],
    }


@pytest.mark.parametrize("status", [400, 401, 409, 422, 451])
def test_other_http_errors_do_not_trigger_fallback(status):
    with respx.mock(assert_all_called=False) as mock:
        primary = mock.get(s.KEV).respond(status)
        mirror = mock.get(s.KEV_MIRROR).respond(200, json=catalog())
        with pytest.raises(http.UpstreamError) as caught:
            s.kev_check([CVE])
        assert primary.call_count == 1 and mirror.call_count == 0
    assert not isinstance(caught.value, http.UpstreamUnavailable)


@pytest.mark.parametrize("failure", ["json", "encoding", "size", "schema", "redirect", "config"])
def test_unsafe_or_invalid_primary_response_never_uses_mirror(failure, monkeypatch):
    target = "https://untrusted.example.test/catalog.json"
    with respx.mock(assert_all_called=False) as mock:
        primary = mock.get(s.KEV)
        mirror = mock.get(s.KEV_MIRROR).respond(200, json=catalog())
        redirect = mock.get(target).respond(200, json=catalog())
        if failure == "json":
            primary.respond(200, text="synthetic-private-invalid-json")
        elif failure == "encoding":
            primary.respond(
                200, headers={"Content-Encoding": "gzip"}, stream=httpx.ByteStream(b"not gzip")
            )
        elif failure == "size":
            monkeypatch.setattr(http, "MAX_RESPONSE_BYTES", 64)
            primary.respond(200, headers={"Content-Length": "65"}, stream=httpx.ByteStream(b"{}"))
        elif failure == "schema":
            primary.respond(200, json={**catalog(), "count": 2})
        elif failure == "redirect":
            primary.respond(302, headers={"Location": target})
        else:
            monkeypatch.setenv("MCP_MAINTAINER_TOOLS_TRUST_ENV", "synthetic-private-bad-config")
            primary.respond(200, json=catalog())
        error_type = s.UpstreamDataError if failure == "schema" else http.UpstreamError
        with pytest.raises(error_type) as caught:
            s.kev_check([CVE])
        assert primary.call_count == (0 if failure == "config" else 1)
        assert mirror.call_count == 0 and redirect.call_count == 0
    assert not isinstance(caught.value, http.UpstreamUnavailable)


@pytest.mark.parametrize("failure", ["status", "transport", "json", "schema"])
def test_failed_mirror_remains_an_error_without_another_fallback(failure):
    with respx.mock as mock:
        primary = mock.get(s.KEV).respond(403)
        mirror = mock.get(s.KEV_MIRROR)
        if failure == "status":
            mirror.respond(503)
        elif failure == "transport":
            mirror.mock(side_effect=httpx.ConnectError("synthetic-private-network-error"))
        elif failure == "json":
            mirror.respond(200, text="synthetic-private-invalid-json")
        else:
            mirror.respond(200, json={**catalog(), "count": 2})
        error_type = s.UpstreamDataError if failure == "schema" else http.UpstreamError
        with pytest.raises(error_type) as caught:
            s.kev_check([CVE])
        assert primary.call_count == 1
        assert mirror.call_count == (3 if failure in {"status", "transport"} else 1)
    assert isinstance(caught.value, http.UpstreamUnavailable) == (
        failure in {"status", "transport"}
    )
