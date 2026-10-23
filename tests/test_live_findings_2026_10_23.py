"""Regressions for defects observed against live providers on 2026-10-23."""

import httpx
import pytest
import respx

from mcp_maintainer_tools import http
from mcp_maintainer_tools import server as s


@pytest.fixture(autouse=True)
def isolated_client(monkeypatch):
    monkeypatch.setattr(http, "_client", None)
    monkeypatch.setattr(http.time, "sleep", lambda _: None)
    yield
    if http._client is not None:
        http._client.close()


# deps.dev resolves crates.io names case-insensitively and treats "-" and "_"
# as the same crate: "Serde" -> "serde", "proc_macro2" -> "proc-macro2",
# "serde-json" -> "serde_json" (observed live on 2026-10-23).
@pytest.mark.parametrize(
    "requested,returned",
    [("Serde", "serde"), ("proc_macro2", "proc-macro2"), ("serde-json", "serde_json")],
)
def test_depsdev_accepts_cargo_name_equivalence(monkeypatch, requested, returned):
    key = {"system": "CARGO", "name": returned}
    monkeypatch.setattr(s, "get", lambda *a, **k: {"packageKey": key, "versions": []})
    assert s.depsdev_package(requested, "cargo")["package_key"] == key


@pytest.mark.parametrize(
    "requested,returned",
    [("serde", "serde_json"), ("serde-json", "serdejson"), ("tokio", "tokio-util")],
)
def test_depsdev_still_rejects_a_different_crate(monkeypatch, requested, returned):
    key = {"system": "CARGO", "name": returned}
    monkeypatch.setattr(s, "get", lambda *a, **k: {"packageKey": key, "versions": []})
    with pytest.raises(s.UpstreamDataError, match="package identity"):
        s.depsdev_package(requested, "cargo")


OSV_NOT_FOUND = {"code": 5, "message": "Vulnerability not found"}
OSV_BAD_ROUTE = {"code": 404, "message": "The current request is not defined by this API."}


def test_osv_vuln_reports_documented_absence_as_not_found():
    url = f"{s.OSV}/vulns/GHSA-0000-0000-0000"
    with respx.mock as mock:
        route = mock.get(url).respond(404, json=OSV_NOT_FOUND)
        out = s.osv_vuln("GHSA-0000-0000-0000")
        assert route.call_count == 1
    assert out["found"] is False
    assert out["id"] == "GHSA-0000-0000-0000"
    assert "record" not in out
    assert out["provider"] == "OSV" and out["source_url"] == url


def test_osv_vuln_success_marks_found():
    url = f"{s.OSV}/vulns/GHSA-1111-1111-1111"
    with respx.mock as mock:
        mock.get(url).respond(200, json={"id": "GHSA-1111-1111-1111"})
        out = s.osv_vuln("GHSA-1111-1111-1111")
    assert out["found"] is True and out["record"] == {"id": "GHSA-1111-1111-1111"}


@pytest.mark.parametrize(
    "status,body",
    [
        (404, OSV_BAD_ROUTE),
        (404, {"code": True, "message": "Vulnerability not found"}),
        (404, {"code": "5"}),
        (404, [5]),
        (404, "not json"),
        (404, {"code": 5, "pad": "x" * 2048}),
        (404, '{"code":5,"message":NaN}'),
        (404, '{"code":5,"code":5}'),
        (404, '{"code":5,"message":"\\ud800"}'),
        (404, '{"code":5.0}'),
        (500, OSV_NOT_FOUND),
        (403, OSV_NOT_FOUND),
    ],
)
def test_osv_vuln_other_errors_are_not_reported_as_absence(status, body):
    url = f"{s.OSV}/vulns/GHSA-0000-0000-0000"
    with respx.mock as mock:
        if isinstance(body, str):
            mock.get(url).respond(status, text=body)
        else:
            mock.get(url).respond(status, json=body)
        with pytest.raises(http.UpstreamError):
            s.osv_vuln("GHSA-0000-0000-0000")


def test_not_found_body_is_bounded_and_not_disclosed():
    marker = "synthetic-private-body"
    with respx.mock as mock:
        mock.get("https://upstream.example.test/x").respond(
            404, json={"code": 7, "message": marker}
        )
        with pytest.raises(http.UpstreamError) as caught:
            http.get("https://upstream.example.test/x", not_found_code=5)
    assert not isinstance(caught.value, http.UpstreamNotFound)
    assert marker not in str(caught.value)


def test_not_found_code_is_opt_in():
    with respx.mock as mock:
        mock.get("https://upstream.example.test/x").respond(404, json=OSV_NOT_FOUND)
        with pytest.raises(http.UpstreamUnavailable) as caught:
            http.get("https://upstream.example.test/x")
    assert not isinstance(caught.value, http.UpstreamNotFound)


def test_kev_fallback_unchanged_for_plain_404():
    catalog = {
        "catalogVersion": "1",
        "dateReleased": "2026-10-23T00:00:00Z",
        "count": 0,
        "vulnerabilities": [],
    }
    with respx.mock as mock:
        mock.get(s.KEV).respond(404, json=OSV_NOT_FOUND)
        mock.get(s.KEV_MIRROR).respond(200, json=catalog)
        assert s.kev_check(["CVE-2021-44228"])["fallback_used"] is True


def test_transport_failure_on_osv_vuln_is_not_absence():
    url = f"{s.OSV}/vulns/GHSA-0000-0000-0000"
    with respx.mock as mock:
        mock.get(url).mock(side_effect=httpx.ConnectError("synthetic"))
        with pytest.raises(http.UpstreamUnavailable):
            s.osv_vuln("GHSA-0000-0000-0000")
