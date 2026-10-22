"""Regression checks for incomplete or misleading upstream security data."""

import pytest

from mcp_maintainer_tools import server as s


CVE = "CVE-2021-44228"
CVE2 = "CVE-2021-45046"


@pytest.fixture
def no_network(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("Unexpected network call")
    monkeypatch.setattr(s, "get", fail)
    monkeypatch.setattr(s, "post", fail)


def test_osv_query_exposes_empty_paginated_page(monkeypatch):
    calls = []
    def post(url, **kwargs):
        calls.append((url, kwargs))
        return {"next_page_token": "next-page"}
    monkeypatch.setattr(s, "post", post)
    out = s.osv_query("example", "1.0.0", page_token="previous-page")
    assert out["has_more"] and out["page_count"] == 0
    assert out["next_page_token"] == "next-page"
    assert calls[0][1]["json"]["page_token"] == "previous-page"
    assert out["provider"] == "OSV" and out["retrieved_at"]


def test_osv_withdrawal_and_aliases_are_preserved(monkeypatch):
    record = {"id": "OSV-TEST-1", "withdrawn": "2026-01-01T00:00:00Z", "aliases": [CVE]}
    monkeypatch.setattr(s, "post", lambda *a, **k: {"vulns": [record]})
    out = s.osv_query("example", "1")
    assert out["vulns"][0]["withdrawn"] == record["withdrawn"]
    assert out["vulns"][0]["aliases"] == [CVE]
    assert not out["has_more"]


def test_osv_batch_preserves_per_package_pagination(monkeypatch):
    captured = {}
    def post(url, **kwargs):
        captured.update(kwargs["json"])
        return {"results": [{"vulns": [{"id": "TEST-1"}], "next_page_token": "a"}, {}]}
    monkeypatch.setattr(s, "post", post)
    out = s.osv_batch([{"name": "one", "version": "1", "page_token": "old"},
                       {"name": "two", "version": "2", "ecosystem": "PyPI"}])
    first, second = out["results"]
    assert first["has_more"] and first["next_page_token"] == "a"
    assert first["vuln_ids"] == ["TEST-1"]
    assert second["vuln_ids"] == [] and not second["has_more"]
    assert captured["queries"][0]["page_token"] == "old"
    assert captured["queries"][1]["package"]["ecosystem"] == "PyPI"


@pytest.mark.parametrize("response", [{"results": []}, {"results": [{}, {}]}, {"results": None}])
def test_osv_batch_rejects_missing_or_misaligned_results(monkeypatch, response):
    monkeypatch.setattr(s, "post", lambda *a, **k: response)
    with pytest.raises(s.UpstreamDataError):
        s.osv_batch([{"name": "one", "version": "1"}])


def test_empty_queries_do_not_contact_providers(no_network):
    assert s.osv_batch([])["results"] == []
    assert s.epss([])["queried"] is False
    assert s.kev_check([])["queried"] is False


def test_osv_details_retain_package_specific_fixes(monkeypatch):
    record = {
        "id": "TEST-1",
        "affected": [
            {"package": {"name": "one"}, "ranges": [{"events": [{"fixed": "1.2"}]}]},
            {"package": {"name": "two"}, "ranges": [{"events": [{"fixed": "9.0"}]}]},
        ],
        "references": [{"type": "WEB", "url": "https://example.org/advisory"}],
    }
    monkeypatch.setattr(s, "get", lambda *a, **k: record)
    out = s.osv_vuln("TEST-1")
    assert out["record"] == record
    assert "fixed_versions" not in out


def test_nvd_preserves_metric_attribution_and_header_auth(monkeypatch):
    captured = {}
    record = {"id": CVE, "metrics": {"cvssMetricV31": [
        {"source": "first.example", "cvssData": {"baseScore": 9.8}},
        {"source": "second.example", "cvssData": {"baseScore": 10.0}},
    ]}}
    def get(url, params, headers=None):
        captured.update({"url": url, "params": params, "headers": headers})
        return {"totalResults": 1, "vulnerabilities": [{"cve": record}]}
    monkeypatch.setenv("NVD_API_KEY", "synthetic-test-key")
    monkeypatch.setattr(s, "get", get)
    out = s.nvd_cve(CVE.lower())
    assert out["record"] == record and out["found"]
    assert captured["headers"] == {"apiKey": "synthetic-test-key"}
    assert captured["params"] == {"cveId": CVE}
    assert "synthetic-test-key" not in str(out)
    assert "synthetic-test-key" not in captured["url"]


@pytest.mark.parametrize("response", [
    {"totalResults": 1, "vulnerabilities": []},
    {"totalResults": 1, "vulnerabilities": [{"cve": {"id": CVE2}}]},
])
def test_nvd_does_not_call_incomplete_data_not_found(monkeypatch, response):
    monkeypatch.setattr(s, "get", lambda *a, **k: response)
    with pytest.raises(s.UpstreamDataError):
        s.nvd_cve(CVE)


def test_nvd_not_found_is_explicit(monkeypatch):
    monkeypatch.setattr(s, "get", lambda *a, **k: {"totalResults": 0, "vulnerabilities": []})
    assert s.nvd_cve(CVE)["found"] is False


def test_kev_is_refetched_and_keeps_catalog_provenance(monkeypatch):
    calls = []
    def get(*a, **k):
        calls.append(1)
        return {"catalogVersion": f"v{len(calls)}", "dateReleased": "2026-10-22T00:00:00Z", "count": 1,
                "vulnerabilities": [{"cveID": CVE, "requiredAction": "See vendor advisory"}]}
    monkeypatch.setattr(s, "get", get)
    first = s.kev_check([CVE.lower(), CVE2])
    second = s.kev_check([CVE])
    assert first["catalog_version"] == "v1" and second["catalog_version"] == "v2"
    assert first["hits"][CVE]["requiredAction"] == "See vendor advisory"
    assert first["not_in_kev"] == [CVE2] and len(calls) == 2


def test_epss_pagination_and_score_date(monkeypatch):
    calls = []
    def get(url, params):
        calls.append(params)
        cve = [CVE, CVE2][params["offset"]]
        return {"status": "OK", "total": 2, "offset": params["offset"],
                "data": [{"cve": cve, "epss": "0.5", "date": "2026-10-21"}]}
    monkeypatch.setattr(s, "get", get)
    first = s.epss([CVE, CVE2], limit=1)
    second = s.epss([CVE, CVE2], offset=first["next_offset"], limit=1)
    assert first["has_more"] and first["next_offset"] == 1
    assert first["data"][0]["date"] == "2026-10-21"
    assert not second["has_more"] and second["next_offset"] is None
    assert calls[0]["cve"] == f"{CVE},{CVE2}"


@pytest.mark.parametrize("response", [
    {"status": "ERROR", "data": [], "total": 0, "offset": 0},
    {"status": "OK", "data": [], "total": 1, "offset": 0},
    {"status": "OK", "data": [{"cve": CVE2}], "total": 1, "offset": 0},
    {"status": "OK", "data": [{"cve": CVE}], "total": 1, "offset": 5},
])
def test_epss_rejects_inconsistent_provider_results(monkeypatch, response):
    monkeypatch.setattr(s, "get", lambda *a, **k: response)
    with pytest.raises(s.UpstreamDataError):
        s.epss([CVE])


def test_depsdev_does_not_guess_latest_version(monkeypatch):
    calls = []
    def get(url):
        calls.append(url)
        key = {"system": "NPM", "name": "@example/package"}
        return {"packageKey": key,
                "versions": [{"versionKey": {**key, "version": "9.9.9"}},
                             {"versionKey": {**key, "version": "1.0.0"}}]}
    monkeypatch.setattr(s, "get", get)
    out = s.depsdev_package("@example/package")
    assert out["default"] is None and out["default_version_info"] is None
    assert out["version_count"] == 2 and len(calls) == 1
    assert calls[0].endswith("/%40example%2Fpackage")


def test_depsdev_uses_only_marked_default(monkeypatch):
    calls = []
    key = {"system": "NPM", "name": "example"}
    info = {"versionKey": {**key, "version": "1.0.0"},
            "licenses": ["MIT"], "advisoryKeys": [{"id": "TEST-1"}]}
    def get(url):
        calls.append(url)
        if len(calls) == 1:
            return {"packageKey": key, "versions": [
                {"versionKey": {**key, "version": "9.9.9"}},
                {"versionKey": {**key, "version": "1.0.0"}, "isDefault": True},
            ]}
        return info
    monkeypatch.setattr(s, "get", get)
    out = s.depsdev_package("example", "NPM")
    assert out["default"] == "1.0.0"
    assert out["default_version_info"] == info
    assert calls[1].endswith("/versions/1.0.0")


@pytest.mark.parametrize("call", [
    lambda: s.nvd_cve("not-a-cve"),
    lambda: s.kev_check([CVE] * 101),
    lambda: s.epss([CVE], offset=-1),
    lambda: s.epss([CVE], limit=0),
    lambda: s.epss([CVE], limit=True),
    lambda: s.osv_query("", "1"),
    lambda: s.osv_query("name", "1", page_token="\n"),
    lambda: s.osv_batch([{"name": "one"}]),
    lambda: s.osv_batch([{"name": "one", "version": "1", "url": "https://example.org"}]),
    lambda: s.osv_vuln(".."),
    lambda: s.depsdev_package("name", "https://example.org"),
])
def test_invalid_inputs_fail_before_network(no_network, call):
    with pytest.raises(ValueError):
        call()
