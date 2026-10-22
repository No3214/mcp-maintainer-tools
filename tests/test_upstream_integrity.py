"""Reject incomplete security feeds and records for the wrong subject."""

import pytest

from mcp_maintainer_tools import server as s


CVE = "CVE-2021-44228"
CVE2 = "CVE-2024-3094"
PACKAGE_KEY = {"system": "NPM", "name": "example"}
VERSION_KEY = {**PACKAGE_KEY, "version": "1.0.0"}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("Unexpected network call")
    monkeypatch.setattr(s, "get", fail)
    monkeypatch.setattr(s, "post", fail)


def kev_catalog(**overrides):
    catalog = {
        "catalogVersion": "2026.10.22",
        "dateReleased": "2026-10-22T00:00:00Z",
        "count": 1,
        "vulnerabilities": [{"cveID": CVE}],
    }
    return {**catalog, **overrides}


@pytest.mark.parametrize("catalog", [
    kev_catalog(count=1500, vulnerabilities=[]),
    kev_catalog(count=True),
    kev_catalog(count="1"),
    kev_catalog(catalogVersion=""),
    kev_catalog(dateReleased=None),
    kev_catalog(vulnerabilities=[{"cveID": ""}]),
    kev_catalog(vulnerabilities=[{"cveID": "not-a-cve"}]),
    kev_catalog(count=2, vulnerabilities=[{"cveID": CVE}, {"cveID": CVE}]),
])
def test_kev_rejects_incomplete_or_ambiguous_catalog(monkeypatch, catalog):
    monkeypatch.setattr(s, "get", lambda *a, **k: catalog)
    with pytest.raises(s.UpstreamDataError):
        s.kev_check([CVE, CVE2])


@pytest.mark.parametrize("token", [0, False, [], {}, 42])
def test_osv_malformed_tokens_cannot_end_pagination(monkeypatch, token):
    monkeypatch.setattr(s, "post", lambda *a, **k: {"next_page_token": token})
    with pytest.raises(s.UpstreamDataError):
        s.osv_query("example", "1.0.0")


@pytest.mark.parametrize("token", [None, ""])
def test_osv_valid_terminal_token_remains_supported(monkeypatch, token):
    monkeypatch.setattr(s, "post", lambda *a, **k: {"next_page_token": token})
    out = s.osv_query("example", "1.0.0")
    assert not out["has_more"] and out["next_page_token"] is None


@pytest.mark.parametrize("record", [
    {"id": "OSV-OTHER"},
    {"id": ""},
    {"id": None},
    {"id": "OSV-OTHER", "aliases": ["OSV-REQUESTED"]},
])
def test_osv_details_must_match_exact_requested_id(monkeypatch, record):
    monkeypatch.setattr(s, "get", lambda *a, **k: record)
    with pytest.raises(s.UpstreamDataError):
        s.osv_vuln("OSV-REQUESTED")


def epss_response(**overrides):
    return {
        "status": "OK", "total": 2, "offset": 0,
        "data": [{"cve": CVE, "epss": "0.9", "percentile": "0.99"}],
        **overrides,
    }


@pytest.mark.parametrize("response,limit", [
    (epss_response(data=[{"cve": CVE}, {"cve": CVE}]), 2),
    (epss_response(data=[{"cve": CVE}, {"cve": CVE2}]), 1),
    (epss_response(total=0), 2),
    (epss_response(total=3), 2),
])
def test_epss_rejects_impossible_page_counts(monkeypatch, response, limit):
    monkeypatch.setattr(s, "get", lambda *a, **k: response)
    with pytest.raises(s.UpstreamDataError):
        s.epss([CVE, CVE2], limit=limit)


def test_epss_empty_page_beyond_end_is_valid(monkeypatch):
    response = epss_response(total=1, offset=2, data=[])
    monkeypatch.setattr(s, "get", lambda *a, **k: response)
    out = s.epss([CVE, CVE2], offset=2)
    assert out["data"] == [] and not out["has_more"]


def package_response(**overrides):
    return {
        "packageKey": PACKAGE_KEY,
        "versions": [{"versionKey": VERSION_KEY, "isDefault": True}],
        **overrides,
    }


@pytest.mark.parametrize("info", [
    {"versionKey": {**VERSION_KEY, "name": "another-package"}},
    {"versionKey": {**VERSION_KEY, "version": "9.0.0"}},
    {"versionKey": {**VERSION_KEY, "system": "PYPI"}},
    {"versionKey": None},
    {},
])
def test_depsdev_details_must_match_selected_version(monkeypatch, info):
    responses = iter([package_response(), info])
    monkeypatch.setattr(s, "get", lambda *a, **k: next(responses))
    with pytest.raises(s.UpstreamDataError):
        s.depsdev_package("example")


@pytest.mark.parametrize("package", [
    package_response(packageKey=None),
    package_response(packageKey={"system": "PYPI", "name": "example"}),
    package_response(packageKey={"system": "NPM", "name": ""}),
    package_response(versions=[{"versionKey": None, "isDefault": True}]),
    package_response(versions=[{
        "versionKey": {**VERSION_KEY, "name": "another-package"}, "isDefault": True,
    }]),
])
def test_depsdev_rejects_invalid_canonical_keys(monkeypatch, package):
    monkeypatch.setattr(s, "get", lambda *a, **k: package)
    with pytest.raises(s.UpstreamDataError):
        s.depsdev_package("example")


def test_depsdev_accepts_provider_canonicalization(monkeypatch):
    key = {"system": "PYPI", "name": "some-package"}
    version_key = {**key, "version": "1.0.0"}
    info = {"versionKey": version_key, "licenses": ["MIT"]}
    responses = iter([
        {"packageKey": key, "versions": [{"versionKey": version_key, "isDefault": True}]},
        info,
    ])
    calls = []
    def get(url):
        calls.append(url)
        return next(responses)
    monkeypatch.setattr(s, "get", get)
    out = s.depsdev_package("Some_Package", "pypi")
    assert out["package_key"] == key
    assert out["default_version_info"] == info
    assert calls[1].endswith("/packages/some-package/versions/1.0.0")


@pytest.mark.parametrize("total", [0, 2, True, "1", None])
def test_nvd_requires_exact_integer_result_total(monkeypatch, total):
    response = {"totalResults": total, "vulnerabilities": [{"cve": {"id": CVE}}]}
    monkeypatch.setattr(s, "get", lambda *a, **k: response)
    with pytest.raises(s.UpstreamDataError):
        s.nvd_cve(CVE)


@pytest.mark.parametrize("cve_record", [None, [], "unexpected-upstream-content", 42])
def test_nvd_malformed_cve_has_safe_error(monkeypatch, cve_record):
    response = {"totalResults": 1, "vulnerabilities": [{"cve": cve_record}]}
    monkeypatch.setattr(s, "get", lambda *a, **k: response)
    with pytest.raises(s.UpstreamDataError) as exc:
        s.nvd_cve(CVE)
    assert "unexpected-upstream-content" not in str(exc.value)


def test_nvd_boolean_zero_cannot_claim_not_found(monkeypatch):
    response = {"totalResults": False, "vulnerabilities": []}
    monkeypatch.setattr(s, "get", lambda *a, **k: response)
    with pytest.raises(s.UpstreamDataError):
        s.nvd_cve(CVE)
