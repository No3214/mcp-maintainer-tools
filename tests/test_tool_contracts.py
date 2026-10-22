"""Exercise tool validation through MCP and against malformed provider records."""

import asyncio
import traceback

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from mcp_maintainer_tools import __version__
from mcp_maintainer_tools import server as s

CVE = "CVE-2021-44228"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("Unexpected network call")

    monkeypatch.setattr(s, "get", fail)
    monkeypatch.setattr(s, "post", fail)


def _epss_response(**fields):
    return {
        "status": "OK",
        "total": 1,
        "offset": 0,
        "data": [
            {
                "cve": CVE,
                "epss": "0.500000000",
                "percentile": "0.900000000",
                "date": "2026-10-22",
                **fields,
            }
        ],
    }


@pytest.mark.parametrize(
    "system,requested,returned",
    [
        ("npm", "requested", "unrelated"),
        ("pypi", "Requested_Package", "unrelated-package"),
        ("nuget", "Requested.Package", "unrelated.package"),
    ],
)
def test_depsdev_rejects_unrelated_package_identity(monkeypatch, system, requested, returned):
    response = {"packageKey": {"system": system.upper(), "name": returned}, "versions": []}
    monkeypatch.setattr(s, "get", lambda *a, **k: response)
    with pytest.raises(s.UpstreamDataError, match="package identity"):
        s.depsdev_package(requested, system)


@pytest.mark.parametrize(
    "system,requested,canonical",
    [
        ("npm", "@scope/example", "@scope/example"),
        ("pypi", "Some._-Package", "some-package"),
        ("nuget", "Some.Package", "some.package"),
        ("cargo", "some_crate", "some_crate"),
        ("go", "example.org/Some/Module", "example.org/Some/Module"),
        ("maven", "org.example:Artifact", "org.example:Artifact"),
        ("rubygems", "SomeGem", "SomeGem"),
    ],
)
def test_depsdev_keeps_documented_package_canonicalization(
    monkeypatch, system, requested, canonical
):
    key = {"system": system.upper(), "name": canonical}
    monkeypatch.setattr(s, "get", lambda *a, **k: {"packageKey": key, "versions": []})
    assert s.depsdev_package(requested, system)["package_key"] == key


@pytest.mark.parametrize("flag", ["true", "false", 1, 0, None])
def test_depsdev_rejects_malformed_default_flag(monkeypatch, flag):
    key = {"system": "NPM", "name": "example"}
    response = {
        "packageKey": key,
        "versions": [
            {"versionKey": {**key, "version": "1"}, "isDefault": flag},
        ],
    }
    monkeypatch.setattr(s, "get", lambda *a, **k: response)
    with pytest.raises(s.UpstreamDataError):
        s.depsdev_package("example")


@pytest.mark.parametrize(
    "field,value",
    [
        ("epss", "NaN"),
        ("epss", "Infinity"),
        ("epss", "-0.01"),
        ("epss", "1.01"),
        ("epss", True),
        ("epss", None),
        ("epss", {"score": "0.5"}),
        ("epss", "not-a-number"),
        ("percentile", "NaN"),
        ("percentile", "-1"),
        ("percentile", "1.1"),
        ("percentile", False),
        ("percentile", None),
        ("date", "yesterday"),
        ("date", "2026-02-30"),
        ("date", "20261022"),
        ("date", "2026-10-22T00:00:00Z"),
        ("date", None),
    ],
)
def test_epss_rejects_invalid_probability_or_date(monkeypatch, field, value):
    monkeypatch.setattr(s, "get", lambda *a, **k: _epss_response(**{field: value}))
    with pytest.raises(s.UpstreamDataError):
        s.epss([CVE])


@pytest.mark.parametrize("field", ["epss", "percentile", "date"])
def test_epss_requires_all_score_fields(monkeypatch, field):
    response = _epss_response()
    del response["data"][0][field]
    monkeypatch.setattr(s, "get", lambda *a, **k: response)
    with pytest.raises(s.UpstreamDataError):
        s.epss([CVE])


@pytest.mark.parametrize("score", ["0", "1", "0.500000000", 0, 1, 0.5])
def test_epss_valid_probabilities_preserve_original_precision(monkeypatch, score):
    response = _epss_response(epss=score, percentile=score)
    monkeypatch.setattr(s, "get", lambda *a, **k: response)
    assert s.epss([CVE])["data"] == response["data"]


@pytest.mark.parametrize(
    "arguments",
    [
        {"cve_ids": [], "offset": True},
        {"cve_ids": [], "offset": "0"},
        {"cve_ids": [], "offset": 0.0},
        {"cve_ids": [], "limit": True},
        {"cve_ids": [], "limit": "1"},
        {"cve_ids": [], "limit": 1.0},
    ],
)
def test_mcp_cannot_coerce_invalid_integer_arguments(arguments):
    with pytest.raises(ToolError):
        asyncio.run(s.mcp.call_tool("epss", arguments))


def test_mcp_validation_errors_do_not_echo_argument_values():
    marker = "private-argument-marker"
    with pytest.raises(ToolError) as exc:
        asyncio.run(s.mcp.call_tool("epss", {"cve_ids": [], "limit": marker}))
    assert "Invalid tool arguments" in str(exc.value)
    assert marker not in str(exc.value)
    assert marker not in "".join(traceback.format_exception(exc.value))


def test_mcp_schema_exposes_resource_bounds():
    tools = {tool.name: tool for tool in asyncio.run(s.mcp.list_tools())}
    osv = tools["osv_query"].inputSchema["properties"]
    assert osv["name"]["maxLength"] == 1000
    assert osv["version"]["maxLength"] == 1000
    assert osv["ecosystem"]["maxLength"] == 100
    assert tools["osv_batch"].inputSchema["properties"]["packages"]["maxItems"] == 100
    package = tools["osv_batch"].inputSchema["$defs"]["PackageQuery"]
    assert package["additionalProperties"] is False
    assert set(package["required"]) == {"name", "version"}
    assert package["properties"]["name"]["maxLength"] == 1000
    epss = tools["epss"].inputSchema["properties"]
    assert epss["cve_ids"]["maxItems"] == 100
    assert epss["cve_ids"]["items"]["maxLength"] == 64
    assert epss["offset"]["minimum"] == 0
    assert epss["limit"]["minimum"] == 1
    assert epss["limit"]["maximum"] == 100


def test_empty_osv_batch_does_not_claim_data_retrieval():
    result = s.osv_batch([])
    assert result["queried"] is False
    assert "retrieved_at" not in result
    assert result["results"] == []


@pytest.mark.parametrize(
    "records",
    [
        [{"id": " "}],
        [{"id": "OSV-1\nINJECTED"}],
        [{"id": "OSV-1"}, {"id": "OSV-1"}],
    ],
)
def test_osv_rejects_invalid_or_duplicate_record_ids(monkeypatch, records):
    monkeypatch.setattr(s, "post", lambda *a, **k: {"vulns": records})
    with pytest.raises(s.UpstreamDataError):
        s.osv_query("example", "1")


@pytest.mark.parametrize("value", ["bad\ud800", "bad\udfff", "bad\x85"])
def test_malformed_unicode_inputs_fail_before_network(value):
    with pytest.raises(ValueError, match="Unicode text"):
        s.osv_vuln(value)


def test_normal_unicode_package_text_remains_supported(monkeypatch):
    monkeypatch.setattr(s, "post", lambda *a, **k: {})
    assert s.osv_query("example-\U0001f4e6", "1")["package"]["name"] == "example-\U0001f4e6"


def _long_cves(last_length):
    return [f"CVE-2026-{index:055d}" for index in range(30)] + [
        "CVE-2026-" + "9" * (last_length - 9)
    ]


def test_epss_accepts_exact_2000_character_query(monkeypatch):
    ids = _long_cves(50)
    assert len(",".join(ids)) == 2000
    calls = []

    def get(url, params):
        calls.append(params)
        return {"status": "OK", "total": 0, "offset": 0, "data": []}

    monkeypatch.setattr(s, "get", get)
    assert s.epss(ids)["queried"] is True
    assert calls[0]["cve"] == ",".join(ids)


def test_epss_rejects_query_over_2000_characters_before_network():
    ids = _long_cves(51)
    assert len(",".join(ids)) == 2001
    with pytest.raises(ValueError, match="2000-character"):
        s.epss(ids)


def test_mcp_batch_accepts_explicit_null_page_token(monkeypatch):
    calls = []

    def post(url, **kwargs):
        calls.append(kwargs["json"])
        return {"results": [{}]}

    monkeypatch.setattr(s, "post", post)
    asyncio.run(
        s.mcp.call_tool(
            "osv_batch",
            {
                "packages": [
                    {"name": "example", "version": "1", "page_token": None},
                ]
            },
        )
    )
    assert calls == [
        {"queries": [{"package": {"name": "example", "ecosystem": "npm"}, "version": "1"}]}
    ]


def test_mcp_batch_rejects_unrecognized_fields_before_network():
    with pytest.raises(ToolError, match="Invalid tool arguments"):
        asyncio.run(
            s.mcp.call_tool(
                "osv_batch",
                {
                    "packages": [
                        {"name": "example", "version": "1", "unknown": "private-value"},
                    ]
                },
            )
        )


@pytest.mark.parametrize("token", ["null", "[]", "{}", "true", "123", '"quoted"'])
def test_mcp_preserves_opaque_page_token_strings(monkeypatch, token):
    requests = []

    def post(url, **kwargs):
        requests.append(kwargs["json"])
        return {}

    monkeypatch.setattr(s, "post", post)
    arguments = {"name": "example", "version": "1", "page_token": token}
    asyncio.run(s.mcp.call_tool("osv_query", arguments))
    assert requests[0]["page_token"] == token
    assert arguments["page_token"] == token


def test_mcp_explicit_null_means_no_page_token(monkeypatch):
    requests = []

    def post(url, **kwargs):
        requests.append(kwargs["json"])
        return {}

    monkeypatch.setattr(s, "post", post)
    asyncio.run(
        s.mcp.call_tool("osv_query", {"name": "example", "version": "1", "page_token": None})
    )
    assert "page_token" not in requests[0]


@pytest.mark.parametrize("token", ["null", "[]", "{}"])
def test_mcp_batch_preserves_opaque_page_token_strings(monkeypatch, token):
    requests = []

    def post(url, **kwargs):
        requests.append(kwargs["json"])
        return {"results": [{}]}

    monkeypatch.setattr(s, "post", post)
    asyncio.run(
        s.mcp.call_tool(
            "osv_batch",
            {
                "packages": [
                    {"name": "example", "version": "1", "page_token": token},
                ]
            },
        )
    )
    assert requests[0]["queries"][0]["page_token"] == token


@pytest.mark.parametrize(
    "tool,arguments",
    [
        ("epss", {"cve_ids": "[]"}),
        ("osv_batch", {"packages": "[]"}),
    ],
)
def test_mcp_requires_declared_json_container_types(tool, arguments):
    with pytest.raises(ToolError, match="Invalid tool arguments"):
        asyncio.run(s.mcp.call_tool(tool, arguments))


def test_protocol_metadata_uses_application_version():
    assert s.mcp._mcp_server.create_initialization_options().server_version == __version__
