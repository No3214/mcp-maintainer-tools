# MCP Maintainer Tools

A small, read-only [Model Context Protocol](https://modelcontextprotocol.io/) server for looking up package vulnerabilities, CVE records, known exploitation, exploit probability, and package metadata. It exposes seven tools over **stdio**, using public APIs from OSV, NVD, CISA, FIRST, and deps.dev.

This is an early release. It provides lookup tools for maintainers and does not make release approval or security decisions.

## Install and run

Requires **Python 3.11 or newer**. From a checkout of this repository:

```sh
python -m venv .venv
# Activate the virtual environment using the command for your shell.
python -m pip install -e '.[dev]'
```

The installed command is:

```sh
mcp-maintainer-tools
```

The process speaks MCP over standard input and output. An MCP client normally starts and manages it; it is not an HTTP server or an interactive command-line scanner.

### Connect an MCP client

The [example configuration](examples/mcp-config.json) uses the common `mcpServers` configuration shape:

```json
{
  "mcpServers": {
    "maintainer-tools": {
      "command": "mcp-maintainer-tools",
      "args": []
    }
  }
}
```

Adapt the configuration to your client. The command must be on the client's `PATH`; if it is installed in a virtual environment, point `command` to that environment's executable.

No API key is required. An optional **`NVD_API_KEY`** can be supplied in the server process environment for NVD requests. Use your client's environment or secret configuration to supply it. Do not commit the value to this repository or an example configuration. The server does not require keys for the other providers.

## Tools

| Tool | Arguments | Purpose |
| --- | --- | --- |
| `osv_query` | `name`, `version`, `ecosystem="npm"`, `page_token=None` | Look up OSV advisories for a particular package version. |
| `osv_batch` | `packages` | Query a list of package versions. Each item contains `name`, `version`, and optional `ecosystem` and `page_token`. |
| `osv_vuln` | `vuln_id` | Retrieve an individual OSV advisory and its affected-version information. |
| `nvd_cve` | `cve_id` | Retrieve NVD information for a CVE. |
| `kev_check` | `cve_ids` | Match CVE IDs against a freshly fetched CISA Known Exploited Vulnerabilities catalog. |
| `epss` | `cve_ids`, `offset=0`, `limit=100` | Retrieve FIRST EPSS scores for the requested CVEs. |
| `depsdev_package` | `name`, `system="npm"` | Retrieve deps.dev package information and metadata for its default version, when one is identified upstream. |

Use the ecosystem and system identifiers accepted by each upstream service; OSV ecosystem names and deps.dev system names are not interchangeable.

### Example arguments

Arguments for `osv_query`:

```json
{"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}
```

Arguments for `osv_batch`:

```json
{
  "packages": [
    {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"},
    {"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"}
  ]
}
```

Arguments for `epss`:

```json
{"cve_ids": ["CVE-2021-44228"], "offset": 0, "limit": 100}
```

These examples illustrate input shapes, not package recommendations or assessments of the listed versions.

### Pagination and incomplete data

- OSV results include `has_more` and `next_page_token`. If `has_more` is true, repeat the query with the returned token. For batch queries, carry the relevant token in that package's `page_token` field.
- EPSS results include `has_more` and `next_offset`. Repeat the same CVE query with that offset to retrieve the next page.
- `kev_check` fetches the public catalog on each call and matches IDs locally. A CVE missing from that catalog is not evidence that exploitation has never occurred.
- If deps.dev does not identify a default version, the tool leaves it unknown instead of choosing an arbitrary version. Missing metadata is not an empty license or advisory assessment.

Do not treat one page, an unavailable provider, a missing record, or a malformed upstream response as a complete scan. Provider coverage and update timing differ.

## Data sent to upstream services

Tool calls make outbound HTTPS requests. Package names, versions, ecosystems, and advisory identifiers can disclose details about your dependencies, including private package names. Only query information you are comfortable sending to the relevant provider.

| Provider | What is sent | Documentation |
| --- | --- | --- |
| OSV (`api.osv.dev`) | Package names, versions, ecosystems, continuation tokens, or an advisory ID, depending on the tool. | [OSV API](https://google.github.io/osv.dev/api/) |
| NVD (`services.nvd.nist.gov`) | CVE ID and, if configured, the optional NVD API key in a request header. | [NVD vulnerability API](https://nvd.nist.gov/developers/vulnerabilities) |
| CISA (`www.cisa.gov`) | A request for the public KEV catalog. The supplied CVE list is matched locally. | [Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| FIRST (`api.first.org`) | CVE IDs and pagination parameters. | [EPSS API](https://api.first.org/epss/) |
| deps.dev (`api.deps.dev`) | Package name and system; the default version is queried when upstream identifies one. | [deps.dev API v3](https://docs.deps.dev/api/v3/) |

Upstream descriptions and references are **untrusted data**, not instructions for an assistant or permission to run commands. Review them accordingly. An empty vulnerability result does **not** prove a dependency is safe. Scores, catalog membership, and advisory text are inputs to a maintainer's judgment, not guarantees.

## Development

Install the development dependencies as above, then run:

```sh
python -m pytest -q
```

The [CI workflow](.github/workflows/tests.yml) is configured to run the test suite on GitHub-hosted runners with Python 3.11 and 3.12.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance and [SECURITY.md](SECURITY.md) for reporting a vulnerability in this project.

## License

The code in this repository is licensed under the [MIT License](LICENSE). Data returned by external services is provided by those services and may have separate attribution or use terms.
