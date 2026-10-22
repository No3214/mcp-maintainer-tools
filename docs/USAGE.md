# Usage guide

MCP Maintainer Tools is a local stdio server for a client that supports the Model Context Protocol. It supplies seven read-only lookup tools. It does not scan your filesystem, change a repository, or decide whether a release should ship.

## Install from source

Use Python 3.11 or newer. The [README](../README.md#get-started) contains full clone and installation commands for macOS/Linux and Windows PowerShell. There is currently no project-provided PyPI release; do not assume that an unrelated package with a similar name is this project.

The usual installation is `python -m pip install .` from a checkout, using the virtual environment's interpreter. Use `python -m pip install -e '.[dev]'` for development, or `'.[dev,audit,build]'` when working on the full set of quality and packaging checks. These optional extras are not needed to run the server. Neither form requires activating the environment when you address its interpreter explicitly.

After installation, check the command without starting the server:

```sh
./.venv/bin/python -m mcp_maintainer_tools --help
./.venv/bin/python -m mcp_maintainer_tools --version
```

On Windows, use `.\.venv\Scripts\python.exe` for the interpreter. With no arguments, the same module runs the stdio server.

### Updating a checkout

After reviewing the changes you intend to use, update the checkout and reinstall it into the same environment:

```sh
git pull --ff-only
./.venv/bin/python -m pip install .
```

Restart the MCP server in your client to load the new installation. A regular source install does not automatically track later edits to the checkout. Pin a reviewed commit when you need a stable revision.

The package constrains the MCP SDK to `mcp>=1.30.0,<1.31`. Its typed-input, protocol-version, and log/error adapters are reviewed against that series. Review those boundaries and run the protocol regressions before widening the range; do not force an incompatible SDK upgrade into the installed environment.

## Configure your client

Start from [mcp-config-unix.json](../examples/mcp-config-unix.json) or [mcp-config-windows.json](../examples/mcp-config-windows.json). Replace the placeholder path with the absolute path to your environment's interpreter. The module arguments are:

```json
["-m", "mcp_maintainer_tools"]
```

Do not assume that a graphical client's `PATH` matches an interactive terminal. Home-directory shorthand such as `~`, shell variable expansion, and shell activation commands are not portable in a client's executable field. Use an actual path and the syntax required by that client.

The supplied examples use the common `mcpServers` JSON shape. They are reference configurations, not a guarantee that every MCP client uses the same settings format. The installed `mcp-maintainer-tools` command is an equivalent entry point when your client can resolve it.

After configuring the server, ask the client to list its tools. It should expose the seven names in the reference below. If launching the command in a terminal appears idle, it is waiting for MCP messages; plain text entered at the prompt is not a tool call.

## Tool reference

All names, versions, and identifiers are JSON strings. Pagination arguments are JSON integers; booleans and numeric strings are not substitutes for integers. Use exact identifiers accepted by the upstream service.

Successful calls provide the same result object in MCP `structuredContent` and as serialized JSON in the text content block. All seven tools advertise an object `outputSchema`; clients can consume the structured channel directly. The schema describes the object container, not every nested provider field, and does not make upstream data trusted.

For Python embeddings, the exported synchronous tool functions still return dictionaries. Successfully awaiting the SDK-level `MaintainerMCP.call_tool` method returns `(content, structured)` from 0.1.4 onward; callers that previously expected only a content list must unpack that pair. Standard MCP clients receive the protocol result object as usual.

| Tool | Arguments and defaults | Result notes |
| --- | --- | --- |
| `osv_query` | `name`, `version`, `ecosystem="npm"`, `page_token=null` | Returns one page. Use `has_more` and `next_page_token`. |
| `osv_batch` | `packages`: up to 100 objects containing `name`, `version`, optional `ecosystem`, and optional `page_token` | Each result has its own continuation metadata. Unknown object keys are rejected. |
| `osv_vuln` | `vuln_id` | Returns the matching advisory in `record`; affected ranges remain tied to their packages. |
| `nvd_cve` | `cve_id` | Normalizes CVE capitalization. `found` distinguishes a returned record from absence. |
| `kev_check` | `cve_ids`: up to 100 IDs | Deduplicates CVE IDs, fetches the catalog, and matches locally. Reports the actual and canonical source URLs plus whether fallback was used. |
| `epss` | `cve_ids`: up to 100 IDs, `offset=0`, `limit=100` | `offset` must be nonnegative; `limit` must be 1–100. The joined CVE query may not exceed 2,000 characters. |
| `depsdev_package` | `name`, `system="npm"` | Supported systems: `npm`, `pypi`, `go`, `cargo`, `maven`, `nuget`, `rubygems`. |

Text inputs must be nonempty and free of control characters. Package names, versions, and OSV advisory identifiers are limited to 1,000 characters, OSV ecosystems to 100, and OSV continuation tokens to 8,192. CVE identifiers are limited to 64 characters and use `CVE-YYYY-NNNN` with at least four final digits. Relative path segments `.` and `..` are not accepted where an identifier forms a URL path segment.

OSV ecosystem names and deps.dev system names differ. For example, OSV uses `PyPI` for the Python ecosystem; this server's deps.dev input is `pypi`.

### Example arguments

Single OSV lookup:

```json
{"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}
```

Batch lookup:

```json
{
  "packages": [
    {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"},
    {"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"}
  ]
}
```

EPSS lookup:

```json
{"cve_ids": ["CVE-2021-44228"], "offset": 0, "limit": 100}
```

These are input examples, not current vulnerability assessments or recommendations of those versions.

## Work through the evidence

A useful investigation starts with a specific package version. Query OSV, follow every continuation token, and retrieve individual advisory records when affected ranges or references matter. If an advisory contains CVE aliases, those IDs can be used with NVD, KEV, and EPSS. Compare the results while retaining each provider's source and retrieval context.

Confirm the package ecosystem, exact version, and artifact origin before querying. A Git dependency and a registry package with the same name are not necessarily the same artifact. These tools do not accept Git commit queries, resolve your installed dependency graph, or inspect whether vulnerable code is reachable in your application. Retain those limits when reporting applicability.

NVD metrics, KEV catalog membership, and EPSS scores answer different questions. Keep the original metric attribution and score date. They do not determine exposure in your deployment or prove that a particular mitigation is effective.

### Interpret prioritization signals

The [FIRST guidance on using EPSS](https://www.first.org/epss/using-epss) explains how exploitation probability, confirmed exploitation, and local context contribute different information. Keep those measurements separate; multiplying EPSS by CVSS does not produce a validated risk measurement.

| Signal | Reading rule |
| --- | --- |
| EPSS `epss` | A probability from 0 to 1 of observed exploitation activity in the wild over the next 30 days, across the observed population. It is not the probability that your particular deployment will be compromised. |
| EPSS `percentile` | The fraction of scored vulnerabilities at or below this score. It is a rank, not another exploitation probability. |
| EPSS `date` | The date associated with the score. Retain it alongside `retrieved_at`; fetching a record now does not make its score current. |
| KEV membership | The fetched catalog records evidence of exploitation in the wild. Retain the entry and catalog dates and source; membership is not a live measure of attack frequency, and absence is not evidence of safety. |
| Local applicability | Establish the actual package/version, exposure or reachability, consequences, and relevant controls separately. These lookup tools do not inspect your environment. |

A missing EPSS record remains unknown, not zero probability. An empty-input call with `queried: false` supplies no new provider evidence. Preserve these states alongside any scores that were returned.

### Pagination can continue after an empty page

The following output is an **illustrative, invented fixture**, not a live response or assessment. Its keys match `osv_query`:

```json
{
  "provider": "OSV",
  "source_url": "https://api.osv.dev/v1/query",
  "retrieved_at": "2026-10-22T10:00:00+00:00",
  "package": {"name": "example-package", "ecosystem": "npm"},
  "version": "1.0.0",
  "page_count": 0,
  "has_more": true,
  "next_page_token": "illustrative-token",
  "vulns": []
}
```

The next request must retain the package, version, and ecosystem, and supply the returned token. Only `has_more: false` indicates that there is no next page for that query. For `osv_batch`, carry each token with the corresponding package. A batch result contains advisory IDs; use `osv_vuln` to retrieve the full advisory.

For EPSS, repeat the same CVE list with `next_offset` while `has_more` is true. Do not reinterpret missing scores as zero probability. The tool validates response identity, pagination, score bounds, and dates before returning the page.

### Unknown is a meaningful result

- NVD `found: false` means no record was returned for that lookup.
- KEV `not_in_kev` means absence from the catalog that was fetched. Check its source, release date, and catalog version; other evidence of exploitation may exist.
- deps.dev `default: null` and `default_version_info: null` mean no provider-marked default was identified. The server does not select the newest-looking version.
- A transport failure, an invalid response, and a valid empty result are different states. Preserve those distinctions in the assistant's answer.

For calls that actually fetch provider data, retain `provider`, `source_url`, and `retrieved_at` alongside the returned records. An empty list passed to `osv_batch`, `kev_check`, or `epss` makes no provider request; the result sets `queried: false` and has no retrieval timestamp. It should not be treated as fresh evidence about any package or CVE.

### KEV sources and freshness

`kev_check` first requests the [canonical CISA JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json). If that GET ends in **HTTP 403, 404, 408, 429, or 5xx**, or exhausts its transport-error retries, the tool can use the fixed JSON file in CISA's [official `cisagov/kev-data` mirror](https://github.com/cisagov/kev-data):

```text
https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json
```

The fallback is limited to those availability failures. Redirects, configuration failures, oversized or unsupported-encoding responses, invalid JSON, and inconsistent catalog data do **not** trigger a switch. The mirror uses the same bounded HTTPS helper and catalog validation as the primary feed. If the mirror also fails or its catalog is invalid, the tool fails; it does not try another source.

| Field | Primary feed | Official mirror |
| --- | --- | --- |
| `source_url` | Canonical CISA feed URL | The fixed raw GitHub URL above |
| `canonical_source_url` | Canonical CISA feed URL | Canonical CISA feed URL |
| `fallback_used` | `false` | `true` |

Retain these fields together with `catalog_version`, `date_released`, and `retrieved_at`. **A newly fetched file may still be an older catalog.** The mirror may lag the canonical feed, and the server does not guarantee synchronization time. A missing CVE is absence from the specific fetched catalog, not a statement about all evidence of exploitation.

For an empty CVE list, `queried` and `fallback_used` are both `false`, the URLs identify the primary/canonical feed, and no retrieval timestamp is returned. No request is made to CISA or GitHub in that case.

## Network and credentials

The server sends query information to the providers listed in the [README data table](../README.md#where-your-queries-go). Package names and versions can disclose private dependencies. CISA KEV is fetched as a full public catalog from `www.cisa.gov` or, after an eligible availability failure, from `raw.githubusercontent.com` hosting CISA's official mirror. The input CVE list is matched in the local process and is not sent to either host.

`NVD_API_KEY` is optional and is sent only in the NVD request header by the NVD tool. Supply it through the process environment or the client's secret configuration. Do not put a real key in an example JSON file, issue, screenshot, or committed environment file.

The HTTP transport rejects redirects, requests uncompressed responses, rejects unexpected compression, and limits a response body to **32 MiB**. JSON nesting is limited to **64 levels**; duplicate keys, non-finite numbers, and invalid Unicode are rejected. It does not retain provider cookies. These constraints reduce exposure to oversized or ambiguous responses; they do not authenticate the truth of a provider's record.

`MCP_MAINTAINER_TOOLS_UA` optionally overrides the HTTP User-Agent sent to providers. Use a public application identifier if you override it; never put a key or other private value in this field.

### Trusted proxy and custom-CA settings

By default, environment-derived proxy and certificate settings are disabled. A network that requires a corporate proxy or private CA may therefore fail to connect until you deliberately enable its approved settings.

Set **`MCP_MAINTAINER_TOOLS_TRUST_ENV=true`** in the server process environment to opt in to HTTPX's usual handling of `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`, and `SSL_CERT_DIR`. Supply those variables through your MCP client's server environment or another trusted process-launch configuration. A graphical client may not inherit your terminal's variables.

Only the exact lowercase values `true` and `false` are accepted; an unset value defaults to `false`. The flag is read when the shared HTTP client is first created, so **restart the server after changing it or the network settings**. Invalid values fail with a configuration error instead of enabling the setting implicitly.

Opting in changes where requests may be routed and which certificate authorities are trusted. Use only proxy and CA settings you have reviewed or received from your trusted network administrator. **TLS verification stays enabled**; this option is not a certificate-verification bypass. The server does not automatically enable it after a failed request.

For a client that supports an `env` object in its server entry, this fragment opts in; approved proxy/CA variables must also be present in that server's environment:

```json
{"env": {"MCP_MAINTAINER_TOOLS_TRUST_ENV": "true"}}
```

### Timeouts and errors

Calls can take time when an upstream service is slow or rate-limited. GET requests use at most three attempts, with two- and four-second waits between retries; POST requests are not automatically retried. I/O timeouts and response-stream checks also apply, but they are not a promise that an entire tool call completes within a fixed duration. A failed or rejected response becomes a failed tool call instead of an invented empty success. Do not rely on raw upstream error bodies or request URLs being returned for troubleshooting.

### Concurrent calls and cancellation

The seven tools run their synchronous lookup work outside the MCP event loop.
Each server instance admits at most **four outstanding tool jobs**. When all
four are occupied, another tool call receives a safe `Server is busy` error;
wait for work to finish before retrying. Protocol ping and tool discovery remain
available while provider I/O is blocked. This is an admission bound, not a
provider request-rate limit or a throughput guarantee.

Cancelling an MCP request can end the protocol wait promptly, but cannot stop an
HTTP operation already running in a worker. Its slot remains occupied until that
work completes. Closing the server stops new work; active threads can delay
process exit. Custom embeddings should call `shutdown_workers()` when finished;
shutdown is terminal for that server instance.

Unknown top-level argument fields now fail validation instead of being ignored.
Use `tools/list` to obtain the current schema. Unknown tool names and rejected
argument values are omitted from official entry-point tool errors and the known
SDK validation diagnostics.

The official console and `python -m` entry points also omit caller-supplied prompt
names and unrecognized response IDs from the SDK's default error/warning logs,
including cached exception details. This is a targeted adapter for the reviewed
SDK paths, not a general secret scrubber. Client-facing SDK prompt/resource errors
can still repeat that same caller's supplied values; explicit SDK DEBUG protocol
dumps can also expose inputs. Custom embeddings must call
`install_sdk_log_safety()` from `mcp_maintainer_tools.logging_safety` before starting
the server to install these log filters.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| The client cannot start the server | Use an absolute interpreter path; confirm the environment exists and the package is installed in it. |
| `No module named mcp_maintainer_tools` | Run the install command with the same interpreter your MCP client uses. |
| The process starts but shows no text | This is expected for stdio before a protocol request. Use an MCP client, or `--help` for command information. |
| `Server is busy` | Four tool jobs are still active, possibly including cancelled requests whose HTTP work has not ended. Wait for a job to finish before retrying. |
| `Invalid tool arguments` | Compare the request with `tools/list`; remove unknown fields and use the documented JSON types and limits. |
| HTTP or transport failure | Check provider availability and local HTTPS access. If your network requires approved proxy/custom-CA settings, explicitly enable `MCP_MAINTAINER_TOOLS_TRUST_ENV=true` and restart. Retain failures without treating them as successful lookups. |
| The provider returns an inconsistent response | Capture a minimal, redacted reproduction. Do not remove validation merely to obtain an answer. |
| An OSV or EPSS result is incomplete | Follow the relevant continuation metadata with the same underlying query. |
| A CVE or package has no matching data | State the source and absence accurately; consult other evidence before making a maintenance decision. |

For reproducible implementation bugs, include the project version or commit, tool name, minimal public example arguments, and the error category. Never include API keys, private package inventories, or sensitive logs. Follow [SECURITY.md](../SECURITY.md) when the issue itself is a vulnerability.
