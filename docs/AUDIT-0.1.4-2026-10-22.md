# 0.1.4 interoperability and evidence review — 2026-10-22

This review starts from commit `ae51cbf814adba11f1246d44923825f0d74b8d06`
(0.1.3). It covers the changes below, the complete existing automated suite,
installed-wheel behavior, selected upstream contracts, and documented alternatives.
It is a maintainer engineering review with a separate code-review agent, not an
independent security certification or proof of user demand.

## Changes and compatibility

### Structured MCP results

All seven tools now declare `dict[str, Any]` return types. With MCP Python SDK
1.30.0, this produces an object `outputSchema` and `structuredContent` while
preserving the existing JSON `TextContent`. The previous bare `dict` annotation
did not generate that schema in this SDK. Structured output is optional in the
[MCP specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools),
so this is an interoperability enhancement, not correction of a protocol violation.

The response object is not wrapped under a new `result` field. Empty OSV, KEV and
EPSS requests retain `queried: false`, and nested provider data retains its JSON
types. The schema is a generic object; it does not validate every upstream field.

The exported Python tool functions still return dictionaries. Code embedding the
SDK-level `MaintainerMCP.call_tool()` must await the call and account for the SDK's
`(content, structured_content)` return tuple when a structured output model exists.
MCP wire clients receive the usual result envelope with both representations.
See [usage](USAGE.md) and the
[SDK conversion implementation](https://raw.githubusercontent.com/modelcontextprotocol/python-sdk/v1.30.0/src/mcp/server/fastmcp/utilities/func_metadata.py).

### NVD parameter maintenance

`nvd_cve()` now sends its single normalized identifier through `cveIds`.
[NVD documentation](https://nvd.nist.gov/developers/vulnerabilities) marks `cveId`
deprecated. This review does not establish that the old parameter currently fails.
The public single-CVE interface, identity checks, count validation, authentication
header handling and not-found behavior are unchanged.

One live, unauthenticated lookup through the updated function returned the exact
requested record, `CVE-2021-44228`, with `found: true`. The retrieval completed at
`2026-10-22T20:00:10.081716+00:00`. The request used `cveIds`, no NVD API key and
the environment's authorized proxy with explicit `MCP_MAINTAINER_TOOLS_TRUST_ENV=true`;
TLS verification remained enabled. This is one integration observation, not an
availability guarantee or a repeat live audit of every provider.

## Verification performed before publication

Local environment: Linux, Python 3.12.14, MCP SDK 1.30.0, Pydantic 2.14.1,
httpx 0.28.1, pytest 9.1.1 and coverage 7.17.0.

| Check | Observed result |
| --- | --- |
| Structured-output regressions before the change | 5 failed; 75 deselected |
| Structured-output focused suite after the change | 80 passed |
| NVD parameter regression before the change | 1 failed |
| NVD focused suite after the change | 4 passed; 27 deselected |
| Complete suite after refreshing installed package metadata | **293 passed**, 16.68 s |
| Combined statement/branch coverage | **96.02%**; 533 statements, 196 branches |
| Independent focused code-review verification | 6 passed; no material finding |
| Ruff lint and format, Bandit, package dependency consistency | Passed |
| Fresh installed-wheel protocol, CLI and logging suite | **6 passed**, 4.79 s |
| Installed-wheel origin | Imported 0.1.4 from the fresh environment's `site-packages`, outside the checkout |
| Distribution build and strict Twine metadata validation | Wheel and source archive passed |

Four cases were added to the 289-test baseline: three parameterized empty-query
structured/text equivalence cases and one nested-provider-data preservation case.
The installed stdio test was also strengthened to require object output schemas
and equivalent structured content. It exercises actual subprocess transport.

The first complete run detected stale editable-install metadata (0.1.3) after the
source version changed to 0.1.4: one failure and 292 passes. Reinstalling the edited
package resolved it; the complete suite was then rerun successfully. An earlier
sandbox IPC restriction was reproduced outside the project and resolved by running
the local subprocess tests with the necessary IPC permission. Neither assertion
was weakened, and no product workaround was added.

The independent reviewer also exercised all seven SDK converters with nested
objects, arrays, booleans, integers, a large integer, floats and null without
provider requests. This checks serialization fidelity, not upstream data truth.
The fresh wheel environment did not install optional Rich logging support.

### Publication checks

The existing [Checks workflow](../.github/workflows/tests.yml) is unchanged. It
runs the complete suite on Ubuntu with Python 3.11–3.14 and Windows/macOS with
Python 3.12, plus package/security-pattern and resolved-dependency jobs. Its final
required gate depends on all prerequisites. Version-specific CI outcomes must be
read from the [workflow runs](https://github.com/No3214/mcp-maintainer-tools/actions/workflows/tests.yml)
for the relevant PR and merged commit; the local table above does not predeclare
those remote outcomes.

## Research and decisions

Three parallel workstreams covered protocol/lifecycle, provider contracts, and
maintainer workflows/alternatives. They issued **14 Exa queries** returning **90
discovery entries**. Selected sections from **29 unique primary URLs** were
reviewed (30 review records, with one URL used by two workstreams). Search-result
counts are not counts of fully read articles or independent demand observations.
Exact queries, source URLs and retrieval limits are recorded in
[the source-review log](research/source-review-2026-10-22.json).

[VALIDATION.md](VALIDATION.md) now includes Grype, Stacklok's OSV MCP and Vulners
MCP alongside existing alternatives, and updates the cyanheads comparison using
its current implementation. These are documentation/code comparisons; the
alternatives were not installed or benchmarked. Overlapping capabilities prevent
a defensible claim that OSV-over-MCP or source-aware advisory output is unique.

The pilot rubric now records registry artifact versus source checkout identity,
distinguishes unqueried input from complete empty results, and separates
installation/tool discovery/first nonempty provider call from investigation time.
These are engineering decisions about measurement quality, not evidence of the
frequency of those problems or demand for this repository. The planned pilot still
requires independent maintainers and comparative repeated use; no participants
were recruited in this review.

[USAGE.md](USAGE.md) clarifies provider score dates, EPSS probability versus
percentile, KEV evidence and the local deployment context this tool does not inspect.
No dependency scanner, installed dependency graph, reachability engine, composite
risk score, telemetry or automatic remediation was added from this evidence.

## Actual Jev review

One authenticated TypeSafe Playground request, using the `jev-preview` alias,
returned **`jev-1.14.0`**. It evaluated six independent choice questions against
reviewer-written summaries of public sources. No private account or project
context was supplied. Jev was not assumed to fetch the linked pages.

| Claim evaluated | Observed choice |
| --- | --- |
| The reported OSV issue supports adding registry-versus-Git identity to a pilot rubric | Insufficient |
| The records establish independent maintainers repeatedly choosing this project | Insufficient |
| OSV lookups through MCP are unique among the supplied alternatives | Contradicted |
| Transitive dependency remediation paths require context beyond current package metadata | Supported |
| EPSS alone establishes risk to a particular deployed system | Contradicted |
| NVD's deprecation notice establishes current `cveId` request failures | Insufficient |

The first result disagrees with the strength of the reviewer's rubric inference.
That disagreement is retained. Artifact identity remains a low-cost engineering
check in the proposed pilot; it is not promoted to a measured demand finding.
There was no favorable-result rerun.

The [request and observed response fields](research/jev-evidence-review-2026-10-22.json)
include the model name, choices, confidence/probability fields and usage. Those
numbers express the model's judgment of supplied summaries; they are not market
probabilities, factual validation or a performance benchmark. This is separate
model-assisted scrutiny, not an independent user study. MiroFish and formal Codex
Security Cloud scanning were not run.

## Remaining limits

- Automated checks do not guarantee absence of security defects, malicious
  upstream data, provider downtime or real-world integration failures.
- Runtime dependencies are range-constrained, not reproducibly locked for every
  user. CI receipts identify the versions actually tested.
- Provider outputs remain untrusted evidence. Generic object schemas do not replace
  provider identity, completeness and semantic validation.
- Existing worker cancellation/shutdown limits are unchanged; running Python
  threads cannot be forcibly interrupted. See the [0.1.2 audit](AUDIT-0.1.2-2026-10-22.md).
- Broad OS/model/tool coverage is not claimed. The workflow defines the actual
  Python/OS matrix, and the research log defines the source-review scope.
- User demand, repeated use, comparative benefit and willingness to pay remain
  unmeasured.
