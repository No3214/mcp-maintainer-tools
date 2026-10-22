# Workflow validation plan

**Status: planned; no pilot results. Last reviewed: 22 October 2026.**

MCP Maintainer Tools provides read-only enrichment for public vulnerability and
package investigations, preserving source context and explicit limits. External
adoption and comparative workflow improvements have not been validated. Technical
tests, branding, stars, and model-generated opinions do not establish demand.

## Question to test

Can maintainers complete a specific investigation with less time or fewer evidence
errors using this server, compared with their existing workflow? MCP access,
multiple providers, aliases, and pagination are already available elsewhere;
none is a demonstrated unique advantage of this project.

## Alternatives and prior art

The linked maintainers' documentation was reviewed on 22 October 2026. Descriptions
below are documented capabilities, not results of installing or benchmarking them.

| Alternative | Documented overlap and comparison role |
| --- | --- |
| [OSV-Scanner](https://google.github.io/osv-scanner/) | Official OSV frontend for finding vulnerabilities in project dependencies, through a CLI or Go library. A baseline for dependency discovery; this server accepts explicit lookup inputs. |
| [Snyk Studio MCP](https://github.com/snyk/studio-mcp) | Exposes Snyk scans and findings through MCP, including dependency, code, container, and configuration scans. Compare the user's existing Snyk workflow when applicable. |
| [cyanheads/osv-advisory-mcp-server](https://github.com/cyanheads/osv-advisory-mcp-server) | OSV package/batch/advisory tools preserve aliases, affected ranges, and truncation information; documented composition with an NVD server includes KEV context. A close comparison for evidence handling. |
| [mukul975/cve-mcp-server](https://github.com/mukul975/cve-mcp-server) | Documents NVD, EPSS, KEV, and OSV tools plus combined CVE triage. Multi-source enrichment already exists; compare the shared lookup tasks without adopting its scoring claims. |
| [gleicon/mcp-osv](https://github.com/gleicon/mcp-osv) | Provides OSV package-version queries through MCP alongside code and secret analysis. An additional overlapping OSV integration. |
| [badchars/cve-mcp](https://github.com/badchars/cve-mcp) | Its indexed README describes NVD, EPSS, KEV, and OSV enrichment. Direct repository/API retrieval returned 404 during this review; treat it as indexed prior art, with current availability unverified. |

Direct provider websites/APIs and the maintainer's current scanner also count as
baselines. Select a suitable available alternative before collecting results;
do not choose an artificially weak manual process to favor this project. This
list is a focused comparison, not an exhaustive market study or endorsement.

## Predeclared pilot

Before the first session, record this plan's commit, exact public cases, expected
answer fields, baseline tool versions, task order, time limit, and review rubric.
Use three independent maintainers outside the project author/contributor team.
Each uses a real public maintenance question they care about; demonstrations by
the author, bots, and simulated users do not count toward that participant goal.

| Task | Required deliverable | What the reviewer checks |
| --- | --- | --- |
| A. Investigate one exact public package version | Package/ecosystem/version, matching OSV advisory IDs, affected ranges, CVE aliases where present, and deps.dev package identity/context | Correct subject, advisory references, and explicit pagination/completeness; a package metadata lookup is not a version-specific vulnerability verdict. |
| B. Enrich three public CVE IDs | A table of NVD metric attribution, KEV membership/source, EPSS score/percentile/date, retrieval times, and unavailable results | Provider meanings remain distinct; missing records and failed lookups are not reported as evidence of safety. |
| C. Handle incomplete evidence | A separately labeled fixture exercise with an empty OSV page plus a continuation token, and an unavailable provider | Continue or mark the result incomplete; retain known evidence and state the unavailable portion. Pin the fixture/harness before use. This is a technical exercise, not user-demand evidence. |

For A and B, compare the same inputs using the existing workflow and this server.
Alternate which workflow runs first across participants and tasks; record order
and learning effects. Keep prompts, client/model versions, and settings constant
when both workflows use an assistant. Run paired attempts close together, retain
source URLs and retrieval/score dates, and flag changes in upstream data.

Record setup time separately. Start each task timer when the input is shown and
stop at the submitted answer; cap each attempt at 15 minutes. A timeout, provider
failure, or incomplete answer remains in the results. Do not discard slow runs.
Review against the retrieved provider evidence, not another model's confidence;
hide the workflow identity from the reviewer where practical.

## Measurements and evidence

| Measure | Record for both workflows |
| --- | --- |
| Effort | Setup minutes, wall-clock task seconds, active human minutes, and manual lookups/corrections |
| Completion | Complete, incomplete, failed, or timed out; include reason and assistance needed |
| Source fidelity | Count incorrect identities, unsupported claims, missing attribution/dates, and incorrectly claimed completeness against the predeclared fields |
| Operating cost | Provider/tool calls, retries, and model usage/cost when available; otherwise `not measured` |
| Repeat use | Whether the participant voluntarily uses it on a different real public task on a later day within 14 days; record an optional public task reference |

For each attempt retain a public case ID, revision/versions, task order, UTC times,
the submitted answer, source references, measured values, reviewer corrections,
and limitations. Distinguish observed, self-reported, fixture, and not-measured
evidence. Record source-data changes separately from tool errors. Publish only
consented, public or synthetic examples; never dependency inventories, credentials,
private package names, personal paths, or unredacted logs. Review [network and credentials](USAGE.md#network-and-credentials)
before using live providers and [SECURITY.md](../SECURITY.md) for security reports.

## Internal decision rule

These are small-project planning heuristics, not statistical proof or any external
program's eligibility criteria. Freeze them before the pilot; later changes need
a new plan revision and must not retroactively turn an unfavorable result into a pass.

- **Continue the narrow workflow:** three independent participants complete the paired tasks, at least two voluntarily return for another task within 14 days, and at least two show either a 20% reduction in median paired-task wall time with no increase in evidence errors, or fewer evidence errors with no increase in median time. All C cases must pass and no critical source-fidelity error may remain unresolved.
- **Revise or stop expansion:** a completed pilot misses those criteria, or a suitable existing tool serves the task without a material observed advantage. Record the reason and consider contributing upstream.
- **Insufficient evidence:** participation, comparisons, repeat use, or measurements are missing. Keep the outcome unvalidated rather than inferring success or no demand.

Wrong package/CVE identity, fabricated source attribution, or presenting incomplete
evidence as confirmed clean is a critical source-fidelity error. Fix it and repeat
the affected evaluation before continuing. Report every case and the small sample's
limitations; do not generalize a pilot percentage into a guaranteed benefit.

## Current record and voluntary feedback

No real-user pilot, repeat-use evidence, or measured comparison is recorded here.
The tables above define future measurements and contain no observed results.
Share a public workflow, an unsuccessful attempt, or a comparison through the
[workflow feedback form](https://github.com/No3214/mcp-maintainer-tools/issues/new?template=workflow-feedback.yml).
Feedback is voluntary; unmeasured suggestions remain suggestions, not adoption evidence.
