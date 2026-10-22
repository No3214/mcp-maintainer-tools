# Follow-up audit — 0.1.2 — 22 October 2026

This review starts from public `main` commit
`3791c363b7cf38d95a64ac18362d4bba87ce9bcb` (0.1.1). It focuses on real MCP
dispatch, cancellation, input/log privacy, and release verification. The
[previous audit](AUDIT-2026-10-22.md) remains a historical record. This is an
implementation review with executed regressions, not an external certification
or evidence of user adoption.

## Reproduced findings and changes

| Finding | Reproduction and cause | Change and evidence |
| --- | --- | --- |
| Provider I/O blocked the MCP event loop | MCP SDK 1.30.0 executes a synchronous tool function inline. A controlled blocked provider prevented ping, tool discovery, and an unrelated empty query from completing. | Register signature-preserving async wrappers; run synchronous work in four worker threads. Actual stdio barrier tests now service unrelated requests while the provider remains blocked. |
| Cancellation could encourage unbounded replacement work in a naive offload | Cancelling an asyncio waiter cannot terminate a running synchronous HTTP request. Releasing capacity when the waiter exits would admit more work while old work remains. | Four nonblocking admission slots are owned by the concurrent futures. MCP and raw asyncio cancellation tests show capacity remains occupied until the underlying work ends; saturation fails promptly and recovery succeeds. |
| Thread-start failure can retain an unreturned queued job | `ThreadPoolExecutor.submit` queues before starting a new thread. A fault-injection test showed failed submission could leave work that ran on a later submission. | Close the executor and cancel queued work on submission failure before releasing admission. The instance remains closed; the regression confirms the abandoned job never later runs. |
| Unknown top-level fields were ignored | The SDK-generated Pydantic models defaulted to ignoring extras. All seven tools accepted fields absent from their schema. | Reject extras and publish `additionalProperties: false`. Seven direct negative cases and actual stdio invocation verify rejection before provider calls and keep supplied values out of errors. |
| Unknown tool names appeared in default SDK diagnostics | The low-level SDK emits a warning containing the supplied name before dispatch. A real SDK/stderr test reproduced the marker leak. | Add a source- and message-specific log filter and a static dispatch error. Clear arguments, cached message, exception and stack fields while retaining severity and unrelated diagnostics. |
| Retained text helper accepted problematic codecs/Unicode | `as_text=True` could raise an uncaught codec `LookupError` or return a lone surrogate. Current MCP tools use JSON, so this was a latent helper issue. | Convert decoding failures to a static `UpstreamError` and validate Unicode scalar values; retain a valid UTF-16/non-BMP control case. |
| Wheel verification could be made more explicit | Installing a wheel did not itself remove the pytest parent's configured source path. The existing stdio child already launched an installed entry point from a temporary directory. | Use isolated Python, clear pytest's source path, and check the actual imported package origin against the environment's installation directories. A negative control rejects the editable checkout. |
| CI lacked one stable required-check context | Matrix job names vary, and a skipped job can satisfy GitHub required checks. Both branch-push and PR triggers also duplicated same-repository PR work. | Add `Required checks` with `always()` and explicit success requirements for all three prerequisite jobs. Keep PR runs and main push runs. All 64 combinations of success/failure/cancelled/skipped prerequisites were exercised; only all-success passes. |

## Local integration measurement

The final integration command used Python 3.12.14 on Linux and a separate
coverage data file, with no simultaneous coverage writer:

```sh
COVERAGE_FILE=/tmp/mcp-round2-verified-012.coverage python -m pytest \
  --cov=mcp_maintainer_tools --cov-report=term-missing \
  --cov-fail-under=90 -q
```

- **281 tests passed** in the measured run, including 16 concurrency/dispatch
  cases and eight new HTTP-text/unknown-name logging cases.
- **96.01% combined statement/branch coverage:** 530 statements and 196 branches,
  with 15 statements and 14 branches unexecuted. Coverage is not a correctness score.
- Ruff lint/format checks, Bandit source-pattern checks, `pip check`, and whitespace
  checks passed on the integrated code.
- The seven complete MCP tool definitions were compared with the baseline. The
  intended schema difference is top-level `additionalProperties: false`.
  Public Python tool functions retain their synchronous signatures.

Provider behavior in the regression suite is mocked. Actual local stdio exchanges
exercise the installed SDK; they are not network load tests. The concurrency tests
use controlled barriers and explicit backstops so cancellation and recovery are
observed without relying on public-service timing.

### Coverage correction and collection boundary

The unchanged 0.1.1 baseline again passed all 257 tests, but fresh coverage measured
**94.86%**, below the prior report's **96.33%**. The earlier higher measurement was
not reproduced; its exact cause was not established. Both exceeded the configured
90% gate, but the higher figure must not be carried forward as a fresh result.

Review also found that the SDK's subprocess environment whitelist drops coverage
startup configuration. The tests now explicitly forward only
`COVERAGE_PROCESS_CONFIG` and `COVERAGE_PROCESS_START` when present. This allows
instrumented stdio children to participate while preserving the SDK's normal
environment isolation. The CLI child was separately confirmed to contribute
coverage with isolated Python enabled. The current coverage result therefore has
an explicit collection boundary and is not a like-for-like product quality trend.

## Release gates and environment evidence

The [CI workflow](../.github/workflows/tests.yml) runs the full suite on Ubuntu
Python 3.11–3.14, Windows Python 3.12, and macOS Python 3.12. Separate jobs perform
lint/format, Bandit, distribution build, strict Twine validation, installed-wheel
CLI/stdio checks, and an advisory audit of separately resolved runtime dependencies.
The ninth job aggregates these results without treating a failed or skipped
prerequisite as success. Actual [workflow runs](https://github.com/No3214/mcp-maintainer-tools/actions/workflows/tests.yml)
are the authority for a particular commit's remote outcome.

`scripts/environment_receipt.py` records the interpreter/platform, a small named
CI metadata whitelist, distribution versions, package origin, and built archive
SHA-256 values. It rejects an editable/source origin when invoked with
`--require-installed`. It does not enumerate arbitrary environment values.

These receipts explain what was tested; they do not freeze future installations.
Runtime ranges, transitive tooling dependencies, build isolation, runner images,
and Python patch versions can still resolve differently. This release adds neither
a complete transitive lock file nor a signed build attestation.

A required-check workflow must be paired with repository protection to enforce a
merge boundary. Protection is a separate repository setting; its current state
must be read back after configuration. Multiple agent reviews are not independent
human approval, and this audit does not claim a mandatory human reviewer.

### Verified remote results and merge protection

[PR #2](https://github.com/No3214/mcp-maintainer-tools/pull/2) passed all nine
[PR jobs](https://github.com/No3214/mcp-maintainer-tools/actions/runs/39825753203)
before merging. The resulting commit
[`0f5b050ce509721f92c470086520bdb99f7878e8`](https://github.com/No3214/mcp-maintainer-tools/commit/0f5b050ce509721f92c470086520bdb99f7878e8)
also passed all nine [main jobs](https://github.com/No3214/mcp-maintainer-tools/actions/runs/39826939889).
Both runs executed 281 tests in each of the six matrix environments. Combined
coverage was 95.99% on Ubuntu Python 3.14 and 96.01% on the other five environments;
every environment exceeded the 90% gate. Each quality job also passed the four
installed-wheel CLI/stdio tests. The full matrix used the source installation.

Repository settings and the branch API were read back on 2026-10-22 after
configuration. `main` was protected with PRs required, up-to-date branches
required, and `Required checks` accepted specifically from GitHub Actions.
These requirements applied to administrators too; force pushes and branch
deletion were not allowed. Human approval was not configured as a required gate.
This is a dated observation of repository settings, which can change independently
of this file; the current settings remain authoritative.

## Remaining operating limits

- The four-job limit applies to synchronous tools dispatched by one server
  instance. Direct Python calls and custom async tools are outside that limit.
- Cancellation releases the protocol waiter, not the active HTTP operation.
  The worker retains capacity; Python may wait for it during process exit.
- Argument validation and response serialization still run on the protocol loop.
  There is no hard latency, whole-request deadline, total-memory, or global
  provider-rate guarantee. HTTP phase limits and the 32 MiB per-response cap remain.
- Provider facts remain untrusted. Structural validation and source attribution
  cannot prove completeness, freshness, exploitability, or absence of vulnerabilities.
- The targeted SDK log filter is not a general secret scrubber. Custom embeddings
  must install it, and explicit SDK DEBUG protocol dumps can still expose inputs.
- The project remains early-stage. Existing tools overlap substantially. The
  [workflow validation plan](VALIDATION.md) contains future pilot criteria and no
  fabricated user results, market-validation claim, or sponsorship guarantee.

See [USAGE.md](USAGE.md), [THREAT_MODEL.md](THREAT_MODEL.md), and
[CONTRIBUTING.md](../CONTRIBUTING.md) for operating and verification instructions.

## Primary references

- [Python executor submission, cancellation, and shutdown](https://docs.python.org/3.12/library/concurrent.futures.html)
- [GitHub required status-check behavior](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)
- [GitHub workflow job dependencies](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-jobs)
- [pytest import and integration practices](https://docs.pytest.org/en/stable/explanation/goodpractices.html)
- [coverage subprocess collection](https://coverage.readthedocs.io/en/latest/subprocess.html)
- [pip repeatable installs](https://pip.pypa.io/en/stable/topics/repeatable-installs/)
