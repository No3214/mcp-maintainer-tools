# Protocol logging audit — 0.1.3 — 22 October 2026

This follow-up starts from public `main` commit
[`0f5b050ce509721f92c470086520bdb99f7878e8`](https://github.com/No3214/mcp-maintainer-tools/commit/0f5b050ce509721f92c470086520bdb99f7878e8)
(0.1.2). It examines default diagnostics from reachable MCP handlers outside the
seven tools. The [0.1.2 audit](AUDIT-0.1.2-2026-10-22.md) records the preceding
dispatch changes, remote results, and repository-protection readback.

## Reproduced findings

Both findings were reproduced through a real initialized stdio server using the
official `python -I -m mcp_maintainer_tools` entry point and synthetic values.
The installed SDK was MCP 1.30.0.

| Finding | Observed behavior before the fix | Scope |
| --- | --- | --- |
| Unknown prompt name in default error logs | `prompts/get` with an unknown name reached FastMCP's `Error getting prompt ...` exception log. The supplied name appeared in stderr and the traceback. | FastMCP registers this handler even when the project defines no prompts. |
| Unrecognized response ID in default warning logs | An unsolicited JSON-RPC response with a nonnumeric string ID reached the session's `Response ID ... cannot be normalized ...` warning. The supplied ID appeared in stderr. | No outstanding server request was required to reach the warning. |

These are limited input-privacy findings: a local protocol peer supplies the
values that reach logs. The reproduction did not extract an ambient API key or
another user's data. An unknown resource URI was returned to the same requesting
client, but did not appear in the observed default stderr; an unsupported
subscription returned `Method not found`. Those observations are not additional
default-log disclosures.

## Change and compatibility boundary

The existing log adapter now matches the two known message prefixes from their
exact installed SDK source files. It replaces the message with a static
diagnostic and clears arguments, exception information, cached exception text,
stack information, and any cached rendered message. The FastMCP logger receives
the same idempotent filter already used for root/session and low-level server
diagnostics. Log levels, handlers, and unrelated records are preserved.

The implementation change is confined to the log adapter and package version.
All seven tools retain their names, schemas, and provider behavior. Client-facing
SDK prompt/resource errors retain their existing semantics and can repeat values
to the same caller. The fix does not disable unsupported protocol handlers or
change their error responses.

The independent module-entry-point reproduction was repeated after the change:
neither prompt nor response markers appeared in stderr, the static diagnostics
remained, and subsequent ping and seven-tool discovery succeeded.

## Executed regression evidence

Tests were added before changing the adapter. The focused set first reported
**5 failed and 15 passed**: both real stdio disclosures, both additional cached
record cleanup cases, and installation on the FastMCP logger failed as expected.
After the change, **20 focused tests passed**. Eight cases were added overall.

`tests/test_protocol_logging.py` resolves the installed console entry point from
distribution metadata and launches isolated Python from a temporary directory.
Provider network connections are guarded; local event-loop IPC remains allowed.
The tests check marker absence, a positive diagnostic specific to each case,
absence of traceback/stdout parse errors, unchanged caller-visible prompt errors,
and continued ping/tool-list operation. Unit cases independently verify severity,
cached-field cleanup, source/message specificity, and installation idempotence.

The separate wheel environment exposed a test-only assumption: optional Rich
logging includes severity labels, while the SDK's plain fallback formatter emits
only the message. The test now checks stable diagnostic tokens instead of
formatter-specific labels. Severity remains checked on `LogRecord.levelno`.
Production logging configuration was not changed to accommodate the test.

### Final local suite

The final run used Python 3.12.14 on Linux, with a distinct coverage file and no
other coverage writer:

```sh
COVERAGE_FILE=/tmp/mcp-round3-release.coverage python -m pytest \
  --cov=mcp_maintainer_tools --cov-report=term-missing \
  --cov-fail-under=90 -q
```

- **289 tests passed.**
- **96.02% combined statement/branch coverage:** 533 statements and 196 branches;
  15 statements and 14 branches were not executed. Coverage is not a safety score.
- Ruff lint/format checks, Bandit source-pattern checks, `pip check`, and whitespace
  checks passed on the integrated code.
- The fresh 0.1.3 wheel was force-installed in a separate virtual environment.
  An installed-origin receipt confirmed imports from that environment's
  `site-packages`, outside the source checkout. All **six CLI/stdio tests passed**
  from a separate copied test directory, without optional Rich installed.

The full suite and wheel checks do not establish live-provider availability or
throughput. Existing provider responses are mocked. The new actual stdio cases
exercise local protocol behavior without sending private data to providers.

## CI and merge requirements

The installed-wheel CI step now includes the two new protocol-log regressions.
The full six-environment matrix remains Ubuntu Python 3.11–3.14, Windows Python
3.12, and macOS Python 3.12. Separate jobs run quality/package checks and the
resolved-runtime advisory audit; `Required checks` requires all prerequisites to
succeed. Actual [workflow runs](https://github.com/No3214/mcp-maintainer-tools/actions/workflows/tests.yml)
are the authority for a particular commit's remote results. Configuration alone
is not a claim that the revision passed remotely.

On 2026-10-22, the persisted GitHub rule and branch API confirmed that `main`
requires PRs, an up-to-date branch, and `Required checks` specifically from GitHub
Actions. Administrators are included; force pushes and deletion are disabled.
Human approval is not a required gate. Repository settings can change separately
from this dated record.

## Remaining limits

- The adapter covers reviewed SDK paths, not arbitrary secrets or explicit SDK
  DEBUG protocol dumps. Custom embeddings must install it before server startup.
- Source paths and message templates are SDK integration points. The dependency
  remains constrained to the reviewed 1.30 series; upgrades require regression
  review as described in [CONTRIBUTING.md](../CONTRIBUTING.md).
- This is source review and executed automated verification, not an external
  security certification or a Codex Security Cloud scan. Multiple agent reviews
  do not constitute independent human approval.
- The [existing operational limits](AUDIT-0.1.2-2026-10-22.md#remaining-operating-limits)
  still apply. Technical tests do not establish real-user demand, which remains
  unmeasured under the [validation plan](VALIDATION.md).

See [USAGE.md](USAGE.md) for the log/privacy boundary and
[THREAT_MODEL.md](THREAT_MODEL.md) for the maintained threat model.
