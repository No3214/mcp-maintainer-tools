# Security policy

## Reporting a vulnerability

For a security issue in this server, use the repository's **Security → Report a vulnerability** option if GitHub private vulnerability reporting is available:

https://github.com/No3214/mcp-maintainer-tools/security

If that option is unavailable, open a minimal issue asking the maintainer for a private reporting channel. Do not include credentials, private package names, sensitive logs, or an exploit payload in a public issue. No response-time guarantee is offered.

A useful private report includes the affected version or commit, the tool involved, a minimal reproduction with sensitive values removed, expected and observed behavior, and the likely impact.

Reports should concern this project's implementation, such as leaking credentials, sending requests to unintended destinations, or mishandling untrusted input. Report vulnerabilities in packages returned by a lookup to their own maintainers through their reporting process.

## Supported code

Security fixes are targeted at the latest code on the default branch. Older snapshots do not have a separate maintenance commitment.

## Operating the server

The server makes outbound requests to the public providers documented in [README.md](README.md). Query parameters can reveal dependency information. Supply an optional NVD API key through the process environment and keep it out of source control and diagnostic output.

Treat all upstream descriptions and references as untrusted data. Tool output does not authorize commands or other actions. Missing advisories, scores, or catalog entries do not establish that a dependency is safe.

## Security boundaries and controls

The supported transport is local MCP **stdio**. This project does not expose an
HTTP listener, provide multi-user authentication, inspect local dependency files,
execute upstream commands, or approve releases. The MCP client decides which tool
calls to authorize and must protect its own conversation and operating environment.

The seven tools use fixed provider origins. Requests use verified HTTPS, refuse
redirects and URL credentials, and do not store provider cookies. The HTTP client
does not inherit proxy or custom-CA environment settings by default. Set
`MCP_MAINTAINER_TOOLS_TRUST_ENV=true` at startup to explicitly use a trusted
environment's proxy and certificate configuration. Normal certificate verification
remains enabled in both modes; this choice is not a substitute for operating-system
network policy.

For KEV, an unavailable canonical CISA feed can use one fixed fallback: CISA's
own `cisagov/kev-data` repository on `raw.githubusercontent.com`. Only selected
availability failures trigger this fallback. Malformed or unsafe responses do
not. Results identify the actual source, canonical source, and fallback status;
the mirror can lag the canonical catalog. The user's CVE list is matched locally
and is not sent to either catalog endpoint.

Successful response bodies are limited to 32 MiB. The client requests identity
encoding and rejects unexpected compression before decompression. JSON must be
UTF-8, have no duplicate keys or non-finite numbers, remain within 64 nesting
levels, and contain valid Unicode scalar values. Provider records are checked for
the subject, structure and pagination constraints documented in [USAGE](docs/USAGE.md).
These checks reduce misleading output; they do not authenticate the truth of a
provider's data or establish that its dataset is complete.

HTTP failures omit upstream response bodies, URLs and credential values. Strict
MCP argument-validation errors omit the supplied values. The official stdio entry
points also sanitize known SDK request, notification and stream-validation logs.
This is not a general secret scrubber: explicitly enabling SDK DEBUG protocol dumps
can expose messages, and custom embeddings must install the logging adapter
themselves. The optional NVD API key
is read from the server process environment and sent only in the NVD request
header. Avoid putting secrets in package names, query arguments or the optional
User-Agent value: those are deliberately transmitted to the selected provider.

## Resource limits and residual risks

- Connect and pool waits use 10-second timeouts; individual reads/writes use
  15-second timeouts. An elapsed-budget check runs after headers and during body
  streaming. **There is no strict whole-request wall-clock deadline**: slow
  headers can delay the first elapsed check, and individual I/O waits have their
  own timeout behavior.
- The shared pool permits 10 total and 5 keep-alive connections. The 32 MiB cap
  applies to one response body, not the process's total memory. JSON objects,
  output serialization and concurrent calls require additional memory.
- GET can retry up to twice; POST is attempted once. Rate limits or unavailable
  providers can still prevent a result. The project does not supply a global
  rate limiter, quota manager or multi-tenant service boundary. KEV's canonical
  and fallback requests each use that bounded GET policy.
- Provider text can contain prompt injection. It remains untrusted content even
  when its JSON structure is valid. The assistant/client must not treat it as
  instructions or permission to act.
- Corporate proxy/custom-CA configuration requires the explicit environment-trust
  opt-in. Only enable it for configuration you trust; it changes routing and the
  certificate trust sources used for provider requests.
- Dependency scans detect known advisories in resolved package versions; they
  do not establish the absence of undisclosed vulnerabilities or malicious code.

See [the threat model](docs/THREAT_MODEL.md) and
[the 2026-10-22 audit](docs/AUDIT-2026-10-22.md) for reviewed scope, evidence and
verification limits. The audit is a maintainer source review with automated checks,
not a security certification or a hosted Codex Security assessment.
