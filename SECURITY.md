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
