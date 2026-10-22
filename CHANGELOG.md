# Changelog

## 0.1.1 — 2026-10-22

This maintenance release strengthens upstream-data validation and request handling,
adds a coherent project identity, and improves installation and contributor guidance.
The seven public tool names and normal call shapes remain stable.

### Fixed

- Reject deps.dev responses for an unrelated package, while supporting documented
  PyPI and NuGet canonicalization. Validate default-version flags.
- Reject EPSS scores outside `[0, 1]`, non-finite values, and invalid dates.
- Prevent MCP argument coercion from turning booleans or strings into integer
  pagination values. Publish input bounds and OSV batch-item structure in schemas.
- Keep rejected argument values out of Pydantic error messages returned to clients.
- Sanitize malformed MCP envelope/notification validation logs and invalid-JSON
  stream errors without suppressing unrelated diagnostics.
- Preserve opaque pagination strings such as `"null"` through MCP dispatch, and
  advertise the application version in the MCP handshake.
- Reject malformed or duplicate OSV advisory identifiers and invalid Unicode.
- Return `queried: false` without a retrieval timestamp for empty OSV batches.
- Keep KEV available when the canonical feed rejects or cannot serve a request,
  using only CISA's documented official mirror after selected availability
  failures. Preserve actual/canonical source URLs and explicit fallback status;
  malformed or unsafe responses still fail.

### Hardened

- Stream upstream responses with a 32 MiB body limit; discard error bodies without
  buffering them and close responses before retrying.
- Request uncompressed data and reject unexpected compression before decoding.
- Reject duplicate JSON keys, non-finite numbers, excessive nesting, and lone
  Unicode surrogates.
- Refuse URL credentials and non-HTTPS requests, retain redirect refusal, and
  sanitize request-encoding failures.
- Avoid provider-controlled cookies and implicit proxy/custom-CA environment
  settings; provide an explicit `MCP_MAINTAINER_TOOLS_TRUST_ENV=true` opt-in for
  trusted environment routing. Bound the connection pool and individual I/O waits.

### Added

- `--help` and `--version` entry points; default invocation still starts MCP stdio.
- Original vector identity, GitHub banner, social card, and a documented brand system.
- Detailed operating guide and explicit Unix/Windows client configurations.
- Strict linting, source security-pattern checks, dependency-advisory checks,
  distribution validation, and expanded platform/Python CI configuration.
- A source-backed audit record and a threat model with explicit residual limitations.

### Compatibility notes

- Invalid inputs previously accepted through coercion now fail validation.
- JSON arrays/objects must be supplied as arrays/objects, not stringified JSON.
- The MCP SDK is constrained to the reviewed 1.30 series because two narrow
  integration points preserve raw argument types and application-version metadata.
- Environment proxies and custom CA paths are not inherited by default. Deployments
  that require trusted environment configuration must explicitly enable the opt-in.
- Providers returning compressed data despite `Accept-Encoding: identity` fail
  with a controlled error.
- Timeouts and elapsed-body checks do not constitute a strict end-to-end deadline.

## 0.1.0 — 2026-10-22

- Initial public MIT-licensed release of seven read-only MCP research tools.
- Source attribution, pagination metadata, credential-safe errors, and mocked tests.
