# Threat model

**Scope:** MCP Maintainer Tools 0.1.2, reviewed 2026-10-22.

## Purpose and assets

The server helps a maintainer retrieve public vulnerability and package records.
It runs as a local stdio subprocess launched by an MCP client. Its sensitive assets
are the optional NVD key, the user's dependency-query information, and the
integrity and availability of data presented to the client. The process also has
the ordinary privileges of the account launching it; run it with only the
permissions appropriate for a public-data lookup tool.

## Trust boundaries

| Boundary | Data crossing it | Enforcement and limits |
| --- | --- | --- |
| MCP client → server | Tool name and arguments | Strict schemas, unknown fields rejected, bounded fields and lists, validation before requests. The host remains responsible for authorizing calls. |
| Validated MCP call → synchronous worker | Provider lookup work and request context | Four outstanding tool jobs per server instance; excess calls fail promptly. A cancelled call retains its slot until its worker actually completes. |
| Server → provider | Package/version/ecosystem/CVE/query token; optional NVD header key | Fixed origins, verified HTTPS, encoded path segments, no redirects, no URL credentials. Queries are disclosed to providers by design. |
| Provider → HTTP decoder | Status, headers, bytes | Streaming, 32 MiB body cap, identity encoding, strict JSON/Unicode validation, I/O limits. No absolute process-memory or wall-clock guarantee. |
| Decoded data → tool result | Advisory text, identities, metrics, dates, pagination | Provider-specific structural and identity checks, explicit source and continuation data. Provider facts and descriptions remain untrusted. |
| Tool result → assistant | Research data and safe errors | Read-only/open-world annotations and instructions. The host must prevent tool-output instructions from becoming authority. |
| Dependency resolver → installed code | MCP SDK, HTTP client, validation libraries and transitive dependencies | Version constraints, resolved-dependency advisory scan, source review and tests. Future versions inside allowed ranges require their own evaluation. |

KEV has two fixed sources: the canonical CISA feed and CISA's official GitHub
mirror. The mirror is used only after a selected availability failure, not after
invalid or unsafe response data. The same catalog validation applies to both.
The result records which source supplied the catalog; mirror synchronization is
an upstream responsibility. CVE matching happens locally for both sources.

## Threats addressed in this release

1. **Misleading package identity or probabilities:** reject mismatched deps.dev
   subjects and invalid EPSS numeric/date fields.
2. **Ambiguous or oversized provider responses:** fail safely on excessive bytes,
   nesting, duplicate keys, non-finite numbers, invalid Unicode or compression that
   was not requested.
3. **Accidental disclosure in errors:** replace Pydantic argument-value errors and
   transport messages that can include URLs, upstream text or credentials.
4. **Silent input coercion:** require strict pagination integers and explicit
   bounded schemas instead of accepting booleans or numeric strings.
5. **Unwanted request state:** refuse response cookies and implicit environment
   proxy/custom-CA configuration; an explicit opt-in supports trusted environments.
   Retain verified TLS and fixed tool destinations.
6. **False completeness:** expose continuation information, preserve missing data,
   and distinguish empty local work from actual provider retrieval.
7. **Protocol stalls and unbounded replacement work:** synchronous lookups run
   outside the protocol event loop with bounded admission. Cancellation releases
   the protocol waiter but cannot terminate an in-flight HTTP operation.
8. **Unknown tool-name disclosure:** official entry points sanitize the SDK's
   specific unknown-tool warning, and return a static unknown-tool error.

## Threats outside the implemented boundary

- A malicious or compromised provider returning plausible but false data.
- A compromised local user account, MCP client, Python interpreter or dependency.
- An assistant obeying instructions embedded in external descriptions.
- Exhaustive vulnerability discovery, reachability analysis, signed source-data
  attestation, complete SBOM scanning or legal/compliance certification.
- Multi-user hosting, HTTP authentication, tenant isolation and remote deployment.
- A strict deadline/cancellation mechanism across every network phase, a global
  request-rate budget, or a fixed total process-memory ceiling.

The worker bound applies to registered synchronous MCP calls on one server
instance. Direct Python function calls and custom async tools do not use this
admission path. JSON validation and output serialization still use the protocol
event loop. Running worker threads may delay process exit after shutdown.

Do not expose this stdio process as a public service without designing those
additional controls. A missing advisory, EPSS record or KEV match is not a safety
verdict.

## Verification approach

Regression tests exercise malformed provider payloads, strict schemas, safe errors,
pagination, retry/stream behavior, and actual MCP tool invocation. The stdio test
starts an installed entry point from an unrelated directory with external network
connections blocked; loopback IPC remains available for Windows event loops.
Package builds and dependency checks complement source review.
The audit record states measured results and the limitations of each check.
