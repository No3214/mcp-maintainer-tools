# Contributing

MCP Maintainer Tools helps maintainers inspect public vulnerability and package evidence. Contributions should make its seven tools more accurate, predictable, or easier to operate.

## Set up a development checkout

Use Python 3.11 or newer. On macOS/Linux:

```sh
git clone https://github.com/No3214/mcp-maintainer-tools.git
cd mcp-maintainer-tools
python3 -m venv .venv
./.venv/bin/python -m pip install -e '.[dev]'
./.venv/bin/python -m pytest -q
```

On Windows PowerShell, create the environment with `py -3 -m venv .venv` and use `.\.venv\Scripts\python.exe` for the two Python commands. Confirm that the selected interpreter is 3.11 or newer. Calling the interpreter directly avoids shell-activation differences.

The [CI workflow](.github/workflows/tests.yml) is configured to test Python 3.11–3.14 on Ubuntu and Python 3.12 on Windows and macOS. It also runs the quality, package, built-wheel CLI/stdio, and runtime dependency checks described below. Consult run results for a particular revision; this description does not assert that all checks have passed.

## Run the quality and package checks

The optional extras separate development, audit, and build dependencies. For the complete local toolset, use:

```sh
./.venv/bin/python -m pip install -e '.[dev,audit,build]'
./.venv/bin/python -m ruff check .
./.venv/bin/python -m ruff format --check .
./.venv/bin/python -m bandit -q -r src
./.venv/bin/python -m pytest --cov=mcp_maintainer_tools --cov-report=term-missing --cov-fail-under=85 -q
./.venv/bin/python -m build
./.venv/bin/python -m twine check --strict dist/*
```

These examples use the macOS/Linux interpreter path; substitute the Windows environment's interpreter when needed. CI installs the resulting wheel and exercises its installed CLI entry point and real stdio exchange. Review those tests when changing package contents or entry points. A local failure should be understood and resolved before changing an expected result or lowering a gate.

### Audit runtime dependencies separately

Audit a separate runtime environment so tooling dependencies are not confused with the server's dependencies. The following macOS/Linux commands mirror the workflow and include the environment's installer packages:

```sh
python3 -m venv .audit-runtime
./.audit-runtime/bin/python -m pip install --upgrade pip
./.audit-runtime/bin/python -m pip install -e .
site_packages="$(./.audit-runtime/bin/python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
./.venv/bin/python -m pip_audit --path "$site_packages" --skip-editable --progress-spinner off
```

The audit contacts public advisory services and checks known dependency vulnerabilities; it is distinct from reviewing this project's source. It is not part of the offline unit-test suite. See the [workflow](.github/workflows/tests.yml) for the authoritative command configuration.

### Review SDK upgrades explicitly

The runtime dependency is constrained to `mcp>=1.30.0,<1.31`. The server's typed-input handling, application-version reporting, and error/log adapters depend on behavior reviewed in that series. Before widening the range, review those integration points and rerun schema, validation-redaction, handshake, CLI, and stdio regression tests against the proposed SDK. A successful dependency resolution alone is not upgrade validation.

For network configuration changes, preserve the default-disabled environment trust setting. `MCP_MAINTAINER_TOOLS_TRUST_ENV` accepts only exact lowercase `true` or `false`; opting in must retain TLS verification and use the trusted process environment. Cover both modes and invalid values in deterministic tests; do not silently turn it on when a request fails.

## Propose a focused change

Open an issue or pull request at [No3214/mcp-maintainer-tools](https://github.com/No3214/mcp-maintainer-tools). Explain the observed problem, expected behavior, the change, and how you verified it. Discuss additional tools or providers in an issue before expanding the server's scope.

Keep tool names and argument behavior stable where possible. If a change intentionally rejects previously accepted input or changes an output field, describe its compatibility impact and update the [usage guide](docs/USAGE.md).

For changes to upstream behavior, cite the provider's official documentation. Check whether the observed response is permitted by that contract before tightening validation. Preserve metric attribution, record identities, source context, continuation tokens, and the distinction between missing information and a successful empty result.

## Write meaningful tests

Tests must be deterministic and must not need live provider access or an API key. Use minimal mocked responses that exercise the behavior being changed. Include relevant error cases, malformed data, pagination, and identity mismatches.

A useful regression test fails before the fix and passes afterward. Avoid assertions that only repeat implementation details. The protocol test checks initialization, tool listing, and tool invocation through a real stdio MCP exchange; keep this boundary covered when changing schemas or tool registration.

Use public, minimal sample data and respect third-party licenses and attribution when adding fixtures. Label invented examples as illustrative. Do not add private dependency inventories, personal filesystem paths, credentials, environment files, or unredacted operational logs.

## Review documentation and visual changes

Keep examples consistent with the implementation and verify that commands, relative links, and JSON are valid. Explain what a maintainer should do when data is missing or incomplete. Avoid describing a test result as a security certification.

Brand assets follow [docs/BRAND.md](docs/BRAND.md). SVG files must stay self-contained: no scripts, embedded third-party assets, remote fonts, or external fetches. Include accessible titles and descriptions. Preview changes at both full size and their intended display size.

## Security and licensing

For vulnerabilities in this server, use [SECURITY.md](SECURITY.md). Do not post credentials, sensitive logs, or a working exploit payload in a public issue.

Contributions are provided under the repository's [MIT License](LICENSE). Preserve applicable copyright and license notices. External data is governed by its own provider terms; adding an integration does not transfer those rights to this project.
