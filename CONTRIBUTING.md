# Contributing

Thank you for helping maintain this small MCP server. Contributions should make its seven existing lookup tools more accurate, predictable, or easier to use.

## Set up a development checkout

Use Python 3.11 or newer and a virtual environment:

```sh
python -m venv .venv
# Activate the virtual environment using the command for your shell.
python -m pip install -e '.[dev]'
python -m pytest -q
```

## Propose a change

Open an issue or pull request at [No3214/mcp-maintainer-tools](https://github.com/No3214/mcp-maintainer-tools). Explain the problem, the expected behavior, and how you checked the change. Discuss additional tools or providers in an issue before expanding the server's scope.

For changes to upstream behavior, link the relevant provider's official API documentation. Keep successful empty results distinct from failures and missing data. Preserve continuation tokens and paging metadata, and avoid inventing defaults when upstream leaves a field unknown.

Tests should use deterministic fixtures or mocked HTTP calls. Cover the behavior being changed, including meaningful error or pagination cases. Automated tests must not depend on live provider availability or require an API key. Use public, minimal example data and respect third-party licenses and attribution when adding fixtures or code.

Do not commit credentials, environment files, private dependency inventories, personal paths, or unredacted operational logs. If a bug involves sensitive information, follow [SECURITY.md](SECURITY.md) instead of posting those details in a public issue.

Contributions are provided under the repository's [MIT License](LICENSE). Preserve applicable copyright and license notices.
