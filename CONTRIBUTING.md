# Contributing

## Scope

This repository is the public Python SDK and CLI for Rare agent flows.

Out of scope:

- private Rare backend implementation
- infrastructure and deployment details
- hosted signer service internals beyond public API behavior
- secrets or local state containing sensitive tokens

## Before You Start

- Open an issue for behavior changes, new public commands, or API changes.
- Keep CLI flags and SDK surface area coherent with the public protocol and platform kit.
- If you change signing behavior or token semantics, update tests and the related protocol docs.

## Development

```bash
pip install -r requirements-test.lock
pip install -e .[test] --no-deps
pytest -q
python -m build
```

## Pull Requests

- Add tests for user-visible behavior changes.
- Document breaking CLI or SDK changes in the pull request description.
- Do not commit private keys, session tokens, or local state files with secrets.
