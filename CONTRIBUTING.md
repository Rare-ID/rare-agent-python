# Contributing to Rare Agent (Python)

## Development setup

```bash
python -m pip install -U pip setuptools wheel
python -m pip install -e .[test]
```

## Quality gates

```bash
pytest -q
python -m build
```

## Pull requests

- Keep changes focused.
- Add tests for behavioral changes.
- Update README/examples when API behavior changes.
