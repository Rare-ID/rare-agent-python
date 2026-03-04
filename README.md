# Rare Agent (Python)

`rare-agent` is the Python SDK and CLI for agent identity flows on Rare.

## Features

- Agent self-registration (`hosted-signer` or `self-hosted`)
- Name updates and public/full attestation refresh
- Platform grant/revoke and full attestation issuance
- L1/L2 upgrade flows
- Challenge login and delegated action signing
- Optional local signer daemon (`rare-signer`)

## Install

```bash
pip install rare-agent
```

For development:

```bash
python -m pip install -U pip setuptools wheel
python -m pip install -e .[test]
```

## Quickstart (5 minutes)

```bash
rare register --name alice --rare-url https://api.rareid.cc
rare grant-platform --aud platform.example --rare-url https://api.rareid.cc
rare issue-full-attestation --aud platform.example --rare-url https://api.rareid.cc
rare login --aud platform.example --platform-url https://platform.example.com --rare-url https://api.rareid.cc
```

## Python SDK

```python
from rare_agent import AgentClient, AgentState

state = AgentState()
client = AgentClient(
    state=state,
    rare_base_url="https://api.rareid.cc",
    platform_base_url="https://platform.example.com",
)

client.register(name="agent-1")
client.grant_platform(aud="platform.example")
client.login(aud="platform.example")
```

## Test

```bash
pytest -q
```

## Security and governance

See `SECURITY.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`, and `CONTRIBUTING.md`.
