# rare-agent-sdk

Python SDK and CLI for the Rare agent identity lifecycle.

## What It Is

`rare-agent-sdk` helps an agent register, manage its identity, request upgrades, issue attestations, and complete Rare login flows against Rare-compatible platforms.

## Who It Is For

- Agent developers integrating Rare identity into Python apps
- Teams choosing between Rare hosted signing and self-hosted keys
- Operators testing end-to-end login and attestation flows locally

## Why It Exists

Rare login is not a single token exchange. Agents need to manage keys, sign fixed protocol payloads, refresh attestations, handle human verification upgrades, and produce delegation material for platforms. This repository packages that lifecycle into a Python API and CLI.

## How It Fits Into Rare

- `Rare-ID/rare-protocol-py` defines the public protocol rules
- `rare-agent-sdk` handles the agent-side lifecycle
- `Rare-ID/rare-platform-ts` is the platform-side toolkit that verifies what this SDK produces

## Quick Start

```bash
pip install rare-agent-sdk
```

Use the hosted Rare API:

```bash
rare register --name alice --rare-url https://api.rareid.cc
rare refresh-attestation --rare-url https://api.rareid.cc
rare show-state --rare-url https://api.rareid.cc
```

Use the Python SDK:

```python
from rare_agent_sdk import AgentClient, AgentState

state = AgentState()
client = AgentClient(
    state=state,
    rare_base_url="https://api.rareid.cc",
)
client.register(name="agent-1")
client.refresh_attestation()
print(client.state.agent_id)
client.close()
```

## Production Notes

- `agent_id` is the Ed25519 public key and remains the primary identity key.
- Two operating modes are supported: `hosted-signer` and `self-hosted`.
- Self-hosted keys are stored separately from the JSON state file under `~/.config/rare/keys/` with `0600` permissions.
- `rare-signer` lets you keep the private key out of the main SDK process by signing over local IPC.
- Platforms should verify the delegation and attestation materials produced by this SDK locally.

Additional docs:

- `STATUS.md`
- `HOSTED_VS_SELF_HOSTED.md`

## Common CLI Flows

```bash
rare-signer
rare register --name alice
rare register --name alice --key-mode self-hosted
rare set-name --name alice-v2
rare refresh-attestation
rare request-upgrade --level L1 --email alice@example.com
rare send-l1-link --request-id <request_id>
rare upgrade-status --request-id <request_id>
rare request-upgrade --level L2
rare start-social --request-id <request_id> --provider github
rare issue-full-attestation --aud platform
rare login --aud platform --platform-url http://127.0.0.1:8000/platform
rare login --aud platform --public-only
rare recovery-factors
rare recover-hosted-token-email
rare recover-hosted-token-email-verify --token <token>
rare recover-hosted-token-social-start --provider github
rare show-state --paths
```

## Development

```bash
pip install -r requirements-test.lock
pip install -e .[test] --no-deps
pytest -q
python -m build
```
