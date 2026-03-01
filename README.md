# rare-sdk-python

Python SDK and CLI for Agent identity flows on Rare.

## Features

- Self register (`hosted-signer` or `self-hosted`)
- Set name (signed)
- Refresh public attestation
- Platform grant/revoke and full attestation issue
- Human-in-the-loop upgrades (`L1` email magic link, `L2` social connect)
- Challenge login via third-party platform
- Delegation/session/action signing via hosted Rare signer or local self-hosted key
- Self-hosted private key stored in separate key file (`~/.config/rare/keys/<agent_id>.key`, mode `0600`)
- Optional local signer daemon (`rare-signer`) so SDK process signs via IPC without loading private key

## Install

```bash
# in this workspace, install core first to provide `rare_identity_protocol`
(cd ../rare-identity-core && pip install -e .)
pip install -e .[test]
```

## CLI

```bash
# terminal A: start local signer
rare-signer

# terminal B: self-hosted register/login via signer IPC
rare register --name alice
rare register --name alice --key-mode self-hosted
rare request-upgrade --level L1 --email alice@example.com
# send magic link (local stub returns token)
rare upgrade-status --request-id <request_id>
rare request-upgrade --level L2
rare start-social --request-id <request_id> --provider github
rare grant-platform --aud platform
rare issue-full-attestation --aud platform
rare login --aud platform --platform-url http://127.0.0.1:8000/platform
rare login --aud platform --public-only
rare set-name --name alice-v2
rare refresh-attestation
rare show-state
```

## SDK

```python
from rare_sdk import AgentClient, AgentState

state = AgentState()
client = AgentClient(state=state)
client.register(name="agent-1")
upg = client.request_upgrade_l1(email="owner@example.com")
sent = client.send_l1_upgrade_magic_link(request_id=upg["upgrade_request_id"])
client.verify_l1_upgrade_magic_link(token=sent["token"])
client.grant_platform(aud="platform")
client.login(aud="platform")
signed = client.sign_platform_action(action="post", action_payload={"content": "hello"})
```
