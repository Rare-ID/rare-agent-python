# rare-agent-sdk-python

Python SDK and CLI for Agent identity flows on Rare.

当前 SDK 的本地 Python 依赖只包含 `rare-identity-protocol`，不再依赖整个 `rare-identity-core` 服务包。

## Features

- Self register (`hosted-signer` or `self-hosted`)
- Set name (signed)
- Refresh public attestation
- Full attestation issue for registered platform
- Human-in-the-loop upgrades (`L1` email magic link, `L2` social connect)
- Challenge login via third-party platform
- Delegation/session/action signing via hosted Rare signer or local self-hosted key
- Self-hosted private key stored in separate key file (`~/.config/rare/keys/<agent_id>.key`, mode `0600`)
- Optional local signer daemon (`rare-signer`) so SDK process signs via IPC without loading private key

## Install

```bash
pip install rare-agent-sdk
```

可复现依赖安装：

```bash
pip install -r requirements-test.lock
pip install -e .[test] --no-deps
```

工作区本地开发仍可使用：

```bash
(cd ../rare-identity-protocol-python && pip install -e .)
pip install -e .[test]
```

## Local Run Prerequisite

先启动 core API：

```bash
(cd ../rare-identity-core && uvicorn rare_api.main:app --reload --host 127.0.0.1 --port 8000)
```

CLI 默认 `--rare-url` 为 `http://127.0.0.1:8000`（无需额外加 `/rare` 前缀）。

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
rare issue-full-attestation --aud platform
rare login --aud platform --platform-url http://127.0.0.1:8000/platform
rare login --aud platform --public-only
rare set-name --name alice-v2
rare refresh-attestation
rare show-state
```

## SDK

```python
from rare_agent_sdk import AgentClient, AgentState

state = AgentState()
client = AgentClient(state=state)
client.register(name="agent-1")
upg = client.request_upgrade_l1(email="owner@example.com")
sent = client.send_l1_upgrade_magic_link(request_id=upg["upgrade_request_id"])
client.verify_l1_upgrade_magic_link(token=sent["token"])
client.login(aud="platform")
signed = client.sign_platform_action(action="post", action_payload={"content": "hello"})
```

## Test

```bash
pytest -q
```

## Related Docs

- 工作区总览：`../Rare.md`
- RIP 文档索引：`../rare-identity-core/docs/RIP_INDEX.md`
- 平台接入规范：`../rare-identity-core/docs/rip-0005-platform-onboarding-and-events.md`
