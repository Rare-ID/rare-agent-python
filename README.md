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

如果你要接入 Rare 托管服务，默认 Rare API URL 可配置为：

```text
https://api.rareid.cc
```

可复现依赖安装（本仓开发）：

```bash
pip install -r requirements-test.lock
pip install -e .[test] --no-deps
```

本地开发时可额外安装协议包：

```bash
(cd ../rare-identity-protocol-python && pip install -e .)
pip install -e .[test]
```

## Configuration

- CLI / SDK 连接公开 Rare 服务：

```bash
rare show-state --rare-url https://api.rareid.cc
```

- 本地联调时，你也可以把 `--rare-url` 指向自建 Rare Core API，例如：

```text
http://127.0.0.1:8000
```

CLI 默认 `--rare-url` 不需要额外加 `/rare` 前缀。

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

- 协议与 RIP 文档：`Rare-ID/rare-protocol-py`
- 平台接入 SDK：`Rare-ID/rare-platform-ts`
