from __future__ import annotations

import json
import os
import stat
import threading
import time
from contextlib import contextmanager
from importlib import import_module
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from _platform_stub import PlatformStubService, create_platform_app
from rare_agent_sdk import AgentClient, AgentState
from rare_agent_sdk.cli import main as cli_main
from rare_agent_sdk.local_signer import create_local_signer_server
from rare_agent_sdk.state import (
    get_agent_private_key_path,
    get_hosted_management_token_path,
    get_signer_key_path,
    load_state,
    save_state,
)


def _load_rare_runtime() -> tuple[object, object]:
    try:
        main_module = import_module("rare_api.main")
        service_module = import_module("rare_api.service")
    except ModuleNotFoundError:
        pytest.skip("rare_api package is unavailable; integration runtime tests skipped")
    return main_module, service_module


def build_runtime(*, rare_mount_path: str = "/rare") -> TestClient:
    main_module, service_module = _load_rare_runtime()
    create_rare_app = getattr(main_module, "create_app")
    rare_service_cls = getattr(service_module, "RareService")
    rare_service = rare_service_cls(allow_local_upgrade_shortcuts=True)
    platform_service = PlatformStubService(
        aud="platform",
        identity_key_resolver=lambda kid: rare_service.get_identity_public_key(kid),
        rare_signer_public_key_provider=rare_service.get_rare_signer_public_key,
    )

    root = FastAPI()
    root.mount("/platform", create_platform_app(platform_service))
    root.mount(rare_mount_path, create_rare_app(rare_service))
    return TestClient(root)


@contextmanager
def run_local_signer(tmp_path: Path):
    socket_path = Path("/tmp") / f"rare-signer-{uuid4().hex}.sock"
    key_path = tmp_path / "keys" / "signer.key"
    server = create_local_signer_server(socket_path=str(socket_path), key_file=str(key_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    for _ in range(100):
        if socket_path.exists():
            break
        time.sleep(0.01)
    try:
        yield socket_path, key_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def test_sdk_identity_flow_hosted_signing() -> None:
    http = build_runtime()
    state = AgentState()

    client = AgentClient(
        rare_base_url="http://testserver/rare",
        platform_base_url="http://testserver/platform",
        state=state,
        http_client=http,
    )

    register = client.register(name="sdk")
    assert register["agent_id"] == state.agent_id
    assert state.key_mode == "hosted-signer"
    assert state.hosted_management_token
    assert isinstance(state.hosted_management_token_expires_at, int)

    login = client.login(aud="platform", prefer_full=False)
    assert login["agent_id"] == state.agent_id

    rename = client.set_name(name="sdk-v2")
    assert rename["name"] == "sdk-v2"

    refresh = client.refresh_attestation()
    assert refresh["agent_id"] == state.agent_id

    client.close()
    http.close()


def test_sdk_identity_flow_with_default_rare_url() -> None:
    http = build_runtime(rare_mount_path="/")
    state = AgentState()

    client = AgentClient(
        platform_base_url="http://testserver/platform",
        state=state,
        http_client=http,
    )

    register = client.register(name="sdk-default-url")
    assert register["agent_id"] == state.agent_id

    login = client.login(aud="platform", prefer_full=False)
    assert login["agent_id"] == state.agent_id

    client.close()
    http.close()


def test_sdk_identity_flow_self_hosted_signing() -> None:
    http = build_runtime()
    state = AgentState()

    client = AgentClient(
        rare_base_url="http://testserver/rare",
        platform_base_url="http://testserver/platform",
        state=state,
        http_client=http,
    )

    register = client.register(name="sdk-self", key_mode="self-hosted")
    assert register["agent_id"] == state.agent_id
    assert state.key_mode == "self-hosted"
    assert state.agent_private_key
    assert state.hosted_management_token is None
    assert state.hosted_management_token_expires_at is None

    login = client.login(aud="platform", prefer_full=False)
    assert login["agent_id"] == state.agent_id

    rename = client.set_name(name="sdk-self-v2")
    assert rename["name"] == "sdk-self-v2"

    client.close()
    http.close()


def test_sdk_can_sign_platform_action_and_call_post() -> None:
    http = build_runtime()
    state = AgentState()

    client = AgentClient(
        rare_base_url="http://testserver/rare",
        platform_base_url="http://testserver/platform",
        state=state,
        http_client=http,
    )

    client.register(name="actor")
    login = client.login(aud="platform", prefer_full=False)

    signed = client.sign_platform_action(
        action="post",
        action_payload={"content": "hello"},
    )

    post_response = http.post(
        "/platform/posts",
        json={
            "content": "hello",
            "nonce": signed["nonce"],
            "issued_at": signed["issued_at"],
            "expires_at": signed["expires_at"],
            "signature_by_session": signed["signature_by_session"],
        },
        headers={"Authorization": f"Bearer {login['session_token']}"},
    )
    assert post_response.status_code == 200

    client.close()
    http.close()


def test_sdk_can_rotate_and_revoke_hosted_management_token() -> None:
    http = build_runtime()
    state = AgentState()

    client = AgentClient(
        rare_base_url="http://testserver/rare",
        platform_base_url="http://testserver/platform",
        state=state,
        http_client=http,
    )

    client.register(name="hosted-token-ops")
    original_token = state.hosted_management_token
    rotated = client.rotate_hosted_management_token()
    assert isinstance(rotated["hosted_management_token"], str)
    assert rotated["hosted_management_token"] != original_token
    assert isinstance(state.hosted_management_token_expires_at, int)

    revoked = client.revoke_hosted_management_token()
    assert revoked["revoked"] is True
    assert state.hosted_management_token is None
    assert state.hosted_management_token_expires_at is None

    client.close()
    http.close()


def test_sdk_self_hosted_can_sign_platform_action_and_call_post() -> None:
    http = build_runtime()
    state = AgentState()

    client = AgentClient(
        rare_base_url="http://testserver/rare",
        platform_base_url="http://testserver/platform",
        state=state,
        http_client=http,
    )

    client.register(name="actor-self", key_mode="self-hosted")
    login = client.login(aud="platform", prefer_full=False)

    signed = client.sign_platform_action(
        action="post",
        action_payload={"content": "hello-self"},
    )

    post_response = http.post(
        "/platform/posts",
        json={
            "content": "hello-self",
            "nonce": signed["nonce"],
            "issued_at": signed["issued_at"],
            "expires_at": signed["expires_at"],
            "signature_by_session": signed["signature_by_session"],
        },
        headers={"Authorization": f"Bearer {login['session_token']}"},
    )
    assert post_response.status_code == 200

    client.close()
    http.close()


def test_sdk_self_hosted_with_local_signer_and_no_private_key_in_state(tmp_path) -> None:
    http = build_runtime()
    state = AgentState()

    with run_local_signer(tmp_path) as (socket_path, key_path):
        client = AgentClient(
            rare_base_url="http://testserver/rare",
            platform_base_url="http://testserver/platform",
            state=state,
            http_client=http,
            signer_socket_path=str(socket_path),
        )

        register = client.register(name="signer-agent", key_mode="self-hosted")
        assert register["agent_id"] == state.agent_id
        assert state.agent_private_key is None
        assert key_path.exists()

        login = client.login(aud="platform", prefer_full=False)
        signed = client.sign_platform_action(
            action="post",
            action_payload={"content": "hello-from-signer"},
        )
        post_response = http.post(
            "/platform/posts",
            json={
                "content": "hello-from-signer",
                "nonce": signed["nonce"],
                "issued_at": signed["issued_at"],
                "expires_at": signed["expires_at"],
                "signature_by_session": signed["signature_by_session"],
            },
            headers={"Authorization": f"Bearer {login['session_token']}"},
        )
        assert post_response.status_code == 200

        client.close()

    http.close()


def test_cli_outputs_json_success(tmp_path, capsys) -> None:
    state_file = tmp_path / "state.json"
    exit_code = cli_main(["--state-file", str(state_file), "show-state"])
    output = capsys.readouterr().out.strip()

    assert exit_code == 0
    payload = json.loads(output)
    assert payload["ok"] is True
    assert payload["command"] == "show-state"


def test_cli_show_state_redacts_sensitive_tokens(tmp_path, capsys) -> None:
    state_file = tmp_path / "state.json"
    state = AgentState(
        agent_id="agent-1",
        key_mode="hosted-signer",
        session_token="session-token",
        hosted_management_token="hosted-token",
    )
    save_state(state_file, state)
    exit_code = cli_main(["--state-file", str(state_file), "show-state"])
    output = capsys.readouterr().out.strip()

    assert exit_code == 0
    payload = json.loads(output)
    data = payload["data"]
    assert data["session_token"] == "***REDACTED***"
    assert data["hosted_management_token"] == "***REDACTED***"


def test_cli_register_redacts_hosted_management_token(monkeypatch, tmp_path, capsys) -> None:
    from rare_agent_sdk import cli as cli_module

    class FakeClient:
        def __init__(self, *args, **kwargs):
            self.state = kwargs["state"]

        def register(self, *args, **kwargs):
            self.state.agent_id = "agent-register"
            self.state.key_mode = "hosted-signer"
            self.state.hosted_management_token = "hosted-secret-token"
            return {
                "agent_id": "agent-register",
                "key_mode": "hosted-signer",
                "hosted_management_token": "hosted-secret-token",
            }

        def close(self):
            return None

    monkeypatch.setattr(cli_module, "AgentClient", FakeClient)

    state_file = tmp_path / "state.json"
    exit_code = cli_module.main(["--state-file", str(state_file), "register"])
    output = capsys.readouterr().out.strip()

    assert exit_code == 0
    payload = json.loads(output)
    assert payload["data"]["hosted_management_token"] == "***REDACTED***"


def test_cli_outputs_json_error(monkeypatch, tmp_path, capsys) -> None:
    from rare_agent_sdk import cli as cli_module
    from rare_agent_sdk.client import AgentClientError

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def register(self, *args, **kwargs):
            raise AgentClientError("boom")

        def close(self):
            return None

    monkeypatch.setattr(cli_module, "AgentClient", FakeClient)

    state_file = tmp_path / "state.json"
    exit_code = cli_module.main(["--state-file", str(state_file), "register"])
    output = capsys.readouterr().out.strip()

    assert exit_code == 1
    payload = json.loads(output)
    assert payload["ok"] is False
    assert payload["command"] == "register"
    assert payload["error"] == "client_error"


def test_self_hosted_private_key_saved_outside_state_json(tmp_path) -> None:
    state_file = tmp_path / "state.json"
    state = AgentState(
        agent_id="agent_abc",
        key_mode="self-hosted",
        agent_private_key="secret-private-key",
    )

    save_state(state_file, state)

    saved_json = json.loads(state_file.read_text(encoding="utf-8"))
    assert "agent_private_key" not in saved_json

    key_path = get_agent_private_key_path(state_file, "agent_abc")
    assert key_path.exists()
    assert key_path.read_text(encoding="utf-8") == "secret-private-key"

    loaded_without_key = load_state(state_file)
    assert loaded_without_key.agent_private_key is None

    loaded = load_state(state_file, include_private_key=True)
    assert loaded.agent_private_key == "secret-private-key"

    if os.name != "nt":
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


def test_hosted_management_token_saved_outside_state_json(tmp_path) -> None:
    state_file = tmp_path / "state.json"
    state = AgentState(
        agent_id="agent_hosted",
        key_mode="hosted-signer",
        hosted_management_token="hosted-secret-token",
        hosted_management_token_expires_at=123456,
    )

    save_state(state_file, state)

    saved_json = json.loads(state_file.read_text(encoding="utf-8"))
    assert "hosted_management_token" not in saved_json
    assert saved_json["hosted_management_token_expires_at"] == 123456

    token_path = get_hosted_management_token_path(state_file, "agent_hosted")
    assert token_path.exists()
    assert token_path.read_text(encoding="utf-8") == "hosted-secret-token"

    loaded = load_state(state_file)
    assert loaded.hosted_management_token == "hosted-secret-token"
    assert loaded.hosted_management_token_expires_at == 123456

    if os.name != "nt":
        assert stat.S_IMODE(state_file.stat().st_mode) == 0o600
        assert stat.S_IMODE(token_path.stat().st_mode) == 0o600


def test_save_state_cleans_stale_agent_secret_files(tmp_path) -> None:
    state_file = tmp_path / "state.json"
    signer_key_path = get_signer_key_path(state_file)
    signer_key_path.parent.mkdir(parents=True, exist_ok=True)
    signer_key_path.write_text("signer-key", encoding="utf-8")

    state_a = AgentState(
        agent_id="agent_a",
        key_mode="hosted-signer",
        hosted_management_token="token-a",
    )
    save_state(state_file, state_a)
    token_a_path = get_hosted_management_token_path(state_file, "agent_a")
    assert token_a_path.exists()

    state_b = AgentState(
        agent_id="agent_b",
        key_mode="self-hosted",
        agent_private_key="key-b",
    )
    save_state(state_file, state_b)
    key_b_path = get_agent_private_key_path(state_file, "agent_b")
    assert key_b_path.exists()
    assert not token_a_path.exists()

    state_c = AgentState(
        agent_id="agent_c",
        key_mode="hosted-signer",
        hosted_management_token="token-c",
    )
    save_state(state_file, state_c)
    token_c_path = get_hosted_management_token_path(state_file, "agent_c")
    assert token_c_path.exists()
    assert not key_b_path.exists()

    assert signer_key_path.exists()


def test_load_state_supports_legacy_private_key_field(tmp_path) -> None:
    state_file = tmp_path / "state.json"
    state_file.write_text(
        json.dumps(
            {
                "agent_id": "agent_legacy",
                "key_mode": "self-hosted",
                "agent_private_key": "legacy-private-key",
            }
        ),
        encoding="utf-8",
    )

    loaded = load_state(state_file, include_private_key=True)
    assert loaded.agent_private_key == "legacy-private-key"

    save_state(state_file, loaded)
    saved_json = json.loads(state_file.read_text(encoding="utf-8"))
    assert "agent_private_key" not in saved_json
    assert get_agent_private_key_path(state_file, "agent_legacy").exists()


def test_load_state_supports_legacy_hosted_management_token_field(tmp_path) -> None:
    state_file = tmp_path / "state.json"
    state_file.write_text(
        json.dumps(
            {
                "agent_id": "agent_legacy_hosted",
                "key_mode": "hosted-signer",
                "hosted_management_token": "legacy-hosted-token",
            }
        ),
        encoding="utf-8",
    )

    loaded = load_state(state_file)
    assert loaded.hosted_management_token == "legacy-hosted-token"
    assert loaded.hosted_management_token_expires_at is None

    save_state(state_file, loaded)
    saved_json = json.loads(state_file.read_text(encoding="utf-8"))
    assert "hosted_management_token" not in saved_json
    token_path = get_hosted_management_token_path(state_file, "agent_legacy_hosted")
    assert token_path.exists()
    assert token_path.read_text(encoding="utf-8") == "legacy-hosted-token"


def test_sdk_upgrade_l1_magic_link_flow() -> None:
    http = build_runtime()
    state = AgentState()
    client = AgentClient(
        rare_base_url="http://testserver/rare",
        platform_base_url="http://testserver/platform",
        state=state,
        http_client=http,
    )

    client.register(name="upgrade-sdk-l1")
    requested = client.request_upgrade_l1(email="owner@example.com")
    assert requested["status"] == "human_pending"
    request_id = requested["upgrade_request_id"]

    sent = client.send_l1_upgrade_magic_link(request_id=request_id)
    assert sent["sent"] is True
    verified = client.verify_l1_upgrade_magic_link(token=sent["token"])
    assert verified["status"] == "upgraded"
    assert verified["level"] == "L1"

    status = client.get_upgrade_status(request_id=request_id)
    assert status["status"] == "upgraded"

    client.close()
    http.close()


def test_sdk_self_hosted_upgrade_status_is_accessible() -> None:
    http = build_runtime()
    state = AgentState()
    client = AgentClient(
        rare_base_url="http://testserver/rare",
        platform_base_url="http://testserver/platform",
        state=state,
        http_client=http,
    )

    client.register(name="self-status", key_mode="self-hosted")
    requested = client.request_upgrade_l1(email="self-status@example.com")
    request_id = requested["upgrade_request_id"]

    status = client.get_upgrade_status(request_id=request_id)
    assert status["upgrade_request_id"] == request_id
    assert status["status"] in {"human_pending", "upgraded"}

    client.close()
    http.close()


def test_sdk_upgrade_l2_social_flow() -> None:
    http = build_runtime()
    state = AgentState()
    client = AgentClient(
        rare_base_url="http://testserver/rare",
        platform_base_url="http://testserver/platform",
        state=state,
        http_client=http,
    )

    client.register(name="upgrade-sdk-l2")
    l1 = client.request_upgrade_l1(email="owner2@example.com")
    sent = client.send_l1_upgrade_magic_link(request_id=l1["upgrade_request_id"])
    verified_l1 = client.verify_l1_upgrade_magic_link(token=sent["token"])
    assert verified_l1["level"] == "L1"

    requested_l2 = client.request_upgrade_l2()
    assert requested_l2["status"] == "human_pending"
    request_id = requested_l2["upgrade_request_id"]
    started = client.start_l2_social(request_id=request_id, provider="github")
    assert started["provider"] == "github"

    completed = client.complete_l2_social(
        request_id=request_id,
        provider="github",
        provider_user_snapshot={"id": "42", "login": "rare-dev"},
    )
    assert completed["status"] == "upgraded"
    assert completed["level"] == "L2"

    client.close()
    http.close()
