from __future__ import annotations

from dataclasses import dataclass

import pytest

from rare_identity_protocol import generate_ed25519_keypair
from rare_agent_sdk import AgentClient, AgentState
from rare_agent_sdk.client import AgentClientError, ApiError
from test_sdk import build_runtime


@dataclass
class _FakeResponse:
    status_code: int
    json_body: object | None = None
    text: str = ""
    json_error: Exception | None = None

    def json(self):  # noqa: ANN201
        if self.json_error is not None:
            raise self.json_error
        return self.json_body


class _FakeHttpClient:
    def __init__(self, responses: list[_FakeResponse]) -> None:
        self._responses = list(responses)

    def request(self, *_args, **_kwargs):  # noqa: ANN002, ANN003, ANN201
        assert self._responses, "fake responses exhausted"
        return self._responses.pop(0)

    def close(self) -> None:
        return None


def test_request_json_rejects_non_dict_success_response() -> None:
    client = AgentClient(http_client=_FakeHttpClient([_FakeResponse(status_code=200, json_body=["not-dict"])]))
    with pytest.raises(AgentClientError, match="expected JSON object response"):
        client._request_json(method="GET", service="rare", path="/v1/test")  # noqa: SLF001


def test_default_rare_base_url_points_to_root_prefix() -> None:
    client = AgentClient(http_client=_FakeHttpClient([]))
    assert client._url("rare", "/v1/test") == "http://127.0.0.1:8000/v1/test"  # noqa: SLF001


def test_request_json_rejects_non_json_success_response() -> None:
    client = AgentClient(
        http_client=_FakeHttpClient(
            [
                _FakeResponse(
                    status_code=200,
                    text="not-json",
                    json_error=ValueError("invalid json"),
                )
            ]
        )
    )
    with pytest.raises(AgentClientError, match="expected JSON object response"):
        client._request_json(method="GET", service="rare", path="/v1/test")  # noqa: SLF001


def test_request_json_surfaces_api_error_from_dict_and_text_body() -> None:
    dict_error_client = AgentClient(
        http_client=_FakeHttpClient([_FakeResponse(status_code=403, json_body={"detail": "denied"})])
    )
    with pytest.raises(ApiError, match="api error 403: denied"):
        dict_error_client._request_json(method="POST", service="rare", path="/v1/test")  # noqa: SLF001

    text_error_client = AgentClient(
        http_client=_FakeHttpClient(
            [_FakeResponse(status_code=500, text="oops", json_error=ValueError("invalid json"))]
        )
    )
    with pytest.raises(ApiError, match="api error 500: oops"):
        text_error_client._request_json(method="POST", service="rare", path="/v1/test")  # noqa: SLF001


def test_register_rejects_missing_hosted_management_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    state = AgentState()
    client = AgentClient(state=state, http_client=_FakeHttpClient([]))

    monkeypatch.setattr(
        client,
        "_request_json",
        lambda **_kwargs: {
            "agent_id": "agent-1",
            "key_mode": "hosted-signer",
            "public_identity_attestation": "public-jws",
        },
    )
    with pytest.raises(AgentClientError, match="missing hosted_management_token"):
        client.register(name="alice")

    monkeypatch.setattr(
        client,
        "_request_json",
        lambda **_kwargs: {
            "agent_id": "agent-1",
            "key_mode": "hosted-signer",
            "public_identity_attestation": "public-jws",
            "hosted_management_token": "token-1",
        },
    )
    with pytest.raises(AgentClientError, match="missing hosted_management_token_expires_at"):
        client.register(name="alice")


def test_client_guard_errors_for_missing_state_and_mode_constraints() -> None:
    empty_client = AgentClient(state=AgentState(), http_client=_FakeHttpClient([]))
    with pytest.raises(AgentClientError, match="run register first"):
        empty_client.refresh_attestation()

    hosted_missing_token = AgentClient(
        state=AgentState(agent_id="agent-1", key_mode="hosted-signer"),
        http_client=_FakeHttpClient([]),
    )
    with pytest.raises(AgentClientError, match="hosted_management_token missing"):
        hosted_missing_token.issue_full_attestation(aud="platform")

    self_hosted = AgentClient(
        state=AgentState(agent_id="agent-2", key_mode="self-hosted"),
        http_client=_FakeHttpClient([]),
    )
    with pytest.raises(AgentClientError, match="only available in hosted-signer mode"):
        self_hosted.rotate_hosted_management_token()
    with pytest.raises(AgentClientError, match="only available in hosted-signer mode"):
        self_hosted.revoke_hosted_management_token()
    with pytest.raises(AgentClientError, match="session_pubkey missing"):
        self_hosted.sign_platform_action(action="post", action_payload={"content": "x"})


def test_login_allows_public_fallback_when_full_hard_fail_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    http = build_runtime()
    state = AgentState()
    client = AgentClient(
        rare_base_url="http://testserver/rare",
        platform_base_url="http://testserver/platform",
        state=state,
        http_client=http,
    )
    client.register(name="fallback-agent")

    def _full_issue_fails(*_args, **_kwargs):  # noqa: ANN002, ANN003
        raise AgentClientError("full attestation unavailable")

    monkeypatch.setattr(client, "issue_full_attestation", _full_issue_fails)

    login = client.login(
        aud="platform",
        prefer_full=True,
        full_hard_fail=False,
    )
    assert login["agent_id"] == state.agent_id
    assert isinstance(state.session_token, str) and state.session_token

    with pytest.raises(AgentClientError, match="full attestation unavailable"):
        client.login(
            aud="platform",
            prefer_full=True,
            full_hard_fail=True,
        )

    client.close()
    http.close()


def test_client_self_hosted_signs_full_issue_before_api_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key, public_key = generate_ed25519_keypair()
    state = AgentState(
        agent_id=public_key,
        key_mode="self-hosted",
        agent_private_key=private_key,
    )
    client = AgentClient(state=state, http_client=_FakeHttpClient([]))
    observed_payloads: list[tuple[str, dict | None]] = []

    def fake_request_json(
        *,
        method: str,
        service: str,
        path: str,
        json_payload: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict:
        del service, headers
        observed_payloads.append((f"{method}:{path}", json_payload))
        raise ApiError(status_code=403, detail="denied")

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    with pytest.raises(ApiError):
        client.issue_full_attestation(aud="platform")

    assert observed_payloads[0][0] == "POST:/v1/attestations/full/issue"
    assert observed_payloads[0][1] is not None
    assert observed_payloads[0][1]["platform_aud"] == "platform"
    assert isinstance(observed_payloads[0][1]["signature_by_agent"], str)


def test_client_hosted_path_for_full_issue_state_update() -> None:
    state = AgentState(
        agent_id="agent-hosted",
        key_mode="hosted-signer",
        hosted_management_token="hosted-token",
        hosted_management_token_expires_at=9999999999,
    )
    responses = [
        _FakeResponse(
            status_code=200,
            json_body={
                "agent_id": "agent-hosted",
                "platform_aud": "platform",
                "nonce": "n3",
                "issued_at": 10,
                "expires_at": 20,
                "signature_by_agent": "sig-3",
            },
        ),
        _FakeResponse(
            status_code=200,
            json_body={
                "agent_id": "agent-hosted",
                "platform_aud": "platform",
                "full_identity_attestation": "full-token",
            },
        ),
    ]
    client = AgentClient(state=state, http_client=_FakeHttpClient(responses))

    issued = client.issue_full_attestation(aud="platform")
    assert issued["full_identity_attestation"] == "full-token"
    assert client.state.full_identity_attestations["platform"] == "full-token"


def test_client_self_hosted_uses_local_signer_for_upgrade_request() -> None:
    class FakeSigner:
        def __init__(self) -> None:
            self.calls: list[dict] = []

        def sign_upgrade_request(
            self,
            *,
            agent_id: str,
            target_level: str,
            request_id: str,
            nonce: str,
            issued_at: int,
            expires_at: int,
        ) -> dict:
            self.calls.append(
                {
                    "agent_id": agent_id,
                    "target_level": target_level,
                    "request_id": request_id,
                    "nonce": nonce,
                    "issued_at": issued_at,
                    "expires_at": expires_at,
                }
            )
            return {"signature_by_agent": "sig-from-signer"}

    signer = FakeSigner()
    state = AgentState(agent_id="agent-self", key_mode="self-hosted")
    client = AgentClient(
        state=state,
        http_client=_FakeHttpClient(
            [
                _FakeResponse(
                    status_code=200,
                    json_body={
                        "upgrade_request_id": "upg-1",
                        "status": "human_pending",
                        "next_step": "connect_social",
                    },
                )
            ]
        ),
        signer_client=signer,  # type: ignore[arg-type]
    )

    response = client.request_upgrade_l2()
    assert response["status"] == "human_pending"
    assert len(signer.calls) == 1
    assert signer.calls[0]["target_level"] == "L2"


def test_login_uses_full_attestation_when_provider_returns_token(monkeypatch: pytest.MonkeyPatch) -> None:
    http = build_runtime()
    state = AgentState()
    client = AgentClient(
        rare_base_url="http://testserver/rare",
        platform_base_url="http://testserver/platform",
        state=state,
        http_client=http,
    )
    client.register(name="full-token-login")

    monkeypatch.setattr(
        client,
        "issue_full_attestation",
        lambda **_kwargs: {"full_identity_attestation": "not-a-valid-jws"},
    )
    with pytest.raises(ApiError, match="api error 400"):
        client.login(aud="platform", prefer_full=True, full_hard_fail=True)

    client.close()
    http.close()
