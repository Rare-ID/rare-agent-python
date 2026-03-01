from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from rare_identity_protocol import (
    build_action_payload,
    build_auth_challenge_payload,
    build_full_attestation_issue_payload,
    build_platform_grant_payload,
    build_register_payload,
    build_set_name_payload,
    build_upgrade_request_payload,
    generate_ed25519_keypair,
    generate_nonce,
    issue_agent_delegation,
    load_private_key,
    now_ts,
    public_key_to_b64,
    sign_detached,
)

from rare_sdk.local_signer import LocalSignerClient, LocalSignerError
from rare_sdk.state import AgentState


class AgentClientError(RuntimeError):
    """Raised for remote API failures or invalid local state transitions."""


@dataclass
class ApiError(AgentClientError):
    status_code: int
    detail: str

    def __str__(self) -> str:
        return f"api error {self.status_code}: {self.detail}"


class AgentClient:
    def __init__(
        self,
        *,
        rare_base_url: str = "http://127.0.0.1:8000/rare",
        platform_base_url: str = "http://127.0.0.1:8000/platform",
        state: AgentState | None = None,
        http_client: Any | None = None,
        signer_socket_path: str | None = None,
        signer_client: LocalSignerClient | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.rare_base_url = rare_base_url.rstrip("/")
        self.platform_base_url = platform_base_url.rstrip("/")
        self.state = state or AgentState()
        if not isinstance(self.state.full_identity_attestations, dict):
            self.state.full_identity_attestations = {}
        self._session_private_key: str | None = None
        self._signer = signer_client or (
            LocalSignerClient(socket_path=signer_socket_path)
            if signer_socket_path
            else None
        )

        self._owns_http_client = http_client is None
        self._http = http_client or httpx.Client(timeout=timeout_seconds)

    def close(self) -> None:
        if self._owns_http_client:
            self._http.close()

    def _url(self, service: str, path: str) -> str:
        base = self.rare_base_url if service == "rare" else self.platform_base_url
        if not path.startswith("/"):
            path = f"/{path}"
        return f"{base}{path}"

    def _request_json(
        self,
        *,
        method: str,
        service: str,
        path: str,
        json_payload: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict:
        response = self._http.request(
            method,
            self._url(service, path),
            json=json_payload,
            headers=headers,
        )

        body: dict | str
        try:
            body = response.json()
        except Exception:  # noqa: BLE001
            body = response.text

        if response.status_code >= 400:
            if isinstance(body, dict):
                detail = str(body.get("detail") or body)
            else:
                detail = body
            raise ApiError(status_code=response.status_code, detail=detail)

        if not isinstance(body, dict):
            raise AgentClientError("expected JSON object response")
        return body

    def register(
        self,
        *,
        name: str | None = None,
        key_mode: str = "hosted-signer",
        agent_private_key: str | None = None,
    ) -> dict:
        if key_mode not in {"hosted-signer", "self-hosted"}:
            raise AgentClientError("key_mode must be hosted-signer or self-hosted")

        payload: dict[str, Any] = {"key_mode": key_mode}
        if name is not None:
            payload["name"] = name

        local_agent_private_key: str | None = None
        if key_mode == "self-hosted":
            requested_name = name or self.state.name
            if not requested_name:
                raise AgentClientError("self-hosted register requires name")

            issued_at = now_ts()
            expires_at = issued_at + 120
            nonce = generate_nonce(10)
            local_agent_private_key = agent_private_key or self.state.agent_private_key

            if local_agent_private_key is None and self._signer is not None:
                signed = self._call_signer(
                    "sign_register",
                    self._signer.sign_register,
                    name=requested_name,
                    nonce=nonce,
                    issued_at=issued_at,
                    expires_at=expires_at,
                )
                payload.update(
                    {
                        "agent_public_key": signed["agent_public_key"],
                        "nonce": nonce,
                        "issued_at": issued_at,
                        "expires_at": expires_at,
                        "signature_by_agent": signed["signature_by_agent"],
                    }
                )
            else:
                if local_agent_private_key is None:
                    local_agent_private_key, generated_agent_public_key = generate_ed25519_keypair()
                else:
                    generated_agent_public_key = public_key_to_b64(
                        load_private_key(local_agent_private_key).public_key()
                    )

                sign_input = build_register_payload(
                    agent_id=generated_agent_public_key,
                    name=requested_name,
                    nonce=nonce,
                    issued_at=issued_at,
                    expires_at=expires_at,
                )
                signature = sign_detached(sign_input, load_private_key(local_agent_private_key))
                payload.update(
                    {
                        "agent_public_key": generated_agent_public_key,
                        "nonce": nonce,
                        "issued_at": issued_at,
                        "expires_at": expires_at,
                        "signature_by_agent": signature,
                    }
                )

        result = self._request_json(
            method="POST",
            service="rare",
            path="/v1/agents/self_register",
            json_payload=payload,
        )

        self.state.agent_id = result.get("agent_id")
        profile = result.get("profile")
        if isinstance(profile, dict):
            maybe_name = profile.get("name")
            if isinstance(maybe_name, str):
                self.state.name = maybe_name

        public_attestation = result.get("public_identity_attestation")
        if isinstance(public_attestation, str):
            self.state.public_identity_attestation = public_attestation

        self.state.key_mode = str(result.get("key_mode") or "hosted-signer")
        if self.state.key_mode == "self-hosted":
            self.state.agent_private_key = local_agent_private_key
        else:
            self.state.agent_private_key = None
            self._session_private_key = None

        self.state.full_identity_attestations = {}
        if not self.state.agent_id:
            raise AgentClientError("missing agent_id in register response")
        return result

    def refresh_attestation(self) -> dict:
        self._require_agent_id()
        result = self._request_json(
            method="POST",
            service="rare",
            path="/v1/attestations/public/issue",
            json_payload={"agent_id": self.state.agent_id},
        )

        public_attestation = result.get("public_identity_attestation")
        if isinstance(public_attestation, str):
            self.state.public_identity_attestation = public_attestation

        profile = result.get("profile")
        if isinstance(profile, dict) and isinstance(profile.get("name"), str):
            self.state.name = profile["name"]

        return result

    def set_name(self, *, name: str, ttl_seconds: int = 120) -> dict:
        agent_id = self._require_agent_id()

        if self._is_self_hosted():
            issued_at = now_ts()
            expires_at = issued_at + ttl_seconds
            nonce = generate_nonce(10)
            if self._signer is not None:
                signed = self._call_signer(
                    "sign_set_name",
                    self._signer.sign_set_name,
                    agent_id=agent_id,
                    name=name,
                    nonce=nonce,
                    issued_at=issued_at,
                    expires_at=expires_at,
                )
                signature = signed["signature_by_agent"]
            else:
                sign_input = build_set_name_payload(
                    agent_id=agent_id,
                    name=name,
                    nonce=nonce,
                    issued_at=issued_at,
                    expires_at=expires_at,
                )
                signature = sign_detached(
                    sign_input,
                    load_private_key(self._require_agent_private_key()),
                )
            signed_payload = {
                "agent_id": agent_id,
                "name": name,
                "nonce": nonce,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "signature_by_agent": signature,
            }
        else:
            signed_payload = self._request_json(
                method="POST",
                service="rare",
                path="/v1/signer/sign_set_name",
                json_payload={
                    "agent_id": agent_id,
                    "name": name,
                    "ttl_seconds": ttl_seconds,
                },
            )

        result = self._request_json(
            method="POST",
            service="rare",
            path="/v1/agents/set_name",
            json_payload=signed_payload,
        )

        maybe_name = result.get("name")
        if isinstance(maybe_name, str):
            self.state.name = maybe_name

        public_attestation = result.get("public_identity_attestation")
        if isinstance(public_attestation, str):
            self.state.public_identity_attestation = public_attestation

        return result

    def grant_platform(self, *, aud: str, ttl_seconds: int = 120) -> dict:
        agent_id = self._require_agent_id()
        issued_at = now_ts()
        expires_at = issued_at + ttl_seconds
        nonce = generate_nonce(10)

        if self._is_self_hosted():
            if self._signer is not None:
                signed = self._call_signer(
                    "sign_platform_grant",
                    self._signer.sign_platform_grant,
                    agent_id=agent_id,
                    platform_aud=aud,
                    nonce=nonce,
                    issued_at=issued_at,
                    expires_at=expires_at,
                )
                signature = signed["signature_by_agent"]
            else:
                sign_input = build_platform_grant_payload(
                    agent_id=agent_id,
                    platform_aud=aud,
                    nonce=nonce,
                    issued_at=issued_at,
                    expires_at=expires_at,
                )
                signature = sign_detached(sign_input, load_private_key(self._require_agent_private_key()))
            signed_payload = {
                "agent_id": agent_id,
                "platform_aud": aud,
                "nonce": nonce,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "signature_by_agent": signature,
            }
        else:
            signed_payload = self._request_json(
                method="POST",
                service="rare",
                path="/v1/signer/sign_platform_grant",
                json_payload={
                    "agent_id": agent_id,
                    "platform_aud": aud,
                    "ttl_seconds": ttl_seconds,
                },
            )
        return self._request_json(
            method="POST",
            service="rare",
            path="/v1/agents/platform-grants",
            json_payload=signed_payload,
        )

    def revoke_platform(self, *, aud: str, ttl_seconds: int = 120) -> dict:
        agent_id = self._require_agent_id()
        issued_at = now_ts()
        expires_at = issued_at + ttl_seconds
        nonce = generate_nonce(10)

        if self._is_self_hosted():
            if self._signer is not None:
                signed = self._call_signer(
                    "sign_platform_grant",
                    self._signer.sign_platform_grant,
                    agent_id=agent_id,
                    platform_aud=aud,
                    nonce=nonce,
                    issued_at=issued_at,
                    expires_at=expires_at,
                )
                signature = signed["signature_by_agent"]
            else:
                sign_input = build_platform_grant_payload(
                    agent_id=agent_id,
                    platform_aud=aud,
                    nonce=nonce,
                    issued_at=issued_at,
                    expires_at=expires_at,
                )
                signature = sign_detached(sign_input, load_private_key(self._require_agent_private_key()))
            signed_payload = {
                "agent_id": agent_id,
                "nonce": nonce,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "signature_by_agent": signature,
            }
        else:
            signed = self._request_json(
                method="POST",
                service="rare",
                path="/v1/signer/sign_platform_grant",
                json_payload={
                    "agent_id": agent_id,
                    "platform_aud": aud,
                    "ttl_seconds": ttl_seconds,
                },
            )
            signed_payload = {
                "agent_id": agent_id,
                "nonce": signed["nonce"],
                "issued_at": signed["issued_at"],
                "expires_at": signed["expires_at"],
                "signature_by_agent": signed["signature_by_agent"],
            }
        return self._request_json(
            method="DELETE",
            service="rare",
            path=f"/v1/agents/platform-grants/{aud}",
            json_payload=signed_payload,
        )

    def list_platform_grants(self) -> dict:
        agent_id = self._require_agent_id()
        return self._request_json(
            method="GET",
            service="rare",
            path=f"/v1/agents/platform-grants/{agent_id}",
        )

    def issue_full_attestation(self, *, aud: str, ttl_seconds: int = 120) -> dict:
        agent_id = self._require_agent_id()
        issued_at = now_ts()
        expires_at = issued_at + ttl_seconds
        nonce = generate_nonce(10)

        if self._is_self_hosted():
            if self._signer is not None:
                signed = self._call_signer(
                    "sign_full_attestation_issue",
                    self._signer.sign_full_attestation_issue,
                    agent_id=agent_id,
                    platform_aud=aud,
                    nonce=nonce,
                    issued_at=issued_at,
                    expires_at=expires_at,
                )
                signature = signed["signature_by_agent"]
            else:
                sign_input = build_full_attestation_issue_payload(
                    agent_id=agent_id,
                    platform_aud=aud,
                    nonce=nonce,
                    issued_at=issued_at,
                    expires_at=expires_at,
                )
                signature = sign_detached(sign_input, load_private_key(self._require_agent_private_key()))
            signed_payload = {
                "agent_id": agent_id,
                "platform_aud": aud,
                "nonce": nonce,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "signature_by_agent": signature,
            }
        else:
            signed_payload = self._request_json(
                method="POST",
                service="rare",
                path="/v1/signer/sign_full_attestation_issue",
                json_payload={
                    "agent_id": agent_id,
                    "platform_aud": aud,
                    "ttl_seconds": ttl_seconds,
                },
            )
        result = self._request_json(
            method="POST",
            service="rare",
            path="/v1/attestations/full/issue",
            json_payload=signed_payload,
        )
        full_attestation = result.get("full_identity_attestation")
        if isinstance(full_attestation, str):
            self.state.full_identity_attestations[aud] = full_attestation
        return result

    def _sign_upgrade_request(
        self,
        *,
        target_level: str,
        request_id: str,
        ttl_seconds: int,
    ) -> dict[str, Any]:
        agent_id = self._require_agent_id()
        issued_at = now_ts()
        expires_at = issued_at + ttl_seconds
        nonce = generate_nonce(10)

        if self._is_self_hosted():
            if self._signer is not None:
                signed = self._call_signer(
                    "sign_upgrade_request",
                    self._signer.sign_upgrade_request,
                    agent_id=agent_id,
                    target_level=target_level,
                    request_id=request_id,
                    nonce=nonce,
                    issued_at=issued_at,
                    expires_at=expires_at,
                )
                signature = signed["signature_by_agent"]
            else:
                sign_input = build_upgrade_request_payload(
                    agent_id=agent_id,
                    target_level=target_level,
                    request_id=request_id,
                    nonce=nonce,
                    issued_at=issued_at,
                    expires_at=expires_at,
                )
                signature = sign_detached(
                    sign_input,
                    load_private_key(self._require_agent_private_key()),
                )
            return {
                "agent_id": agent_id,
                "target_level": target_level,
                "request_id": request_id,
                "nonce": nonce,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "signature_by_agent": signature,
            }

        return self._request_json(
            method="POST",
            service="rare",
            path="/v1/signer/sign_upgrade_request",
            json_payload={
                "agent_id": agent_id,
                "target_level": target_level,
                "request_id": request_id,
                "ttl_seconds": ttl_seconds,
            },
        )

    def request_upgrade_l1(self, *, email: str, ttl_seconds: int = 120) -> dict:
        request_id = generate_nonce(10)
        signed_payload = self._sign_upgrade_request(
            target_level="L1",
            request_id=request_id,
            ttl_seconds=ttl_seconds,
        )
        signed_payload["contact_email"] = email
        return self._request_json(
            method="POST",
            service="rare",
            path="/v1/upgrades/requests",
            json_payload=signed_payload,
        )

    def request_upgrade_l2(self, *, ttl_seconds: int = 120) -> dict:
        request_id = generate_nonce(10)
        signed_payload = self._sign_upgrade_request(
            target_level="L2",
            request_id=request_id,
            ttl_seconds=ttl_seconds,
        )
        return self._request_json(
            method="POST",
            service="rare",
            path="/v1/upgrades/requests",
            json_payload=signed_payload,
        )

    def get_upgrade_status(self, *, request_id: str) -> dict:
        return self._request_json(
            method="GET",
            service="rare",
            path=f"/v1/upgrades/requests/{request_id}",
        )

    def send_l1_upgrade_magic_link(self, *, request_id: str) -> dict:
        return self._request_json(
            method="POST",
            service="rare",
            path="/v1/upgrades/l1/email/send-link",
            json_payload={"upgrade_request_id": request_id},
        )

    def verify_l1_upgrade_magic_link(self, *, token: str) -> dict:
        return self._request_json(
            method="GET",
            service="rare",
            path=f"/v1/upgrades/l1/email/verify?token={token}",
        )

    def start_l2_social(self, *, request_id: str, provider: str) -> dict:
        return self._request_json(
            method="POST",
            service="rare",
            path="/v1/upgrades/l2/social/start",
            json_payload={
                "upgrade_request_id": request_id,
                "provider": provider,
            },
        )

    def complete_l2_social(
        self,
        *,
        request_id: str,
        provider: str,
        provider_user_snapshot: dict[str, Any],
    ) -> dict:
        return self._request_json(
            method="POST",
            service="rare",
            path="/v1/upgrades/l2/social/complete",
            json_payload={
                "upgrade_request_id": request_id,
                "provider": provider,
                "provider_user_snapshot": provider_user_snapshot,
            },
        )

    def login(
        self,
        *,
        aud: str = "platform",
        scope: list[str] | None = None,
        delegation_ttl_seconds: int = 3600,
        use_rare_signer: bool = True,
        prefer_full: bool = True,
        full_hard_fail: bool = True,
    ) -> dict:
        del use_rare_signer
        agent_id = self._require_agent_id()
        scope = scope or ["login"]

        challenge = self._request_json(
            method="POST",
            service="platform",
            path="/auth/challenge",
            json_payload={"aud": aud},
        )

        if self._is_self_hosted():
            if self._signer is not None:
                proof = self._call_signer(
                    "create_auth_proof",
                    self._signer.create_auth_proof,
                    agent_id=agent_id,
                    aud=aud,
                    nonce=challenge["nonce"],
                    issued_at=challenge["issued_at"],
                    expires_at=challenge["expires_at"],
                    scope=scope,
                    delegation_ttl_seconds=delegation_ttl_seconds,
                )
                self._session_private_key = None
            else:
                session_private_key, session_pubkey = generate_ed25519_keypair()
                sign_input = build_auth_challenge_payload(
                    aud=aud,
                    nonce=challenge["nonce"],
                    issued_at=challenge["issued_at"],
                    expires_at=challenge["expires_at"],
                )
                signature = sign_detached(sign_input, load_private_key(session_private_key))
                delegation = issue_agent_delegation(
                    agent_id=agent_id,
                    session_pubkey=session_pubkey,
                    aud=aud,
                    scope=scope,
                    signer_private_key=load_private_key(self._require_agent_private_key()),
                    kid=f"agent-{agent_id[:8]}",
                    ttl_seconds=delegation_ttl_seconds,
                    jti=generate_nonce(12),
                )
                proof = {
                    "session_pubkey": session_pubkey,
                    "delegation_token": delegation,
                    "signature_by_session": signature,
                }
                self._session_private_key = session_private_key
        else:
            proof = self._request_json(
                method="POST",
                service="rare",
                path="/v1/signer/prepare_auth",
                json_payload={
                    "agent_id": agent_id,
                    "aud": aud,
                    "nonce": challenge["nonce"],
                    "issued_at": challenge["issued_at"],
                    "expires_at": challenge["expires_at"],
                    "scope": scope,
                    "delegation_ttl_seconds": delegation_ttl_seconds,
                },
            )
            self._session_private_key = None

        full_attestation: str | None = None
        if prefer_full:
            try:
                full_result = self.issue_full_attestation(aud=aud)
                maybe_full = full_result.get("full_identity_attestation")
                if isinstance(maybe_full, str):
                    full_attestation = maybe_full
            except AgentClientError:
                if full_hard_fail:
                    raise

        public_attestation = self._require_public_identity_attestation()
        result = self._request_json(
            method="POST",
            service="platform",
            path="/auth/complete",
            json_payload={
                "nonce": challenge["nonce"],
                "agent_id": agent_id,
                "session_pubkey": proof["session_pubkey"],
                "delegation_token": proof["delegation_token"],
                "signature_by_session": proof["signature_by_session"],
                "public_identity_attestation": public_attestation,
                "full_identity_attestation": full_attestation,
            },
        )

        self.state.session_token = str(result.get("session_token") or "")
        self.state.session_pubkey = str(proof["session_pubkey"])
        self.state.session_aud = aud

        maybe_level = result.get("level")
        if isinstance(maybe_level, str):
            self.state.level = maybe_level

        maybe_display_name = result.get("display_name")
        if isinstance(maybe_display_name, str):
            self.state.display_name = maybe_display_name

        if not self.state.session_token:
            raise AgentClientError("missing session_token in login response")

        return result

    def sign_platform_action(
        self,
        *,
        action: str,
        action_payload: dict[str, Any],
        ttl_seconds: int = 120,
        aud: str | None = None,
    ) -> dict:
        agent_id = self._require_agent_id()
        session_pubkey = self._require_session_pubkey()
        session_token = self._require_session_token()
        resolved_aud = aud or self.state.session_aud or "platform"

        issued_at = now_ts()
        expires_at = issued_at + ttl_seconds
        nonce = generate_nonce(10)

        if self._is_self_hosted():
            if self._signer is not None:
                signed = self._call_signer(
                    "sign_action",
                    self._signer.sign_action,
                    session_pubkey=session_pubkey,
                    session_token=session_token,
                    aud=resolved_aud,
                    action=action,
                    action_payload=action_payload,
                    nonce=nonce,
                    issued_at=issued_at,
                    expires_at=expires_at,
                )
                signature = signed["signature_by_session"]
            else:
                signing_input = build_action_payload(
                    aud=resolved_aud,
                    session_token=session_token,
                    action=action,
                    action_payload=action_payload,
                    nonce=nonce,
                    issued_at=issued_at,
                    expires_at=expires_at,
                )
                signature = sign_detached(
                    signing_input,
                    load_private_key(self._require_session_private_key()),
                )
            return {
                "agent_id": agent_id,
                "session_pubkey": session_pubkey,
                "session_token": session_token,
                "aud": resolved_aud,
                "action": action,
                "action_payload": action_payload,
                "nonce": nonce,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "signature_by_session": signature,
            }

        return self._request_json(
            method="POST",
            service="rare",
            path="/v1/signer/sign_action",
            json_payload={
                "agent_id": agent_id,
                "session_pubkey": session_pubkey,
                "session_token": session_token,
                "aud": resolved_aud,
                "action": action,
                "action_payload": action_payload,
                "nonce": nonce,
                "issued_at": issued_at,
                "expires_at": expires_at,
            },
        )

    def _require_agent_id(self) -> str:
        if not self.state.agent_id:
            raise AgentClientError("agent_id missing; run register first")
        return self.state.agent_id

    def _require_public_identity_attestation(self) -> str:
        if not self.state.public_identity_attestation:
            raise AgentClientError("public_identity_attestation missing; register or refresh first")
        return self.state.public_identity_attestation

    def _require_session_token(self) -> str:
        if not self.state.session_token:
            raise AgentClientError("session_token missing; run login first")
        return self.state.session_token

    def _require_session_pubkey(self) -> str:
        if not self.state.session_pubkey:
            raise AgentClientError("session_pubkey missing; run login first")
        return self.state.session_pubkey

    def _is_self_hosted(self) -> bool:
        return self.state.key_mode == "self-hosted"

    def _require_agent_private_key(self) -> str:
        if not self.state.agent_private_key:
            if self._signer is not None:
                raise AgentClientError("agent_private_key missing; use configured local signer")
            raise AgentClientError("agent_private_key missing for self-hosted mode")
        return self.state.agent_private_key

    def _require_session_private_key(self) -> str:
        if not self._session_private_key:
            raise AgentClientError("session_private_key missing; run login in current process first")
        return self._session_private_key

    def _call_signer(self, operation: str, func, **kwargs):
        try:
            return func(**kwargs)
        except LocalSignerError as exc:
            raise AgentClientError(f"local signer {operation} failed: {exc}") from exc
