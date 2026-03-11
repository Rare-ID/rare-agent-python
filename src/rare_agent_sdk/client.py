from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from rare_identity_protocol import (
    build_action_payload,
    build_agent_auth_payload,
    build_auth_challenge_payload,
    build_full_attestation_issue_payload,
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

from rare_agent_sdk.local_signer import LocalSignerClient, LocalSignerError
from rare_agent_sdk.state import AgentState


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
        rare_base_url: str = "http://127.0.0.1:8000",
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
            self.state.hosted_management_token = None
            self.state.hosted_management_token_expires_at = None
        else:
            self.state.agent_private_key = None
            self._session_private_key = None
            hosted_management_token = result.get("hosted_management_token")
            if not isinstance(hosted_management_token, str) or not hosted_management_token:
                raise AgentClientError("missing hosted_management_token in register response")
            hosted_management_token_expires_at = result.get("hosted_management_token_expires_at")
            if not isinstance(hosted_management_token_expires_at, int):
                raise AgentClientError("missing hosted_management_token_expires_at in register response")
            self.state.hosted_management_token = hosted_management_token
            self.state.hosted_management_token_expires_at = hosted_management_token_expires_at

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
                headers=self._hosted_signer_headers(),
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
                headers=self._hosted_signer_headers(),
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
            headers=self._hosted_signer_headers(),
        )

    def request_upgrade_l1(self, *, email: str, ttl_seconds: int = 120, send_email: bool = True) -> dict:
        request_id = generate_nonce(10)
        signed_payload = self._sign_upgrade_request(
            target_level="L1",
            request_id=request_id,
            ttl_seconds=ttl_seconds,
        )
        signed_payload["contact_email"] = email
        signed_payload["send_email"] = send_email
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
            headers=self._management_headers(operation="upgrade_status", resource_id=request_id),
        )

    def rotate_hosted_management_token(self) -> dict:
        if self._is_self_hosted():
            raise AgentClientError("rotate_hosted_management_token is only available in hosted-signer mode")
        agent_id = self._require_agent_id()
        result = self._request_json(
            method="POST",
            service="rare",
            path="/v1/signer/rotate_management_token",
            json_payload={"agent_id": agent_id},
            headers=self._hosted_signer_headers(),
        )
        token = result.get("hosted_management_token")
        expires_at = result.get("hosted_management_token_expires_at")
        if not isinstance(token, str) or not token:
            raise AgentClientError("missing hosted_management_token in rotate response")
        if not isinstance(expires_at, int):
            raise AgentClientError("missing hosted_management_token_expires_at in rotate response")
        self.state.hosted_management_token = token
        self.state.hosted_management_token_expires_at = expires_at
        return result

    def get_hosted_management_recovery_factors(self, *, agent_id: str | None = None) -> dict:
        resolved_agent_id = agent_id or self._require_agent_id()
        return self._request_json(
            method="GET",
            service="rare",
            path=f"/v1/signer/recovery/factors/{resolved_agent_id}",
        )

    def send_hosted_management_recovery_email_link(self, *, agent_id: str | None = None) -> dict:
        resolved_agent_id = agent_id or self._require_agent_id()
        return self._request_json(
            method="POST",
            service="rare",
            path="/v1/signer/recovery/email/send-link",
            json_payload={"agent_id": resolved_agent_id},
        )

    def verify_hosted_management_recovery_email(self, *, token: str) -> dict:
        result = self._request_json(
            method="POST",
            service="rare",
            path="/v1/signer/recovery/email/verify",
            json_payload={"token": token},
        )
        self._apply_recovered_hosted_management_token(result)
        return result

    def start_hosted_management_recovery_social(self, *, provider: str, agent_id: str | None = None) -> dict:
        resolved_agent_id = agent_id or self._require_agent_id()
        return self._request_json(
            method="POST",
            service="rare",
            path="/v1/signer/recovery/social/start",
            json_payload={"agent_id": resolved_agent_id, "provider": provider},
        )

    def complete_hosted_management_recovery_social(
        self,
        *,
        provider: str,
        provider_user_snapshot: dict[str, Any],
        agent_id: str | None = None,
    ) -> dict:
        resolved_agent_id = agent_id or self._require_agent_id()
        result = self._request_json(
            method="POST",
            service="rare",
            path="/v1/signer/recovery/social/complete",
            json_payload={
                "agent_id": resolved_agent_id,
                "provider": provider,
                "provider_user_snapshot": provider_user_snapshot,
            },
        )
        self._apply_recovered_hosted_management_token(result)
        return result

    def revoke_hosted_management_token(self) -> dict:
        if self._is_self_hosted():
            raise AgentClientError("revoke_hosted_management_token is only available in hosted-signer mode")
        agent_id = self._require_agent_id()
        result = self._request_json(
            method="POST",
            service="rare",
            path="/v1/signer/revoke_management_token",
            json_payload={"agent_id": agent_id},
            headers=self._hosted_signer_headers(),
        )
        self.state.hosted_management_token = None
        self.state.hosted_management_token_expires_at = None
        return result

    def send_l1_upgrade_magic_link(self, *, request_id: str) -> dict:
        return self._request_json(
            method="POST",
            service="rare",
            path="/v1/upgrades/l1/email/send-link",
            json_payload={"upgrade_request_id": request_id},
            headers=self._management_headers(operation="upgrade_send_link", resource_id=request_id),
        )

    def verify_l1_upgrade_magic_link(self, *, token: str) -> dict:
        return self._request_json(
            method="POST",
            service="rare",
            path="/v1/upgrades/l1/email/verify",
            json_payload={"token": token},
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
            headers=self._management_headers(
                operation="upgrade_start_social",
                resource_id=f"{request_id}:{provider}",
            ),
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
            headers=self._management_headers(
                operation="upgrade_complete_social",
                resource_id=f"{request_id}:{provider}",
            ),
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
                headers=self._hosted_signer_headers(),
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
            headers=self._hosted_signer_headers(),
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

    def _require_hosted_management_token(self) -> str:
        if not self.state.hosted_management_token:
            raise AgentClientError("hosted_management_token missing; re-register hosted-signer agent")
        expires_at = self.state.hosted_management_token_expires_at
        if isinstance(expires_at, int) and expires_at <= now_ts():
            raise AgentClientError("hosted_management_token expired; rotate hosted token or re-register agent")
        return self.state.hosted_management_token

    def _hosted_signer_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._require_hosted_management_token()}"}

    def _apply_recovered_hosted_management_token(self, payload: dict[str, Any]) -> None:
        agent_id = payload.get("agent_id")
        token = payload.get("hosted_management_token")
        expires_at = payload.get("hosted_management_token_expires_at")
        if not isinstance(agent_id, str) or not agent_id:
            raise AgentClientError("missing agent_id in hosted management recovery response")
        if self.state.agent_id and self.state.agent_id != agent_id:
            raise AgentClientError("recovery response agent_id does not match local state")
        if not isinstance(token, str) or not token:
            raise AgentClientError("missing hosted_management_token in hosted management recovery response")
        if not isinstance(expires_at, int):
            raise AgentClientError("missing hosted_management_token_expires_at in hosted management recovery response")
        self.state.agent_id = agent_id
        self.state.key_mode = "hosted-signer"
        self.state.hosted_management_token = token
        self.state.hosted_management_token_expires_at = expires_at

    def _management_headers(self, *, operation: str, resource_id: str) -> dict[str, str]:
        if not self._is_self_hosted():
            return self._hosted_signer_headers()
        return self._self_hosted_management_headers(operation=operation, resource_id=resource_id)

    def _self_hosted_management_headers(self, *, operation: str, resource_id: str) -> dict[str, str]:
        agent_id = self._require_agent_id()
        issued_at = now_ts()
        expires_at = issued_at + 120
        nonce = generate_nonce(10)

        if self._signer is not None:
            signed = self._call_signer(
                "sign_management_auth",
                self._signer.sign_management_auth,
                agent_id=agent_id,
                operation=operation,
                resource_id=resource_id,
                nonce=nonce,
                issued_at=issued_at,
                expires_at=expires_at,
            )
            signature = signed["signature_by_agent"]
        else:
            payload = build_agent_auth_payload(
                agent_id=agent_id,
                operation=operation,
                resource_id=resource_id,
                nonce=nonce,
                issued_at=issued_at,
                expires_at=expires_at,
            )
            signature = sign_detached(payload, load_private_key(self._require_agent_private_key()))

        return {
            "X-Rare-Agent-Id": agent_id,
            "X-Rare-Agent-Nonce": nonce,
            "X-Rare-Agent-Issued-At": str(issued_at),
            "X-Rare-Agent-Expires-At": str(expires_at),
            "X-Rare-Agent-Signature": signature,
        }

    def _call_signer(self, operation: str, func, **kwargs):
        try:
            return func(**kwargs)
        except LocalSignerError as exc:
            raise AgentClientError(f"local signer {operation} failed: {exc}") from exc
