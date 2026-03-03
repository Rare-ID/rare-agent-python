from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from rare_identity_protocol import (
    TokenValidationError,
    build_action_payload,
    build_auth_challenge_payload,
    decode_jws,
    generate_nonce,
    load_public_key,
    now_ts,
    verify_detached,
)
from rare_identity_verifier import verify_delegation_token, verify_identity_attestation


@dataclass
class ChallengeRecord:
    nonce: str
    aud: str
    issued_at: int
    expires_at: int
    consumed: bool = False


@dataclass
class SessionRecord:
    token: str
    agent_id: str
    session_pubkey: str
    level: str
    display_name: str
    expires_at: int


class PlatformStubService:
    def __init__(
        self,
        *,
        aud: str,
        identity_key_resolver: Callable[[str], Ed25519PublicKey | None],
        rare_signer_public_key_provider: Callable[[], Ed25519PublicKey | None],
        challenge_ttl_seconds: int = 120,
        session_ttl_seconds: int = 3600,
    ) -> None:
        self.aud = aud
        self.identity_key_resolver = identity_key_resolver
        self.rare_signer_public_key_provider = rare_signer_public_key_provider
        self.challenge_ttl_seconds = challenge_ttl_seconds
        self.session_ttl_seconds = session_ttl_seconds
        self.challenges: dict[str, ChallengeRecord] = {}
        self.sessions: dict[str, SessionRecord] = {}
        self.used_action_nonces: dict[tuple[str, str], int] = {}
        self.posts: list[dict[str, Any]] = []

    def issue_challenge(self) -> dict[str, Any]:
        now = now_ts()
        nonce = generate_nonce(18)
        record = ChallengeRecord(
            nonce=nonce,
            aud=self.aud,
            issued_at=now,
            expires_at=now + self.challenge_ttl_seconds,
        )
        self.challenges[nonce] = record
        return {
            "nonce": record.nonce,
            "aud": record.aud,
            "issued_at": record.issued_at,
            "expires_at": record.expires_at,
        }

    def _consume_challenge(self, nonce: str) -> ChallengeRecord:
        record = self.challenges.get(nonce)
        if record is None:
            raise TokenValidationError("unknown challenge nonce")
        if record.consumed:
            raise TokenValidationError("challenge nonce already consumed")
        if record.expires_at < now_ts() - 30:
            raise TokenValidationError("challenge expired")
        record.consumed = True
        return record

    def complete_auth(
        self,
        *,
        nonce: str,
        agent_id: str,
        session_pubkey: str,
        delegation_token: str,
        signature_by_session: str,
        public_identity_attestation: str | None = None,
        full_identity_attestation: str | None = None,
    ) -> dict[str, Any]:
        challenge = self._consume_challenge(nonce)
        challenge_payload = build_auth_challenge_payload(
            aud=challenge.aud,
            nonce=challenge.nonce,
            issued_at=challenge.issued_at,
            expires_at=challenge.expires_at,
        )
        verify_detached(
            challenge_payload,
            signature_by_session,
            load_public_key(session_pubkey),
        )

        delegation = verify_delegation_token(
            delegation_token,
            expected_aud=self.aud,
            required_scope="login",
            rare_signer_public_key=self.rare_signer_public_key_provider(),
        ).payload

        identity_token = full_identity_attestation or public_identity_attestation
        if not identity_token:
            raise TokenValidationError("missing identity attestation")
        identity_header = decode_jws(identity_token).header
        expected_aud = self.aud if identity_header.get("typ") == "rare.identity.full+jws" else None
        identity = verify_identity_attestation(
            identity_token,
            key_resolver=self.identity_key_resolver,
            expected_aud=expected_aud,
        ).payload

        delegated_agent = delegation.get("agent_id")
        identity_sub = identity.get("sub")
        if agent_id != delegated_agent or agent_id != identity_sub:
            raise TokenValidationError("agent identity triad mismatch")
        if delegation.get("session_pubkey") != session_pubkey:
            raise TokenValidationError("session pubkey mismatch")

        level = identity.get("lvl")
        if not isinstance(level, str):
            raise TokenValidationError("identity level missing")

        display_name = "unknown"
        claims = identity.get("claims")
        if isinstance(claims, dict):
            profile = claims.get("profile")
            if isinstance(profile, dict):
                maybe_name = profile.get("name")
                if isinstance(maybe_name, str) and maybe_name.strip():
                    display_name = maybe_name

        session_token = generate_nonce(24)
        self.sessions[session_token] = SessionRecord(
            token=session_token,
            agent_id=agent_id,
            session_pubkey=session_pubkey,
            level=level,
            display_name=display_name,
            expires_at=now_ts() + self.session_ttl_seconds,
        )
        return {
            "session_token": session_token,
            "agent_id": agent_id,
            "level": level,
            "display_name": display_name,
            "session_pubkey": session_pubkey,
        }

    def _require_session(self, session_token: str) -> SessionRecord:
        session = self.sessions.get(session_token)
        if session is None:
            raise PermissionError("invalid session token")
        if session.expires_at < now_ts():
            self.sessions.pop(session_token, None)
            raise PermissionError("session expired")
        return session

    def _cleanup_action_nonces(self, *, now: int) -> None:
        expired = [key for key, exp in self.used_action_nonces.items() if exp < now]
        for key in expired:
            self.used_action_nonces.pop(key, None)

    def create_post(
        self,
        *,
        session_token: str,
        content: str,
        nonce: str,
        issued_at: int,
        expires_at: int,
        signature_by_session: str,
    ) -> dict[str, Any]:
        session = self._require_session(session_token)
        now = now_ts()
        self._cleanup_action_nonces(now=now)
        nonce_key = (session_token, nonce)
        if nonce_key in self.used_action_nonces:
            raise TokenValidationError("action nonce already consumed")
        if expires_at < now - 30:
            raise TokenValidationError("action expired")
        if expires_at <= issued_at:
            raise TokenValidationError("action expires_at must be greater than issued_at")

        signing_input = build_action_payload(
            aud=self.aud,
            session_token=session_token,
            action="post",
            action_payload={"content": content},
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        verify_detached(signing_input, signature_by_session, load_public_key(session.session_pubkey))
        self.used_action_nonces[nonce_key] = expires_at

        post = {
            "id": f"post-{len(self.posts) + 1}",
            "agent_id": session.agent_id,
            "display_name": session.display_name,
            "level": session.level,
            "content": content,
            "created_at": now,
        }
        self.posts.append(post)
        return post


class AuthChallengeRequest(BaseModel):
    aud: str | None = None


class AuthCompleteRequest(BaseModel):
    nonce: str
    agent_id: str
    session_pubkey: str
    delegation_token: str
    signature_by_session: str
    public_identity_attestation: str | None = None
    full_identity_attestation: str | None = None


class PostRequest(BaseModel):
    content: str = Field(min_length=1, max_length=2000)
    nonce: str
    issued_at: int
    expires_at: int
    signature_by_session: str


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="missing Authorization header")
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        raise HTTPException(status_code=401, detail="invalid Authorization header")
    token = authorization[len(prefix) :].strip()
    if not token:
        raise HTTPException(status_code=401, detail="empty bearer token")
    return token


def _raise_http(exc: Exception) -> None:
    if isinstance(exc, PermissionError):
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    if isinstance(exc, TokenValidationError):
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    raise HTTPException(status_code=500, detail="internal server error") from exc


def create_platform_app(service: PlatformStubService) -> FastAPI:
    app = FastAPI(title="Platform Stub", version="0.1.0")

    @app.post("/auth/challenge")
    def auth_challenge(request: AuthChallengeRequest) -> dict[str, Any]:
        if request.aud and request.aud != service.aud:
            raise HTTPException(status_code=400, detail="aud mismatch")
        return service.issue_challenge()

    @app.post("/auth/complete")
    def auth_complete(request: AuthCompleteRequest) -> dict[str, Any]:
        try:
            return service.complete_auth(
                nonce=request.nonce,
                agent_id=request.agent_id,
                session_pubkey=request.session_pubkey,
                delegation_token=request.delegation_token,
                signature_by_session=request.signature_by_session,
                public_identity_attestation=request.public_identity_attestation,
                full_identity_attestation=request.full_identity_attestation,
            )
        except Exception as exc:  # noqa: BLE001
            _raise_http(exc)

    @app.post("/posts")
    def create_post(
        request: PostRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        token = _extract_bearer_token(authorization)
        try:
            return service.create_post(
                session_token=token,
                content=request.content,
                nonce=request.nonce,
                issued_at=request.issued_at,
                expires_at=request.expires_at,
                signature_by_session=request.signature_by_session,
            )
        except Exception as exc:  # noqa: BLE001
            _raise_http(exc)

    return app
