from __future__ import annotations

import json
import os
import socket
import socketserver
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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


class LocalSignerError(RuntimeError):
    """Raised when local signer IPC or operation execution fails."""


@dataclass
class LocalSignerService:
    key_file: Path
    session_private_keys: dict[str, str] = field(default_factory=dict)
    _agent_private_key: str = field(init=False)

    def __post_init__(self) -> None:
        self._agent_private_key = self._load_or_create_agent_key()

    @property
    def agent_id(self) -> str:
        return public_key_to_b64(load_private_key(self._agent_private_key).public_key())

    def _load_or_create_agent_key(self) -> str:
        if self.key_file.exists():
            raw = self.key_file.read_text(encoding="utf-8").strip()
            load_private_key(raw)
            return raw

        private_key, _ = generate_ed25519_keypair()
        self.key_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.key_file.parent, 0o700)
        except FileNotFoundError:
            pass
        self.key_file.write_text(private_key, encoding="utf-8")
        os.chmod(self.key_file, 0o600)
        return private_key

    def sign_register(self, *, name: str, nonce: str, issued_at: int, expires_at: int) -> dict[str, Any]:
        sign_input = build_register_payload(
            agent_id=self.agent_id,
            name=name,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        signature = sign_detached(sign_input, load_private_key(self._agent_private_key))
        return {
            "agent_public_key": self.agent_id,
            "signature_by_agent": signature,
        }

    def sign_set_name(
        self,
        *,
        agent_id: str,
        name: str,
        nonce: str,
        issued_at: int,
        expires_at: int,
    ) -> dict[str, Any]:
        if agent_id != self.agent_id:
            raise LocalSignerError("agent_id does not match signer identity")
        sign_input = build_set_name_payload(
            agent_id=agent_id,
            name=name,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        signature = sign_detached(sign_input, load_private_key(self._agent_private_key))
        return {"signature_by_agent": signature}

    def create_auth_proof(
        self,
        *,
        agent_id: str,
        aud: str,
        nonce: str,
        issued_at: int,
        expires_at: int,
        scope: list[str],
        delegation_ttl_seconds: int,
    ) -> dict[str, Any]:
        if agent_id != self.agent_id:
            raise LocalSignerError("agent_id does not match signer identity")
        if issued_at > now_ts() + 30:
            raise LocalSignerError("challenge issued_at too far in future")
        if expires_at <= issued_at:
            raise LocalSignerError("challenge expires_at must be greater than issued_at")

        session_private_key, session_pubkey = generate_ed25519_keypair()
        sign_input = build_auth_challenge_payload(
            aud=aud,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        signature_by_session = sign_detached(sign_input, load_private_key(session_private_key))
        delegation_token = issue_agent_delegation(
            agent_id=agent_id,
            session_pubkey=session_pubkey,
            aud=aud,
            scope=scope,
            signer_private_key=load_private_key(self._agent_private_key),
            kid=f"agent-{agent_id[:8]}",
            ttl_seconds=delegation_ttl_seconds,
            jti=generate_nonce(12),
        )
        self.session_private_keys[session_pubkey] = session_private_key
        return {
            "session_pubkey": session_pubkey,
            "delegation_token": delegation_token,
            "signature_by_session": signature_by_session,
        }

    def sign_platform_grant(
        self,
        *,
        agent_id: str,
        platform_aud: str,
        nonce: str,
        issued_at: int,
        expires_at: int,
    ) -> dict[str, Any]:
        if agent_id != self.agent_id:
            raise LocalSignerError("agent_id does not match signer identity")
        sign_input = build_platform_grant_payload(
            agent_id=agent_id,
            platform_aud=platform_aud,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        signature = sign_detached(sign_input, load_private_key(self._agent_private_key))
        return {"signature_by_agent": signature}

    def sign_full_attestation_issue(
        self,
        *,
        agent_id: str,
        platform_aud: str,
        nonce: str,
        issued_at: int,
        expires_at: int,
    ) -> dict[str, Any]:
        if agent_id != self.agent_id:
            raise LocalSignerError("agent_id does not match signer identity")
        sign_input = build_full_attestation_issue_payload(
            agent_id=agent_id,
            platform_aud=platform_aud,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        signature = sign_detached(sign_input, load_private_key(self._agent_private_key))
        return {"signature_by_agent": signature}

    def sign_upgrade_request(
        self,
        *,
        agent_id: str,
        target_level: str,
        request_id: str,
        nonce: str,
        issued_at: int,
        expires_at: int,
    ) -> dict[str, Any]:
        if agent_id != self.agent_id:
            raise LocalSignerError("agent_id does not match signer identity")
        sign_input = build_upgrade_request_payload(
            agent_id=agent_id,
            target_level=target_level,
            request_id=request_id,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        signature = sign_detached(sign_input, load_private_key(self._agent_private_key))
        return {"signature_by_agent": signature}

    def sign_action(
        self,
        *,
        session_pubkey: str,
        session_token: str,
        aud: str,
        action: str,
        action_payload: dict[str, Any],
        nonce: str,
        issued_at: int,
        expires_at: int,
    ) -> dict[str, Any]:
        session_private_key = self.session_private_keys.get(session_pubkey)
        if session_private_key is None:
            raise LocalSignerError("unknown session_pubkey")

        sign_input = build_action_payload(
            aud=aud,
            session_token=session_token,
            action=action,
            action_payload=action_payload,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        signature = sign_detached(sign_input, load_private_key(session_private_key))
        return {"signature_by_session": signature}

    def dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "ping":
            return {"agent_id": self.agent_id}
        if method == "sign_register":
            return self.sign_register(**params)
        if method == "sign_set_name":
            return self.sign_set_name(**params)
        if method == "create_auth_proof":
            return self.create_auth_proof(**params)
        if method == "sign_platform_grant":
            return self.sign_platform_grant(**params)
        if method == "sign_full_attestation_issue":
            return self.sign_full_attestation_issue(**params)
        if method == "sign_upgrade_request":
            return self.sign_upgrade_request(**params)
        if method == "sign_action":
            return self.sign_action(**params)
        raise LocalSignerError(f"unsupported method: {method}")


class _LocalSignerServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, socket_path: str, service: LocalSignerService) -> None:
        socket_file = Path(socket_path)
        socket_file.parent.mkdir(parents=True, exist_ok=True)
        if socket_file.exists():
            socket_file.unlink()
        super().__init__(socket_path, _LocalSignerHandler)
        self.service = service
        os.chmod(socket_path, 0o600)

    def server_close(self) -> None:
        socket_path = Path(str(self.server_address))
        super().server_close()
        if socket_path.exists():
            socket_path.unlink()


class _LocalSignerHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        raw = self.rfile.readline()
        if not raw:
            return
        try:
            request = json.loads(raw.decode("utf-8"))
            method = request.get("method")
            params = request.get("params") or {}
            if not isinstance(method, str):
                raise LocalSignerError("invalid method")
            if not isinstance(params, dict):
                raise LocalSignerError("invalid params")
            result = self.server.service.dispatch(method, params)  # type: ignore[attr-defined]
            response = {"ok": True, "result": result}
        except Exception as exc:  # noqa: BLE001
            response = {"ok": False, "error": str(exc)}
        self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))


def create_local_signer_server(*, socket_path: str, key_file: str) -> _LocalSignerServer:
    if os.name == "nt":
        raise LocalSignerError("local signer requires Unix domain sockets")
    service = LocalSignerService(key_file=Path(key_file))
    return _LocalSignerServer(socket_path=socket_path, service=service)


def serve_local_signer(*, socket_path: str, key_file: str) -> None:
    server = create_local_signer_server(socket_path=socket_path, key_file=key_file)
    try:
        server.serve_forever()
    finally:
        server.shutdown()
        server.server_close()


class LocalSignerClient:
    def __init__(self, *, socket_path: str, timeout_seconds: float = 2.0) -> None:
        self.socket_path = socket_path
        self.timeout_seconds = timeout_seconds

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        payload = json.dumps({"method": method, "params": params}) + "\n"
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout_seconds)
                sock.connect(self.socket_path)
                sock.sendall(payload.encode("utf-8"))
                response = self._recv_line(sock)
        except OSError as exc:
            raise LocalSignerError(f"local signer unavailable at {self.socket_path}") from exc

        try:
            body = json.loads(response)
        except json.JSONDecodeError as exc:
            raise LocalSignerError("invalid local signer response") from exc

        if not isinstance(body, dict):
            raise LocalSignerError("invalid local signer response")
        if not body.get("ok"):
            raise LocalSignerError(str(body.get("error") or "local signer error"))

        result = body.get("result")
        if not isinstance(result, dict):
            raise LocalSignerError("invalid local signer response result")
        return result

    @staticmethod
    def _recv_line(sock: socket.socket) -> str:
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
        return b"".join(chunks).decode("utf-8").strip()

    def ping(self) -> dict[str, Any]:
        return self._request("ping", {})

    def sign_register(
        self, *, name: str, nonce: str, issued_at: int, expires_at: int
    ) -> dict[str, Any]:
        return self._request(
            "sign_register",
            {
                "name": name,
                "nonce": nonce,
                "issued_at": issued_at,
                "expires_at": expires_at,
            },
        )

    def sign_set_name(
        self,
        *,
        agent_id: str,
        name: str,
        nonce: str,
        issued_at: int,
        expires_at: int,
    ) -> dict[str, Any]:
        return self._request(
            "sign_set_name",
            {
                "agent_id": agent_id,
                "name": name,
                "nonce": nonce,
                "issued_at": issued_at,
                "expires_at": expires_at,
            },
        )

    def create_auth_proof(
        self,
        *,
        agent_id: str,
        aud: str,
        nonce: str,
        issued_at: int,
        expires_at: int,
        scope: list[str],
        delegation_ttl_seconds: int,
    ) -> dict[str, Any]:
        return self._request(
            "create_auth_proof",
            {
                "agent_id": agent_id,
                "aud": aud,
                "nonce": nonce,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "scope": scope,
                "delegation_ttl_seconds": delegation_ttl_seconds,
            },
        )

    def sign_action(
        self,
        *,
        session_pubkey: str,
        session_token: str,
        aud: str,
        action: str,
        action_payload: dict[str, Any],
        nonce: str,
        issued_at: int,
        expires_at: int,
    ) -> dict[str, Any]:
        return self._request(
            "sign_action",
            {
                "session_pubkey": session_pubkey,
                "session_token": session_token,
                "aud": aud,
                "action": action,
                "action_payload": action_payload,
                "nonce": nonce,
                "issued_at": issued_at,
                "expires_at": expires_at,
            },
        )

    def sign_platform_grant(
        self,
        *,
        agent_id: str,
        platform_aud: str,
        nonce: str,
        issued_at: int,
        expires_at: int,
    ) -> dict[str, Any]:
        return self._request(
            "sign_platform_grant",
            {
                "agent_id": agent_id,
                "platform_aud": platform_aud,
                "nonce": nonce,
                "issued_at": issued_at,
                "expires_at": expires_at,
            },
        )

    def sign_full_attestation_issue(
        self,
        *,
        agent_id: str,
        platform_aud: str,
        nonce: str,
        issued_at: int,
        expires_at: int,
    ) -> dict[str, Any]:
        return self._request(
            "sign_full_attestation_issue",
            {
                "agent_id": agent_id,
                "platform_aud": platform_aud,
                "nonce": nonce,
                "issued_at": issued_at,
                "expires_at": expires_at,
            },
        )

    def sign_upgrade_request(
        self,
        *,
        agent_id: str,
        target_level: str,
        request_id: str,
        nonce: str,
        issued_at: int,
        expires_at: int,
    ) -> dict[str, Any]:
        return self._request(
            "sign_upgrade_request",
            {
                "agent_id": agent_id,
                "target_level": target_level,
                "request_id": request_id,
                "nonce": nonce,
                "issued_at": issued_at,
                "expires_at": expires_at,
            },
        )
