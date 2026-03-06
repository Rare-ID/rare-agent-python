from __future__ import annotations

import json
import socket
import socketserver
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

import pytest

from rare_identity_protocol import now_ts
from rare_agent_sdk.local_signer import (
    LocalSignerClient,
    LocalSignerError,
    LocalSignerService,
    create_local_signer_server,
)


@contextmanager
def _run_local_signer(tmp_path: Path):
    socket_path = Path("/tmp") / f"rare-local-signer-{uuid4().hex}.sock"
    key_path = tmp_path / "keys" / "signer.key"
    server = create_local_signer_server(socket_path=str(socket_path), key_file=str(key_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    for _ in range(100):
        if socket_path.exists():
            break
        time.sleep(0.01)
    try:
        yield socket_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
        if socket_path.exists():
            socket_path.unlink()


def _short_socket_path(prefix: str) -> Path:
    return Path("/tmp") / f"rare-{prefix}-{uuid4().hex[:8]}.sock"


class _StaticReplyServer(socketserver.UnixStreamServer):
    allow_reuse_address = True


class _StaticReplyHandler(socketserver.StreamRequestHandler):
    reply = b"{}\n"

    def handle(self) -> None:
        _ = self.rfile.readline()
        self.wfile.write(self.reply)


@contextmanager
def _run_static_reply_server(*, socket_path: Path, reply_body: bytes):
    class Handler(_StaticReplyHandler):
        reply = reply_body

    if socket_path.exists():
        socket_path.unlink()
    server = _StaticReplyServer(str(socket_path), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    for _ in range(100):
        if socket_path.exists():
            break
        time.sleep(0.01)
    try:
        yield
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
        if socket_path.exists():
            socket_path.unlink()


def test_local_signer_service_dispatch_rejects_unsupported_method(tmp_path: Path) -> None:
    service = LocalSignerService(key_file=tmp_path / "keys" / "signer.key")
    with pytest.raises(LocalSignerError, match="unsupported method"):
        service.dispatch("unknown_method", {})


def test_local_signer_service_rejects_agent_id_mismatch_and_unknown_session(tmp_path: Path) -> None:
    service = LocalSignerService(key_file=tmp_path / "keys" / "signer.key")
    with pytest.raises(LocalSignerError, match="agent_id does not match signer identity"):
        service.sign_set_name(
            agent_id="agent-404",
            name="alice",
            nonce="n1",
            issued_at=1,
            expires_at=2,
        )

    with pytest.raises(LocalSignerError, match="unknown session_pubkey"):
        service.sign_action(
            session_pubkey="missing-session",
            session_token="sess",
            aud="platform",
            action="post",
            action_payload={"content": "x"},
            nonce="n1",
            issued_at=1,
            expires_at=2,
        )


def test_local_signer_service_happy_path_methods_and_dispatch(tmp_path: Path) -> None:
    key_file = tmp_path / "keys" / "signer.key"
    service = LocalSignerService(key_file=key_file)
    assert key_file.exists()

    # Load from existing key file to cover key re-read branch.
    reloaded = LocalSignerService(key_file=key_file)
    assert reloaded.agent_id == service.agent_id

    signed_register = service.sign_register(name="alice", nonce="n1", issued_at=1, expires_at=120)
    assert signed_register["agent_public_key"] == service.agent_id
    assert isinstance(signed_register["signature_by_agent"], str)

    signed_set_name = service.sign_set_name(
        agent_id=service.agent_id,
        name="alice-v2",
        nonce="n2",
        issued_at=1,
        expires_at=120,
    )
    assert isinstance(signed_set_name["signature_by_agent"], str)

    auth_proof = service.create_auth_proof(
        agent_id=service.agent_id,
        aud="platform",
        nonce="n3",
        issued_at=now_ts(),
        expires_at=now_ts() + 120,
        scope=["login", "post"],
        delegation_ttl_seconds=300,
    )
    assert isinstance(auth_proof["delegation_token"], str)
    assert isinstance(auth_proof["signature_by_session"], str)

    signed_action = service.sign_action(
        session_pubkey=auth_proof["session_pubkey"],
        session_token="sess",
        aud="platform",
        action="post",
        action_payload={"content": "hello"},
        nonce="n4",
        issued_at=1,
        expires_at=120,
    )
    assert isinstance(signed_action["signature_by_session"], str)

    assert isinstance(
        service.sign_full_attestation_issue(
            agent_id=service.agent_id,
            platform_aud="platform",
            nonce="n5",
            issued_at=1,
            expires_at=120,
        )["signature_by_agent"],
        str,
    )
    assert isinstance(
        service.sign_upgrade_request(
            agent_id=service.agent_id,
            target_level="L1",
            request_id="upg-1",
            nonce="n6",
            issued_at=1,
            expires_at=120,
        )["signature_by_agent"],
        str,
    )
    assert isinstance(
        service.sign_management_auth(
            agent_id=service.agent_id,
            operation="upgrade_status",
            resource_id="upg-1",
            nonce="n7",
            issued_at=1,
            expires_at=120,
        )["signature_by_agent"],
        str,
    )

    assert service.dispatch("ping", {})["agent_id"] == service.agent_id
    assert isinstance(
        service.dispatch("sign_register", {"name": "alice", "nonce": "d1", "issued_at": 1, "expires_at": 2})[
            "signature_by_agent"
        ],
        str,
    )
    assert isinstance(
        service.dispatch(
            "sign_set_name",
            {
                "agent_id": service.agent_id,
                "name": "alice",
                "nonce": "d2",
                "issued_at": 1,
                "expires_at": 2,
            },
        )["signature_by_agent"],
        str,
    )
    assert isinstance(
        service.dispatch(
            "create_auth_proof",
            {
                "agent_id": service.agent_id,
                "aud": "platform",
                "nonce": "d3",
                "issued_at": now_ts(),
                "expires_at": now_ts() + 120,
                "scope": ["login"],
                "delegation_ttl_seconds": 300,
            },
        )["delegation_token"],
        str,
    )
    assert isinstance(
        service.dispatch(
            "sign_full_attestation_issue",
            {
                "agent_id": service.agent_id,
                "platform_aud": "platform",
                "nonce": "d4",
                "issued_at": 1,
                "expires_at": 2,
            },
        )["signature_by_agent"],
        str,
    )
    assert isinstance(
        service.dispatch(
            "sign_upgrade_request",
            {
                "agent_id": service.agent_id,
                "target_level": "L1",
                "request_id": "upg-d",
                "nonce": "d5",
                "issued_at": 1,
                "expires_at": 2,
            },
        )["signature_by_agent"],
        str,
    )
    assert isinstance(
        service.dispatch(
            "sign_management_auth",
            {
                "agent_id": service.agent_id,
                "operation": "upgrade_status",
                "resource_id": "agent-id",
                "nonce": "d6",
                "issued_at": 1,
                "expires_at": 2,
            },
        )["signature_by_agent"],
        str,
    )
    assert isinstance(
        service.dispatch(
            "sign_action",
            {
                "session_pubkey": auth_proof["session_pubkey"],
                "session_token": "sess",
                "aud": "platform",
                "action": "post",
                "action_payload": {"content": "x"},
                "nonce": "d7",
                "issued_at": 1,
                "expires_at": 2,
            },
        )["signature_by_session"],
        str,
    )


def test_local_signer_service_validates_auth_proof_window(tmp_path: Path) -> None:
    service = LocalSignerService(key_file=tmp_path / "keys" / "signer.key")
    with pytest.raises(LocalSignerError, match="issued_at too far in future"):
        service.create_auth_proof(
            agent_id=service.agent_id,
            aud="platform",
            nonce="future",
            issued_at=now_ts() + 90,
            expires_at=now_ts() + 120,
            scope=["login"],
            delegation_ttl_seconds=300,
        )
    now = now_ts()
    with pytest.raises(LocalSignerError, match="expires_at must be greater than issued_at"):
        service.create_auth_proof(
            agent_id=service.agent_id,
            aud="platform",
            nonce="bad-exp",
            issued_at=now,
            expires_at=now,
            scope=["login"],
            delegation_ttl_seconds=300,
        )


def test_local_signer_client_reports_socket_unavailable() -> None:
    client = LocalSignerClient(socket_path=f"/tmp/rare-missing-{uuid4().hex}.sock")
    with pytest.raises(LocalSignerError, match="local signer unavailable"):
        client.ping()


def test_local_signer_client_reports_server_side_bad_params(tmp_path: Path) -> None:
    with _run_local_signer(tmp_path) as socket_path:
        client = LocalSignerClient(socket_path=str(socket_path))
        with pytest.raises(LocalSignerError, match="invalid params"):
            client._request("ping", "bad-params")  # type: ignore[arg-type]  # noqa: SLF001
        with pytest.raises(LocalSignerError):
            client._request("sign_set_name", {})  # noqa: SLF001


def test_local_signer_client_rejects_invalid_json_response(tmp_path: Path) -> None:
    _ = tmp_path
    socket_path = _short_socket_path("invalid-json")
    with _run_static_reply_server(socket_path=socket_path, reply_body=b"not-json\n"):
        client = LocalSignerClient(socket_path=str(socket_path))
        with pytest.raises(LocalSignerError, match="invalid local signer response"):
            client.ping()


def test_local_signer_client_rejects_non_dict_result_response(tmp_path: Path) -> None:
    _ = tmp_path
    socket_path = _short_socket_path("invalid-result")
    response = json.dumps({"ok": True, "result": "not-dict"}).encode("utf-8") + b"\n"
    with _run_static_reply_server(socket_path=socket_path, reply_body=response):
        client = LocalSignerClient(socket_path=str(socket_path))
        with pytest.raises(LocalSignerError, match="response result"):
            client.ping()


def test_local_signer_client_rejects_server_error_response(tmp_path: Path) -> None:
    _ = tmp_path
    socket_path = _short_socket_path("error-response")
    response = json.dumps({"ok": False, "error": "boom"}).encode("utf-8") + b"\n"
    with _run_static_reply_server(socket_path=socket_path, reply_body=response):
        client = LocalSignerClient(socket_path=str(socket_path))
        with pytest.raises(LocalSignerError, match="boom"):
            client.ping()


def test_local_signer_handler_rejects_invalid_method_and_params(tmp_path: Path) -> None:
    socket_path = _short_socket_path("handler-errors")
    key_path = tmp_path / "keys" / "signer.key"
    # Pre-create file path to exercise create_local_signer_server unlink branch.
    socket_path.write_text("", encoding="utf-8")
    server = create_local_signer_server(socket_path=str(socket_path), key_file=str(key_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(str(socket_path))
            sock.sendall(b'{"method": 123, "params": {}}\n')
            body = sock.recv(4096).decode("utf-8")
        assert '"ok": false' in body.lower()
        assert "invalid method" in body

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(str(socket_path))
            sock.sendall(b'{"method": "ping", "params": "bad"}\n')
            body = sock.recv(4096).decode("utf-8")
        assert '"ok": false' in body.lower()
        assert "invalid params" in body

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(str(socket_path))
            sock.sendall(b"not-json\n")
            body = sock.recv(4096).decode("utf-8")
        assert '"ok": false' in body.lower()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
        if socket_path.exists():
            socket_path.unlink()
