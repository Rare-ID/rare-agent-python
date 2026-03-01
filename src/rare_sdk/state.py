from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path


DEFAULT_STATE_FILE = Path.home() / ".config" / "rare" / "state.json"
KEYS_DIR_NAME = "keys"
PRIVATE_KEY_FILE_SUFFIX = ".key"
HOSTED_TOKEN_FILE_SUFFIX = ".hosted-token"
SIGNER_SOCKET_FILE_NAME = "signer.sock"
SIGNER_KEY_FILE_NAME = "signer.key"


@dataclass
class AgentState:
    agent_id: str | None = None
    name: str | None = None
    public_identity_attestation: str | None = None
    full_identity_attestations: dict[str, str] = field(default_factory=dict)
    level: str | None = None

    session_token: str | None = None
    session_pubkey: str | None = None
    session_aud: str | None = None
    display_name: str | None = None

    key_mode: str = "hosted-signer"
    agent_private_key: str | None = None
    hosted_management_token: str | None = None
    hosted_management_token_expires_at: int | None = None

    def to_dict(self, *, include_secrets: bool = False) -> dict:
        payload = asdict(self)
        payload.pop("agent_private_key", None)
        if not include_secrets:
            payload.pop("hosted_management_token", None)
        return payload

    @classmethod
    def from_dict(cls, payload: dict) -> "AgentState":
        accepted = {field_name: payload[field_name] for field_name in cls.__dataclass_fields__ if field_name in payload}
        return cls(**accepted)


def get_agent_private_key_path(state_path: str | Path, agent_id: str) -> Path:
    resolved_state_path = Path(state_path)
    return (
        resolved_state_path.parent
        / KEYS_DIR_NAME
        / f"{agent_id}{PRIVATE_KEY_FILE_SUFFIX}"
    )


def get_hosted_management_token_path(state_path: str | Path, agent_id: str) -> Path:
    resolved_state_path = Path(state_path)
    return (
        resolved_state_path.parent
        / KEYS_DIR_NAME
        / f"{agent_id}{HOSTED_TOKEN_FILE_SUFFIX}"
    )


def get_signer_socket_path(state_path: str | Path) -> Path:
    resolved_state_path = Path(state_path)
    return resolved_state_path.parent / SIGNER_SOCKET_FILE_NAME


def get_signer_key_path(state_path: str | Path) -> Path:
    resolved_state_path = Path(state_path)
    return resolved_state_path.parent / KEYS_DIR_NAME / SIGNER_KEY_FILE_NAME


def _chmod_dir(path: Path) -> None:
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def _chmod_file(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _store_secret(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _chmod_dir(path.parent)
    path.write_text(value, encoding="utf-8")
    _chmod_file(path)


def _cleanup_stale_agent_secret_files(*, state_path: Path, keep_files: set[Path]) -> None:
    keys_dir = state_path.parent / KEYS_DIR_NAME
    if not keys_dir.exists():
        return

    for candidate in keys_dir.glob(f"*{PRIVATE_KEY_FILE_SUFFIX}"):
        if candidate.name == SIGNER_KEY_FILE_NAME:
            continue
        if candidate in keep_files:
            continue
        if candidate.is_file():
            candidate.unlink()

    for candidate in keys_dir.glob(f"*{HOSTED_TOKEN_FILE_SUFFIX}"):
        if candidate in keep_files:
            continue
        if candidate.is_file():
            candidate.unlink()


def load_state(path: str | Path = DEFAULT_STATE_FILE, *, include_private_key: bool = False) -> AgentState:
    state_path = Path(path)
    if not state_path.exists():
        return AgentState()
    data = json.loads(state_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("state file must contain a JSON object")

    legacy_private_key = data.get("agent_private_key")
    legacy_hosted_management_token = data.get("hosted_management_token")
    if "identity_attestation" in data and "public_identity_attestation" not in data:
        legacy_attestation = data.get("identity_attestation")
        if isinstance(legacy_attestation, str):
            data["public_identity_attestation"] = legacy_attestation
    state = AgentState.from_dict(data)

    if include_private_key and state.key_mode == "self-hosted" and state.agent_id:
        key_path = get_agent_private_key_path(state_path, state.agent_id)
        if key_path.exists():
            state.agent_private_key = key_path.read_text(encoding="utf-8")
        elif isinstance(legacy_private_key, str):
            state.agent_private_key = legacy_private_key

    if state.key_mode == "hosted-signer" and state.agent_id:
        token_path = get_hosted_management_token_path(state_path, state.agent_id)
        if token_path.exists():
            state.hosted_management_token = token_path.read_text(encoding="utf-8")
        elif isinstance(legacy_hosted_management_token, str):
            state.hosted_management_token = legacy_hosted_management_token
    else:
        state.hosted_management_token = None
        state.hosted_management_token_expires_at = None
    return state


def save_state(path: str | Path = DEFAULT_STATE_FILE, state: AgentState | None = None) -> None:
    if state is None:
        state = AgentState()
    state_path = Path(path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    _chmod_dir(state_path.parent)
    keep_files: set[Path] = set()

    if state.agent_id:
        key_path = get_agent_private_key_path(state_path, state.agent_id)
        if state.key_mode == "self-hosted" and state.agent_private_key:
            _store_secret(key_path, state.agent_private_key)
            keep_files.add(key_path)
        elif key_path.exists():
            key_path.unlink()

        token_path = get_hosted_management_token_path(state_path, state.agent_id)
        if state.key_mode == "hosted-signer" and state.hosted_management_token:
            _store_secret(token_path, state.hosted_management_token)
            keep_files.add(token_path)
        elif token_path.exists():
            token_path.unlink()
            state.hosted_management_token_expires_at = None

    _cleanup_stale_agent_secret_files(state_path=state_path, keep_files=keep_files)

    state_path.write_text(
        json.dumps(state.to_dict(), ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    _chmod_file(state_path)
