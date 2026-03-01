from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path


DEFAULT_STATE_FILE = Path.home() / ".config" / "rare" / "state.json"
KEYS_DIR_NAME = "keys"
PRIVATE_KEY_FILE_SUFFIX = ".key"
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

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload.pop("agent_private_key", None)
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


def get_signer_socket_path(state_path: str | Path) -> Path:
    resolved_state_path = Path(state_path)
    return resolved_state_path.parent / SIGNER_SOCKET_FILE_NAME


def get_signer_key_path(state_path: str | Path) -> Path:
    resolved_state_path = Path(state_path)
    return resolved_state_path.parent / KEYS_DIR_NAME / SIGNER_KEY_FILE_NAME


def _store_private_key(path: Path, private_key: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except FileNotFoundError:
        pass
    path.write_text(private_key, encoding="utf-8")
    os.chmod(path, 0o600)


def load_state(path: str | Path = DEFAULT_STATE_FILE, *, include_private_key: bool = False) -> AgentState:
    state_path = Path(path)
    if not state_path.exists():
        return AgentState()
    data = json.loads(state_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("state file must contain a JSON object")

    legacy_private_key = data.get("agent_private_key")
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
    return state


def save_state(path: str | Path = DEFAULT_STATE_FILE, state: AgentState | None = None) -> None:
    if state is None:
        state = AgentState()
    state_path = Path(path)
    state_path.parent.mkdir(parents=True, exist_ok=True)

    if state.agent_id:
        key_path = get_agent_private_key_path(state_path, state.agent_id)
        if state.key_mode == "self-hosted" and state.agent_private_key:
            _store_private_key(key_path, state.agent_private_key)
        elif key_path.exists():
            key_path.unlink()

    state_path.write_text(
        json.dumps(state.to_dict(), ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
