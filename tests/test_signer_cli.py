from __future__ import annotations

from pathlib import Path

from rare_sdk import signer_cli
from rare_sdk.state import DEFAULT_STATE_FILE, get_signer_key_path, get_signer_socket_path


def test_signer_cli_parser_defaults() -> None:
    parser = signer_cli._build_parser()  # noqa: SLF001
    args = parser.parse_args([])
    assert args.state_file == str(DEFAULT_STATE_FILE)
    assert args.socket_path is None
    assert args.key_file is None


def test_signer_cli_main_uses_state_derived_paths(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, str] = {}

    def fake_serve_local_signer(*, socket_path: str, key_file: str) -> None:
        captured["socket_path"] = socket_path
        captured["key_file"] = key_file

    monkeypatch.setattr(signer_cli, "serve_local_signer", fake_serve_local_signer)
    state_file = tmp_path / "state.json"
    exit_code = signer_cli.main(["--state-file", str(state_file)])
    assert exit_code == 0
    assert captured["socket_path"] == str(get_signer_socket_path(state_file))
    assert captured["key_file"] == str(get_signer_key_path(state_file))


def test_signer_cli_main_respects_explicit_socket_and_key(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, str] = {}

    def fake_serve_local_signer(*, socket_path: str, key_file: str) -> None:
        captured["socket_path"] = socket_path
        captured["key_file"] = key_file

    monkeypatch.setattr(signer_cli, "serve_local_signer", fake_serve_local_signer)
    state_file = tmp_path / "state.json"
    socket_path = tmp_path / "custom.sock"
    key_path = tmp_path / "custom.key"
    exit_code = signer_cli.main(
        [
            "--state-file",
            str(state_file),
            "--socket-path",
            str(socket_path),
            "--key-file",
            str(key_path),
        ]
    )
    assert exit_code == 0
    assert captured["socket_path"] == str(socket_path)
    assert captured["key_file"] == str(key_path)
