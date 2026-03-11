from __future__ import annotations

import json

from rare_agent_sdk import cli as cli_module
from rare_agent_sdk.client import ApiError


class FakeClient:
    def __init__(self, *args, **kwargs):
        self.state = kwargs["state"]

    def close(self):
        return None

    def login(self, *args, **kwargs):
        return {"session_token": "sess", "level": "L1"}

    def set_name(self, *args, **kwargs):
        return {"name": kwargs.get("name", "next")}

    def issue_full_attestation(self, *args, **kwargs):
        return {"full_identity_attestation": "full-token"}

    def request_upgrade_l1(self, *args, **kwargs):
        return {"status": "human_pending", "upgrade_request_id": "upg-l1"}

    def request_upgrade_l2(self, *args, **kwargs):
        return {"status": "human_pending", "upgrade_request_id": "upg-l2"}

    def get_upgrade_status(self, *args, **kwargs):
        return {"status": "human_pending", "upgrade_request_id": kwargs.get("request_id")}

    def send_l1_upgrade_magic_link(self, *args, **kwargs):
        return {"status": "human_pending", "upgrade_request_id": kwargs.get("request_id"), "sent": True}

    def start_l2_social(self, *args, **kwargs):
        return {"provider": kwargs.get("provider"), "state": "oauth-state"}

    def get_hosted_management_recovery_factors(self, *args, **kwargs):
        return {"available_factors": [{"type": "email"}]}

    def send_hosted_management_recovery_email_link(self, *args, **kwargs):
        return {"sent": True, "recovery_factor": "email"}

    def verify_hosted_management_recovery_email(self, *args, **kwargs):
        return {"recovered": True, "hosted_management_token": "recovered"}

    def start_hosted_management_recovery_social(self, *args, **kwargs):
        return {"provider": kwargs.get("provider"), "authorize_url": "https://example.com"}

    def complete_hosted_management_recovery_social(self, *args, **kwargs):
        return {"recovered": True, "recovery_factor": f"social:{kwargs.get('provider')}"}

    def rotate_hosted_management_token(self):
        return {"hosted_management_token": "rotated-token"}

    def revoke_hosted_management_token(self):
        return {"revoked": True}

    def refresh_attestation(self):
        return {"public_identity_attestation": "public-token"}


def test_cli_covers_command_dispatch_branches(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setattr(cli_module, "AgentClient", FakeClient)
    state_file = tmp_path / "state.json"

    commands = [
        ["login"],
        ["set-name", "--name", "n1"],
        ["issue-full-attestation", "--aud", "platform"],
        ["request-upgrade", "--level", "L1", "--email", "a@example.com"],
        ["request-upgrade", "--level", "L1", "--email", "a@example.com", "--no-send-email"],
        ["request-upgrade", "--level", "L2"],
        ["upgrade-status", "--request-id", "req-1"],
        ["send-l1-link", "--request-id", "req-1"],
        ["start-social", "--request-id", "req-2", "--provider", "github"],
        ["rotate-hosted-token"],
        ["revoke-hosted-token"],
        ["recovery-factors"],
        ["recover-hosted-token-email"],
        ["recover-hosted-token-email-verify", "--token", "email-token"],
        ["recover-hosted-token-social-start", "--provider", "github"],
        [
            "recover-hosted-token-social-complete",
            "--provider",
            "github",
            "--snapshot-json",
            '{"id":"42","login":"rare-dev"}',
        ],
        ["refresh-attestation"],
    ]
    for cmd in commands:
        exit_code = cli_module.main(["--state-file", str(state_file), *cmd])
        assert exit_code == 0
        payload = json.loads(capsys.readouterr().out.strip())
        assert payload["ok"] is True


def test_cli_signer_serve_branch(monkeypatch, tmp_path) -> None:
    captured: dict[str, str] = {}

    def fake_serve_local_signer(*, socket_path: str, key_file: str) -> None:
        captured["socket_path"] = socket_path
        captured["key_file"] = key_file

    monkeypatch.setattr(cli_module, "serve_local_signer", fake_serve_local_signer)
    state_file = tmp_path / "state.json"
    exit_code = cli_module.main(
        [
            "--state-file",
            str(state_file),
            "signer-serve",
            "--socket-path",
            str(tmp_path / "explicit.sock"),
            "--key-file",
            str(tmp_path / "explicit.key"),
        ]
    )
    assert exit_code == 0
    assert captured["socket_path"].endswith("explicit.sock")
    assert captured["key_file"].endswith("explicit.key")


def test_cli_api_error_and_unexpected_error_paths(monkeypatch, tmp_path, capsys) -> None:
    class ApiFailClient(FakeClient):
        def set_name(self, *args, **kwargs):
            raise ApiError(status_code=403, detail="forbidden")

    monkeypatch.setattr(cli_module, "AgentClient", ApiFailClient)
    state_file = tmp_path / "state.json"
    exit_code = cli_module.main(["--state-file", str(state_file), "set-name", "--name", "x"])
    assert exit_code == 1
    api_payload = json.loads(capsys.readouterr().out.strip())
    assert api_payload["error"] == "api_error"
    assert api_payload["status_code"] == 403

    class UnexpectedFailClient(FakeClient):
        def set_name(self, *args, **kwargs):
            raise RuntimeError("boom")

    monkeypatch.setattr(cli_module, "AgentClient", UnexpectedFailClient)
    exit_code = cli_module.main(["--state-file", str(state_file), "set-name", "--name", "x"])
    assert exit_code == 1
    unexpected_payload = json.loads(capsys.readouterr().out.strip())
    assert unexpected_payload["error"] == "unexpected_error"


def test_redact_payload_handles_lists() -> None:
    redacted = cli_module._redact_payload(
        [{"hosted_management_token": "token"}, {"a": 1}],
        fields={"hosted_management_token"},
    )
    assert redacted[0]["hosted_management_token"] == "***REDACTED***"


def test_cli_default_rare_url_matches_root_api_prefix() -> None:
    parser = cli_module._build_parser()
    args = parser.parse_args(["show-state"])
    assert args.rare_url == "http://127.0.0.1:8000"
