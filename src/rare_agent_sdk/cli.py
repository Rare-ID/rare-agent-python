from __future__ import annotations

import argparse
import json
from contextlib import suppress
from pathlib import Path

from rare_agent_sdk.client import AgentClient, AgentClientError, ApiError
from rare_agent_sdk.local_signer import serve_local_signer
from rare_agent_sdk.state import (
    DEFAULT_STATE_FILE,
    get_agent_private_key_path,
    get_hosted_management_token_path,
    get_signer_key_path,
    get_signer_socket_path,
    load_state,
    save_state,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rare", description="Rare Identity CLI")
    parser.add_argument(
        "--state-file",
        default=str(DEFAULT_STATE_FILE),
        help="Path to local agent state",
    )
    parser.add_argument("--rare-url", default="http://127.0.0.1:8000", help="Rare API base URL")
    parser.add_argument(
        "--platform-url",
        default="http://127.0.0.1:8000/platform",
        help="Third-party platform base URL",
    )
    parser.add_argument(
        "--signer-socket",
        default=None,
        help="Local signer socket path (defaults to <state-dir>/signer.sock)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    register = subparsers.add_parser("register", help="Register an agent")
    register.add_argument("--name", default=None)
    register.add_argument(
        "--key-mode",
        default="hosted-signer",
        choices=["hosted-signer", "self-hosted"],
    )
    register.add_argument("--agent-private-key", default=None)

    login = subparsers.add_parser("login", help="Complete challenge login")
    login.add_argument("--aud", default="platform")
    login.add_argument("--scope", nargs="*", default=["login"])
    login.add_argument("--delegation-ttl", type=int, default=3600)
    login.add_argument("--public-only", action="store_true", help="Skip full attestation flow")
    login.add_argument(
        "--allow-public-fallback",
        action="store_true",
        help="If full attestation fails, continue with public attestation",
    )

    set_name = subparsers.add_parser("set-name", help="Update display name")
    set_name.add_argument("--name", required=True)
    set_name.add_argument("--ttl", type=int, default=120)

    issue_full = subparsers.add_parser("issue-full-attestation", help="Issue full identity attestation for a platform")
    issue_full.add_argument("--aud", required=True)
    issue_full.add_argument("--ttl", type=int, default=120)

    request_upgrade = subparsers.add_parser("request-upgrade", help="Request human verification upgrade")
    request_upgrade.add_argument("--level", required=True, choices=["L1", "L2"])
    request_upgrade.add_argument("--email", default=None)
    request_upgrade.add_argument("--ttl", type=int, default=120)
    request_upgrade.add_argument(
        "--no-send-email",
        action="store_true",
        help="Create the L1 request without automatically sending the verification email",
    )

    upgrade_status = subparsers.add_parser("upgrade-status", help="Check upgrade request status")
    upgrade_status.add_argument("--request-id", required=True)

    send_l1_link = subparsers.add_parser("send-l1-link", help="Send or resend the L1 verification email")
    send_l1_link.add_argument("--request-id", required=True)

    start_social = subparsers.add_parser("start-social", help="Start L2 social verification flow")
    start_social.add_argument("--request-id", required=True)
    start_social.add_argument("--provider", required=True, choices=["x", "github", "linkedin"])

    subparsers.add_parser("rotate-hosted-token", help="Rotate hosted signer management token")
    subparsers.add_parser("revoke-hosted-token", help="Revoke hosted signer management token")
    subparsers.add_parser("recovery-factors", help="Show available hosted token recovery factors")
    subparsers.add_parser("recover-hosted-token-email", help="Send hosted token recovery email")
    recover_email_verify = subparsers.add_parser(
        "recover-hosted-token-email-verify",
        help="Verify hosted token recovery email link and store the recovered token",
    )
    recover_email_verify.add_argument("--token", required=True)
    recover_social_start = subparsers.add_parser(
        "recover-hosted-token-social-start",
        help="Start hosted token social recovery flow",
    )
    recover_social_start.add_argument("--provider", required=True, choices=["x", "github", "linkedin"])
    recover_social_complete = subparsers.add_parser(
        "recover-hosted-token-social-complete",
        help="Complete hosted token social recovery flow with a local snapshot",
    )
    recover_social_complete.add_argument("--provider", required=True, choices=["x", "github", "linkedin"])
    recover_social_complete.add_argument("--snapshot-json", required=True)
    subparsers.add_parser("refresh-attestation", help="Refresh identity attestation")
    show_state = subparsers.add_parser("show-state", help="Show local state")
    show_state.add_argument("--paths", action="store_true", help="Include resolved local secret and socket paths")
    signer_serve = subparsers.add_parser("signer-serve", help="Run local signer daemon")
    signer_serve.add_argument("--socket-path", default=None)
    signer_serve.add_argument("--key-file", default=None)

    return parser


def _print(payload: dict) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))


def _redact_payload(payload: object, *, fields: set[str]) -> object:
    if isinstance(payload, dict):
        redacted: dict[str, object] = {}
        for key, value in payload.items():
            if key in fields and isinstance(value, str) and value:
                redacted[key] = "***REDACTED***"
            else:
                redacted[key] = _redact_payload(value, fields=fields)
        return redacted
    if isinstance(payload, list):
        return [_redact_payload(item, fields=fields) for item in payload]
    return payload


def _redact_sensitive_state(state_payload: dict) -> dict:
    redacted = _redact_payload(
        state_payload,
        fields={"session_token", "hosted_management_token"},
    )
    assert isinstance(redacted, dict)
    return redacted


def _redact_command_response(response_payload: object) -> object:
    return _redact_payload(response_payload, fields={"hosted_management_token"})


def _show_state_payload(*, state_file: Path, signer_socket: Path, state) -> dict:
    payload = _redact_sensitive_state(state.to_dict(include_secrets=True))
    paths = {
        "state_file": str(state_file),
        "signer_socket": str(signer_socket),
    }
    if state.agent_id and state.key_mode == "hosted-signer":
        paths["hosted_management_token_file"] = str(get_hosted_management_token_path(state_file, state.agent_id))
    if state.agent_id and state.key_mode == "self-hosted":
        paths["agent_private_key_file"] = str(get_agent_private_key_path(state_file, state.agent_id))
    payload["paths"] = paths
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    state_file = Path(args.state_file)
    signer_socket = Path(args.signer_socket) if args.signer_socket else get_signer_socket_path(state_file)

    if args.command == "signer-serve":
        socket_path = Path(args.socket_path) if args.socket_path else signer_socket
        key_file = Path(args.key_file) if args.key_file else get_signer_key_path(state_file)
        serve_local_signer(socket_path=str(socket_path), key_file=str(key_file))
        return 0

    state = load_state(state_file)
    client = AgentClient(
        rare_base_url=args.rare_url,
        platform_base_url=args.platform_url,
        state=state,
        signer_socket_path=str(signer_socket),
    )

    try:
        if args.command == "register":
            response = client.register(
                name=args.name,
                key_mode=args.key_mode,
                agent_private_key=args.agent_private_key,
            )
        elif args.command == "login":
            response = client.login(
                aud=args.aud,
                scope=args.scope,
                delegation_ttl_seconds=args.delegation_ttl,
                prefer_full=not args.public_only,
                full_hard_fail=not args.allow_public_fallback,
            )
        elif args.command == "set-name":
            response = client.set_name(name=args.name, ttl_seconds=args.ttl)
        elif args.command == "issue-full-attestation":
            response = client.issue_full_attestation(aud=args.aud, ttl_seconds=args.ttl)
        elif args.command == "request-upgrade":
            if args.level == "L1":
                if not args.email:
                    raise AgentClientError("request-upgrade L1 requires --email")
                response = client.request_upgrade_l1(
                    email=args.email,
                    ttl_seconds=args.ttl,
                    send_email=not args.no_send_email,
                )
            else:
                response = client.request_upgrade_l2(ttl_seconds=args.ttl)
        elif args.command == "upgrade-status":
            response = client.get_upgrade_status(request_id=args.request_id)
        elif args.command == "send-l1-link":
            response = client.send_l1_upgrade_magic_link(request_id=args.request_id)
        elif args.command == "start-social":
            response = client.start_l2_social(
                request_id=args.request_id,
                provider=args.provider,
            )
        elif args.command == "rotate-hosted-token":
            response = client.rotate_hosted_management_token()
        elif args.command == "revoke-hosted-token":
            response = client.revoke_hosted_management_token()
        elif args.command == "recovery-factors":
            response = client.get_hosted_management_recovery_factors()
        elif args.command == "recover-hosted-token-email":
            response = client.send_hosted_management_recovery_email_link()
        elif args.command == "recover-hosted-token-email-verify":
            response = client.verify_hosted_management_recovery_email(token=args.token)
        elif args.command == "recover-hosted-token-social-start":
            response = client.start_hosted_management_recovery_social(provider=args.provider)
        elif args.command == "recover-hosted-token-social-complete":
            response = client.complete_hosted_management_recovery_social(
                provider=args.provider,
                provider_user_snapshot=json.loads(args.snapshot_json),
            )
        elif args.command == "refresh-attestation":
            response = client.refresh_attestation()
        elif args.command == "show-state":
            response = (
                _show_state_payload(state_file=state_file, signer_socket=signer_socket, state=state)
                if args.paths
                else _redact_sensitive_state(state.to_dict(include_secrets=True))
            )
        else:
            parser.error(f"unknown command: {args.command}")
            return 2

        save_state(state_file, state)
        _print(
            {
                "ok": True,
                "command": args.command,
                "data": _redact_command_response(response),
            }
        )
        return 0
    except ApiError as exc:
        _print(
            {
                "ok": False,
                "command": args.command,
                "error": "api_error",
                "status_code": exc.status_code,
                "detail": exc.detail,
            }
        )
        return 1
    except AgentClientError as exc:
        _print({"ok": False, "command": args.command, "error": "client_error", "detail": str(exc)})
        return 1
    except Exception as exc:  # noqa: BLE001
        _print({"ok": False, "command": args.command, "error": "unexpected_error", "detail": str(exc)})
        return 1
    finally:
        with suppress(Exception):
            client.close()


if __name__ == "__main__":
    raise SystemExit(main())
