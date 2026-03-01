from __future__ import annotations

import argparse
import json
from contextlib import suppress
from pathlib import Path

from rare_sdk.client import AgentClient, AgentClientError, ApiError
from rare_sdk.local_signer import serve_local_signer
from rare_sdk.state import (
    DEFAULT_STATE_FILE,
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
    parser.add_argument("--rare-url", default="http://127.0.0.1:8000/rare", help="Rare API base URL")
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

    grant_platform = subparsers.add_parser("grant-platform", help="Grant platform access for full attestation")
    grant_platform.add_argument("--aud", required=True)
    grant_platform.add_argument("--ttl", type=int, default=120)

    revoke_platform = subparsers.add_parser("revoke-platform", help="Revoke platform full-attestation access")
    revoke_platform.add_argument("--aud", required=True)
    revoke_platform.add_argument("--ttl", type=int, default=120)

    issue_full = subparsers.add_parser("issue-full-attestation", help="Issue full identity attestation for a platform")
    issue_full.add_argument("--aud", required=True)
    issue_full.add_argument("--ttl", type=int, default=120)

    request_upgrade = subparsers.add_parser("request-upgrade", help="Request human verification upgrade")
    request_upgrade.add_argument("--level", required=True, choices=["L1", "L2"])
    request_upgrade.add_argument("--email", default=None)
    request_upgrade.add_argument("--ttl", type=int, default=120)

    upgrade_status = subparsers.add_parser("upgrade-status", help="Check upgrade request status")
    upgrade_status.add_argument("--request-id", required=True)

    start_social = subparsers.add_parser("start-social", help="Start L2 social verification flow")
    start_social.add_argument("--request-id", required=True)
    start_social.add_argument("--provider", required=True, choices=["x", "github"])

    subparsers.add_parser("rotate-hosted-token", help="Rotate hosted signer management token")
    subparsers.add_parser("revoke-hosted-token", help="Revoke hosted signer management token")
    subparsers.add_parser("refresh-attestation", help="Refresh identity attestation")
    subparsers.add_parser("show-state", help="Show local state")
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
        elif args.command == "grant-platform":
            response = client.grant_platform(aud=args.aud, ttl_seconds=args.ttl)
        elif args.command == "revoke-platform":
            response = client.revoke_platform(aud=args.aud, ttl_seconds=args.ttl)
        elif args.command == "issue-full-attestation":
            response = client.issue_full_attestation(aud=args.aud, ttl_seconds=args.ttl)
        elif args.command == "request-upgrade":
            if args.level == "L1":
                if not args.email:
                    raise AgentClientError("request-upgrade L1 requires --email")
                response = client.request_upgrade_l1(email=args.email, ttl_seconds=args.ttl)
            else:
                response = client.request_upgrade_l2(ttl_seconds=args.ttl)
        elif args.command == "upgrade-status":
            response = client.get_upgrade_status(request_id=args.request_id)
        elif args.command == "start-social":
            response = client.start_l2_social(
                request_id=args.request_id,
                provider=args.provider,
            )
        elif args.command == "rotate-hosted-token":
            response = client.rotate_hosted_management_token()
        elif args.command == "revoke-hosted-token":
            response = client.revoke_hosted_management_token()
        elif args.command == "refresh-attestation":
            response = client.refresh_attestation()
        elif args.command == "show-state":
            response = _redact_sensitive_state(state.to_dict(include_secrets=True))
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
