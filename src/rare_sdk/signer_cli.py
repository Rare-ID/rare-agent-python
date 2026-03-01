from __future__ import annotations

import argparse
from pathlib import Path

from rare_sdk.local_signer import serve_local_signer
from rare_sdk.state import DEFAULT_STATE_FILE, get_signer_key_path, get_signer_socket_path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rare-signer", description="Rare local signer daemon")
    parser.add_argument(
        "--state-file",
        default=str(DEFAULT_STATE_FILE),
        help="Path to local agent state",
    )
    parser.add_argument("--socket-path", default=None, help="Unix socket path for signer IPC")
    parser.add_argument("--key-file", default=None, help="Ed25519 private key file path")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    state_file = Path(args.state_file)
    socket_path = Path(args.socket_path) if args.socket_path else get_signer_socket_path(state_file)
    key_file = Path(args.key_file) if args.key_file else get_signer_key_path(state_file)
    serve_local_signer(socket_path=str(socket_path), key_file=str(key_file))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
