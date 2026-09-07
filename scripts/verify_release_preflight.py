"""Fail-closed verifier for a sealed release preflight receipt.

The workflow must validate the structured receipt rather than grepping a
human-facing marker.  This keeps a written-but-failed receipt from entering a
Marketplace candidate and bounds parsing so a malformed artifact cannot
consume unbounded runner memory.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

MAX_RECEIPT_BYTES = 4 * 1024 * 1024


def verify(path: str | Path) -> dict[str, object]:
    receipt_path = Path(path)
    raw = receipt_path.read_bytes()
    if len(raw) > MAX_RECEIPT_BYTES:
        raise ValueError("release preflight receipt exceeds 4 MiB")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("release preflight receipt must be a JSON object")
    if payload.get("ok") is not True:
        raise ValueError("release preflight receipt is not approved (ok must be true)")
    return payload


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: verify_release_preflight.py RECEIPT", file=sys.stderr)
        return 2
    try:
        verify(args[0])
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"release preflight verification failed: {exc}", file=sys.stderr)
        return 1
    print("RELEASE_PREFLIGHT_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
