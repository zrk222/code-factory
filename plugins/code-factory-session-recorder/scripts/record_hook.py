"""Store a bounded hash-chain of Claude Code hook envelopes.

The hook intentionally does not copy prompts, tool arguments, output, or
environment values.  Use ``factory wrap`` for the admitted execution,
validator, and Agent License receipts; this trace only makes Claude Code's
PreToolUse and Stop boundaries visible.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
from datetime import datetime, timezone


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def main() -> int:
    event = sys.argv[1] if len(sys.argv) == 2 else "unknown"
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    root = Path(os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())).resolve()
    session_id = str(payload.get("session_id", "unidentified"))
    session_key = hashlib.sha256(session_id.encode("utf-8", errors="replace")).hexdigest()[:24]
    target = root / ".factory" / "session-recorder" / "claude-hooks" / session_key
    target.mkdir(parents=True, exist_ok=True)
    existing = sorted(target.glob("*.json"))
    previous = None
    if existing:
        try:
            prior = json.loads(existing[-1].read_text(encoding="utf-8"))
            previous = prior.get("event_sha256")
        except (OSError, json.JSONDecodeError):
            previous = None
    tool_name = payload.get("tool_name") if isinstance(payload.get("tool_name"), str) else None
    tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    core = {
        "schema": "factory.claude-hook-event.v1",
        "event": event,
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "session_key": session_key,
        "tool_name": tool_name,
        "tool_input_sha256": digest(tool_input),
        "previous_event_sha256": previous,
        "authority": {"observation": True, "execution": False, "approval": False, "sandboxing": False},
        "scope_limits": ["No prompt, tool input, tool output, credential, or environment value is retained.", "This hook trace is not a governed run receipt; use factory wrap for admission, validation, and licensing."],
    }
    record = {**core, "event_sha256": digest(core)}
    index = len(existing) + 1
    path = target / f"{index:06d}-{re.sub(r'[^a-z0-9-]+', '-', event.lower())}.json"
    path.write_bytes(canonical(record) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
