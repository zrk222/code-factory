"""Change-aware feedback for fast local development loops.

The live surface turns a signed, read-only check manifest into a compact
impact plan and, when explicitly requested, runs only affected checks in the
existing fresh-workspace replay boundary.  It never edits source, commits,
approves, publishes, deploys, signs, or uses credentials.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

from .runtime_audit_common import canonical_bytes, exact_keys, reject_secret_material
from .senior_assurance import SeniorAssuranceError, _source_digest, run_replay


SCHEMA = "factory.live-feedback.v1"
RECEIPT_SCHEMA = "factory.live-feedback-receipt.v1"
MAX_CHECKS = 64
MAX_PATHS = 256
MAX_CHECK_PATHS = 128
MAX_ARGV = 64
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_DENIED_EXECUTABLES = {
    "curl",
    "docker",
    "git",
    "invoke-webrequest",
    "npm",
    "pip",
    "powershell",
    "pwsh",
    "python",  # allowed below only when it is a test runner/module command
    "wget",
}
_DENIED_ARGUMENTS = {
    "clone",
    "install",
    "publish",
    "push",
    "upload",
    "webrequest",
}


class LiveFeedbackError(ValueError):
    """Stable fail-closed live-feedback validation error."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _sha(value: object) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise LiveFeedbackError("E_LIVE_DIGEST", f"{label} must be a SHA-256 digest")
    return value


def _normalize_live_path(raw: Any, label: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise LiveFeedbackError("E_LIVE_PATHS", f"{label} contains an invalid path")
    path = raw.replace("\\", "/").strip()
    if path.startswith("/") or path.startswith("../") or "/../" in f"/{path}/":
        raise LiveFeedbackError("E_LIVE_PATH_ESCAPE", f"unsafe path: {raw}")
    normalized = "/".join(part for part in path.split("/") if part not in {"", "."})
    if not normalized:
        raise LiveFeedbackError("E_LIVE_PATHS", f"{label} contains the workspace root")
    return normalized


def _paths(value: object, label: str, *, maximum: int = MAX_PATHS) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise LiveFeedbackError(
            "E_LIVE_PATHS", f"{label} must contain 1..{maximum} paths"
        )
    result: list[str] = []
    for raw in value:
        result.append(_normalize_live_path(raw, label))
    if len(set(result)) != len(result):
        raise LiveFeedbackError("E_LIVE_PATHS", f"{label} must be unique")
    return sorted(result)


def _intersects(left: str, right: str) -> bool:
    a = tuple(part for part in left.split("/") if part)
    b = tuple(part for part in right.split("/") if part)
    return (
        a == b
        or (len(a) < len(b) and b[: len(a)] == a)
        or (len(b) < len(a) and a[: len(b)] == b)
    )


def _argv(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ARGV:
        raise LiveFeedbackError(
            "E_LIVE_ARGV", f"{label} must contain 1..{MAX_ARGV} strings"
        )
    if any(
        not isinstance(item, str) or not item.strip() or len(item) > 512
        for item in value
    ):
        raise LiveFeedbackError("E_LIVE_ARGV", f"{label} contains an invalid argument")
    executable = Path(value[0]).name.lower()
    arguments = {item.lower().lstrip("-") for item in value[1:]}
    if executable in _DENIED_EXECUTABLES and executable != "python":
        raise LiveFeedbackError(
            "E_LIVE_SIDE_EFFECT", f"{executable} is not an approved live check runner"
        )
    if executable == "python" and arguments & _DENIED_ARGUMENTS:
        raise LiveFeedbackError(
            "E_LIVE_SIDE_EFFECT", "live checks cannot install, publish, upload, or push"
        )
    return list(value)


def _validate_live_contract_shape(value: dict[str, Any]) -> None:
    try:
        exact_keys(
            value,
            {"schema", "live_id", "contract_sha256", "changed_paths", "checks"},
            {"description"},
        )
    except Exception as exc:
        raise LiveFeedbackError("E_LIVE_CONTRACT", str(exc)) from exc
    if value.get("schema") != SCHEMA:
        raise LiveFeedbackError("E_LIVE_SCHEMA", f"schema must be {SCHEMA}")


def _live_check_list(value: dict[str, Any]) -> list[Any]:
    checks = value.get("checks")
    if not isinstance(checks, list) or not 1 <= len(checks) <= MAX_CHECKS:
        raise LiveFeedbackError(
            "E_LIVE_CHECKS", f"checks must contain 1..{MAX_CHECKS} items"
        )
    return checks


def _live_check_shape(check: Any, index: int) -> dict[str, Any]:
    if not isinstance(check, dict):
        raise LiveFeedbackError("E_LIVE_CHECK", f"checks[{index}] must be an object")
    try:
        exact_keys(
            check,
            {
                "id",
                "paths",
                "argv",
                "expected_exit",
                "timeout_seconds",
                "max_output_bytes",
            },
            {"env", "description"},
        )
    except Exception as exc:
        raise LiveFeedbackError("E_LIVE_CHECK", f"checks[{index}]: {exc}") from exc
    return check


def _live_check_id(check: dict[str, Any], index: int, ids: set[str]) -> str:
    check_id = check.get("id")
    if (
        not isinstance(check_id, str)
        or not check_id.strip()
        or len(check_id) > 128
        or check_id in ids
    ):
        raise LiveFeedbackError(
            "E_LIVE_CHECK", f"checks[{index}].id must be unique and non-empty"
        )
    return check_id


def _live_check_limits(check: dict[str, Any], check_id: str) -> tuple[int, int, int]:
    expected, timeout, output = (
        check.get("expected_exit"),
        check.get("timeout_seconds"),
        check.get("max_output_bytes"),
    )
    if type(expected) is not int or not -255 <= expected <= 255:
        raise LiveFeedbackError(
            "E_LIVE_CHECK", f"{check_id}.expected_exit must be between -255 and 255"
        )
    if type(timeout) is not int or not 1 <= timeout <= 300:
        raise LiveFeedbackError(
            "E_LIVE_CHECK", f"{check_id}.timeout_seconds must be 1..300"
        )
    if type(output) is not int or not 1 <= output <= 1_048_576:
        raise LiveFeedbackError(
            "E_LIVE_CHECK", f"{check_id}.max_output_bytes must be 1..1048576"
        )
    return expected, timeout, output


def _live_check_environment(check: dict[str, Any], check_id: str) -> dict[str, str]:
    env = check.get("env", {})
    if (
        not isinstance(env, dict)
        or len(env) > 32
        or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in env.items()
        )
    ):
        raise LiveFeedbackError(
            "E_LIVE_ENV", f"{check_id}.env must be a bounded string map"
        )
    return env


def _normalized_live_check(check: Any, index: int, ids: set[str]) -> dict[str, Any]:
    check = _live_check_shape(check, index)
    check_id = _live_check_id(check, index, ids)
    paths = _paths(
        check.get("paths"), f"checks[{index}].paths", maximum=MAX_CHECK_PATHS
    )
    argv = _argv(check.get("argv"), f"checks[{index}].argv")
    expected, timeout, output = _live_check_limits(check, check_id)
    env = _live_check_environment(check, check_id)
    ids.add(check_id)
    return {
        "id": check_id,
        "paths": paths,
        "argv": argv,
        "expected_exit": expected,
        "timeout_seconds": timeout,
        "max_output_bytes": output,
        "env": env,
        "description": check.get("description"),
    }


def validate_live_manifest(
    root: Path, value: dict[str, Any], *, changed_paths: list[str] | None = None
) -> dict[str, Any]:
    """Validate and normalize a live feedback contract without executing checks."""
    if not isinstance(value, dict):
        raise LiveFeedbackError("E_LIVE_CONTRACT", "manifest must be an object")
    reject_secret_material(value, path="live")
    _validate_live_contract_shape(value)
    live_id = value.get("live_id")
    if not isinstance(live_id, str) or not live_id.strip() or len(live_id) > 128:
        raise LiveFeedbackError("E_LIVE_CONTRACT", "live_id must be a non-empty string")
    contract_sha256 = _digest(value.get("contract_sha256"), "contract_sha256")
    selected_paths = _paths(
        changed_paths if changed_paths is not None else value.get("changed_paths"),
        "changed_paths",
    )
    checks = _live_check_list(value)
    normalized = []
    ids: set[str] = set()
    for index, check in enumerate(checks):
        normalized.append(_normalized_live_check(check, index, ids))
    return {
        "schema": SCHEMA,
        "live_id": live_id,
        "contract_sha256": contract_sha256,
        "changed_paths": selected_paths,
        "checks": normalized,
    }


def _run_check(
    root: Path, check: dict[str, Any], source_sha256: str, contract_sha256: str
) -> dict[str, Any]:
    replay = {
        "schema": "factory.replay-manifest.v1",
        "replay_id": f"live-{check['id']}",
        "source_root": ".",
        "source_sha256": source_sha256,
        "dependencies_sha256": contract_sha256,
        "policy_sha256": contract_sha256,
        "input_files": [],
        "argv": check["argv"],
        "env": check["env"],
        "expected_exit": check["expected_exit"],
        "timeout_seconds": check["timeout_seconds"],
        "max_output_bytes": check["max_output_bytes"],
        "contract_sha256": contract_sha256,
    }
    return run_replay(root, replay, execute=True)


def _live_check_row(
    root: Path,
    check: dict[str, Any],
    changed_paths: list[str],
    execute: bool,
    source_sha256: str,
    contract_sha256: str,
) -> dict[str, Any]:
    affected = any(
        _intersects(changed, path)
        for changed in changed_paths
        for path in check["paths"]
    )
    base = {"id": check["id"], "affected_paths": check["paths"], "affected": affected}
    if not affected:
        return {
            **base,
            "state": "SKIPPED",
            "reason": "NO_AFFECTED_PATH",
            "next_action": "No check required for this change.",
        }
    if not execute:
        return {
            **base,
            "state": "READY",
            "reason": "AFFECTED_CHECK_PENDING",
            "next_action": "Run the same manifest with --execute to collect fresh evidence.",
        }
    try:
        receipt = _run_check(root, check, source_sha256, contract_sha256)
    except (SeniorAssuranceError, OSError, ValueError) as exc:
        return {
            **base,
            "state": "BLOCKED",
            "reason": getattr(exc, "code", "LIVE_CHECK_ERROR"),
            "message": str(exc),
            "next_action": "Review the bounded check contract before retrying.",
        }
    state = "PASS" if receipt.get("state") == "PASS" else "FAIL"
    action = (
        "Inspect the linked replay receipt and open CF Fix."
        if state == "FAIL"
        else "Continue coding; no affected check failed."
    )
    return {
        **base,
        "state": state,
        "reason": receipt.get("failure_reason") or "CHECK_PASSED",
        "receipt_sha256": receipt.get("receipt_sha256"),
        "duration_ms": receipt.get("duration_ms"),
        "next_action": action,
    }


def _live_feedback_rows(
    root: Path,
    normalized: dict[str, Any],
    execute: bool,
    source_sha256: str,
) -> list[dict[str, Any]]:
    return [
        _live_check_row(
            root,
            check,
            normalized["changed_paths"],
            execute,
            source_sha256,
            normalized["contract_sha256"],
        )
        for check in normalized["checks"]
    ]


def _live_feedback_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {
        state: sum(row["state"] == state for row in rows)
        for state in ("PASS", "FAIL", "READY", "SKIPPED", "BLOCKED")
    }


def _live_feedback_receipt(
    normalized: dict[str, Any],
    source_sha256: str,
    execute: bool,
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    core = {
        "schema": RECEIPT_SCHEMA,
        "marker": "LIVE_FEEDBACK_IMPACT_RECEIPT",
        "live_id": normalized["live_id"],
        "contract_sha256": normalized["contract_sha256"],
        "source_sha256": source_sha256,
        "changed_paths": normalized["changed_paths"],
        "changed_paths_sha256": _sha(normalized["changed_paths"]),
        "mode": "execute" if execute else "plan",
        "checks": rows,
        "counts": _live_feedback_counts(rows),
        "authority": "none",
        "release_approval": False,
        "claim_boundary": "Change-aware local feedback and fresh replay evidence only; no source mutation, approval, merge, publication, deployment, signing, or credentials.",
    }
    return {**core, "receipt_sha256": _sha(core)}


def run_live_feedback(
    root: Path,
    manifest: dict[str, Any],
    *,
    execute: bool = False,
    changed_paths: list[str] | None = None,
    out: Path | None = None,
) -> dict[str, Any]:
    """Create a compact change impact receipt and optionally execute affected checks."""
    root = Path(root).resolve()
    normalized = validate_live_manifest(root, manifest, changed_paths=changed_paths)
    try:
        source_sha256, _ = _source_digest(root)
    except SeniorAssuranceError as exc:
        raise LiveFeedbackError(exc.code, exc.message) from exc
    rows = _live_feedback_rows(root, normalized, execute, source_sha256)
    result = _live_feedback_receipt(normalized, source_sha256, execute, rows)
    if out is not None:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_bytes(canonical_bytes(result) + b"\n")
    return result


def load_live_json(path: Path) -> dict[str, Any]:
    """Load one bounded live-feedback manifest or receipt from JSON."""
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LiveFeedbackError("E_LIVE_JSON", str(exc)) from exc
    if not isinstance(value, dict):
        raise LiveFeedbackError("E_LIVE_JSON", "JSON must be an object")
    return value
