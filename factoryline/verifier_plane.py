"""Hash-bound, supervised evidence contracts for independent verification.

The module deliberately does not execute workers, validators, containers, or
network calls.  It creates and verifies the evidence contract that an external
runner must enforce.  A valid result proves the supplied bytes and identities,
not host isolation, network policy, credential handling, or release authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
from pathlib import Path
import re
from typing import Any, Iterable


SESSION_SCHEMA = "factory.verifier-session.v1"
WORKER_RESULT_SCHEMA = "factory.verifier-worker-result.v1"
RESULT_SCHEMA = "factory.verifier-result.v1"
PROGRESS_SCHEMA = "factory.verifier-progress.v1"
_VERDICTS = frozenset({"passed", "needs_revision", "failed", "stalled", "budget_exhausted"})
_MAX_BUNDLE_FILES = 100
_MAX_EVIDENCE_FILES = 100
_DEFAULT_BUDGETS = {"max_attempts": 5, "max_wall_seconds": 3600, "max_tokens": 100000, "max_cost_usd": 25.0}


class VerifierPlaneError(ValueError):
    """Closed, machine-readable Verifier Plane input or evidence failure."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.marker = "VERIFIER_RESULT_REJECTED"


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _sha_path(path: Path) -> str:
    return _sha_bytes(path.read_bytes())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _text(value: object, field: str, *, maximum: int = 160) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum:
        raise VerifierPlaneError("VERIFIER_INPUT_INVALID", f"{field} must be a non-empty string of at most {maximum} characters")
    return value.strip()


def _digest(value: object, field: str) -> str:
    result = _text(value, field, maximum=64).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", result):
        raise VerifierPlaneError("VERIFIER_INPUT_INVALID", f"{field} must be a SHA-256 hexadecimal digest")
    return result


def _number(value: object, field: str, *, integer: bool = False) -> float | int:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise VerifierPlaneError("VERIFIER_INPUT_INVALID", f"{field} must be a finite non-negative number")
    if integer:
        if not isinstance(value, int):
            raise VerifierPlaneError("VERIFIER_INPUT_INVALID", f"{field} must be a non-negative integer")
        return value
    return float(value)


def _root(root: Path) -> Path:
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise VerifierPlaneError("VERIFIER_ROOT_INVALID", f"root must be an existing directory: {workspace}")
    return workspace


def _under(root: Path, value: Path, code: str, label: str, *, directory: bool | None = None) -> Path:
    candidate = Path(value).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise VerifierPlaneError(code, f"{label} must be beneath root") from exc
    if directory is True and not candidate.is_dir():
        raise VerifierPlaneError(code, f"{label} must be an existing directory")
    if directory is False and not candidate.is_file():
        raise VerifierPlaneError(code, f"{label} must be an existing file")
    return candidate


def _relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root).as_posix()


def _load(path: Path, schema: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerifierPlaneError("VERIFIER_INPUT_INVALID", f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise VerifierPlaneError("VERIFIER_INPUT_INVALID", f"{label} must use schema {schema}")
    return value


def _tree_digest(root: Path) -> str:
    """Hash the candidate bytes with stable, path-sensitive ordering."""
    items: list[dict[str, str]] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root)
        if any(part in {".git", ".factory", "node_modules", "__pycache__"} for part in relative.parts):
            continue
        items.append({"path": relative.as_posix(), "sha256": _sha_path(path)})
    return _sha_bytes(_canonical(items))


def _file_descriptors(root: Path, paths: Iterable[Path], *, label: str, maximum: int) -> list[dict[str, str]]:
    values = list(paths)
    if not values or len(values) > maximum:
        raise VerifierPlaneError("VERIFIER_INPUT_INVALID", f"{label} must contain 1 through {maximum} files")
    descriptors: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in values:
        path = _under(root, item, "VERIFIER_PATH_REJECTED", label, directory=False)
        relative = _relative(root, path)
        if relative in seen:
            raise VerifierPlaneError("VERIFIER_INPUT_INVALID", f"{label} must not contain duplicate files")
        seen.add(relative)
        descriptors.append({"path": relative, "sha256": _sha_path(path)})
    return sorted(descriptors, key=lambda item: item["path"])


def _bundle_digest(bundle: list[dict[str, str]]) -> str:
    return _sha_bytes(_canonical(bundle))


def _bounded_budgets(*, max_attempts: int, max_wall_seconds: int, max_tokens: int, max_cost_usd: float) -> dict[str, int | float]:
    values = {
        "max_attempts": _number(max_attempts, "max_attempts", integer=True),
        "max_wall_seconds": _number(max_wall_seconds, "max_wall_seconds", integer=True),
        "max_tokens": _number(max_tokens, "max_tokens", integer=True),
        "max_cost_usd": _number(max_cost_usd, "max_cost_usd"),
    }
    for key, ceiling in _DEFAULT_BUDGETS.items():
        if values[key] < 1 or values[key] > ceiling:
            raise VerifierPlaneError("VERIFIER_BUDGET_INVALID", f"{key} must be from 1 through {ceiling:g}")
    return values


def _atomic_json(path: Path, value: dict[str, Any], *, force: bool) -> None:
    if path.exists() and not force:
        raise VerifierPlaneError("VERIFIER_SESSION_EXISTS", f"session already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def create_verifier_session(
    root: Path,
    mission_path: Path,
    candidate_root: Path,
    verifier_bundle: list[Path],
    owner: str,
    *,
    max_attempts: int = 5,
    max_wall_seconds: int = 3600,
    max_tokens: int = 100000,
    max_cost_usd: float = 25.0,
    force: bool = False,
) -> dict[str, Any]:
    """Create one local verifier session; external runners remain responsible for enforcement."""
    workspace = _root(root)
    mission_file = _under(workspace, mission_path, "VERIFIER_PATH_REJECTED", "mission", directory=False)
    candidate = _under(workspace, candidate_root, "VERIFIER_PATH_REJECTED", "candidate_root", directory=True)
    mission = _load(mission_file, "factory.mission.v1", "mission")
    mission_id = _text(mission.get("id"), "mission.id", maximum=64)
    safe_owner = _text(owner, "owner", maximum=96)
    bundle = _file_descriptors(workspace, verifier_bundle, label="verifier_bundle", maximum=_MAX_BUNDLE_FILES)
    if any((workspace / item["path"]).resolve().is_relative_to(candidate) for item in bundle):
        raise VerifierPlaneError("VERIFIER_BUNDLE_WRITABLE", "verifier bundle files must be outside candidate_root")
    budgets = _bounded_budgets(
        max_attempts=max_attempts,
        max_wall_seconds=max_wall_seconds,
        max_tokens=max_tokens,
        max_cost_usd=max_cost_usd,
    )
    core = {
        "schema": SESSION_SCHEMA,
        "mission_id": mission_id,
        "mission_path": _relative(workspace, mission_file),
        "mission_sha256": _sha_path(mission_file),
        "candidate_root": _relative(workspace, candidate),
        "candidate_baseline_sha256": _tree_digest(candidate),
        "verifier_bundle": bundle,
        "verifier_bundle_sha256": _bundle_digest(bundle),
        "owner": safe_owner,
        "budgets": budgets,
        "authority": {"execute": False, "merge": False, "publish": False, "deploy": False, "credentials": False, "network": False},
        "scope_limits": [
            "Session creation proves local paths and bytes, not runtime isolation.",
            "An external runner must enforce filesystem, network, credential, and process boundaries.",
        ],
    }
    session_sha = _sha_bytes(_canonical(core))
    result = {**core, "session_sha256": session_sha, "created_at": _now(), "markers": ["VERIFIER_SESSION_BOUND", "VERIFIER_RUNTIME_UNATTESTED"]}
    path = workspace / ".factory" / "verifier-sessions" / f"{mission_id}-{session_sha[:12]}.session.json"
    _atomic_json(path, result, force=force)
    return {**result, "path": str(path.resolve())}


def _session(root: Path, path: Path) -> tuple[Path, dict[str, Any]]:
    session_path = _under(root, path, "VERIFIER_PATH_REJECTED", "session", directory=False)
    session = _load(session_path, SESSION_SCHEMA, "session")
    digest = _digest(session.get("session_sha256"), "session.session_sha256")
    core = {key: value for key, value in session.items() if key not in {"session_sha256", "created_at", "markers"}}
    if _sha_bytes(_canonical(core)) != digest:
        raise VerifierPlaneError("VERIFIER_SESSION_DRIFT", "session digest does not match canonical session bytes")
    return session_path, session


def _paths(root: Path, values: object, *, label: str, maximum: int) -> list[dict[str, str]]:
    if not isinstance(values, list):
        raise VerifierPlaneError("VERIFIER_INPUT_INVALID", f"{label} must be a list")
    descriptors: list[dict[str, str]] = []
    if len(values) > maximum:
        raise VerifierPlaneError("VERIFIER_INPUT_INVALID", f"{label} must contain at most {maximum} files")
    for index, value in enumerate(values):
        if not isinstance(value, dict):
            raise VerifierPlaneError("VERIFIER_INPUT_INVALID", f"{label}[{index}] must be an object")
        raw = _text(value.get("path"), f"{label}[{index}].path", maximum=400)
        relative = Path(raw)
        if relative.is_absolute() or ".." in relative.parts:
            raise VerifierPlaneError("VERIFIER_PATH_REJECTED", f"{label}[{index}] must be workspace-relative")
        path = _under(root, root / relative, "VERIFIER_PATH_REJECTED", f"{label}[{index}]", directory=False)
        supplied = _digest(value.get("sha256"), f"{label}[{index}].sha256")
        if _sha_path(path) != supplied:
            raise VerifierPlaneError("VERIFIER_EVIDENCE_DRIFT", f"{label}[{index}] digest does not match current bytes")
        descriptors.append({"path": _relative(root, path), "sha256": supplied})
    if len({item["path"] for item in descriptors}) != len(descriptors):
        raise VerifierPlaneError("VERIFIER_INPUT_INVALID", f"{label} must not contain duplicate paths")
    return sorted(descriptors, key=lambda item: item["path"])


@dataclass(frozen=True)
class _WorkerResult:
    worker_id: str
    candidate_tree_sha256: str
    usage: dict[str, int | float]
    failure_signature: str | None
    progress: dict[str, int]


def _worker_result(root: Path, path: Path, session: dict[str, Any]) -> tuple[Path, _WorkerResult, str]:
    result_path = _under(root, path, "VERIFIER_PATH_REJECTED", "worker_result", directory=False)
    value = _load(result_path, WORKER_RESULT_SCHEMA, "worker_result")
    if _digest(value.get("session_sha256"), "worker_result.session_sha256") != session["session_sha256"]:
        raise VerifierPlaneError("VERIFIER_SESSION_BINDING", "worker result is not bound to the session")
    worker_id = _text(value.get("worker_id"), "worker_result.worker_id", maximum=96)
    candidate = _under(root, root / _text(session.get("candidate_root"), "session.candidate_root", maximum=400), "VERIFIER_PATH_REJECTED", "candidate_root", directory=True)
    supplied_tree = _digest(value.get("candidate_tree_sha256"), "worker_result.candidate_tree_sha256")
    if _tree_digest(candidate) != supplied_tree:
        raise VerifierPlaneError("VERIFIER_CANDIDATE_DRIFT", "worker result candidate tree does not match current candidate bytes")
    writes = value.get("declared_writes")
    if not isinstance(writes, list):
        raise VerifierPlaneError("VERIFIER_INPUT_INVALID", "worker_result.declared_writes must be a list")
    for raw in writes:
        relative = Path(_text(raw, "worker_result.declared_writes[]", maximum=400))
        if relative.is_absolute() or ".." in relative.parts:
            raise VerifierPlaneError("VERIFIER_PATH_REJECTED", "worker_result.declared_writes must be candidate-relative")
        _under(candidate, candidate / relative, "VERIFIER_PATH_REJECTED", "worker_result.declared_writes", directory=False)
    bundle_paths = {item["path"] for item in session["verifier_bundle"]}
    if any(_relative(root, candidate / Path(raw)) in bundle_paths for raw in writes):
        raise VerifierPlaneError("VERIFIER_BUNDLE_WRITABLE", "worker result declares a write to verifier bundle")
    raw_usage = value.get("usage")
    if not isinstance(raw_usage, dict):
        raise VerifierPlaneError("VERIFIER_INPUT_INVALID", "worker_result.usage must be an object")
    usage = {
        "attempt": _number(raw_usage.get("attempt"), "worker_result.usage.attempt", integer=True),
        "wall_seconds": _number(raw_usage.get("wall_seconds"), "worker_result.usage.wall_seconds", integer=True),
        "tokens": _number(raw_usage.get("tokens"), "worker_result.usage.tokens", integer=True),
        "cost_usd": _number(raw_usage.get("cost_usd"), "worker_result.usage.cost_usd"),
    }
    budgets = session["budgets"]
    if usage["attempt"] < 1 or usage["attempt"] > budgets["max_attempts"] or usage["wall_seconds"] > budgets["max_wall_seconds"] or usage["tokens"] > budgets["max_tokens"] or usage["cost_usd"] > budgets["max_cost_usd"]:
        raise VerifierPlaneError("VERIFIER_BUDGET_EXCEEDED", "worker usage exceeds the session's hard budget")
    failure = value.get("failure_signature")
    if failure is not None:
        failure = _text(failure, "worker_result.failure_signature", maximum=160)
    raw_progress = value.get("progress")
    if not isinstance(raw_progress, dict):
        raise VerifierPlaneError("VERIFIER_INPUT_INVALID", "worker_result.progress must be an object")
    progress = {field: _number(raw_progress.get(field), f"worker_result.progress.{field}", integer=True) for field in ("passed_checks", "failed_checks", "criteria_covered")}
    return result_path, _WorkerResult(worker_id, supplied_tree, usage, failure, progress), _sha_path(result_path)


def _bundle_current(root: Path, session: dict[str, Any]) -> str:
    descriptors = []
    for item in session["verifier_bundle"]:
        path = _under(root, root / item["path"], "VERIFIER_PATH_REJECTED", "verifier_bundle", directory=False)
        descriptors.append({"path": item["path"], "sha256": _sha_path(path)})
    digest = _bundle_digest(sorted(descriptors, key=lambda item: item["path"]))
    if digest != session["verifier_bundle_sha256"]:
        raise VerifierPlaneError("VERIFIER_BUNDLE_DRIFT", "verifier bundle bytes differ from the bound session")
    return digest


def _checks(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise VerifierPlaneError("VERIFIER_INPUT_INVALID", "verifier_result.checks must be a non-empty list")
    checks: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict) or not isinstance(item.get("passed"), bool):
            raise VerifierPlaneError("VERIFIER_INPUT_INVALID", f"verifier_result.checks[{index}] must contain boolean passed")
        checks.append({"id": _text(item.get("id"), f"verifier_result.checks[{index}].id", maximum=96), "passed": item["passed"]})
    if len({item["id"] for item in checks}) != len(checks):
        raise VerifierPlaneError("VERIFIER_INPUT_INVALID", "verifier_result.checks must not repeat IDs")
    return sorted(checks, key=lambda item: item["id"])


def _verifier_input(root: Path, path: Path, session: dict[str, Any], worker_sha: str, worker_id: str) -> tuple[Path, dict[str, Any], str]:
    verifier_path = _under(root, path, "VERIFIER_PATH_REJECTED", "verifier_result", directory=False)
    value = _load(verifier_path, RESULT_SCHEMA, "verifier_result")
    if _digest(value.get("session_sha256"), "verifier_result.session_sha256") != session["session_sha256"]:
        raise VerifierPlaneError("VERIFIER_SESSION_BINDING", "verifier result is not bound to the session")
    if _digest(value.get("worker_result_sha256"), "verifier_result.worker_result_sha256") != worker_sha:
        raise VerifierPlaneError("VERIFIER_WORKER_BINDING", "verifier result is not bound to current worker result bytes")
    verifier_id = _text(value.get("verifier_id"), "verifier_result.verifier_id", maximum=96)
    if verifier_id == worker_id:
        raise VerifierPlaneError("VERIFIER_IDENTITY_DISTINCT", "worker and verifier identities must differ")
    if value.get("fresh_session") is not True or value.get("context_wall") != "isolated":
        raise VerifierPlaneError("VERIFIER_CONTEXT_WALL", "verifier result requires fresh_session=true and context_wall=isolated")
    return verifier_path, value, verifier_id


def _verifier_details(root: Path, session: dict[str, Any], value: dict[str, Any]) -> tuple[str, str, list[dict[str, str]], list[dict[str, Any]], str, str | None]:
    bundle_digest = _bundle_current(root, session)
    if _digest(value.get("verifier_bundle_sha256"), "verifier_result.verifier_bundle_sha256") != bundle_digest:
        raise VerifierPlaneError("VERIFIER_BUNDLE_DRIFT", "verifier result bundle digest differs from bound bundle")
    toolchain_digest = _digest(value.get("toolchain_sha256"), "verifier_result.toolchain_sha256")
    evidence = _paths(root, value.get("evidence"), label="verifier_result.evidence", maximum=_MAX_EVIDENCE_FILES)
    checks = _checks(value.get("checks"))
    verdict = _text(value.get("verdict"), "verifier_result.verdict", maximum=32)
    if verdict not in _VERDICTS:
        raise VerifierPlaneError("VERIFIER_INPUT_INVALID", f"verifier_result.verdict must be one of {sorted(_VERDICTS)}")
    all_passed = all(item["passed"] for item in checks)
    if verdict == "passed" and not all_passed:
        raise VerifierPlaneError("VERIFIER_VERDICT_INVALID", "passed verdict requires every declared check to pass")
    if verdict == "needs_revision" and all_passed:
        raise VerifierPlaneError("VERIFIER_VERDICT_INVALID", "needs_revision verdict requires at least one failed check")
    harness = value.get("harness_attestation")
    harness_sha = None
    if harness is not None:
        if not isinstance(harness, dict):
            raise VerifierPlaneError("VERIFIER_INPUT_INVALID", "harness_attestation must be an object")
        harness_sha = _sha_bytes(_canonical(harness))
    return bundle_digest, toolchain_digest, evidence, checks, verdict, harness_sha


def verify_verifier_result(session_path: Path, worker_result_path: Path, verifier_result_path: Path, root: Path) -> dict[str, Any]:
    """Verify evidence emitted by separate worker and verifier identities without executing either."""
    workspace = _root(root)
    checked_session_path, session = _session(workspace, session_path)
    try:
        checked_worker_path, worker, worker_sha = _worker_result(workspace, worker_result_path, session)
    except VerifierPlaneError as exc:
        exc.marker = "VERIFIER_WORKER_RESULT_REJECTED"
        raise
    verifier_path, value, verifier_id = _verifier_input(workspace, verifier_result_path, session, worker_sha, worker.worker_id)
    bundle_digest, toolchain_digest, evidence, checks, verdict, harness_sha = _verifier_details(workspace, session, value)
    core = {
        "schema": RESULT_SCHEMA,
        "session_path": _relative(workspace, checked_session_path),
        "session_sha256": session["session_sha256"],
        "worker_result_path": _relative(workspace, checked_worker_path),
        "worker_result_sha256": worker_sha,
        "candidate_tree_sha256": worker.candidate_tree_sha256,
        "worker_id": worker.worker_id,
        "verifier_id": verifier_id,
        "fresh_session": True,
        "context_wall": "isolated",
        "verifier_bundle_sha256": bundle_digest,
        "toolchain_sha256": toolchain_digest,
        "evidence": evidence,
        "checks": checks,
        "verdict": verdict,
        "harness_attestation_sha256": harness_sha,
        "authority": {"merge": False, "publish": False, "deploy": False, "credentials": False},
        "scope_limits": [
            "Verification proves supplied local evidence, byte bindings, and distinct declared identities.",
            "A harness attestation is evidence; it is not proof that Code Factory enforced isolation itself.",
        ],
    }
    result_sha = _sha_bytes(_canonical(core))
    return {
        **core,
        "result_sha256": result_sha,
        "valid": True,
        "markers": [
            "VERIFIER_RESULT_BOUND",
            "VERIFIER_IDENTITIES_DISTINCT",
            "VERIFIER_BUNDLE_CURRENT",
            "VERIFIER_HARNESS_ATTESTATION_BOUND" if harness_sha else "VERIFIER_RUNTIME_UNATTESTED",
        ],
    }


def _normalized_attempt(item: object, index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise VerifierPlaneError("VERIFIER_INPUT_INVALID", f"attempts[{index}] must be an object")
    progress = item.get("progress")
    if not isinstance(progress, dict):
        raise VerifierPlaneError("VERIFIER_INPUT_INVALID", f"attempts[{index}].progress must be an object")
    return {
        "attempt": _number(item.get("attempt", index), f"attempts[{index}].attempt", integer=True),
        "failure_signature": _text(item.get("failure_signature"), f"attempts[{index}].failure_signature", maximum=160),
        "progress": {field: _number(progress.get(field), f"attempts[{index}].progress.{field}", integer=True) for field in ("passed_checks", "failed_checks", "criteria_covered")},
    }


def _normalized_attempts(attempts: object) -> list[dict[str, Any]]:
    if not isinstance(attempts, list) or len(attempts) < 1 or len(attempts) > _DEFAULT_BUDGETS["max_attempts"]:
        raise VerifierPlaneError("VERIFIER_INPUT_INVALID", f"attempts must contain 1 through {_DEFAULT_BUDGETS['max_attempts']} records")
    normalized = [_normalized_attempt(item, index) for index, item in enumerate(attempts, 1)]
    if [item["attempt"] for item in normalized] != sorted(item["attempt"] for item in normalized) or len({item["attempt"] for item in normalized}) != len(normalized):
        raise VerifierPlaneError("VERIFIER_INPUT_INVALID", "attempts must have strictly increasing unique attempt numbers")
    return normalized


def _progress_delta(previous: dict[str, Any] | None, current: dict[str, Any]) -> tuple[bool, bool]:
    if previous is None:
        return False, False
    repeated = current["failure_signature"] == previous["failure_signature"]
    improved = (
        current["progress"]["passed_checks"] > previous["progress"]["passed_checks"]
        or current["progress"]["failed_checks"] < previous["progress"]["failed_checks"]
        or current["progress"]["criteria_covered"] > previous["progress"]["criteria_covered"]
    )
    return repeated, improved


def evaluate_progress(attempts: list[dict[str, Any]]) -> dict[str, Any]:
    """Detect exact, deterministic no-progress loops without semantic self-grading."""
    normalized = _normalized_attempts(attempts)
    current = normalized[-1]
    previous = normalized[-2] if len(normalized) > 1 else None
    repeated, improved = _progress_delta(previous, current)
    stalled = bool(repeated and not improved)
    return {
        "schema": PROGRESS_SCHEMA,
        "attempts": normalized,
        "failure_signature_repeated": repeated,
        "deterministic_progress": bool(improved),
        "verdict": "stalled" if stalled else "continue",
        "owner_review_required": stalled,
        "next_action": "owner_review" if stalled else "retry_with_fresh_context",
        "markers": ["VERIFIER_PROGRESS_STALLED"] if stalled else ["VERIFIER_PROGRESS_CONTINUES"],
        "scope_limits": ["Progress compares declared deterministic counts and exact failure signatures; it does not judge reasoning quality."],
    }
