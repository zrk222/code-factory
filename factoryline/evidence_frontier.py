"""Deterministic next-evidence selection for verified repair candidates.

Evidence Frontier consumes a sealed ProofSearch evaluation and ranks supplied
experiment hypotheses by the number of viable candidate pairs they can
separate. It never generates code, executes commands, or changes a workspace.
"""
from __future__ import annotations

from itertools import combinations
from pathlib import Path
from typing import Any
import hashlib
import json
import math
import re
import tempfile

from .proofsearch import verify_proofsearch_evaluation


REQUEST_SCHEMA = "factory.evidence-frontier-request.v1"
FRONTIER_SCHEMA = "factory.evidence-frontier.v1"
MAX_SOURCE_BYTES = 2_097_152
MAX_EXPERIMENTS = 64
MAX_ELAPSED_MS = 1_000_000
_SHA = re.compile(r"^[0-9a-f]{64}$")
_OUTCOMES = frozenset({"pass", "fail", "unknown"})
_KINDS = frozenset({"inspection", "mutation", "replay", "test"})
_AUTHORITY = {
    "code_generation": False,
    "command_execution": False,
    "workspace_mutation": False,
    "test_mutation": False,
    "checkpoint_mutation": False,
    "approval": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


class EvidenceFrontierError(ValueError):
    """Closed, user-correctable Evidence Frontier contract failure."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    source = Path(path)
    try:
        if not source.is_file() or source.stat().st_size > MAX_SOURCE_BYTES:
            raise EvidenceFrontierError("EVIDENCE_FRONTIER_SOURCE_UNREADABLE", "source is missing or exceeds 2097152 bytes")
        value = json.loads(source.read_text(encoding="utf-8"))
    except EvidenceFrontierError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_SOURCE_UNREADABLE", "source must be readable JSON") from exc
    if not isinstance(value, dict):
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_SOURCE_INVALID", "source root must be one object")
    return value


def _write(payload: dict[str, Any], out: Path) -> None:
    destination = Path(out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=destination.parent, prefix=f".{destination.name}.", suffix=".tmp", delete=False) as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            temporary = Path(handle.name)
        temporary.replace(destination)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _text(value: object, field: str, maximum: int = 320) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_SOURCE_INVALID", f"{field} must be non-empty and at most {maximum} characters")
    return value.strip()


def _relative(value: object, field: str) -> str:
    path = _text(value, field).replace("\\", "/").removeprefix("./").rstrip("/")
    if not path or path.startswith("/") or path.startswith("../") or "/../" in path or re.match(r"^[A-Za-z]:", path):
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_PATH_INVALID", f"{field} must be workspace-relative")
    return path


def _integer(value: object, field: str, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_SOURCE_INVALID", f"{field} must be an integer from 0 through {maximum}")
    return value


def _sha(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_SOURCE_INVALID", f"{field} must be a lowercase SHA-256 digest")
    return value


def _path_sha(root: Path, relative: str, expected: str, field: str) -> Path:
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_PATH_INVALID", f"{field} escapes the workspace") from exc
    if not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_EVIDENCE_UNREADABLE", f"{field} is missing or too large")
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_EVIDENCE_HASH_MISMATCH", f"{field} SHA-256 does not match")
    return path


def _evaluation(root: Path, raw: object) -> tuple[dict[str, Any], dict[str, str], list[str]]:
    if not isinstance(raw, dict) or set(raw) != {"path", "sha256"}:
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_REQUEST_INVALID", "evaluation must contain exactly path and sha256")
    path = _relative(raw.get("path"), "evaluation.path")
    digest = _sha(raw.get("sha256"), "evaluation.sha256")
    source = _path_sha(root, path, digest, "evaluation")
    verification = verify_proofsearch_evaluation(root, source)
    if verification.get("valid") is not True:
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_EVALUATION_INVALID", "evaluation must be a current verified ProofSearch receipt")
    value = _load(source)
    candidates = value.get("candidates")
    if not isinstance(candidates, list):
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_EVALUATION_INVALID", "evaluation candidates are invalid")
    eligible = sorted(_text(item.get("candidate_id"), "evaluation.candidate_id", 120) for item in candidates if isinstance(item, dict) and item.get("eligible") is True)
    if not 2 <= len(eligible) <= 12 or len(set(eligible)) != len(eligible):
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_ELIGIBLE_CANDIDATES_REQUIRED", "evaluation must contain 2 through 12 unique eligible candidates")
    return value, {"path": path, "sha256": digest}, eligible


def _measurement(root: Path, raw: object, experiment_id: str) -> dict[str, Any] | None:
    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) != {"elapsed_ms", "receipt"}:
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_EXPERIMENT_INVALID", f"{experiment_id}.measurement must contain exactly elapsed_ms and receipt")
    receipt = raw.get("receipt")
    if not isinstance(receipt, dict) or set(receipt) != {"path", "sha256"}:
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_EXPERIMENT_INVALID", f"{experiment_id}.measurement.receipt must contain exactly path and sha256")
    path = _relative(receipt.get("path"), f"{experiment_id}.measurement.receipt.path")
    digest = _sha(receipt.get("sha256"), f"{experiment_id}.measurement.receipt.sha256")
    _path_sha(root, path, digest, f"{experiment_id}.measurement.receipt")
    return {"elapsed_ms": _integer(raw.get("elapsed_ms"), f"{experiment_id}.measurement.elapsed_ms", MAX_ELAPSED_MS), "receipt": {"path": path, "sha256": digest}}


def _experiment(root: Path, raw: object, eligible: list[str], seen: set[str]) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != {"experiment_id", "kind", "description", "predictions", "measurement"}:
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_EXPERIMENT_INVALID", "experiment must contain exactly experiment_id, kind, description, predictions, and measurement")
    experiment_id = _text(raw.get("experiment_id"), "experiment_id", 120)
    if experiment_id in seen:
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_EXPERIMENT_DUPLICATE", f"duplicate experiment_id: {experiment_id}")
    seen.add(experiment_id)
    kind = _text(raw.get("kind"), f"{experiment_id}.kind", 32)
    if kind not in _KINDS:
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_EXPERIMENT_INVALID", f"{experiment_id}.kind must be one of {', '.join(sorted(_KINDS))}")
    predictions = raw.get("predictions")
    if not isinstance(predictions, dict) or set(predictions) != set(eligible):
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_PREDICTION_INVALID", f"{experiment_id}.predictions must contain exactly the eligible candidate identifiers")
    normalized = {candidate_id: predictions[candidate_id] for candidate_id in eligible}
    if any(value not in _OUTCOMES for value in normalized.values()):
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_PREDICTION_INVALID", f"{experiment_id}.predictions values must be pass, fail, or unknown")
    pairs = list(combinations(eligible, 2))
    separated = sum(normalized[left] != "unknown" and normalized[right] != "unknown" and normalized[left] != normalized[right] for left, right in pairs)
    return {
        "experiment_id": experiment_id,
        "kind": kind,
        "description": _text(raw.get("description"), f"{experiment_id}.description"),
        "predictions": normalized,
        "measurement": _measurement(root, raw.get("measurement"), experiment_id),
        "separation_count": separated,
        "candidate_pair_count": len(pairs),
    }


def _rank(experiment: dict[str, Any]) -> tuple[object, ...]:
    measurement = experiment["measurement"]
    return (-experiment["separation_count"], measurement is None, measurement["elapsed_ms"] if measurement else 0, experiment["experiment_id"])


def _core(evaluation: dict[str, str], eligible: list[str], maximum: int, experiments: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(experiments, key=_rank)
    for position, experiment in enumerate(ordered, 1):
        experiment["rank"] = position
    chosen = ordered[0] if ordered and ordered[0]["separation_count"] > 0 else None
    return {
        "schema": FRONTIER_SCHEMA,
        "evaluation": evaluation,
        "eligible_candidate_ids": eligible,
        "max_experiments": maximum,
        "experiments": ordered,
        "next_experiment": chosen["experiment_id"] if chosen else None,
        "decision": "next_experiment_selected" if chosen else "no_discriminating_experiment",
        "savings": {"elapsed_ms": None, "tokens": None, "cost_usd": None, "productivity": None, "evidence": "unavailable"},
        "authority": _AUTHORITY,
    }


def plan_evidence_frontier(root: Path, request_path: Path, out: Path) -> dict[str, Any]:
    """Seal a non-executing next-evidence recommendation from local receipts."""
    workspace = Path(root).resolve()
    request = _load(request_path)
    if request.get("schema") != REQUEST_SCHEMA:
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_REQUEST_INVALID", f"schema must be {REQUEST_SCHEMA}")
    evaluation_value, evaluation, eligible = _evaluation(workspace, request.get("evaluation"))
    maximum = _integer(request.get("max_experiments"), "max_experiments", MAX_EXPERIMENTS)
    if maximum < 1:
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_REQUEST_INVALID", "max_experiments must be from 1 through 64")
    raw_experiments = request.get("experiments")
    if not isinstance(raw_experiments, list) or not 1 <= len(raw_experiments) <= maximum:
        raise EvidenceFrontierError("EVIDENCE_FRONTIER_EXPERIMENT_COUNT", "experiments must contain 1 through max_experiments items")
    seen: set[str] = set()
    experiments = [_experiment(workspace, item, eligible, seen) for item in raw_experiments]
    core = _core(evaluation, eligible, maximum, experiments)
    chosen = core["next_experiment"]
    marker = "EVIDENCE_FRONTIER_NEXT_EXPERIMENT_SELECTED" if chosen else "EVIDENCE_FRONTIER_NO_DISCRIMINATING_EXPERIMENT"
    payload = {
        **core,
        "frontier_sha256": _digest(core),
        "marker": marker,
        "markers": [marker, "EVIDENCE_FRONTIER_PREDICTIONS_UNVERIFIED", "EVIDENCE_FRONTIER_AUTHORITY_RETAINED", "EVIDENCE_FRONTIER_SAVINGS_UNMEASURED"],
    }
    _write(payload, out)
    return {**payload, "path": str(Path(out))}


def verify_evidence_frontier(root: Path, frontier_path: Path) -> dict[str, Any]:
    """Verify a sealed frontier and its current ProofSearch evaluation binding."""
    workspace = Path(root).resolve()
    value = _load(frontier_path)
    errors: list[str] = []
    if value.get("schema") != FRONTIER_SCHEMA:
        errors.append(f"schema must be {FRONTIER_SCHEMA}")
    if value.get("authority") != _AUTHORITY:
        errors.append("authority boundary is invalid")
    try:
        _, evaluation, eligible = _evaluation(workspace, value.get("evaluation"))
        maximum = _integer(value.get("max_experiments"), "max_experiments", MAX_EXPERIMENTS)
        experiments = value.get("experiments")
        if not isinstance(experiments, list) or not 1 <= len(experiments) <= maximum:
            raise EvidenceFrontierError("EVIDENCE_FRONTIER_EXPERIMENT_COUNT", "experiments must contain 1 through max_experiments items")
        seen: set[str] = set()
        rebuilt = [_experiment(workspace, {key: item.get(key) for key in ("experiment_id", "kind", "description", "predictions", "measurement")}, eligible, seen) for item in experiments if isinstance(item, dict)]
        if len(rebuilt) != len(experiments) or value.get("eligible_candidate_ids") != eligible:
            raise EvidenceFrontierError("EVIDENCE_FRONTIER_SOURCE_INVALID", "frontier candidates or experiments are invalid")
        core = _core(evaluation, eligible, maximum, rebuilt)
        if value.get("frontier_sha256") != _digest(core):
            errors.append("frontier_sha256 does not match canonical frontier content")
    except EvidenceFrontierError as exc:
        errors.append(f"{exc.code}: {exc}")
    marker = "EVIDENCE_FRONTIER_VERIFIED" if not errors else "EVIDENCE_FRONTIER_INVALID"
    return {
        "schema": "factory.evidence-frontier-verification.v1",
        "valid": not errors,
        "errors": sorted(set(errors)),
        "frontier_sha256": value.get("frontier_sha256"),
        "next_experiment": value.get("next_experiment"),
        "marker": marker,
        "markers": [marker, "EVIDENCE_FRONTIER_AUTHORITY_RETAINED"],
    }
