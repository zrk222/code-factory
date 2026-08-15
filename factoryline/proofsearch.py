"""Deterministic counterfactual repair planning and evidence comparison.

ProofSearch never generates or applies a repair. It binds a verified graph
divergence to an exact proof slice and compares local, hash-bound candidate
evidence using a documented total ordering.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import hashlib
import json
import math
import re
import tempfile

from .graph_forensics import GraphForensicsError, graph_forensics


PLAN_SCHEMA = "factory.proofsearch-plan.v1"
REQUEST_SCHEMA = "factory.proofsearch-request.v1"
EVALUATION_SCHEMA = "factory.proofsearch-evaluation.v1"
MAX_SOURCE_BYTES = 2_097_152
MAX_CANDIDATES = 12
MAX_PROOFS = 64
MAX_PATHS = 256
_SHA = re.compile(r"^[0-9a-f]{64}$")
_AUTHORITY = {
    "code_generation": False, "command_execution": False,
    "workspace_mutation": False, "test_mutation": False,
    "checkpoint_mutation": False, "approval": False, "merge": False,
    "publication": False, "deployment": False, "signing": False,
    "messaging": False, "credential": False, "connector": False,
}


class ProofSearchError(ValueError):
    """A closed, user-correctable ProofSearch contract failure."""

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
            raise ProofSearchError("PROOFSEARCH_SOURCE_UNREADABLE", "source is missing or exceeds 2097152 bytes")
        value = json.loads(source.read_text(encoding="utf-8"))
    except ProofSearchError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProofSearchError("PROOFSEARCH_SOURCE_UNREADABLE", "source must be readable JSON") from exc
    if not isinstance(value, dict):
        raise ProofSearchError("PROOFSEARCH_SOURCE_INVALID", "source root must be one object")
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
        raise ProofSearchError("PROOFSEARCH_SOURCE_INVALID", f"{field} must be non-empty and at most {maximum} characters")
    return value.strip()


def _relative(value: object, field: str) -> str:
    path = _text(value, field).replace("\\", "/").removeprefix("./").rstrip("/")
    if not path or path.startswith("/") or path.startswith("../") or "/../" in path or re.match(r"^[A-Za-z]:", path):
        raise ProofSearchError("PROOFSEARCH_PATH_INVALID", f"{field} must be workspace-relative")
    return path


def _integer(value: object, field: str, maximum: int = 10**12) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > maximum:
        raise ProofSearchError("PROOFSEARCH_SOURCE_INVALID", f"{field} must be an integer from 0 through {maximum}")
    return value


def _number_or_none(value: object, field: str) -> float | int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0 or not math.isfinite(float(value)):
        raise ProofSearchError("PROOFSEARCH_SOURCE_INVALID", f"{field} must be null or a finite non-negative number")
    return value


def _sha(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ProofSearchError("PROOFSEARCH_SOURCE_INVALID", f"{field} must be a lowercase SHA-256 digest")
    return value


def _path_sha(root: Path, relative: str, expected: str, field: str) -> None:
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ProofSearchError("PROOFSEARCH_PATH_INVALID", f"{field} escapes the workspace") from exc
    if not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
        raise ProofSearchError("PROOFSEARCH_EVIDENCE_UNREADABLE", f"{field} is missing or too large")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise ProofSearchError("PROOFSEARCH_EVIDENCE_HASH_MISMATCH", f"{field} SHA-256 does not match")


def create_proofsearch_plan(root: Path, baseline_path: Path, candidate_path: Path, changed_paths: list[str], out: Path) -> dict[str, Any]:
    """Seal one verified divergence and its exact local proof-impact slice."""
    from .graph_ops import graph_ops_impact

    workspace = Path(root).resolve()
    changed = sorted({_relative(item, "changed_path") for item in changed_paths})
    if not changed or len(changed) > MAX_PATHS:
        raise ProofSearchError("PROOFSEARCH_CHANGED_PATHS_INVALID", f"changed_paths must contain 1 through {MAX_PATHS} items")
    try:
        forensic = graph_forensics(Path(baseline_path), Path(candidate_path))
    except GraphForensicsError as exc:
        raise ProofSearchError(exc.code, str(exc)) from exc
    if forensic["divergence"] is None:
        raise ProofSearchError("PROOFSEARCH_DIVERGENCE_REQUIRED", "verified lineage receipts do not diverge")
    impact = graph_ops_impact(workspace, changed)
    core = {
        "schema": PLAN_SCHEMA,
        "graph_id": forensic["graph_id"],
        "forensics_sha256": forensic["forensics_sha256"],
        "first_divergence": forensic["divergence"],
        "authorized_changed_paths": changed,
        "proof_slice": {
            "graph_sha256": impact["graph_sha256"],
            "matched_proofs": impact["matched_proofs"],
            "rerun_proofs": impact["rerun_proofs"],
            "verified_current_proofs": impact["verified_current_proofs"],
            "unmatched_changed_paths": impact["unmatched_changed_paths"],
        },
        "authority": _AUTHORITY,
    }
    payload = {**core, "plan_sha256": _digest(core), "marker": "PROOFSEARCH_PLAN_SEALED", "markers": ["PROOFSEARCH_PLAN_SEALED", "PROOFSEARCH_PROOF_SLICE_EXACT", "PROOFSEARCH_AUTHORITY_RETAINED"]}
    _write(payload, out)
    return {**payload, "path": str(Path(out))}


def _verify_plan(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("schema") != PLAN_SCHEMA or value.get("authority") != _AUTHORITY:
        raise ProofSearchError("PROOFSEARCH_PLAN_INVALID", "plan schema or authority boundary is invalid")
    core = {key: value.get(key) for key in ("schema", "graph_id", "forensics_sha256", "first_divergence", "authorized_changed_paths", "proof_slice", "authority")}
    if value.get("plan_sha256") != _digest(core):
        raise ProofSearchError("PROOFSEARCH_PLAN_INVALID", "plan_sha256 does not match canonical plan content")
    return value


def _proof(root: Path, raw: object, offset: int) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ProofSearchError("PROOFSEARCH_CANDIDATE_INVALID", f"proofs[{offset}] must be an object")
    receipt = raw.get("receipt")
    if not isinstance(receipt, dict):
        raise ProofSearchError("PROOFSEARCH_CANDIDATE_INVALID", f"proofs[{offset}].receipt must be an object")
    path = _relative(receipt.get("path"), f"proofs[{offset}].receipt.path")
    digest = _sha(receipt.get("sha256"), f"proofs[{offset}].receipt.sha256")
    _path_sha(root, path, digest, f"proofs[{offset}].receipt")
    receipt_value = _load(root / path)
    observed = _receipt_outcome(receipt_value)
    status = raw.get("status")
    if status not in {"passed", "failed"}:
        raise ProofSearchError("PROOFSEARCH_CANDIDATE_INVALID", f"proofs[{offset}].status must be passed or failed")
    return {
        "name": _text(raw.get("name"), f"proofs[{offset}].name", 160),
        "required": raw.get("required") is True,
        "status": status,
        "receipt_passed": observed,
        "receipt": {"path": path, "sha256": digest},
        "elapsed_ms": _integer(raw.get("elapsed_ms"), f"proofs[{offset}].elapsed_ms"),
        "tokens": _number_or_none(raw.get("tokens"), f"proofs[{offset}].tokens"),
        "cost_usd": _number_or_none(raw.get("cost_usd"), f"proofs[{offset}].cost_usd"),
    }


def _receipt_outcome(receipt: dict[str, Any]) -> bool | None:
    for key in ("passed", "valid", "ok"):
        if isinstance(receipt.get(key), bool):
            return receipt[key]
    for key in ("status", "verdict", "decision"):
        value = receipt.get(key)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"passed", "pass", "verified", "valid", "ok", "satisfied"}:
                return True
            if normalized in {"failed", "fail", "invalid", "rejected", "blocked", "needs_revision"}:
                return False
    return None


def _candidate(root: Path, raw: object, authorized: set[str], seen: set[str]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ProofSearchError("PROOFSEARCH_CANDIDATE_INVALID", "candidate must be an object")
    candidate_id = _text(raw.get("candidate_id"), "candidate_id", 120)
    if candidate_id in seen:
        raise ProofSearchError("PROOFSEARCH_CANDIDATE_DUPLICATE", f"duplicate candidate_id: {candidate_id}")
    seen.add(candidate_id)
    patch = raw.get("patch")
    if not isinstance(patch, dict):
        raise ProofSearchError("PROOFSEARCH_CANDIDATE_INVALID", f"{candidate_id}.patch must be an object")
    patch_path = _relative(patch.get("path"), f"{candidate_id}.patch.path")
    patch_sha = _sha(patch.get("sha256"), f"{candidate_id}.patch.sha256")
    _path_sha(root, patch_path, patch_sha, f"{candidate_id}.patch")
    paths = sorted({_relative(item, f"{candidate_id}.changed_path") for item in raw.get("changed_paths", [])})
    if not paths or len(paths) > MAX_PATHS:
        raise ProofSearchError("PROOFSEARCH_CANDIDATE_INVALID", f"{candidate_id}.changed_paths must contain 1 through {MAX_PATHS} items")
    raw_proofs = raw.get("proofs")
    if not isinstance(raw_proofs, list) or not raw_proofs or len(raw_proofs) > MAX_PROOFS:
        raise ProofSearchError("PROOFSEARCH_CANDIDATE_INVALID", f"{candidate_id}.proofs must contain 1 through {MAX_PROOFS} items")
    proofs = [_proof(root, item, offset) for offset, item in enumerate(raw_proofs)]
    mutation = raw.get("mutation")
    if not isinstance(mutation, dict):
        raise ProofSearchError("PROOFSEARCH_CANDIDATE_INVALID", f"{candidate_id}.mutation must be an object")
    killed = _integer(mutation.get("killed"), f"{candidate_id}.mutation.killed", 100000)
    total = _integer(mutation.get("total"), f"{candidate_id}.mutation.total", 100000)
    guardrails = raw.get("guardrails")
    if not isinstance(guardrails, dict) or set(guardrails) != {"weakens_tests", "suppresses_errors", "expands_scope"} or any(not isinstance(value, bool) for value in guardrails.values()):
        raise ProofSearchError("PROOFSEARCH_CANDIDATE_INVALID", f"{candidate_id}.guardrails must contain three boolean fields")
    reasons: list[str] = []
    if any(item["receipt_passed"] is None for item in proofs): reasons.append("PROOF_RECEIPT_OUTCOME_UNVERIFIABLE")
    if any(item["receipt_passed"] is not None and item["receipt_passed"] != (item["status"] == "passed") for item in proofs): reasons.append("PROOF_RECEIPT_STATUS_MISMATCH")
    if any(item["required"] and item["status"] != "passed" for item in proofs): reasons.append("REQUIRED_PROOF_FAILED")
    if total < 1 or killed != total: reasons.append("HOLLOW_CANDIDATE_TESTS")
    if not set(paths).issubset(authorized): reasons.append("CANDIDATE_SCOPE_ESCAPE")
    if guardrails["weakens_tests"]: reasons.append("TEST_WEAKENING_DECLARED")
    if guardrails["suppresses_errors"]: reasons.append("ERROR_SUPPRESSION_DECLARED")
    if guardrails["expands_scope"]: reasons.append("SCOPE_EXPANSION_DECLARED")
    return {
        "candidate_id": candidate_id, "patch": {"path": patch_path, "sha256": patch_sha},
        "changed_paths": paths, "proofs": proofs, "mutation": {"killed": killed, "total": total},
        "guardrails": guardrails, "risk_score": _integer(raw.get("risk_score"), f"{candidate_id}.risk_score", 100),
        "changed_lines": _integer(raw.get("changed_lines"), f"{candidate_id}.changed_lines", 1000000),
        "eligible": not reasons, "reasons": sorted(reasons),
    }


def _metrics(candidate: dict[str, Any]) -> dict[str, Any]:
    proofs = candidate["proofs"]
    tokens = [item["tokens"] for item in proofs]
    costs = [item["cost_usd"] for item in proofs]
    return {
        "proof_elapsed_ms": sum(item["elapsed_ms"] for item in proofs),
        "tokens": sum(tokens) if all(item is not None for item in tokens) else None,
        "cost_usd": round(sum(float(item) for item in costs), 8) if all(item is not None for item in costs) else None,
    }


def _rank(candidate: dict[str, Any]) -> tuple[object, ...]:
    metrics = candidate["metrics"]
    return (
        candidate["risk_score"], candidate["changed_lines"], metrics["proof_elapsed_ms"],
        metrics["tokens"] is None, metrics["tokens"] or 0,
        metrics["cost_usd"] is None, metrics["cost_usd"] or 0, candidate["candidate_id"],
    )


def _savings(request: dict[str, Any], winner: dict[str, Any] | None) -> dict[str, Any]:
    unknown = {"elapsed_ms": None, "tokens": None, "cost_usd": None, "productivity": None, "evidence": "unavailable"}
    baseline = request.get("paired_baseline")
    if winner is None or baseline is None:
        return unknown
    if not isinstance(baseline, dict) or set(baseline) != {"elapsed_ms", "tokens", "cost_usd"}:
        raise ProofSearchError("PROOFSEARCH_BASELINE_INVALID", "paired_baseline must contain exactly elapsed_ms, tokens, and cost_usd")
    elapsed = _integer(baseline["elapsed_ms"], "paired_baseline.elapsed_ms")
    tokens = _integer(baseline["tokens"], "paired_baseline.tokens")
    cost = _number_or_none(baseline["cost_usd"], "paired_baseline.cost_usd")
    metrics = winner["metrics"]
    return {
        "elapsed_ms": elapsed - metrics["proof_elapsed_ms"],
        "tokens": tokens - metrics["tokens"] if metrics["tokens"] is not None else None,
        "cost_usd": round(float(cost) - metrics["cost_usd"], 8) if cost is not None and metrics["cost_usd"] is not None else None,
        "productivity": None,
        "evidence": "exact_paired_baseline",
    }


def _compare_candidates(
    workspace: Path,
    raw_candidates: list[object],
    authorized: set[str],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    seen: set[str] = set()
    candidates = [_candidate(workspace, raw, authorized, seen) for raw in raw_candidates]
    for candidate in candidates:
        candidate["metrics"] = _metrics(candidate)
    eligible = sorted((item for item in candidates if item["eligible"]), key=_rank)
    winner = eligible[0] if eligible else None
    winner_id = winner["candidate_id"] if winner else None
    for candidate in candidates:
        if candidate["eligible"] and candidate["candidate_id"] != winner_id:
            candidate["reasons"] = ["PARETO_DOMINATED_BY_VERIFIED_WINNER"]
    return candidates, winner


def _evaluation_markers(
    marker: str,
    candidates: list[dict[str, Any]],
    paired_baseline: object,
) -> list[str]:
    markers = [
        marker,
        "PROOFSEARCH_CANDIDATE_BOUNDS_ENFORCED",
        "PROOFSEARCH_CANDIDATES_HASH_BOUND",
        "PROOFSEARCH_LOSERS_EXPLAINED",
        "PROOFSEARCH_MUTATION_EXACT",
        "PROOFSEARCH_AUTHORITY_RETAINED",
    ]
    if any(not candidate["eligible"] for candidate in candidates):
        markers.append("PROOFSEARCH_CANDIDATE_REJECTED")
    if paired_baseline is None:
        markers.append("PROOFSEARCH_SAVINGS_UNMEASURED")
    return markers


def evaluate_proofsearch(root: Path, request_path: Path, out: Path) -> dict[str, Any]:
    """Verify and compare supplied candidate evidence without executing it."""
    workspace = Path(root).resolve()
    request = _load(request_path)
    if request.get("schema") != REQUEST_SCHEMA:
        raise ProofSearchError("PROOFSEARCH_REQUEST_INVALID", f"schema must be {REQUEST_SCHEMA}")
    plan_ref = request.get("plan")
    if not isinstance(plan_ref, dict):
        raise ProofSearchError("PROOFSEARCH_REQUEST_INVALID", "plan must be an object")
    plan_path = _relative(plan_ref.get("path"), "plan.path")
    plan_sha = _sha(plan_ref.get("sha256"), "plan.sha256")
    _path_sha(workspace, plan_path, plan_sha, "plan")
    plan = _verify_plan(_load(workspace / plan_path))
    raw_candidates = request.get("candidates")
    if not isinstance(raw_candidates, list) or not 2 <= len(raw_candidates) <= MAX_CANDIDATES:
        raise ProofSearchError("PROOFSEARCH_CANDIDATE_COUNT", f"candidates must contain 2 through {MAX_CANDIDATES} items")
    authorized = set(plan["authorized_changed_paths"])
    candidates, winner = _compare_candidates(workspace, raw_candidates, authorized)
    winner_id = winner["candidate_id"] if winner else None
    core = {
        "schema": EVALUATION_SCHEMA, "plan_sha256": plan["plan_sha256"],
        "winner": winner_id, "candidates": sorted(candidates, key=lambda item: item["candidate_id"]),
        "savings": _savings(request, winner),
        "decision": "verified_winner" if winner else "no_eligible_candidate",
        "apply": False, "authority": _AUTHORITY,
    }
    marker = "PROOFSEARCH_WINNER_VERIFIED" if winner else "PROOFSEARCH_NO_ELIGIBLE_CANDIDATE"
    markers = _evaluation_markers(marker, candidates, request.get("paired_baseline"))
    payload = {**core, "evaluation_sha256": _digest(core), "marker": marker, "markers": markers}
    _write(payload, out)
    return {**payload, "path": str(Path(out))}


def verify_proofsearch_evaluation(root: Path, evaluation_path: Path) -> dict[str, Any]:
    """Verify a sealed evaluation and every referenced local evidence hash."""
    workspace = Path(root).resolve()
    value = _load(evaluation_path)
    errors: list[str] = []
    if value.get("schema") != EVALUATION_SCHEMA: errors.append(f"schema must be {EVALUATION_SCHEMA}")
    if value.get("authority") != _AUTHORITY or value.get("apply") is not False: errors.append("authority boundary is invalid")
    for candidate in value.get("candidates", []):
        try:
            _path_sha(workspace, candidate["patch"]["path"], candidate["patch"]["sha256"], "candidate.patch")
            for proof in candidate["proofs"]:
                _path_sha(workspace, proof["receipt"]["path"], proof["receipt"]["sha256"], "candidate.proof.receipt")
        except (KeyError, TypeError, ProofSearchError) as exc:
            errors.append(str(exc))
    core = {key: value.get(key) for key in ("schema", "plan_sha256", "winner", "candidates", "savings", "decision", "apply", "authority")}
    calculated = _digest(core)
    if value.get("evaluation_sha256") != calculated: errors.append("evaluation_sha256 does not match canonical evaluation content")
    marker = "PROOFSEARCH_EVALUATION_VERIFIED" if not errors else "PROOFSEARCH_EVALUATION_INVALID"
    return {"schema": "factory.proofsearch-verification.v1", "valid": not errors, "errors": sorted(set(errors)), "evaluation_sha256": calculated, "winner": value.get("winner"), "marker": marker, "markers": [marker, "PROOFSEARCH_AUTHORITY_RETAINED"]}
