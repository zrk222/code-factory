"""Content-addressed, fail-closed reuse for read-only proof gates."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import time
from typing import Any, Iterable

from .run_metrics import _atomic_json
from .savings import SavingsError, record_savings_pair


REQUEST_SCHEMA = "factory.proof-request.v1"
RECEIPT_SCHEMA = "factory.proof-receipt.v1"
PLAN_SCHEMA = "factory.proof-plan.v1"


class ProofReuseError(ValueError):
    """A typed unsafe or invalid proof-reuse request."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_file(path: Path) -> str:
    return _sha_bytes(Path(path).read_bytes())


def _normalized_mapping(value: object, label: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ProofReuseError("PROOF_IDENTITY_INVALID", f"{label} must be an object")
    result = {}
    for key, item in sorted(value.items()):
        if not isinstance(key, str) or not key.strip() or not isinstance(item, (str, int, float, bool)):
            raise ProofReuseError("PROOF_IDENTITY_INVALID", f"{label} entries must be scalar and named")
        result[key.strip()] = str(item)
    return result


def _relative_file(root: Path, raw: str, label: str) -> tuple[str, Path]:
    if not isinstance(raw, str) or not raw.strip():
        raise ProofReuseError("PROOF_INPUT_INVALID", f"{label} path must be a non-empty string")
    root = Path(root).resolve()
    candidate = (root / raw).resolve() if not Path(raw).is_absolute() else Path(raw).resolve()
    try:
        relative = candidate.relative_to(root)
    except ValueError as error:
        raise ProofReuseError("PROOF_PATH_ESCAPE", f"{label} path escapes the workspace") from error
    if not candidate.is_file():
        raise ProofReuseError("PROOF_INPUT_MISSING", f"{label} path is not a regular file: {relative.as_posix()}")
    return relative.as_posix(), candidate


def _snapshot(root: Path, paths: object, label: str) -> list[dict[str, str]]:
    if not isinstance(paths, list) or not paths:
        raise ProofReuseError("PROOF_INPUT_INVALID", f"{label} must contain at least one file")
    seen = set()
    rows = []
    for raw in paths:
        relative, candidate = _relative_file(root, raw, label)
        if relative in seen:
            continue
        seen.add(relative)
        rows.append({"path": relative, "sha256": _sha_file(candidate)})
    return sorted(rows, key=lambda item: item["path"])


def _command_digest(command: object) -> str:
    if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
        raise ProofReuseError("PROOF_COMMAND_INVALID", "command must be a non-empty argv string array")
    return _sha_bytes(_canonical(command))


def _proof_key(facts: dict[str, Any]) -> str:
    return _sha_bytes(_canonical(facts))


def proof_facts(root: Path, gate: dict[str, Any]) -> dict[str, Any]:
    """Return canonical proof facts without retaining raw command text."""
    if not isinstance(gate, dict):
        raise ProofReuseError("PROOF_GATE_INVALID", "gate must be an object")
    name = gate.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 120:
        raise ProofReuseError("PROOF_GATE_INVALID", "gate name must contain 1 to 120 characters")
    return {
        "schema": RECEIPT_SCHEMA,
        "gate": name.strip(),
        "command_sha256": _command_digest(gate.get("command")),
        "inputs": _snapshot(Path(root), gate.get("inputs"), "inputs"),
        "toolchain": _normalized_mapping(gate.get("toolchain"), "toolchain"),
        "environment": _normalized_mapping(gate.get("environment"), "environment"),
    }


def proof_key(root: Path, gate: dict[str, Any]) -> str:
    """Compute the content-addressed key for a proof gate."""
    return _proof_key(proof_facts(root, gate))


def _proof_directory(root: Path) -> Path:
    return Path(root).resolve() / ".factory" / "proofs"


def _plan_directory(root: Path) -> Path:
    return Path(root).resolve() / ".factory" / "proof-plans"


def _validate_record_observation(gate: dict[str, Any], elapsed_ms: int, tokens: int | None, status: str) -> None:
    if gate.get("read_only") is not True:
        raise ProofReuseError("PROOF_SIDE_EFFECT_REUSE_REFUSED", "only explicitly read-only gates can be recorded for reuse")
    if not isinstance(elapsed_ms, int) or isinstance(elapsed_ms, bool) or elapsed_ms <= 0:
        raise ProofReuseError("PROOF_ELAPSED_INVALID", "elapsed_ms must be a positive integer")
    if tokens is not None and (not isinstance(tokens, int) or isinstance(tokens, bool) or tokens < 0):
        raise ProofReuseError("PROOF_TOKENS_INVALID", "tokens must be a non-negative integer or null")
    if status != "green":
        raise ProofReuseError("PROOF_STATUS_NOT_GREEN", "only green proofs can be reused")


def _authority() -> dict[str, bool]:
    return {
        "validation_reuse": True,
        "publish": False,
        "deploy": False,
        "sign": False,
        "approve": False,
        "external_message": False,
    }


def record_proof(
    root: Path,
    gate: dict[str, Any],
    *,
    elapsed_ms: int,
    tokens: int | None = None,
    status: str = "green",
    replace: bool = False,
) -> dict[str, Any]:
    """Record one completed, read-only proof observation."""
    _validate_record_observation(gate, elapsed_ms, tokens, status)
    facts = proof_facts(Path(root), gate)
    outputs = _snapshot(Path(root), gate.get("outputs"), "outputs")
    key = _proof_key(facts)
    core = {
        "schema": RECEIPT_SCHEMA,
        "marker": "PROOF_RECEIPT_ATOMIC",
        "markers": [
            "PROOF_KEY_CONTENT_ADDRESSED", "PROOF_RECEIPT_ATOMIC",
            "PROOF_PUBLICATION_AUTHORITY_UNCHANGED",
        ],
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "proof_key": key,
        "gate": facts["gate"],
        "command_sha256": facts["command_sha256"],
        "read_only": True,
        "status": "green",
        "inputs": facts["inputs"],
        "outputs": outputs,
        "toolchain": facts["toolchain"],
        "environment": facts["environment"],
        "baseline": {"elapsed_ms": elapsed_ms, "tokens": tokens},
        "authority": _authority(),
    }
    receipt = {**core, "receipt_sha256": _sha_bytes(_canonical(core))}
    destination = _proof_directory(Path(root)) / f"{key}.json"
    if destination.exists() and not replace:
        raise ProofReuseError("PROOF_OVERWRITE_REFUSED", "proof receipt exists; pass replace explicitly")
    _atomic_json(destination, receipt)
    return {**receipt, "receipt": str(destination)}


def _load_receipt(receipt_path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        payload = json.loads(Path(receipt_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return None, [f"receipt unreadable: {error}"]
    return payload, []


def _verify_rows(root: Path, payload: dict[str, Any], field: str) -> list[str]:
    rows = payload.get(field)
    if not isinstance(rows, list) or not rows:
        return [f"{field} are missing"]
    errors = []
    for row in rows:
        if not isinstance(row, dict):
            errors.append(f"{field}: artifact row must be an object")
            continue
        try:
            relative, candidate = _relative_file(Path(root), row.get("path"), field)
        except ProofReuseError as error:
            errors.append(f"{field}: {error}")
            continue
        if relative != row.get("path") or _sha_file(candidate) != row.get("sha256"):
            errors.append(f"{field} hash mismatch: {relative}")
    return errors


def _receipt_facts(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "gate": payload.get("gate"),
        "command_sha256": payload.get("command_sha256"),
        "inputs": payload.get("inputs"),
        "toolchain": payload.get("toolchain"),
        "environment": payload.get("environment"),
    }


def verify_proof_receipt(root: Path, receipt_path: Path) -> dict[str, Any]:
    """Verify receipt integrity and all current input/output hashes."""
    payload, errors = _load_receipt(receipt_path)
    if payload is None:
        return {"valid": False, "errors": errors, "marker": "PROOF_INPUT_INTEGRITY_REQUIRED"}
    if payload.get("schema") != RECEIPT_SCHEMA:
        errors.append("unsupported receipt schema")
    core = {key: value for key, value in payload.items() if key != "receipt_sha256"}
    if _sha_bytes(_canonical(core)) != payload.get("receipt_sha256"):
        errors.append("receipt hash mismatch")
    if payload.get("read_only") is not True or payload.get("status") != "green":
        errors.append("receipt is not a green read-only proof")
    errors.extend(_verify_rows(Path(root), payload, "inputs"))
    errors.extend(_verify_rows(Path(root), payload, "outputs"))
    if _proof_key(_receipt_facts(payload)) != payload.get("proof_key"):
        errors.append("proof key mismatch")
    return {
        "schema": "factory.proof-verification.v1",
        "marker": "PROOF_RECEIPT_VERIFIED" if not errors else "PROOF_INPUT_INTEGRITY_REQUIRED",
        "valid": not errors,
        "proof_key": payload.get("proof_key"),
        "receipt_sha256": payload.get("receipt_sha256"),
        "errors": errors,
    }


def _normalize_changed(paths: Iterable[str]) -> list[str]:
    return sorted({str(path).replace("\\", "/").lstrip("./") for path in paths if str(path).strip()})


def _relevant(gate: dict[str, Any], changed: list[str]) -> bool | None:
    if not changed:
        return None
    relevant = gate.get("relevant_paths")
    if gate.get("safe_to_skip") is not True or not isinstance(relevant, list) or not relevant:
        return None
    normalized = [str(path).replace("\\", "/").strip("/") for path in relevant if isinstance(path, str) and path.strip()]
    if not normalized:
        return None
    return any(path == prefix or path.startswith(prefix + "/") for path in changed for prefix in normalized)


def _reuse_savings(root: Path, receipt_path: Path, routing_elapsed_ms: int) -> dict[str, Any] | None:
    payload = json.loads(Path(receipt_path).read_text(encoding="utf-8"))
    baseline = payload.get("baseline") or {}
    elapsed = baseline.get("elapsed_ms")
    if not isinstance(elapsed, int) or elapsed <= 0 or routing_elapsed_ms <= 0:
        return None
    baseline_tokens = baseline.get("tokens")
    observed_tokens = 0 if isinstance(baseline_tokens, int) else None
    pair_id = f"proof-{payload['proof_key'][:16]}-{time.time_ns()}"
    result = record_savings_pair(
        Path(root),
        pair_id,
        {"elapsed_ms": elapsed, "tokens": baseline_tokens},
        {"elapsed_ms": routing_elapsed_ms, "tokens": observed_tokens},
        equivalent_outcome=True,
        evidence=Path(receipt_path),
    )
    return {
        "marker": "PROOF_AUTO_SAVINGS_EXACT",
        "time_saved_ms": result["savings"]["time_saved_ms"],
        "tokens_saved": result["savings"]["tokens_saved"],
        "token_marker": "PROOF_TOKEN_SAVINGS_UNKNOWN" if result["savings"]["tokens_saved"] is None else "PROOF_TOKEN_SAVINGS_EXACT",
    }


def _route_gate(root: Path, gate: object, changed: list[str], auto_savings: bool) -> dict[str, Any]:
    started = time.perf_counter_ns()
    name = gate.get("name") if isinstance(gate, dict) else None
    markers = ["PROOF_PLAN_DISPOSITION_EXACT", "PROOF_PUBLICATION_AUTHORITY_UNCHANGED"]
    item = {"gate": name if isinstance(name, str) else "invalid", "proof_key": None, "receipt_sha256": None, "savings": None}
    if not isinstance(gate, dict) or gate.get("read_only") is not True:
        item.update(disposition="BLOCK", reason="gate is not explicitly read-only")
        markers.append("PROOF_SIDE_EFFECT_REUSE_REFUSED")
        return _finish_route(item, markers, started)
    try:
        proof = _proof_key(proof_facts(root, gate))
    except ProofReuseError as error:
        item.update(disposition="BLOCK", reason=error.code)
        markers.append("PROOF_INPUT_INTEGRITY_REQUIRED")
        return _finish_route(item, markers, started)
    item["proof_key"] = proof
    relevance = _relevant(gate, changed)
    if relevance is False:
        item.update(disposition="SKIP", reason="reviewed relevance matcher returned unaffected")
        markers.append("PROOF_IRRELEVANT_CHANGE")
        return _finish_route(item, markers, started)
    receipt_path = _proof_directory(root) / f"{proof}.json"
    verification = verify_proof_receipt(root, receipt_path) if receipt_path.exists() else None
    if not verification or not verification["valid"]:
        item.update(disposition="RUN", reason="no exact verified green receipt" if verification is None else "receipt verification failed")
        markers.append("PROOF_EXECUTION_REQUIRED")
        if relevance is None:
            markers.append("PROOF_RELEVANCE_FAIL_CLOSED")
        return _finish_route(item, markers, started)
    item.update(disposition="REUSE", reason="exact green receipt verified", receipt_sha256=verification["receipt_sha256"])
    markers.append("PROOF_RECEIPT_REUSED")
    routing_ms = max(1, (time.perf_counter_ns() - started) // 1_000_000)
    if auto_savings:
        item["savings"] = _reuse_savings(root, receipt_path, routing_ms)
        if item["savings"]:
            markers.extend([item["savings"]["marker"], item["savings"]["token_marker"]])
    return _finish_route(item, markers, started, routing_ms)


def _finish_route(item: dict[str, Any], markers: list[str], started: int, elapsed_ms: int | None = None) -> dict[str, Any]:
    item["routing_elapsed_ms"] = elapsed_ms or max(1, (time.perf_counter_ns() - started) // 1_000_000)
    item["markers"] = sorted(set(markers))
    return item


def _validated_gates(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(manifest, dict) or manifest.get("schema") != REQUEST_SCHEMA:
        raise ProofReuseError("PROOF_MANIFEST_INVALID", f"manifest schema must be {REQUEST_SCHEMA}")
    gates = manifest.get("gates")
    if not isinstance(gates, list) or not gates or len(gates) > 500:
        raise ProofReuseError("PROOF_MANIFEST_INVALID", "manifest must contain 1 to 500 gates")
    return gates


def plan_proofs(
    root: Path,
    manifest: dict[str, Any],
    *,
    changed_paths: Iterable[str] = (),
    auto_savings: bool = False,
    out: Path | None = None,
) -> dict[str, Any]:
    """Route every requested proof to RUN, REUSE, SKIP, or BLOCK."""
    gates = _validated_gates(manifest)
    changed = _normalize_changed(changed_paths)
    items = [_route_gate(Path(root), gate, changed, auto_savings) for gate in gates]
    counts = {name: sum(item["disposition"] == name for item in items) for name in ("RUN", "REUSE", "SKIP", "BLOCK")}
    core = {
        "schema": PLAN_SCHEMA,
        "marker": "PROOF_PLAN_COMPACT",
        "markers": [
            "PROOF_PLAN_DISPOSITION_EXACT", "PROOF_PLAN_COMPACT",
            "PROOF_PUBLICATION_AUTHORITY_UNCHANGED", "RELEASE_023_SYNCHRONIZED",
        ],
        "manifest_sha256": _sha_bytes(_canonical(manifest)),
        "changed_paths_sha256": _sha_bytes(_canonical(changed)),
        "counts": counts,
        "items": items,
        "scope": [
            "The plan never executes gate commands.",
            "REUSE is limited to verified read-only validation receipts.",
            "Publication and other external side-effect authority are unchanged.",
        ],
    }
    plan_sha = _sha_bytes(_canonical(core))
    plan = {**core, "plan_sha256": plan_sha}
    destination = Path(out).resolve() if out else _plan_directory(Path(root)) / f"{plan_sha}.json"
    _atomic_json(destination, plan)
    return {**plan, "plan": str(destination)}


def load_manifest(path: Path) -> dict[str, Any]:
    """Load one proof-request JSON object and reject unreadable or non-object input."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProofReuseError("PROOF_MANIFEST_INVALID", str(error)) from error
    if not isinstance(payload, dict):
        raise ProofReuseError("PROOF_MANIFEST_INVALID", "manifest must be an object")
    return payload


def challenge_proof_receipt(root: Path, receipt_path: Path) -> dict[str, Any]:
    """Prove one isolated input mutation invalidates the receipt."""
    payload = json.loads(Path(receipt_path).read_text(encoding="utf-8"))
    rows = payload.get("inputs") or []
    if not rows:
        raise ProofReuseError("PROOF_INPUT_INVALID", "receipt has no challengeable input")
    with tempfile.TemporaryDirectory() as temporary:
        challenge_root = Path(temporary)
        for field in ("inputs", "outputs"):
            for row in payload.get(field, []):
                relative, source = _relative_file(Path(root), row["path"], field)
                destination = challenge_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
        baseline = verify_proof_receipt(challenge_root, Path(receipt_path))
        target = challenge_root / rows[0]["path"]
        target.write_bytes(target.read_bytes() + b"\nproof-mutation")
        mutated = verify_proof_receipt(challenge_root, Path(receipt_path))
    passed = baseline["valid"] and not mutated["valid"]
    return {
        "schema": "factory.proof-challenge.v1",
        "marker": "PROOF_MUTATION_REJECTED" if passed else "HOLLOW_PROOF_REUSE",
        "passed": passed,
        "baseline_valid": baseline["valid"],
        "mutated_valid": mutated["valid"],
        "disposition_after_mutation": "RUN" if not mutated["valid"] else "REUSE",
        "mutation": "append bytes to one isolated declared input",
    }
