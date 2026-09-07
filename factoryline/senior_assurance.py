"""Four bounded senior-engineering assurance controls for 0.46.3.

The controls in this module are deliberately provider-neutral and zero-authority:
they make a replayable observation, compare a repair against the original
failure, explain why a proof may be reused, and turn a failed receipt into an
actionable briefing.  They do not approve, publish, deploy, sign, or contact
external systems.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .assembly_process import run_cli_detailed
from .runtime_audit_common import (
    MAX_ARTIFACT_BYTES,
    RuntimeAuditError,
    canonical_bytes,
    exact_keys,
    read_stable_json,
    reject_secret_material,
    require_digest,
    require_int,
    require_str,
    sha256_bytes,
)


REPLAY_MANIFEST_SCHEMA = "factory.replay-manifest.v1"
REPLAY_RECEIPT_SCHEMA = "factory.replay-receipt.v1"
REPAIR_SCHEMA = "factory.repair-comparison.v1"
REUSE_REQUEST_SCHEMA = "factory.evidence-reuse-request.v1"
REUSE_RECEIPT_SCHEMA = "factory.evidence-reuse.v1"
BRIEF_SCHEMA = "factory.failure-brief.v1"

MAX_FILES = 1024
MAX_TREE_BYTES = 32 * 1024 * 1024
MAX_PREVIEW = 2048
MAX_ARGV = 64
MAX_ENV = 32
SECRET_NAME = re.compile(r"(?i)(secret|token|password|credential|private[_-]?key|api[_-]?key|authorization)")
IGNORED_TREE_NAMES = {".git", ".factory", "node_modules", "__pycache__", ".pytest_cache"}


class SeniorAssuranceError(ValueError):
    """A bounded input, execution, or evidence-reuse failure."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha(value: object) -> str:
    return sha256_bytes(canonical_bytes(value))


def _write_json(out: Path | None, value: dict[str, Any]) -> dict[str, Any]:
    if out is None:
        return value
    target = Path(out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(canonical_bytes(value))
    return value


def _load_json(path: Path) -> tuple[dict[str, Any], str]:
    try:
        value, digest = read_stable_json(Path(path))
    except RuntimeAuditError as exc:
        raise SeniorAssuranceError(exc.code, exc.message) from exc
    return value, digest


def _inside(root: Path, raw: str, label: str) -> tuple[Path, str]:
    if not isinstance(raw, str) or not raw.strip():
        raise SeniorAssuranceError("E_REPLAY_PATH", f"{label} must be a non-empty path")
    base = Path(root).resolve()
    candidate = (base / raw).resolve() if not Path(raw).is_absolute() else Path(raw).resolve()
    try:
        relative = candidate.relative_to(base)
    except ValueError as exc:
        raise SeniorAssuranceError("E_REPLAY_PATH_ESCAPE", f"{label} escapes the workspace") from exc
    current = base
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise SeniorAssuranceError("E_REPLAY_SYMLINK", f"{label} traverses a symlink: {relative.as_posix()}")
    return candidate, relative.as_posix() or "."


def _file_digest(path: Path, label: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise SeniorAssuranceError("E_REPLAY_INPUT", f"{label} is not a regular file: {path}")
    raw = path.read_bytes()
    if len(raw) > MAX_ARTIFACT_BYTES * 16:
        raise SeniorAssuranceError("E_REPLAY_INPUT_SIZE", f"{label} exceeds the bounded input size")
    return sha256_bytes(raw)


def _paths_intersect(left: str, right: str) -> bool:
    """Match workspace paths by component, including directory/file overlap."""
    def normalize(value: str) -> tuple[str, ...]:
        return tuple(part for part in value.replace("\\", "/").strip("/").split("/") if part and part != ".")
    a, b = normalize(left), normalize(right)
    return bool(a and b) and (a == b or (len(a) < len(b) and b[:len(a)] == a) or (len(b) < len(a) and a[:len(b)] == b))


def _tree_snapshot(source: Path) -> list[dict[str, Any]]:
    if source.is_symlink() or not source.is_dir():
        raise SeniorAssuranceError("E_REPLAY_SOURCE", f"source_root is not a regular directory: {source}")
    rows: list[dict[str, Any]] = []
    total = 0
    for candidate in sorted(source.rglob("*")):
        relative_parts = candidate.relative_to(source).parts
        if any(part in IGNORED_TREE_NAMES for part in relative_parts):
            continue
        if candidate.is_symlink():
            raise SeniorAssuranceError("E_REPLAY_SYMLINK", f"source tree contains a symlink: {candidate}")
        if not candidate.is_file():
            continue
        size = candidate.stat().st_size
        total += size
        if len(rows) >= MAX_FILES or total > MAX_TREE_BYTES:
            raise SeniorAssuranceError("E_REPLAY_SOURCE_LIMIT", "source tree exceeds the bounded file or byte limit")
        rows.append({"path": candidate.relative_to(source).as_posix(), "sha256": _file_digest(candidate, "source file"), "size": int(size)})
    if not rows:
        raise SeniorAssuranceError("E_REPLAY_SOURCE_EMPTY", "source_root must contain at least one regular file")
    return rows


def _source_digest(source: Path) -> tuple[str, list[dict[str, Any]]]:
    rows = _tree_snapshot(source)
    return _sha(rows), rows


def _descriptor_digest(root: Path, value: object, label: str) -> str:
    if isinstance(value, str):
        return require_digest(value, label)
    if not isinstance(value, dict):
        raise SeniorAssuranceError("E_REPLAY_DIGEST", f"{label} must be a digest or descriptor")
    try:
        exact_keys(value, {"sha256"}, {"path"})
        digest = require_digest(value["sha256"], f"{label}.sha256")
    except RuntimeAuditError as exc:
        raise SeniorAssuranceError(exc.code, exc.message) from exc
    if "path" in value:
        path, _ = _inside(root, value["path"], f"{label}.path")
        observed = _file_digest(path, f"{label}.path")
        if observed != digest:
            raise SeniorAssuranceError("E_REPLAY_DIGEST_MISMATCH", f"{label}.path digest does not match")
    return digest


def _validate_env(value: object) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > MAX_ENV:
        raise SeniorAssuranceError("E_REPLAY_ENV", "env must be a bounded mapping")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", key) or SECRET_NAME.search(key):
            raise SeniorAssuranceError("E_REPLAY_SECRET", f"secret-shaped environment name is not allowed: {key}")
        if not isinstance(item, str) or len(item) > 256 or any(ord(char) < 32 for char in item):
            raise SeniorAssuranceError("E_REPLAY_ENV", f"environment value for {key} is invalid")
        if SECRET_NAME.search(item):
            raise SeniorAssuranceError("E_REPLAY_SECRET", f"secret-shaped environment value is not allowed: {key}")
        result[key] = item
    return result


def _validate_argv(value: object) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ARGV:
        raise SeniorAssuranceError("E_REPLAY_ARGV", "argv must contain 1..64 strings")
    if any(not isinstance(item, str) or not item or len(item) > 512 or any(ord(char) < 32 for char in item) for item in value):
        raise SeniorAssuranceError("E_REPLAY_ARGV", "argv contains an invalid item")
    if any(SECRET_NAME.search(item) for item in value):
        raise SeniorAssuranceError("E_REPLAY_SECRET", "argv contains secret-shaped material")
    return list(value)


def validate_replay_manifest(root: Path, value: dict[str, Any]) -> dict[str, Any]:
    """Validate a replay contract and its source/input digests without executing it."""
    try:
        reject_secret_material(value)
        exact_keys(
            value,
            {"schema", "replay_id", "source_root", "source_sha256", "dependencies_sha256", "policy_sha256", "input_files", "argv", "expected_exit", "timeout_seconds", "max_output_bytes", "contract_sha256"},
            {"env", "description", "authority", "marker", "dependencies", "policy"},
        )
        if value.get("schema") != REPLAY_MANIFEST_SCHEMA:
            raise RuntimeAuditError("E_REPLAY_SCHEMA", "schema must be factory.replay-manifest.v1")
        replay_id = require_str(value["replay_id"], "replay_id", maximum=128)
        source, source_root = _inside(root, value["source_root"], "source_root")
        source_sha256 = require_digest(value["source_sha256"], "source_sha256")
        dependencies_sha256 = _descriptor_digest(root, value["dependencies_sha256"], "dependencies_sha256")
        policy_sha256 = _descriptor_digest(root, value["policy_sha256"], "policy_sha256")
        input_files = value["input_files"]
        if not isinstance(input_files, list) or len(input_files) > MAX_FILES:
            raise RuntimeAuditError("E_REPLAY_INPUT", "input_files must be a bounded list")
        inputs: list[dict[str, Any]] = []
        for index, item in enumerate(input_files):
            if not isinstance(item, dict):
                raise RuntimeAuditError("E_REPLAY_INPUT", f"input_files[{index}] must be an object")
            exact_keys(item, {"path", "sha256"})
            path, relative = _inside(root, item["path"], f"input_files[{index}].path")
            digest = require_digest(item["sha256"], f"input_files[{index}].sha256")
            observed = _file_digest(path, f"input_files[{index}]")
            if observed != digest:
                raise RuntimeAuditError("E_REPLAY_DIGEST_MISMATCH", f"input_files[{index}] digest does not match")
            inputs.append({"path": relative, "sha256": digest})
        argv = _validate_argv(value["argv"])
        env = _validate_env(value.get("env"))
        expected_exit = require_int(value["expected_exit"], "expected_exit", minimum=-255, maximum=255)
        timeout_seconds = require_int(value["timeout_seconds"], "timeout_seconds", minimum=1, maximum=300)
        max_output_bytes = require_int(value["max_output_bytes"], "max_output_bytes", minimum=1, maximum=1_048_576)
        contract_sha256 = require_digest(value["contract_sha256"], "contract_sha256")
    except RuntimeAuditError as exc:
        raise SeniorAssuranceError(exc.code, exc.message) from exc
    observed_source_sha256, _ = _source_digest(source)
    if observed_source_sha256 != source_sha256:
        raise SeniorAssuranceError("E_REPLAY_SOURCE_CHANGED", "source_sha256 does not match source_root")
    return {
        "schema": REPLAY_MANIFEST_SCHEMA,
        "replay_id": replay_id,
        "source_root": source_root,
        "source_sha256": source_sha256,
        "dependencies_sha256": dependencies_sha256,
        "policy_sha256": policy_sha256,
        "input_files": sorted(inputs, key=lambda item: item["path"]),
        "argv": argv,
        "env": env,
        "expected_exit": expected_exit,
        "timeout_seconds": timeout_seconds,
        "max_output_bytes": max_output_bytes,
        "contract_sha256": contract_sha256,
    }


def _copy_source(source: Path, destination: Path) -> None:
    def ignore(_directory: str, names: list[str]) -> set[str]:
        return {name for name in names if name in IGNORED_TREE_NAMES}

    shutil.copytree(source, destination, copy_function=shutil.copy2, ignore=ignore)


def _process_environment(normalized: dict[str, Any]) -> dict[str, str]:
    """Build a minimal declared environment without reading the parent environment."""
    executable = shutil.which(normalized["argv"][0])
    path = str(Path(executable).parent) if executable else ""
    result = {"PATH": path, "SystemRoot": "C:\\Windows", "WINDIR": "C:\\Windows", "TEMP": "", "TMP": "", "PYTHONIOENCODING": "utf-8"}
    result.update(normalized["env"])
    return result


def _capture_process(source: Path, normalized: dict[str, Any]) -> dict[str, Any]:
    """Run a bounded argv in a copied workspace and normalize its observations."""
    started = time.monotonic()
    outcome: dict[str, Any] = {"timed_out": False, "observed_exit": None, "stdout": b"", "stderr": b"", "cleanup": False, "failure_reason": None}
    try:
        with tempfile.TemporaryDirectory(prefix="factory-replay-") as temporary:
            sandbox_root = Path(temporary) / "workspace"
            _copy_source(source, sandbox_root)
            result = run_cli_detailed(
                normalized["argv"][0], normalized["argv"][1:], sandbox_root,
                env=_process_environment(normalized),
                timeout=normalized["timeout_seconds"],
                max_stream_bytes=normalized["max_output_bytes"],
            )
            outcome.update({
                "observed_exit": result.get("exit_code"),
                "stdout": result.get("stdout", b"")[: normalized["max_output_bytes"]],
                "stderr": result.get("stderr", b"")[: normalized["max_output_bytes"]],
                "cleanup": bool(result.get("cleanup_confirmed")) and bool(result.get("streams_closed")),
            })
            reason = str(result.get("reason") or "")
            if reason == "stage timed out":
                outcome.update({"timed_out": True, "failure_reason": "TIMEOUT"})
            elif reason:
                outcome["failure_reason"] = reason.upper().replace(" ", "_")
            elif not result.get("ok") and outcome["observed_exit"] is None:
                outcome["failure_reason"] = "EXECUTION_ERROR:LAUNCH_FAILED"
        outcome["cleanup"] = bool(outcome["cleanup"])
    except OSError as exc:
        outcome.update({"failure_reason": f"EXECUTION_ERROR:{type(exc).__name__}", "cleanup": True})
    outcome["duration_ms"] = max(0, int((time.monotonic() - started) * 1000))
    if outcome["failure_reason"] is None and not outcome["timed_out"] and outcome["observed_exit"] != normalized["expected_exit"]:
        outcome["failure_reason"] = f"EXIT_MISMATCH:expected={normalized['expected_exit']}:observed={outcome['observed_exit']}"
    outcome["state"] = "PASS" if outcome["failure_reason"] is None and outcome["cleanup"] else "FAIL"
    return outcome


def _bounded_output(value: object) -> bytes:
    if isinstance(value, bytes):
        return value[:MAX_PREVIEW]
    return str(value or "").encode("utf-8")[:MAX_PREVIEW]


def _verify_replay_inputs(root: Path, source: Path, normalized: dict[str, Any]) -> None:
    source_after, _ = _source_digest(source)
    if source_after != normalized["source_sha256"]:
        raise SeniorAssuranceError("E_REPLAY_SOURCE_CHANGED", "source changed during replay")
    for item in normalized["input_files"]:
        path = root / item["path"]
        if _file_digest(path, "input") != item["sha256"]:
            raise SeniorAssuranceError("E_REPLAY_INPUT_CHANGED", f"input changed during replay: {item['path']}")


def _replay_base(normalized: dict[str, Any]) -> dict[str, Any]:
    return {"schema": REPLAY_RECEIPT_SCHEMA, "marker": "REPLAY_SOURCE_AND_POLICY_BOUND", "replay_id": normalized["replay_id"], "source_root": normalized["source_root"], "source_sha256": normalized["source_sha256"], "dependencies_sha256": normalized["dependencies_sha256"], "policy_sha256": normalized["policy_sha256"], "input_files": normalized["input_files"], "argv": normalized["argv"], "argv_sha256": _sha(normalized["argv"]), "contract_sha256": normalized["contract_sha256"], "expected_exit": normalized["expected_exit"], "isolation": "fresh_temporary_workspace_and_process", "sandbox_boundary": "process_boundary_only; no_kernel_or_container_claim", "authority": "none", "release_approval": False, "created_at": _now()}


def run_replay(root: Path, manifest: dict[str, Any], *, execute: bool = False, out: Path | None = None) -> dict[str, Any]:
    """Reproduce one candidate in a fresh temporary process workspace.

    This is a bounded process/workspace isolation boundary, not a kernel or
    container sandbox, and the candidate receives no signing credentials.
    """
    root = Path(root).resolve()
    normalized = validate_replay_manifest(root, manifest)
    source = root / normalized["source_root"]
    base = _replay_base(normalized)
    if not execute:
        receipt = {**base, "state": "PLAN_ONLY", "executed": False, "cleanup": None, "timed_out": None, "observed_exit": None, "stdout_sha256": None, "stderr_sha256": None, "stdout_preview": "", "stderr_preview": "", "duration_ms": None, "failure_reason": None, "reproducer": {"argv": normalized["argv"], "cwd": normalized["source_root"]}}
        receipt["receipt_sha256"] = _sha(receipt)
        return _write_json(out, receipt)
    outcome = _capture_process(source, normalized)
    _verify_replay_inputs(root, source, normalized)
    receipt = {**base, "executed": True, "state": outcome["state"], "cleanup": outcome["cleanup"], "timed_out": outcome["timed_out"], "observed_exit": outcome["observed_exit"], "stdout_sha256": sha256_bytes(outcome["stdout"]), "stderr_sha256": sha256_bytes(outcome["stderr"]), "stdout_preview": outcome["stdout"].decode("utf-8", errors="replace")[:MAX_PREVIEW], "stderr_preview": outcome["stderr"].decode("utf-8", errors="replace")[:MAX_PREVIEW], "duration_ms": outcome["duration_ms"], "failure_reason": outcome["failure_reason"], "reproducer": {"argv": normalized["argv"], "cwd": normalized["source_root"], "contract_sha256": normalized["contract_sha256"]}}
    receipt["receipt_sha256"] = _sha(receipt)
    return _write_json(out, receipt)


def _validate_repair_manifest(root: Path, value: dict[str, Any]) -> dict[str, Any]:
    try:
        reject_secret_material(value)
        exact_keys(value, {"schema", "comparison_id", "contract_sha256", "buggy", "fixed", "negative_controls"}, {"expectations_changed", "review", "description", "authority"})
        if value.get("schema") != REPAIR_SCHEMA:
            raise RuntimeAuditError("E_REPAIR_SCHEMA", "schema must be factory.repair-comparison.v1")
        comparison_id = require_str(value["comparison_id"], "comparison_id", maximum=128)
        contract_sha256 = require_digest(value["contract_sha256"], "contract_sha256")
        negative_controls = value["negative_controls"]
        if not isinstance(negative_controls, list) or not 1 <= len(negative_controls) <= 32:
            raise RuntimeAuditError("E_REPAIR_CONTROLS", "negative_controls must contain 1..32 manifests")
    except RuntimeAuditError as exc:
        raise SeniorAssuranceError(exc.code, exc.message) from exc
    manifests = {"buggy": validate_replay_manifest(root, value["buggy"]), "fixed": validate_replay_manifest(root, value["fixed"])}
    manifests["negative_controls"] = [validate_replay_manifest(root, item) for item in negative_controls]
    if manifests["buggy"]["contract_sha256"] != contract_sha256 or manifests["fixed"]["contract_sha256"] != contract_sha256 or any(item["contract_sha256"] != contract_sha256 for item in manifests["negative_controls"]):
        raise SeniorAssuranceError("E_REPAIR_CONTRACT", "all replay manifests must bind the same approved contract")
    if manifests["buggy"]["source_sha256"] == manifests["fixed"]["source_sha256"]:
        raise SeniorAssuranceError("E_REPAIR_NO_CHANGE", "fixed candidate must differ from the original source")
    if manifests["buggy"]["expected_exit"] == 0 or manifests["fixed"]["expected_exit"] != 0 or any(item["expected_exit"] == 0 for item in manifests["negative_controls"]):
        raise SeniorAssuranceError("E_REPAIR_EXPECTATIONS", "buggy and negative controls must fail while fixed must pass")
    changed = value.get("expectations_changed", False)
    if not isinstance(changed, bool):
        raise SeniorAssuranceError("E_REPAIR_REVIEW", "expectations_changed must be boolean")
    review = value.get("review")
    if changed:
        if not isinstance(review, dict) or review.get("approved") is not True or not isinstance(review.get("reviewer"), str) or not isinstance(review.get("reason"), str) or not review["reason"].strip():
            raise SeniorAssuranceError("E_EXPECTATION_REVIEW_REQUIRED", "changed expectations require an approving reviewer and reason")
    return {"schema": REPAIR_SCHEMA, "comparison_id": comparison_id, "contract_sha256": contract_sha256, "manifests": manifests, "expectations_changed": changed, "review": review}


def compare_repair(root: Path, manifest: dict[str, Any], *, execute: bool = False, out: Path | None = None) -> dict[str, Any]:
    """Compare original failure, proposed repair, and negative controls together."""
    normalized = _validate_repair_manifest(Path(root).resolve(), manifest)
    ids = {key: item["replay_id"] for key, item in normalized["manifests"].items() if isinstance(item, dict) and "replay_id" in item}
    base = {"schema": REPAIR_SCHEMA, "marker": "REPAIR_COMPARISON_SEALED", "comparison_id": normalized["comparison_id"], "contract_sha256": normalized["contract_sha256"], "expectations_changed": normalized["expectations_changed"], "review": normalized["review"], "authority": "none", "release_approval": False, "created_at": _now()}
    if not execute:
        receipt = {**base, "state": "PLAN_ONLY", "executed": False, "replays": ids, "original_failure_required": True, "negative_controls_required": len(normalized["manifests"]["negative_controls"])}
        receipt["receipt_sha256"] = _sha(receipt)
        return _write_json(out, receipt)
    buggy = run_replay(root, normalized["manifests"]["buggy"], execute=True)
    fixed = run_replay(root, normalized["manifests"]["fixed"], execute=True)
    controls = [run_replay(root, item, execute=True) for item in normalized["manifests"]["negative_controls"]]
    passed = buggy["state"] == "PASS" and fixed["state"] == "PASS" and all(item["state"] == "PASS" for item in controls)
    findings: list[dict[str, Any]] = []
    if buggy["observed_exit"] == buggy["expected_exit"] == 0:
        findings.append({"id": "ORIGINAL_DID_NOT_FAIL", "summary": "original candidate did not reproduce the expected failure", "evidence": buggy["receipt_sha256"]})
    if fixed["state"] != "PASS":
        findings.append({"id": "REPAIR_DID_NOT_PASS", "summary": "proposed repair did not satisfy the approved expectation", "evidence": fixed["receipt_sha256"]})
    for item in controls:
        if item["state"] != "PASS":
            findings.append({"id": "NEGATIVE_CONTROL_WEAKENED", "summary": "a negative control no longer fails as expected", "evidence": item["receipt_sha256"]})
    receipt = {**base, "state": "PASS" if passed else "FAIL", "executed": True, "original": buggy, "repaired": fixed, "negative_controls": controls, "findings": findings, "regression_checks": {"original_fails": buggy["state"] == "PASS", "repaired_passes": fixed["state"] == "PASS", "negative_controls_fail": all(item["state"] == "PASS" for item in controls)}}
    receipt["receipt_sha256"] = _sha(receipt)
    return _write_json(out, receipt)


def _fingerprint(value: object) -> str | None:
    if value is None:
        return None
    return _sha(value)


def _reuse_gate(root: Path, gate: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    gate_id = require_str(gate.get("id"), "gate.id", maximum=128)
    read_only = gate.get("read_only")
    side_effects = gate.get("side_effects", False)
    if not isinstance(read_only, bool) or not isinstance(side_effects, bool):
        raise SeniorAssuranceError("E_REUSE_GATE", f"{gate_id} must declare read_only and side_effects")
    explanation: dict[str, Any] = {"gate": gate_id, "decision": "RUN", "reason": "EVIDENCE_NOT_EXACT", "unknown_inputs": [], "compared": {}}
    if side_effects or not read_only:
        explanation.update({"decision": "BLOCK", "reason": "SIDE_EFFECT_REUSE_REFUSED"})
        return explanation
    receipt_path_raw = gate.get("receipt_path")
    if not isinstance(receipt_path_raw, str) or not receipt_path_raw.strip():
        explanation["unknown_inputs"].append("receipt_path")
        explanation["reason"] = "UNKNOWN_INPUT_REQUIRES_EXECUTION"
        return explanation
    receipt_path, relative = _inside(root, receipt_path_raw, f"{gate_id}.receipt_path")
    if not receipt_path.is_file():
        explanation.update({"reason": "RECEIPT_MISSING", "receipt_path": relative})
        return explanation
    try:
        receipt, observed_file_sha = _load_json(receipt_path)
    except SeniorAssuranceError:
        explanation.update({"reason": "RECEIPT_UNREADABLE", "receipt_path": relative})
        return explanation
    explanation["receipt_path"] = relative
    explanation["receipt_sha256"] = observed_file_sha
    if gate.get("receipt_sha256") != observed_file_sha:
        explanation.update({"reason": "RECEIPT_DIGEST_MISMATCH"})
        return explanation
    if receipt.get("status") != "green" or receipt.get("read_only") is not True:
        explanation.update({"reason": "RECEIPT_NOT_GREEN_READ_ONLY"})
        return explanation
    required_facts = {"policy_sha256": request.get("policy_sha256"), "dependencies_sha256": request.get("dependencies_sha256"), "toolchain": gate.get("toolchain"), "environment": gate.get("environment")}
    for field, expected in required_facts.items():
        observed = receipt.get(field)
        explanation["compared"][field] = {"expected": expected, "observed": observed}
        if expected is None or observed is None:
            explanation["unknown_inputs"].append(field)
        elif field.endswith("_sha256") and expected != observed:
            explanation["reason"] = "FINGERPRINT_MISMATCH"
            return explanation
        elif field in {"toolchain", "environment"} and _fingerprint(expected) != _fingerprint(observed):
            explanation["reason"] = "FINGERPRINT_MISMATCH"
            return explanation
    if explanation["unknown_inputs"]:
        explanation["reason"] = "UNKNOWN_INPUT_REQUIRES_EXECUTION"
        return explanation
    changed = request.get("changed_paths", [])
    receipt_inputs = receipt.get("inputs", [])
    input_paths = {item.get("path") for item in receipt_inputs if isinstance(item, dict) and isinstance(item.get("path"), str)}
    if isinstance(changed, list) and any(_paths_intersect(path, input_path) for path in changed if isinstance(path, str) for input_path in input_paths):
        explanation.update({"reason": "CHANGED_INPUT_REQUIRES_EXECUTION"})
        return explanation
    explanation.update({"decision": "REUSE", "reason": "EXACT_EVIDENCE_REUSED"})
    return explanation


def explain_evidence_reuse(root: Path, manifest: dict[str, Any], *, out: Path | None = None) -> dict[str, Any]:
    """Explain RUN/REUSE/BLOCK using policy, dependency, toolchain, and environment fingerprints."""
    try:
        reject_secret_material(manifest)
        exact_keys(manifest, {"schema", "request_id", "policy_sha256", "dependencies_sha256", "gates"}, {"changed_paths", "toolchain", "environment", "authority"})
        if manifest.get("schema") != REUSE_REQUEST_SCHEMA:
            raise RuntimeAuditError("E_REUSE_SCHEMA", "schema must be factory.evidence-reuse-request.v1")
        request_id = require_str(manifest["request_id"], "request_id", maximum=128)
        policy_sha256 = require_digest(manifest["policy_sha256"], "policy_sha256")
        dependencies_sha256 = require_digest(manifest["dependencies_sha256"], "dependencies_sha256")
    except RuntimeAuditError as exc:
        raise SeniorAssuranceError(exc.code, exc.message) from exc
    gates = manifest["gates"]
    if not isinstance(gates, list) or not 1 <= len(gates) <= 256:
        raise SeniorAssuranceError("E_REUSE_GATES", "gates must contain 1..256 items")
    explanations = [_reuse_gate(Path(root).resolve(), gate, {**manifest, "policy_sha256": policy_sha256, "dependencies_sha256": dependencies_sha256}) for gate in gates]
    receipt = {"schema": REUSE_RECEIPT_SCHEMA, "marker": "EVIDENCE_REUSE_EXPLAINED", "request_id": request_id, "policy_sha256": policy_sha256, "dependencies_sha256": dependencies_sha256, "changed_paths": manifest.get("changed_paths", []), "gates": explanations, "counts": {"RUN": sum(item["decision"] == "RUN" for item in explanations), "REUSE": sum(item["decision"] == "REUSE" for item in explanations), "BLOCK": sum(item["decision"] == "BLOCK" for item in explanations)}, "authority": "none", "release_approval": False, "created_at": _now()}
    receipt["receipt_sha256"] = _sha(receipt)
    return _write_json(out, receipt)


def _brief_findings(receipt: dict[str, Any], evidence_ref: str | None) -> list[dict[str, Any]]:
    findings = receipt.get("findings") if isinstance(receipt.get("findings"), list) else []
    if not findings and receipt.get("failure_reason"):
        findings = [{"id": "REPLAY_FAILURE", "summary": str(receipt["failure_reason"]), "evidence": receipt.get("receipt_sha256")}]
    if not findings and receipt.get("state", receipt.get("decision")) in {"FAIL", "BLOCKED", "MISMATCH", "INVALID"}:
        findings = [{"id": "FAILED_RECEIPT", "summary": f"receipt decision is {receipt.get('state', receipt.get('decision', 'UNKNOWN'))}", "evidence": receipt.get("receipt_sha256")}]
    rows = []
    for index, item in enumerate(findings):
        if isinstance(item, dict):
            rows.append({"id": item.get("id", f"finding-{index + 1}"), "summary": item.get("summary", item.get("message", "unspecified finding")), "evidence": item.get("evidence") or evidence_ref})
        else:
            rows.append({"id": f"finding-{index + 1}", "summary": str(item), "evidence": evidence_ref})
    return rows


def _brief_uncertainty(receipt: dict[str, Any], reproducer: dict[str, Any]) -> list[str]:
    uncertainty: list[str] = []
    if not receipt.get("owners") and not receipt.get("owner"):
        uncertainty.append("owner was not supplied")
    if not receipt.get("impact") and not receipt.get("affected_components") and not receipt.get("affected"):
        uncertainty.append("business or user impact was not supplied")
    if not isinstance(reproducer.get("argv"), list) or not reproducer.get("argv"):
        uncertainty.append("runnable reproducer was not supplied")
    return uncertainty


def _brief_evidence(receipt_path: str | None, evidence_ref: str | None) -> list[dict[str, Any]]:
    if evidence_ref:
        return [{"receipt_sha256": evidence_ref, "receipt_path": receipt_path, "pointer": "/"}]
    return [{"receipt_sha256": None, "receipt_path": receipt_path, "pointer": "/", "uncertain": True}]


def _brief_affected(receipt: dict[str, Any], source_root: str | None) -> Any:
    return receipt.get("affected_components") or receipt.get("affected") or ([source_root] if source_root else ["unknown component; impact scope was not supplied"])


def failure_brief(receipt: dict[str, Any], *, receipt_path: str | None = None, receipt_sha256: str | None = None, out: Path | None = None) -> dict[str, Any]:
    """Create a concise, evidence-linked failure briefing without guessing ownership."""
    if not isinstance(receipt, dict):
        raise SeniorAssuranceError("E_BRIEF_INPUT", "receipt must be an object")
    decision = receipt.get("state", receipt.get("decision", "UNKNOWN"))
    failed = bool(decision in {"FAIL", "BLOCKED", "MISMATCH", "INVALID"} or receipt.get("failure_reason"))
    evidence_ref = receipt_sha256 or receipt.get("receipt_sha256")
    findings = _brief_findings(receipt, evidence_ref)
    evidence = _brief_evidence(receipt_path, evidence_ref)
    what_broke = findings or [{"id": "NONE", "summary": "no failure finding was declared", "evidence": evidence_ref}]
    source_root = receipt.get("source_root") or receipt.get("original", {}).get("source_root")
    affected = _brief_affected(receipt, source_root)
    reproducer = receipt.get("reproducer") if isinstance(receipt.get("reproducer"), dict) else {"argv": receipt.get("argv"), "cwd": source_root}
    next_fix = receipt.get("next_fix") or receipt.get("next_action") or "Inspect the linked evidence, propose a bounded repair, then run the repair comparison with negative controls."
    uncertainty = _brief_uncertainty(receipt, reproducer)
    brief = {"schema": BRIEF_SCHEMA, "marker": "FAILURE_BRIEF_EVIDENCE_LINKED", "state": "ACTION_REQUIRED" if failed else "NO_FAILURE_DECLARED", "what_broke": what_broke, "affected": affected, "reproduce": reproducer, "next_fix": next_fix, "uncertainty": uncertainty, "evidence": evidence, "authority": "none", "release_approval": False, "created_at": _now()}
    brief["brief_sha256"] = _sha(brief)
    return _write_json(out, brief)


def load_assurance_json(path: Path) -> dict[str, Any]:
    """Load one bounded JSON object for senior-assurance CLI commands."""
    value, _ = _load_json(Path(path))
    return value
