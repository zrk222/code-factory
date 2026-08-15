"""Supervised runtime proof cards for one declared product behavior.

Reality Check deliberately composes the existing proof-by-sabotage E2E runner.
It makes the user-visible promise and its negative case explicit, but it never
invents commands, grants approval, repairs code, or turns one local run into a
production-readiness claim.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

from .e2e_proof import E2EProofError, public_e2e_proof_receipt, validate_e2e_proof_receipt, verify_e2e_proof


REALITY_CHECK_MANIFEST_SCHEMA = "factory.reality-check-manifest.v1"
REALITY_CHECK_RECEIPT_SCHEMA = "factory.reality-check-receipt.v1"
MAX_TEXT = 600
MAX_ASSERTIONS = 16
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_SHA = re.compile(r"^[a-f0-9]{64}$")
AUTHORITY = {
    "execution": True, "test_execution": True, "approval": False, "publication": False,
    "deployment": False, "signing": False, "messaging": False, "credential": False,
    "connector": False, "source_write": False, "repair": False,
}


class RealityCheckError(ValueError):
    """Raised when a Reality Check contract or receipt is malformed."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _reject(code: str, message: str) -> None:
    raise RealityCheckError(code, message)


def _relative_file(root: Path, value: object, field: str) -> tuple[Path, str]:
    if not isinstance(value, str) or not value.strip():
        _reject("REALITY_CHECK_MANIFEST_INVALID", f"{field} must be a non-empty workspace-relative path")
    raw = value.replace("\\", "/").strip()
    if raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw) or ".." in raw.split("/"):
        _reject("REALITY_CHECK_MANIFEST_INVALID", f"{field} must stay inside the workspace")
    path = (root / raw).resolve()
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        _reject("REALITY_CHECK_MANIFEST_INVALID", f"{field} resolves outside the workspace")
    if not path.is_file():
        _reject("REALITY_CHECK_MANIFEST_INVALID", f"{field} must name a readable JSON file")
    return path, relative


def _text(value: object, field: str, *, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > MAX_TEXT:
        _reject("REALITY_CHECK_MANIFEST_INVALID", f"{field} must be a non-empty string of at most {MAX_TEXT} characters")
    result = value.strip()
    if identifier and not _ID.fullmatch(result):
        _reject("REALITY_CHECK_MANIFEST_INVALID", f"{field} has an unsupported format")
    return result


def _load(root: Path, manifest_path: Path) -> tuple[dict[str, Any], str, str]:
    path = Path(manifest_path).resolve()
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        _reject("REALITY_CHECK_MANIFEST_INVALID", "manifest must stay inside the workspace")
    if not path.is_file():
        _reject("REALITY_CHECK_MANIFEST_INVALID", "manifest must name a readable JSON file")
    raw = path.read_bytes()
    try:
        source = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _reject("REALITY_CHECK_MANIFEST_INVALID", f"manifest cannot be decoded as JSON: {exc}")
    if not isinstance(source, dict):
        _reject("REALITY_CHECK_MANIFEST_INVALID", "manifest must contain one JSON object")
    return source, relative, sha256(raw).hexdigest()


def _intent_assertions(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 2 <= len(value) <= MAX_ASSERTIONS:
        _reject("REALITY_CHECK_MANIFEST_INVALID", f"intent_assertions must contain 2 through {MAX_ASSERTIONS} assertions")
    assertions: list[dict[str, str]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict) or set(item) != {"id", "statement", "evidence"}:
            _reject("REALITY_CHECK_MANIFEST_INVALID", f"intent_assertions[{index}] must contain exactly id, statement, and evidence")
        evidence = item.get("evidence")
        if evidence not in {"positive", "negative"}:
            _reject("REALITY_CHECK_MANIFEST_INVALID", f"intent_assertions[{index}].evidence must be positive or negative")
        assertions.append({"id": _text(item.get("id"), f"intent_assertions[{index}].id", identifier=True), "statement": _text(item.get("statement"), f"intent_assertions[{index}].statement"), "evidence": evidence})
    if len({item["id"] for item in assertions}) != len(assertions) or {item["evidence"] for item in assertions} != {"positive", "negative"}:
        _reject("REALITY_CHECK_MANIFEST_INVALID", "intent assertions require unique ids and at least one positive plus one negative assertion")
    return assertions


def validate_reality_check_manifest(root: Path, manifest_path: Path) -> dict[str, Any]:
    """Validate a human-approved, local-only behavioral contract."""
    workspace = Path(root).resolve()
    source, path, digest = _load(workspace, manifest_path)
    required = {"schema", "id", "approval", "behavior", "intent_assertions", "e2e_manifest"}
    if set(source) != required or source.get("schema") != REALITY_CHECK_MANIFEST_SCHEMA:
        _reject("REALITY_CHECK_MANIFEST_INVALID", "manifest must contain exactly schema, id, approval, behavior, intent_assertions, and e2e_manifest")
    approval = source.get("approval")
    if not isinstance(approval, dict) or set(approval) != {"state", "approved_by"}:
        _reject("REALITY_CHECK_MANIFEST_INVALID", "approval must contain exactly state and approved_by")
    if approval.get("state") != "approved":
        _reject("REALITY_CHECK_UNAPPROVED", "approval.state must be approved before the declared checks can run")
    behavior = source.get("behavior")
    if not isinstance(behavior, dict) or set(behavior) != {"promise", "happy_path", "failure_case"}:
        _reject("REALITY_CHECK_MANIFEST_INVALID", "behavior must contain exactly promise, happy_path, and failure_case")
    e2e_path, e2e_relative = _relative_file(workspace, source.get("e2e_manifest"), "e2e_manifest")
    return {
        "schema": REALITY_CHECK_MANIFEST_SCHEMA,
        "id": _text(source.get("id"), "id", identifier=True),
        "approval": {"state": "approved", "approved_by": _text(approval.get("approved_by"), "approval.approved_by")},
        "behavior": {name: _text(behavior.get(name), f"behavior.{name}") for name in ("promise", "happy_path", "failure_case")},
        "intent_assertions": _intent_assertions(source.get("intent_assertions")),
        "e2e_manifest": {"path": e2e_relative, "sha256": sha256(e2e_path.read_bytes()).hexdigest()},
        "manifest_path": path,
        "manifest_sha256": digest,
    }


def inspect_reality_intent(root: Path, manifest_path: Path) -> dict[str, Any]:
    """Validate a behavior's declared positive and negative proof coverage without running commands."""
    manifest = validate_reality_check_manifest(root, manifest_path)
    assertions = manifest["intent_assertions"]
    positive = [item["id"] for item in assertions if item["evidence"] == "positive"]
    negative = [item["id"] for item in assertions if item["evidence"] == "negative"]
    return {
        "schema": "factory.reality-intent-inspection.v1", "marker": "REALITY_INTENT_CONTRACT_READY",
        "manifest": manifest, "assertion_count": len(assertions), "positive_assertion_ids": positive,
        "negative_assertion_ids": negative, "execution": False,
        "scope_limits": ["Inspection validates declared intent-to-evidence coverage only; it does not run commands or establish behavior."],
    }


def _terminal(e2e: dict[str, Any]) -> tuple[str, str, bool]:
    if e2e["marker"] == "E2E_PROOF_PASS":
        return "verified", "REALITY_CHECK_VERIFIED", True
    if e2e["marker"] == "HOLLOW_E2E_TEST":
        return "hollow", "REALITY_CHECK_HOLLOW", False
    return "blocked", "REALITY_CHECK_BLOCKED", False


def _assertion_results(manifest: dict[str, Any], e2e: dict[str, Any]) -> list[dict[str, Any]]:
    verified = e2e["marker"] == "E2E_PROOF_PASS"
    return [{**item, "verified": verified, "e2e_marker": e2e["marker"]} for item in manifest["intent_assertions"]]


def _mermaid(receipt: dict[str, Any]) -> str:
    return "\n".join([
        "flowchart LR", '  P["Declared product promise"] --> H["Approved happy path"]',
        '  F["Declared failure case"] --> N["Negative check"]', '  H --> G["Reality Check"]',
        '  N --> G', f'  G --> R["{receipt["marker"]}"]', '  R --> X["Human release decision remains external"]', "",
    ])


def _markdown(receipt: dict[str, Any]) -> str:
    behavior = receipt["manifest"]["behavior"]
    return "\n".join([
        "# Factory Reality Check", "", f"- Check ID: `{receipt['manifest']['id']}`", f"- Promise: {behavior['promise']}",
        f"- Happy path: {behavior['happy_path']}", f"- Failure case: {behavior['failure_case']}",
        f"- Result: `{receipt['marker']}`", f"- Receipt SHA-256: `{receipt['receipt_sha256']}`", "",
        "This card proves only the declared local command pair and named behavioral contract. It does not establish browser isolation, production coverage, security, or release readiness.", "",
    ])


def run_reality_check(root: Path, manifest_path: Path) -> dict[str, Any]:
    """Run one already-approved E2E pair and bind it to a behavior promise."""
    workspace = Path(root).resolve()
    manifest = validate_reality_check_manifest(workspace, manifest_path)
    try:
        e2e_private = verify_e2e_proof(workspace, workspace / manifest["e2e_manifest"]["path"])
    except E2EProofError as exc:
        _reject(exc.code, str(exc))
    e2e = public_e2e_proof_receipt(e2e_private)
    state, marker, ok = _terminal(e2e)
    core = {
        "schema": REALITY_CHECK_RECEIPT_SCHEMA, "marker": marker, "ok": ok, "run_state": state,
        "manifest": manifest, "e2e_receipt": e2e, "intent_verification": _assertion_results(manifest, e2e), "authority": AUTHORITY,
        "scope_limits": [
            "Reality Check runs only the approved E2E argv pair with shell=False; it does not invent browser actions or commands.",
            "A verified check proves only the declared happy and negative command outcomes plus supplied artifacts.",
            "Reality Check cannot repair source, approve, merge, publish, deploy, sign, message, access credentials, or grant connectors.",
        ],
    }
    receipt = {**core, "receipt_sha256": _sha(core)}
    receipt["mermaid"] = _mermaid(receipt)
    receipt["receipt_markdown"] = _markdown(receipt)
    return receipt


def _receipt_shape(value: object) -> tuple[dict[str, Any], set[str]]:
    if not isinstance(value, dict) or value.get("schema") != REALITY_CHECK_RECEIPT_SCHEMA:
        _reject("REALITY_CHECK_RECEIPT_INVALID", f"a {REALITY_CHECK_RECEIPT_SCHEMA} payload is required")
    required = {"schema", "marker", "ok", "run_state", "manifest", "e2e_receipt", "intent_verification", "authority", "scope_limits", "receipt_sha256", "mermaid", "receipt_markdown"}
    if set(value) != required or value.get("authority") != AUTHORITY:
        _reject("REALITY_CHECK_RECEIPT_INVALID", "receipt has unsupported fields or a changed authority boundary")
    return value, required


def _receipt_manifest(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        _reject("REALITY_CHECK_RECEIPT_INVALID", "receipt manifest must be an object")
    required = {"schema", "id", "approval", "behavior", "intent_assertions", "e2e_manifest", "manifest_path", "manifest_sha256"}
    if set(value) != required or value.get("schema") != REALITY_CHECK_MANIFEST_SCHEMA:
        _reject("REALITY_CHECK_RECEIPT_INVALID", "receipt manifest has unsupported fields")
    approval = value.get("approval")
    behavior = value.get("behavior")
    e2e_manifest = value.get("e2e_manifest")
    if not isinstance(approval, dict) or approval.get("state") != "approved" or set(approval) != {"state", "approved_by"}:
        _reject("REALITY_CHECK_RECEIPT_INVALID", "receipt manifest approval is invalid")
    if not isinstance(behavior, dict) or set(behavior) != {"promise", "happy_path", "failure_case"}:
        _reject("REALITY_CHECK_RECEIPT_INVALID", "receipt manifest behavior is invalid")
    if not isinstance(e2e_manifest, dict) or set(e2e_manifest) != {"path", "sha256"} or not isinstance(e2e_manifest.get("sha256"), str) or not _SHA.fullmatch(e2e_manifest["sha256"]):
        _reject("REALITY_CHECK_RECEIPT_INVALID", "receipt manifest E2E binding is invalid")
    _text(value.get("id"), "receipt manifest id", identifier=True)
    _text(approval.get("approved_by"), "receipt manifest approved_by")
    for field in ("promise", "happy_path", "failure_case"):
        _text(behavior.get(field), f"receipt manifest behavior.{field}")
    _text(e2e_manifest.get("path"), "receipt manifest E2E path")
    _text(value.get("manifest_path"), "receipt manifest path")
    if not isinstance(value.get("manifest_sha256"), str) or not _SHA.fullmatch(value["manifest_sha256"]):
        _reject("REALITY_CHECK_RECEIPT_INVALID", "receipt manifest SHA-256 is invalid")
    _intent_assertions(value.get("intent_assertions"))
    return value


def _receipt_result(value: dict[str, Any]) -> None:
    e2e = validate_e2e_proof_receipt(value["e2e_receipt"])
    state, marker, ok = _terminal(e2e)
    if (value["run_state"], value["marker"], value["ok"]) != (state, marker, ok):
        _reject("REALITY_CHECK_RECEIPT_INVALID", "marker, state, and E2E result are inconsistent")
    if value["intent_verification"] != _assertion_results(_receipt_manifest(value["manifest"]), e2e):
        _reject("REALITY_CHECK_RECEIPT_INVALID", "intent assertion verification does not match the declared E2E result")


def _receipt_hash_and_views(value: dict[str, Any], required: set[str]) -> None:
    core = {key: value[key] for key in required - {"receipt_sha256", "mermaid", "receipt_markdown"}}
    if not isinstance(value["receipt_sha256"], str) or not _SHA.fullmatch(value["receipt_sha256"]) or value["receipt_sha256"] != _sha(core):
        _reject("REALITY_CHECK_RECEIPT_INVALID", "receipt SHA-256 does not match")
    if value["mermaid"] != _mermaid(value) or value["receipt_markdown"] != _markdown(value):
        _reject("REALITY_CHECK_RECEIPT_INVALID", "receipt views do not match receipt facts")


def validate_reality_check_receipt(value: object) -> dict[str, Any]:
    """Validate a hash-bound Reality Check receipt and its deterministic views."""
    receipt, required = _receipt_shape(value)
    _receipt_result(receipt)
    _receipt_hash_and_views(receipt, required)
    return receipt


def write_reality_check_artifacts(receipt: dict[str, Any], out_dir: Path) -> dict[str, str]:
    """Write canonical receipt, Markdown, and Mermaid artifacts below one output directory."""
    receipt = validate_reality_check_receipt(receipt)
    destination = Path(out_dir).resolve(); destination.mkdir(parents=True, exist_ok=True)
    stem = f"reality-check-{receipt['receipt_sha256'][:12]}"
    outputs = {"receipt": destination / f"{stem}.reality.json", "markdown": destination / f"{stem}.md", "mermaid": destination / f"{stem}.mmd"}
    for name, path in outputs.items():
        value = receipt if name == "receipt" else receipt["receipt_markdown"] if name == "markdown" else receipt["mermaid"]
        path.write_bytes(_canonical(value) if name == "receipt" else value.encode("utf-8"))
    return {name: str(path) for name, path in outputs.items()}
