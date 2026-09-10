"""Evidence-bound full-stack engineering and ethical UX release review."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import tempfile
from pathlib import Path, PureWindowsPath
from typing import Any


MANIFEST_SCHEMA = "factory.full-stack-ux-harness.manifest.v1"
RECEIPT_SCHEMA = "factory.full-stack-ux-harness.receipt.v1"
MAX_MANIFEST_BYTES = 1_048_576
MAX_EVIDENCE_BYTES = 10_000_000
APPROVED_PROVENANCE = frozenset({"human_confirmed", "trusted_source", "observed_production"})

CORE_CHECKS = (
    "architecture.separation_of_concerns",
    "contracts.strict_types_and_boundary_validation",
    "states.loading_empty_partial_error_recovery",
    "state.deterministic_locality",
    "performance.render_and_compute_efficiency",
    "performance.resource_loading",
    "security.no_hardcoded_secrets",
    "security.input_output_safety",
    "security.origin_and_content_policy",
    "privacy.data_minimization",
    "testing.main_journey_and_negative_states",
    "release.native_test_lint_build",
)

UI_CHECKS = (
    "ui.responsive_layout",
    "ui.keyboard_navigation",
    "ui.screen_reader_semantics",
    "ui.wcag_contrast",
    "ui.immediate_honest_feedback",
    "ui.visual_system_consistency",
    "ui.claims_and_signals_truth",
)

JUDGMENTS = (
    "truth",
    "regret",
    "transparency",
    "alignment",
    "comprehension",
    "vulnerability",
)


class FullStackUXHarnessError(ValueError):
    """Stable refusal for a malformed or unsafe quality-harness input."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        unexpected = sorted(actual - expected)
        missing = sorted(expected - actual)
        raise FullStackUXHarnessError(
            "E_UX_MANIFEST_SCHEMA",
            f"{label} keys must be exact; missing={missing}, unexpected={unexpected}",
        )


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def quality_harness_template(*, ui_in_scope: bool) -> dict[str, Any]:
    """Return the closed manifest shape without claiming that any check passed."""
    check_ids = [*CORE_CHECKS, *UI_CHECKS] if ui_in_scope else list(CORE_CHECKS)
    return {
        "schema": MANIFEST_SCHEMA,
        "ui_in_scope": ui_in_scope,
        "checks": [
            {"id": check_id, "state": "unknown", "provenance": "agent_proposed", "evidence": []}
            for check_id in check_ids
        ],
        "reviewer": {"name": "", "type": "unassigned"},
        "judgments": [
            {"id": judgment_id, "approved": False, "rationale": ""}
            for judgment_id in JUDGMENTS
        ],
    }


def write_quality_harness_template(root: Path, out: Path, *, ui_in_scope: bool) -> dict[str, Any]:
    """Write one template inside the workspace without overwriting existing work."""
    workspace = Path(root).resolve()
    destination = Path(out) if Path(out).is_absolute() else workspace / out
    destination = destination.resolve()
    try:
        destination.relative_to(workspace)
    except ValueError as exc:
        raise FullStackUXHarnessError("E_UX_MANIFEST_PATH", "template must stay inside the workspace") from exc
    if destination.exists():
        raise FullStackUXHarnessError("E_UX_MANIFEST_EXISTS", f"refusing to replace {destination}")
    payload = quality_harness_template(ui_in_scope=ui_in_scope)
    _atomic_json(destination, payload)
    return {**payload, "path": str(destination)}


def _load_manifest(root: Path, path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    workspace = root.resolve()
    source = path if path.is_absolute() else workspace / path
    source = source.resolve()
    try:
        relative = source.relative_to(workspace)
    except ValueError as exc:
        raise FullStackUXHarnessError("E_UX_MANIFEST_PATH", "manifest must stay inside the workspace") from exc
    try:
        data = source.read_bytes()
    except OSError as exc:
        raise FullStackUXHarnessError("E_UX_MANIFEST_MISSING", f"cannot read manifest: {relative.as_posix()}") from exc
    if not data or len(data) > MAX_MANIFEST_BYTES:
        raise FullStackUXHarnessError("E_UX_MANIFEST_SIZE", f"manifest must contain 1 to {MAX_MANIFEST_BYTES} bytes")
    try:
        value = json.loads(data.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise FullStackUXHarnessError("E_UX_MANIFEST_JSON", "manifest must be valid UTF-8 JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != MANIFEST_SCHEMA:
        raise FullStackUXHarnessError("E_UX_MANIFEST_SCHEMA", f"manifest must use {MANIFEST_SCHEMA}")
    _require_exact_keys(value, {"schema", "ui_in_scope", "checks", "reviewer", "judgments"}, "manifest")
    return value, {"path": relative.as_posix(), "sha256": _sha(data), "bytes": len(data)}


def _evidence_binding(root: Path, value: object, check_id: str) -> dict[str, Any]:
    if not isinstance(value, str) or not value.strip():
        raise FullStackUXHarnessError("E_UX_EVIDENCE_PATH", f"{check_id} evidence must be a relative path")
    relative = Path(value)
    if relative.is_absolute() or PureWindowsPath(value).drive or ".." in relative.parts:
        raise FullStackUXHarnessError("E_UX_EVIDENCE_PATH", f"{check_id} evidence must stay inside the workspace")
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise FullStackUXHarnessError("E_UX_EVIDENCE_PATH", f"{check_id} evidence escapes the workspace") from exc
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise FullStackUXHarnessError("E_UX_EVIDENCE_MISSING", f"{check_id} evidence is missing: {relative.as_posix()}") from exc
    if not data or len(data) > MAX_EVIDENCE_BYTES:
        raise FullStackUXHarnessError("E_UX_EVIDENCE_SIZE", f"{check_id} evidence must contain 1 to {MAX_EVIDENCE_BYTES} bytes")
    return {"path": relative.as_posix(), "sha256": _sha(data), "bytes": len(data)}


def _check_findings(root: Path, manifest: dict[str, Any]) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    findings: list[dict[str, str]] = []
    checks = manifest.get("checks")
    ui_in_scope = manifest.get("ui_in_scope")
    if not isinstance(ui_in_scope, bool) or not isinstance(checks, list):
        raise FullStackUXHarnessError("E_UX_MANIFEST_SCHEMA", "ui_in_scope must be boolean and checks must be an array")
    expected = set(CORE_CHECKS) | (set(UI_CHECKS) if ui_in_scope else set())
    ids = [item.get("id") for item in checks if isinstance(item, dict)]
    if len(checks) != len(expected) or len(ids) != len(checks) or set(ids) != expected or len(set(ids)) != len(ids):
        findings.append({"code": "E_UX_CHECK_SET_MISMATCH", "detail": f"expected exactly {len(expected)} closed check identifiers"})
        return findings, []
    bound_checks: list[dict[str, Any]] = []
    for item in sorted(checks, key=lambda candidate: candidate["id"]):
        _require_exact_keys(item, {"id", "state", "provenance", "evidence"}, f"check {item['id']}")
        check_id = item["id"]
        state, provenance, evidence = item.get("state"), item.get("provenance"), item.get("evidence")
        if state != "passed":
            findings.append({"code": "E_UX_CHECK_NOT_PASSED", "detail": check_id})
        if provenance not in APPROVED_PROVENANCE:
            findings.append({"code": "E_UX_CHECK_PROVENANCE", "detail": check_id})
        if not isinstance(evidence, list) or not 1 <= len(evidence) <= 16:
            findings.append({"code": "E_UX_CHECK_EVIDENCE_INCOMPLETE", "detail": check_id})
            bindings = []
        else:
            string_evidence = [path for path in evidence if isinstance(path, str)]
            if len(set(string_evidence)) != len(string_evidence):
                findings.append({"code": "E_UX_CHECK_EVIDENCE_DUPLICATE", "detail": check_id})
            bindings = [_evidence_binding(root, path, check_id) for path in evidence]
        bound_checks.append({"id": check_id, "state": state, "provenance": provenance, "evidence": bindings})
    return findings, bound_checks


def _judgment_findings(manifest: dict[str, Any]) -> tuple[list[dict[str, str]], dict[str, Any]]:
    findings: list[dict[str, str]] = []
    reviewer, judgments = manifest.get("reviewer"), manifest.get("judgments")
    if not isinstance(reviewer, dict) or not isinstance(judgments, list):
        raise FullStackUXHarnessError("E_UX_MANIFEST_SCHEMA", "reviewer and judgments are required")
    _require_exact_keys(reviewer, {"name", "type"}, "reviewer")
    name = reviewer.get("name")
    reviewer_type = reviewer.get("type")
    ids = [item.get("id") for item in judgments if isinstance(item, dict)]
    if not isinstance(name, str) or not name.strip() or reviewer_type != "human":
        findings.append({"code": "E_UX_HUMAN_REVIEW_REQUIRED", "detail": "one named human reviewer is required"})
    if len(judgments) != len(JUDGMENTS) or len(ids) != len(judgments) or set(ids) != set(JUDGMENTS) or len(set(ids)) != len(ids):
        findings.append({"code": "E_UX_JUDGMENT_SET_MISMATCH", "detail": "exactly six closed judgments are required"})
        return findings, {"name": name if isinstance(name, str) else "", "type": reviewer_type, "judgments": []}
    normalized = []
    for item in sorted(judgments, key=lambda candidate: candidate["id"]):
        _require_exact_keys(item, {"id", "approved", "rationale"}, f"judgment {item['id']}")
        rationale = item.get("rationale")
        approved = item.get("approved") is True
        if not approved or not isinstance(rationale, str) or not 12 <= len(rationale.strip()) <= 1000:
            findings.append({"code": "E_UX_HUMAN_REVIEW_REQUIRED", "detail": item["id"]})
        normalized.append({"id": item["id"], "approved": approved, "rationale": rationale.strip() if isinstance(rationale, str) else ""})
    return findings, {"name": name.strip() if isinstance(name, str) else "", "type": reviewer_type, "judgments": normalized}


def verify_quality_harness(root: Path, manifest_path: Path, *, out: Path | None = None) -> dict[str, Any]:
    """Verify declared evidence and human judgment; never execute checks or release work."""
    workspace = Path(root).resolve()
    manifest_input = Path(manifest_path)
    manifest_source = (manifest_input if manifest_input.is_absolute() else workspace / manifest_input).resolve()
    manifest, source = _load_manifest(workspace, manifest_input)
    check_findings, checks = _check_findings(workspace, manifest)
    judgment_findings, review = _judgment_findings(manifest)
    findings = [*check_findings, *judgment_findings]
    decision = "READY_FOR_HUMAN_RELEASE_REVIEW" if not findings else "BLOCKED"
    core = {
        "schema": RECEIPT_SCHEMA,
        "source": source,
        "ui_in_scope": manifest.get("ui_in_scope"),
        "decision": decision,
        "checks": checks,
        "review": review,
        "findings": findings,
        "evidence_classes": {
            "deterministic": "file presence, byte size, digest, closed check set, state, and provenance",
            "heuristic": "six named human interaction judgments with recorded rationale",
        },
        "review_identity": {
            "authenticated": False,
            "boundary": "The local reviewer name and type are declared metadata, not authenticated identity.",
        },
        "authority": {
            "execution": False,
            "source_modification": False,
            "approval": False,
            "deployment": False,
            "publication": False,
            "signing": False,
            "credential_access": False,
            "provider_access": False,
            "connector_access": False,
            "messaging": False,
        },
        "claim_boundary": "Local evidence binding plus declared human judgment is not authenticated identity, certification, or measured accessibility, security, conversion, or production-fitness proof. Run the named native tools and preserve release-owner approval.",
    }
    receipt = {**core, "receipt_sha256": _sha(core), "generated_at": _now()}
    destination = Path(out) if out else workspace / ".factory" / "quality-harness" / f"{Path(manifest_path).stem}.receipt.json"
    if not destination.is_absolute():
        destination = workspace / destination
    destination = destination.resolve()
    try:
        destination.relative_to(workspace)
    except ValueError as exc:
        raise FullStackUXHarnessError("E_UX_RECEIPT_PATH", "receipt must stay inside the workspace") from exc
    if destination == manifest_source:
        raise FullStackUXHarnessError(
            "E_UX_RECEIPT_PATH",
            "receipt destination must differ from the manifest source",
        )
    _atomic_json(destination, receipt)
    return {**receipt, "path": str(destination)}
