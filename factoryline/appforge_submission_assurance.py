"""Build-bound AppForge submission assurance and human-readable dossier.

The gate joins local App Review, Store media, and SaaS lifecycle receipts for
one iOS candidate.  It does not communicate with Apple, create a TestFlight
build, submit an app, or certify that Apple will approve it.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import hashlib
import json
import os
import tempfile

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .app_review_gate import SCHEMA as APP_REVIEW_SCHEMA
from .appforge_quality_audit import RECEIPT_SCHEMA as QUALITY_AUDIT_SCHEMA
from .appforge_store_media import RECEIPT_SCHEMA as STORE_MEDIA_SCHEMA
from .revenueforge import AUTHORITY, RevenueForgeError
from .saas_proof import RECEIPT_SCHEMA as SAAS_PROOF_SCHEMA
from .appforge_oracle import verify_appforge_oracle_authority


CONTRACT_SCHEMA = "factory.appforge.submission-assurance-contract.v1"
RECEIPT_SCHEMA = "factory.appforge.submission-assurance-receipt.v1"
MAX_BYTES = 1_048_576
CANDIDATE_KEYS = ("bundle_identifier", "version", "build_number", "source_commit")


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: object, field: str, *, limit: int = 500) -> str:
    result = str(value or "").strip()
    if not result or len(result) > limit:
        raise RevenueForgeError("APPFORGE_ASSURANCE_CONTRACT_INVALID", f"{field} must be a non-empty bounded string")
    return result


def _digest(value: object, field: str) -> str:
    result = _text(value, field, limit=64).lower()
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise RevenueForgeError("APPFORGE_ASSURANCE_CONTRACT_INVALID", f"{field} must be a SHA-256 hex digest")
    return result


def _candidate(value: object, field: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise RevenueForgeError("APPFORGE_ASSURANCE_CANDIDATE_INVALID", f"{field} must be an object")
    return {key: _text(value.get(key), f"{field}.{key}", limit=200) for key in CANDIDATE_KEYS}


def _local(root: Path, path: Path, *, exists: bool = True) -> Path:
    workspace = root.resolve()
    resolved = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise RevenueForgeError("APPFORGE_ASSURANCE_PATH_REJECTED", "paths must remain inside the workspace") from exc
    if exists and not resolved.is_file():
        raise RevenueForgeError("APPFORGE_ASSURANCE_INPUT_UNAVAILABLE", "input must be a regular workspace file")
    return resolved


def _read_json(root: Path, path: Path, *, schema: str | None = None) -> tuple[dict[str, Any], Path]:
    source = _local(root, path)
    if source.stat().st_size > MAX_BYTES:
        raise RevenueForgeError("APPFORGE_ASSURANCE_INPUT_TOO_LARGE", "JSON input exceeds 1 MiB")
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RevenueForgeError("APPFORGE_ASSURANCE_INPUT_INVALID", "input must be valid JSON") from exc
    if not isinstance(value, dict) or (schema and value.get("schema") != schema):
        raise RevenueForgeError("APPFORGE_ASSURANCE_SCHEMA_REJECTED", f"expected {schema}" if schema else "input must be an object")
    return value, source


def _valid_receipt(value: dict[str, Any], schema: str) -> bool:
    supplied = value.get("receipt_sha256")
    if not isinstance(supplied, str) or len(supplied) != 64:
        return False
    core = {key: item for key, item in value.items() if key != "receipt_sha256"}
    return value.get("schema") == schema and _sha(core) == supplied


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _atomic_text(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(contents)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _recipient(contract: dict[str, Any]) -> dict[str, str]:
    packet = contract.get("reviewer_packet")
    if not isinstance(packet, dict):
        raise RevenueForgeError("APPFORGE_ASSURANCE_CONTRACT_INVALID", "reviewer_packet must be an object")
    return {
        "support_url": _text(packet.get("support_url"), "reviewer_packet.support_url"),
        "privacy_url": _text(packet.get("privacy_url"), "reviewer_packet.privacy_url"),
        "review_notes_sha256": _digest(packet.get("review_notes_sha256"), "reviewer_packet.review_notes_sha256"),
        "reviewer_access_instructions_sha256": _digest(packet.get("reviewer_access_instructions_sha256"), "reviewer_packet.reviewer_access_instructions_sha256"),
        "approved_by": _text(packet.get("approved_by"), "reviewer_packet.approved_by"),
        "approved_at": _text(packet.get("approved_at"), "reviewer_packet.approved_at", limit=60),
    }


def _require_receipt(
    root: Path,
    path: Path,
    schema: str,
    candidate: dict[str, str],
    candidate_field: str,
    ready: tuple[str, str],
) -> tuple[dict[str, Any] | None, dict[str, str] | None]:
    try:
        value, source = _read_json(root, path, schema=schema)
    except RevenueForgeError as error:
        return None, {"code": error.code, "detail": str(error)}
    if not _valid_receipt(value, schema):
        return None, {"code": "APPFORGE_ASSURANCE_RECEIPT_TAMPERED", "detail": f"{source.name} is not hash-valid"}
    if value.get(candidate_field) != candidate:
        return None, {"code": "APPFORGE_ASSURANCE_CANDIDATE_MISMATCH", "detail": f"{source.name} is not bound to the reviewed candidate"}
    if value.get(ready[0]) != ready[1]:
        return None, {"code": "APPFORGE_ASSURANCE_GATE_NOT_READY", "detail": f"{source.name} did not pass its local gate"}
    return value, None


def _markdown(receipt: dict[str, Any]) -> str:
    candidate = receipt["candidate"]
    lines = [
        "# AppForge iOS Submission Assurance Checklist",
        "",
        "## Candidate",
        "",
        f"- Bundle identifier: `{candidate['bundle_identifier']}`",
        f"- Version/build: `{candidate['version']} ({candidate['build_number']})`",
        f"- Source commit: `{candidate['source_commit']}`",
        f"- Generated: `{receipt['generated_at']}`",
        "",
        "## Audited and passed",
        "",
    ]
    for item in receipt["audit"]:
        lines.append(f"- [x] **{item['name']}** - {item['detail']}  ")
        lines.append(f"  Evidence: `{item['receipt_path']}` (`{item['receipt_sha256']}`)")
    packet = receipt["reviewer_packet"]
    lines.extend([
        "",
        "## Reviewer packet checked",
        "",
        f"- [x] Support URL recorded: {packet['support_url']}",
        f"- [x] Privacy URL recorded: {packet['privacy_url']}",
        f"- [x] Review notes digest: `{packet['review_notes_sha256']}`",
        f"- [x] Reviewer-access instructions digest: `{packet['reviewer_access_instructions_sha256']}`",
        f"- [x] Packet approved by: {packet['approved_by']} at {packet['approved_at']}",
        "",
        "## Integrity",
        "",
        f"- [x] Dossier receipt SHA-256: `{receipt['receipt_sha256']}`",
        "",
        "## Claim boundary",
        "",
        "This is a hash-bound local readiness dossier. It does not prove App Store Connect upload state, TestFlight completion, App Review submission, Apple policy certification, or Apple approval.",
        "",
    ])
    return "\n".join(lines)


def _pdf(path: Path, receipt: dict[str, Any]) -> None:
    styles = getSampleStyleSheet()
    document = SimpleDocTemplate(str(path), pagesize=letter, rightMargin=0.65 * inch, leftMargin=0.65 * inch, topMargin=0.65 * inch, bottomMargin=0.65 * inch)
    story: list[Any] = [Paragraph("AppForge iOS Submission Assurance Checklist", styles["Title"]), Spacer(1, 0.12 * inch)]
    candidate = receipt["candidate"]
    story.append(Paragraph(f"<b>Candidate:</b> {candidate['bundle_identifier']} - {candidate['version']} ({candidate['build_number']})", styles["BodyText"]))
    story.append(Paragraph(f"<b>Source commit:</b> {candidate['source_commit']}", styles["BodyText"]))
    story.append(Spacer(1, 0.15 * inch))
    rows = [["Audit", "Status", "Evidence"]]
    for item in receipt["audit"]:
        rows.append([item["name"], "Passed", item["receipt_sha256"][:16] + "..."])
    table = Table(rows, colWidths=[2.55 * inch, 0.75 * inch, 3.0 * inch], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17324D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#B7C5D3")),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F5F8FB")),
        ("TEXTCOLOR", (1, 1), (1, -1), colors.HexColor("#137333")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([table, Spacer(1, 0.18 * inch), Paragraph("Reviewer packet checked", styles["Heading2"])])
    packet = receipt["reviewer_packet"]
    for label in ("support_url", "privacy_url", "review_notes_sha256", "reviewer_access_instructions_sha256", "approved_by", "approved_at"):
        story.append(Paragraph(f"<b>{label.replace('_', ' ').title()}:</b> {packet[label]}", styles["BodyText"]))
    story.extend([Spacer(1, 0.12 * inch), Paragraph("Claim boundary", styles["Heading2"]), Paragraph(receipt["claim_boundary"], styles["BodyText"]), Spacer(1, 0.08 * inch), Paragraph(f"Receipt SHA-256: {receipt['receipt_sha256']}", styles["BodyText"])])
    document.build(story)


def verify_submission_assurance(
    root: Path,
    contract_path: Path,
    app_review_path: Path,
    store_media_path: Path,
    saas_proof_path: Path,
    quality_audit_path: Path,
    out_path: Path,
    report_dir: Path,
    oracle_authority_path: Path | None = None,
) -> dict[str, Any]:
    """Join three hash-valid, exact-candidate gates and emit final reports only when ready."""
    workspace = Path(root).resolve()
    contract, contract_source = _read_json(workspace, contract_path, schema=CONTRACT_SCHEMA)
    candidate = _candidate(contract.get("candidate"), "contract.candidate")
    packet = _recipient(contract)
    audit: list[dict[str, str]] = []
    findings: list[dict[str, str]] = []
    inputs = (
        ("App Review readiness", app_review_path, APP_REVIEW_SCHEMA, "candidate", ("marker", "APP_REVIEW_READY")),
        ("Store media truth", store_media_path, STORE_MEDIA_SCHEMA, "candidate", ("marker", "APPFORGE_STORE_MEDIA_READY")),
        ("SaaS identity to entitlement", saas_proof_path, SAAS_PROOF_SCHEMA, "release_candidate", ("verdict", "verified")),
        ("UX, accessibility, and full-stack audit", quality_audit_path, QUALITY_AUDIT_SCHEMA, "candidate", ("marker", "APPFORGE_QUALITY_AUDIT_READY")),
    )
    for name, path, schema, candidate_field, ready in inputs:
        value, issue = _require_receipt(workspace, path, schema, candidate, candidate_field, ready)
        if issue:
            findings.append({"gate": name, **issue})
            continue
        source = _local(workspace, path)
        audit.append({"name": name, "detail": str(value.get("action_summary") or "Hash-valid local evidence passed."), "receipt_path": source.relative_to(workspace).as_posix(), "receipt_sha256": str(value["receipt_sha256"])})
    configured_oracle = oracle_authority_path
    oracle_authority_relative: str | None = None
    if configured_oracle is None:
        oracle_config = contract.get("oracle_authority")
        if isinstance(oracle_config, dict) and oracle_config.get("required") is True:
            path_value = oracle_config.get("path")
            if not isinstance(path_value, str) or not path_value.strip():
                findings.append({"gate": "Oracle authority", "code": "APPFORGE_ORACLE_AUTHORITY_REQUIRED", "detail": "submission contract requires a workspace-contained Oracle authority receipt"})
            else:
                configured_oracle = Path(path_value)
    oracle_authority: dict[str, Any] | None = None
    if configured_oracle is not None:
        try:
            oracle_authority = verify_appforge_oracle_authority(workspace, configured_oracle, candidate=candidate)
            if not oracle_authority.get("ok"):
                findings.extend({"gate": "Oracle authority", "code": item.get("code", "APPFORGE_ORACLE_AUTHORITY_BLOCKED"), "detail": item.get("detail", "Oracle authority is not current")} for item in oracle_authority.get("findings", []))
            else:
                oracle_path = _local(workspace, configured_oracle)
                oracle_authority_relative = oracle_path.relative_to(workspace).as_posix()
                audit.append({"name": "Oracle authority", "detail": str(oracle_authority.get("action_summary")), "receipt_path": oracle_path.relative_to(workspace).as_posix(), "receipt_sha256": str(oracle_authority.get("receipt_sha256"))})
        except (RevenueForgeError, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            findings.append({"gate": "Oracle authority", "code": getattr(error, "code", "APPFORGE_ORACLE_AUTHORITY_BLOCKED"), "detail": str(error)})
    ready = not findings
    destination = _local(workspace, out_path, exists=False)
    core: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "marker": "APPFORGE_SUBMISSION_DOSSIER_READY" if ready else "APPFORGE_SUBMISSION_DOSSIER_BLOCKED",
        "ok": ready,
        "action_summary": "Join exact-candidate App Review, Store media, and SaaS lifecycle receipts, then produce a human-readable local submission checklist only when every required gate passes.",
        "candidate": candidate,
        "contract_sha256": hashlib.sha256(contract_source.read_bytes()).hexdigest(),
        "reviewer_packet": packet,
        "oracle_authority": {
            "required": configured_oracle is not None,
            "path": oracle_authority_relative,
            "marker": oracle_authority.get("marker") if oracle_authority else None,
            "receipt_sha256": oracle_authority.get("receipt_sha256") if oracle_authority else None,
        },
        "audit": audit,
        "findings": findings,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "authority": {**AUTHORITY, "app_store_connect_write": False, "testflight_upload": False, "app_review_submit": False, "apple_approval_claim": False},
        "claim_boundary": "hash-bound local readiness dossier only; not App Store Connect upload state, TestFlight completion, App Review submission, Apple policy certification, or Apple approval.",
    }
    core["receipt_sha256"] = _sha(core)
    _atomic_json(destination, core)
    result = {**core, "path": destination.relative_to(workspace).as_posix()}
    if not ready:
        return result
    reports = _local(workspace, report_dir, exists=False)
    reports.mkdir(parents=True, exist_ok=True)
    stem = f"{candidate['bundle_identifier'].replace('.', '-')}-{candidate['version']}-{candidate['build_number']}-submission-assurance"
    markdown = reports / f"{stem}.md"
    pdf = reports / f"{stem}.pdf"
    _atomic_text(markdown, _markdown(core))
    _pdf(pdf, core)
    return {**result, "reports": {"markdown": markdown.relative_to(workspace).as_posix(), "pdf": pdf.relative_to(workspace).as_posix()}}


def submission_assurance_projection(root: Path) -> dict[str, Any]:
    """Read only hash-valid dossier state; reports remain evidence, not authorization."""
    workspace = Path(root).resolve()
    current: list[dict[str, Any]] = []
    invalid: list[str] = []
    for path in sorted((workspace / ".factory" / "appforge").rglob("submission-assurance*.json"))[:100]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            supplied = value.pop("receipt_sha256", None)
            valid = value.get("schema") == RECEIPT_SCHEMA and isinstance(supplied, str) and _sha(value) == supplied
            if valid:
                current.append({"path": path.relative_to(workspace).as_posix(), "marker": value.get("marker"), "ok": value.get("ok"), "candidate": value.get("candidate"), "receipt_sha256": supplied})
            else:
                invalid.append(path.relative_to(workspace).as_posix())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            invalid.append(path.relative_to(workspace).as_posix())
    return {"schema": "factory.appforge.submission-assurance-projection.v1", "marker": "APPFORGE_SUBMISSION_ASSURANCE_READ_ONLY", "current_count": len(current), "invalid_count": len(invalid), "latest": current[-1] if current else None, "invalid": invalid, "authority": AUTHORITY, "claim_boundary": "hash-verified local dossier status only; not TestFlight, App Review, or Apple approval state."}
