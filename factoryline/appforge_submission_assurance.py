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

from .app_review_gate import SCHEMA as APP_REVIEW_SCHEMA
from .appforge_quality_audit import RECEIPT_SCHEMA as QUALITY_AUDIT_SCHEMA
from .appforge_store_media import RECEIPT_SCHEMA as STORE_MEDIA_SCHEMA
from .revenueforge import AUTHORITY, RevenueForgeError
from .saas_proof import RECEIPT_SCHEMA as SAAS_PROOF_SCHEMA
from .appforge_oracle import (
    RECEIPT_SCHEMA as ORACLE_AUTHORITY_RECEIPT_SCHEMA,
    verify_appforge_oracle_authority,
)
from . import canonical_json_bytes as _canonical  # noqa: F401 - module encoder contract
from . import canonical_sha as _sha
from . import file_sha256


CONTRACT_SCHEMA = "factory.appforge.submission-assurance-contract.v1"
RECEIPT_SCHEMA = "factory.appforge.submission-assurance-receipt.v1"
MAX_BYTES = 1_048_576
CANDIDATE_KEYS = ("bundle_identifier", "version", "build_number", "source_commit")
SUBMISSION_GATES = (
    (
        "App Review readiness",
        APP_REVIEW_SCHEMA,
        "candidate",
        ("marker", "APP_REVIEW_READY"),
    ),
    (
        "Store media truth",
        STORE_MEDIA_SCHEMA,
        "candidate",
        ("marker", "APPFORGE_STORE_MEDIA_READY"),
    ),
    (
        "SaaS identity to entitlement",
        SAAS_PROOF_SCHEMA,
        "release_candidate",
        ("verdict", "verified"),
    ),
    (
        "UX, accessibility, and full-stack audit",
        QUALITY_AUDIT_SCHEMA,
        "candidate",
        ("marker", "APPFORGE_QUALITY_AUDIT_READY"),
    ),
)


def _text(value: object, field: str, *, limit: int = 500) -> str:
    result = str(value or "").strip()
    if not result or len(result) > limit:
        raise RevenueForgeError(
            "APPFORGE_ASSURANCE_CONTRACT_INVALID",
            f"{field} must be a non-empty bounded string",
        )
    return result


def _digest(value: object, field: str) -> str:
    result = _text(value, field, limit=64).lower()
    if len(result) != 64 or any(
        character not in "0123456789abcdef" for character in result
    ):
        raise RevenueForgeError(
            "APPFORGE_ASSURANCE_CONTRACT_INVALID",
            f"{field} must be a SHA-256 hex digest",
        )
    return result


def _candidate(value: object, field: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise RevenueForgeError(
            "APPFORGE_ASSURANCE_CANDIDATE_INVALID", f"{field} must be an object"
        )
    return {
        key: _text(value.get(key), f"{field}.{key}", limit=200)
        for key in CANDIDATE_KEYS
    }


def _local(root: Path, path: Path, *, exists: bool = True) -> Path:
    workspace = root.resolve()
    resolved = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise RevenueForgeError(
            "APPFORGE_ASSURANCE_PATH_REJECTED", "paths must remain inside the workspace"
        ) from exc
    if exists and not resolved.is_file():
        raise RevenueForgeError(
            "APPFORGE_ASSURANCE_INPUT_UNAVAILABLE",
            "input must be a regular workspace file",
        )
    return resolved


def _read_json(
    root: Path, path: Path, *, schema: str | None = None
) -> tuple[dict[str, Any], Path]:
    source = _local(root, path)
    if source.stat().st_size > MAX_BYTES:
        raise RevenueForgeError(
            "APPFORGE_ASSURANCE_INPUT_TOO_LARGE", "JSON input exceeds 1 MiB"
        )
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RevenueForgeError(
            "APPFORGE_ASSURANCE_INPUT_INVALID", "input must be valid JSON"
        ) from exc
    if not isinstance(value, dict) or (schema and value.get("schema") != schema):
        raise RevenueForgeError(
            "APPFORGE_ASSURANCE_SCHEMA_REJECTED",
            f"expected {schema}" if schema else "input must be an object",
        )
    return value, source


def _valid_receipt(value: dict[str, Any], schema: str) -> bool:
    supplied = value.get("receipt_sha256")
    if not isinstance(supplied, str) or len(supplied) != 64:
        return False
    core = {key: item for key, item in value.items() if key != "receipt_sha256"}
    return value.get("schema") == schema and _sha(core) == supplied


def _atomic_json(
    path: Path, payload: dict[str, Any], *, exclusive: bool = False
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if exclusive:
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise RevenueForgeError(
                    "APPFORGE_ASSURANCE_OUTPUT_EXISTS",
                    "output dossier is immutable; choose a new path",
                ) from exc
        else:
            os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _persist_oracle_authority_receipt(root: Path, receipt: dict[str, Any]) -> Path:
    """Persist a hash-valid derived authority receipt at a content-addressed path.

    The authority input is not the same object as the verified authority
    receipt.  The dossier therefore references this immutable, derived receipt
    rather than attaching its digest to the mutable input file.
    """
    supplied = receipt.get("receipt_sha256")
    if not isinstance(supplied, str) or not _valid_receipt(
        receipt, ORACLE_AUTHORITY_RECEIPT_SCHEMA
    ):
        raise RevenueForgeError(
            "APPFORGE_ORACLE_RECEIPT_INVALID",
            "derived Oracle authority receipt is not hash-valid",
        )
    target = _local(
        root,
        Path(".factory/appforge/oracle-authority")
        / f"oracle-authority-{supplied}.json",
        exists=False,
    )
    if target.exists():
        existing, _ = _read_json(root, target, schema=ORACLE_AUTHORITY_RECEIPT_SCHEMA)
        if (
            not _valid_receipt(existing, ORACLE_AUTHORITY_RECEIPT_SCHEMA)
            or existing != receipt
        ):
            raise RevenueForgeError(
                "APPFORGE_ORACLE_RECEIPT_CONFLICT",
                "content-addressed Oracle authority receipt path contains different bytes",
            )
        return target
    _atomic_json(target, receipt)
    return target


def _recipient(contract: dict[str, Any]) -> dict[str, str]:
    packet = contract.get("reviewer_packet")
    if not isinstance(packet, dict):
        raise RevenueForgeError(
            "APPFORGE_ASSURANCE_CONTRACT_INVALID", "reviewer_packet must be an object"
        )
    return {
        "support_url": _text(packet.get("support_url"), "reviewer_packet.support_url"),
        "privacy_url": _text(packet.get("privacy_url"), "reviewer_packet.privacy_url"),
        "review_notes_sha256": _digest(
            packet.get("review_notes_sha256"), "reviewer_packet.review_notes_sha256"
        ),
        "reviewer_access_instructions_sha256": _digest(
            packet.get("reviewer_access_instructions_sha256"),
            "reviewer_packet.reviewer_access_instructions_sha256",
        ),
        "approved_by": _text(packet.get("approved_by"), "reviewer_packet.approved_by"),
        "approved_at": _text(
            packet.get("approved_at"), "reviewer_packet.approved_at", limit=60
        ),
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
        return None, {
            "code": "APPFORGE_ASSURANCE_RECEIPT_TAMPERED",
            "detail": f"{source.name} is not hash-valid",
        }
    if value.get(candidate_field) != candidate:
        return None, {
            "code": "APPFORGE_ASSURANCE_CANDIDATE_MISMATCH",
            "detail": f"{source.name} is not bound to the reviewed candidate",
        }
    if value.get(ready[0]) != ready[1] or (
        ready[0] == "marker" and value.get("ok") is not True
    ):
        return None, {
            "code": "APPFORGE_ASSURANCE_GATE_NOT_READY",
            "detail": f"{source.name} did not pass its local gate",
        }
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
        lines.append(
            f"  Evidence: `{item['receipt_path']}` (`{item['receipt_sha256']}`)"
        )
    packet = receipt["reviewer_packet"]
    lines.extend(
        [
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
            f"- [x] Dossier content SHA-256: `{receipt['content_sha256']}`",
            "",
            "## Claim boundary",
            "",
            "This is a hash-bound local readiness dossier. It does not prove App Store Connect upload state, TestFlight completion, App Review submission, Apple policy certification, or Apple approval.",
            "",
        ]
    )
    return "\n".join(lines)


def _pdf(path: Path, receipt: dict[str, Any]) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise RevenueForgeError(
            "APPFORGE_ASSURANCE_PDF_DEPENDENCY_MISSING",
            "PDF dossier generation requires the optional 'pdf' extra; install with "
            "`python -m pip install 'factoryline-code-factory[pdf]'`.",
        ) from exc

    styles = getSampleStyleSheet()
    document = SimpleDocTemplate(
        str(path),
        pagesize=letter,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
    )
    story: list[Any] = [
        Paragraph("AppForge iOS Submission Assurance Checklist", styles["Title"]),
        Spacer(1, 0.12 * inch),
    ]
    candidate = receipt["candidate"]
    story.append(
        Paragraph(
            f"<b>Candidate:</b> {candidate['bundle_identifier']} - {candidate['version']} ({candidate['build_number']})",
            styles["BodyText"],
        )
    )
    story.append(
        Paragraph(
            f"<b>Source commit:</b> {candidate['source_commit']}", styles["BodyText"]
        )
    )
    story.append(Spacer(1, 0.15 * inch))
    rows = [["Audit", "Status", "Evidence"]]
    for item in receipt["audit"]:
        rows.append([item["name"], "Passed", item["receipt_sha256"][:16] + "..."])
    table = Table(rows, colWidths=[2.55 * inch, 0.75 * inch, 3.0 * inch], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17324D")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#B7C5D3")),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F5F8FB")),
                ("TEXTCOLOR", (1, 1), (1, -1), colors.HexColor("#137333")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.extend(
        [
            table,
            Spacer(1, 0.18 * inch),
            Paragraph("Reviewer packet checked", styles["Heading2"]),
        ]
    )
    packet = receipt["reviewer_packet"]
    for label in (
        "support_url",
        "privacy_url",
        "review_notes_sha256",
        "reviewer_access_instructions_sha256",
        "approved_by",
        "approved_at",
    ):
        story.append(
            Paragraph(
                f"<b>{label.replace('_', ' ').title()}:</b> {packet[label]}",
                styles["BodyText"],
            )
        )
    story.extend(
        [
            Spacer(1, 0.12 * inch),
            Paragraph("Claim boundary", styles["Heading2"]),
            Paragraph(receipt["claim_boundary"], styles["BodyText"]),
            Spacer(1, 0.08 * inch),
            Paragraph(
                f"Dossier content SHA-256: {receipt['content_sha256']}",
                styles["BodyText"],
            ),
        ]
    )
    document.build(story)


def _submission_gate_inputs(
    workspace: Path,
    candidate: dict[str, str],
    receipt_paths: tuple[Path, Path, Path, Path],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    audit: list[dict[str, str]] = []
    findings: list[dict[str, str]] = []
    for path, (name, schema, candidate_field, ready) in zip(
        receipt_paths, SUBMISSION_GATES, strict=True
    ):
        value, issue = _require_receipt(
            workspace, path, schema, candidate, candidate_field, ready
        )
        if issue:
            findings.append({"gate": name, **issue})
            continue
        assert value is not None
        source = _local(workspace, path)
        audit.append(
            {
                "name": name,
                "detail": str(
                    value.get("action_summary") or "Hash-valid local evidence passed."
                ),
                "receipt_path": source.relative_to(workspace).as_posix(),
                "receipt_sha256": str(value["receipt_sha256"]),
            }
        )
    return audit, findings


def _configured_oracle_path(
    contract: dict[str, Any],
    oracle_authority_path: Path | None,
    findings: list[dict[str, str]],
) -> Path | None:
    configured = oracle_authority_path
    if configured is None:
        oracle_config = contract.get("oracle_authority")
        if isinstance(oracle_config, dict) and oracle_config.get("required") is True:
            path_value = oracle_config.get("path")
            if not isinstance(path_value, str) or not path_value.strip():
                findings.append(
                    {
                        "gate": "Oracle authority",
                        "code": "APPFORGE_ORACLE_AUTHORITY_REQUIRED",
                        "detail": "submission contract requires a workspace-contained Oracle authority receipt",
                    }
                )
            else:
                configured = Path(path_value)
    if configured is None:
        findings.append(
            {
                "gate": "Oracle authority",
                "code": "APPFORGE_ORACLE_AUTHORITY_REQUIRED",
                "detail": "submission assurance requires a candidate-bound Oracle authority receipt",
            }
        )
    return configured


def _review_oracle_authority(
    workspace: Path,
    configured: Path | None,
    candidate: dict[str, str],
    audit: list[dict[str, str]],
    findings: list[dict[str, str]],
) -> tuple[dict[str, Any] | None, str | None, str | None]:
    authority: dict[str, Any] | None = None
    authority_path: str | None = None
    source_path: str | None = None
    if configured is None:
        return authority, authority_path, source_path
    try:
        authority = verify_appforge_oracle_authority(
            workspace, configured, candidate=candidate
        )
        if not authority.get("ok"):
            _append_oracle_findings(findings, authority)
        else:
            authority_path, source_path = _record_oracle_authority(
                workspace, configured, authority, audit
            )
    except (
        RevenueForgeError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        findings.append(
            {
                "gate": "Oracle authority",
                "code": getattr(error, "code", "APPFORGE_ORACLE_AUTHORITY_BLOCKED"),
                "detail": str(error),
            }
        )
    return authority, authority_path, source_path


def _append_oracle_findings(
    findings: list[dict[str, str]], authority: dict[str, Any]
) -> None:
    findings.extend(
        {
            "gate": "Oracle authority",
            "code": item.get("code", "APPFORGE_ORACLE_AUTHORITY_BLOCKED"),
            "detail": item.get("detail", "Oracle authority is not current"),
        }
        for item in authority.get("findings", [])
    )


def _record_oracle_authority(
    workspace: Path,
    configured: Path,
    authority: dict[str, Any],
    audit: list[dict[str, str]],
) -> tuple[str, str]:
    source = _local(workspace, configured)
    persisted = _persist_oracle_authority_receipt(workspace, authority)
    authority_path = persisted.relative_to(workspace).as_posix()
    source_path = source.relative_to(workspace).as_posix()
    audit.append(
        {
            "name": "Oracle authority",
            "detail": str(authority.get("action_summary")),
            "receipt_path": authority_path,
            "receipt_sha256": str(authority.get("receipt_sha256")),
        }
    )
    return authority_path, source_path


def _submission_core(
    contract_source: Path,
    candidate: dict[str, str],
    packet: dict[str, str],
    configured_oracle: Path | None,
    oracle_authority: dict[str, Any] | None,
    oracle_authority_path: str | None,
    oracle_authority_source_path: str | None,
    audit: list[dict[str, str]],
    findings: list[dict[str, str]],
) -> dict[str, Any]:
    ready = not findings
    core: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "marker": "APPFORGE_SUBMISSION_DOSSIER_READY"
        if ready
        else "APPFORGE_SUBMISSION_DOSSIER_BLOCKED",
        "ok": ready,
        "action_summary": "Join exact-candidate App Review, Store media, and SaaS lifecycle receipts, then produce a human-readable local submission checklist only when every required gate passes.",
        "candidate": candidate,
        "contract_sha256": hashlib.sha256(contract_source.read_bytes()).hexdigest(),
        "reviewer_packet": packet,
        "oracle_authority": {
            "required": configured_oracle is not None,
            "path": oracle_authority_path,
            "source_path": oracle_authority_source_path,
            "source_sha256": oracle_authority.get("authority_source_sha256")
            if oracle_authority
            else None,
            "marker": oracle_authority.get("marker") if oracle_authority else None,
            "receipt_sha256": oracle_authority.get("receipt_sha256")
            if oracle_authority
            else None,
        },
        "audit": audit,
        "findings": findings,
        "generated_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "authority": {
            **AUTHORITY,
            "app_store_connect_write": False,
            "testflight_upload": False,
            "app_review_submit": False,
            "apple_approval_claim": False,
        },
        "claim_boundary": "hash-bound local readiness dossier only; not App Store Connect upload state, TestFlight completion, App Review submission, Apple policy certification, or Apple approval.",
    }
    return core


def _write_submission_reports(
    workspace: Path,
    report_dir: Path,
    destination: Path,
    core: dict[str, Any],
) -> None:
    reports = _local(workspace, report_dir, exists=False)
    reports.mkdir(parents=True, exist_ok=True)
    candidate = core["candidate"]
    stem = f"{candidate['bundle_identifier'].replace('.', '-')}-{candidate['version']}-{candidate['build_number']}-submission-assurance"
    if Path(stem).name != stem or any(char in stem for char in "/\\:"):
        raise RevenueForgeError(
            "APPFORGE_ASSURANCE_CANDIDATE_INVALID",
            "candidate cannot form a report filename",
        )
    paths = {
        kind: reports / f"{stem}.{suffix}"
        for kind, suffix in (("markdown", "md"), ("pdf", "pdf"))
    }
    if any(path.exists() for path in paths.values()):
        raise RevenueForgeError(
            "APPFORGE_ASSURANCE_OUTPUT_EXISTS",
            "report outputs are immutable; choose a new report directory or candidate build",
        )
    core["reports"] = {
        kind: path.relative_to(workspace).as_posix() for kind, path in paths.items()
    }
    # Render against the dossier content, then seal the rendered bytes into the receipt.
    core["content_sha256"] = _sha(core)
    with tempfile.TemporaryDirectory(
        prefix=".submission-assurance-", dir=reports
    ) as stage:
        staged = {kind: Path(stage) / path.name for kind, path in paths.items()}
        staged["markdown"].write_text(_markdown(core), encoding="utf-8", newline="\n")
        _pdf(staged["pdf"], core)
        core["report_sha256"] = {
            kind: file_sha256(path) for kind, path in staged.items()
        }
        core["receipt_sha256"] = _sha(core)
        published = []
        try:
            for kind, path in paths.items():
                os.link(staged[kind], path)
                published.append(path)
            verify_current_submission_assurance(workspace, core, candidate)
            _atomic_json(destination, core, exclusive=True)
        except BaseException:
            for path in published:
                path.unlink(missing_ok=True)
            raise


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
    contract, contract_source = _read_json(
        workspace, contract_path, schema=CONTRACT_SCHEMA
    )
    candidate = _candidate(contract.get("candidate"), "contract.candidate")
    packet = _recipient(contract)
    audit, findings = _submission_gate_inputs(
        workspace,
        candidate,
        (app_review_path, store_media_path, saas_proof_path, quality_audit_path),
    )
    configured_oracle = _configured_oracle_path(
        contract, oracle_authority_path, findings
    )
    oracle_authority, oracle_authority_relative, oracle_authority_source_relative = (
        _review_oracle_authority(
            workspace, configured_oracle, candidate, audit, findings
        )
    )
    destination = _local(workspace, out_path, exists=False)
    if destination.exists():
        raise RevenueForgeError(
            "APPFORGE_ASSURANCE_OUTPUT_EXISTS",
            "output dossier is immutable; choose a new path",
        )
    core = _submission_core(
        contract_source,
        candidate,
        packet,
        configured_oracle,
        oracle_authority,
        oracle_authority_relative,
        oracle_authority_source_relative,
        audit,
        findings,
    )
    core["contract_path"] = contract_source.relative_to(workspace).as_posix()
    if core["ok"]:
        _write_submission_reports(workspace, report_dir, destination, core)
    else:
        core["receipt_sha256"] = _sha(core)
        _atomic_json(destination, core, exclusive=True)
    return {**core, "path": destination.relative_to(workspace).as_posix()}


def _assurance_blocked(detail: str) -> RevenueForgeError:
    return RevenueForgeError(
        "APPFORGE_ASSURANCE_PREREQUISITE_CHANGED",
        f"{detail}. Restore the original evidence or rerun `factory revenue submission-assurance` with current evidence and fresh output paths.",
    )


def _verify_file(root: Path, path: object, expected: object, label: str) -> None:
    if not isinstance(path, str) or not isinstance(expected, str):
        raise _assurance_blocked(f"{label} is missing from the dossier")
    try:
        actual = file_sha256(_local(root, Path(path)))
    except (RevenueForgeError, OSError) as exc:
        raise _assurance_blocked(f"{label} is unavailable") from exc
    if actual != expected:
        raise _assurance_blocked(f"{label} has changed")


def verify_current_submission_assurance(
    root: Path, receipt: dict[str, Any], candidate: dict[str, str]
) -> None:
    """Recheck the prerequisites of a sealed ready dossier without writing files."""
    _verify_file(
        root,
        receipt.get("contract_path"),
        receipt.get("contract_sha256"),
        "Submission contract",
    )
    audit = receipt.get("audit")
    if not isinstance(audit, list) or len(audit) != len(SUBMISSION_GATES) + 1:
        raise _assurance_blocked("Required gate receipts are missing from the dossier")
    for row, (name, schema, field, ready) in zip(
        audit[:-1], SUBMISSION_GATES, strict=True
    ):
        if (
            not isinstance(row, dict)
            or row.get("name") != name
            or not isinstance(row.get("receipt_path"), str)
        ):
            raise _assurance_blocked(f"{name} is missing from the dossier")
        current, _ = _require_receipt(
            root, Path(row["receipt_path"]), schema, candidate, field, ready
        )
        if current is None or current["receipt_sha256"] != row.get("receipt_sha256"):
            raise _assurance_blocked(f"{name} no longer matches its passing receipt")

    oracle = receipt.get("oracle_authority")
    if not isinstance(oracle, dict) or not isinstance(oracle.get("source_path"), str):
        raise _assurance_blocked("Oracle authority is missing from the dossier")
    oracle_row = audit[-1]
    if (
        not isinstance(oracle_row, dict)
        or oracle_row.get("name") != "Oracle authority"
        or not isinstance(oracle_row.get("receipt_path"), str)
        or oracle_row["receipt_path"] != oracle.get("path")
        or oracle_row.get("receipt_sha256") != oracle.get("receipt_sha256")
    ):
        raise _assurance_blocked("Oracle authority is missing from the audit")
    try:
        _verify_file(
            root,
            oracle["source_path"],
            oracle.get("source_sha256"),
            "Oracle authority source",
        )
        current = verify_appforge_oracle_authority(
            root, Path(oracle["source_path"]), candidate=candidate
        )
        sealed, _ = _read_json(
            root,
            Path(oracle_row["receipt_path"]),
            schema=ORACLE_AUTHORITY_RECEIPT_SCHEMA,
        )
    except (RevenueForgeError, OSError, ValueError) as exc:
        raise _assurance_blocked("Oracle authority is unavailable or invalid") from exc
    if (
        current != sealed
        or current.get("ok") is not True
        or current["receipt_sha256"] != oracle["receipt_sha256"]
    ):
        raise _assurance_blocked(
            "Oracle authority no longer matches its passing receipt"
        )

    reports = receipt.get("reports")
    digests = receipt.get("report_sha256")
    if not isinstance(reports, dict) or not isinstance(digests, dict):
        raise _assurance_blocked(
            "Completed Markdown and PDF reports are missing from the dossier"
        )
    for kind in ("markdown", "pdf"):
        _verify_file(
            root, reports.get(kind), digests.get(kind), f"{kind.upper()} report"
        )


def _projection_ranked(
    workspace: Path, candidates: list[Path], invalid: list[str]
) -> list[tuple[int, Path]]:
    ranked: list[tuple[int, Path]] = []
    for path in candidates[:1_000]:
        try:
            ranked.append((path.stat().st_mtime_ns, path))
        except OSError:
            invalid.append(path.relative_to(workspace).as_posix())
    return ranked


def _project_receipt(workspace: Path, path: Path) -> dict[str, Any] | None:
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("submission assurance receipt exceeds 1 MiB")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("submission assurance receipt must be an object")
    if not _valid_receipt(value, RECEIPT_SCHEMA):
        return None
    if (
        value.get("ok") is True
        or value.get("marker") == "APPFORGE_SUBMISSION_DOSSIER_READY"
    ):
        if (
            value.get("ok") is not True
            or value.get("marker") != "APPFORGE_SUBMISSION_DOSSIER_READY"
        ):
            raise _assurance_blocked("Dossier readiness fields disagree")
        verify_current_submission_assurance(
            workspace, value, _candidate(value.get("candidate"), "dossier.candidate")
        )
    return {
        "path": path.relative_to(workspace).as_posix(),
        "marker": value.get("marker"),
        "ok": value.get("ok"),
        "candidate": value.get("candidate"),
        "findings": value.get("findings", []),
        "receipt_sha256": value["receipt_sha256"],
    }


def _project_receipts(
    workspace: Path,
    ranked: list[tuple[int, Path]],
    invalid: list[str],
    blockers: dict[str, str],
) -> list[dict[str, Any]]:
    current: list[dict[str, Any]] = []
    for _mtime, path in sorted(ranked, key=lambda item: (item[0], item[1].as_posix()))[
        -100:
    ]:
        try:
            projected = _project_receipt(workspace, path)
            if projected is None:
                invalid.append(path.relative_to(workspace).as_posix())
            else:
                current.append(projected)
        except RevenueForgeError as error:
            relative = path.relative_to(workspace).as_posix()
            invalid.append(relative)
            blockers[relative] = str(error)
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ):
            invalid.append(path.relative_to(workspace).as_posix())
    return current


def submission_assurance_projection(root: Path) -> dict[str, Any]:
    """Read only hash-valid dossier state; reports remain evidence, not authorization."""
    workspace = Path(root).resolve()
    invalid: list[str] = []
    blockers: dict[str, str] = {}
    candidates = list(
        (workspace / ".factory" / "appforge").rglob("submission-assurance*.json")
    )
    truncated = len(candidates) > 1_000
    ranked = _projection_ranked(workspace, candidates, invalid)
    current = _project_receipts(workspace, ranked, invalid, blockers)
    newest = max(ranked, key=lambda item: (item[0], item[1].as_posix()), default=None)
    latest = current[-1] if current else None
    if (
        truncated
        or newest is None
        or (latest and latest["path"] != newest[1].relative_to(workspace).as_posix())
    ):
        latest = None
    if truncated:
        invalid.append(".factory/appforge/<scan-truncated>")
    return {
        "schema": "factory.appforge.submission-assurance-projection.v1",
        "marker": "APPFORGE_SUBMISSION_ASSURANCE_REVIEW_REQUIRED"
        if invalid
        else "APPFORGE_SUBMISSION_ASSURANCE_READ_ONLY",
        "current_count": len(current),
        "invalid_count": len(invalid),
        "truncated": truncated,
        "latest": latest,
        "invalid": invalid,
        "blockers": blockers,
        "authority": AUTHORITY,
        "claim_boundary": "hash-verified local dossier status only; not TestFlight, App Review, or Apple approval state.",
    }
