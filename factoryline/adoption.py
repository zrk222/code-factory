"""Local, privacy-bounded activation evidence and shareable Proof Cards.

The adoption surface deliberately avoids hosted analytics.  The first proof
keeps its disposable sandbox demonstration, but also records a bounded local
inventory of the selected workspace so a new user can see what was assessed.
The inventory is not a certification and never includes source bodies,
commands, prompts, logs, or user identifiers.
"""

from __future__ import annotations

from . import canonical_json_compat_bytes as _canonical

import copy
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable
from .e2e_proof import (
    E2EProofError,
    validate_e2e_proof_receipt,
    verify_e2e_proof,
    write_e2e_proof_artifacts,
)
from .review_audits import MAX_SECURITY_SOURCE_FILES
from .cli_foundations import _SCRIPT_LANGUAGE_SUFFIXES


FIRST_PROOF_SCHEMA = "factory.first-proof.v1"
PROOF_CARD_SCHEMA = "factory.proof-card.v1"
ADOPTION_EVENT_SCHEMA = "factory.adoption-event.v1"
ADOPTION_STATUS_SCHEMA = "factory.adoption-status.v1"
MILESTONES = frozenset(
    {
        "first_proof_completed",
        "proof_receipt_saved",
        "proof_card_saved",
        "seven_day_return",
    }
)
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


class AdoptionError(ValueError):
    """Malformed or tampered adoption evidence."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _project_native_worker_execution(result: dict[str, Any]) -> None:
    """Remove only run-envelope fields from the native worker result schema."""
    for key in (
        "run_id",
        "parent_run",
        "sequence",
        "event_sha256",
        "updated_at",
        "review_evidence_path",
    ):
        result.pop(key, None)
    enrollment = result.get("action_enrollment")
    if isinstance(enrollment, dict):
        enrollment.pop("actions_sha256", None)
        for action in enrollment.get("actions", []):
            if isinstance(action, dict):
                action.pop("run_id", None)
                action.pop("action_id", None)
    for lane in result.get("lanes", []):
        if isinstance(lane, dict):
            lane.pop("action_id", None)


def _project_native_observation(domain: object) -> None:
    if isinstance(domain, dict) and isinstance(domain.get("result"), dict):
        domain["result"].pop("run_id", None)


def _scan_identity_projection(result: dict[str, Any]) -> dict[str, Any]:
    """Return deterministic scan content while excluding run receipt evidence."""
    identity = copy.deepcopy(result)
    identity.pop("scan_sha256", None)
    identity.pop("run_receipt_sha256", None)
    deep_audit = identity.get("deep_audit")
    if isinstance(deep_audit, dict):
        deep_audit.pop("telemetry", None)
        deep_audit.pop("audit_sha256", None)
        for lane in deep_audit.get("lanes", []):
            if isinstance(lane, dict) and isinstance(lane.get("result"), dict):
                if lane.get("measurement_id") == "native_worker_execution":
                    _project_native_worker_execution(lane["result"])
                if lane.get("measurement_id") in {
                    "runtime_coverage",
                    "dependencies_and_supply_chain",
                }:
                    _project_native_observation(
                        lane["result"].get("native_observations")
                    )
        native_domains = deep_audit.get("native_domains")
        if isinstance(native_domains, dict):
            for domain in native_domains.get("domains", []):
                _project_native_observation(domain)
            for finding in native_domains.get("findings", []):
                if isinstance(finding, dict):
                    finding.pop("run_id", None)
    return identity


def _utc(value: datetime | None = None) -> datetime:
    instant = value or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    return instant.astimezone(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


_INVENTORY_IGNORED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".factory",
        ".venv",
        "venv",
        "node_modules",
        "dist",
        "build",
        "__pycache__",
    }
)


def _workspace_inventory(workspace: Path, *, limit: int = 10_000) -> dict[str, Any]:
    """Collect only relative file metadata for an immediate, safe assessment."""
    rows: list[dict[str, Any]] = []
    truncated = False
    for directory, dirnames, filenames in os.walk(workspace, followlinks=False):
        dirnames[:] = sorted(
            name for name in dirnames if name not in _INVENTORY_IGNORED_DIRS
        )
        for name in sorted(filenames):
            path = Path(directory) / name
            try:
                relative = path.relative_to(workspace).as_posix()
                size = path.stat().st_size
            except (OSError, ValueError):
                continue
            rows.append({"path": relative, "bytes": size})
            if len(rows) >= limit:
                truncated = True
                break
        if truncated:
            break
    suffixes = {
        "python": (".py",),
        **_SCRIPT_LANGUAGE_SUFFIXES,
        "docs": (".md", ".rst"),
        "go": (".go",),
        "rust": (".rs",),
        "java": (".java",),
        "kotlin": (".kt", ".kts"),
        "c_cpp": (".c", ".h", ".cpp", ".hpp", ".cc"),
        "csharp": (".cs",),
        "ruby": (".rb",),
        "php": (".php",),
        "swift": (".swift",),
        "shell": (".sh", ".ps1", ".bash"),
    }
    counts = {
        key: sum(row["path"].lower().endswith(extensions) for row in rows)
        for key, extensions in suffixes.items()
    }
    return {
        "state": "ASSESSED" if rows else "INCOMPLETE",
        "files_discovered": len(rows),
        "files_truncated": truncated,
        "file_types": counts,
        "inventory_sha256": _sha(rows),
        "scope": "relative file names and byte sizes only; source contents were not read",
    }


def _atomic_json(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)
    return path


def _workspace_path(root: Path, path: Path) -> Path:
    workspace = Path(root).resolve()
    candidate = Path(path)
    resolved = (
        candidate.resolve()
        if candidate.is_absolute()
        else (workspace / candidate).resolve()
    )
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise AdoptionError(
            "E_ADOPTION_PATH_ESCAPE",
            "adoption artifacts must stay inside the workspace",
        ) from exc
    return resolved


def _card_facts(receipt: dict[str, Any]) -> dict[str, Any]:
    validated = validate_e2e_proof_receipt(receipt)
    marker = validated["marker"]
    if marker == "E2E_PROOF_PASS":
        outcome = "FAILURE_CASE_REJECTED"
        headline = "The declared failure case was rejected"
    elif marker == "HOLLOW_E2E_TEST":
        outcome = "HOLLOW_TEST_DETECTED"
        headline = "A test that could not say no was caught"
    else:
        outcome = "PROOF_BLOCKED"
        headline = "The declared proof did not complete"
    core = {
        "schema": PROOF_CARD_SCHEMA,
        "evidence_schema": validated["schema"],
        "source_receipt_sha256": validated["receipt_sha256"],
        "marker": marker,
        "outcome": outcome,
        "headline": headline,
        "positive_check_passed": validated["commands"]["positive"]["exit_code"] == 0,
        "negative_case_rejected": validated["commands"]["negative"]["exit_code"]
        not in (None, 0),
        "hollow_test_detected": marker == "HOLLOW_E2E_TEST",
        "privacy": {
            "contains_commands": False,
            "contains_paths": False,
            "contains_repository_name": False,
            "contains_prompts_or_logs": False,
            "contains_user_identity": False,
        },
        "authority": {
            "share": True,
            "approval": False,
            "merge": False,
            "publication": False,
            "deployment": False,
        },
        "scope_limit": "This card summarizes one verified local receipt. It is not a production-readiness, security, coverage, or identity certificate.",
    }
    return {**core, "card_sha256": _sha(core)}


def _card_markdown(card: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Code Factory Proof Card",
            "",
            f"## {card['headline']}",
            "",
            f"- Outcome: `{card['outcome']}`",
            f"- Marker: `{card['marker']}`",
            f"- Positive check passed: `{str(card['positive_check_passed']).lower()}`",
            f"- Negative case rejected: `{str(card['negative_case_rejected']).lower()}`",
            f"- Hollow test detected: `{str(card['hollow_test_detected']).lower()}`",
            f"- Source receipt: `{card['source_receipt_sha256']}`",
            f"- Card SHA-256: `{card['card_sha256']}`",
            "",
            "No commands, paths, repository name, prompts, logs, or user identity are included.",
            "",
            card["scope_limit"],
            "",
            "https://github.com/zrk222/code-factory",
            "",
        ]
    )


def _card_svg(card: dict[str, Any]) -> str:
    positive = "PASS" if card["positive_check_passed"] else "BLOCKED"
    negative = "REJECTED" if card["negative_case_rejected"] else "SURVIVED"
    accent = "#0f766e" if card["outcome"] == "FAILURE_CASE_REJECTED" else "#b45309"
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="720" viewBox="0 0 1280 720" role="img" aria-labelledby="title desc">
  <title id="title">Code Factory Proof Card</title>
  <desc id="desc">{escape(card["headline"])}. Privacy-safe summary of one verified local receipt.</desc>
  <rect width="1280" height="720" rx="36" fill="#f8fafc"/>
  <rect x="44" y="44" width="1192" height="632" rx="28" fill="#ffffff" stroke="#cbd5e1" stroke-width="3"/>
  <text x="92" y="118" font-family="Arial, sans-serif" font-size="24" font-weight="700" fill="#475569">CODE FACTORY · PROOF CARD</text>
  <text x="92" y="205" font-family="Arial, sans-serif" font-size="50" font-weight="800" fill="#0f172a">{escape(card["headline"])}</text>
  <rect x="92" y="260" width="500" height="126" rx="20" fill="#ecfeff" stroke="#a5f3fc"/>
  <text x="124" y="308" font-family="Arial, sans-serif" font-size="20" font-weight="700" fill="#475569">POSITIVE CHECK</text>
  <text x="124" y="358" font-family="Arial, sans-serif" font-size="34" font-weight="800" fill="#0f766e">{positive}</text>
  <rect x="620" y="260" width="500" height="126" rx="20" fill="#fff7ed" stroke="#fed7aa"/>
  <text x="652" y="308" font-family="Arial, sans-serif" font-size="20" font-weight="700" fill="#475569">DECLARED FAILURE CASE</text>
  <text x="652" y="358" font-family="Arial, sans-serif" font-size="34" font-weight="800" fill="{accent}">{negative}</text>
  <text x="92" y="468" font-family="Arial, sans-serif" font-size="23" fill="#334155">Outcome · {escape(card["outcome"])}</text>
  <text x="92" y="510" font-family="Arial, sans-serif" font-size="20" fill="#64748b">Receipt · {card["source_receipt_sha256"][:20]}…</text>
  <text x="92" y="550" font-family="Arial, sans-serif" font-size="20" fill="#64748b">No code, paths, prompts, logs, or identity included.</text>
  <line x1="92" y1="590" x2="1120" y2="590" stroke="#e2e8f0" stroke-width="2"/>
  <text x="92" y="632" font-family="Arial, sans-serif" font-size="18" fill="#64748b">One verified receipt · not a production-readiness certificate</text>
  <text x="1120" y="632" text-anchor="end" font-family="Arial, sans-serif" font-size="18" font-weight="700" fill="#2563eb">github.com/zrk222/code-factory</text>
</svg>
'''


def verify_proof_card(value: object) -> dict[str, Any]:
    """Validate the exact Proof Card schema, privacy flags, and canonical digest."""
    if not isinstance(value, dict) or value.get("schema") != PROOF_CARD_SCHEMA:
        raise AdoptionError(
            "E_PROOF_CARD_INVALID", f"a {PROOF_CARD_SCHEMA} object is required"
        )
    required = {
        "schema",
        "evidence_schema",
        "source_receipt_sha256",
        "marker",
        "outcome",
        "headline",
        "positive_check_passed",
        "negative_case_rejected",
        "hollow_test_detected",
        "privacy",
        "authority",
        "scope_limit",
        "card_sha256",
    }
    if set(value) != required:
        raise AdoptionError("E_PROOF_CARD_INVALID", "Proof Card fields changed")
    if not _SHA256.fullmatch(str(value.get("source_receipt_sha256", ""))):
        raise AdoptionError("E_PROOF_CARD_INVALID", "source receipt digest is invalid")
    core = {key: value[key] for key in value if key != "card_sha256"}
    if value.get("card_sha256") != _sha(core):
        raise AdoptionError("E_PROOF_CARD_INVALID", "Proof Card hash does not match")
    if value["privacy"] != {
        "contains_commands": False,
        "contains_paths": False,
        "contains_repository_name": False,
        "contains_prompts_or_logs": False,
        "contains_user_identity": False,
    }:
        raise AdoptionError(
            "E_PROOF_CARD_INVALID", "Proof Card privacy boundary changed"
        )
    return value


def write_proof_card(receipt: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Write JSON, Markdown, and SVG cards from one verified E2E proof receipt."""
    card = verify_proof_card(_card_facts(receipt))
    destination = Path(out_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    stem = f"proof-card-{card['card_sha256'][:12]}"
    paths = {
        "json": destination / f"{stem}.json",
        "markdown": destination / f"{stem}.md",
        "svg": destination / f"{stem}.svg",
    }
    _atomic_json(paths["json"], card)
    paths["markdown"].write_text(_card_markdown(card), encoding="utf-8")
    paths["svg"].write_text(_card_svg(card), encoding="utf-8")
    return {"card": card, "paths": {key: str(path) for key, path in paths.items()}}


def proof_card_from_receipt(
    root: Path, receipt_path: Path, out_dir: Path
) -> dict[str, Any]:
    """Create a Proof Card from a workspace-contained E2E receipt file."""
    workspace = Path(root).resolve()
    source = _workspace_path(workspace, receipt_path)
    if not source.is_file():
        raise AdoptionError(
            "E_PROOF_CARD_SOURCE", "receipt must name a workspace-contained JSON file"
        )
    try:
        receipt = json.loads(source.read_text(encoding="utf-8"))
        validate_e2e_proof_receipt(receipt)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, E2EProofError) as exc:
        raise AdoptionError(
            "E_PROOF_CARD_SOURCE", f"receipt is not a valid E2E proof: {exc}"
        ) from exc
    return write_proof_card(receipt, _workspace_path(workspace, out_dir))


def _completion_card_json(path: Path) -> tuple[dict[str, Any], str]:
    from .product_missions import MAX_DAILY_RECEIPT_BYTES
    from .runtime_audit_process import bounded_file_sha256

    try:
        digest, raw = bounded_file_sha256(
            path, MAX_DAILY_RECEIPT_BYTES, include_bytes=True
        )
        value = json.loads(raw.decode("utf-8-sig"))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise AdoptionError(
            "E_COMPLETION_CARD_SOURCE", "invalid or oversized local artifact"
        ) from exc
    if not isinstance(value, dict):
        raise AdoptionError(
            "E_COMPLETION_CARD_SOURCE", "local artifact must be a JSON object"
        )
    return value, digest


def _completion_card_inputs(workspace: Path, receipt: dict[str, Any]) -> Path:
    from .product_missions import MAX_COMPLETION_EVIDENCE

    mission_path = _workspace_path(workspace, Path(receipt["mission"]["path"]))
    _workspace_path(workspace, Path(receipt["validation"]["path"]))
    evidence = receipt.get("evidence", [])
    if not isinstance(evidence, list) or len(evidence) > MAX_COMPLETION_EVIDENCE:
        raise AdoptionError("E_COMPLETION_CARD_SOURCE", "invalid evidence inventory")
    for item in evidence:
        _workspace_path(workspace, Path(item["path"]))
    mission, _digest = _completion_card_json(mission_path)
    for group in (mission.get("inputs", {}), mission.get("loop", {})):
        for key, value in group.items():
            if key.endswith("_path"):
                _workspace_path(workspace, Path(value))
    return mission_path


def _completion_case_outcome(value: object) -> str:
    return {
        "baseline_assertion_pass_mutant_assertion_fail": "Original passed; deliberately broken code triggered the assertion",
        "baseline_assertion_pass_mutant_assertion_pass": "Unrelated control passed with both original and broken code",
    }.get(str(value), "Not established by supported execution evidence")


def _completion_card_cases(summary: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for criterion in summary.get("criteria", []):
        for case in criterion.get("cases", []):
            rows.append(
                {
                    "criterion_id": criterion["criterion_id"],
                    "case_id": case["case_id"],
                    "polarity": case.get("polarity"),
                    "disposition": case.get("disposition", "unverified"),
                    "input_sha256": case.get("input_sha256"),
                    "expected": _completion_case_outcome(
                        case.get("expected_outcome_claim")
                    ),
                    "observed": _completion_case_outcome(case.get("observed_outcome")),
                }
            )
    return rows


def _completion_card_facts(
    workspace,
    source,
    receipt,
    digest,
    verification,
    mission,
    applied_budget,
    applied_snapshot,
):
    intact = verification.get("integrity_valid") is True
    complete = intact and verification.get("complete") is True
    summary = verification.get("daily_verification", {}) if intact else {}
    status = "COMPLETE" if complete else "INCOMPLETE" if intact else "INVALID"
    request = mission.get("slice", {}).get("user_outcome") if intact else None
    from .proof_worklog import applied_change_projection, bound_candidate_context

    applied_changes = {
        "state": "unavailable",
        "reason": "completion_receipt_invalid" if not intact else "baseline_unbound",
        "baseline_oid": None,
        "head_oid": None,
        "candidate_sha256": None,
        "binding_sha256": None,
        "changes": [],
        "unrelated_dirty_paths": [],
        "rationale": None,
    }
    if intact:
        baseline, candidate_root, declared_paths, baseline_files, binding_sha256 = (
            bound_candidate_context(
                workspace,
                Path(receipt["mission"]["path"]),
                mission,
                receipt["mission"]["sha256"],
                _budget=applied_budget,
            )
        )
        if baseline and candidate_root:
            manifest = []
            manifest_valid = True
            for item in summary.get("source_manifest", []):
                source_path = _workspace_path(workspace, Path(item["path"]))
                try:
                    relative = source_path.relative_to(candidate_root).as_posix()
                except ValueError:
                    manifest_valid = False
                    break
                if relative not in declared_paths:
                    manifest_valid = False
                    break
                manifest.append({"path": relative, "sha256": item["sha256"]})
            if manifest_valid and manifest:
                applied_changes = applied_change_projection(
                    candidate_root,
                    baseline,
                    manifest,
                    request,
                    candidate_sha256=summary.get("candidate_sha256"),
                    baseline_files=baseline_files,
                    _budget=applied_budget,
                    _snapshot_out=applied_snapshot,
                )
                applied_changes["binding_sha256"] = binding_sha256
            else:
                applied_changes["reason"] = "candidate_manifest_does_not_match_binding"
    core = {
        "schema": "factory.completion-card.v1",
        "status": status,
        "headline": {
            "COMPLETE": "Declared checks recorded; human review remains",
            "INCOMPLETE": "More evidence is needed",
            "INVALID": "Evidence changed; refresh the checks",
        }[status],
        "requested_behavior": request,
        "source_receipt": source.relative_to(workspace).as_posix(),
        "source_receipt_sha256": digest,
        "completion_sha256": receipt.get("completion_sha256"),
        "candidate_sha256": summary.get("candidate_sha256"),
        "integrity_valid": intact,
        "local_execution_observed": summary.get("local_execution_observed") is True,
        "independent_execution_verified": summary.get("execution_verified") is True,
        "signer_claims_verified": summary.get("attestation_verified") is True,
        "required_criteria": len(
            mission.get("completion_contract", {}).get("criteria", [])
        )
        if intact
        else None,
        "cases": _completion_card_cases(summary),
        "files_checked": [item["path"] for item in summary.get("source_manifest", [])],
        "applied_changes": applied_changes,
        "actual_diff": (
            f"Applied-change projection: {applied_changes['state']} ({applied_changes['reason'] or 'source bytes and Git baseline checked'})."
        ),
        "unfinished": list(
            dict.fromkeys(
                [
                    *summary.get("gaps", []),
                    *verification.get("errors", []),
                ]
            )
        ),
        "unexamined_scope": summary.get("scope_limitations", []),
        "human_review": [
            "Confirm the requested behavior matches what users need.",
            "Review the actual diff and scenarios not covered by the recorded checks.",
            "Review deployment, permissions and live behavior before any release.",
        ],
        "next_action": "Review the remaining human checks before release."
        if complete
        else "Run the missing checks and refresh this local summary."
        if intact
        else "Re-run verification for the current sources, then refresh this summary.",
        "privacy": "Local details include task text and relative paths; this is not a share card.",
        "authority": {
            "share": False,
            "approval": False,
            "merge": False,
            "publication": False,
            "deployment": False,
        },
        "scope_limit": "Current receipt evidence only; not independent correctness or production certification.",
    }
    return {**core, "card_sha256": _sha(core)}


def _completion_card_text(value: object) -> str:
    text = escape(str(value)).replace("\n", " ").replace("\r", " ")
    for character in ("\\", "`", "[", "]", "(", ")", "*", "_", "#", "!", "|"):
        text = text.replace(character, "\\" + character)
    return text


def _completion_card_markdown(card: dict[str, Any]) -> str:
    text = _completion_card_text
    lines = [
        "# Local completion summary",
        "",
        f"## {card['headline']}",
        "",
        f"Status: **{card['status']}**",
        "",
        "### What was requested",
        "",
        text(
            card["requested_behavior"] or "No current mission request is established."
        ),
        "",
        "### What the checks observed",
        "",
    ]
    lines.extend(
        f"- {text(row['case_id'])}: Expected: {text(row['expected'])}. "
        f"Observed: {text(row['observed'])} ({text(row['disposition'])}). "
        f"Input digest: {text(row['input_sha256'] or 'not established')}."
        for row in card["cases"]
    )
    if not card["cases"]:
        lines.append("No current executed cases are established by this receipt.")
    for title, items in (
        ("Files checked", card["files_checked"]),
        ("Unfinished work", card["unfinished"]),
        ("Unexamined scope", card["unexamined_scope"]),
        ("Human review", card["human_review"]),
    ):
        lines.extend(["", f"### {title}", ""])
        lines.extend(f"- {text(item)}" for item in items)
        if not items:
            lines.append(
                "No items recorded; this does not establish complete coverage."
            )
    projection = card.get("applied_changes", {})
    lines.extend(["", "### Applied changes", ""])
    if projection.get("state") != "available":
        lines.append(
            f"Applied changes unavailable: {text(projection.get('reason') or 'projection_unavailable')}."
        )
    else:
        lines.append(f"Baseline: `{text(projection.get('baseline_oid'))}`")
        lines.append(f"Candidate: `{text(projection.get('candidate_sha256'))}`")
        lines.append(
            f"Declared rationale: {text(projection.get('rationale') or 'not declared')}"
        )
        for change in projection.get("changes", []):
            before = change.get("before_sha256") or "absent"
            after = change.get("after_sha256") or "absent"
            lines.append(
                f"- {text(change['kind'])} `{text(change.get('old_path') or change['path'])}`"
                + (f" → `{text(change['path'])}`" if change.get("old_path") else "")
                + f": {text(change['disposition'])}; before {text(before)}; after {text(after)}."
            )
        lines.extend(
            f"- Unrelated dirty path: `{text(path)}`"
            for path in projection.get("unrelated_dirty_paths", [])
        )
        if not projection.get("changes") and not projection.get(
            "unrelated_dirty_paths"
        ):
            lines.append("No Git changes were found from the explicit baseline.")
    lines.extend(
        [
            "",
            card["actual_diff"],
            "",
            f"Next action: {card['next_action']}",
            "",
            card["privacy"],
            "",
            card["scope_limit"],
            "",
        ]
    )
    return "\n".join(lines)


def completion_card_from_receipt(
    root: Path, receipt_path: Path, out_dir: Path
) -> dict[str, Any]:
    """Render a fresh local mission view, separately from privacy-safe share cards."""
    from .product_missions import MISSION_COMPLETION_SCHEMA

    workspace = Path(root).resolve()
    source = _workspace_path(workspace, receipt_path)
    receipt, digest = _completion_card_json(source)
    if receipt.get("schema") != MISSION_COMPLETION_SCHEMA:
        raise AdoptionError(
            "E_COMPLETION_CARD_SOURCE", "a mission completion receipt is required"
        )
    mission_path, verification, mission, mission_digest = (
        _verified_completion_card_inputs(workspace, source, receipt, digest)
    )
    from .proof_worklog import _new_applied_change_budget

    applied_budget = _new_applied_change_budget()
    applied_snapshot = {}
    card = _completion_card_facts(
        workspace,
        source,
        receipt,
        digest,
        verification,
        mission,
        applied_budget,
        applied_snapshot,
    )
    markdown = _completion_card_markdown(card)
    _recheck_completion_card_projection(
        workspace,
        source,
        digest,
        mission_path,
        mission_digest,
        mission,
        receipt,
        verification,
        card,
        applied_snapshot,
        applied_budget,
    )
    destination = _workspace_path(workspace, out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    stem = f"completion-card-{card['card_sha256'][:12]}"
    paths = {
        "json": destination / f"{stem}.json",
        "markdown": destination / f"{stem}.md",
    }
    _atomic_json(paths["json"], card)
    paths["markdown"].write_text(markdown, encoding="utf-8")
    return {
        "card": card,
        "markdown": markdown,
        "paths": {key: str(path) for key, path in paths.items()},
    }


def _verified_completion_card_inputs(workspace, source, receipt, digest):
    """Read mission inputs and verify source bytes stayed stable during loading."""
    from .product_missions import verify_mission_completion

    try:
        mission_path = _completion_card_inputs(workspace, receipt)
        verification = verify_mission_completion(source)
        mission, mission_digest = _completion_card_json(mission_path)
    except (KeyError, TypeError, ValueError) as exc:
        raise AdoptionError(
            "E_COMPLETION_CARD_SOURCE", f"mission evidence cannot be read: {exc}"
        ) from exc
    if _completion_card_json(source)[1] != digest:
        raise AdoptionError(
            "E_COMPLETION_CARD_DRIFT", "completion receipt changed during rendering"
        )
    if (
        verification.get("integrity_valid")
        and mission_digest != receipt["mission"]["sha256"]
    ):
        raise AdoptionError(
            "E_COMPLETION_CARD_DRIFT", "mission changed during rendering"
        )
    return mission_path, verification, mission, mission_digest


def _recheck_completion_card_projection(
    workspace,
    source,
    digest,
    mission_path,
    mission_digest,
    mission,
    receipt,
    verification,
    card,
    applied_snapshot,
    applied_budget,
):
    """Recheck all candidate binding and byte facts before saving a card."""
    from .product_missions import verify_mission_completion
    from .proof_worklog import (
        _verify_applied_change_snapshot,
        bound_candidate_context,
    )

    applied = card.get("applied_changes", {})
    if applied.get("state") != "available":
        return
    (
        baseline,
        candidate_root,
        _declared,
        baseline_files,
        binding_sha256,
    ) = bound_candidate_context(
        workspace,
        mission_path,
        mission,
        receipt["mission"]["sha256"],
        _budget=applied_budget,
    )
    if (
        baseline != applied.get("baseline_oid")
        or binding_sha256 != applied.get("binding_sha256")
        or baseline_files != applied_snapshot.get("value", {}).get("baseline_files")
    ):
        raise AdoptionError(
            "E_COMPLETION_CARD_DRIFT", "candidate binding changed during rendering"
        )
    final_verification = verify_mission_completion(source)
    if not _completion_card_candidate_is_current(
        source,
        digest,
        mission_path,
        mission_digest,
        final_verification,
        applied,
    ):
        raise AdoptionError(
            "E_COMPLETION_CARD_DRIFT", "candidate changed during rendering"
        )
    try:
        _verify_applied_change_snapshot(
            candidate_root, applied_snapshot["value"], applied_budget
        )
    except (KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        raise AdoptionError(
            "E_COMPLETION_CARD_DRIFT",
            "applied-change snapshot changed during rendering",
        ) from exc


def _completion_card_candidate_is_current(
    source, digest, mission_path, mission_digest, verification, applied
):
    """Confirm receipt, mission, and candidate digest still match the card."""
    return (
        _completion_card_json(source)[1] == digest
        and _completion_card_json(mission_path)[1] == mission_digest
        and verification.get("integrity_valid")
        and verification.get("daily_verification", {}).get("candidate_sha256")
        == applied.get("candidate_sha256")
    )


def record_adoption_event(
    root: Path,
    milestone: str,
    *,
    evidence_sha256: str | None = None,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Append one allowlisted, identity-free local activation milestone."""
    if milestone not in MILESTONES:
        raise AdoptionError(
            "E_ADOPTION_MILESTONE",
            f"milestone must be one of {', '.join(sorted(MILESTONES))}",
        )
    if evidence_sha256 is not None and not _SHA256.fullmatch(evidence_sha256):
        raise AdoptionError(
            "E_ADOPTION_EVIDENCE", "evidence_sha256 must be a lowercase SHA-256 digest"
        )
    core = {
        "schema": ADOPTION_EVENT_SCHEMA,
        "milestone": milestone,
        "observed_at": _iso(observed_at),
        "evidence_sha256": evidence_sha256,
        "privacy": "local aggregate milestone only; no project, path, prompt, log, command, user, or provider identity",
    }
    event = {**core, "event_sha256": _sha(core)}
    stamp = core["observed_at"].replace(":", "").replace("-", "")
    path = (
        Path(root).resolve()
        / ".factory"
        / "adoption"
        / "events"
        / f"{stamp}-{milestone}-{event['event_sha256'][:12]}.json"
    )
    _atomic_json(path, event)
    return {"event": event, "path": str(path)}


def _load_events(root: Path) -> list[dict[str, Any]]:
    directory = Path(root).resolve() / ".factory" / "adoption" / "events"
    events: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")) if directory.is_dir() else []:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AdoptionError(
                "E_ADOPTION_EVENT_INVALID", f"cannot read adoption event: {exc}"
            ) from exc
        if not isinstance(value, dict) or set(value) != {
            "schema",
            "milestone",
            "observed_at",
            "evidence_sha256",
            "privacy",
            "event_sha256",
        }:
            raise AdoptionError(
                "E_ADOPTION_EVENT_INVALID", "adoption event shape changed"
            )
        core = {key: value[key] for key in value if key != "event_sha256"}
        if (
            value["schema"] != ADOPTION_EVENT_SCHEMA
            or value["milestone"] not in MILESTONES
            or value["event_sha256"] != _sha(core)
        ):
            raise AdoptionError(
                "E_ADOPTION_EVENT_INVALID", "adoption event is malformed or tampered"
            )
        events.append(value)
    return events


def adoption_status(root: Path) -> dict[str, Any]:
    """Aggregate verified local milestones while preserving unknown provider facts."""
    events = _load_events(root)
    counts = {
        milestone: sum(event["milestone"] == milestone for event in events)
        for milestone in sorted(MILESTONES)
    }
    first = min((event["observed_at"] for event in events), default=None)
    last = max((event["observed_at"] for event in events), default=None)
    return {
        "schema": ADOPTION_STATUS_SCHEMA,
        "measurement": "local_opt_in_events_only",
        "events": len(events),
        "first_observed_at": first,
        "last_observed_at": last,
        "milestones": counts,
        "funnel": {
            "page_visit": None,
            "install": None,
            "first_proof": counts["first_proof_completed"],
            "proof_receipt_saved": counts["proof_receipt_saved"],
            "proof_card_saved": counts["proof_card_saved"],
            "seven_day_return": counts["seven_day_return"],
        },
        "unknown_reason": "Page visits and installs are provider metrics. Local events are not users, conversions, or causal attribution.",
        "privacy": "No central transmission; no project, path, prompt, log, command, user, or provider identity.",
    }


def export_adoption_status(root: Path, out: Path) -> dict[str, Any]:
    """Write the privacy-bounded local activation aggregate inside the workspace."""
    workspace = Path(root).resolve()
    path = _workspace_path(workspace, out)
    payload = adoption_status(workspace)
    _atomic_json(path, payload)
    # The export is intentionally safe to paste into an issue or dashboard.
    # Return the workspace-relative artifact reference rather than disclosing
    # the caller's absolute checkout path on POSIX or Windows.
    return {"status": payload, "path": path.relative_to(workspace).as_posix()}


SCHEMA = "factory.deep-repository-audit.v1"


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded).hexdigest()


def _lane(
    measurement_id: str,
    *,
    state: str,
    applicable: bool,
    result: Any = None,
    basis: str,
    next_action: str,
    denominator_state: str = "DECLARED",
) -> dict[str, Any]:
    measurement_state = {
        "PASS": "MEASURED",
        "HEALTHY": "MEASURED",
        "CLEAN": "MEASURED",
        "OBSERVED": "MEASURED",
        "NOT_APPLICABLE": "NOT_APPLICABLE",
        "NOT_RUN": "NOT_MEASURED",
        "INCOMPLETE": "NOT_MEASURED",
        "BLOCKED": "BLOCKED",
        "INVALID": "BLOCKED",
        "REVIEW_REQUIRED": "REVIEW_REQUIRED",
    }.get(state, "NOT_MEASURED")
    return {
        "measurement_id": measurement_id,
        "state": state,
        "measurement_state": measurement_state,
        "applicability_state": "APPLICABLE" if applicable else "NOT_APPLICABLE",
        "denominator_state": denominator_state,
        "basis": basis,
        "result": result,
        "next_action": next_action,
    }


def _safe(call: Callable[[], Any], *, error_action: str) -> tuple[Any, str | None]:
    try:
        return call(), None
    except Exception as exc:  # analyzers must not hide a failed lane
        return {
            "state": "INVALID",
            "message": _analyzer_failure_message(exc),
        }, error_action


def _analyzer_failure_message(error):
    """Expose bounded analyzer input errors without serializing arbitrary failures."""
    from .review_audits import ReviewAuditError

    message = "Analyzer failed: " + type(error).__name__
    if isinstance(error, ReviewAuditError):
        detail = " ".join(str(error).split())[:500]
        if detail:
            message += ": " + detail
    return message


def _manifest_paths(root: Path) -> list[str]:
    names = (
        "pyproject.toml",
        "requirements.txt",
        "requirements.lock",
        "poetry.lock",
        "uv.lock",
        "Pipfile.lock",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "go.mod",
        "go.sum",
        "Cargo.toml",
        "Cargo.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "Gemfile.lock",
    )
    ignored = {".git", ".factory", ".venv", "venv", "node_modules", "dist", "build"}
    found: list[str] = []
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in ignored and not (Path(directory) / name).is_symlink()
        )
        for name in sorted(filenames):
            path = Path(directory) / name
            if name in names and not path.is_symlink():
                found.append(path.relative_to(root).as_posix())
    return sorted(found)


def _receipt_inventory(
    root: Path, *, patterns: tuple[str, ...]
) -> list[dict[str, Any]]:
    """Inventory bounded worker receipts without treating presence as proof."""
    evidence_root = root / ".factory"
    if not evidence_root.is_dir():
        return []
    rows: list[dict[str, Any]] = []
    from .deep_audit_io import local_file

    for path in evidence_root.rglob("*"):
        if not any(path.match(pattern) for pattern in patterns) or not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        try:
            verified_path = local_file(root, relative)
            with verified_path.open("rb") as stream:
                payload = stream.read(16 * 1024 * 1024 + 1)
        except (OSError, UnicodeError, ValueError):
            continue
        if len(payload) > 16 * 1024 * 1024:
            continue
        parsed_schema = None
        if path.suffix.lower() == ".json":
            try:
                parsed = json.loads(payload.decode("utf-8"))
                if isinstance(parsed, dict):
                    parsed_schema = parsed.get("schema")
            except (UnicodeError, json.JSONDecodeError):
                parsed_schema = None
        rows.append(
            {
                "path": relative,
                "sha256": sha256(payload).hexdigest(),
                "schema": parsed_schema,
                "verification": "PRESENT_UNVERIFIED",
            }
        )
        if len(rows) >= 256:
            break
    return sorted(rows, key=lambda row: row["path"])


def _state_for_findings(
    result: dict[str, Any], *, clean: str = "PASS", advisory_findings: bool = False
) -> str:
    if result.get("state") in {"BLOCKED", "INVALID"}:
        return "BLOCKED"
    if str(result.get("state", "")).upper() in {
        "INCOMPLETE",
        "NOT_RUN",
        "INSUFFICIENT_EVIDENCE",
    }:
        return "INCOMPLETE"
    if result.get("decision") == "REVIEW_REQUIRED":
        return "REVIEW_REQUIRED"
    if result.get("findings"):
        return "REVIEW_REQUIRED" if advisory_findings else "BLOCKED"
    if result.get("regressions"):
        return "BLOCKED"
    return clean


def _python_audit_lanes(
    workspace: Path,
    python_count: int,
    tenant_contract: str,
    oracle_options: dict[str, str] | None = None,
    max_files: int | None = None,
) -> list[dict[str, Any]]:
    lanes: list[dict[str, Any]] = []
    if python_count:
        from .review_audits import (
            load_tenant_read_contract,
            security_evals,
            security_scan,
        )

        try:
            calls, bindings, contract = load_tenant_read_contract(
                workspace, tenant_contract
            )
            security = security_scan(
                workspace,
                max_files=max_files,
                tenant_read_calls=tuple(calls),
                tenant_read_bindings=tuple(bindings),
                tenant_read_scopes=contract.get("scoped_reads"),
                tenant_policy_applies=contract.get("policy_applies", False),
                **(oracle_options or {}),
            )
            security_state = _state_for_findings(
                security,
                clean=security.get("state", "INVALID"),
                advisory_findings=True,
            )
        except Exception as exc:
            security = {
                "state": "INVALID",
                "message": _analyzer_failure_message(exc),
            }
            security_state = "BLOCKED"
        lanes.append(
            _lane(
                "python_ast_security",
                state=security_state,
                applicable=True,
                result=security,
                basis=f"Python AST security, hollow-test, tenant-contract and alias-aware checks over the {max_files or MAX_SECURITY_SOURCE_FILES}-file scanner boundary.",
                next_action=security.get(
                    "action_summary", "Resolve Python security or test-oracle findings."
                ),
                denominator_state="MEASURED"
                if security_state != "BLOCKED"
                else "DECLARED",
            )
        )
        evals, error = _safe(
            security_evals,
            error_action="Repair the scanner self-evaluation fixtures and rerun.",
        )
        if error:
            evals["next_action"] = error
        lanes.append(
            _lane(
                "scanner_self_evaluation",
                state="PASS" if evals.get("state") == "PASS" else "BLOCKED",
                applicable=True,
                result=evals,
                basis="Adversarial and safe-control fixtures for scanner rule behavior; separate from repository findings.",
                next_action=evals.get(
                    "action_summary", "Repair failed scanner self-evaluations."
                ),
            )
        )
    else:
        lanes.extend(
            [
                _lane(
                    "python_ast_security",
                    state="NOT_APPLICABLE",
                    applicable=False,
                    basis="No Python source was discovered.",
                    next_action="Run a language-specific security lane for each detected non-Python language.",
                    denominator_state="MEASURED",
                ),
                _lane(
                    "scanner_self_evaluation",
                    state="NOT_APPLICABLE",
                    applicable=False,
                    basis="Python scanner self-evaluation is not applicable without Python source.",
                    next_action="Use the applicable language-specific verifier suite.",
                    denominator_state="MEASURED",
                ),
            ]
        )

    return lanes


def _native_worker_lane(
    workspace: Path, config: str | None, applicable: bool
) -> dict[str, Any]:
    """Execute authorized native worker plans discovered in the workspace."""
    action = "Configure .factory/native-worker-config.json with a signed execution manifest, authorization and pinned trust root."
    default_config = workspace / ".factory/native-worker-config.json"
    if config is None and (default_config.exists() or default_config.is_symlink()):
        config = ".factory/native-worker-config.json"
    if config is None:
        return _lane(
            "native_worker_execution",
            state="NOT_RUN" if applicable else "NOT_APPLICABLE",
            applicable=applicable,
            basis="Isolated native scanners require explicit signed authorization.",
            next_action=action,
        )
    from .deep_audit import scan_deep_audit
    from .deep_audit_io import LIMIT, local_file, strict_json
    from .runtime_audit_common import require_digest

    def execute() -> dict:
        path = local_file(workspace, config)
        with path.open("rb") as stream:
            raw = stream.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError("Worker configuration exceeds byte budget")
        settings = strict_json(raw)
        required = {
            "manifest",
            "manifest_sha256",
            "authorization",
            "trust_root",
            "trust_root_sha256",
        }
        if set(settings) != required:
            raise ValueError(
                "Worker configuration fields do not match the execution contract"
            )
        return scan_deep_audit(
            workspace,
            local_file(workspace, settings["manifest"]),
            require_digest(settings["manifest_sha256"], "manifest_sha256"),
            authorization=local_file(workspace, settings["authorization"]),
            trust_root=local_file(workspace, settings["trust_root"]),
            trust_root_sha256=require_digest(
                settings["trust_root_sha256"], "trust_root_sha256"
            ),
        )

    result, error = _safe(execute, error_action=action)
    state = "BLOCKED" if error else "INCOMPLETE"
    if not error and result.get("analysis_complete") is True:
        state = "REVIEW_REQUIRED"
    return _lane(
        "native_worker_execution",
        state=state,
        applicable=True,
        result=result,
        basis="Signed manifest and authorization checked by the existing isolated Docker worker engine.",
        next_action=action
        if error
        else "Inspect native gaps and repairs; obtain independent agent review for this run before release.",
    )


def _candidate_inventory_lane(
    inventory: dict[str, Any], source_count: int
) -> dict[str, Any]:
    truncated = inventory.get("files_truncated")
    return _lane(
        "candidate_inventory",
        state="PASS" if source_count and not truncated else "INCOMPLETE",
        applicable=True,
        result=inventory,
        basis="Bounded relative-path inventory with byte sizes and stable digest.",
        next_action=(
            "Resolve an empty or truncated candidate inventory before trusting any lane."
            if not source_count or truncated
            else "Inventory is bound; continue through every applicable lane."
        ),
        denominator_state="MEASURED",
    )


def _architecture_health_lane(workspace: Path) -> dict[str, Any]:
    policy_path = workspace / "architecture-policy.json"
    if not policy_path.is_file():
        return _lane(
            "architecture_health",
            state="NOT_APPLICABLE",
            applicable=False,
            basis="No architecture-policy.json was supplied by this repository.",
            next_action="Add a reviewed architecture policy if architecture budgets are required.",
            denominator_state="UNDECLARED",
        )
    from .architecture_health import evaluate_architecture_health

    result, error = _safe(
        lambda: evaluate_architecture_health(workspace, policy_path, strict=True),
        error_action="Repair the architecture policy or runner error, then rerun.",
    )
    if error:
        result["next_action"] = error
    return _lane(
        "architecture_health",
        state=_state_for_findings(result, clean=result.get("decision", "INVALID")),
        applicable=True,
        result=result,
        basis="Strict architecture budgets, file-size guards, boundaries, changelog and cadence policy.",
        next_action=result.get("next_action", "Resolve architecture findings."),
    )


def _pattern_guard_path_lane(workspace: Path, source_count: int) -> dict[str, Any]:
    review_policy = workspace / ".factory" / "review-audits.json"
    if not review_policy.is_file():
        return _lane(
            "pattern_and_guard_path_audit",
            state="NOT_MEASURED",
            applicable=bool(source_count),
            basis="No .factory/review-audits.json manifest was supplied.",
            next_action="Create a project review-audits manifest before treating pattern coverage as measured.",
            denominator_state="UNDECLARED",
        )
    from .review_audits import audit_code

    result, error = _safe(
        lambda: audit_code(workspace, ".factory/review-audits.json", tool="all"),
        error_action="Repair or bind the project review-audits manifest, then rerun.",
    )
    if error:
        result["next_action"] = error
    return _lane(
        "pattern_and_guard_path_audit",
        state=_state_for_findings(result),
        applicable=True,
        result=result,
        basis="Manifest-bound patterns and guard paths; unlisted paths are not silently counted as clean.",
        next_action=result.get(
            "next_action", "Resolve each pattern or guard-path finding."
        ),
    )


def _non_python_security_lane(workspace: Path, languages: list[str]) -> dict[str, Any]:
    non_python = [name for name in languages if name not in {"python", "docs"}]
    receipts = _receipt_inventory(
        workspace,
        patterns=(
            "*.sarif",
            "*codeql*.json",
            "*semgrep*.json",
            "*gitleaks*.json",
            "*trivy*.json",
        ),
    )
    return _lane(
        "non_python_security",
        state="NOT_MEASURED" if non_python else "NOT_APPLICABLE",
        applicable=bool(non_python),
        result={"receipts": receipts, "verification": "UNVERIFIED"},
        basis="The bundled AST lane does not cover non-Python source languages.",
        next_action=(
            "Run and verify language-specific CodeQL/Semgrep or equivalent worker receipts for: "
            + ", ".join(non_python)
            if non_python
            else "No non-Python source was discovered."
        ),
        denominator_state="UNMEASURED" if non_python else "MEASURED",
    )


def _documentation_integrity_lane(
    documentation_count: int,
) -> dict[str, Any]:
    applicable = bool(documentation_count)
    return _lane(
        "documentation_integrity",
        state="NOT_MEASURED" if applicable else "NOT_APPLICABLE",
        applicable=applicable,
        result={"files_discovered": documentation_count},
        basis="Documentation was inventoried separately from executable source; links, examples and product claims need explicit documentation checks.",
        next_action=(
            "Run canonical-document, link, example and claim-boundary checks for the documentation set."
            if applicable
            else "No supported documentation files were discovered."
        ),
        denominator_state="UNMEASURED" if applicable else "MEASURED",
    )


def _workflow_integrity_lane(workspace: Path) -> dict[str, Any]:
    workflow_dir = workspace / ".github" / "workflows"
    if not workflow_dir.is_dir() or not list(workflow_dir.glob("*.y*ml")):
        return _lane(
            "workflow_integrity",
            state="NOT_APPLICABLE",
            applicable=False,
            basis="No GitHub workflow files were discovered.",
            next_action="Declare a CI profile if external workflow integrity is in scope.",
            denominator_state="MEASURED",
        )
    from .workflow_audit import audit_action_pins

    result, error = _safe(
        lambda: audit_action_pins(workspace),
        error_action="Repair workflow evidence and rerun.",
    )
    if error:
        result["next_action"] = error
    return _lane(
        "workflow_integrity",
        state=_state_for_findings(result),
        applicable=True,
        result=result,
        basis="GitHub workflow syntax and immutable action/container reference pinning.",
        next_action=result.get(
            "next_action", "Pin every workflow action to an immutable revision."
        ),
    )


def _requirement_runtime_lanes(
    workspace: Path, code_count: int
) -> list[dict[str, Any]]:
    from .attribution import requirement_coverage
    from .runtime_coverage import read_runtime_coverage_report

    requirement = requirement_coverage(workspace)
    applies = bool(requirement.get("applicable"))
    requirement_lane = _lane(
        "requirement_to_test_coverage",
        state=(
            "PASS"
            if requirement.get("status") == "complete"
            else "NOT_APPLICABLE"
            if not applies
            else "INCOMPLETE"
        ),
        applicable=applies,
        result=requirement,
        basis="Requirement manifest to non-hollow smoke-test mapping when an app blueprint declares it.",
        next_action=(
            "Resolve uncovered requirements."
            if applies
            else "No app requirement manifest declared."
        ),
        denominator_state="MEASURED" if applies else "UNDECLARED",
    )

    runtime = read_runtime_coverage_report(workspace, include_files=True)
    runtime_state = (
        "PASS"
        if runtime.get("state") == "OBSERVED"
        and runtime.get("receipt_status") == "VERIFIED"
        else "NOT_MEASURED"
        if runtime.get("state") == "NOT_RUN"
        else "INCOMPLETE"
    )
    runtime_lane = _lane(
        "runtime_coverage",
        state=runtime_state,
        applicable=bool(code_count),
        result=runtime,
        basis="Hash-bound Coverage.py statement and branch evidence; runtime counts do not prove correctness.",
        next_action="Run the project tests with the documented coverage profile and bind a clean receipt.",
        denominator_state=(
            "MEASURED" if runtime.get("state") == "OBSERVED" else "UNMEASURED"
        ),
    )
    return [requirement_lane, runtime_lane]


def _supply_chain_lane(workspace: Path) -> dict[str, Any]:
    manifests = _manifest_paths(workspace)
    receipts = _receipt_inventory(
        workspace,
        patterns=(
            "*.sbom.json",
            "*osv*.json",
            "*supply-chain*.json",
            "*provenance*.json",
        ),
    )
    has_manifests = bool(manifests)
    return _lane(
        "dependencies_and_supply_chain",
        state="NOT_MEASURED" if has_manifests else "NOT_APPLICABLE",
        applicable=has_manifests,
        result={
            "manifests": manifests,
            "worker_receipts": receipts,
            "verification": "UNVERIFIED",
        },
        basis="Dependency manifests were inventoried; advisory, SBOM and provenance workers require explicit receipts.",
        next_action=(
            "Generate a pinned SBOM and run OSV/advisory/provenance workers."
            if has_manifests
            else "No supported dependency manifest was discovered."
        ),
        denominator_state="UNMEASURED" if has_manifests else "MEASURED",
    )


def _native_domain_projection(lanes: list[dict[str, Any]]) -> dict[str, Any]:
    """Project fresh engine output, never receipt filenames, into bounded domains."""
    execution = next(
        row.get("result") or {}
        for row in lanes
        if row["measurement_id"] == "native_worker_execution"
    )
    domains = []
    findings = []
    for family in (
        "static",
        "secrets",
        "configuration",
        "dependencies",
        "runtime",
        "fuzz",
    ):
        workers = [
            row for row in execution.get("lanes", []) if row.get("family") == family
        ]
        observed = [
            row
            for row in workers
            if row.get("state") == "OBSERVED" and not row.get("gaps")
        ]
        current = bool(execution.get("candidate_sha256")) and not any(
            row.get("code")
            in {"SOURCE_CHANGED_DURING_RUN", "CANDIDATE_DRIFT", "SNAPSHOT_DRIFT"}
            for row in execution.get("gaps", [])
        )
        state = (
            "REVIEW_REQUIRED"
            if observed and len(observed) == len(workers) and current
            else "INCOMPLETE"
            if workers
            else "NOT_RUN"
        )
        domains.append(
            _lane(
                "native_" + family,
                state=state,
                applicable=True,
                result={
                    "workers": workers,
                    "observed_workers": len(observed) if current else 0,
                    "run_id": execution.get("run_id"),
                    "candidate_sha256": execution.get("candidate_sha256"),
                    "manifest_sha256": execution.get("manifest_sha256"),
                    "execution_gaps": execution.get("gaps", []),
                    "source_current": current,
                    "authority": "none",
                },
                basis="Validated native execution observations cover only the recorded paths and obligations; not whole-domain approval.",
                next_action="Review findings and worker coverage/challenge gaps; supply missing source-bound obligations and rerun affected workers.",
                denominator_state="SCOPED" if observed and current else "UNMEASURED",
            )
        )
        for worker in workers:
            findings.extend(
                {
                    **finding,
                    "family": family,
                    "engine": worker["engine"],
                    "candidate_sha256": execution.get("candidate_sha256"),
                    "run_id": execution.get("run_id"),
                    "source_current": current,
                    "worker_state": worker["state"],
                    "report_sha256": worker.get("report_sha256"),
                }
                for finding in worker.get("findings", [])
            )
    targets = {
        "dependencies": "dependencies_and_supply_chain",
        "runtime": "runtime_coverage",
    }
    for family, target in targets.items():
        lane = next(row for row in lanes if row["measurement_id"] == target)
        domain = next(
            row for row in domains if row["measurement_id"] == "native_" + family
        )
        lane["result"]["native_observations"] = domain
    return {"domains": domains, "findings": findings, "authority": "none"}


def _deep_audit_report(
    lanes: list[dict[str, Any]],
    python_count: int,
    languages: list[str],
    max_files: int | None = None,
) -> dict[str, Any]:
    applicable = [lane for lane in lanes if lane["applicability_state"] == "APPLICABLE"]
    blocked = [lane for lane in applicable if lane["measurement_state"] == "BLOCKED"]
    unmeasured = [
        lane for lane in applicable if lane["measurement_state"] == "NOT_MEASURED"
    ]
    review_required = [
        lane for lane in applicable if lane["measurement_state"] == "REVIEW_REQUIRED"
    ]
    measured = [lane for lane in applicable if lane["measurement_state"] == "MEASURED"]
    state = (
        "BLOCKED"
        if blocked
        else "INCOMPLETE"
        if unmeasured or review_required
        else "PASS"
    )
    report = {
        "schema": SCHEMA,
        "state": state,
        "scope": {
            "root": ".",
            "python_source_limit": max_files or MAX_SECURITY_SOURCE_FILES,
            "python_source_discovered": python_count,
            "languages": languages,
        },
        "lanes": lanes,
        "native_domains": _native_domain_projection(lanes),
        "coverage": {
            "applicable": len(applicable),
            "measured": len(measured),
            "blocked": len(blocked),
            "unmeasured": len(unmeasured),
            "review_required": len(review_required),
            "not_applicable": len(lanes) - len(applicable),
            "audit_rate": round(len(measured) / len(applicable), 4)
            if applicable
            else None,
        },
        "claim_boundary": "Full local orchestration of available evidence lanes; not a penetration test, runtime certification, or release approval.",
        "next_actions": [
            lane["next_action"] for lane in [*blocked, *unmeasured, *review_required]
        ],
    }
    report["audit_sha256"] = _digest(
        {key: value for key, value in report.items() if key != "audit_sha256"}
    )
    return report


def _observed_native_lane(recorder, name, operation):
    from .operations import measured_span

    attributes = {"operation": name}
    try:
        with measured_span(recorder, name, attributes=attributes) as parent_id:
            result = operation()
            attributes["result_sha256"] = _digest(result)
            rows = result if isinstance(result, list) else [result]
            for row in rows:
                recorder.span(
                    row["measurement_id"],
                    parent_span_id=parent_id,
                    attributes={
                        "kind": "lane_result_observation",
                        "result_sha256": _digest(row),
                        "lane_state": row["state"],
                    },
                )
        return rows
    except Exception as exc:
        failed = _lane(
            name,
            state="BLOCKED",
            applicable=True,
            basis=_analyzer_failure_message(exc),
            next_action="Repair the failed local analyzer and rerun its affected checks.",
        )
        recorder.span(
            name + ".failure",
            parent_span_id=recorder._active.get(),
            status="ERROR",
            attributes={
                "kind": "lane_result_observation",
                "result_sha256": _digest(failed),
                "lane_state": "BLOCKED",
            },
        )
        return [failed]


def run_deep_repository_audit(
    root: Path,
    inventory: dict[str, Any],
    *,
    tenant_contract: str = ".factory/tenant-read-contract.json",
    worker_config: str | None = None,
    oracle_options: dict[str, str] | None = None,
    max_files: int | None = None,
) -> dict[str, Any]:
    """Run all applicable local audit lanes and return an evidence map."""
    workspace = Path(root).resolve()
    from .review_audits import _validate_source_file_limit

    max_files = _validate_source_file_limit(max_files)
    file_types = inventory.get("file_types", {})
    python_count = int(file_types.get("python", 0))
    oracle_options = _validated_oracle_options(oracle_options, python_count)
    source_count = inventory.get("files_discovered", 0)
    code_count = sum(
        int(count) for name, count in file_types.items() if name not in {"docs"}
    )
    languages = [name for name, count in file_types.items() if count]
    from .operations import TelemetryRecorder, measured_span

    recorder = TelemetryRecorder("local-workspace", service="factory.scan")
    operations = [
        ("inventory", lambda: _candidate_inventory_lane(inventory, source_count)),
        ("architecture", lambda: _architecture_health_lane(workspace)),
        ("pattern_guard", lambda: _pattern_guard_path_lane(workspace, source_count)),
        (
            "python",
            lambda: _python_audit_lanes(
                workspace, python_count, tenant_contract, oracle_options, max_files
            ),
        ),
        ("languages", lambda: _non_python_security_lane(workspace, languages)),
        (
            "documentation",
            lambda: _documentation_integrity_lane(int(file_types.get("docs", 0))),
        ),
        ("workflows", lambda: _workflow_integrity_lane(workspace)),
        ("runtime", lambda: _requirement_runtime_lanes(workspace, code_count)),
        ("supply_chain", lambda: _supply_chain_lane(workspace)),
        (
            "workers",
            lambda: _native_worker_lane(workspace, worker_config, bool(code_count)),
        ),
    ]
    lanes = []
    with measured_span(recorder, "repository_audit"):
        for name, operation in operations:
            lanes.extend(_observed_native_lane(recorder, name, operation))
    report = _deep_audit_report(lanes, python_count, languages, max_files)
    report["telemetry"] = {
        "schema": "factory.scan-telemetry.v1",
        "trace_id": recorder.trace_id,
        "spans": recorder.spans,
        "scope": "Observed local orchestration; nested external worker internals are separate evidence.",
    }
    report["audit_sha256"] = _digest(
        {key: value for key, value in report.items() if key != "audit_sha256"}
    )
    return report


def _scan_security_and_deep_audit(
    workspace: Path,
    inventory: dict[str, Any],
    deep: bool,
    worker_config: str | None,
    oracle_options: dict[str, str] | None = None,
    max_files: int | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None, str | None]:
    if not deep:
        return (
            _scan_static_security(workspace, inventory, oracle_options, max_files),
            None,
            None,
        )
    try:
        deep_audit = run_deep_repository_audit(
            workspace,
            inventory,
            worker_config=worker_config,
            oracle_options=oracle_options,
            max_files=max_files,
        )
        static_security = next(
            (
                lane.get("result") or {}
                for lane in deep_audit["lanes"]
                if lane["measurement_id"] == "python_ast_security"
            ),
            {
                "state": "NOT_RUN",
                "findings": [],
                "audit_coverage": {"measurement_state": "not_run"},
            },
        )
        if not static_security:
            static_security = _scan_static_security(
                workspace, inventory, oracle_options, max_files
            )
        return static_security, deep_audit, None
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        return (
            {
                "state": "INVALID",
                "findings": [],
                "audit_coverage": {"measurement_state": "invalid"},
            },
            None,
            _analyzer_failure_message(exc),
        )


def _scan_static_security(
    workspace: Path,
    inventory: dict[str, Any],
    oracle_options: dict[str, str] | None = None,
    max_files: int | None = None,
) -> dict[str, Any]:
    python_count = int(inventory.get("file_types", {}).get("python", 0))
    if not python_count:
        return {
            "state": "NO_SOURCES",
            "findings": [],
            "audit_coverage": {"measurement_state": "not_applicable"},
            "action_summary": "No eligible Python sources were found; no static security conclusions were drawn.",
        }
    try:
        from .review_audits import load_tenant_read_contract, security_scan

        calls, bindings, contract = load_tenant_read_contract(
            workspace, ".factory/tenant-read-contract.json"
        )
        return security_scan(
            workspace,
            max_files=max_files,
            tenant_read_calls=tuple(calls),
            tenant_read_bindings=tuple(bindings),
            tenant_read_scopes=contract.get("scoped_reads"),
            tenant_policy_applies=contract.get("policy_applies", False),
            **(oracle_options or {}),
        )
    except Exception as exc:
        return {
            "state": "INVALID",
            "message": _analyzer_failure_message(exc),
            "findings": [],
            "audit_coverage": {"measurement_state": "invalid"},
        }


def _repo_scan_state(
    deep_audit: dict[str, Any] | None,
    static_security: dict[str, Any],
    deep: bool,
    inventory: dict[str, Any],
) -> tuple[str, str]:
    if any(
        finding.get("severity") in {"CRITICAL", "HIGH"}
        for finding in static_security.get("findings", [])
    ):
        return "BLOCKED", "BLOCKED"
    if deep_audit is not None:
        state = deep_audit["state"]
        return state, state
    findings = static_security.get("findings", [])
    if static_security.get("state") in {"BLOCKED", "INVALID"}:
        return "BLOCKED", "BLOCKED"
    if findings:
        return "INCOMPLETE", "INCOMPLETE"
    if static_security.get("regressions"):
        return "BLOCKED", "BLOCKED"
    return "INCOMPLETE", "INCOMPLETE"


def _validated_oracle_options(
    options: dict[str, str] | None,
    python_count: int,
) -> dict[str, str]:
    """Reject silently unused or partial oracle evidence before orchestration."""
    if not options:
        return {}
    required = {
        "oracle_evidence",
        "oracle_trust_root",
        "oracle_trust_sha256",
        "oracle_environment_sha256",
    }
    if set(options) != required or any(
        not isinstance(value, str) or not value.strip() for value in options.values()
    ):
        raise ValueError(
            "Runtime oracle evidence requires all four nonempty oracle options"
        )
    if not python_count:
        raise ValueError("Runtime oracle evidence requires Python sources in the scan")
    return dict(options)


def run_repo_scan(
    root: Path,
    *,
    deep: bool = True,
    worker_config: str | None = None,
    oracle_options: dict[str, str] | None = None,
    max_files: int | None = None,
) -> dict[str, Any]:
    """Run every local audit lane unless explicitly restricted to static checks.

    This is intentionally an honest first verdict: static evidence can block a
    workspace, but a clean result remains incomplete until the project supplies
    applicable runtime/test evidence.
    """
    if worker_config is not None and not deep:
        raise ValueError("--worker-config requires --deep")
    from .review_audits import _validate_source_file_limit

    max_files = _validate_source_file_limit(max_files)
    workspace = Path(root).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    from .ops_telemetry import _measure_phase

    with _measure_phase("source_inventory"):
        inventory = _workspace_inventory(workspace)
    oracle_options = _validated_oracle_options(
        oracle_options, int(inventory.get("file_types", {}).get("python", 0))
    )
    from .pytest_collection_audit import advisory_collection_context

    with (
        _measure_phase("source_audit"),
        advisory_collection_context(not oracle_options),
    ):
        static_security, deep_audit, security_error = _scan_security_and_deep_audit(
            workspace, inventory, deep, worker_config, oracle_options, max_files
        )
    state, verdict = _repo_scan_state(deep_audit, static_security, deep, inventory)
    next_actions = (
        list(deep_audit["next_actions"])
        if deep_audit is not None
        else [
            "Run applicable workers and bind clean, commit-scoped receipts before treating the result as complete.",
            "Review every finding and unmeasured lane before making a merge or release decision.",
        ]
    )
    if any(
        finding.get("code") == "SECURITY_TENANT_READ_UNDECLARED"
        for finding in static_security.get("findings", [])
    ):
        next_actions.insert(
            0,
            "Review the observed potential ORM read for tenant scope; if tenant isolation applies, declare it in .factory/tenant-read-contract.json and bind its tenant scope.",
        )
    result = {
        "schema": "factory.repo-scan.v1",
        "state": state,
        "verdict": verdict,
        "assessment": inventory,
        "static_security": static_security,
        "deep_audit": deep_audit,
        "evidence_limits": [
            "Inventory and Python AST findings are local observations, not runtime coverage or certification.",
            "The default scan runs all applicable local audit lanes and discovers authorized workspace workers; --static-only explicitly restricts the scope. Every unmeasured lane remains visible.",
            "Tenant-read guidance follows a potential ORM read and asks whether tenant scope applies; framework imports alone are not a tenant contract.",
            "Tests, dependency analysis, runtime behavior, and deployment behavior require explicit project evidence and are not inferred.",
            "Deep orchestration is not a penetration test, runtime certification, or release approval.",
        ],
        "next_actions": next_actions,
    }
    if security_error:
        result["static_security_error"] = security_error
    result["scan_sha256"] = _sha(_scan_identity_projection(result))
    result["run_receipt_sha256"] = _sha(result)
    return result


def run_first_proof(
    root: Path, *, out_dir: Path | None = None, observed_at: datetime | None = None
) -> dict[str, Any]:
    """Run an explicit sandbox proof that demonstrates a hollow negative check."""
    workspace = Path(root).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    instant = _utc(observed_at)
    run_id = instant.strftime("first-proof-%Y%m%dT%H%M%SZ")
    destination = _workspace_path(
        workspace, out_dir or Path(".factory/adoption/first-proof") / run_id
    )
    destination.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema": "factory.e2e_proof_manifest.v1",
        "id": run_id,
        "approval": {"state": "approved", "approved_by": "local-first-proof-user"},
        "working_directory": ".",
        "timeout_seconds": 30,
        "network_egress": "not_granted",
        "positive": {"argv": [sys.executable, "-c", "raise SystemExit(0)"]},
        "negative": {"argv": [sys.executable, "-c", "raise SystemExit(0)"]},
        "artifact_paths": [],
    }
    manifest_path = destination / "first-proof.manifest.json"
    _atomic_json(manifest_path, manifest)
    proof = verify_e2e_proof(workspace, manifest_path)
    if proof["marker"] != "HOLLOW_E2E_TEST":
        raise AdoptionError(
            "E_FIRST_PROOF_UNEXPECTED",
            "sandbox first proof did not detect the deliberately hollow check",
        )
    proof_artifacts = write_e2e_proof_artifacts(proof, destination / "evidence")
    card_artifacts = write_proof_card(proof, destination / "share")
    for milestone in (
        "first_proof_completed",
        "proof_receipt_saved",
        "proof_card_saved",
    ):
        evidence = (
            proof["receipt_sha256"]
            if milestone != "proof_card_saved"
            else card_artifacts["card"]["card_sha256"]
        )
        record_adoption_event(
            workspace, milestone, evidence_sha256=evidence, observed_at=instant
        )
    assessment = _workspace_inventory(workspace)
    core = {
        "schema": FIRST_PROOF_SCHEMA,
        "observed_at": _iso(instant),
        "demo": True,
        "marker": "HOLLOW_TEST_DETECTED",
        "assessment": assessment,
        "proof_receipt_sha256": proof["receipt_sha256"],
        "proof_card_sha256": card_artifacts["card"]["card_sha256"],
        "scope_limits": [
            "The sandbox demonstration is separate from the bounded workspace inventory; it does not execute or certify the caller's project.",
            "The inventory records only relative file names and byte sizes. It is not a source, runtime, dependency, or security assessment.",
            "The generated Proof Card omits commands, paths, repository name, prompts, logs, and user identity.",
            "No network, approval, merge, release, publication, deployment, signing, credential, connector, or message authority is granted.",
        ],
    }
    activation = {**core, "receipt_sha256": _sha(core)}
    activation_path = _atomic_json(destination / "activation.json", activation)
    return {
        "activation": activation,
        "activation_path": str(activation_path),
        "proof": {key: value for key, value in proof.items() if key != "_captures"},
        "proof_artifacts": proof_artifacts,
        "proof_card": card_artifacts,
        "adoption_status": adoption_status(workspace),
    }
