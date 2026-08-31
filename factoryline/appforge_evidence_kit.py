"""Guided, fail-closed local evidence kit for AppForge iOS submissions.

The kit removes JSON ceremony without manufacturing evidence.  It creates
candidate-bound templates and a novice-readable worklist; every template is
deliberately incomplete until a human supplies observed local evidence.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import hashlib
import json

from .app_review_gate import RULES
from .appforge_quality_audit import CONDITIONAL_CHECKS, DESIGN_CHECKS, STACK_CHECKS
from .revenue_evidence import _atomic_json
from .revenueforge import AUTHORITY, RevenueForgeError


CANDIDATE_SCHEMA = "factory.appforge.release-candidate.v1"
RECEIPT_SCHEMA = "factory.appforge.evidence-kit-receipt.v1"
MAX_INPUT_BYTES = 1_048_576
CANDIDATE_KEYS = ("bundle_identifier", "version", "build_number", "source_commit")
IPHONE_JOURNEYS = (
    "first_value", "core_action", "result", "privacy_control", "error_recovery",
    "offline_recovery", "settings", "accessibility", "purchase", "restore",
)
IPAD_JOURNEYS = ("landing", "core_workspace", "result")


def _local(root: Path, path: Path, *, must_exist: bool = True) -> Path:
    workspace = Path(root).resolve()
    resolved = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise RevenueForgeError("APPFORGE_EVIDENCE_KIT_PATH_REJECTED", "paths must remain inside the workspace") from exc
    if must_exist and not resolved.is_file():
        raise RevenueForgeError("APPFORGE_EVIDENCE_KIT_INPUT_UNAVAILABLE", "input must be a regular workspace file")
    return resolved


def _text(value: object, field: str) -> str:
    result = str(value or "").strip()
    if not result or len(result) > 300:
        raise RevenueForgeError("APPFORGE_EVIDENCE_KIT_CANDIDATE_INVALID", f"{field} must be a non-empty bounded string")
    return result


def _read_candidate(root: Path, path: Path) -> tuple[dict[str, str], Path]:
    source = _local(root, path)
    if source.stat().st_size > MAX_INPUT_BYTES:
        raise RevenueForgeError("APPFORGE_EVIDENCE_KIT_INPUT_TOO_LARGE", "candidate input exceeds 1 MiB")
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RevenueForgeError("APPFORGE_EVIDENCE_KIT_INPUT_INVALID", "candidate input must be valid JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != CANDIDATE_SCHEMA or not isinstance(value.get("candidate"), dict):
        raise RevenueForgeError("APPFORGE_EVIDENCE_KIT_SCHEMA_REJECTED", f"candidate input must use {CANDIDATE_SCHEMA}")
    return ({key: _text(value["candidate"].get(key), f"candidate.{key}") for key in CANDIDATE_KEYS}, source)


def _conditional_templates(items: tuple[str, ...]) -> dict[str, dict[str, str]]:
    return {
        item: {
            "status": "REPLACE_WITH_required_OR_not_applicable",
            "reviewed_by": "REPLACE_WITH_NAMED_REVIEWER",
            "rationale": "REPLACE_WITH_A_CONCRETE_RATIONALE_OF_AT_LEAST_20_CHARACTERS",
        }
        for item in items
    }


def _write_readme(path: Path, candidate: dict[str, str], design_input: Path, design_sha: str) -> None:
    lines = [
        "# AppForge iOS evidence kit",
        "",
        "## What this kit does",
        "",
        "This kit binds every later check to one candidate and one user design input. It does **not** run a device, generate screenshots, access credentials, upload to Apple, submit to App Review, or claim approval.",
        "",
        "## Candidate",
        "",
        f"- Bundle identifier: `{candidate['bundle_identifier']}`",
        f"- Version/build: `{candidate['version']} ({candidate['build_number']})`",
        f"- Source commit: `{candidate['source_commit']}`",
        f"- User design input: `{design_input.as_posix()}` (`{design_sha}`)",
        "",
        "## Do these in order",
        "",
        "1. Read `WORKLIST.md`. Replace every `REPLACE_WITH...` value only with an observed fact or a named human decision.",
        "2. Collect real iPhone and iPad captures. This product kit asks for 10 iPhone journeys and 3 iPad 13-inch journeys; this is a product-quality bundle, not Apple’s global screenshot minimum.",
        "3. Run the App Review, Store media, SaaS, and quality gates. A blocked receipt is useful: fix the named gap rather than editing the receipt.",
        "4. Run `factory revenue submission-assurance` only after all four receipts are ready. It writes the final Markdown/PDF dossier only then.",
        "",
        "## Authority boundary",
        "",
        "Only a named human can authorize a later Apple handoff. Keep credentials outside this kit; use references such as a keychain item or environment-variable name only.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def _write_worklist(path: Path) -> None:
    checks = [*DESIGN_CHECKS, *STACK_CHECKS, *CONDITIONAL_CHECKS]
    lines = [
        "# AppForge evidence worklist",
        "",
        "Every item below needs a real, candidate-bound artifact. Do not mark an item passed because source code exists or an agent predicted the result.",
        "",
        "## App Review and reviewer access",
        "",
        "- [ ] Classify each conditional App Review rule with a named reviewer and concrete rationale.",
        "- [ ] Record real current-build outcomes for all required App Review checks.",
        "- [ ] Hash review notes and reviewer-access instructions; never place credentials in a receipt.",
        "",
        "## Store media",
        "",
        "- [ ] 10 distinct iPhone journeys, each from an allowed real capture source.",
        "- [ ] 3 distinct 13-inch iPad journeys: landing, core workspace, and result.",
        "- [ ] Named product/design confirmation that captures represent the candidate and storyboard.",
        "",
        "## Strict design, accessibility, and full-stack audit",
        "",
    ]
    lines.extend(f"- [ ] {check.replace('_', ' ')}" for check in checks)
    lines.extend([
        "",
        "## Final dossier",
        "",
        "- [ ] All four gate receipts are hash-valid and bound to the same candidate.",
        "- [ ] Named release owner has checked support, privacy, review notes, and reviewer-access packets.",
        "- [ ] Generate Markdown/PDF dossier. This still does not submit to Apple.",
        "",
    ])
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def initialize_appforge(
    root: Path,
    out_dir: Path,
    *,
    app_name: str,
    bundle_identifier: str,
    version: str,
    build_number: str,
    source_commit: str,
    audience: str,
    primary_job: str,
    desired_emotion: str,
) -> dict[str, Any]:
    """Capture user-supplied AppForge mission inputs into a safe local start."""
    workspace = Path(root).resolve()
    candidate = {
        "bundle_identifier": _text(bundle_identifier, "bundle_identifier"),
        "version": _text(version, "version"),
        "build_number": _text(build_number, "build_number"),
        "source_commit": _text(source_commit, "source_commit"),
    }
    mission = {
        "app_name": _text(app_name, "app_name"),
        "audience": _text(audience, "audience"),
        "primary_job": _text(primary_job, "primary_job"),
        "desired_emotion": _text(desired_emotion, "desired_emotion"),
    }
    destination = _local(workspace, out_dir, must_exist=False)
    if destination.exists():
        raise RevenueForgeError("APPFORGE_INIT_OUTPUT_EXISTS", "AppForge init destination already exists; choose a new app-and-build directory")
    destination.mkdir(parents=True, exist_ok=False)
    candidate_file = destination / "release-candidate.json"
    design_file = destination / "user-design-input.md"
    brief_file = destination / "appforge-design-brief.json"
    next_file = destination / "NEXT.md"
    _atomic_json(candidate_file, {"schema": CANDIDATE_SCHEMA, "candidate": candidate})
    design_file.write_text(
        "# User design input\n\n"
        f"- App: {mission['app_name']}\n"
        f"- Audience: {mission['audience']}\n"
        f"- Primary job: {mission['primary_job']}\n"
        f"- Desired emotion: {mission['desired_emotion']}\n\n"
        "## User constraints and decisions\n\n"
        "Add the user's non-negotiable flows, content, accessibility needs, brand constraints, and explicit approval notes here before compiling the storyboard.\n",
        encoding="utf-8", newline="\n",
    )
    _atomic_json(brief_file, {**mission, "screens": [{"id": "landing", "user_goal": mission["primary_job"], "primary_action": "continue"}]})
    next_file.write_text(
        "# AppForge Init — next safe actions\n\n"
        "1. Edit `user-design-input.md` with the user's actual constraints and approval notes.\n"
        "2. Compile the storyboard: `factory revenue appforge-design --root . --brief appforge-design-brief.json --out-dir .factory/appforge/design --json`.\n"
        "3. Create the evidence workspace: `factory revenue evidence-kit --root . --candidate release-candidate.json --design-input user-design-input.md --out-dir .factory/appforge/evidence --json`.\n"
        "4. Collect real evidence. The kit is not a TestFlight upload or Apple submission action.\n",
        encoding="utf-8", newline="\n",
    )
    artifacts = {"candidate": candidate_file, "user_design_input": design_file, "design_brief": brief_file, "next": next_file}
    receipt: dict[str, Any] = {
        "schema": "factory.appforge.init-receipt.v1",
        "marker": "APPFORGE_INIT_WRITTEN",
        "ok": True,
        "action_summary": "Record the user-supplied app mission and exact release candidate, then write an AppForge start workspace and next safe actions; do not infer design decisions, collect evidence, access credentials, run devices, or submit to Apple.",
        "candidate": candidate,
        "mission": mission,
        "artifacts": {key: value.relative_to(workspace).as_posix() for key, value in artifacts.items()},
        "authority": {**AUTHORITY, "app_store_connect_write": False, "testflight_upload": False, "app_review_submit": False, "apple_approval_claim": False},
        "claim_boundary": "local user-input capture only; not a design approval, evidence receipt, TestFlight state, App Review submission, or Apple approval.",
    }
    receipt["receipt_sha256"] = hashlib.sha256(json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    receipt_file = destination / "appforge-init-receipt.json"
    _atomic_json(receipt_file, receipt)
    return {**receipt, "path": receipt_file.relative_to(workspace).as_posix()}


def appforge_init_projection(root: Path) -> dict[str, Any]:
    """Read hash-valid AppForge Init state without activating a project."""
    workspace = Path(root).resolve()
    current: list[dict[str, Any]] = []
    invalid: list[str] = []
    for path in sorted((workspace / ".factory" / "appforge").rglob("appforge-init-receipt.json"))[:100]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            supplied = value.pop("receipt_sha256", None)
            valid = (
                value.get("schema") == "factory.appforge.init-receipt.v1"
                and isinstance(supplied, str)
                and hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest() == supplied
            )
            if valid:
                current.append({"path": path.relative_to(workspace).as_posix(), "marker": value.get("marker"), "candidate": value.get("candidate"), "mission": value.get("mission"), "receipt_sha256": supplied})
            else:
                invalid.append(path.relative_to(workspace).as_posix())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            invalid.append(path.relative_to(workspace).as_posix())
    return {
        "schema": "factory.appforge.init-projection.v1",
        "marker": "APPFORGE_INIT_READ_ONLY",
        "current_count": len(current),
        "invalid_count": len(invalid),
        "latest": current[-1] if current else None,
        "invalid": invalid,
        "authority": {**AUTHORITY, "app_store_connect_write": False, "testflight_upload": False, "app_review_submit": False, "apple_approval_claim": False},
        "claim_boundary": "hash-verified local mission/candidate state only; not design approval, evidence, TestFlight, App Review, or Apple approval.",
    }


def create_evidence_kit(root: Path, candidate_path: Path, design_input_path: Path, out_dir: Path) -> dict[str, Any]:
    """Create safe templates for a human-reviewed AppForge evidence collection run."""
    workspace = Path(root).resolve()
    candidate, candidate_source = _read_candidate(workspace, candidate_path)
    design_source = _local(workspace, design_input_path)
    if design_source.stat().st_size > MAX_INPUT_BYTES:
        raise RevenueForgeError("APPFORGE_EVIDENCE_KIT_INPUT_TOO_LARGE", "design input exceeds 1 MiB")
    design_sha = hashlib.sha256(design_source.read_bytes()).hexdigest()
    destination = _local(workspace, out_dir, must_exist=False)
    if destination.exists():
        raise RevenueForgeError("APPFORGE_EVIDENCE_KIT_OUTPUT_EXISTS", "evidence kit destination already exists; choose a new candidate-scoped directory")
    destination.mkdir(parents=True, exist_ok=False)

    def write_json(name: str, value: dict[str, Any]) -> Path:
        path = destination / name
        _atomic_json(path, value)
        return path

    artifacts: dict[str, Path] = {}
    artifacts["candidate"] = write_json("release-candidate.json", {"schema": CANDIDATE_SCHEMA, "candidate": candidate})
    app_review_conditionals = tuple(key for key, _, mode, _, _ in RULES if mode == "conditional")
    artifacts["app_review_contract"] = write_json("app-review-contract.json", {"candidate": candidate, "applicability": _conditional_templates(app_review_conditionals)})
    artifacts["app_review_evidence"] = write_json("app-review-evidence.json", {"candidate": candidate, "checks": {key: False for key, *_ in RULES}})
    artifacts["store_media_contract"] = write_json("store-media-contract.json", {
        "schema": "factory.appforge.store-media-contract.v1", "candidate": candidate, "intent_sha256": design_sha, "require_no_alpha": True,
        "media_sets": [
            {"id": "iphone", "min_count": 10, "max_count": 10, "accepted_dimensions": [{"width": 1320, "height": 2868}, {"width": 1290, "height": 2796}], "required_journeys": list(IPHONE_JOURNEYS), "allowed_capture_sources": ["physical_device"]},
            {"id": "ipad_13", "min_count": 3, "max_count": 10, "accepted_dimensions": [{"width": 2064, "height": 2752}, {"width": 2048, "height": 2732}], "required_journeys": list(IPAD_JOURNEYS), "allowed_capture_sources": ["physical_device"]},
        ],
    })
    artifacts["store_media_evidence"] = write_json("store-media-evidence.json", {"schema": "factory.appforge.store-media-evidence.v1", "candidate": candidate, "intent_sha256": design_sha, "review": {"representative_confirmed_by": "REPLACE_WITH_NAMED_REVIEWER", "storyboard_confirmed_by": "REPLACE_WITH_NAMED_REVIEWER", "confirmed_at": "REPLACE_WITH_RFC3339_TIMESTAMP"}, "captures": []})
    artifacts["quality_contract"] = write_json("quality-contract.json", {"schema": "factory.appforge.quality-audit-contract.v1", "candidate": candidate, "user_design_input_sha256": design_sha, "conditional": _conditional_templates(CONDITIONAL_CHECKS)})
    artifacts["quality_evidence"] = write_json("quality-evidence.json", {"schema": "factory.appforge.quality-audit-evidence.v1", "candidate": candidate, "user_design_input_sha256": design_sha, "design_review": {"reviewed_by": "REPLACE_WITH_NAMED_REVIEWER", "reviewed_at": "REPLACE_WITH_RFC3339_TIMESTAMP", "user_design_input_considered": False, "storyboard_sha256": "REPLACE_WITH_REAL_STORYBOARD_SHA256"}, "checks": []})
    artifacts["assurance_contract"] = write_json("submission-assurance-contract.json", {"schema": "factory.appforge.submission-assurance-contract.v1", "candidate": candidate, "reviewer_packet": {"support_url": "REPLACE_WITH_REACHABLE_SUPPORT_URL", "privacy_url": "REPLACE_WITH_REACHABLE_PRIVACY_URL", "review_notes_sha256": "REPLACE_WITH_REAL_REVIEW_NOTES_SHA256", "reviewer_access_instructions_sha256": "REPLACE_WITH_REAL_ACCESS_INSTRUCTIONS_SHA256", "approved_by": "REPLACE_WITH_NAMED_RELEASE_OWNER", "approved_at": "REPLACE_WITH_RFC3339_TIMESTAMP"}})
    readme, worklist = destination / "README.md", destination / "WORKLIST.md"
    _write_readme(readme, candidate, design_source.relative_to(workspace), design_sha)
    _write_worklist(worklist)
    artifacts["readme"], artifacts["worklist"] = readme, worklist
    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "marker": "APPFORGE_EVIDENCE_KIT_WRITTEN",
        "ok": True,
        "action_summary": "Create a candidate-bound AppForge evidence worklist and deliberately incomplete local templates; do not infer evidence, access credentials, run devices, upload media, submit to Apple, or claim approval.",
        "candidate": candidate,
        "candidate_source_sha256": hashlib.sha256(candidate_source.read_bytes()).hexdigest(),
        "user_design_input": {"path": design_source.relative_to(workspace).as_posix(), "sha256": design_sha},
        "artifacts": {key: value.relative_to(workspace).as_posix() for key, value in artifacts.items()},
        "authority": {**AUTHORITY, "app_store_connect_write": False, "testflight_upload": False, "app_review_submit": False, "apple_approval_claim": False},
        "claim_boundary": "local setup kit only; the generated templates are not evidence and cannot establish App Review readiness, TestFlight completion, submission, or approval.",
    }
    receipt["receipt_sha256"] = hashlib.sha256(json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    _atomic_json(destination / "appforge-evidence-kit-receipt.json", receipt)
    return {**receipt, "path": (destination / "appforge-evidence-kit-receipt.json").relative_to(workspace).as_posix()}
