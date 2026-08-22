"""Local, privacy-bounded activation evidence and shareable Proof Cards.

The adoption surface deliberately avoids hosted analytics.  A first proof is
an explicit sandbox demonstration, not an assessment of the caller's project.
Proof Cards contain only verified receipt facts and never include commands,
paths, repository names, prompts, logs, or user identifiers.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from html import escape
import json
from pathlib import Path
import re
import sys
from typing import Any

from .e2e_proof import (
    E2EProofError,
    validate_e2e_proof_receipt,
    verify_e2e_proof,
    write_e2e_proof_artifacts,
)


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


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _utc(value: datetime | None = None) -> datetime:
    instant = value or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    return instant.astimezone(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _atomic_json(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
    return path


def _workspace_path(root: Path, path: Path) -> Path:
    workspace = Path(root).resolve()
    candidate = Path(path)
    resolved = candidate.resolve() if candidate.is_absolute() else (workspace / candidate).resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise AdoptionError("E_ADOPTION_PATH_ESCAPE", "adoption artifacts must stay inside the workspace") from exc
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
        "negative_case_rejected": validated["commands"]["negative"]["exit_code"] not in (None, 0),
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
  <desc id="desc">{escape(card['headline'])}. Privacy-safe summary of one verified local receipt.</desc>
  <rect width="1280" height="720" rx="36" fill="#f8fafc"/>
  <rect x="44" y="44" width="1192" height="632" rx="28" fill="#ffffff" stroke="#cbd5e1" stroke-width="3"/>
  <text x="92" y="118" font-family="Arial, sans-serif" font-size="24" font-weight="700" fill="#475569">CODE FACTORY · PROOF CARD</text>
  <text x="92" y="205" font-family="Arial, sans-serif" font-size="50" font-weight="800" fill="#0f172a">{escape(card['headline'])}</text>
  <rect x="92" y="260" width="500" height="126" rx="20" fill="#ecfeff" stroke="#a5f3fc"/>
  <text x="124" y="308" font-family="Arial, sans-serif" font-size="20" font-weight="700" fill="#475569">POSITIVE CHECK</text>
  <text x="124" y="358" font-family="Arial, sans-serif" font-size="34" font-weight="800" fill="#0f766e">{positive}</text>
  <rect x="620" y="260" width="500" height="126" rx="20" fill="#fff7ed" stroke="#fed7aa"/>
  <text x="652" y="308" font-family="Arial, sans-serif" font-size="20" font-weight="700" fill="#475569">DECLARED FAILURE CASE</text>
  <text x="652" y="358" font-family="Arial, sans-serif" font-size="34" font-weight="800" fill="{accent}">{negative}</text>
  <text x="92" y="468" font-family="Arial, sans-serif" font-size="23" fill="#334155">Outcome · {escape(card['outcome'])}</text>
  <text x="92" y="510" font-family="Arial, sans-serif" font-size="20" fill="#64748b">Receipt · {card['source_receipt_sha256'][:20]}…</text>
  <text x="92" y="550" font-family="Arial, sans-serif" font-size="20" fill="#64748b">No code, paths, prompts, logs, or identity included.</text>
  <line x1="92" y1="590" x2="1120" y2="590" stroke="#e2e8f0" stroke-width="2"/>
  <text x="92" y="632" font-family="Arial, sans-serif" font-size="18" fill="#64748b">One verified receipt · not a production-readiness certificate</text>
  <text x="1120" y="632" text-anchor="end" font-family="Arial, sans-serif" font-size="18" font-weight="700" fill="#2563eb">github.com/zrk222/code-factory</text>
</svg>
'''


def verify_proof_card(value: object) -> dict[str, Any]:
    """Validate the exact Proof Card schema, privacy flags, and canonical digest."""
    if not isinstance(value, dict) or value.get("schema") != PROOF_CARD_SCHEMA:
        raise AdoptionError("E_PROOF_CARD_INVALID", f"a {PROOF_CARD_SCHEMA} object is required")
    required = {
        "schema", "evidence_schema", "source_receipt_sha256", "marker", "outcome", "headline",
        "positive_check_passed", "negative_case_rejected", "hollow_test_detected", "privacy",
        "authority", "scope_limit", "card_sha256",
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
        raise AdoptionError("E_PROOF_CARD_INVALID", "Proof Card privacy boundary changed")
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


def proof_card_from_receipt(root: Path, receipt_path: Path, out_dir: Path) -> dict[str, Any]:
    """Create a Proof Card from a workspace-contained E2E receipt file."""
    workspace = Path(root).resolve()
    source = _workspace_path(workspace, receipt_path)
    if not source.is_file():
        raise AdoptionError("E_PROOF_CARD_SOURCE", "receipt must name a workspace-contained JSON file")
    try:
        receipt = json.loads(source.read_text(encoding="utf-8"))
        validate_e2e_proof_receipt(receipt)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, E2EProofError) as exc:
        raise AdoptionError("E_PROOF_CARD_SOURCE", f"receipt is not a valid E2E proof: {exc}") from exc
    return write_proof_card(receipt, _workspace_path(workspace, out_dir))


def record_adoption_event(
    root: Path,
    milestone: str,
    *,
    evidence_sha256: str | None = None,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Append one allowlisted, identity-free local activation milestone."""
    if milestone not in MILESTONES:
        raise AdoptionError("E_ADOPTION_MILESTONE", f"milestone must be one of {', '.join(sorted(MILESTONES))}")
    if evidence_sha256 is not None and not _SHA256.fullmatch(evidence_sha256):
        raise AdoptionError("E_ADOPTION_EVIDENCE", "evidence_sha256 must be a lowercase SHA-256 digest")
    core = {
        "schema": ADOPTION_EVENT_SCHEMA,
        "milestone": milestone,
        "observed_at": _iso(observed_at),
        "evidence_sha256": evidence_sha256,
        "privacy": "local aggregate milestone only; no project, path, prompt, log, command, user, or provider identity",
    }
    event = {**core, "event_sha256": _sha(core)}
    stamp = core["observed_at"].replace(":", "").replace("-", "")
    path = Path(root).resolve() / ".factory" / "adoption" / "events" / f"{stamp}-{milestone}-{event['event_sha256'][:12]}.json"
    _atomic_json(path, event)
    return {"event": event, "path": str(path)}


def _load_events(root: Path) -> list[dict[str, Any]]:
    directory = Path(root).resolve() / ".factory" / "adoption" / "events"
    events: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")) if directory.is_dir() else []:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AdoptionError("E_ADOPTION_EVENT_INVALID", f"cannot read adoption event: {exc}") from exc
        if not isinstance(value, dict) or set(value) != {
            "schema", "milestone", "observed_at", "evidence_sha256", "privacy", "event_sha256"
        }:
            raise AdoptionError("E_ADOPTION_EVENT_INVALID", "adoption event shape changed")
        core = {key: value[key] for key in value if key != "event_sha256"}
        if value["schema"] != ADOPTION_EVENT_SCHEMA or value["milestone"] not in MILESTONES or value["event_sha256"] != _sha(core):
            raise AdoptionError("E_ADOPTION_EVENT_INVALID", "adoption event is malformed or tampered")
        events.append(value)
    return events


def adoption_status(root: Path) -> dict[str, Any]:
    """Aggregate verified local milestones while preserving unknown provider facts."""
    events = _load_events(root)
    counts = {milestone: sum(event["milestone"] == milestone for event in events) for milestone in sorted(MILESTONES)}
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
    return {"status": payload, "path": str(path)}


def run_first_proof(root: Path, *, out_dir: Path | None = None, observed_at: datetime | None = None) -> dict[str, Any]:
    """Run an explicit sandbox proof that demonstrates a hollow negative check."""
    workspace = Path(root).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    instant = _utc(observed_at)
    run_id = instant.strftime("first-proof-%Y%m%dT%H%M%SZ")
    destination = _workspace_path(workspace, out_dir or Path(".factory/adoption/first-proof") / run_id)
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
        raise AdoptionError("E_FIRST_PROOF_UNEXPECTED", "sandbox first proof did not detect the deliberately hollow check")
    proof_artifacts = write_e2e_proof_artifacts(proof, destination / "evidence")
    card_artifacts = write_proof_card(proof, destination / "share")
    for milestone in ("first_proof_completed", "proof_receipt_saved", "proof_card_saved"):
        evidence = proof["receipt_sha256"] if milestone != "proof_card_saved" else card_artifacts["card"]["card_sha256"]
        record_adoption_event(workspace, milestone, evidence_sha256=evidence, observed_at=instant)
    core = {
        "schema": FIRST_PROOF_SCHEMA,
        "observed_at": _iso(instant),
        "demo": True,
        "marker": "HOLLOW_TEST_DETECTED",
        "proof_receipt_sha256": proof["receipt_sha256"],
        "proof_card_sha256": card_artifacts["card"]["card_sha256"],
        "scope_limits": [
            "This is a sandbox demonstration with an intentionally hollow negative command; it does not inspect or assess the caller's project.",
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
