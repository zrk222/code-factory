"""Deterministic signal intake, Opinion Dock triage, and owner promotion.

External channel payloads are stored as untrusted data. This module has no
network client, scheduler, model provider, deployment, or messaging authority.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Iterable

from .product_missions import compile_product_text
from .failure_guidance import explain_failure


SIGNAL_SCHEMA = "factory.signal.v1"
SIGNAL_QUEUE_SCHEMA = "factory.signal.queue.v1"
OPINION_DOCK_SCHEMA = "factory.opinion_dock.v1"
TRIAGE_SCHEMA = "factory.signal.triage.v1"
OWNER_DECISION_SCHEMA = "factory.owner_decision.v1"
MAX_DOCK_LINES = 2000
MAX_RULES = 500
MAX_BODY_BYTES = 65536
SOURCES = {"manual", "github", "slack", "sentry", "social", "telemetry", "internal"}
AUTHORIZATIONS = {"owner_supplied", "connector_verified", "public_reference"}
DECISIONS = {"approved", "rejected", "deferred"}
FEEDBACK_SCHEMA = "factory.outcome-feedback.v1"


class SignalLoopError(ValueError):
    """A closed-class signal loop failure suitable for CLI attribution."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.guidance = explain_failure(code, message)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _sha_path(path: Path) -> str:
    return sha256(Path(path).read_bytes()).hexdigest()


def _slug(value: str, fallback: str = "signal") -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:56] or fallback


def _atomic_text(path: Path, text: str, *, replace: bool = False) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not replace:
        if path.read_text(encoding="utf-8") == text:
            return path
        raise SignalLoopError("ARTIFACT_EXISTS", f"refusing to replace {path}")
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return path


def _atomic_json(path: Path, value: object, *, replace: bool = False) -> Path:
    return _atomic_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n", replace=replace)


def _load(path: Path, schema: str, hash_field: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SignalLoopError("ARTIFACT_INVALID", f"cannot read {path}") from exc
    if value.get("schema") != schema:
        raise SignalLoopError("SCHEMA_INVALID", f"expected {schema}: {path}")
    core = {key: item for key, item in value.items() if key not in {hash_field, "generated_at", "path", "idempotent"}}
    if _sha(core) != value.get(hash_field):
        raise SignalLoopError("HASH_INVALID", f"content hash mismatch: {path}")
    return value


def _sealed(core: dict[str, Any], field: str) -> dict[str, Any]:
    return {**core, field: _sha(core), "generated_at": _now()}


def _default_rules() -> list[dict[str, Any]]:
    return [
        {
            "id": "external-effects-need-review",
            "kind": "architecture_guardrail",
            "statement": "Merge, deploy, publish, production writes, credentials, connectors, and external messages require human approval.",
            "match_any": ["merge", "deploy", "publish", "production", "credential", "connector", "external message"],
            "weight": 40,
            "action": "review",
            "active": True,
            "version": 1,
        },
        {
            "id": "security-work-needs-independent-proof",
            "kind": "domain_expertise",
            "statement": "Authentication, authorization, privacy, and secret handling require independent high-reasoning verification.",
            "match_any": ["authentication", "authorization", "privacy", "secret", "security"],
            "weight": 30,
            "action": "review",
            "active": True,
            "version": 1,
        },
    ]


def init_opinion_dock(root: Path, owner: str, *, force: bool = False) -> dict[str, Any]:
    """Create a compact owner-controlled cognitive anchor with no product guesses."""
    if not owner.strip() or len(owner) > 120:
        raise SignalLoopError("OWNER_INVALID", "owner is required and must be at most 120 characters")
    core = {
        "schema": OPINION_DOCK_SCHEMA,
        "version": 1,
        "owner": owner.strip(),
        "line_budget": MAX_DOCK_LINES,
        "rules": _default_rules(),
        "routing_profiles": {
            "economy": {"creator": "fast_generation", "verifier": "independent_standard_reasoning"},
            "balanced": {"creator": "balanced_generation", "verifier": "independent_high_reasoning"},
            "critical": {"creator": "high_reasoning", "verifier": "independent_high_reasoning"},
        },
        "corrections": [],
        "authority": {"triage": "advisory", "promotion": "product_owner", "external_effects": False},
        "markers": ["OPINION_DOCK_BOUND", "MODEL_ROUTING_ADVISORY_ONLY"],
    }
    dock = _sealed(core, "dock_sha256")
    path = Path(root).resolve() / ".factory" / "opinions" / "opinion_dock.json"
    _atomic_json(path, dock, replace=force)
    return {**dock, "path": str(path), "idempotent": False}


def verify_opinion_dock(path: Path) -> dict[str, Any]:
    """Verify an opinion dock's schema and sealed digest before routing signals."""
    dock = _load(path, OPINION_DOCK_SCHEMA, "dock_sha256")
    lines = len(Path(path).read_text(encoding="utf-8").splitlines())
    errors: list[str] = []
    if lines > MAX_DOCK_LINES:
        errors.append(f"Opinion Dock has {lines} lines; maximum is {MAX_DOCK_LINES}")
    if len(dock.get("rules", [])) > MAX_RULES:
        errors.append(f"Opinion Dock has more than {MAX_RULES} rules")
    if not dock.get("owner"):
        errors.append("Opinion Dock owner is missing")
    result = {
        "schema": "factory.opinion_dock.verification.v1",
        "valid": not errors,
        "lines": lines,
        "marker": "OPINION_DOCK_BOUND" if not errors else "OPINION_DOCK_LINE_BUDGET",
        "errors": errors,
    }
    if errors:
        result["failure"] = explain_failure("OPINION_DOCK_LINE_BUDGET", "; ".join(errors), errors=errors)
    return result


def _validated_rule(rule: dict[str, Any]) -> dict[str, Any]:
    required = {"id", "kind", "statement", "match_any", "weight", "action"}
    if required - set(rule):
        raise SignalLoopError("RULE_INVALID", f"missing fields: {', '.join(sorted(required - set(rule)))}")
    if not rule["id"] or len(str(rule["statement"])) > 1000:
        raise SignalLoopError("RULE_INVALID", "rule id is required and statement is limited to 1000 characters")
    if rule["action"] not in {"consider", "review", "block"}:
        raise SignalLoopError("RULE_INVALID", "rule action must be consider, review, or block")
    if not isinstance(rule["match_any"], list) or not all(isinstance(item, str) and item.strip() for item in rule["match_any"]):
        raise SignalLoopError("RULE_INVALID", "match_any must contain non-empty strings")
    if not isinstance(rule["weight"], int) or not 0 <= rule["weight"] <= 100:
        raise SignalLoopError("RULE_INVALID", "rule weight must be an integer from 0 through 100")
    return {
        "id": _slug(str(rule["id"]), "rule"),
        "kind": str(rule["kind"]),
        "statement": str(rule["statement"]).strip(),
        "match_any": sorted({str(item).strip().lower() for item in rule["match_any"]}),
        "weight": rule["weight"],
        "action": rule["action"],
        "active": bool(rule.get("active", True)),
    }


def correct_opinion_dock(path: Path, owner: str, rule: dict[str, Any], rationale: str) -> dict[str, Any]:
    """Upsert one rule while preserving a hash-linked corrective history."""
    dock = _load(path, OPINION_DOCK_SCHEMA, "dock_sha256")
    if owner.strip() != dock["owner"]:
        raise SignalLoopError("OWNER_MISMATCH", "only the Opinion Dock owner may record a correction")
    if not rationale.strip() or len(rationale) > 2000:
        raise SignalLoopError("RATIONALE_INVALID", "correction rationale is required and limited to 2000 characters")
    candidate = _validated_rule(rule)
    previous = next((item for item in dock["rules"] if item["id"] == candidate["id"]), None)
    candidate["version"] = (previous or {}).get("version", 0) + 1
    previous_hash = _sha(previous) if previous else None
    rules = [item for item in dock["rules"] if item["id"] != candidate["id"]] + [candidate]
    rules.sort(key=lambda item: item["id"])
    correction_core = {
        "rule_id": candidate["id"],
        "rule_version": candidate["version"],
        "previous_rule_sha256": previous_hash,
        "new_rule_sha256": _sha(candidate),
        "rationale": rationale.strip(),
        "owner": owner.strip(),
        "previous_correction_sha256": dock["corrections"][-1]["correction_sha256"] if dock["corrections"] else None,
    }
    correction = {**correction_core, "correction_sha256": _sha(correction_core), "recorded_at": _now()}
    core = {key: value for key, value in dock.items() if key not in {"dock_sha256", "generated_at"}}
    core.update({"version": dock["version"] + 1, "rules": rules, "corrections": [*dock["corrections"], correction]})
    updated = _sealed(core, "dock_sha256")
    rendered = json.dumps(updated, indent=2, sort_keys=True) + "\n"
    if len(rendered.splitlines()) > MAX_DOCK_LINES:
        raise SignalLoopError("OPINION_DOCK_LINE_BUDGET", f"correction would exceed {MAX_DOCK_LINES} lines")
    _atomic_text(path, rendered, replace=True)
    return {**updated, "path": str(Path(path).resolve()), "marker": "OPINION_CORRECTION_APPEND_ONLY"}


def _instruction_like(text: str) -> bool:
    patterns = ("ignore previous", "system prompt", "developer message", "run this command", "override your instructions")
    lowered = text.lower()
    return any(pattern in lowered for pattern in patterns)


def _signal_queue(root: Path) -> tuple[Path, dict[str, Any]]:
    path = Path(root).resolve() / ".factory" / "signals" / "queue.json"
    if not path.exists():
        return path, {"schema": SIGNAL_QUEUE_SCHEMA, "signals": []}
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != SIGNAL_QUEUE_SCHEMA or not isinstance(value.get("signals"), list):
        raise SignalLoopError("SIGNAL_QUEUE_INVALID", f"invalid signal queue: {path}")
    return path, value


def capture_signal(root: Path, *, source: str, title: str, body: str, authorization: str,
                   severity: int = 3, external_id: str | None = None, url: str | None = None,
                   observed_at: str | None = None, hypotheses: Iterable[str] = (),
                   requirements: Iterable[str] = (), outcomes: Iterable[str] = (),
                   acceptance: Iterable[str] = ()) -> dict[str, Any]:
    """Capture supplied channel content without polling or treating it as instructions."""
    if source not in SOURCES:
        raise SignalLoopError("SOURCE_INVALID", f"source must be one of {', '.join(sorted(SOURCES))}")
    if authorization not in AUTHORIZATIONS:
        raise SignalLoopError("AUTHORIZATION_INVALID", f"authorization must be one of {', '.join(sorted(AUTHORIZATIONS))}")
    if not title.strip() or len(title) > 240:
        raise SignalLoopError("TITLE_INVALID", "title is required and limited to 240 characters")
    body_bytes = body.encode("utf-8")
    if not body.strip() or len(body_bytes) > MAX_BODY_BYTES:
        raise SignalLoopError("BODY_INVALID", f"body is required and limited to {MAX_BODY_BYTES} UTF-8 bytes")
    if not isinstance(severity, int) or not 1 <= severity <= 5:
        raise SignalLoopError("SEVERITY_INVALID", "severity must be an integer from 1 through 5")
    content = {
        "source": source,
        "external_id": external_id,
        "title": title.strip(),
        "body": body,
        "hypotheses": [item.strip() for item in hypotheses if item.strip()],
        "requirements": [item.strip() for item in requirements if item.strip()],
        "outcomes": [item.strip() for item in outcomes if item.strip()],
        "acceptance": [item.strip() for item in acceptance if item.strip()],
    }
    content_sha = _sha(content)
    signal_id = f"sig-{_slug(title)[:32]}-{content_sha[:10]}"
    core = {
        "schema": SIGNAL_SCHEMA,
        "id": signal_id,
        "content": content,
        "severity": severity,
        "provenance": {
            "authorization": authorization,
            "observed_at": observed_at or _now(),
            "captured_at": _now(),
            "url": url,
            "content_sha256": content_sha,
        },
        "trust": {"classification": "untrusted_data", "execute_as_instructions": False, "instruction_like": _instruction_like(f"{title}\n{body}")},
        "authority": {"network": False, "external_message": False, "promotion": False},
        "markers": ["SIGNAL_NORMALIZED_LOCAL_ONLY", "SIGNAL_PROVENANCE_BOUND", "SIGNAL_DEDUP_HASHED"],
    }
    signal = _sealed(core, "signal_sha256")
    directory = Path(root).resolve() / ".factory" / "signals"
    path = directory / f"{signal_id}.json"
    if path.exists():
        existing = _load(path, SIGNAL_SCHEMA, "signal_sha256")
        return {**existing, "path": str(path), "idempotent": True}
    queue_path, queue = _signal_queue(root)
    _atomic_json(path, signal)
    queue["signals"] = [*queue["signals"], {"id": signal_id, "path": str(path), "signal_sha256": signal["signal_sha256"]}]
    queue["updated_at"] = _now()
    _atomic_json(queue_path, queue, replace=queue_path.exists())
    return {**signal, "path": str(path), "idempotent": False}


def capture_outcome_feedback(root: Path, *, mission_id: str, metric: str,
                             observed: float, target: float, evidence_path: Path) -> dict[str, Any]:
    """Close the local loop by turning measured outcome evidence into a signal."""
    root = Path(root).resolve()
    evidence = Path(evidence_path).resolve()
    try:
        evidence.relative_to(root)
    except ValueError as exc:
        raise SignalLoopError("EVIDENCE_OUTSIDE_ROOT", f"feedback evidence must be beneath {root}") from exc
    if not evidence.is_file():
        raise SignalLoopError("EVIDENCE_MISSING", f"feedback evidence not found: {evidence}")
    if not mission_id.strip() or not metric.strip():
        raise SignalLoopError("FEEDBACK_INPUT_INVALID", "mission id and metric are required")
    evidence_sha = _sha_path(evidence)
    signal = capture_signal(
        root,
        source="telemetry",
        title=f"Outcome feedback: {metric.strip()}",
        body=(
            f"Mission {mission_id.strip()} measured {metric.strip()}={observed}; "
            f"target={target}. Evidence SHA-256: {evidence_sha}."
        ),
        authorization="owner_supplied",
        severity=4 if observed < target else 2,
        external_id=f"outcome:{mission_id.strip()}:{metric.strip()}:{evidence_sha[:12]}",
        hypotheses=[f"A follow-up change can move {metric.strip()} from {observed} toward {target}."],
        outcomes=[f"Meet or exceed {target} for {metric.strip()}."],
    )
    core = {
        "schema": FEEDBACK_SCHEMA,
        "mission_id": mission_id.strip(),
        "metric": metric.strip(),
        "observed": observed,
        "target": target,
        "source_evidence": {"path": str(evidence), "sha256": evidence_sha},
        "signal": {"path": signal["path"], "signal_id": signal["id"], "signal_sha256": signal["signal_sha256"]},
        "markers": ["OUTCOME_FEEDBACK_SIGNAL_BOUND", "SIGNAL_LOOP_REENTERED_LOCAL_ONLY"],
        "authority": "local feedback capture only; no polling, triage approval, execution, or deployment authority",
    }
    receipt = _sealed(core, "feedback_sha256")
    path = root / ".factory" / "signals" / "feedback" / f"{_slug(mission_id)}-{_slug(metric)}.json"
    _atomic_json(path, receipt)
    return {**receipt, "path": str(path)}


def _rule_matches(rule: dict[str, Any], text: str) -> list[str]:
    return [needle for needle in rule.get("match_any", []) if needle.lower() in text]


def _routing_profile(score: int, blocked: bool, severity: int) -> str:
    if blocked or severity >= 5 or score >= 70:
        return "critical"
    if severity >= 3 or score >= 30:
        return "balanced"
    return "economy"


def triage_signal(signal_path: Path, dock_path: Path, root: Path, *, force: bool = False) -> dict[str, Any]:
    """Score one signal against explicit rules and preserve every contribution."""
    signal = _load(signal_path, SIGNAL_SCHEMA, "signal_sha256")
    dock_check = verify_opinion_dock(dock_path)
    if not dock_check["valid"]:
        raise SignalLoopError("OPINION_DOCK_LINE_BUDGET", "; ".join(dock_check["errors"]))
    dock = _load(dock_path, OPINION_DOCK_SCHEMA, "dock_sha256")
    text = "\n".join([signal["content"]["title"], signal["content"]["body"], *signal["content"]["requirements"]]).lower()
    contributions = []
    for rule in dock["rules"]:
        matches = _rule_matches(rule, text) if rule.get("active", True) else []
        if matches:
            contributions.append({"rule_id": rule["id"], "rule_version": rule["version"], "matches": matches, "points": rule["weight"], "action": rule["action"]})
    blocked = any(item["action"] == "block" for item in contributions)
    score = min(100, signal["severity"] * 10 + sum(item["points"] for item in contributions))
    profile = _routing_profile(score, blocked, signal["severity"])
    core = {
        "schema": TRIAGE_SCHEMA,
        "id": f"triage-{signal['id']}",
        "signal": {"path": str(Path(signal_path).resolve()), "sha256": signal["signal_sha256"]},
        "opinion_dock": {"path": str(Path(dock_path).resolve()), "sha256": dock["dock_sha256"], "version": dock["version"]},
        "score": score,
        "contributions": contributions,
        "recommended_decision": "blocked" if blocked else "consider",
        "routing": {"profile": profile, **dock["routing_profiles"][profile], "provider_invoked": False},
        "owner_decision": "required",
        "markers": ["TRIAGE_EXPLAINABLE", "OWNER_DECISION_REQUIRED", "MODEL_ROUTING_ADVISORY_ONLY", *(["HANDS_OFF_RULE_ENFORCED"] if blocked else [])],
    }
    triage = _sealed(core, "triage_sha256")
    path = Path(root).resolve() / ".factory" / "triage" / f"{signal['id']}.json"
    _atomic_json(path, triage, replace=force)
    return {**triage, "path": str(path)}


def decide_triage(triage_path: Path, root: Path, *, owner: str, decision: str,
                  rationale: str, override_block: bool = False, force: bool = False) -> dict[str, Any]:
    """Record a human-owned triage outcome, rejecting invalid or replayed decisions."""
    triage = _load(triage_path, TRIAGE_SCHEMA, "triage_sha256")
    dock = _load(Path(triage["opinion_dock"]["path"]), OPINION_DOCK_SCHEMA, "dock_sha256")
    if owner.strip() != dock["owner"]:
        raise SignalLoopError("OWNER_MISMATCH", "decision owner must match the Opinion Dock owner")
    if decision not in DECISIONS:
        raise SignalLoopError("DECISION_INVALID", f"decision must be one of {', '.join(sorted(DECISIONS))}")
    if not rationale.strip() or len(rationale) > 2000:
        raise SignalLoopError("RATIONALE_INVALID", "decision rationale is required and limited to 2000 characters")
    if decision == "approved" and triage["recommended_decision"] == "blocked" and not override_block:
        raise SignalLoopError("HANDS_OFF_RULE_ENFORCED", "blocked triage requires an explicit owner override")
    core = {
        "schema": OWNER_DECISION_SCHEMA,
        "id": f"decision-{triage['id']}",
        "triage": {"path": str(Path(triage_path).resolve()), "sha256": triage["triage_sha256"]},
        "signal": triage["signal"],
        "opinion_dock": triage["opinion_dock"],
        "owner": owner.strip(),
        "decision": decision,
        "rationale": rationale.strip(),
        "blocked_rule_override": bool(override_block),
        "authority": {"promote_to_product_graph": decision == "approved", "execute": False, "merge": False, "deploy": False},
        "markers": ["OWNER_DECISION_BOUND"],
    }
    result = _sealed(core, "decision_sha256")
    path = Path(root).resolve() / ".factory" / "decisions" / f"{triage['id']}.json"
    _atomic_json(path, result, replace=force)
    return {**result, "path": str(path)}


def _signal_prd(signal: dict[str, Any], decision: dict[str, Any]) -> str:
    content = signal["content"]
    outcomes = "\n".join(f"- {item}" for item in content["outcomes"]) or "- Product Owner must define a measurable outcome."
    requirements = "\n".join(f"- {item}" for item in content["requirements"]) or "- Product Owner must define testable requirements."
    acceptance = "\n\n".join(content["acceptance"]) or "Product Owner must supply at least one Gherkin scenario."
    hypotheses = "\n".join(f"- {item}" for item in content["hypotheses"]) or "- Validate whether this signal represents a repeatable user need."
    return f"""# {content['title']}

## Actors
- Product Owner: approved this signal for product specification.

## Outcomes
{outcomes}

## Hypotheses
{hypotheses}

## Requirements
{requirements}

## Acceptance
{acceptance}

## Signal provenance
- Signal ID: {signal['id']}
- Signal SHA-256: {signal['signal_sha256']}
- Owner decision SHA-256: {decision['decision_sha256']}

This draft grants no execution, merge, deployment, publication, connector, or external-message authority.
"""


def promote_signal(decision_path: Path, root: Path, *, project: str | None = None, force: bool = False) -> dict[str, Any]:
    """Promote only owner-approved supplied facts; expose missing product facts."""
    decision = _load(decision_path, OWNER_DECISION_SCHEMA, "decision_sha256")
    if decision["decision"] != "approved":
        raise SignalLoopError("OWNER_DECISION_REQUIRED", "only an approved signal may be promoted")
    signal = _load(Path(decision["signal"]["path"]), SIGNAL_SCHEMA, "signal_sha256")
    prd = _signal_prd(signal, decision)
    draft_path = Path(root).resolve() / ".factory" / "signals" / "prd-drafts" / f"{signal['id']}.md"
    _atomic_text(draft_path, prd, replace=force)
    complete = bool(signal["content"]["requirements"] and signal["content"]["acceptance"])
    if not complete:
        return {
            "schema": "factory.signal.promotion.v1",
            "status": "needs_input",
            "marker": "SIGNAL_SPEC_GAPS_EXPOSED",
            "prd_draft": str(draft_path),
            "missing": [name for name in ("requirements", "acceptance") if not signal["content"][name]],
            "authority": "draft only; no mission or external effect created",
        }
    graph = compile_product_text(
        prd,
        root=Path(root),
        source_name=draft_path.name,
        project=project or _slug(signal["content"]["title"]),
        force=force,
        bindings={"signal_sha256": signal["signal_sha256"], "owner_decision_sha256": decision["decision_sha256"]},
    )
    return {
        "schema": "factory.signal.promotion.v1",
        "status": graph["status"],
        "marker": "SIGNAL_TO_PRODUCT_GRAPH_BOUND",
        "prd_draft": str(draft_path),
        "graph": graph,
        "authority": "Product Graph only; mission execution still requires approval",
    }
