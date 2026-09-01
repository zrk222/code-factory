"""Receipt-governed, local agent autonomy licenses.

The module deliberately measures only evidence which first passed the existing
run-admission boundary.  Agent and verifier subjects are declared identifiers,
not an external identity proof.  A License is locally hash-bound by default and
can be bound to a Receipt v2 DSSE envelope when a separate signing authority is
provided.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from .attribution import FailureClass


AGENT_IDENTITY_SCHEMA = "factory.agent-identity.v1"
AGENT_RUN_SCHEMA = "factory.agent-run.v1"
AGENT_LICENSE_SCHEMA = "factory.agent-license.v1"
AGENT_LICENSE_INCIDENT_SCHEMA = "factory.agent-license-incident.v1"
LICENSE_POLICY_SCHEMA = "factory.agent-license-policy.v1"
EVENT_DIR = Path(".factory") / "agent-licenses" / "events"
LICENSE_DIR = Path(".factory") / "agent-licenses" / "licenses"
INCIDENT_DIR = Path(".factory") / "agent-licenses" / "incidents"

EVIDENCE_TTL_DAYS = 30
SUPERVISED_MIN_CLEAN_RUNS = 3
AUTONOMOUS_MIN_CLEAN_RUNS = 20
AUTONOMOUS_MIN_INDEPENDENT_VERIFICATIONS = 15
POST_INCIDENT_REQUALIFICATION_RUNS = 5
SEVERE_FAILURES = frozenset({
    FailureClass.HOLLOW_TEST.value,
    FailureClass.HOLLOW_VALIDATOR.value,
    FailureClass.SCOPE_ESCAPE.value,
    FailureClass.ORACLE_WEAKENING.value,
})
AUTONOMY_RANK = {"human_controlled": 0, "supervised": 1, "autonomous": 2}
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,159}$")
_TASK_IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{0,95}$")
_AUTHORITY = {
    "execution": False,
    "approval": False,
    "repair": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


class AgentLicenseError(ValueError):
    """A stable, fail-closed license error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise AgentLicenseError("E_LICENSE_INPUT_INVALID", f"{field} must be RFC3339 text")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AgentLicenseError("E_LICENSE_INPUT_INVALID", f"{field} must be RFC3339 text") from exc
    if parsed.tzinfo is None:
        raise AgentLicenseError("E_LICENSE_INPUT_INVALID", f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _text(value: object, field: str, *, maximum: int = 160) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum:
        raise AgentLicenseError("E_LICENSE_INPUT_INVALID", f"{field} must be a non-empty string of at most {maximum} characters")
    return value.strip()


def _relative(root: Path, value: object, field: str) -> tuple[Path, str]:
    if isinstance(value, Path):
        text = str(value)
    else:
        text = _text(value, field, maximum=512)
    if not text.strip() or len(text.strip()) > 2048:
        raise AgentLicenseError("E_LICENSE_INPUT_INVALID", f"{field} must be a non-empty path")
    text = text.replace("\\", "/")
    candidate = Path(text)
    resolved_root = Path(root).resolve()
    resolved = candidate.resolve() if candidate.is_absolute() else (resolved_root / candidate).resolve()
    try:
        relative = resolved.relative_to(resolved_root).as_posix()
    except ValueError as exc:
        raise AgentLicenseError("E_LICENSE_PATH_OUT_OF_SCOPE", f"{field} must remain inside the workspace") from exc
    return resolved, relative


def _load_json(path: Path, *, code: str = "E_LICENSE_INPUT_UNREADABLE") -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentLicenseError(code, f"cannot read JSON: {path}") from exc
    if not isinstance(value, dict):
        raise AgentLicenseError(code, f"JSON must be an object: {path}")
    return value


def _file_binding(root: Path, value: object, field: str) -> dict[str, str]:
    path, relative = _relative(root, value, field)
    if not path.is_file():
        raise AgentLicenseError("E_LICENSE_EVIDENCE_MISSING", f"{field} must name an existing workspace file")
    return {"path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def normalize_agent_identity(value: object, field: str = "agent") -> dict[str, str]:
    """Normalize a declared, non-secret agent identity with a stable digest."""
    allowed = {"schema", "subject", "provider", "model", "identity_sha256"}
    if not isinstance(value, dict) or not {"schema", "subject", "provider", "model"}.issubset(value) or set(value) - allowed:
        raise AgentLicenseError("E_LICENSE_IDENTITY_INVALID", f"{field} must contain schema, subject, provider, and model")
    if value.get("schema") != AGENT_IDENTITY_SCHEMA:
        raise AgentLicenseError("E_LICENSE_IDENTITY_INVALID", f"{field}.schema must equal {AGENT_IDENTITY_SCHEMA}")
    identity = {
        "schema": AGENT_IDENTITY_SCHEMA,
        "subject": _text(value.get("subject"), f"{field}.subject"),
        "provider": _text(value.get("provider"), f"{field}.provider"),
        "model": _text(value.get("model"), f"{field}.model"),
    }
    for key in ("subject", "provider", "model"):
        if not _IDENTIFIER.fullmatch(identity[key]):
            raise AgentLicenseError("E_LICENSE_IDENTITY_INVALID", f"{field}.{key} contains unsupported characters")
    digest = _sha(identity)
    if "identity_sha256" in value and value["identity_sha256"] != digest:
        raise AgentLicenseError("E_LICENSE_IDENTITY_INVALID", f"{field}.identity_sha256 does not match identity fields")
    return {**identity, "identity_sha256": digest}


def _normalized_paths(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 64:
        raise AgentLicenseError("E_LICENSE_INPUT_INVALID", f"{field} must contain 1 through 64 workspace paths")
    paths: list[str] = []
    for item in value:
        text = _text(item, field, maximum=512).replace("\\", "/").rstrip("/") or "."
        path = Path(text)
        if path.is_absolute() or ".." in path.parts:
            raise AgentLicenseError("E_LICENSE_PATH_OUT_OF_SCOPE", f"{field} paths must be workspace relative")
        paths.append(path.as_posix())
    if len(set(paths)) != len(paths):
        raise AgentLicenseError("E_LICENSE_INPUT_INVALID", f"{field} paths must be unique")
    return sorted(paths)


def _event_core(value: dict[str, Any]) -> dict[str, Any]:
    fields = {
        "schema", "event_id", "recorded_at", "agent", "task_id", "admission", "result_receipt",
        "verification", "passed", "failure_classes", "paths", "event_sha256",
    }
    if set(value) != fields or value.get("schema") != AGENT_RUN_SCHEMA:
        raise AgentLicenseError("E_LICENSE_EVENT_INVALID", "agent run event has an unsupported schema or fields")
    core = {key: value[key] for key in fields - {"event_sha256"}}
    if value.get("event_sha256") != _sha(core):
        raise AgentLicenseError("E_LICENSE_EVENT_INVALID", "agent run event hash mismatch")
    return core


def _validate_ledger_event(root: Path, value: dict[str, Any], *, require_evidence_files: bool = True) -> dict[str, Any]:
    core = _event_core(value)
    event_id = _text(core.get("event_id"), "event_id", maximum=96)
    if not _TASK_IDENTIFIER.fullmatch(event_id):
        raise AgentLicenseError("E_LICENSE_EVENT_INVALID", "event_id must use lowercase letters, digits, and hyphens")
    recorded_at = _timestamp(core.get("recorded_at"), "recorded_at")
    agent = normalize_agent_identity(core.get("agent"))
    task_id = core.get("task_id")
    if task_id is not None and (not isinstance(task_id, str) or not _TASK_IDENTIFIER.fullmatch(task_id)):
        raise AgentLicenseError("E_LICENSE_EVENT_INVALID", "task_id must be omitted or a lowercase task identifier")
    admission = core.get("admission")
    result = core.get("result_receipt")
    verification = core.get("verification")
    if not isinstance(admission, dict) or set(admission) != {"path", "packet_sha256"}:
        raise AgentLicenseError("E_LICENSE_EVENT_INVALID", "admission must contain path and packet_sha256")
    if not isinstance(result, dict) or set(result) != {"path", "sha256"}:
        raise AgentLicenseError("E_LICENSE_EVENT_INVALID", "result_receipt must contain path and sha256")
    if not isinstance(verification, dict) or set(verification) != {"subject", "receipt"}:
        raise AgentLicenseError("E_LICENSE_EVENT_INVALID", "verification must contain subject and receipt")
    verifier_subject = _text(verification.get("subject"), "verification.subject")
    if verifier_subject == agent["subject"]:
        raise AgentLicenseError("E_LICENSE_VERIFIER_NOT_INDEPENDENT", "verifier subject must differ from the agent subject")
    verifier_receipt = verification.get("receipt")
    if not isinstance(verifier_receipt, dict) or set(verifier_receipt) != {"path", "sha256"}:
        raise AgentLicenseError("E_LICENSE_EVENT_INVALID", "verification.receipt must contain path and sha256")
    passed = core.get("passed")
    if not isinstance(passed, bool):
        raise AgentLicenseError("E_LICENSE_EVENT_INVALID", "passed must be boolean")
    failures = core.get("failure_classes")
    if not isinstance(failures, list) or len(failures) > len(FailureClass):
        raise AgentLicenseError("E_LICENSE_EVENT_INVALID", "failure_classes must be a bounded list")
    normalized_failures: list[str] = []
    for failure in failures:
        if not isinstance(failure, str):
            raise AgentLicenseError("E_LICENSE_EVENT_INVALID", "failure_classes must contain strings")
        try:
            normalized_failures.append(FailureClass(failure).value)
        except ValueError as exc:
            raise AgentLicenseError("E_LICENSE_EVENT_INVALID", f"unsupported failure class: {failure}") from exc
    if len(set(normalized_failures)) != len(normalized_failures):
        raise AgentLicenseError("E_LICENSE_EVENT_INVALID", "failure_classes must be unique")
    if passed and normalized_failures:
        raise AgentLicenseError("E_LICENSE_EVENT_INVALID", "passing events cannot declare failure classes")
    if not passed and not normalized_failures:
        raise AgentLicenseError("E_LICENSE_EVENT_INVALID", "failed events must declare at least one failure class")
    paths = _normalized_paths(core.get("paths"), "paths")
    if require_evidence_files:
        for label, binding in (("result_receipt", result), ("verification.receipt", verifier_receipt)):
            evidence_path, _ = _relative(root, binding["path"], label)
            if not evidence_path.is_file() or hashlib.sha256(evidence_path.read_bytes()).hexdigest() != binding["sha256"]:
                raise AgentLicenseError("E_LICENSE_EVIDENCE_STALE", f"{label} hash does not match the referenced workspace file")
    return {
        **core,
        "event_id": event_id,
        "recorded_at": _iso(recorded_at),
        "agent": agent,
        "task_id": task_id,
        "verification": {"subject": verifier_subject, "receipt": verifier_receipt},
        "failure_classes": sorted(normalized_failures),
        "paths": paths,
    }


def _atomic_json(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(_canonical(payload) + b"\n")
    os.replace(temporary, path)
    return path


def _event_from_input(root: Path, input_value: dict[str, Any]) -> dict[str, Any]:
    """Validate a new event against the ready packet before any ledger write."""
    allowed = {"schema", "id", "agent", "task_id", "admission", "result_receipt", "verification", "passed", "failure_classes"}
    if set(input_value) != allowed or input_value.get("schema") != AGENT_RUN_SCHEMA:
        raise AgentLicenseError("E_LICENSE_INPUT_INVALID", f"run input must use {AGENT_RUN_SCHEMA} and its exact fields")
    event_id = _text(input_value.get("id"), "id", maximum=96)
    if not _TASK_IDENTIFIER.fullmatch(event_id):
        raise AgentLicenseError("E_LICENSE_INPUT_INVALID", "id must use lowercase letters, digits, and hyphens")
    agent = normalize_agent_identity(input_value.get("agent"))
    admission_path, admission_relative = _relative(root, input_value.get("admission"), "admission")
    if not admission_path.is_file():
        raise AgentLicenseError("E_LICENSE_ADMISSION_INVALID", "admission packet is missing")
    # Avoid a module import cycle: admission uses this module only when an
    # agent identity is declared, while a completed run is recorded afterwards.
    from .run_admission import verify_admission
    ready = verify_admission(root, admission_path)
    if ready.get("verdict") != "READY":
        raise AgentLicenseError("E_LICENSE_ADMISSION_INVALID", "admission packet must verify as READY")
    packet = _load_json(admission_path)
    packet_agent = packet.get("request", {}).get("agent") if isinstance(packet.get("request"), dict) else None
    if normalize_agent_identity(packet_agent, "admission.request.agent") != agent:
        raise AgentLicenseError("E_LICENSE_IDENTITY_MISMATCH", "run identity must exactly match the admission request")
    packet_paths = packet.get("request", {}).get("paths") if isinstance(packet.get("request"), dict) else None
    paths = _normalized_paths(packet_paths, "admission.request.paths")
    result = _file_binding(root, input_value.get("result_receipt"), "result_receipt")
    verification = input_value.get("verification")
    if not isinstance(verification, dict) or set(verification) != {"subject", "receipt"}:
        raise AgentLicenseError("E_LICENSE_INPUT_INVALID", "verification must contain subject and receipt")
    verifier_subject = _text(verification.get("subject"), "verification.subject")
    if verifier_subject == agent["subject"]:
        raise AgentLicenseError("E_LICENSE_VERIFIER_NOT_INDEPENDENT", "verifier subject must differ from agent subject")
    verifier_receipt = _file_binding(root, verification.get("receipt"), "verification.receipt")
    passed = input_value.get("passed")
    failures = input_value.get("failure_classes")
    task_id = input_value.get("task_id")
    core = {
        "schema": AGENT_RUN_SCHEMA,
        "event_id": event_id,
        "recorded_at": _iso(_now()),
        "agent": agent,
        "task_id": task_id,
        "admission": {"path": admission_relative, "packet_sha256": ready["packet_sha256"]},
        "result_receipt": result,
        "verification": {"subject": verifier_subject, "receipt": verifier_receipt},
        "passed": passed,
        "failure_classes": failures,
        "paths": paths,
    }
    return _validate_ledger_event(root, {**core, "event_sha256": _sha(core)})


def _incident(event: dict[str, Any]) -> dict[str, Any] | None:
    severe = sorted(set(event["failure_classes"]) & SEVERE_FAILURES)
    if not severe:
        return None
    core = {
        "schema": AGENT_LICENSE_INCIDENT_SCHEMA,
        "marker": "AGENT_LICENSE_AUTOMATIC_DEMOTION",
        "event_id": event["event_id"],
        "agent": event["agent"],
        "recorded_at": event["recorded_at"],
        "failure_classes": severe,
        "evidence": {"event_sha256": event["event_sha256"], "result_receipt_sha256": event["result_receipt"]["sha256"]},
        "effect": {"tier": "human_controlled", "requalification_clean_runs": POST_INCIDENT_REQUALIFICATION_RUNS},
        "scope_limits": ["Incident capsules classify a governed result; they do not diagnose a person or external identity."],
    }
    return {**core, "incident_sha256": _sha(core)}


def _store_governed_event(workspace: Path, event: dict[str, Any], out_dir: Path | None) -> dict[str, Any]:
    """Persist one validated immutable event and any automatic incident."""
    target = Path(out_dir) if out_dir is not None else workspace / EVENT_DIR
    target = target if target.is_absolute() else workspace / target
    try:
        target.resolve().relative_to(workspace)
    except ValueError as exc:
        raise AgentLicenseError("E_LICENSE_PATH_OUT_OF_SCOPE", "out_dir must remain inside workspace") from exc
    output = target / f"{event['event_id']}.json"
    final = {**event, "event_sha256": _sha(event)}
    if output.exists():
        existing = _load_json(output)
        if existing.get("event_sha256") == final["event_sha256"]:
            return {"marker": "AGENT_LICENSE_EVENT_ALREADY_RECORDED", "event": existing, "path": str(output.resolve()), "incident_path": None}
        raise AgentLicenseError("E_LICENSE_EVENT_EXISTS", "event id is already bound to different immutable content")
    _atomic_json(output, final)
    incident = _incident(final)
    incident_path: Path | None = None
    if incident is not None:
        incident_path = workspace / INCIDENT_DIR / f"{event['event_id']}.json"
        _atomic_json(incident_path, incident)
    return {"marker": "AGENT_LICENSE_EVENT_RECORDED", "event": final, "path": str(output.resolve()), "incident_path": str(incident_path.resolve()) if incident_path else None}


def record_bound_governed_event(root: Path, event: dict[str, Any], *, out_dir: Path | None = None) -> dict[str, Any]:
    """Record a completed event whose READY admission was bound before execution.

    This path exists for the session recorder: an admitted coding run is expected
    to change the workspace, so the pre-run packet cannot truthfully verify as
    current after execution.  The event and its bound result receipt are still
    validated here, including the exact admission packet digest and both evidence
    file digests.  Callers must have obtained READY immediately before execution.
    """
    workspace = Path(root).resolve()
    if not isinstance(event, dict):
        raise AgentLicenseError("E_LICENSE_EVENT_INVALID", "event must be an object")
    validated = _validate_ledger_event(workspace, event, require_evidence_files=True)
    admission_path, _ = _relative(workspace, validated["admission"]["path"], "admission")
    packet = _load_json(admission_path) if admission_path.is_file() else {}
    if packet.get("packet_sha256") != validated["admission"]["packet_sha256"]:
        raise AgentLicenseError("E_LICENSE_ADMISSION_INVALID", "admission packet digest does not match the pre-run binding")
    return _store_governed_event(workspace, validated, out_dir)


def record_governed_run(root: Path, event_path: Path, *, out_dir: Path | None = None) -> dict[str, Any]:
    """Record one immutable, already-admitted run and any automatic incident."""
    workspace = Path(root).resolve()
    source, _ = _relative(workspace, event_path, "event")
    input_value = _load_json(source)
    event = _event_from_input(workspace, input_value)
    return _store_governed_event(workspace, event, out_dir)


def load_governed_runs(root: Path, *, agent: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Read only valid immutable event records; stale evidence is withheld."""
    workspace = Path(root).resolve()
    identity = normalize_agent_identity(agent) if agent is not None else None
    events: list[dict[str, Any]] = []
    for path in sorted((workspace / EVENT_DIR).glob("*.json")):
        try:
            value = _validate_ledger_event(workspace, _load_json(path), require_evidence_files=True)
            event = {**value, "event_sha256": _sha(value)}
        except AgentLicenseError:
            continue
        if identity is None or event["agent"]["identity_sha256"] == identity["identity_sha256"]:
            events.append(event)
    return sorted(events, key=lambda item: (item["recorded_at"], item["event_id"]))


def _common_paths(events: list[dict[str, Any]]) -> list[str]:
    if not events:
        return []
    candidates = sorted({path for event in events for path in event["paths"]})
    allowed: list[str] = []
    for candidate in candidates:
        if all(any(scope == "." or candidate == scope or candidate.startswith(scope.rstrip("/") + "/") for scope in event["paths"]) for event in events):
            allowed.append(candidate)
    return allowed


def _policy() -> dict[str, Any]:
    return {
        "schema": LICENSE_POLICY_SCHEMA,
        "evidence_ttl_days": EVIDENCE_TTL_DAYS,
        "supervised_min_clean_runs": SUPERVISED_MIN_CLEAN_RUNS,
        "autonomous_min_clean_runs": AUTONOMOUS_MIN_CLEAN_RUNS,
        "autonomous_min_independent_verifications": AUTONOMOUS_MIN_INDEPENDENT_VERIFICATIONS,
        "post_incident_requalification_clean_runs": POST_INCIDENT_REQUALIFICATION_RUNS,
        "severe_failure_classes": sorted(SEVERE_FAILURES),
        "policy_note": "These are explicit V1 governance policy values, not an empirical quality benchmark or vendor ranking.",
    }


def _license_evidence(root: Path, identity: dict[str, Any], instant: datetime) -> dict[str, Any]:
    evidence = load_governed_runs(root, agent=identity)
    expiry_cutoff = instant - timedelta(days=EVIDENCE_TTL_DAYS)
    current = [event for event in evidence if _timestamp(event["recorded_at"], "recorded_at") >= expiry_cutoff]
    stale = [event for event in evidence if event not in current]
    current.sort(key=lambda item: (item["recorded_at"], item["event_id"]))
    incidents = [event for event in current if set(event["failure_classes"]) & SEVERE_FAILURES]
    try:
        from .oracle_firewall import oracle_incidents_for_agent
        oracle_incidents = oracle_incidents_for_agent(root, identity)
    except (ImportError, ValueError, OSError, json.JSONDecodeError):
        oracle_incidents = []
    latest_incident = incidents[-1] if incidents else None
    event_incident_at = _timestamp(latest_incident["recorded_at"], "recorded_at") if latest_incident else None
    oracle_incident_at = max((_timestamp(item["recorded_at"], "recorded_at") for item in oracle_incidents), default=None)
    latest_incident_at = max((item for item in (event_incident_at, oracle_incident_at) if item is not None), default=None)
    after_incident = [event for event in current if latest_incident_at is None or _timestamp(event["recorded_at"], "recorded_at") > latest_incident_at]
    clean_after_incident = [event for event in after_incident if event["passed"] and not event["failure_classes"]]
    independent = [event for event in clean_after_incident if event["verification"]["subject"] != identity["subject"]]
    scopes = _common_paths(clean_after_incident)
    return {"all": evidence, "current": current, "stale": stale, "incidents": incidents, "oracle_incidents": oracle_incidents, "latest_incident": latest_incident, "latest_incident_at": latest_incident_at, "clean": clean_after_incident, "independent": independent, "scopes": scopes}


def _license_tier(evidence: dict[str, Any]) -> tuple[str, str]:
    current, all_events = evidence["current"], evidence["all"]
    if evidence["oracle_incidents"] and len(evidence["clean"]) < POST_INCIDENT_REQUALIFICATION_RUNS:
        return "human_controlled", "ORACLE_WEAKENING_DEMOTION"
    if not current:
        return ("supervised", "EVIDENCE_EXPIRED") if all_events else ("human_controlled", "INSUFFICIENT_GOVERNED_EVIDENCE")
    if evidence["latest_incident"] is not None and len(evidence["clean"]) < POST_INCIDENT_REQUALIFICATION_RUNS:
        return "human_controlled", "SEVERE_FAILURE_DEMOTION"
    if len(evidence["clean"]) >= AUTONOMOUS_MIN_CLEAN_RUNS and len(evidence["independent"]) >= AUTONOMOUS_MIN_INDEPENDENT_VERIFICATIONS and evidence["scopes"]:
        return "autonomous", "CURRENT_GOVERNED_EVIDENCE_SATISFIES_POLICY"
    if len(evidence["clean"]) >= SUPERVISED_MIN_CLEAN_RUNS:
        return "supervised", "CURRENT_GOVERNED_EVIDENCE_REQUIRES_SUPERVISION"
    return "human_controlled", "INSUFFICIENT_CLEAN_GOVERNED_EVIDENCE"


def derive_license(root: Path, agent: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Derive a current tier from immutable, locally valid governed evidence."""
    instant = (now or _now()).astimezone(timezone.utc)
    identity = normalize_agent_identity(agent)
    evidence = _license_evidence(root, identity, instant)
    tier, reason = _license_tier(evidence)
    latest = evidence["all"][-1] if evidence["all"] else None
    expires_at = _iso(_timestamp(latest["recorded_at"], "recorded_at") + timedelta(days=EVIDENCE_TTL_DAYS)) if latest else None
    core = {
        "schema": AGENT_LICENSE_SCHEMA,
        "marker": "AGENT_LICENSE_DERIVED_LOCAL",
        "issued_at": _iso(instant),
        "agent": identity,
        "identity_provenance": "declared_in_admission_packet",
        "tier": tier,
        "reason": reason,
        "allowed_paths": evidence["scopes"] if tier == "autonomous" else [],
        "expires_at": expires_at,
        "evidence": {
            "valid_governed_event_count": len(evidence["all"]),
            "current_governed_event_count": len(evidence["current"]),
            "stale_governed_event_count": len(evidence["stale"]),
            "clean_events_since_latest_incident": len(evidence["clean"]),
            "independent_verification_count_since_latest_incident": len(evidence["independent"]),
            "oracle_incident_count": len(evidence["oracle_incidents"]),
            "latest_event_sha256": latest["event_sha256"] if latest else None,
        },
        "incidents": [
            {"event_id": event["event_id"], "recorded_at": event["recorded_at"], "failure_classes": sorted(set(event["failure_classes"]) & SEVERE_FAILURES), "event_sha256": event["event_sha256"]}
            for event in evidence["incidents"]
        ] + [
            {"recorded_at": item["recorded_at"], "failure_classes": [FailureClass.ORACLE_WEAKENING.value], "incident_sha256": item["incident_sha256"]}
            for item in evidence["oracle_incidents"]
        ],
        "policy": _policy(),
        "authority": dict(_AUTHORITY),
        "scope_limits": [
            "Agent and verifier subjects are declared identifiers; this local adapter does not authenticate them.",
            "A license caps only admission declarations that include this identity. It does not execute, approve, repair, merge, publish, deploy, sign, or grant credentials.",
            "A locally hash-bound license is not cryptographically signed unless an optional DSSE envelope is separately verified.",
        ],
    }
    return {**core, "license_sha256": _sha(core)}


def issue_license(root: Path, agent: dict[str, Any], *, out: Path | None = None) -> dict[str, Any]:
    """Write a hash-bound license artifact after deterministic derivation."""
    workspace = Path(root).resolve()
    license_value = derive_license(workspace, agent)
    target = Path(out) if out is not None else workspace / LICENSE_DIR / f"{license_value['agent']['identity_sha256'][:24]}.json"
    target = target if target.is_absolute() else workspace / target
    try:
        target.resolve().relative_to(workspace)
    except ValueError as exc:
        raise AgentLicenseError("E_LICENSE_PATH_OUT_OF_SCOPE", "license output must remain inside workspace") from exc
    _atomic_json(target, license_value)
    return {"marker": "AGENT_LICENSE_ISSUED", "license": license_value, "path": str(target.resolve())}


def verify_license(path: Path) -> dict[str, Any]:
    """Verify canonical local-license integrity without network access."""
    try:
        value = _load_json(Path(path))
        fields = set(value)
        if value.get("schema") != AGENT_LICENSE_SCHEMA or "license_sha256" not in fields:
            raise AgentLicenseError("E_LICENSE_INVALID", "unsupported license schema")
        core = {key: value[key] for key in fields - {"license_sha256"}}
        if value["license_sha256"] != _sha(core):
            raise AgentLicenseError("E_LICENSE_INVALID", "license hash mismatch")
        _timestamp(value.get("issued_at"), "issued_at")
        if value.get("tier") not in AUTONOMY_RANK:
            raise AgentLicenseError("E_LICENSE_INVALID", "unsupported license tier")
        normalize_agent_identity(value.get("agent"))
    except AgentLicenseError as exc:
        return {"schema": AGENT_LICENSE_SCHEMA, "marker": "AGENT_LICENSE_INVALID", "ok": False, "reason": exc.code}
    return {"schema": AGENT_LICENSE_SCHEMA, "marker": "AGENT_LICENSE_VERIFIED", "ok": True, "license_sha256": value["license_sha256"], "tier": value["tier"], "signature": "not_supplied"}


def seal_license(path: Path, *, private_key_path: Path, keyid: str, identity: str, issuer: str, tenant_id: str, out: Path) -> dict[str, Any]:
    """Optionally bind a verified local license to the existing Receipt v2 DSSE path."""
    verified = verify_license(path)
    if not verified["ok"]:
        raise AgentLicenseError("E_LICENSE_SIGNING_FAILED", "license must verify before sealing")
    value = _load_json(Path(path))
    try:
        from .enterprise_receipts import EnterpriseReceiptError, seal_receipt_v2
        payload = {
            "schema": "factory.receipt.v2", "module": "agent-license", "stage": "license",
            "feature": value["agent"]["identity_sha256"][:32], "ok": True, "tenant_id": _text(tenant_id, "tenant_id"),
            "run_id": value["license_sha256"][:32], "ts": _iso(_now()), "subject_sha256": value["license_sha256"],
        }
        envelope = seal_receipt_v2(payload, Path(private_key_path), _text(keyid, "keyid"), _text(identity, "identity"), _text(issuer, "issuer"), Path(out))
    except (ImportError, OSError, EnterpriseReceiptError) as exc:
        raise AgentLicenseError("E_LICENSE_SIGNING_FAILED", str(exc)) from exc
    return {"schema": AGENT_LICENSE_SCHEMA, "marker": "AGENT_LICENSE_SEALED", "license_sha256": value["license_sha256"], "path": str(Path(out).resolve()), "payload_sha256": envelope["payload_sha256"], "authority": {**_AUTHORITY, "signing": True}}


def admission_license_decision(root: Path, passport: dict[str, Any], request: dict[str, Any]) -> dict[str, Any] | None:
    """Return the exact license cap for a declared identity, or None for legacy requests."""
    agent = request.get("agent")
    if agent is None:
        return None
    identity = normalize_agent_identity(agent, "agent")
    license_value = derive_license(root, identity)
    requested = passport.get("autonomy")
    if requested not in AUTONOMY_RANK:
        raise AgentLicenseError("E_LICENSE_EXCEEDED", "Loop Passport declares an unsupported autonomy level")
    if AUTONOMY_RANK[requested] > AUTONOMY_RANK[license_value["tier"]]:
        raise AgentLicenseError("E_LICENSE_EXCEEDED", f"requested {requested} autonomy exceeds current {license_value['tier']} license")
    if requested == "autonomous":
        paths = _normalized_paths(request.get("paths"), "paths")
        grants = license_value["allowed_paths"]
        if not grants or any(not any(scope == "." or path == scope or path.startswith(scope.rstrip("/") + "/") for scope in grants) for path in paths):
            raise AgentLicenseError("E_LICENSE_EXCEEDED", "requested paths exceed the current autonomous license scope")
    return license_value


def license_projection(root: Path) -> dict[str, Any]:
    """Return redacted, read-only current license facts for Graph Ops and MCP."""
    workspace = Path(root).resolve()
    agents: dict[str, dict[str, str]] = {}
    for event in load_governed_runs(workspace):
        agents[event["agent"]["identity_sha256"]] = event["agent"]
    licenses = [derive_license(workspace, agent) for _, agent in sorted(agents.items())]
    return {
        "marker": "AGENT_LICENSE_STATUS_READ_ONLY",
        "available": bool(licenses),
        "licenses": licenses,
        "authority": dict(_AUTHORITY),
        "scope_limits": ["Projection excludes agent prompts, source bodies, and raw verifier transcripts."],
    }
