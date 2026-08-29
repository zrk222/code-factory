"""One human-controlled proof-review workflow over Continuous Proof Operations."""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import html
import json
import os
from pathlib import Path
import re
from typing import Any

from .continuous_proof import assess_continuous_proof, verify_continuous_proof


INTENT_SCHEMA = "factory.intent-contract.v1"
TRAJECTORY_SCHEMA = "factory.agent-trajectory-proof.v1"
REVIEW_SCHEMA = "factory.proof-review.v1"
INBOX_SCHEMA = "factory.team-proof-inbox.v1"
REGRESSION_SCHEMA = "factory.regression-capsule.v1"
CARD_SCHEMA = "factory.shareable-proof-card.v1"
HOOK_SCHEMA = "factory.agent-hook-pack.v1"
MAX_BYTES = 1_048_576
MAX_EVENTS = 500
MAX_RECORDS = 500
_ID = re.compile(r"^[a-z][a-z0-9-]{0,95}$")
_SHA = re.compile(r"^[a-f0-9]{64}$")
_ROUTES = ("evidence_required", "human_required", "reverification_required", "review_ready")
_ROUTE_ORDER = {name: index for index, name in enumerate(("human_required", "reverification_required", "evidence_required", "review_ready"))}
_AUTHORITY = {
    "execution": False, "source_modify": False, "approval": False, "commit": False,
    "merge": False, "publication": False, "deployment": False, "signing": False,
    "messaging": False, "credential": False, "connector": False, "network": False,
}


class ProofReviewError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _workspace(root: Path) -> Path:
    value = Path(root).resolve()
    if not value.is_dir():
        raise ProofReviewError("PROOF_REVIEW_ROOT_INVALID", "root must be an existing directory")
    return value


def _path(workspace: Path, value: Path, field: str, *, must_exist: bool = True) -> tuple[Path, str]:
    candidate = Path(value)
    resolved = (candidate if candidate.is_absolute() else workspace / candidate).resolve()
    try:
        relative = resolved.relative_to(workspace).as_posix()
    except ValueError as exc:
        raise ProofReviewError("PROOF_REVIEW_PATH_REJECTED", f"{field} must stay inside the workspace") from exc
    if must_exist and (not resolved.is_file() or resolved.stat().st_size > MAX_BYTES):
        raise ProofReviewError("PROOF_REVIEW_INPUT_INVALID", f"{field} must be a file no larger than {MAX_BYTES} bytes")
    return resolved, relative


def _load(workspace: Path, value: Path, field: str) -> tuple[dict[str, Any], Path, str]:
    path, relative = _path(workspace, value, field)
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProofReviewError("PROOF_REVIEW_JSON_INVALID", f"{field} is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ProofReviewError("PROOF_REVIEW_JSON_INVALID", f"{field} must be a JSON object")
    return data, path, relative


def _atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def _write_receipt(path: Path, core: dict[str, Any], digest_key: str) -> dict[str, Any]:
    receipt = {**core, digest_key: _sha(core)}
    _atomic(path, _canonical(receipt) + b"\n")
    return receipt


def _strings(value: Any, field: str, *, minimum: int = 1) -> list[str]:
    if not isinstance(value, list) or len(value) < minimum or not all(isinstance(item, str) and item.strip() for item in value):
        raise ProofReviewError("INTENT_CONTRACT_INCOMPLETE", f"{field} must contain at least {minimum} non-empty string")
    return [item.strip() for item in value]


def _binding_matches(workspace: Path, binding: dict[str, Any]) -> bool:
    path_value = binding.get("path")
    digest = binding.get("sha256")
    if not isinstance(path_value, str) or not isinstance(digest, str) or _SHA.fullmatch(digest) is None:
        return False
    try:
        path, _ = _path(workspace, Path(path_value), "bound artifact")
    except ProofReviewError:
        return False
    return sha256(path.read_bytes()).hexdigest() == digest


def create_intent_contract(root: Path, contract_id: str, draft_path: Path, confirmed_by: str) -> dict[str, Any]:
    """Seal a complete workspace-contained intent draft after named human confirmation."""
    workspace = _workspace(root)
    if not _ID.fullmatch(contract_id):
        raise ProofReviewError("INTENT_CONTRACT_ID_INVALID", "contract id must be a lowercase identifier")
    if not isinstance(confirmed_by, str) or not confirmed_by.strip():
        raise ProofReviewError("INTENT_CONTRACT_CONFIRMATION_REQUIRED", "a named human confirmer is required")
    draft, path, relative = _load(workspace, draft_path, "intent draft")
    outcome = draft.get("outcome")
    if not isinstance(outcome, str) or not outcome.strip():
        raise ProofReviewError("INTENT_CONTRACT_INCOMPLETE", "outcome is required")
    acceptance = _strings(draft.get("acceptance"), "acceptance")
    rejection = _strings(draft.get("rejection"), "rejection")
    validators = _strings(draft.get("validators"), "validators")
    allowed_paths = _strings(draft.get("allowed_paths"), "allowed_paths")
    non_goals = _strings(draft.get("non_goals", []), "non_goals", minimum=0)
    core = {
        "schema": INTENT_SCHEMA,
        "marker": "INTENT_CONTRACT_CONFIRMED",
        "contract_id": contract_id,
        "recorded_at": _now(),
        "source": {"path": relative, "sha256": sha256(path.read_bytes()).hexdigest()},
        "outcome": outcome.strip(),
        "acceptance": acceptance,
        "rejection": rejection,
        "non_goals": non_goals,
        "allowed_paths": allowed_paths,
        "validators": validators,
        "confirmed_by": confirmed_by.strip(),
        "human_confirmed": True,
        "final_approval": False,
        "authority": dict(_AUTHORITY),
    }
    destination = workspace / ".factory" / "proof-review" / "contracts" / f"{contract_id}.json"
    if destination.exists():
        raise ProofReviewError("INTENT_CONTRACT_EXISTS", "intent contract ids are immutable")
    result = _write_receipt(destination, core, "contract_sha256")
    return {**result, "artifact": str(destination)}


def verify_intent_contract(root: Path, contract_path: Path) -> dict[str, Any]:
    """Verify an intent receipt digest and its binding to the current draft bytes."""
    workspace = _workspace(root)
    value, _, relative = _load(workspace, contract_path, "intent contract")
    digest = value.get("contract_sha256")
    core = {key: item for key, item in value.items() if key != "contract_sha256"}
    if value.get("schema") != INTENT_SCHEMA or not isinstance(digest, str) or digest != _sha(core) or value.get("human_confirmed") is not True:
        return {"schema": INTENT_SCHEMA, "marker": "INTENT_CONTRACT_INVALID", "ok": False, "path": relative, "reason": "receipt_digest"}
    source = value.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("path"), str) or not isinstance(source.get("sha256"), str):
        return {"schema": INTENT_SCHEMA, "marker": "INTENT_CONTRACT_INVALID", "ok": False, "path": relative, "reason": "source_binding"}
    source_path = (workspace / source["path"]).resolve()
    if not source_path.is_file() or sha256(source_path.read_bytes()).hexdigest() != source["sha256"]:
        return {"schema": INTENT_SCHEMA, "marker": "INTENT_CONTRACT_STALE", "ok": False, "path": relative, "reason": "source_drift"}
    return {"schema": INTENT_SCHEMA, "marker": "INTENT_CONTRACT_VERIFIED", "ok": True, "path": relative, "contract_sha256": digest}


def _trajectory_configuration(trace: dict[str, Any], policy: dict[str, Any]) -> tuple[list[Any], list[str], set[str], set[str], list[str], str]:
    events = trace.get("events")
    max_steps = policy.get("max_steps", MAX_EVENTS)
    if isinstance(max_steps, bool) or not isinstance(max_steps, int) or max_steps < 1:
        raise ProofReviewError("TRAJECTORY_POLICY_INVALID", "max_steps must be an integer from 1 to 500")
    if not isinstance(events, list) or not events or len(events) > min(max_steps, MAX_EVENTS):
        raise ProofReviewError("TRAJECTORY_EVENTS_INVALID", f"events must contain 1 to {MAX_EVENTS} items")
    worker = trace.get("worker_actor")
    if not isinstance(worker, str) or not worker:
        raise ProofReviewError("TRAJECTORY_ACTOR_INVALID", "worker_actor is required")
    return (
        events,
        _strings(policy.get("required_events"), "required_events"),
        set(_strings(policy.get("allowed_tools", []), "allowed_tools", minimum=0)),
        set(_strings(policy.get("forbidden_tools", []), "forbidden_tools", minimum=0)),
        _strings(policy.get("allowed_paths"), "allowed_paths"),
        worker,
    )


def _event_policy_violations(event: dict[str, Any], index: int, allowed_tools: set[str], forbidden_tools: set[str], allowed_paths: list[str]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    tool = event.get("tool")
    tool_rejected = tool is not None and (not isinstance(tool, str) or tool in forbidden_tools or (allowed_tools and tool not in allowed_tools))
    if tool_rejected:
        findings.append({"kind": "tool_policy", "event": str(index)})
    path = event.get("path")
    unsafe_path = isinstance(path, str) and (Path(path).is_absolute() or ".." in Path(path).parts)
    path_allowed = isinstance(path, str) and any(path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in allowed_paths)
    if path is not None and (not isinstance(path, str) or unsafe_path or not path_allowed):
        findings.append({"kind": "scope_escape", "event": str(index)})
    return findings


def _ordered_events_present(observed: list[str], required: list[str]) -> bool:
    cursor = 0
    for event_type in observed:
        if cursor < len(required) and event_type == required[cursor]:
            cursor += 1
    return cursor == len(required)


def _trajectory_findings(events: list[Any], required: list[str], allowed_tools: set[str], forbidden_tools: set[str], allowed_paths: list[str], worker: str) -> tuple[list[dict[str, str]], bool]:
    observed: list[str] = []
    findings: list[dict[str, str]] = []
    independent = False
    for index, event in enumerate(events):
        if not isinstance(event, dict) or not isinstance(event.get("type"), str) or not isinstance(event.get("actor"), str):
            raise ProofReviewError("TRAJECTORY_EVENT_INVALID", f"event {index} must declare type and actor")
        observed.append(event["type"])
        findings.extend(_event_policy_violations(event, index, allowed_tools, forbidden_tools, allowed_paths))
        independent = independent or (event["type"] == "independent_audit" and event["actor"] != worker)
    if not _ordered_events_present(observed, required):
        findings.append({"kind": "required_event_order", "event": "sequence"})
    if not independent or events[-1].get("type") != "independent_audit":
        findings.append({"kind": "independent_audit", "event": str(len(events) - 1)})
    return findings, independent


def prove_trajectory(root: Path, trace_path: Path, policy_path: Path, trajectory_id: str) -> dict[str, Any]:
    """Evaluate a bounded agent trace against ordered, scoped, independently audited policy."""
    workspace = _workspace(root)
    if not _ID.fullmatch(trajectory_id):
        raise ProofReviewError("TRAJECTORY_ID_INVALID", "trajectory id must be a lowercase identifier")
    trace, trace_file, trace_relative = _load(workspace, trace_path, "trajectory trace")
    policy, policy_file, policy_relative = _load(workspace, policy_path, "trajectory policy")
    events, required, allowed_tools, forbidden_tools, allowed_paths, worker = _trajectory_configuration(trace, policy)
    violations, independent = _trajectory_findings(events, required, allowed_tools, forbidden_tools, allowed_paths, worker)
    core = {
        "schema": TRAJECTORY_SCHEMA,
        "marker": "AGENT_TRAJECTORY_PROVED",
        "trajectory_id": trajectory_id,
        "recorded_at": _now(),
        "trace": {"path": trace_relative, "sha256": sha256(trace_file.read_bytes()).hexdigest()},
        "policy": {"path": policy_relative, "sha256": sha256(policy_file.read_bytes()).hexdigest()},
        "event_count": len(events),
        "required_events": required,
        "independent_audit": independent,
        "violations": violations,
        "passed": not violations,
        "final_approval": False,
        "authority": dict(_AUTHORITY),
    }
    destination = workspace / ".factory" / "proof-review" / "trajectories" / f"{trajectory_id}.json"
    if destination.exists():
        raise ProofReviewError("TRAJECTORY_EXISTS", "trajectory ids are immutable")
    result = _write_receipt(destination, core, "trajectory_sha256")
    return {**result, "artifact": str(destination)}


def verify_trajectory(root: Path, trajectory_path: Path) -> dict[str, Any]:
    """Verify a trajectory receipt and both of its workspace-contained source bindings."""
    workspace = _workspace(root)
    value, _, relative = _load(workspace, trajectory_path, "trajectory proof")
    digest = value.get("trajectory_sha256")
    core = {key: item for key, item in value.items() if key != "trajectory_sha256"}
    if value.get("schema") != TRAJECTORY_SCHEMA or not isinstance(digest, str) or digest != _sha(core):
        return {"schema": TRAJECTORY_SCHEMA, "marker": "AGENT_TRAJECTORY_INVALID", "ok": False, "path": relative, "reason": "receipt_digest"}
    for name in ("trace", "policy"):
        binding = value.get(name)
        if not isinstance(binding, dict) or not _binding_matches(workspace, binding):
            return {"schema": TRAJECTORY_SCHEMA, "marker": "AGENT_TRAJECTORY_INVALID", "ok": False, "path": relative, "reason": name}
    return {"schema": TRAJECTORY_SCHEMA, "marker": "AGENT_TRAJECTORY_VERIFIED", "ok": True, "passed": value.get("passed") is True, "path": relative, "trajectory_sha256": digest}


def create_quick_review(
    root: Path, review_id: str, contract_path: Path, changed: list[str], *,
    session_path: Path | None = None, trajectory_path: Path | None = None,
    repair_scope_path: Path | None = None, repair_patch_path: Path | None = None,
    prior_receipt_path: Path | None = None, session_phase: str = "change",
) -> dict[str, Any]:
    """Join current intent, change, session, repair, and trajectory evidence into one review route."""
    workspace = _workspace(root)
    if not _ID.fullmatch(review_id):
        raise ProofReviewError("PROOF_REVIEW_ID_INVALID", "review id must be a lowercase identifier")
    contract_check = verify_intent_contract(workspace, contract_path)
    if not contract_check.get("ok"):
        raise ProofReviewError("INTENT_CONTRACT_NOT_CURRENT", "intent contract must verify against current source bytes")
    contract, contract_file, contract_relative = _load(workspace, contract_path, "intent contract")
    continuous = assess_continuous_proof(
        workspace, review_id, contract_file, changed, session_path=session_path,
        session_phase=session_phase, repair_scope_path=repair_scope_path,
        repair_patch_path=repair_patch_path, prior_receipt_path=prior_receipt_path,
    )
    trajectory: dict[str, Any] | None = None
    route = continuous["route"]
    next_action = dict(continuous["next_action"])
    if trajectory_path is not None:
        trajectory_check = verify_trajectory(workspace, trajectory_path)
        trajectory_value, trajectory_file, trajectory_relative = _load(workspace, trajectory_path, "trajectory proof")
        trajectory = {"path": trajectory_relative, "sha256": sha256(trajectory_file.read_bytes()).hexdigest(), "trajectory_sha256": trajectory_value.get("trajectory_sha256"), "passed": trajectory_check.get("passed") if trajectory_check.get("ok") else False}
        if not trajectory_check.get("ok") or trajectory_check.get("passed") is not True:
            route = "human_required"
            next_action = {"action": "inspect_agent_trajectory", "reason": "The agent trajectory is invalid, stale, or failed its independent policy audit."}
    continuous_path = Path(continuous["artifacts"]["json"])
    core = {
        "schema": REVIEW_SCHEMA,
        "marker": "FIVE_MINUTE_PROOF_REVIEW_RECORDED",
        "review_id": review_id,
        "recorded_at": _now(),
        "intent_contract": {"path": contract_relative, "sha256": sha256(contract_file.read_bytes()).hexdigest(), "contract_sha256": contract["contract_sha256"]},
        "continuous_proof": {"path": continuous_path.relative_to(workspace).as_posix(), "sha256": sha256(continuous_path.read_bytes()).hexdigest(), "receipt_sha256": continuous["receipt_sha256"]},
        "trajectory": trajectory,
        "route": route,
        "next_action": next_action,
        "changed_paths": continuous["changed_paths"],
        "final_approval": False,
        "authority": dict(_AUTHORITY),
        "claim_limits": ["Review records are not unique users.", "No time, token, cost, quality, security, compliance, or productivity outcome is inferred."],
    }
    destination = workspace / ".factory" / "proof-review" / "reviews" / f"{review_id}.json"
    if destination.exists():
        raise ProofReviewError("PROOF_REVIEW_EXISTS", "proof review ids are immutable")
    result = _write_receipt(destination, core, "review_sha256")
    return {**result, "artifact": str(destination)}


def _review_binding_failure(workspace: Path, value: dict[str, Any]) -> str | None:
    contract = value.get("intent_contract")
    continuous = value.get("continuous_proof")
    if not isinstance(contract, dict) or not isinstance(continuous, dict):
        return "bindings"
    if not _binding_matches(workspace, contract) or not _binding_matches(workspace, continuous):
        return "binding_bytes"
    if not verify_intent_contract(workspace, Path(contract.get("path", ""))).get("ok"):
        return "intent_contract"
    if not verify_continuous_proof(workspace, Path(continuous.get("path", ""))).get("ok"):
        return "continuous_proof"
    trajectory = value.get("trajectory")
    if trajectory is not None and not isinstance(trajectory, dict):
        return "trajectory"
    if isinstance(trajectory, dict) and (not _binding_matches(workspace, trajectory) or not verify_trajectory(workspace, Path(trajectory.get("path", ""))).get("ok")):
        return "trajectory"
    return None


def verify_quick_review(root: Path, review_path: Path) -> dict[str, Any]:
    """Verify a proof-review digest and every nested artifact binding without execution."""
    workspace = _workspace(root)
    value, _, relative = _load(workspace, review_path, "proof review")
    digest = value.get("review_sha256")
    core = {key: item for key, item in value.items() if key != "review_sha256"}
    if value.get("schema") != REVIEW_SCHEMA or not isinstance(digest, str) or digest != _sha(core) or value.get("route") not in _ROUTES:
        return {"schema": REVIEW_SCHEMA, "marker": "PROOF_REVIEW_INVALID", "ok": False, "path": relative, "reason": "receipt_digest"}
    binding_failure = _review_binding_failure(workspace, value)
    if binding_failure:
        marker = "PROOF_REVIEW_INVALID" if binding_failure == "bindings" else "PROOF_REVIEW_STALE"
        return {"schema": REVIEW_SCHEMA, "marker": marker, "ok": False, "path": relative, "reason": binding_failure}
    return {"schema": REVIEW_SCHEMA, "marker": "PROOF_REVIEW_VERIFIED", "ok": True, "path": relative, "route": value["route"], "review_sha256": digest}


def promote_regression(root: Path, review_path: Path, capsule_id: str, confirmed_by: str, title: str) -> dict[str, Any]:
    """Promote one current causal failure into an immutable, human-confirmed regression capsule."""
    workspace = _workspace(root)
    if not _ID.fullmatch(capsule_id):
        raise ProofReviewError("REGRESSION_ID_INVALID", "capsule id must be a lowercase identifier")
    if not confirmed_by.strip() or not title.strip():
        raise ProofReviewError("REGRESSION_CONFIRMATION_REQUIRED", "named confirmer and title are required")
    check = verify_quick_review(workspace, review_path)
    if not check.get("ok"):
        raise ProofReviewError("REGRESSION_REVIEW_INVALID", "proof review must be current and verified")
    review, review_file, review_relative = _load(workspace, review_path, "proof review")
    continuous, _, _ = _load(workspace, Path(review["continuous_proof"]["path"]), "continuous proof")
    failures = list(continuous.get("session", {}).get("failure_classes", []))
    findings = list(continuous.get("change_review", {}).get("findings", []))
    if not failures and not findings and review.get("route") == "review_ready":
        raise ProofReviewError("REGRESSION_CAUSAL_FAILURE_REQUIRED", "a causal failure or deterministic finding is required")
    core = {
        "schema": REGRESSION_SCHEMA, "marker": "REGRESSION_CAPSULE_PROMOTED", "capsule_id": capsule_id,
        "recorded_at": _now(), "title": title.strip(), "confirmed_by": confirmed_by.strip(),
        "human_confirmed": True,
        "proof_review": {"path": review_relative, "sha256": sha256(review_file.read_bytes()).hexdigest(), "review_sha256": review["review_sha256"]},
        "failure_classes": sorted(str(item) for item in failures),
        "deterministic_findings": sorted({str(item.get("kind")) for item in findings if isinstance(item, dict)}),
        "final_approval": False, "authority": dict(_AUTHORITY),
    }
    destination = workspace / ".factory" / "proof-review" / "regressions" / f"{capsule_id}.json"
    if destination.exists():
        raise ProofReviewError("REGRESSION_CAPSULE_EXISTS", "regression capsule ids are immutable")
    result = _write_receipt(destination, core, "capsule_sha256")
    return {**result, "artifact": str(destination)}


def team_proof_inbox(root: Path) -> dict[str, Any]:
    """Return a bounded risk-ordered view of current reviews while separating stale inputs."""
    workspace = _workspace(root)
    directory = workspace / ".factory" / "proof-review" / "reviews"
    paths = sorted(directory.glob("*.json"))[: MAX_RECORDS + 1] if directory.is_dir() else []
    truncated = len(paths) > MAX_RECORDS
    records: list[dict[str, Any]] = []
    stale = invalid = 0
    for path in paths[:MAX_RECORDS]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            invalid += 1
            continue
        checked = verify_quick_review(workspace, path)
        if not checked.get("ok"):
            if checked.get("marker") == "PROOF_REVIEW_STALE": stale += 1
            else: invalid += 1
            continue
        records.append({"review_id": value["review_id"], "recorded_at": value["recorded_at"], "route": value["route"], "next_action": value["next_action"], "changed_path_count": len(value["changed_paths"]), "review_sha256": value["review_sha256"], "path": path.relative_to(workspace).as_posix()})
    records.sort(key=lambda item: (_ROUTE_ORDER[item["route"]], item["recorded_at"], item["review_id"]))
    return {
        "schema": INBOX_SCHEMA, "marker": "TEAM_PROOF_INBOX_READ_ONLY", "current_count": len(records),
        "stale_count": stale, "invalid_count": invalid, "truncated": truncated,
        "next_item": records[0] if records else None, "items": records,
        "authority": dict(_AUTHORITY),
        "claim_limits": ["Inbox records are not unique users.", "No effort, time, cost, savings, quality, or productivity value is inferred."],
    }


def install_hook_pack(root: Path) -> dict[str, Any]:
    """Write five inert agent-hook templates without changing any vendor configuration file."""
    workspace = _workspace(root)
    directory = workspace / ".factory" / "proof-review" / "hooks"
    writer = """from pathlib import Path\nimport datetime, json, os, sys\nallowed={'session_start','prompt_submitted','pre_tool','post_tool','agent_stop','error','independent_audit'}\nif len(sys.argv) < 3 or sys.argv[1] not in allowed: raise SystemExit(2)\nrecord={'type':sys.argv[1],'actor':sys.argv[2],'recorded_at':datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')}\nif len(sys.argv)>3: record['tool']=sys.argv[3]\nout=Path('.factory/proof-review/hook-events.jsonl'); out.parent.mkdir(parents=True,exist_ok=True)\nwith out.open('a',encoding='utf-8') as handle: handle.write(json.dumps(record,sort_keys=True,separators=(',',':'))+'\\n')\n"""
    files = {
        "event_writer.py": writer,
        "github-copilot.json": json.dumps({"version": 1, "events": {"sessionStart": "python .factory/proof-review/hooks/event_writer.py session_start copilot", "userPromptSubmitted": "python .factory/proof-review/hooks/event_writer.py prompt_submitted copilot", "preToolUse": "python .factory/proof-review/hooks/event_writer.py pre_tool copilot", "postToolUse": "python .factory/proof-review/hooks/event_writer.py post_tool copilot", "agentStop": "python .factory/proof-review/hooks/event_writer.py agent_stop copilot"}}, indent=2),
        "claude-code.json": json.dumps({"hooks": {"SessionStart": "python .factory/proof-review/hooks/event_writer.py session_start claude", "PreToolUse": "python .factory/proof-review/hooks/event_writer.py pre_tool claude", "PostToolUse": "python .factory/proof-review/hooks/event_writer.py post_tool claude", "Stop": "python .factory/proof-review/hooks/event_writer.py agent_stop claude"}}, indent=2),
        "codex.json": json.dumps({"adapter": "generic-jsonl", "events": ["session_start", "prompt_submitted", "pre_tool", "post_tool", "agent_stop", "error"]}, indent=2),
        "cursor.json": json.dumps({"adapter": "generic-jsonl", "events": ["session_start", "prompt_submitted", "pre_tool", "post_tool", "agent_stop", "error"]}, indent=2),
        "generic-jsonl.json": json.dumps({"schema": "factory.agent-hook-event.v1", "writer": ".factory/proof-review/hooks/event_writer.py", "output": ".factory/proof-review/hook-events.jsonl"}, indent=2),
    }
    artifacts: list[dict[str, str]] = []
    for name, content in files.items():
        target = directory / name
        data = content.encode("utf-8")
        if target.exists() and target.read_bytes() != data:
            raise ProofReviewError("HOOK_PACK_CONFLICT", f"refusing to overwrite changed hook template: {name}")
        _atomic(target, data)
        artifacts.append({"path": target.relative_to(workspace).as_posix(), "sha256": sha256(data).hexdigest()})
    core = {"schema": HOOK_SCHEMA, "marker": "AGENT_HOOK_PACK_WRITTEN", "recorded_at": _now(), "adapters": ["github-copilot", "claude-code", "codex", "cursor", "generic-jsonl"], "artifacts": artifacts, "installed_vendor_config": False, "authority": dict(_AUTHORITY)}
    manifest = _write_receipt(directory / "manifest.json", core, "pack_sha256")
    return {**manifest, "artifact": str(directory / "manifest.json")}


def create_proof_card(root: Path, review_path: Path, card_id: str) -> dict[str, Any]:
    """Export public-safe JSON, Markdown, and SVG views of one current proof review."""
    workspace = _workspace(root)
    if not _ID.fullmatch(card_id):
        raise ProofReviewError("PROOF_CARD_ID_INVALID", "card id must be a lowercase identifier")
    checked = verify_quick_review(workspace, review_path)
    if not checked.get("ok"):
        raise ProofReviewError("PROOF_CARD_REVIEW_INVALID", "proof review must be current and verified")
    review, _, _ = _load(workspace, review_path, "proof review")
    core = {
        "schema": CARD_SCHEMA, "marker": "SHAREABLE_PROOF_CARD_EXPORTED", "card_id": card_id,
        "recorded_at": _now(), "review_id": review["review_id"], "review_sha256": review["review_sha256"],
        "route": review["route"], "changed_path_count": len(review["changed_paths"]),
        "next_action": review["next_action"], "human_approval_required": True, "final_approval": False,
        "claim_limits": ["Ready means ready for human review only.", "No merge, deployment, compliance, production-readiness, user, savings, or productivity claim is made."],
    }
    destination = workspace / ".factory" / "proof-review" / "cards" / card_id
    card = {**core, "card_sha256": _sha(core)}
    json_path = destination / "card.json"
    _atomic(json_path, _canonical(card) + b"\n")
    markdown = f"# Code Factory Proof Card\n\n**Route:** `{card['route']}`  \n**Changed paths:** {card['changed_path_count']}  \n**Next action:** `{card['next_action']['action']}`  \n**Human approval required:** yes  \n**Card SHA-256:** `{card['card_sha256']}`\n\nReady means ready for human review only.\n"
    _atomic(destination / "card.md", markdown.encode("utf-8"))
    colour = {"review_ready": "#17835c", "human_required": "#b33a3a", "reverification_required": "#b06d00", "evidence_required": "#3b67b1"}[card["route"]]
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630"><rect width="1200" height="630" rx="36" fill="#f7f4ec"/><rect x="64" y="64" width="1072" height="502" rx="28" fill="#fff" stroke="#d9d3c5"/><text x="108" y="150" font-family="Arial,sans-serif" font-size="30" fill="#333">CODE FACTORY PROOF CARD</text><text x="108" y="240" font-family="Arial,sans-serif" font-size="58" font-weight="700" fill="{colour}">{html.escape(card['route'])}</text><text x="108" y="320" font-family="Arial,sans-serif" font-size="28" fill="#444">{card['changed_path_count']} changed path(s) · human approval required</text><text x="108" y="390" font-family="Arial,sans-serif" font-size="24" fill="#555">Next: {html.escape(card['next_action']['action'])}</text><text x="108" y="490" font-family="monospace" font-size="18" fill="#666">{card['card_sha256']}</text></svg>'''
    _atomic(destination / "card.svg", svg.encode("utf-8"))
    return {**card, "artifacts": {"json": str(json_path), "markdown": str(destination / "card.md"), "svg": str(destination / "card.svg")}}


def verify_proof_card(card_path: Path) -> dict[str, Any]:
    """Verify a proof-card canonical digest offline without requiring its source workspace."""
    path = Path(card_path).resolve()
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {"schema": CARD_SCHEMA, "marker": "PROOF_CARD_INVALID", "ok": False, "reason": "unreadable"}
    digest = value.get("card_sha256") if isinstance(value, dict) else None
    core = {key: item for key, item in value.items() if key != "card_sha256"} if isinstance(value, dict) else {}
    ok = value.get("schema") == CARD_SCHEMA and isinstance(digest, str) and _SHA.fullmatch(digest) is not None and digest == _sha(core)
    return {"schema": CARD_SCHEMA, "marker": "PROOF_CARD_VERIFIED" if ok else "PROOF_CARD_INVALID", "ok": ok, "card_sha256": digest if ok else None, "reason": None if ok else "receipt_digest"}


def proof_review_projection(root: Path) -> dict[str, Any]:
    """Project bounded inbox counts and the next review item for read-only Graph Ops."""
    inbox = team_proof_inbox(root)
    regressions = Path(root).resolve() / ".factory" / "proof-review" / "regressions"
    return {"current_count": inbox["current_count"], "stale_count": inbox["stale_count"], "invalid_count": inbox["invalid_count"], "next_item": inbox["next_item"], "regression_capsule_count": len(list(regressions.glob("*.json"))) if regressions.is_dir() else 0, "authority": dict(_AUTHORITY)}
