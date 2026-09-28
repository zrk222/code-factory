"""Governed task-specific instruction learning with fresh worker contexts."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import hashlib
import json
import os
import re
import tempfile

from .enterprise_receipts import EnterpriseReceiptError, verify_signed_document
from .failure_guidance import explain_failure


TASK_SCHEMA = "factory.learning.task.v1"
CANDIDATE_SCHEMA = "factory.learning.candidate.v1"
VALIDATION_SCHEMA = "factory.learning.validation.v1"
PROMOTION_SCHEMA = "factory.learning.promotion.v1"
ROLLBACK_SCHEMA = "factory.learning.rollback.v1"
PACKET_SCHEMA = "factory.learning.worker-packet.v1"
EXPERIMENT_SCHEMA = "factory.learning.experiment-plan.v1"
FORENSIC_SCHEMA = "factory.forensic-rejection.v1"
OBSERVER_GATE_PAYLOAD_TYPE = "application/vnd.factory.observer-gate.v1+json"
OBSERVER_REPLAY_SCHEMA = "factory.observer-replay.v1"
OBSERVER_REVIEW_SCHEMA = "factory.specialty-ai-review.v1"
AKU_SCHEMA = "hsf.aku.v1"
MAX_MILESTONES = 50
MAX_CRITERIA = 100
MAX_INSTRUCTIONS = 100
HARNESS_DIMENSIONS = {
    "d1_context_assembly": "prompt inputs, examples, retrieval, and compression",
    "d2_tool_interaction": "tool grants, selection, and retrieval parameters",
    "d3_generation_control": "runtime sampling, token, and stop controls",
    "d4_orchestration": "workflow, state machine, and refinement order",
    "d5_memory_management": "retention, summarization, retrieval, and deletion",
    "d6_output_processing": "parsing, schemas, validators, and fallbacks",
}
SEARCH_VARIANTS = frozenset({"asha", "hyperband", "bohb"})
OBSERVER_GATES = frozenset(
    {
        "forensic-replay",
        "holdout-regression",
        "false-positive-control",
        "specialty-ai-review",
    }
)
FORENSIC_CLASSES = frozenset(
    {
        "mutation_survivor",
        "policy_breach",
        "counterfactual_risk",
        "review_correction",
        "runtime_failure",
    }
)


class LearningLoopError(ValueError):
    """Fail-closed, machine-readable learning-lane error."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.guidance = explain_failure(code, message)


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise LearningLoopError(
            "FORENSIC_PACKET_INVALID", f"{field} must be a SHA-256 digest"
        )
    return value


def _forensic_rows(
    packet: dict[str, Any], key: str, fields: set[str]
) -> list[dict[str, Any]]:
    rows = packet.get(key)
    if not isinstance(rows, list) or len(rows) > MAX_CRITERIA:
        raise LearningLoopError(
            "FORENSIC_PACKET_INVALID", f"{key} must be a bounded array"
        )
    for row in rows:
        if not isinstance(row, dict) or set(row) != fields:
            raise LearningLoopError(
                "FORENSIC_PACKET_INCOMPLETE",
                f"{key} rows must contain {sorted(fields)}",
            )
    return rows


def _forensic_packet_fields() -> set[str]:
    return {
        "schema",
        "candidate_sha256",
        "source_sha256",
        "failure_class",
        "failure_id",
        "failed_mutation_seeds",
        "policy_breaches",
        "counterfactual_profiles",
        "review_corrections",
        "validator_versions",
        "evidence_bindings",
        "unknowns",
    }


def _validate_forensic_header(value: object) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != _forensic_packet_fields()
        or value.get("schema") != FORENSIC_SCHEMA
    ):
        raise LearningLoopError(
            "FORENSIC_PACKET_INCOMPLETE", "packet fields or schema are incomplete"
        )
    _require_digest(value["candidate_sha256"], "candidate_sha256")
    _require_digest(value["source_sha256"], "source_sha256")
    if (
        not isinstance(value["failure_class"], str)
        or value["failure_class"] not in FORENSIC_CLASSES
    ):
        raise LearningLoopError(
            "FORENSIC_PACKET_INVALID", "failure class is not recognized"
        )
    if not isinstance(value["failure_id"], str) or not value["failure_id"].strip():
        raise LearningLoopError("FORENSIC_PACKET_INVALID", "failure id is required")

    return value


def _bind_forensic_evidence(
    root: Path, value: dict[str, Any]
) -> tuple[list[dict[str, Any]], set[str]]:
    bindings = _forensic_rows(
        value, "evidence_bindings", {"id", "kind", "path", "sha256"}
    )
    binding_ids: set[str] = set()
    normalized = []
    for binding in bindings:
        if not all(
            isinstance(binding.get(key), str) and binding[key].strip()
            for key in ("id", "kind", "path")
        ):
            raise LearningLoopError(
                "FORENSIC_PACKET_INVALID", "evidence binding fields are required"
            )
        if binding["id"] in binding_ids:
            raise LearningLoopError(
                "FORENSIC_PACKET_INVALID", "evidence binding ids must be unique"
            )
        binding_ids.add(binding["id"])
        _require_digest(binding["sha256"], "evidence sha256")
        path = _inside(root, Path(binding["path"]), "FORENSIC_EVIDENCE_OUTSIDE_ROOT")
        if _sha(path.read_bytes()) != binding["sha256"]:
            raise LearningLoopError(
                "HASH_INVALID", f"forensic evidence changed: {binding['id']}"
            )
        normalized.append({**binding, "path": str(path)})
    return normalized, binding_ids


def _forensic_event_schemas() -> dict[str, set[str]]:
    return {
        "failed_mutation_seeds": {
            "id",
            "seed_sha256",
            "expected",
            "observed",
            "evidence_id",
        },
        "policy_breaches": {"id", "rule_id", "severity", "evidence_id"},
        "counterfactual_profiles": {
            "id",
            "candidate_sha256",
            "risk_sha256",
            "rank",
            "evidence_id",
        },
        "review_corrections": {
            "id",
            "reviewer",
            "finding_sha256",
            "correction_sha256",
            "evidence_id",
        },
    }


def _validate_forensic_events(value: dict[str, Any], binding_ids: set[str]) -> int:
    events = 0
    for key, fields in _forensic_event_schemas().items():
        rows = _forensic_rows(value, key, fields)
        events += len(rows)
        for row in rows:
            if row["evidence_id"] not in binding_ids:
                raise LearningLoopError(
                    "FORENSIC_PACKET_INCOMPLETE", f"{key} references missing evidence"
                )
    return events


def _validate_forensic_metadata(
    value: dict[str, Any], events: int, bindings: int
) -> None:
    validators = _forensic_rows(value, "validator_versions", {"name", "version"})
    if not validators or not all(
        isinstance(row["name"], str) and isinstance(row["version"], str)
        for row in validators
    ):
        raise LearningLoopError(
            "FORENSIC_PACKET_INCOMPLETE", "validator versions are required"
        )
    unknowns = value["unknowns"]
    if not isinstance(unknowns, list) or not all(
        isinstance(item, str) and item.strip() for item in unknowns
    ):
        raise LearningLoopError(
            "FORENSIC_PACKET_INVALID", "unknowns must be explicit strings"
        )
    if not events or (not bindings and not unknowns):
        raise LearningLoopError(
            "FORENSIC_PACKET_INCOMPLETE",
            "packet needs rejection evidence or explicit unknowns",
        )


def seal_forensic_rejection_packet(root: Path, value: dict[str, Any]) -> dict[str, Any]:
    """Validate and seal a normalized, evidence-bound Factory-B rejection packet."""
    value = _validate_forensic_header(value)
    bindings, binding_ids = _bind_forensic_evidence(root, value)
    events = _validate_forensic_events(value, binding_ids)
    _validate_forensic_metadata(value, events, len(bindings))
    core = {key: value[key] for key in _forensic_packet_fields()}
    core["evidence_bindings"] = bindings
    return {**core, "packet_sha256": _sha(core)}


def validate_forensic_rejection_packet(root: Path, packet_path: Path) -> dict[str, Any]:
    """Load a sealed rejection packet and recheck every source evidence digest."""
    path = _inside(root, packet_path, "FORENSIC_PACKET_OUTSIDE_ROOT")
    try:
        packet = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LearningLoopError(
            "FORENSIC_PACKET_INVALID", "cannot read forensic packet"
        ) from exc
    claimed = packet.get("packet_sha256") if isinstance(packet, dict) else None
    core = (
        {key: item for key, item in packet.items() if key != "packet_sha256"}
        if isinstance(packet, dict)
        else {}
    )
    if claimed != _sha(core):
        raise LearningLoopError("HASH_INVALID", "forensic packet digest does not match")
    return seal_forensic_rejection_packet(root, core)


def diagnose_forensic_rejection(packet: dict[str, Any]) -> dict[str, str]:
    """Return a bounded root-cause hypothesis linked only to packet facts."""
    mapping = {
        "mutation_survivor": ("weak_oracle_or_assertion", "d6_output_processing"),
        "policy_breach": ("planning_or_policy_guard_missing", "d4_orchestration"),
        "counterfactual_risk": (
            "candidate_selection_did_not_control_risk",
            "d4_orchestration",
        ),
        "review_correction": (
            "review_criteria_missed_a_recorded_fact",
            "d6_output_processing",
        ),
        "runtime_failure": ("runtime_boundary_or_recovery_gap", "d4_orchestration"),
    }
    cause, dimension = mapping[packet["failure_class"]]
    return {
        "cause": cause,
        "dimension": dimension,
        "confidence": "hypothesis_requires_replay",
        "failure_id": packet["failure_id"],
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(
        value if isinstance(value, bytes) else _canonical(value)
    ).hexdigest()


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not slug:
        raise LearningLoopError(
            "LEARNING_TASK_INVALID", "task id must contain a letter or number"
        )
    return slug[:64]


def _sealed(core: dict[str, Any], field: str) -> dict[str, Any]:
    return {**core, field: _sha(core)}


def _atomic_json(path: Path, value: dict[str, Any], *, replace: bool = False) -> None:
    data = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    if path.exists() and not replace:
        if path.read_bytes() == data:
            return
        raise LearningLoopError("ARTIFACT_EXISTS", f"refusing to replace {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _load(path: Path, schema: str, hash_field: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LearningLoopError(
            "ARTIFACT_INVALID", f"cannot read {path}: {exc}"
        ) from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise LearningLoopError("SCHEMA_INVALID", f"expected {schema}: {path}")
    claimed = value.get(hash_field)
    core = {
        key: item
        for key, item in value.items()
        if key not in {hash_field, "generated_at"}
    }
    if claimed != _sha(core):
        raise LearningLoopError("HASH_INVALID", f"{hash_field} mismatch: {path}")
    return value


def _inside(root: Path, path: Path, code: str) -> Path:
    root = Path(root).resolve()
    path = Path(path).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise LearningLoopError(
            code, f"artifact must be beneath {root}: {path}"
        ) from exc
    if not path.is_file():
        raise LearningLoopError("EVIDENCE_MISSING", f"artifact not found: {path}")
    return path


def _task_dir(root: Path, task_id: str) -> Path:
    return Path(root).resolve() / ".factory" / "learning" / _slug(task_id)


def _normalize_milestones(milestones: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(milestones, list) or not 1 <= len(milestones) <= MAX_MILESTONES:
        raise LearningLoopError(
            "MILESTONE_CONTRACT_INVALID", f"declare 1-{MAX_MILESTONES} milestones"
        )
    normalized = []
    seen: set[str] = set()
    for position, milestone in enumerate(milestones, 1):
        if not isinstance(milestone, dict):
            raise LearningLoopError(
                "MILESTONE_CONTRACT_INVALID", "each milestone must be an object"
            )
        milestone_id = _slug(str(milestone.get("id", "")))
        criteria = milestone.get("criteria")
        if (
            milestone_id in seen
            or not isinstance(criteria, list)
            or not 1 <= len(criteria) <= MAX_CRITERIA
        ):
            raise LearningLoopError(
                "MILESTONE_CONTRACT_INVALID",
                "milestone ids must be unique and criteria non-empty",
            )
        normalized_criteria = _normalize_criteria(criteria)
        seen.add(milestone_id)
        normalized.append(
            {"id": milestone_id, "position": position, "criteria": normalized_criteria}
        )
    return normalized


def _normalize_criteria(criteria: list[dict[str, Any]]) -> list[dict[str, str]]:
    normalized = []
    criterion_ids: set[str] = set()
    for criterion in criteria:
        if (
            not isinstance(criterion, dict)
            or not str(criterion.get("id", "")).strip()
            or not str(criterion.get("statement", "")).strip()
        ):
            raise LearningLoopError(
                "MILESTONE_CONTRACT_INVALID", "each criterion needs id and statement"
            )
        criterion_id = _slug(str(criterion["id"]))
        if criterion_id in criterion_ids:
            raise LearningLoopError(
                "MILESTONE_CONTRACT_INVALID", f"duplicate criterion: {criterion_id}"
            )
        criterion_ids.add(criterion_id)
        normalized.append(
            {"id": criterion_id, "statement": str(criterion["statement"]).strip()}
        )
    return normalized


def init_learning_task(
    root: Path,
    task_id: str,
    owner: str,
    objective: str,
    milestones: list[dict[str, Any]],
    *,
    force: bool = False,
) -> dict[str, Any]:
    """Create a task contract with ordered, criterion-bearing milestones."""
    if not owner.strip() or not objective.strip():
        raise LearningLoopError(
            "LEARNING_TASK_INVALID", "owner and objective are required"
        )
    normalized = _normalize_milestones(milestones)
    task = _sealed(
        {
            "schema": TASK_SCHEMA,
            "id": _slug(task_id),
            "owner": owner.strip(),
            "objective": objective.strip(),
            "milestones": normalized,
            "control_surfaces": HARNESS_DIMENSIONS,
            "governance": {
                "autonomy": "human_controlled",
                "candidate_authority": "none",
                "promotion_requires": [
                    "distinct_validator",
                    "all_criteria_pass",
                    "recorded_owner",
                ],
            },
            "markers": [
                "LEARNING_TASK_BOUND",
                "MILESTONE_GATES_BOUND",
                "HUMAN_PROMOTION_REQUIRED",
            ],
        },
        "task_sha256",
    )
    path = _task_dir(root, task_id) / "task.json"
    _atomic_json(path, task, replace=force)
    return {**task, "path": str(path)}


def _milestone(task: dict[str, Any], milestone_id: str) -> dict[str, Any]:
    for milestone in task["milestones"]:
        if milestone["id"] == _slug(milestone_id):
            return milestone
    raise LearningLoopError("MILESTONE_UNKNOWN", f"unknown milestone: {milestone_id}")


def _promotion_path(task_path: Path, milestone_id: str) -> Path:
    return (
        Path(task_path).resolve().parent / "promotions" / f"{_slug(milestone_id)}.json"
    )


def _assert_prior_milestones(
    task: dict[str, Any], task_path: Path, milestone: dict[str, Any]
) -> None:
    for prior in task["milestones"][: milestone["position"] - 1]:
        path = _promotion_path(task_path, prior["id"])
        if not path.exists():
            raise LearningLoopError(
                "MILESTONE_ORDER_BLOCKED",
                f"complete {prior['id']} before {milestone['id']}",
            )
        _load(path, PROMOTION_SCHEMA, "promotion_sha256")


def _prepare_forensic_candidate(
    root: Path,
    packet_path: Path | None,
    outcome: Path,
    milestone: dict[str, Any],
    instructions: list[dict[str, str]],
) -> tuple[dict[str, Any] | None, dict[str, str] | None]:
    if packet_path is None:
        return None, None
    forensic = validate_forensic_rejection_packet(root, packet_path)
    try:
        outcome_value = json.loads(outcome.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LearningLoopError(
            "FORENSIC_OUTCOME_INVALID", "forensic outcome must be JSON"
        ) from exc
    if (
        not isinstance(outcome_value, dict)
        or outcome_value.get("candidate_sha256") != forensic["candidate_sha256"]
        or outcome_value.get("source_sha256") != forensic["source_sha256"]
    ):
        raise LearningLoopError(
            "FORENSIC_CANDIDATE_MISMATCH",
            "outcome and rejection packet identify different source",
        )
    required_gates = OBSERVER_GATES
    declared_gates = {item["id"] for item in milestone["criteria"]}
    if not required_gates.issubset(declared_gates):
        raise LearningLoopError(
            "OBSERVER_GATES_INCOMPLETE",
            f"forensic milestone needs {sorted(required_gates)}",
        )
    diagnosis = diagnose_forensic_rejection(forensic)
    dimensions = {item["dimension"] for item in instructions}
    if diagnosis["dimension"] not in dimensions:
        raise LearningLoopError(
            "OBSERVER_SKILL_SCOPE",
            "instruction proposal must address the diagnosed control dimension",
        )
    return forensic, diagnosis


def propose_instruction_candidate(
    task_path: Path,
    root: Path,
    milestone_id: str,
    worker: str,
    outcome_path: Path,
    instructions: list[dict[str, str]],
    *,
    forensic_packet_path: Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Bind one worker outcome to an untrusted task-specific instruction candidate."""
    task = _load(task_path, TASK_SCHEMA, "task_sha256")
    milestone = _milestone(task, milestone_id)
    _assert_prior_milestones(task, task_path, milestone)
    worker = worker.strip()
    clean = _normalize_instruction_edits(instructions)
    if not worker:
        raise LearningLoopError(
            "INSTRUCTION_CANDIDATE_INVALID", "worker identity is required"
        )
    outcome = _inside(root, outcome_path, "OUTCOME_OUTSIDE_ROOT")
    forensic, diagnosis = _prepare_forensic_candidate(
        root, forensic_packet_path, outcome, milestone, clean
    )
    previous_path = _promotion_path(task_path, milestone["id"])
    previous = (
        _load(previous_path, PROMOTION_SCHEMA, "promotion_sha256")
        if previous_path.exists()
        else None
    )
    core = {
        "schema": CANDIDATE_SCHEMA,
        "task": {"path": str(Path(task_path).resolve()), "sha256": task["task_sha256"]},
        "milestone": milestone,
        "worker": worker,
        "outcome": {"path": str(outcome), "sha256": _sha(outcome.read_bytes())},
        "instruction_edits": clean,
        "instructions": [item["instruction"] for item in clean],
        "forensic_rejection": {
            "path": str(Path(forensic_packet_path).resolve()),
            "root": str(Path(root).resolve()),
            "packet_sha256": forensic["packet_sha256"],
            "candidate_sha256": forensic["candidate_sha256"],
            "source_sha256": forensic["source_sha256"],
            "diagnosis": diagnosis,
            "authority": {"edit_skill": False, "approve": False, "promote": False},
        }
        if forensic
        else None,
        "supersedes_promotion_sha256": previous.get("promotion_sha256")
        if previous
        else None,
        "trust": "untrusted_candidate",
        "authority": {"activate": False, "promote": False, "edit_opinion_dock": False},
        "markers": ["INSTRUCTION_CANDIDATE_BOUND", "CANDIDATE_UNTRUSTED"],
    }
    candidate = {**_sealed(core, "candidate_sha256"), "generated_at": _now()}
    path = (
        Path(task_path).resolve().parent
        / "candidates"
        / f"{milestone['id']}-{candidate['candidate_sha256'][:12]}.json"
    )
    _atomic_json(path, candidate, replace=force)
    return {**candidate, "path": str(path)}


def _normalize_instruction_edits(
    instructions: list[dict[str, str]],
) -> list[dict[str, str]]:
    if (
        not isinstance(instructions, list)
        or not 1 <= len(instructions) <= MAX_INSTRUCTIONS
    ):
        raise LearningLoopError(
            "INSTRUCTION_CANDIDATE_INVALID",
            f"declare 1-{MAX_INSTRUCTIONS} instruction edits",
        )
    clean = []
    for item in instructions:
        if not isinstance(item, dict):
            raise LearningLoopError(
                "INSTRUCTION_CANDIDATE_INVALID",
                "each edit needs dimension and instruction",
            )
        dimension = str(item.get("dimension", "")).strip()
        instruction = str(item.get("instruction", "")).strip()
        if dimension not in HARNESS_DIMENSIONS or not instruction:
            raise LearningLoopError(
                "INSTRUCTION_CANDIDATE_INVALID",
                "use a declared d1-d6 dimension and non-empty instruction",
            )
        clean.append({"dimension": dimension, "instruction": instruction})
    if len({(item["dimension"], item["instruction"]) for item in clean}) != len(clean):
        raise LearningLoopError(
            "INSTRUCTION_CANDIDATE_INVALID", "instruction edits must be unique"
        )
    return clean


def _normalize_validation_results(
    root: Path, results: list[dict[str, Any]], expected: set[str]
) -> tuple[list[dict[str, Any]], bool]:
    observed = [str(item.get("id", "")) for item in results if isinstance(item, dict)]
    if set(observed) != expected or len(observed) != len(expected):
        raise LearningLoopError(
            "MILESTONE_VALIDATION_INCOMPLETE", "validate every criterion exactly once"
        )
    normalized = []
    all_passed = True
    for result in results:
        evidence_values = result.get("evidence")
        if not isinstance(evidence_values, list) or not evidence_values:
            raise LearningLoopError(
                "MILESTONE_VALIDATION_INCOMPLETE",
                f"criterion {result['id']} requires evidence",
            )
        evidence = [_bound_evidence(root, value) for value in evidence_values]
        passed = result.get("passed") is True
        all_passed = all_passed and passed
        normalized.append({"id": result["id"], "passed": passed, "evidence": evidence})
    return sorted(normalized, key=lambda item: item["id"]), all_passed


def _bound_evidence(root: Path, value: object) -> dict[str, str]:
    path = _inside(root, Path(str(value)), "EVIDENCE_OUTSIDE_ROOT")
    return {"path": str(path), "sha256": _sha(path.read_bytes())}


def _observer_trust_root(root: Path, trust_root_path: Path | None) -> Path:
    if trust_root_path is None:
        raise LearningLoopError(
            "OBSERVER_TRUST_ROOT_REQUIRED",
            "forensic gates require a separately administered DSSE trust root",
        )
    workspace = root.resolve()
    trust_root = Path(trust_root_path).resolve()
    if trust_root == workspace or workspace in trust_root.parents:
        raise LearningLoopError(
            "OBSERVER_TRUST_ROOT_IN_WORKSPACE",
            "store the observer trust root outside the candidate workspace",
        )
    return trust_root


def _observer_payload(
    path: Path, result: dict[str, Any], trust_root_path: Path
) -> tuple[dict[str, Any], str]:
    schema = (
        OBSERVER_REVIEW_SCHEMA
        if result["id"] == "specialty-ai-review"
        else OBSERVER_REPLAY_SCHEMA
    )
    try:
        verified = verify_signed_document(
            path,
            payload_type=OBSERVER_GATE_PAYLOAD_TYPE,
            schema=schema,
            trust_root_path=trust_root_path,
        )
    except (EnterpriseReceiptError, OSError) as exc:
        raise LearningLoopError(
            "OBSERVER_SIGNATURE_INVALID",
            f"{result['id']} evidence needs a valid signature from the configured trust root",
        ) from exc
    identity = verified["signature"].get("identity")
    if not isinstance(identity, str) or not identity:
        raise LearningLoopError(
            "OBSERVER_SIGNATURE_INVALID", f"{result['id']} signer identity is missing"
        )
    return verified["payload"], identity


def _verify_observer_gate_receipt(
    result: dict[str, Any],
    candidate: dict[str, Any],
    validator: str,
    trust_root_path: Path,
) -> None:
    forensic = candidate["forensic_rejection"]
    for binding in result["evidence"]:
        path = Path(binding["path"])
        receipt, signer = _observer_payload(path, result, trust_root_path)
        common = (
            receipt.get("candidate_sha256") == forensic["candidate_sha256"]
            and receipt.get("forensic_packet_sha256") == forensic["packet_sha256"]
        )
        if result["id"] == "specialty-ai-review":
            valid = (
                signer == validator
                and signer.startswith("specialty-ai:")
                and receipt.get("reviewer_agent") == validator
                and receipt.get("verdict") == "APPROVE"
                and receipt.get("findings") == []
            )
        else:
            valid = (
                signer != candidate["worker"]
                and receipt.get("check_id") == result["id"]
                and receipt.get("result") == "PASS"
            )
        if not common or not valid:
            raise LearningLoopError(
                "OBSERVER_EVIDENCE_MISMATCH",
                f"{result['id']} receipt does not bind this candidate and packet",
            )


def _validate_specialty_candidate(
    candidate: dict[str, Any], root: Path, validator: str
) -> dict[str, Any] | None:
    forensic = candidate.get("forensic_rejection")
    if not forensic:
        return None
    if not validator.startswith("specialty-ai:"):
        raise LearningLoopError(
            "SPECIALTY_REVIEW_REQUIRED",
            "forensic skill updates require a specialty AI validator",
        )
    packet = validate_forensic_rejection_packet(root, Path(forensic["path"]))
    if packet["packet_sha256"] != forensic["packet_sha256"]:
        raise LearningLoopError(
            "HASH_INVALID", "forensic packet changed after proposal"
        )
    return forensic


def _verify_observer_results(
    results: list[dict[str, Any]],
    candidate: dict[str, Any],
    validator: str,
    forensic: dict[str, Any] | None,
    trust_root_path: Path | None,
) -> None:
    if not forensic:
        return
    trusted_root = _observer_trust_root(Path(forensic["root"]), trust_root_path)
    for result in results:
        if result["id"] in OBSERVER_GATES:
            _verify_observer_gate_receipt(
                result, candidate, validator, trusted_root
            )


def validate_instruction_candidate(
    candidate_path: Path,
    root: Path,
    validator: str,
    results: list[dict[str, Any]],
    *,
    force: bool = False,
    observer_trust_root: Path | None = None,
) -> dict[str, Any]:
    """Independently validate every milestone criterion with bound evidence."""
    candidate = _load(candidate_path, CANDIDATE_SCHEMA, "candidate_sha256")
    validator = validator.strip()
    if not validator or validator == candidate["worker"]:
        raise LearningLoopError(
            "VALIDATOR_IDENTITY_DISTINCT",
            "validator must differ from the candidate worker",
        )
    forensic = _validate_specialty_candidate(candidate, root, validator)
    expected = {item["id"] for item in candidate["milestone"]["criteria"]}
    normalized, all_passed = _normalize_validation_results(root, results, expected)
    _verify_observer_results(
        normalized, candidate, validator, forensic, observer_trust_root
    )
    core = {
        "schema": VALIDATION_SCHEMA,
        "candidate": {
            "path": str(Path(candidate_path).resolve()),
            "sha256": candidate["candidate_sha256"],
        },
        "worker": candidate["worker"],
        "validator": validator,
        "milestone_id": candidate["milestone"]["id"],
        "forensic_packet_sha256": forensic["packet_sha256"] if forensic else None,
        "results": normalized,
        "valid": all_passed,
        "markers": [
            "VALIDATOR_CONTEXT_INDEPENDENT",
            "MILESTONE_EVIDENCE_BOUND",
            "MILESTONE_VALIDATED" if all_passed else "MILESTONE_REJECTED",
        ],
        "authority": {"activate": False, "promote": False},
    }
    validation = {**_sealed(core, "validation_sha256"), "generated_at": _now()}
    path = (
        Path(candidate_path).resolve().parent.parent
        / "validations"
        / f"{candidate['candidate_sha256'][:12]}.json"
    )
    _atomic_json(path, validation, replace=force)
    return {**validation, "path": str(path)}


def _promotion_context(
    validation_path: Path, owner: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    validation = _load(validation_path, VALIDATION_SCHEMA, "validation_sha256")
    candidate = _load(
        Path(validation["candidate"]["path"]), CANDIDATE_SCHEMA, "candidate_sha256"
    )
    task = _load(Path(candidate["task"]["path"]), TASK_SCHEMA, "task_sha256")
    owner = owner.strip()
    if owner != task["owner"]:
        raise LearningLoopError(
            "OWNER_MISMATCH", "promotion owner must match the learning task owner"
        )
    if owner in {candidate["worker"], validation["validator"]}:
        raise LearningLoopError(
            "PROMOTER_IDENTITY_DISTINCT",
            "owner, worker, and validator must be distinct",
        )
    if not validation["valid"]:
        raise LearningLoopError(
            "MILESTONE_VALIDATION_INCOMPLETE", "a rejected candidate cannot be promoted"
        )
    return validation, candidate, task, owner


def _validate_promotion_evidence(
    validation: dict[str, Any], candidate: dict[str, Any]
) -> dict[str, Any] | None:
    outcome = Path(candidate["outcome"]["path"])
    if (
        not outcome.is_file()
        or _sha(outcome.read_bytes()) != candidate["outcome"]["sha256"]
    ):
        raise LearningLoopError("HASH_INVALID", "candidate outcome evidence drifted")
    forensic = candidate.get("forensic_rejection")
    if forensic:
        packet = validate_forensic_rejection_packet(
            Path(forensic["root"]), Path(forensic["path"])
        )
        if packet["packet_sha256"] != forensic["packet_sha256"]:
            raise LearningLoopError(
                "HASH_INVALID", "forensic packet changed before promotion"
            )
    for result in validation["results"]:
        for evidence in result["evidence"]:
            path = Path(evidence["path"])
            if not path.is_file() or _sha(path.read_bytes()) != evidence["sha256"]:
                raise LearningLoopError(
                    "HASH_INVALID", f"validation evidence drifted: {path}"
                )
    return forensic


def _previous_promotion(
    candidate: dict[str, Any], validation: dict[str, Any]
) -> dict[str, Any] | None:
    if not candidate.get("supersedes_promotion_sha256"):
        return None
    return _load(
        _promotion_path(Path(candidate["task"]["path"]), validation["milestone_id"]),
        PROMOTION_SCHEMA,
        "promotion_sha256",
    )


def promote_instruction_candidate(
    validation_path: Path, owner: str, *, force: bool = False
) -> dict[str, Any]:
    """Promote a validated candidate into an active AKU under recorded human authority."""
    validation, candidate, task, owner = _promotion_context(validation_path, owner)
    forensic = _validate_promotion_evidence(validation, candidate)
    previous = _previous_promotion(candidate, validation)
    promotion = _make_instruction_promotion(
        validation, candidate, task, owner, forensic, previous
    )
    path = _promotion_path(Path(candidate["task"]["path"]), validation["milestone_id"])
    return _store_instruction_promotion(path, promotion, candidate, force)


def _make_instruction_promotion(
    validation: dict[str, Any],
    candidate: dict[str, Any],
    task: dict[str, Any],
    owner: str,
    forensic: dict[str, Any] | None,
    previous: dict[str, Any] | None,
) -> dict[str, Any]:
    previous_version = previous["aku"]["metadata"]["version"] if previous else 0
    aku = {
        "schema": AKU_SCHEMA,
        "intent": {
            "task_id": task["id"],
            "milestone_id": validation["milestone_id"],
            "objective": task["objective"],
        },
        "procedure": candidate["instructions"],
        "instruction_edits": candidate["instruction_edits"],
        "tools": [],
        "metadata": {
            "owner": owner,
            "version": previous_version + 1,
            "control_dimensions": sorted(
                {item["dimension"] for item in candidate["instruction_edits"]}
            ),
            "provenance": {
                "candidate_sha256": candidate["candidate_sha256"],
                "validation_sha256": validation["validation_sha256"],
                "forensic_packet_sha256": forensic["packet_sha256"]
                if forensic
                else None,
            },
        },
        "governance": {
            "autonomy": "supervised",
            "runtime_model_boundary": "worker receives packet only",
            "out_of_bounds": [
                "self-promotion",
                "creator self-validation",
                "hidden-reasoning transfer",
            ],
        },
        "continuations": {
            "success": "advance to the next milestone",
            "failure": "submit a new candidate",
            "escalation": "return to the recorded owner",
        },
        "validators": {
            "pre": ["task hash"],
            "post": [item["id"] for item in validation["results"]],
            "invariant": ["fresh context", "distinct validator", "human promotion"],
        },
    }
    core = {
        "schema": PROMOTION_SCHEMA,
        "task": candidate["task"],
        "milestone_id": validation["milestone_id"],
        "worker": candidate["worker"],
        "validator": validation["validator"],
        "owner": owner,
        "candidate_sha256": candidate["candidate_sha256"],
        "validation_sha256": validation["validation_sha256"],
        "previous_promotion_sha256": candidate["supersedes_promotion_sha256"],
        "aku": aku,
        "markers": ["HUMAN_PROMOTION_BOUND", "AKU_ACTIVATED", "MILESTONE_GATE_PASSED"],
        "authority": "instruction activation only; no execution, merge, deployment, or Opinion Dock edit",
    }
    return {**_sealed(core, "promotion_sha256"), "generated_at": _now()}


def _store_instruction_promotion(
    path: Path, promotion: dict[str, Any], candidate: dict[str, Any], force: bool
) -> dict[str, Any]:
    if path.exists():
        current = _load(path, PROMOTION_SCHEMA, "promotion_sha256")
        expected = candidate.get("supersedes_promotion_sha256")
        if current["promotion_sha256"] != expected:
            raise LearningLoopError(
                "PROMOTION_STALE", "active promotion changed after candidate proposal"
            )
        if current["promotion_sha256"] != promotion["promotion_sha256"]:
            if not force:
                raise LearningLoopError(
                    "ARTIFACT_EXISTS", f"refusing to replace {path} without --force"
                )
            history_path = _promotion_history_path(path, current["promotion_sha256"])
            _atomic_json(history_path, current)
    _atomic_json(path, promotion, replace=force)
    return {**promotion, "path": str(path)}


def _promotion_history_path(promotion_path: Path, promotion_sha256: str) -> Path:
    return (
        promotion_path.parent
        / "history"
        / f"{promotion_path.stem}-{promotion_sha256[:16]}.json"
    )


def _find_historical_promotion(
    history_root: Path, promotion_sha256: str
) -> dict[str, Any] | None:
    history_files = sorted(history_root.glob("*.json")) if history_root.exists() else []
    for path in history_files:
        item = _load(path, PROMOTION_SCHEMA, "promotion_sha256")
        if item["promotion_sha256"] == promotion_sha256:
            return item
    return None


def _restore_active_promotion(
    task: dict[str, Any],
    owner: str,
    archived: dict[str, Any],
    active_path: Path,
    current: dict[str, Any] | None,
    history_root: Path,
) -> dict[str, Any]:
    if current:
        current_history = _promotion_history_path(
            active_path, current["promotion_sha256"]
        )
        _atomic_json(current_history, current)
    core = {
        "schema": ROLLBACK_SCHEMA,
        "task_sha256": task["task_sha256"],
        "milestone_id": archived["milestone_id"],
        "owner": owner,
        "from_promotion_sha256": current["promotion_sha256"] if current else None,
        "to_promotion_sha256": archived["promotion_sha256"],
        "restored_version": archived["aku"]["metadata"]["version"],
    }
    rollback = _sealed(core, "rollback_sha256")
    rollback_path = history_root / "rollbacks" / f"{rollback['rollback_sha256']}.json"
    _atomic_json(rollback_path, rollback)
    _atomic_json(active_path, archived, replace=True)
    return {
        **archived,
        "path": str(active_path),
        "rollback": {**rollback, "path": str(rollback_path)},
        "restored": True,
    }


def restore_instruction_promotion(
    task_path: Path, owner: str, promotion_sha256: str
) -> dict[str, Any]:
    """Restore an immutable prior promotion and record the owner-authorized rollback."""
    task_path = Path(task_path).resolve()
    task = _load(task_path, TASK_SCHEMA, "task_sha256")
    owner = owner.strip()
    if owner != task["owner"]:
        raise LearningLoopError(
            "OWNER_MISMATCH", "rollback owner must match the learning task owner"
        )
    if not isinstance(promotion_sha256, str) or not re.fullmatch(
        r"[a-f0-9]{64}", promotion_sha256
    ):
        raise LearningLoopError(
            "PROMOTION_HASH_INVALID", "promotion_sha256 must be a SHA-256 digest"
        )
    history_root = task_path.parent / "promotions" / "history"
    archived = _find_historical_promotion(history_root, promotion_sha256)
    if archived is None:
        raise LearningLoopError(
            "PROMOTION_HISTORY_NOT_FOUND",
            "no immutable promotion with that hash exists for this task",
        )
    if archived["task"]["sha256"] != task["task_sha256"]:
        raise LearningLoopError(
            "TASK_MISMATCH", "archived promotion belongs to another learning task"
        )
    milestone = _milestone(task, archived["milestone_id"])
    active_path = _promotion_path(task_path, milestone["id"])
    current = (
        _load(active_path, PROMOTION_SCHEMA, "promotion_sha256")
        if active_path.exists()
        else None
    )
    if current and current["promotion_sha256"] == promotion_sha256:
        return {
            **archived,
            "path": str(active_path),
            "rollback": None,
            "restored": False,
        }
    return _restore_active_promotion(
        task, owner, archived, active_path, current, history_root
    )


def build_fresh_worker_packet(
    task_path: Path, milestone_id: str, worker: str, *, force: bool = False
) -> dict[str, Any]:
    """Emit a fresh worker packet containing facts and promoted instructions, never prior reasoning."""
    task = _load(task_path, TASK_SCHEMA, "task_sha256")
    milestone = _milestone(task, milestone_id)
    _assert_prior_milestones(task, task_path, milestone)
    worker = worker.strip()
    if not worker:
        raise LearningLoopError("WORKER_ID_INVALID", "worker identity is required")
    promotion_path = _promotion_path(task_path, milestone["id"])
    promotion = (
        _load(promotion_path, PROMOTION_SCHEMA, "promotion_sha256")
        if promotion_path.exists()
        else None
    )
    packet_core = {
        "schema": PACKET_SCHEMA,
        "task": {
            "id": task["id"],
            "objective": task["objective"],
            "sha256": task["task_sha256"],
        },
        "milestone": milestone,
        "worker": worker,
        "instructions": promotion["aku"]["procedure"] if promotion else [],
        "harness_adaptation": {
            dimension: [
                item["instruction"]
                for item in promotion["aku"].get("instruction_edits", [])
                if item["dimension"] == dimension
            ]
            if promotion
            else []
            for dimension in HARNESS_DIMENSIONS
        },
        "instruction_promotion_sha256": promotion.get("promotion_sha256")
        if promotion
        else None,
        "instruction_version": promotion["aku"]["metadata"]["version"]
        if promotion
        else None,
        "context": {"fresh": True, "prior_reasoning": [], "prior_worker_outputs": []},
        "authority": {
            "validate_self": False,
            "promote_instructions": False,
            "edit_opinion_dock": False,
            "external_effects": False,
        },
        "markers": [
            "FRESH_WORKER_CONTEXT",
            "PROMOTED_INSTRUCTIONS_ONLY",
            "WORKER_AUTHORITY_BOUNDED",
        ],
    }
    packet = {**_sealed(packet_core, "packet_sha256"), "generated_at": _now()}
    path = (
        Path(task_path).resolve().parent
        / "packets"
        / f"{milestone['id']}-{_slug(worker)}-{packet['packet_sha256'][:10]}.json"
    )
    _atomic_json(path, packet, replace=force)
    return {**packet, "path": str(path)}


def plan_learning_experiment(
    task_path: Path,
    search_space: dict[str, list[Any]],
    *,
    variant: str = "asha",
    max_resource: int = 50,
    grace_period: int = 5,
    reduction_factor: int = 3,
    max_concurrent: int = 4,
    samples: int = 20,
    force: bool = False,
) -> dict[str, Any]:
    """Write a bounded correctness-first Hyperband-family experiment contract."""
    task = _load(task_path, TASK_SCHEMA, "task_sha256")
    _validate_experiment_inputs(
        search_space,
        variant,
        max_resource,
        grace_period,
        reduction_factor,
        max_concurrent,
        samples,
    )
    core = {
        "schema": EXPERIMENT_SCHEMA,
        "task": {"path": str(Path(task_path).resolve()), "sha256": task["task_sha256"]},
        "variant": variant,
        "scheduler": {
            "time_attr": "evaluation_iteration",
            "max_resource": max_resource,
            "grace_period": grace_period,
            "reduction_factor": reduction_factor,
            "max_concurrent": max_concurrent,
            "samples": samples,
            "asynchronous": variant == "asha",
            "guided_sampler": "bohb"
            if variant == "bohb"
            else "random_or_adapter_supplied",
        },
        "objective": {
            "ordering": "lexicographic",
            "primary": {
                "metric": "correctness",
                "mode": "max",
                "required": True,
                "range": [0.0, 1.0],
            },
            "tie_breakers": [
                {"metric": "cost_usd", "mode": "min"},
                {"metric": "tokens", "mode": "min"},
                {"metric": "latency_seconds", "mode": "min"},
            ],
            "promotion_rule": "search ranking proposes candidates only; milestone validation and human promotion remain required",
        },
        "search_space": {key: search_space[key] for key in sorted(search_space)},
        "adapter": {
            "runner": "external",
            "harbor_compatible": True,
            "required_report_fields": [
                "trial_id",
                "evaluation_iteration",
                "correctness",
                "cost_usd",
                "tokens",
                "latency_seconds",
                "evidence_path",
            ],
        },
        "authority": {
            "execute": False,
            "read_credentials": False,
            "train": False,
            "promote": False,
        },
        "markers": [
            "SEARCH_PLAN_BOUND",
            "CORRECTNESS_FIRST_OBJECTIVE",
            "EARLY_STOPPING_BOUNDED",
            "EXTERNAL_RUNNER_NO_AUTHORITY",
        ],
    }
    plan = {**_sealed(core, "experiment_sha256"), "generated_at": _now()}
    path = (
        Path(task_path).resolve().parent
        / "experiments"
        / f"{variant}-{plan['experiment_sha256'][:12]}.json"
    )
    _atomic_json(path, plan, replace=force)
    return {**plan, "path": str(path)}


def _validate_experiment_inputs(
    search_space: dict[str, list[Any]],
    variant: str,
    max_resource: int,
    grace_period: int,
    reduction_factor: int,
    max_concurrent: int,
    samples: int,
) -> None:
    if variant not in SEARCH_VARIANTS:
        raise LearningLoopError(
            "SEARCH_VARIANT_INVALID",
            f"variant must be one of {', '.join(sorted(SEARCH_VARIANTS))}",
        )
    if not search_space or set(search_space) - set(HARNESS_DIMENSIONS):
        raise LearningLoopError(
            "SEARCH_SPACE_INVALID",
            "search space keys must be declared d1-d6 dimensions",
        )
    if any(
        not isinstance(values, list) or not values for values in search_space.values()
    ):
        raise LearningLoopError(
            "SEARCH_SPACE_INVALID",
            "every selected dimension requires at least one candidate value",
        )
    if not (1 <= grace_period <= max_resource <= 10000 and 2 <= reduction_factor <= 10):
        raise LearningLoopError(
            "SEARCH_BUDGET_INVALID",
            "require 1 <= grace_period <= max_resource <= 10000 and reduction factor 2-10",
        )
    if not (1 <= max_concurrent <= 1000 and 1 <= samples <= 100000):
        raise LearningLoopError(
            "SEARCH_BUDGET_INVALID",
            "concurrency and sample budgets exceed published bounds",
        )
