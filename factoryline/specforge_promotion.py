"""Hash-sealed promotion bridge between SpecLine intent and ForgeLine execution."""

from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path
from typing import Any
from .revenueforge import AUTHORITY, RevenueForgeError


def _sha(v: object) -> str:
    return hashlib.sha256(
        json.dumps(v, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _read(root: Path, path: Path) -> tuple[dict[str, Any], Path]:
    p = path.resolve() if path.is_absolute() else (root / path).resolve()
    try:
        p.relative_to(root.resolve())
    except ValueError as e:
        raise RevenueForgeError(
            "SPECFORGE_PATH_REJECTED", "paths must stay in workspace"
        ) from e
    try:
        v = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise RevenueForgeError("SPECFORGE_INPUT_INVALID", "inputs must be JSON") from e
    if not isinstance(v, dict):
        raise RevenueForgeError("SPECFORGE_INPUT_INVALID", "inputs must be objects")
    return v, p


def _output(root: Path, path: Path) -> Path:
    """Resolve a receipt destination and reject any path that escapes the workspace before writing."""
    target = path.resolve() if path.is_absolute() else (root / path).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise RevenueForgeError(
            "SPECFORGE_PATH_REJECTED", "output path must stay in workspace"
        ) from exc
    return target


def _validate_spec(spec: dict[str, Any]) -> None:
    valid = (
        set(spec) == {"schema", "intent", "approval", "obligations", "required_gates"}
        and spec.get("schema") == "factory.specline.delivery-packet.v1"
        and isinstance(spec.get("intent"), dict)
        and isinstance(spec.get("obligations"), list)
        and isinstance(spec.get("required_gates"), list)
        and all(isinstance(item, str) and item for item in spec["required_gates"])
    )
    if not valid:
        raise RevenueForgeError(
            "SPECFORGE_SPEC_INVALID",
            "SpecLine packet must contain intent, approval, obligations, and explicit required_gates",
        )


def _spec_findings(spec: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    approval = spec["approval"]
    if not isinstance(approval, dict) or approval.get("origin") not in {
        "human_confirmed",
        "trusted_source",
    }:
        findings.append("E_SPECLINE_AUTHORITY_MISSING")
    obligations = spec["obligations"]
    if not obligations or not all(
        isinstance(item, dict)
        and item.get("id")
        and item.get("forbidden_behavior")
        and isinstance(item.get("gate"), str)
        and item["gate"] in spec["required_gates"]
        for item in obligations
    ):
        findings.append("E_SPECLINE_OBLIGATION_LOOSE")
    return findings


def _forge_findings(
    spec: dict[str, Any], forge: dict[str, Any], digest: str
) -> list[str]:
    findings: list[str] = []
    if (
        set(forge) != {"schema", "intent_sha256", "state", "gates"}
        or forge.get("schema") != "factory.forgeline.delivery-state.v1"
        or forge.get("intent_sha256") != digest
    ):
        findings.append("E_FORGELINE_INTENT_DRIFT")
    gates = forge.get("gates") if isinstance(forge.get("gates"), dict) else {}
    for gate in spec["required_gates"]:
        if gates.get(gate) is not True:
            findings.append("E_FORGELINE_REQUIRED_GATE_MISSING:" + gate)
    if forge.get("state") != "verified":
        findings.append("E_FORGELINE_STATE_NOT_VERIFIED")
    return findings


def _repair_plan(findings: list[str]) -> list[str]:
    plan: list[str] = []
    for finding in findings:
        if finding == "E_FORGELINE_INTENT_DRIFT":
            plan.append(
                "Re-issue ForgeLine state from the exact approved SpecLine intent."
            )
        elif finding.startswith("E_FORGELINE_REQUIRED"):
            plan.append(
                "Restore the missing selected capability gate with its candidate-bound receipt."
            )
        else:
            plan.append(
                "Confirm intent approval and map every obligation to an explicitly required gate."
            )
    return plan


def _promotion_core(
    spec: dict[str, Any],
    spec_source: Path,
    forge_source: Path,
    root: Path,
    digest: str,
    findings: list[str],
) -> dict[str, Any]:
    ready = not findings
    return {
        "schema": "factory.specforge.promotion-receipt.v1",
        "evidence_level": "declared_topology",
        "marker": "SPECFORGE_PROMOTION_READY"
        if ready
        else "SPECFORGE_PROMOTION_BLOCKED",
        "ok": ready,
        "action_summary": "Bind ForgeLine promotion to one approved SpecLine intent digest and only the explicitly selected capability gates; do not execute, release, or override a human.",
        "intent_sha256": digest,
        "obligation_count": len(spec["obligations"]),
        "required_gates": spec["required_gates"],
        "findings": findings,
        "repair_plan": _repair_plan(findings),
        "sources": {
            "specline": spec_source.relative_to(root).as_posix(),
            "forgeline": forge_source.relative_to(root).as_posix(),
        },
        "authority": {**AUTHORITY, "execution": False, "release": False},
        "claim_boundary": "Local topology and digest validation only; not proof that external SpecLine or ForgeLine ran, nor a release approval.",
    }


def _native_promotion(root: Path, spec: dict, forge: dict) -> dict:
    """Use the same live acceptance and Forge receipt checks as assembly."""
    from .assembly import _forge_intent_trace

    feature = spec.get("feature")
    trace = None
    if (
        isinstance(feature, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", feature)
        and forge.get("intent_evidence") == spec
        and forge.get("shipped") is True
        and forge.get("intent_traceable") is True
    ):
        trace = _forge_intent_trace(root, feature, forge)
    return {
        "schema": "factory.specforge.native-promotion-receipt.v1",
        "evidence_level": "native_trace_verified"
        if trace
        else "native_trace_unverified",
        "marker": "SPECFORGE_PROMOTION_READY"
        if trace
        else "SPECFORGE_PROMOTION_BLOCKED",
        "ok": trace is not None,
        "intent_trace": trace,
        "findings": [] if trace else ["E_SPECFORGE_NATIVE_HANDOFF_UNVERIFIED"],
        "authority": {**AUTHORITY, "execution": False, "release": False},
    }


def verify_specforge_promotion(
    root: Path, spec_path: Path, forge_path: Path, out_path: Path
) -> dict[str, Any]:
    """Fail closed if ForgeLine tries to promote work outside an approved SpecLine packet."""
    root = Path(root).resolve()
    spec, spec_source = _read(root, spec_path)
    forge, forge_source = _read(root, forge_path)
    if spec.get("schema") == "specline.intent-envelope.v1":
        core = _native_promotion(root, spec, forge)
        core["sources"] = {
            "specline": spec_source.relative_to(root).as_posix(),
            "forgeline": forge_source.relative_to(root).as_posix(),
        }
    else:
        _validate_spec(spec)
        digest = _sha(spec["intent"])
        findings = _spec_findings(spec) + _forge_findings(spec, forge, digest)
        core = _promotion_core(spec, spec_source, forge_source, root, digest, findings)
    receipt = {**core, "receipt_sha256": _sha(core)}
    target = _output(root, out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {**receipt, "path": target.relative_to(root).as_posix()}


_JOB_SCHEMA = "factory.specforge.mission-job.v1"
_JOB_FIELDS = frozenset(
    {
        "schema",
        "mission_id",
        "mission_sha256",
        "intent_sha256",
        "intent_file_sha256",
        "source_commit",
        "repository",
        "store_path",
        "phase_plan",
        "job_sha256",
    }
)


def _hex_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _valid_phase_plan(plan):
    from .agentic_control import INCIDENT_PHASES

    return (
        isinstance(plan, dict)
        and set(plan) == set(INCIDENT_PHASES)
        and all(_valid_phase_action(action) for action in plan.values())
    )


def _valid_phase_action(action):
    return (
        isinstance(action, dict)
        and set(action) == {"driver_id", "policy_sha256", "action_sha256"}
        and isinstance(action["driver_id"], str)
        and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,95}", action["driver_id"])
        is not None
        and all(_hex_digest(action[key]) for key in ("policy_sha256", "action_sha256"))
    )


def _job_digest(binding):
    return _sha({key: value for key, value in binding.items() if key != "job_sha256"})


def _job_store_path(root, value):
    if not isinstance(value, str) or not value:
        return None
    path = Path(value)
    expected = (".factory", "workflow-runtime", "runtime.sqlite3")
    if path.is_absolute() or ".." in path.parts or path.parts[-3:] != expected:
        return None
    return path if (root / path).resolve() == root / path else None


def _same_mission_and_source(root, mission, binding):
    from .release_candidate import _git_head

    repository = binding["repository"]
    return (
        binding["mission_id"] == mission["id"]
        and binding["mission_sha256"] == mission["mission_sha256"]
        and isinstance(repository, str)
        and re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", repository)
        is not None
        and len(repository) <= 255
        and _job_store_path(root, binding["store_path"]) is not None
        and isinstance(binding["source_commit"], str)
        and _git_head(root) == binding["source_commit"]
    )


def _validate_factory_job_binding(root, mission, binding, envelope, envelope_file_sha):
    """Revalidate the native intent and exact job payload before ledger admission."""
    from .assembly import _validated_forge_acceptance

    if not isinstance(binding, dict) or set(binding) != _JOB_FIELDS:
        return False
    if not all(
        (
            binding["schema"] == _JOB_SCHEMA,
            _valid_phase_plan(binding["phase_plan"]),
            _hex_digest(binding["intent_sha256"]),
            binding["intent_file_sha256"] == envelope_file_sha,
            binding["job_sha256"] == _job_digest(binding),
        )
    ):
        return False
    feature = envelope.get("feature")
    return (
        envelope.get("schema") == "specline.intent-envelope.v1"
        and isinstance(feature, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", feature) is not None
        and _same_mission_and_source(root, mission, binding)
        and _validated_forge_acceptance(
            root, feature, envelope, binding["intent_sha256"]
        )
    )


def _job_local_source(binding):
    return {
        "provider": "factoryline",
        "account": "local",
        "repository": binding["repository"],
        "kind": "mission",
        "external_id": binding["job_sha256"],
        "revision": 1,
        "head_sha": binding["source_commit"],
        "state": "open",
        "title": f"Factory mission {binding['mission_id']}",
    }


def _job_binding(
    root, mission, envelope, file_sha, store_path, repository, source, plan
):
    if not _valid_phase_plan(plan):
        raise RevenueForgeError("SPECFORGE_JOB_BINDING", "declared phase plan required")
    binding = {
        "schema": _JOB_SCHEMA,
        "mission_id": mission["id"],
        "mission_sha256": mission["mission_sha256"],
        "intent_sha256": envelope.get("sealed_hash"),
        "intent_file_sha256": file_sha,
        "store_path": store_path,
        "repository": repository,
        "source_commit": source,
        "phase_plan": plan,
    }
    binding["job_sha256"] = _job_digest(binding)
    if not _validate_factory_job_binding(root, mission, binding, envelope, file_sha):
        raise RevenueForgeError("SPECFORGE_JOB_BINDING", "current job binding required")
    return binding


def _job_envelope(root, path, mission_id):
    from .mission_graph import _bound_receipt

    return _bound_receipt(root, _output(root, path), mission_id)


def bind_factory_mission_job(
    root,
    mission_path,
    intent_path,
    store,
    owner,
    *,
    repository,
    source_commit,
    phase_plan,
):
    """Bind one authorized mission to the existing incident store idempotently."""
    from .agentic_control import WorkflowEventStore
    from .mission_graph import _canonical, _mission, _sha_bytes, apply_mission_event

    root = Path(root).resolve(strict=True)
    if not isinstance(store, WorkflowEventStore) or not store.path.is_relative_to(root):
        raise RevenueForgeError("SPECFORGE_JOB_STORE", "local workflow store required")
    if (
        not isinstance(repository, str)
        or ("factoryline", "local", repository) not in store.allowed
    ):
        raise RevenueForgeError("SPECFORGE_JOB_STORE", "local source scope not enabled")
    path, mission = _mission(root, _output(root, Path(mission_path)))
    intent, envelope, file_sha = _job_envelope(root, Path(intent_path), mission["id"])
    binding = _job_binding(
        root,
        mission,
        envelope,
        file_sha,
        store.path.relative_to(root).as_posix(),
        repository,
        source_commit,
        phase_plan,
    )
    event = apply_mission_event(
        path,
        root,
        "factory_job_bound",
        owner,
        "owner",
        "factory-job",
        receipt_path=intent,
        payload=binding,
    )
    record = event["event"]
    if event["state"] != "creator_running":
        raise RevenueForgeError(
            "SPECFORGE_JOB_STATE", "mission is not authorized to start"
        )
    outcome = store.intake(
        "mission-" + binding["job_sha256"], _job_local_source(binding)
    )
    item = outcome["item"]
    if item["source"] != _job_local_source(binding):
        raise RevenueForgeError("SPECFORGE_JOB_DRIFT", "workflow source differs")
    return {
        "binding": binding,
        "source_key": item["source_key"],
        "mission_event_sha256": record.get("event_sha256")
        or _sha_bytes(_canonical(record)),
        "authority": {**AUTHORITY, "execution": False, "release": False},
    }


def _live_factory_job(root, mission_path, *, owner=None):
    from .mission_graph import _db_path, _mission, mission_graph_history

    path, mission = _mission(root, _output(root, Path(mission_path)))
    if not _db_path(root, path).is_file():
        raise RevenueForgeError(
            "SPECFORGE_JOB_STATE", "approved mission graph required"
        )
    history = mission_graph_history(path, root)
    if owner is not None and (
        history["state"] != "creator_running" or owner != mission["owner"]
    ):
        raise RevenueForgeError(
            "SPECFORGE_JOB_STATE", "mission is not authorized to run"
        )
    event = next(
        (row for row in history["events"] if row["event"] == "factory_job_bound"),
        None,
    )
    if event is None:
        raise RevenueForgeError("SPECFORGE_JOB_STATE", "mission has no bound job")
    binding = event["payload"]
    _, envelope, file_sha = _job_envelope(
        root, Path(event["receipt"]["path"]), mission["id"]
    )
    if not _validate_factory_job_binding(root, mission, binding, envelope, file_sha):
        raise RevenueForgeError("SPECFORGE_JOB_DRIFT", "bound job inputs changed")
    return binding, history, envelope


def _factory_job_item(root, binding, store):
    from .agentic_control import WorkflowEventStore, _runtime_source_key

    if not isinstance(store, WorkflowEventStore) or (
        store.path != root / binding["store_path"]
    ):
        raise RevenueForgeError("SPECFORGE_JOB_STORE", "bound workflow store required")
    source = _job_local_source(binding)
    item = store.get(_runtime_source_key(source))
    if item["source"] != source:
        raise RevenueForgeError("SPECFORGE_JOB_DRIFT", "workflow source differs")
    return item


def _guarded_factory_driver(root, mission_path, owner, binding, driver):
    from .agentic_control import DurableIncidentDriver

    def current():
        latest, _, _ = _live_factory_job(root, mission_path, owner=owner)
        return latest == binding

    def authorize(requester, intent):
        return (
            requester == owner
            and current()
            and driver.authorizer(requester, intent) is True
            and current()
        )

    def observe(source):
        if not current():
            raise RevenueForgeError("SPECFORGE_JOB_DRIFT", "mission binding changed")
        return driver.source_observer(source)

    return DurableIncidentDriver(
        driver.store,
        driver.drivers,
        authorizer=authorize,
        phase_verifiers=driver.phase_verifiers,
        source_observer=observe,
    )


def advance_factory_mission_job(
    root, mission_path, driver, owner, *, phase_evidence=None, ttl=30
):
    """Reconcile or advance one registered phase under the live mission decision."""
    from .agentic_control import DurableIncidentDriver, INCIDENT_PHASES

    if not isinstance(driver, DurableIncidentDriver):
        raise RevenueForgeError("SPECFORGE_JOB_DRIVER", "registered driver required")
    root = Path(root).resolve(strict=True)
    binding, _, _ = _live_factory_job(root, mission_path, owner=owner)
    item = _factory_job_item(root, binding, driver.store)
    checkpoints = item.get("incident", {}).get("checkpoints", [])
    if not _job_checkpoints_current(item, binding, len(checkpoints)):
        raise RevenueForgeError("SPECFORGE_JOB_DRIFT", "unexpected phase checkpoint")
    if len(checkpoints) == len(INCIDENT_PHASES):
        return {
            "status": "proof_handoff_required",
            "source_key": item["source_key"],
            "authority": {**AUTHORITY, "execution": False, "release": False},
        }
    phase = INCIDENT_PHASES[len(checkpoints)]
    guarded = _guarded_factory_driver(root, mission_path, owner, binding, driver)
    if phase_evidence is not None:
        return guarded.checkpoint(item["source_key"], owner, phase, phase_evidence)
    return guarded.launch_phase(
        item["source_key"], owner, phase, ttl=ttl, **binding["phase_plan"][phase]
    )


def factory_proof_action_sha256(manifest, execution_budget):
    """Digest the proof request that the owner binds to the verify phase."""
    return _sha(
        {
            "schema": "factory.specforge.proof-action.v1",
            "manifest": manifest,
            "execution_budget": execution_budget,
        }
    )


def _job_owned_run(root, path, driver, owner, binding, intent, run_id):
    if driver.authorizer(owner, intent) is not True:
        return False
    current, _, _ = _live_factory_job(root, path, owner=owner)
    item = _factory_job_item(root, binding, driver.store)
    result = item.get("run") or {}
    return (
        current == binding
        and result.get("id") == run_id
        and result.get("epoch") == item["epoch"]
        and result.get("owner") == owner
        and result.get("invalidated") is False
        and result.get("expires_at", 0) > driver.store.clock()
    )


def run_factory_mission_proofs(
    root,
    mission_path,
    driver,
    owner,
    run_id,
    intent,
    manifest,
    *,
    execution_budget=None,
):
    """Run the existing proof scheduler for one authorized, hash-bound verify action."""
    from .agentic_control import DurableIncidentDriver
    from .incremental_scheduler import run_pre_pr

    if not isinstance(driver, DurableIncidentDriver):
        raise RevenueForgeError("SPECFORGE_JOB_DRIVER", "registered driver required")
    root = Path(root).resolve(strict=True)
    binding, _, envelope = _live_factory_job(root, mission_path, owner=owner)
    item = _factory_job_item(root, binding, driver.store)
    action = binding["phase_plan"]["verify"]
    expected, expected_binding = driver._intent(item, "verify", **action)
    run = item.get("run") or {}
    if not isinstance(manifest, dict) or not all(
        (
            manifest.get("feature") == envelope["feature"],
            factory_proof_action_sha256(manifest, execution_budget)
            == action["action_sha256"],
            intent == expected,
            run.get("driver_binding") == expected_binding,
            run.get("id") == run_id,
            _job_checkpoints_current(item, binding, 4),
        )
    ):
        raise RevenueForgeError("SPECFORGE_JOB_PROOF", "proof action binding differs")

    def allowed(_gate):
        return _job_owned_run(
            root, mission_path, driver, owner, binding, expected, run_id
        )

    if not allowed(None):
        raise RevenueForgeError("SPECFORGE_JOB_STATE", "proof action is not authorized")
    driver.store.reserve_factory_proof_dispatch(
        item["source_key"], owner, run_id, expected_binding["action_intent_sha256"]
    )
    proof = run_pre_pr(
        root,
        manifest,
        execute=True,
        execution_budget=execution_budget,
        before_dispatch=allowed,
    )
    if not allowed(None):
        raise RevenueForgeError("SPECFORGE_JOB_STATE", "proof authority changed")
    return proof


def factory_forge_action_sha256():
    """Identify the native ForgeLine ship operation in the sealed repair plan."""
    from .protocol import ASSEMBLY_STAGES

    return _sha(
        {"schema": "factory.specforge.forge-action.v1", "stage": ASSEMBLY_STAGES[-1]}
    )


def _bound_forge_result(root, envelope, report):
    rows = report["stages"]
    if (
        len(rows) != 1
        or rows[0].get("status") != "ok"
        or not rows[0].get("intent_receipt")
    ):
        raise RevenueForgeError(
            "SPECFORGE_JOB_PROOF", "native ForgeLine ship did not verify"
        )
    receipt, _, _ = _job_forge_snapshot(root, rows[0]["intent_receipt"])
    trace = receipt["outputs"].get("intent_trace", {})
    forge = {
        "shipped": trace.get("shipped"),
        "intent_traceable": trace.get("intent_traceable"),
        "intent_hash": trace.get("intent_hash"),
        "intent_evidence": envelope,
    }
    if (
        receipt["outputs"].get("assembly_run_id") != report["run_id"]
        or trace.get("intent_hash") != envelope["sealed_hash"]
        or _native_promotion(root, envelope, forge)["intent_trace"] != trace
    ):
        raise RevenueForgeError(
            "SPECFORGE_JOB_PROOF", "ForgeLine output binding differs"
        )
    return forge


def run_factory_mission_forge(root, mission_path, driver, owner, run_id, intent):
    """Dispatch the existing Forge ship stage exactly once under a live repair lease."""
    from .agentic_control import DurableIncidentDriver
    from .assembly import assemble
    from .contract import write_atomic_json
    from .protocol import ASSEMBLY_STAGES

    if not isinstance(driver, DurableIncidentDriver):
        raise RevenueForgeError("SPECFORGE_JOB_DRIVER", "registered driver required")
    root = Path(root).resolve(strict=True)
    binding, _, envelope = _live_factory_job(root, mission_path, owner=owner)
    item = _factory_job_item(root, binding, driver.store)
    action = binding["phase_plan"]["repair"]
    expected, expected_binding = driver._intent(item, "repair", **action)
    if not (
        factory_forge_action_sha256() == action["action_sha256"]
        and intent == expected
        and (item.get("run") or {}).get("driver_binding") == expected_binding
        and _job_checkpoints_current(item, binding, 3)
        and _job_owned_run(root, mission_path, driver, owner, binding, expected, run_id)
    ):
        raise RevenueForgeError(
            "SPECFORGE_JOB_STATE", "ForgeLine action is not authorized"
        )
    driver.store.reserve_factory_dispatch(
        item["source_key"],
        owner,
        run_id,
        expected_binding["action_intent_sha256"],
        "repair",
    )
    report = assemble(root, envelope["feature"], chain=[ASSEMBLY_STAGES[-1]])
    forge = _bound_forge_result(root, envelope, report)
    path = _output(
        root, Path(binding["store_path"]).parent / f"{binding['job_sha256']}-forge.json"
    )
    write_atomic_json(path, forge, durable=True)
    if not _job_owned_run(root, mission_path, driver, owner, binding, expected, run_id):
        raise RevenueForgeError("SPECFORGE_JOB_STATE", "ForgeLine authority changed")
    return path


def _job_checkpoints_current(item, binding, count):
    from .agentic_control import INCIDENT_PHASES, _sha as hash_record

    checkpoints = item.get("incident", {}).get("checkpoints", [])
    if len(checkpoints) != count or count > len(INCIDENT_PHASES):
        return False
    for name, record in zip(INCIDENT_PHASES, checkpoints):
        action = binding["phase_plan"][name]
        core = {
            key: value for key, value in record.items() if key != "checkpoint_sha256"
        }
        if (
            record.get("phase") != name
            or record.get("checkpoint_sha256") != hash_record(core)
            or record.get("source_sha256") != hash_record(item["source"])
            or any(record.get(key) != value for key, value in action.items())
        ):
            return False
    return True


def _job_completion_checkpoints(item, binding, forge_sha, completion_sha):
    from .agentic_control import INCIDENT_PHASES

    if item.get("run") is not None or not _job_checkpoints_current(
        item, binding, len(INCIDENT_PHASES)
    ):
        return False
    results = {
        row["phase"]: row["result_sha256"] for row in item["incident"]["checkpoints"]
    }
    return (
        results["repair"] == forge_sha
        and results["verify"] == completion_sha
        and results["review"] == completion_sha
    )


def _native_job_proof(root, envelope, forge, completion, candidate, required_files):
    from .verification import verify_feature

    if (
        forge.get("intent_evidence") != envelope
        or not _native_promotion(root, envelope, forge)["ok"]
    ):
        return False
    evidence = {
        (row.get("path"), row.get("sha256"))
        for row in completion.get("evidence", [])
        if isinstance(row, dict)
    }
    subject = candidate["mission"]
    return (
        completion.get("mission")
        == {
            "path": subject["path"],
            "sha256": subject["file_sha256"],
            "mission_sha256": subject["mission_sha256"],
        }
        and _job_candidate_observed(root, candidate, completion, envelope)
        and set(required_files).issubset(evidence)
        and verify_feature(root, envelope["feature"])["shippable"] is True
    )


def _job_candidate_observed(root, candidate, completion, envelope):
    observed = {
        (row["path"], row["sha256"])
        for row in completion["daily_verification"]["source_manifest"]
    }
    workspace = Path(candidate["workspace"])
    expected = {
        ((workspace / row["path"]).relative_to(root).as_posix(), row["sha256"])
        for row in candidate["files"]
        if row["state"] == "existing"
    }
    native_sources = set(envelope["acceptance_evidence"]["sources"].items())
    return (
        bool(expected)
        and len(expected) == len(candidate["files"])
        and expected <= observed
        and expected <= native_sources
    )


def _job_forge_snapshot(root, path):
    from .mission_graph import MAX_EVENT_BYTES

    resolved = _output(root, Path(path))
    with resolved.open("rb") as stream:
        raw = stream.read(MAX_EVENT_BYTES + 1)
    if len(raw) > MAX_EVENT_BYTES:
        raise RevenueForgeError(
            "SPECFORGE_JOB_PROOF", "ForgeLine result exceeds receipt size"
        )
    forge = json.loads(raw)
    if not isinstance(forge, dict):
        raise RevenueForgeError(
            "SPECFORGE_JOB_PROOF", "ForgeLine result must be an object"
        )
    return forge, resolved, hashlib.sha256(raw).hexdigest()


def _verified_job_receipts(root, binding, envelope, item, owner, paths):
    from .product_missions import verify_mission_candidate, verify_mission_completion

    forge, forge_file, forge_sha = _job_forge_snapshot(root, paths["forge"])
    candidate_file, candidate, candidate_sha = _job_envelope(
        root, Path(paths["candidate"]), binding["mission_id"]
    )
    proof_file, proof, proof_sha = _job_envelope(
        root, Path(paths["completion"]), binding["mission_id"]
    )
    if not (
        _job_completion_checkpoints(item, binding, forge_sha, proof_sha)
        and verify_mission_candidate(candidate_file, root, owner=owner)["valid"] is True
        and verify_mission_completion(proof_file)["complete"] is True
        and _native_job_proof(
            root,
            envelope,
            forge,
            proof,
            candidate,
            ((str(forge_file), forge_sha), (str(candidate_file), candidate_sha)),
        )
    ):
        raise RevenueForgeError(
            "SPECFORGE_JOB_PROOF", "current native job proof required"
        )
    return {
        "candidate": (candidate_file, candidate_sha),
        "completion": (proof_file, proof_sha),
        "forge": {"path": forge_file.relative_to(root).as_posix(), "sha256": forge_sha},
        "actors": (proof["creator_id"], proof["verifier_id"]),
    }


def complete_factory_mission_job(
    root, mission_path, store, owner, *, forge_path, candidate_path, completion_path
):
    """Record completion from the same current ForgeLine and FactoryLine proof."""
    from .mission_graph import _mission, apply_mission_event

    root = Path(root).resolve(strict=True)
    path, mission = _mission(root, _output(root, Path(mission_path)))
    if owner != mission["owner"]:
        raise RevenueForgeError("SPECFORGE_JOB_OWNER", "mission owner required")
    binding, history, envelope = _live_factory_job(root, path)
    if history["state"] not in {
        "creator_running",
        "independent_verification",
        "completion_receipted",
    }:
        raise RevenueForgeError(
            "SPECFORGE_JOB_STATE", "mission proof handoff not allowed"
        )
    item = _factory_job_item(root, binding, store)
    receipts = _verified_job_receipts(
        root,
        binding,
        envelope,
        item,
        owner,
        {
            "forge": forge_path,
            "candidate": candidate_path,
            "completion": completion_path,
        },
    )
    job = binding["job_sha256"]
    candidate_file, candidate_sha = receipts["candidate"]
    proof_file, proof_sha = receipts["completion"]
    creator, verifier = receipts["actors"]
    apply_mission_event(
        path,
        root,
        "candidate_ready",
        creator,
        "worker",
        "factory-candidate-" + job,
        receipt_path=candidate_file,
        payload={"factory_job_sha256": job},
        expected_receipt_sha256=candidate_sha,
    )
    return apply_mission_event(
        path,
        root,
        "validation_passed",
        verifier,
        "validator",
        "factory-completion-" + job,
        receipt_path=proof_file,
        payload={"factory_job_sha256": job, "forge": receipts["forge"]},
        expected_receipt_sha256=proof_sha,
    )


def factory_mission_timeline(root, mission_path, store, *, after=0):
    """Project the two authoritative journals through one ordered operator view."""
    root = Path(root).resolve(strict=True)
    binding, mission, envelope = _live_factory_job(root, mission_path)
    return _factory_timeline(root, binding, mission, envelope, store, after)


def _local_factory_mission_timeline(root, mission_path, *, after=0):
    """Read an existing explicitly local-only workflow store from the CLI."""
    from .agentic_control import WorkflowEventStore

    root = Path(root).resolve(strict=True)
    binding, mission, envelope = _live_factory_job(root, mission_path)
    database = root / binding["store_path"]
    if not database.is_file():
        raise RevenueForgeError(
            "SPECFORGE_JOB_STORE", "bound workflow store is missing"
        )
    store = WorkflowEventStore(
        database.parents[2], [("factoryline", "local", binding["repository"])]
    )
    return _factory_timeline(root, binding, mission, envelope, store, after)


def _timeline_job_proof(root, binding, mission, envelope, item):
    job_id = binding["job_sha256"]
    events = {row["idempotency_key"]: row for row in mission["events"]}
    candidate = events.get("factory-candidate-" + job_id)
    completion = events.get("factory-completion-" + job_id)
    if not candidate or not completion or completion["event"] != "validation_passed":
        return False
    try:
        forge = completion["payload"]["forge"]
        paths = {
            "forge": forge["path"],
            "candidate": candidate["receipt"]["path"],
            "completion": completion["receipt"]["path"],
        }
        receipts = _verified_job_receipts(
            root, binding, envelope, item, events["factory-job"]["actor"], paths
        )
        return (
            receipts["forge"] == forge
            and receipts["candidate"][1] == candidate["receipt"]["sha256"]
            and receipts["completion"][1] == completion["receipt"]["sha256"]
        )
    except (ValueError, OSError, KeyError, TypeError):
        return False


def _factory_timeline(root, binding, mission, envelope, store, after):
    item = _factory_job_item(root, binding, store)
    journal = store.history(item["source_key"], after=after, limit=100)
    timeline = [
        {
            "ledger": "mission",
            "sequence": row["version"],
            "event": row["event"],
            "sha256": row["event_sha256"],
        }
        for row in mission["events"]
    ]
    workflow = [
        {
            "ledger": "workflow",
            "sequence": row["sequence"],
            "event": row["action"],
            "state": row["item"]["phase"],
        }
        for row in journal["events"]
    ]
    start = next(
        i for i, row in enumerate(timeline) if row["event"] == "factory_job_bound"
    )
    proof_recorded = _timeline_job_proof(root, binding, mission, envelope, item)
    return {
        "schema": "factory.specforge.mission-timeline.v1",
        "job_sha256": binding["job_sha256"],
        "state": mission["state"],
        "job_proof_recorded": proof_recorded,
        "events": timeline[: start + 1] + workflow + timeline[start + 1 :],
        "workflow_cursor": journal["next_cursor"],
        "workflow_has_more": journal["has_more"],
        "order": "Mission event order with the workflow journal attached at the job binding.",
        "human_interventions": sum(
            row["event"]
            in {
                "approve",
                "defer",
                "reject",
                "pause",
                "resume",
                "plan_revised",
                "retry",
            }
            for row in timeline
        ),
        "next_action": _job_next_action(mission["state"], item, proof_recorded),
        "authority": {**AUTHORITY, "execution": False, "release": False},
    }


def _job_next_action(state, item, proof_recorded):
    from .agentic_control import INCIDENT_PHASES

    if state == "completion_receipted":
        if proof_recorded:
            return "Review the verified completion before requesting release."
        return (
            "Verify the native factory job handoff separately from mission completion."
        )
    if state != "creator_running":
        return "Inspect the current mission decision."
    if item.get("run") is not None:
        return "Reconcile the current phase using its registered driver."
    completed = len(item.get("incident", {}).get("checkpoints", []))
    if completed == len(INCIDENT_PHASES):
        return "Bind the current ForgeLine handoff and FactoryLine completion proof."
    last = item.get("last_run") or {}
    if (
        last.get("terminal_state") == "terminal"
        and last.get("driver_binding", {}).get("phase") == INCIDENT_PHASES[completed]
    ):
        return f"Verify and checkpoint the result for {INCIDENT_PHASES[completed]}."
    return (
        f"Reconcile or start the next registered phase: {INCIDENT_PHASES[completed]}."
    )
