from __future__ import annotations

import copy
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import threading

import pytest

from factoryline.atomic_proof_adapter import (
    BOUND_MARKER,
    MAX_BYTES,
    MCP_MARKER,
    AtomicProofAdapterError,
    atomic_envelope_template,
    atomic_proof_projection,
    import_atomic_run,
    verify_atomic_receipt,
)
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.oracle_firewall import capture_intent_handoff, seal_oracle_contract


AGENT = {
    "schema": "factory.agent-identity.v1",
    "subject": "atomic-worker",
    "provider": "atomic-exporter",
    "model": "declared-model",
}


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _contract(root: Path) -> Path:
    existing = root / ".factory/oracles/contracts/atomic-checkout.json"
    if existing.is_file():
        return existing
    intent = root / "briefs" / "original-intent.md"
    intent.parent.mkdir(parents=True, exist_ok=True)
    intent.write_text(
        "Checkout must preserve a valid order and never expose private account data.\n",
        encoding="utf-8",
    )
    source_file = root / "src" / "checkout.py"
    source_file.parent.mkdir(parents=True, exist_ok=True)
    source_file.write_text(
        "def checkout(order):\n    return bool(order)\n", encoding="utf-8", newline="\n"
    )
    handoff = capture_intent_handoff(
        root,
        intent,
        AGENT,
        "atomic-intake",
        Path(".factory/oracles/handoffs/atomic-intake.json"),
    )
    rules = {
        "requirements": [
            {
                "id": "complete-checkout",
                "statement": "The approved checkout completes for a valid order.",
                "origin": "human_confirmed",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
            }
        ],
        "forbidden_behaviors": [
            {
                "id": "private-data",
                "statement": "Checkout must not expose private account data.",
                "origin": "human_confirmed",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
            }
        ],
        "gates": [
            {
                "id": "checkout-proof",
                "statement": "Checkout evidence reaches the approved threshold.",
                "origin": "trusted_source",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
                "comparison": "gte",
                "value": 95,
            }
        ],
        "exceptions": [
            {
                "id": "offline-note",
                "statement": "Offline evidence remains advisory until a human review.",
                "origin": "human_confirmed",
                "effect": "advisory",
                "source_id": "original-intent",
                "critical": False,
            }
        ],
        "negative_cases": [
            {
                "id": "bad-order",
                "statement": "An invalid order must not complete checkout.",
                "origin": "human_confirmed",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
            }
        ],
        "invariants": [
            {
                "id": "scope-bound",
                "statement": "The candidate must remain inside the sealed source scope.",
                "origin": "trusted_source",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
            }
        ],
        "tests": [
            {
                "id": "checkout-test",
                "statement": "Checkout tests exercise the rejected order path.",
                "origin": "human_confirmed",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
                "path": "tests/test_checkout.py",
            }
        ],
    }
    payload = {
        "schema": "factory.oracle-contract-input.v1",
        "id": "atomic-checkout",
        "version": 1,
        "approved_by": "Release Owner",
        "approval_rationale": "The release owner approved the original checkout intent and its strict negative boundary.",
        "scope_paths": ["src"],
        "handoff": handoff["path"],
        "sources": [],
        **rules,
    }
    source = _write(root / "oracle-input.json", payload)
    return (
        root
        / seal_oracle_contract(
            root, source, Path(".factory/oracles/contracts/atomic-checkout.json")
        )["path"]
    )


def _workflow() -> dict[str, object]:
    nodes = [
        {"id": "plan", "kind": "planner"},
        {"id": "build", "kind": "worker"},
        {"id": "verify", "kind": "validator"},
    ]
    edges = [{"from": "plan", "to": "build"}, {"from": "build", "to": "verify"}]
    return {
        "id": "checkout-proof-workflow",
        "definition_sha256": _digest("atomic-workflow-definition"),
        "topology_sha256": _sha(
            {
                "nodes": sorted(nodes, key=lambda item: item["id"]),
                "edges": sorted(edges, key=lambda item: (item["from"], item["to"])),
            }
        ),
        "nodes": nodes,
        "edges": edges,
    }


def _stage(identifier: str, kind: str, capabilities: list[str]) -> dict[str, object]:
    source_preconditions = [
        {
            "path": "src/checkout.py",
            "sha256": _digest("def checkout(order):\n    return bool(order)\n"),
        }
    ]
    return {
        "id": identifier,
        "kind": kind,
        "status": "completed",
        "scope_paths": ["src"],
        "capabilities": capabilities,
        "input_sha256": _digest(f"{identifier}-input"),
        "output_sha256": _digest(f"{identifier}-output"),
        "artifact_sha256": _digest(f"{identifier}-artifact"),
        "tool_manifest_sha256": _digest(f"{identifier}-tools"),
        "checkpoint": {
            "id": f"checkpoint-{identifier}",
            "sha256": _digest(f"checkpoint-{identifier}-v1"),
        },
        "source_preconditions": source_preconditions,
    }


def _handoff(
    identifier: str,
    source: dict[str, object],
    target: dict[str, object],
    contract_sha: str,
) -> dict[str, object]:
    return {
        "id": identifier,
        "from_stage": source["id"],
        "to_stage": target["id"],
        "capability": "handoff",
        "scope_paths": ["src"],
        "contract_sha256": contract_sha,
        "source_preconditions_sha256": _sha(source["source_preconditions"]),
        "artifact_sha256": source["artifact_sha256"],
        "tool_manifest_sha256": source["tool_manifest_sha256"],
    }


def _envelope(
    root: Path, *, run_id: str = "atomic-run-1"
) -> tuple[dict[str, object], Path]:
    contract = _contract(root)
    contract_value = json.loads(contract.read_text(encoding="utf-8"))
    plan = _stage("plan", "planner", ["read_workspace", "handoff"])
    build = _stage("build", "worker", ["read_workspace", "write_workspace", "handoff"])
    verify = _stage("verify", "validator", ["read_workspace", "verify", "handoff"])
    payload = {
        "schema": "factory.atomic-run-envelope.v1",
        "envelope_id": f"envelope-{run_id}",
        "run_id": run_id,
        "status": "completed",
        "agent": AGENT,
        "autonomy": "supervised",
        "isolation": "declared_worktree",
        "oracle": {
            "contract_path": contract.relative_to(root).as_posix(),
            "contract_sha256": contract_value["contract_sha256"],
        },
        "workflow": _workflow(),
        "stages": [plan, build, verify],
        "handoffs": [
            _handoff("plan-to-build", plan, build, contract_value["contract_sha256"]),
            _handoff(
                "build-to-verify", build, verify, contract_value["contract_sha256"]
            ),
        ],
    }
    return payload, contract


def _import(
    root: Path, envelope: dict[str, object], *, filename: str = "atomic-envelope.json"
) -> dict[str, object]:
    path = _write(root / filename, envelope)
    return import_atomic_run(root, path.relative_to(root))


def _crash_with_history_lock(root: str, acquired) -> None:
    from factoryline.atomic_proof_adapter import _atomic_history_lock

    with _atomic_history_lock(Path(root)):
        acquired.set()
        os._exit(17)


def _hold_history_lock(root: str, acquired, release) -> None:
    from factoryline.atomic_proof_adapter import _atomic_history_lock

    with _atomic_history_lock(Path(root)):
        acquired.set()
        if not release.wait(10):
            raise RuntimeError("test did not release history lock")


def test_template_gives_connected_agents_a_secret_free_handoff_shape() -> None:
    template = atomic_envelope_template()

    assert template["schema"] == "factory.atomic-envelope-template.v1"
    assert template["envelope_schema"] == "factory.atomic-run-envelope.v1"
    assert template["authority"] == {key: False for key in template["authority"]}
    assert set(template["envelope"]) == {
        "schema",
        "envelope_id",
        "run_id",
        "status",
        "agent",
        "autonomy",
        "isolation",
        "oracle",
        "workflow",
        "stages",
        "handoffs",
    }
    assert [stage["id"] for stage in template["envelope"]["stages"]] == [
        "plan",
        "build",
        "verify",
    ]
    assert "credentials" in template["claim_boundary"]


def test_import_binds_typed_dag_handoffs_checkpoints_and_read_only_projection(
    tmp_path: Path,
) -> None:
    envelope, _ = _envelope(tmp_path)
    receipt = _import(tmp_path, envelope)

    assert receipt["marker"] == BOUND_MARKER
    assert receipt["authority"] == {key: False for key in receipt["authority"]}
    checked = verify_atomic_receipt(tmp_path, Path(receipt["path"]))
    projection = atomic_proof_projection(tmp_path)
    assert checked["ok"] is True
    assert checked["receipt"]["stages"] == receipt["stages"]
    assert checked["receipt"]["handoffs"] == receipt["handoffs"]
    assert checked["receipt"]["resume"] == receipt["resume"]
    assert projection["marker"] == MCP_MARKER
    assert projection["bound_count"] == 1
    assert projection["latest"]["handoff_count"] == 2


def test_import_rejects_private_fields_and_scope_escape_without_adapter_receipt(
    tmp_path: Path,
) -> None:
    envelope, _ = _envelope(tmp_path)
    envelope["raw_prompt"] = "not allowed"
    with pytest.raises(AtomicProofAdapterError, match="unsupported") as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_ATOMIC_PRIVATE_FIELD"
    assert not (tmp_path / ".factory" / "atomic").exists()

    envelope, _ = _envelope(tmp_path)
    envelope["stages"][1]["scope_paths"] = ["admin"]
    with pytest.raises(AtomicProofAdapterError) as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_ATOMIC_SCOPE_ESCAPE"
    assert not (tmp_path / ".factory" / "atomic").exists()


def test_import_rejects_cyclic_or_unbound_workflow_evidence_without_receipt(
    tmp_path: Path,
) -> None:
    envelope, _ = _envelope(tmp_path)
    workflow = envelope["workflow"]
    workflow["edges"].append({"from": "verify", "to": "plan"})
    workflow["topology_sha256"] = _sha(
        {
            "nodes": sorted(workflow["nodes"], key=lambda item: item["id"]),
            "edges": sorted(
                workflow["edges"], key=lambda item: (item["from"], item["to"])
            ),
        }
    )
    with pytest.raises(AtomicProofAdapterError) as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_ATOMIC_EVIDENCE_UNVERIFIED"
    assert not (tmp_path / ".factory" / "atomic").exists()


def test_import_rejects_source_precondition_that_does_not_match_workspace_bytes(
    tmp_path: Path,
) -> None:
    envelope, _ = _envelope(tmp_path)
    (tmp_path / "src" / "checkout.py").write_text(
        "def checkout(order):\n    return True\n", encoding="utf-8", newline="\n"
    )
    with pytest.raises(AtomicProofAdapterError) as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_ATOMIC_EVIDENCE_UNVERIFIED"
    assert not (tmp_path / ".factory" / "atomic").exists()


def test_import_rejects_handoff_drift_and_history_drift(tmp_path: Path) -> None:
    envelope, _ = _envelope(tmp_path)
    envelope["handoffs"][0]["artifact_sha256"] = _digest("drifted-artifact")
    with pytest.raises(AtomicProofAdapterError) as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_ATOMIC_HANDOFF_DRIFT"

    original, _ = _envelope(tmp_path)
    _import(tmp_path, original, filename="first.json")
    changed, _ = _envelope(tmp_path, run_id="atomic-run-2")
    changed["stages"][0]["artifact_sha256"] = _digest("new-plan-artifact")
    changed["handoffs"][0]["artifact_sha256"] = changed["stages"][0]["artifact_sha256"]
    with pytest.raises(AtomicProofAdapterError) as raised:
        _import(tmp_path, changed, filename="second.json")
    assert raised.value.code == "E_ATOMIC_HANDOFF_DRIFT"


def test_concurrent_conflicting_imports_serialize_history_across_output_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from factoryline import atomic_proof_adapter as adapter

    first, _ = _envelope(tmp_path, run_id="atomic-race-1")
    second, _ = _envelope(tmp_path, run_id="atomic-race-2")
    changed_artifact = _digest("different-build-artifact")
    second["stages"][1]["artifact_sha256"] = changed_artifact
    second["handoffs"][1]["artifact_sha256"] = changed_artifact
    first_path = _write(tmp_path / "first-envelope.json", first)
    second_path = _write(tmp_path / "second-envelope.json", second)

    first_inside_history = threading.Event()
    second_inside_history = threading.Event()
    release_first = threading.Event()
    original = adapter._handoff_history

    def observed_history(root, workflow_id, handoffs):
        if threading.current_thread().name == "first-import":
            first_inside_history.set()
            assert release_first.wait(5)
        else:
            second_inside_history.set()
        return original(root, workflow_id, handoffs)

    monkeypatch.setattr(adapter, "_handoff_history", observed_history)
    outcomes: dict[str, object] = {}

    def run(name: str, source: Path, output: str) -> None:
        try:
            outcomes[name] = adapter.import_atomic_run(
                tmp_path,
                source.relative_to(tmp_path),
                Path("exports") / output,
            )
        except BaseException as exc:
            outcomes[name] = exc

    first_thread = threading.Thread(
        name="first-import",
        target=run,
        args=("first", first_path, "first.json"),
    )
    second_thread = threading.Thread(
        name="second-import",
        target=run,
        args=("second", second_path, "second.json"),
    )
    first_thread.start()
    assert first_inside_history.wait(5)
    second_thread.start()
    assert not second_inside_history.wait(0.2)
    release_first.set()
    first_thread.join(5)
    second_thread.join(5)

    assert not first_thread.is_alive() and not second_thread.is_alive()
    assert isinstance(outcomes["first"], dict)
    assert isinstance(outcomes["second"], AtomicProofAdapterError)
    assert outcomes["second"].code == "E_ATOMIC_HANDOFF_DRIFT"
    history = list((tmp_path / ".factory" / "atomic").glob("*.json"))
    assert len(history) == 1
    assert (tmp_path / "exports" / "first.json").read_bytes() == history[0].read_bytes()
    assert not (tmp_path / "exports" / "second.json").exists()


def test_atomic_receipt_publication_never_exposes_partial_final_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from factoryline import atomic_proof_adapter as adapter

    target = tmp_path / ".factory" / "atomic" / "complete.json"
    entered_publish = threading.Event()
    release_publish = threading.Event()
    failures: list[BaseException] = []
    original_link = adapter.os.link

    def paused_link(source, destination):
        entered_publish.set()
        assert release_publish.wait(5)
        original_link(source, destination)

    monkeypatch.setattr(adapter.os, "link", paused_link)

    def write() -> None:
        try:
            adapter._atomic_json(target, {"complete": True})
        except BaseException as exc:
            failures.append(exc)

    writer = threading.Thread(target=write)
    writer.start()
    assert entered_publish.wait(5)
    assert not target.exists()
    release_publish.set()
    writer.join(5)
    assert not writer.is_alive() and not failures
    assert json.loads(target.read_text(encoding="utf-8")) == {"complete": True}
    assert not list(target.parent.glob("*.tmp"))


def test_atomic_receipt_writer_cleans_failed_temp_and_never_clobbers_incumbent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from factoryline import atomic_proof_adapter as adapter

    target = tmp_path / ".factory" / "atomic" / "immutable.json"
    original_fsync = adapter.os.fsync

    def fail_fsync(_descriptor):
        raise OSError("writer failed")

    monkeypatch.setattr(adapter.os, "fsync", fail_fsync)
    with pytest.raises(OSError, match="writer failed"):
        adapter._atomic_json(target, {"attempt": "failed"})
    assert not target.exists()
    assert not list(target.parent.glob("*.tmp"))

    monkeypatch.setattr(adapter.os, "fsync", original_fsync)
    adapter._atomic_json(target, {"version": 1})
    incumbent = target.read_bytes()
    with pytest.raises(AtomicProofAdapterError, match="already exists"):
        adapter._atomic_json(target, {"version": 2})
    assert target.read_bytes() == incumbent
    assert not list(target.parent.glob("*.tmp"))


def test_atomic_history_lock_serializes_processes_and_releases_after_crash(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("spawn")
    acquired = context.Event()
    release = context.Event()
    holder = context.Process(
        target=_hold_history_lock, args=(str(tmp_path), acquired, release)
    )
    holder.start()
    assert acquired.wait(10)
    parent_entered = threading.Event()

    def acquire_in_parent() -> None:
        from factoryline.atomic_proof_adapter import _atomic_history_lock

        with _atomic_history_lock(tmp_path):
            parent_entered.set()

    contender = threading.Thread(target=acquire_in_parent)
    contender.start()
    assert not parent_entered.wait(0.2)
    release.set()
    holder.join(10)
    contender.join(10)
    assert holder.exitcode == 0
    assert not contender.is_alive() and parent_entered.is_set()

    crashed = context.Event()
    process = context.Process(
        target=_crash_with_history_lock, args=(str(tmp_path), crashed)
    )
    process.start()
    assert crashed.wait(10)
    process.join(10)
    assert process.exitcode == 17

    from factoryline.atomic_proof_adapter import _atomic_history_lock

    with _atomic_history_lock(tmp_path):
        assert (tmp_path / ".factory" / ".atomic-history.lock").is_file()


def test_atomic_history_lock_rejects_factory_directory_symlink_without_outside_write(
    tmp_path: Path,
) -> None:
    from factoryline.atomic_proof_adapter import (
        AtomicProofAdapterError,
        _atomic_history_lock,
    )

    outside = tmp_path.parent / f"{tmp_path.name}-outside-lock-dir"
    outside.mkdir()
    try:
        (tmp_path / ".factory").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlink creation unavailable: {exc}")

    with pytest.raises(AtomicProofAdapterError) as raised:
        with _atomic_history_lock(tmp_path):
            pytest.fail("linked workspace lock directory was accepted")
    assert raised.value.code == "E_ATOMIC_SCOPE_ESCAPE"
    assert not (outside / ".atomic-history.lock").exists()


def test_atomic_history_lock_rejects_lockfile_symlink_without_target_mutation(
    tmp_path: Path,
) -> None:
    from factoryline.atomic_proof_adapter import (
        AtomicProofAdapterError,
        _atomic_history_lock,
    )

    outside = tmp_path.parent / f"{tmp_path.name}-outside-lock-file"
    outside.write_bytes(b"")
    factory = tmp_path / ".factory"
    factory.mkdir()
    try:
        (factory / ".atomic-history.lock").symlink_to(outside)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"file symlink creation unavailable: {exc}")

    with pytest.raises(AtomicProofAdapterError) as raised:
        with _atomic_history_lock(tmp_path):
            pytest.fail("linked lock file was accepted")
    assert raised.value.code == "E_ATOMIC_SCOPE_ESCAPE"
    assert outside.read_bytes() == b""


def test_custom_output_keeps_canonical_history_and_conflict_check(
    tmp_path: Path,
) -> None:
    first, _ = _envelope(tmp_path, run_id="atomic-export-1")
    first_path = _write(tmp_path / "export-envelope-1.json", first)
    receipt = import_atomic_run(
        tmp_path, first_path.relative_to(tmp_path), Path("exports/first.json")
    )
    history = list((tmp_path / ".factory" / "atomic").glob("*.json"))
    assert len(history) == 1
    exported = tmp_path / "exports" / "first.json"
    assert Path(str(receipt["path"])) == Path("exports/first.json")
    assert exported.read_bytes() == history[0].read_bytes()

    second, _ = _envelope(tmp_path, run_id="atomic-export-2")
    changed_artifact = _digest("custom-path-cannot-bypass-history")
    second["stages"][1]["artifact_sha256"] = changed_artifact
    second["handoffs"][1]["artifact_sha256"] = changed_artifact
    second_path = _write(tmp_path / "export-envelope-2.json", second)
    with pytest.raises(AtomicProofAdapterError) as raised:
        import_atomic_run(
            tmp_path, second_path.relative_to(tmp_path), Path("exports/second.json")
        )
    assert raised.value.code == "E_ATOMIC_HANDOFF_DRIFT"
    assert not (tmp_path / "exports" / "second.json").exists()
    assert len(list((tmp_path / ".factory" / "atomic").glob("*.json"))) == 1


def test_custom_output_collision_is_checked_before_history_commit(
    tmp_path: Path,
) -> None:
    envelope, _ = _envelope(tmp_path)
    source = _write(tmp_path / "collision-envelope.json", envelope)
    output = _write(tmp_path / "exports" / "occupied.json", {"owner": "incumbent"})
    before = output.read_bytes()
    with pytest.raises(AtomicProofAdapterError, match="already exists"):
        import_atomic_run(
            tmp_path, source.relative_to(tmp_path), Path("exports/occupied.json")
        )
    assert output.read_bytes() == before
    assert not list((tmp_path / ".factory" / "atomic").glob("*.json"))


def test_custom_export_failure_keeps_committed_canonical_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from factoryline import atomic_proof_adapter as adapter

    envelope, _ = _envelope(tmp_path)
    source = _write(tmp_path / "export-failure-envelope.json", envelope)
    original_link = adapter.os.link
    calls = 0

    def fail_export(source_path, destination):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("export link failed")
        original_link(source_path, destination)

    monkeypatch.setattr(adapter.os, "link", fail_export)
    with pytest.raises(OSError, match="export link failed"):
        import_atomic_run(
            tmp_path, source.relative_to(tmp_path), Path("exports/unavailable.json")
        )
    history = list((tmp_path / ".factory" / "atomic").glob("*.json"))
    assert len(history) == 1
    assert (
        verify_atomic_receipt(tmp_path, history[0].relative_to(tmp_path))["ok"] is True
    )
    assert not (tmp_path / "exports" / "unavailable.json").exists()
    assert not list((tmp_path / ".factory" / "atomic").glob("*.tmp"))


def test_import_requires_hash_equal_checkpoint_for_human_reviewed_resume(
    tmp_path: Path,
) -> None:
    first, _ = _envelope(tmp_path, run_id="atomic-run-1")
    first_receipt = _import(tmp_path, first, filename="first.json")
    resumed, _ = _envelope(tmp_path, run_id="atomic-run-2")
    worker = next(stage for stage in resumed["stages"] if stage["id"] == "build")
    resumed["resume"] = {
        "prior_receipt": first_receipt["path"],
        "prior_run_id": "atomic-run-1",
        "checkpoint_id": worker["checkpoint"]["id"],
        "checkpoint_sha256": worker["checkpoint"]["sha256"],
    }
    receipt = _import(tmp_path, resumed, filename="resumed.json")
    assert receipt["resume"]["recovery_action"] == "human_reviewed_fork"

    divergent = copy.deepcopy(resumed)
    divergent["run_id"] = "atomic-run-3"
    divergent["envelope_id"] = "envelope-atomic-run-3"
    divergent["resume"]["checkpoint_sha256"] = _digest("different-checkpoint")
    with pytest.raises(AtomicProofAdapterError) as raised:
        _import(tmp_path, divergent, filename="divergent.json")
    assert raised.value.code == "E_ATOMIC_RESUME_DIVERGENCE"


def test_import_rejects_resume_when_a_checkpoint_moves_to_a_different_stage(
    tmp_path: Path,
) -> None:
    first, _ = _envelope(tmp_path, run_id="atomic-run-1")
    first_receipt = _import(tmp_path, first, filename="first.json")
    resumed, _ = _envelope(tmp_path, run_id="atomic-run-2")
    prior_plan = next(stage for stage in first["stages"] if stage["id"] == "plan")
    current_plan = next(stage for stage in resumed["stages"] if stage["id"] == "plan")
    current_build = next(stage for stage in resumed["stages"] if stage["id"] == "build")
    current_plan["checkpoint"] = {
        "id": "checkpoint-replaced-plan",
        "sha256": _digest("checkpoint-replaced-plan"),
    }
    current_build["checkpoint"] = copy.deepcopy(prior_plan["checkpoint"])
    resumed["resume"] = {
        "prior_receipt": first_receipt["path"],
        "prior_run_id": "atomic-run-1",
        "checkpoint_id": prior_plan["checkpoint"]["id"],
        "checkpoint_sha256": prior_plan["checkpoint"]["sha256"],
    }
    with pytest.raises(AtomicProofAdapterError) as raised:
        _import(tmp_path, resumed, filename="moved-stage.json")
    assert raised.value.code == "E_ATOMIC_RESUME_DIVERGENCE"


def test_import_fails_closed_when_atomic_history_exceeds_its_comparison_bound(
    tmp_path: Path,
) -> None:
    envelope, _ = _envelope(tmp_path)
    history = tmp_path / ".factory" / "atomic"
    history.mkdir(parents=True)
    for index in range(201):
        (history / f"history-{index:03}.json").write_text("{}", encoding="utf-8")
    with pytest.raises(AtomicProofAdapterError) as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_ATOMIC_HISTORY_TRUNCATED"


def test_import_rejects_oversized_atomic_history_before_json_parse_or_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from factoryline import atomic_proof_adapter

    envelope, _ = _envelope(tmp_path)
    source = _write(tmp_path / "oversized-history-envelope.json", envelope)
    history = tmp_path / ".factory" / "atomic" / "oversized.json"
    history.parent.mkdir(parents=True, exist_ok=True)
    original = b'{"padding":"' + b"a" * MAX_BYTES + b'"}'
    history.write_bytes(original)

    original_loads = atomic_proof_adapter.json.loads

    def reject_oversized_json(value: str | bytes, *args: object, **kwargs: object):
        byte_count = (
            len(value.encode("utf-8")) if isinstance(value, str) else len(value)
        )
        assert byte_count <= MAX_BYTES, "oversized history reached JSON parsing"
        return original_loads(value, *args, **kwargs)

    monkeypatch.setattr(atomic_proof_adapter.json, "loads", reject_oversized_json)
    with pytest.raises(AtomicProofAdapterError) as raised:
        import_atomic_run(tmp_path, source.relative_to(tmp_path))

    assert raised.value.code == "E_ATOMIC_EVIDENCE_UNVERIFIED"
    assert "exceeds 1 MiB" in str(raised.value)
    assert history.read_bytes() == original
    assert list(history.parent.glob("*.json")) == [history]


def test_import_keeps_tampered_history_visible_and_blocks_successor_receipt(
    tmp_path: Path,
) -> None:
    first, _ = _envelope(tmp_path, run_id="atomic-run-1")
    prior = _import(tmp_path, first, filename="first.json")
    prior_path = tmp_path / str(prior["path"])
    original = json.loads(prior_path.read_text(encoding="utf-8"))
    assert len(original["stages"]) == 3
    assert len(original["handoffs"]) == 2
    assert all(stage["checkpoint"]["sha256"] for stage in original["stages"])

    original["handoffs"][0]["artifact_sha256"] = _digest("tampered-history")
    tampered_bytes = json.dumps(original, ensure_ascii=False, indent=2).encode("utf-8")
    prior_path.write_bytes(tampered_bytes)
    checked = verify_atomic_receipt(tmp_path, Path(str(prior["path"])))
    assert checked["ok"] is False
    assert checked["reason"] == "E_ATOMIC_EVIDENCE_UNVERIFIED"

    successor, _ = _envelope(tmp_path, run_id="atomic-run-2")
    with pytest.raises(AtomicProofAdapterError) as raised:
        _import(tmp_path, successor, filename="successor.json")

    assert raised.value.code == "E_ATOMIC_EVIDENCE_UNVERIFIED"
    assert prior_path.read_bytes() == tampered_bytes
    assert sorted(path.name for path in prior_path.parent.glob("*.json")) == [
        prior_path.name
    ]


@pytest.mark.parametrize("nested", [False, True])
def test_duplicate_json_members_cannot_validate_or_extend_atomic_history(
    tmp_path: Path, nested: bool
) -> None:
    first, _ = _envelope(tmp_path, run_id="atomic-run-1")
    prior = _import(tmp_path, first)
    prior_path = tmp_path / str(prior["path"])
    original = prior_path.read_text(encoding="utf-8")
    field = "artifact_sha256" if nested else "schema"
    value = prior["handoffs"][0][field] if nested else "factory.atomic-proof-adapter.v1"
    selected = json.dumps(field) + ": " + json.dumps(value)
    ambiguous = original.replace(
        selected, json.dumps(field) + ': "wrong", ' + selected, 1
    )
    assert ambiguous != original
    prior_path.write_text(ambiguous, encoding="utf-8")
    assert verify_atomic_receipt(tmp_path, Path(str(prior["path"]))) == {
        "ok": False,
        "marker": "ATOMIC_RECEIPT_INVALID",
        "reason": "E_ATOMIC_EVIDENCE_UNVERIFIED",
        "authority": {key: False for key in prior["authority"]},
    }
    successor, _ = _envelope(tmp_path, run_id="atomic-run-2")
    with pytest.raises(AtomicProofAdapterError) as raised:
        _import(tmp_path, successor, filename="successor.json")
    assert raised.value.code == "E_ATOMIC_EVIDENCE_UNVERIFIED"
    assert prior_path.read_text(encoding="utf-8") == ambiguous
    assert list(prior_path.parent.glob("*.json")) == [prior_path]


@pytest.mark.parametrize("bad_input", ["duplicate", "nested-duplicate", "deep"])
def test_import_rejects_ambiguous_or_deep_atomic_json_with_controlled_error(
    tmp_path: Path, bad_input: str
) -> None:
    envelope, _ = _envelope(tmp_path)
    original = json.dumps(envelope)
    field = "artifact_sha256" if bad_input == "nested-duplicate" else "schema"
    value = (
        envelope["handoffs"][0][field]
        if bad_input == "nested-duplicate"
        else envelope["schema"]
    )
    selected = json.dumps(field) + ": " + json.dumps(value)
    raw = (
        "[" * 2000 + "0" + "]" * 2000
        if bad_input == "deep"
        else original.replace(selected, json.dumps(field) + ': "wrong", ' + selected, 1)
    )
    source = tmp_path / "ambiguous-envelope.json"
    source.write_text(raw, encoding="utf-8")
    with pytest.raises(AtomicProofAdapterError) as raised:
        import_atomic_run(tmp_path, source.relative_to(tmp_path))
    assert raised.value.code == "E_ATOMIC_ENVELOPE_SCHEMA"
    assert source.read_text(encoding="utf-8") == raw
    assert not (tmp_path / ".factory" / "atomic").exists()


def test_adapter_has_no_runtime_or_network_dependency(tmp_path: Path) -> None:
    source = (
        Path(__file__).parents[1] / "factoryline" / "atomic_proof_adapter.py"
    ).read_text(encoding="utf-8")
    assert "import subprocess" not in source
    assert "import requests" not in source
    assert "import httpx" not in source
    assert "import socket" not in source
    assert atomic_proof_projection(tmp_path)["receipt_count"] == 0


def test_cli_and_graph_ops_expose_atomic_facts_without_an_execution_surface(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    envelope, _ = _envelope(tmp_path)
    source = _write(tmp_path / "atomic-envelope.json", envelope)
    from factoryline.cli import main

    assert (
        main(
            [
                "atomic",
                "import",
                "--root",
                str(tmp_path),
                "--envelope",
                source.relative_to(tmp_path).as_posix(),
                "--json",
            ]
        )
        == 0
    )
    imported = json.loads(capsys.readouterr().out)
    assert imported["marker"] == BOUND_MARKER
    assert main(["atomic", "status", "--root", str(tmp_path), "--json"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["marker"] == MCP_MARKER
    graph = graph_ops_snapshot(tmp_path)
    assert graph["facts"]["atomic_bound_count"] == 1
    assert "GRAPH_OPS_ATOMIC_PROOF_ADAPTER_READ_ONLY" in graph["markers"]
    assert {node["kind"] for node in graph["nodes"]} >= {
        "atomic_contract",
        "atomic_workflow",
        "atomic_run",
        "atomic_stage",
        "atomic_handoff",
    }
    assert (
        all(
            value is False
            for value in graph["atomic_proof_adapter"].get("authority", {}).values()
        )
        or graph["atomic_proof_adapter"]["invalid_count"] == 0
    )
