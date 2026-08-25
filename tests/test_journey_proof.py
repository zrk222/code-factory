from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import sys

import pytest

from factoryline.journey_proof import (
    AUTHORITY,
    JourneyProofError,
    compile_reality_graph,
    create_failure_capsule,
    journey_proof_status,
    verify_proof_gated_healing,
    verify_stateful_workflow,
)
from factoryline.graph_ops import graph_ops_html, graph_ops_snapshot
from factoryline.mcp import dispatch
from factoryline.cli import main


def _write(root: Path, name: str, payload: object) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return Path(name)


def _artifact(root: Path, name: str = "evidence/screenshot.txt") -> dict[str, str]:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("observed", encoding="utf-8")
    return {"path": name, "sha256": sha256(path.read_bytes()).hexdigest(), "kind": "text"}


def _reality_inputs(root: Path) -> tuple[Path, Path]:
    declaration = {
        "schema": "factory.journey-declaration.v1",
        "project_id": "shop",
        "journey_id": "checkout",
        "states": [
            {"id": "cart", "requirements": ["REQ-1"], "outcome": False},
            {"id": "payment", "requirements": ["REQ-2"], "outcome": False},
            {"id": "confirmed", "requirements": ["REQ-2"], "outcome": True},
        ],
        "transitions": [
            {"id": "cart-to-payment", "from": "cart", "to": "payment", "requirements": ["REQ-1"]},
            {"id": "payment-to-confirmed", "from": "payment", "to": "confirmed", "requirements": ["REQ-2"]},
        ],
        "requirements": ["REQ-1", "REQ-2"],
        "outcomes": ["confirmed"],
    }
    observation = {
        "schema": "factory.journey-observation.v1",
        "project_id": "shop",
        "journey_id": "checkout",
        "run_id": "run-1",
        "code_version": "abc123",
        "environment": {"label": "local", "fingerprint": "py-test"},
        "states": [{"id": "cart"}, {"id": "payment"}, {"id": "error"}],
        "transitions": [{"id": "cart-to-payment", "from": "cart", "to": "payment", "artifacts": [_artifact(root)]}],
        "requirements": ["REQ-1", "REQ-2"],
        "outcomes": ["confirmed"],
        "observed_at": "2026-08-25T00:00:00Z",
    }
    return _write(root, "declaration.json", declaration), _write(root, "observation.json", observation)


def test_reality_reports_exact_drift_and_verified_status(tmp_path: Path) -> None:
    declaration, observation = _reality_inputs(tmp_path)
    receipt = compile_reality_graph(tmp_path, declaration, observation)
    assert receipt["marker"] == "JOURNEY_REALITY_REVIEW_REQUIRED"
    assert receipt["deltas"]["states"] == {"missing": ["confirmed"], "unexpected": ["error"]}
    assert receipt["deltas"]["transitions"] == {"missing": ["payment-to-confirmed"], "unexpected": []}
    status = journey_proof_status(tmp_path)
    assert status["marker"] == "JOURNEY_STATUS_READ_ONLY"
    assert status["facts"] == {"verified_count": 1, "invalid_count": 0}
    assert status["receipts"][0]["receipt_sha256"] == receipt["receipt_sha256"]


def test_reality_rejects_unknown_fields_and_stale_artifacts(tmp_path: Path) -> None:
    declaration, observation = _reality_inputs(tmp_path)
    payload = json.loads((tmp_path / declaration).read_text(encoding="utf-8"))
    payload["unknown"] = True
    _write(tmp_path, str(declaration), payload)
    with pytest.raises(JourneyProofError, match="unknown"):
        compile_reality_graph(tmp_path, declaration, observation)
    payload.pop("unknown")
    _write(tmp_path, str(declaration), payload)
    (tmp_path / "evidence/screenshot.txt").write_text("changed", encoding="utf-8")
    receipt = compile_reality_graph(tmp_path, declaration, observation)
    assert receipt["deltas"]["stale_artifact_hashes"] == ["evidence/screenshot.txt"]


def test_failure_capsule_binds_adjacent_context_and_markdown(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path, "evidence/trace.txt")
    manifest = {
        "schema": "factory.failure-capsule-input.v1",
        "project_id": "shop",
        "journey_id": "checkout",
        "run_id": "run-2",
        "code_version": "abc123",
        "environment": {"label": "local"},
        "classification": "wrong_output",
        "hypothesis": "The total was stale.",
        "suggested_repair": "Re-read the total.",
        "failed_step_index": 2,
        "steps": [{"index": index, "label": f"step {index}", "status": "failed" if index == 2 else "passed"} for index in range(5)],
        "artifacts": [{**artifact, "step_index": 2}],
        "reproduction_argv": [sys.executable, "-c", "raise SystemExit(1)"],
        "observed_at": "2026-08-25T00:00:00Z",
    }
    receipt = create_failure_capsule(tmp_path, _write(tmp_path, "failure.json", manifest))
    assert receipt["marker"] == "FAILURE_CAPSULE_BOUND"
    assert [step["index"] for step in receipt["step_context"]] == [1, 2, 3]
    assert receipt["hypothesis"]["trust"] == "unverified"
    assert (tmp_path / receipt["markdown_path"]).is_file()


def _workflow(cleanup: bool = True) -> dict[str, object]:
    tests = [
        {"id": "create", "index": 1, "depends_on": [], "produces": ["order_id"], "consumes": [], "side_effects": ["order-7"], "cleanup_for": [], "is_cleanup": False},
        {"id": "read", "index": 2, "depends_on": ["create"], "produces": [], "consumes": ["order_id"], "side_effects": [], "cleanup_for": [], "is_cleanup": False},
        {"id": "cleanup", "index": 3, "depends_on": ["read"], "produces": [], "consumes": [], "side_effects": [], "cleanup_for": ["order-7"], "is_cleanup": True},
    ]
    digest = sha256(b"order-7").hexdigest()
    results = [
        {"test_id": "create", "status": "passed", "produced": {"order_id": digest}, "consumed": {}, "side_effects_created": ["order-7"], "cleanup_completed": [], "idempotency_probe_passed": None},
        {"test_id": "read", "status": "passed", "produced": {}, "consumed": {"order_id": digest}, "side_effects_created": [], "cleanup_completed": [], "idempotency_probe_passed": None},
        {"test_id": "cleanup", "status": "passed", "produced": {}, "consumed": {}, "side_effects_created": [], "cleanup_completed": ["order-7"] if cleanup else [], "idempotency_probe_passed": cleanup},
    ]
    return {"schema": "factory.stateful-workflow-input.v1", "project_id": "shop", "workflow_id": "order-lifecycle", "run_id": "run-3", "code_version": "abc123", "environment": {"label": "local"}, "tests": tests, "results": results, "observed_at": "2026-08-25T00:00:00Z"}


def test_workflow_proves_values_cleanup_and_idempotency(tmp_path: Path) -> None:
    receipt = verify_stateful_workflow(tmp_path, _write(tmp_path, "workflow.json", _workflow()))
    assert receipt["marker"] == "WORKFLOW_PROOF_PASSED"
    assert all(receipt["facts"].values())


def test_workflow_fails_closed_for_missing_cleanup(tmp_path: Path) -> None:
    receipt = verify_stateful_workflow(tmp_path, _write(tmp_path, "workflow.json", _workflow(cleanup=False)))
    assert receipt["decision"] == "failed"
    assert "WORKFLOW_CLEANUP_MISSING" in receipt["markers"]
    assert receipt["facts"]["workflow_cleanup_valid"] is False


def _healing(root: Path, mode: str = "human_controlled", agent: object = None, negative_exit: int = 1) -> dict[str, object]:
    patch = root / "repair.patch"
    patch.write_text("selector repair", encoding="utf-8")
    return {
        "schema": "factory.proof-gated-healing-input.v1",
        "healing_id": "heal-1",
        "review_mode": mode,
        "agent": agent,
        "patch": {"path": "repair.patch", "sha256": sha256(patch.read_bytes()).hexdigest(), "changed_paths": ["tests/selector.py"]},
        "allowed_paths": ["tests"],
        "semantic_identity": {"before": {"role": "button", "label": "Pay", "route": "/checkout", "state": "ready"}, "after": {"role": "button", "label": "Pay", "route": "/checkout", "state": "ready"}},
        "coverage_before": ["checkout"],
        "coverage_after": ["checkout", "receipt"],
        "positive_argv": [sys.executable, "-c", "raise SystemExit(0)"],
        "negative_argv": [sys.executable, "-c", f"raise SystemExit({negative_exit})"],
    }


def test_human_healing_requires_human_and_rejects_hollow_test(tmp_path: Path) -> None:
    receipt = verify_proof_gated_healing(tmp_path, _write(tmp_path, "healing.json", _healing(tmp_path)))
    assert receipt["decision"] == "admissible_for_human_review"
    assert "HEALING_HUMAN_REVIEW_REQUIRED" in receipt["markers"]
    assert receipt["facts"]["final_approval"] is False
    assert receipt["authority"] == AUTHORITY
    hollow = _healing(tmp_path, negative_exit=0)
    rejected = verify_proof_gated_healing(tmp_path, _write(tmp_path, "hollow.json", hollow))
    assert rejected["marker"] == "HOLLOW_HEALING_PROOF"
    assert rejected["decision"] == "rejected"


def test_human_mode_rejects_agent_contract(tmp_path: Path) -> None:
    agent = {"identity": {"provider": "local", "subject": "worker", "display_name": "Worker"}, "argv": [sys.executable, "-c", "pass"], "max_attempts": 1, "timeout_seconds": 30}
    with pytest.raises(JourneyProofError) as raised:
        verify_proof_gated_healing(tmp_path, _write(tmp_path, "healing.json", _healing(tmp_path, agent=agent)))
    assert raised.value.code == "HEALING_REVIEW_MODE_INVALID"


def test_supervised_auto_audits_worker_and_never_self_approves(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    command = "from pathlib import Path; Path('tests/selector.py').write_text('fixed')"
    agent = {"identity": {"provider": "byok", "subject": "agent-7", "display_name": "Local Agent"}, "argv": [sys.executable, "-c", command], "max_attempts": 2, "timeout_seconds": 30}
    manifest = _healing(tmp_path, "supervised_auto", agent)
    receipt = verify_proof_gated_healing(tmp_path, _write(tmp_path, "healing.json", manifest))
    assert receipt["decision"] == "admissible_for_human_review"
    assert "HEALING_AUTO_AWAITING_PROMOTION" in receipt["markers"]
    assert "AGENT_WORK_AUDITED" in receipt["markers"]
    assert receipt["facts"]["agent_audit_valid"] is True
    audit = json.loads((tmp_path / receipt["agent_audit"]["path"]).read_text(encoding="utf-8"))
    assert audit["changed_paths"] == ["tests/selector.py"]
    assert audit["outcome_classification"] == "passed"
    assert audit["failure_classification"] is None
    assert audit["worker_approval"] is False
    assert audit["authority"] == AUTHORITY


def test_supervised_auto_stops_on_scope_escape_and_still_audits(tmp_path: Path) -> None:
    command = "from pathlib import Path; Path('escaped.py').write_text('bad')"
    agent = {"identity": {"provider": "managed", "subject": "agent-8", "display_name": "Managed Agent"}, "argv": [sys.executable, "-c", command], "max_attempts": 3, "timeout_seconds": 30}
    receipt = verify_proof_gated_healing(tmp_path, _write(tmp_path, "healing.json", _healing(tmp_path, "supervised_auto", agent)))
    assert receipt["marker"] == "HEALING_AGENT_SCOPE_ESCAPE"
    assert len(receipt["agent_attempts"]) == 1
    assert receipt["facts"]["agent_scope_valid"] is False
    assert "AGENT_WORK_AUDITED" in receipt["markers"]


def test_graph_ops_and_mcp_project_the_same_verified_receipt_read_only(tmp_path: Path) -> None:
    declaration, observation = _reality_inputs(tmp_path)
    receipt = compile_reality_graph(tmp_path, declaration, observation)
    before = {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    graph = graph_ops_snapshot(tmp_path)
    response = dispatch({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "factory.journey_status", "arguments": {}},
    }, tmp_path)
    content = json.loads(response["result"]["content"][0]["text"])
    after = {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    node = next(item for item in graph["nodes"] if item["kind"] == "journey_reality")
    assert node["facts"]["receipt_sha256"] == receipt["receipt_sha256"]
    assert content["marker"] == "JOURNEY_STATUS_READ_ONLY"
    assert content["receipts"][0]["receipt_sha256"] == receipt["receipt_sha256"]
    assert "GRAPH_OPS_JOURNEY_PROOF_READ_ONLY" in graph["markers"]
    assert before == after


def test_graph_ops_exposes_explicit_human_or_supervised_auto_manifest_control() -> None:
    page = graph_ops_html("token")
    assert 'id="healing-review-mode"' in page
    assert 'value="human_controlled"' in page
    assert 'value="supervised_auto"' in page
    assert 'id="healing-agent-source" disabled' in page
    assert "BYOK / local — default" in page
    assert "Managed service — paid convenience tier" in page
    assert "Final approval is always withheld" in page


def test_journey_cli_returns_nonzero_for_review_required_reality(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    declaration, observation = _reality_inputs(tmp_path)
    exit_code = main(["journey", "reality", str(declaration), str(observation), "--root", str(tmp_path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert payload["marker"] == "JOURNEY_REALITY_REVIEW_REQUIRED"


@pytest.mark.parametrize("schema_kind", ["declaration", "observation", "capsule", "workflow", "healing"])
def test_every_input_schema_rejects_unknown_fields(tmp_path: Path, schema_kind: str) -> None:
    root = tmp_path / schema_kind
    root.mkdir()
    if schema_kind in {"declaration", "observation"}:
        declaration, observation = _reality_inputs(root)
        target = declaration if schema_kind == "declaration" else observation
        payload = json.loads((root / target).read_text(encoding="utf-8"))
        payload["unknown"] = True
        _write(root, str(target), payload)
        invoke = lambda: compile_reality_graph(root, declaration, observation)
    elif schema_kind == "capsule":
        payload = {
            "schema": "factory.failure-capsule-input.v1",
            "project_id": "shop",
            "journey_id": "checkout",
            "run_id": "run-unknown",
            "code_version": "abc123",
            "environment": {"label": "local"},
            "classification": "wrong_output",
            "hypothesis": "Unverified.",
            "suggested_repair": "Review.",
            "failed_step_index": 0,
            "steps": [{"index": 0, "label": "checkout", "status": "failed"}],
            "artifacts": [],
            "reproduction_argv": [sys.executable, "-c", "raise SystemExit(1)"],
            "observed_at": "2026-08-25T00:00:00Z",
            "unknown": True,
        }
        manifest = _write(root, "capsule.json", payload)
        invoke = lambda: create_failure_capsule(root, manifest)
    elif schema_kind == "workflow":
        payload = {**_workflow(), "unknown": True}
        manifest = _write(root, "workflow.json", payload)
        invoke = lambda: verify_stateful_workflow(root, manifest)
    else:
        payload = {**_healing(root), "unknown": True}
        manifest = _write(root, "healing.json", payload)
        invoke = lambda: verify_proof_gated_healing(root, manifest)
    with pytest.raises(JourneyProofError) as raised:
        invoke()
    assert raised.value.code == "JOURNEY_INPUT_REJECTED"
    assert not list((root / ".factory/journey-proof").glob("*.json"))


def test_workflow_fails_closed_for_cycle_and_value_hash_mismatch(tmp_path: Path) -> None:
    payload = _workflow()
    payload["tests"][0]["depends_on"] = ["read"]
    payload["results"][1]["consumed"]["order_id"] = sha256(b"wrong-order").hexdigest()
    receipt = verify_stateful_workflow(tmp_path, _write(tmp_path, "workflow.json", payload))
    assert receipt["decision"] == "failed"
    assert "WORKFLOW_CYCLE_DETECTED" in receipt["reason_codes"]
    assert "WORKFLOW_VALUE_HASH_MISMATCH" in receipt["reason_codes"]
    assert receipt["facts"]["workflow_acyclic"] is False
    assert receipt["facts"]["workflow_values_valid"] is False


def test_supervised_auto_reports_bounded_agent_failure_and_audits_it(tmp_path: Path) -> None:
    agent = {
        "identity": {"provider": "byok", "subject": "agent-fail", "display_name": "Failing Agent"},
        "argv": [sys.executable, "-c", "raise SystemExit(2)"],
        "max_attempts": 2,
        "timeout_seconds": 30,
    }
    receipt = verify_proof_gated_healing(
        tmp_path,
        _write(tmp_path, "healing.json", _healing(tmp_path, "supervised_auto", agent)),
    )
    assert receipt["marker"] == "HEALING_AGENT_FAILED"
    assert len(receipt["agent_attempts"]) == 2
    assert receipt["facts"]["agent_command_exit_zero"] is False
    audit = json.loads((tmp_path / receipt["agent_audit"]["path"]).read_text(encoding="utf-8"))
    assert audit["outcome_classification"] == "agent_failed"
    assert audit["failure_classification"] == "runtime_crash"
    assert audit["worker_approval"] is False


def test_missing_agent_audit_rejects_healing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    agent = {
        "identity": {"provider": "managed", "subject": "agent-audit", "display_name": "Managed Agent"},
        "argv": [sys.executable, "-c", "pass"],
        "max_attempts": 1,
        "timeout_seconds": 30,
    }

    def reject_audit(*_args: object, **_kwargs: object) -> object:
        raise OSError("simulated receipt failure")

    monkeypatch.setattr("factoryline.journey_proof._write", reject_audit)
    with pytest.raises(JourneyProofError) as raised:
        verify_proof_gated_healing(
            tmp_path,
            _write(tmp_path, "healing.json", _healing(tmp_path, "supervised_auto", agent)),
        )
    assert raised.value.code == "HEALING_AGENT_AUDIT_FAILED"
