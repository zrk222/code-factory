from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path

from factoryline.cli import main
from factoryline.continuous_proof import (
    assess_continuous_proof,
    continuous_proof_history,
    verify_continuous_proof,
)
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.proof_reuse import record_proof
from factoryline.repair_sandbox import create_repair_scope, write_repair_scope_artifacts


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _file_sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _ready_workspace(root: Path) -> tuple[Path, Path]:
    changed = root / "src" / "service.py"
    intent = root / "intent.md"
    output = root / "proof.txt"
    changed.parent.mkdir(parents=True, exist_ok=True)
    changed.write_text("answer = 42\n", encoding="utf-8")
    intent.write_text("The service shall return the declared answer.\n", encoding="utf-8")
    output.write_text("passed\n", encoding="utf-8")
    coverage = root / "coverage"
    smoke = root / "smoke"
    coverage.mkdir(exist_ok=True)
    smoke.mkdir(exist_ok=True)
    (coverage / "requirements.json").write_text(json.dumps({"requirements": [{"id": "REQ_SERVICE"}]}), encoding="utf-8")
    (smoke / "service.json").write_text(json.dumps({"checks": [{"covers": ["REQ_SERVICE"], "must_fail_on_stub": True}]}), encoding="utf-8")
    record_proof(root, {
        "name": "service-unit", "command": ["python", "-m", "pytest"], "read_only": True,
        "inputs": ["src/service.py"], "outputs": ["proof.txt"],
    }, elapsed_ms=10, replace=True)
    return changed, intent


def _session(root: Path, *, passed: bool, changed_path: str = "src/service.py") -> Path:
    directory = root / ".factory" / "session-recorder" / ("passed-run" if passed else "failed-run")
    directory.mkdir(parents=True, exist_ok=True)
    current = root / changed_path
    result = {
        "schema": "factory.session-recorder.result.v1",
        "workspace_delta": [{"path": changed_path, "status": "modified", "after_sha256": _file_sha(current)}],
    }
    result_path = directory / "result.json"
    result_path.write_bytes(_canonical(result) + b"\n")
    verification = {"schema": "factory.session-recorder.validation.v1", "passed": passed}
    verification_path = directory / "verification.json"
    verification_path.write_bytes(_canonical(verification) + b"\n")
    core = {
        "schema": "factory.observed-session.v1",
        "marker": "OBSERVED_SESSION_RECORDED",
        "run_id": directory.name,
        "recorded_at": "2026-08-29T12:00:00Z",
        "previous_session_sha256": None,
        "result": {"path": result_path.relative_to(root).as_posix(), "sha256": _file_sha(result_path)},
        "verification": {"path": verification_path.relative_to(root).as_posix(), "sha256": _file_sha(verification_path)},
        "agent_event": {"path": ".factory/agent-licenses/events/fake.json", "sha256": "0" * 64},
        "passed": passed,
        "failure_classes": [] if passed else ["wrong_output"],
        "authority": {},
        "scope_limits": [],
    }
    receipt = {**core, "session_sha256": sha256(_canonical(core)).hexdigest()}
    session_path = directory / "session.json"
    session_path.write_bytes(_canonical(receipt) + b"\n")
    return session_path


def _assess(root: Path, **kwargs):
    changed, intent = _ready_workspace(root)
    return assess_continuous_proof(
        root,
        kwargs.pop("workflow_id", "change-one"),
        intent,
        [changed.relative_to(root).as_posix()],
        recorded_at=kwargs.pop("recorded_at", datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)),
        **kwargs,
    )


def test_core_missing_session_routes_to_evidence_required_and_writes_views(tmp_path: Path) -> None:
    receipt = _assess(tmp_path)

    assert receipt["schema"] == "factory.continuous-proof.v1"
    assert receipt["route"] == "evidence_required"
    assert receipt["next_action"]["action"] == "record_observed_session"
    assert receipt["final_approval"] is False
    assert all(value is False for value in receipt["authority"].values())
    assert all(Path(path).is_file() for path in receipt["artifacts"].values())
    assert verify_continuous_proof(tmp_path, Path(receipt["artifacts"]["json"]))["ok"] is True


def test_core_passing_session_routes_to_human_review_ready(tmp_path: Path) -> None:
    changed, intent = _ready_workspace(tmp_path)
    session = _session(tmp_path, passed=True)

    receipt = assess_continuous_proof(
        tmp_path, "passing-change", intent, [changed.relative_to(tmp_path).as_posix()], session_path=session,
        recorded_at=datetime(2026, 8, 29, 12, 1, tzinfo=timezone.utc),
    )

    assert receipt["session"]["state"] == "verified_passed"
    assert receipt["route"] == "review_ready"
    assert receipt["next_action"]["action"] == "human_review_record"
    assert receipt["final_approval"] is False


def test_core_failed_session_routes_to_human_required(tmp_path: Path) -> None:
    changed, intent = _ready_workspace(tmp_path)
    session = _session(tmp_path, passed=False)

    receipt = assess_continuous_proof(
        tmp_path, "failed-change", intent, [changed.relative_to(tmp_path).as_posix()], session_path=session,
        recorded_at=datetime(2026, 8, 29, 12, 2, tzinfo=timezone.utc),
    )

    assert receipt["session"]["state"] == "verified_failed"
    assert receipt["route"] == "human_required"
    assert receipt["session"]["failure_classes"] == ["wrong_output"]


def test_core_intent_and_changed_byte_drift_fail_closed(tmp_path: Path) -> None:
    receipt = _assess(tmp_path)
    receipt_path = Path(receipt["artifacts"]["json"])
    (tmp_path / "intent.md").write_text("changed intent\n", encoding="utf-8")

    stale = verify_continuous_proof(tmp_path, receipt_path)
    assert stale == {
        "schema": "factory.continuous-proof.v1", "marker": "CONTINUOUS_PROOF_STALE", "ok": False,
        "path": receipt_path.relative_to(tmp_path).as_posix(), "reason": "intent",
    }

    second = _assess(tmp_path, workflow_id="change-two")
    second_path = Path(second["artifacts"]["json"])
    (tmp_path / "src" / "service.py").write_text("answer = 0\n", encoding="utf-8")
    assert verify_continuous_proof(tmp_path, second_path)["reason"] == "changed_bytes"


def test_core_tampered_receipt_is_invalid(tmp_path: Path) -> None:
    receipt = _assess(tmp_path)
    path = Path(receipt["artifacts"]["json"])
    value = json.loads(path.read_text(encoding="utf-8"))
    value["route"] = "review_ready"
    path.write_text(json.dumps(value), encoding="utf-8")

    checked = verify_continuous_proof(tmp_path, path)
    assert checked["ok"] is False
    assert checked["marker"] == "CONTINUOUS_PROOF_INVALID"


def test_core_scoped_repair_requires_fresh_reverification(tmp_path: Path) -> None:
    changed, intent = _ready_workspace(tmp_path)
    scope = create_repair_scope(tmp_path, "service-fix", ["src/service.py"])
    scope_artifacts = write_repair_scope_artifacts(scope, tmp_path, tmp_path / ".factory" / "repair")
    patch = tmp_path / ".factory" / "repair" / "candidate.patch"
    patch.write_text(
        "diff --git a/src/service.py b/src/service.py\n--- a/src/service.py\n+++ b/src/service.py\n@@ -1 +1 @@\n-answer = 42\n+answer = 43\n",
        encoding="utf-8",
    )

    receipt = assess_continuous_proof(
        tmp_path, "repair-change", intent, [changed.relative_to(tmp_path).as_posix()],
        repair_scope_path=Path(scope_artifacts["paths"]["json"]), repair_patch_path=patch,
        recorded_at=datetime(2026, 8, 29, 12, 3, tzinfo=timezone.utc),
    )

    assert receipt["repair"]["state"] == "candidate_scoped"
    assert receipt["route"] == "reverification_required"
    assert receipt["authority"]["patch_apply"] is False

    # A human applies the reviewed candidate outside FactoryLine, then a fresh
    # observed session binds the resulting bytes back to the prior receipt.
    changed.write_text("answer = 43\n", encoding="utf-8")
    (tmp_path / "proof.txt").write_text("passed again\n", encoding="utf-8")
    record_proof(tmp_path, {
        "name": "service-unit", "command": ["python", "-m", "pytest"], "read_only": True,
        "inputs": ["src/service.py"], "outputs": ["proof.txt"],
    }, elapsed_ms=11, replace=True)
    session = _session(tmp_path, passed=True)
    follow_up = assess_continuous_proof(
        tmp_path, "repair-change-follow-up", intent, [changed.relative_to(tmp_path).as_posix()],
        session_path=session, session_phase="post_repair", prior_receipt_path=Path(receipt["artifacts"]["json"]),
        recorded_at=datetime(2026, 8, 29, 12, 4, tzinfo=timezone.utc),
    )

    assert follow_up["repair"]["state"] == "candidate_scoped_prior"
    assert follow_up["repair_reverified"] is True
    assert follow_up["route"] == "review_ready"
    assert follow_up["prior"]["receipt_sha256"] == receipt["receipt_sha256"]
    assert follow_up["final_approval"] is False


def test_core_history_preserves_counts_and_claim_limits(tmp_path: Path) -> None:
    _assess(tmp_path, workflow_id="first", recorded_at=datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc))
    changed, intent = _ready_workspace(tmp_path)
    session = _session(tmp_path, passed=True)
    assess_continuous_proof(
        tmp_path, "second", intent, [changed.relative_to(tmp_path).as_posix()], session_path=session,
        recorded_at=datetime(2026, 8, 29, 12, 1, tzinfo=timezone.utc),
    )

    history = continuous_proof_history(tmp_path)
    assert history["verified_record_count"] == 2
    assert history["route_counts"] == {"evidence_required": 1, "review_ready": 1}
    assert history["latest"]["workflow_id"] == "second"
    assert "not unique users" in history["claim_limits"][0]
    assert "savings" in history["claim_limits"][1]


def test_cli_assess_verify_and_history_are_machine_readable(tmp_path: Path, capsys) -> None:
    changed, intent = _ready_workspace(tmp_path)
    assert main([
        "proof-ops", "assess", "--root", str(tmp_path), "--workflow-id", "cli-change",
        "--intent", str(intent), "--changed", changed.relative_to(tmp_path).as_posix(), "--json",
    ]) == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["route"] == "evidence_required"
    assert main(["proof-ops", "verify", receipt["artifacts"]["json"], "--root", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    assert main(["proof-ops", "history", "--root", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["verified_record_count"] == 1


def test_graph_projects_continuous_proof_history_read_only(tmp_path: Path) -> None:
    _assess(tmp_path)

    snapshot = graph_ops_snapshot(tmp_path)

    assert snapshot["continuous_proof"]["count"] == 1
    assert snapshot["facts"]["continuous_proof_count"] == 1
    assert snapshot["facts"]["continuous_proof_latest_route"] == "evidence_required"
    assert "GRAPH_OPS_CONTINUOUS_PROOF_READ_ONLY" in snapshot["markers"]
    assert all(value is False for value in snapshot["continuous_proof"]["authority"].values())
