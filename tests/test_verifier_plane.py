from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

import pytest

from factoryline.verifier_plane import (
    RESULT_SCHEMA,
    WORKER_RESULT_SCHEMA,
    VerifierPlaneError,
    create_verifier_session,
    evaluate_progress,
    verify_verifier_result,
)
from factoryline.cli import main
from factoryline.graph_ops import graph_ops_snapshot


def _sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _tree(path: Path) -> str:
    from factoryline.verifier_plane import _tree_digest

    return _tree_digest(path)


def _setup(tmp_path: Path) -> tuple[Path, dict, Path, Path, Path]:
    root = tmp_path / "repo"
    candidate = root / "candidate"
    bundle = root / "verification" / "checks.json"
    evidence = root / "evidence" / "tests.json"
    mission = root / "mission.json"
    candidate.mkdir(parents=True)
    bundle.parent.mkdir()
    evidence.parent.mkdir()
    (candidate / "main.py").write_text("def approved():\n    return True\n", encoding="utf-8")
    bundle.write_text('{"checks":["unit","policy"]}\n', encoding="utf-8")
    evidence.write_text('{"unit": "passed"}\n', encoding="utf-8")
    mission.write_text(json.dumps({"schema": "factory.mission.v1", "id": "checkout-proof"}), encoding="utf-8")
    session = create_verifier_session(root, mission, candidate, [bundle], "owner-1")
    return root, session, candidate, bundle, evidence


def _worker(root: Path, session: dict, candidate: Path, *, worker_id: str = "worker-1", writes: list[str] | None = None) -> Path:
    path = root / "worker-result.json"
    path.write_text(json.dumps({
        "schema": WORKER_RESULT_SCHEMA,
        "session_sha256": session["session_sha256"],
        "worker_id": worker_id,
        "candidate_tree_sha256": _tree(candidate),
        "declared_writes": writes if writes is not None else ["main.py"],
        "usage": {"attempt": 1, "wall_seconds": 12, "tokens": 120, "cost_usd": 0.01},
        "failure_signature": "unit:previous-failure",
        "progress": {"passed_checks": 2, "failed_checks": 0, "criteria_covered": 3},
    }, indent=2), encoding="utf-8")
    return path


def _verifier(root: Path, session: dict, worker: Path, bundle: Path, evidence: Path, *, verifier_id: str = "verifier-1", verdict: str = "passed", checks: list[dict] | None = None) -> Path:
    path = root / "verifier-result.json"
    path.write_text(json.dumps({
        "schema": RESULT_SCHEMA,
        "session_sha256": session["session_sha256"],
        "worker_result_sha256": _sha(worker),
        "verifier_id": verifier_id,
        "fresh_session": True,
        "context_wall": "isolated",
        "verifier_bundle_sha256": session["verifier_bundle_sha256"],
        "toolchain_sha256": "a" * 64,
        "evidence": [{"path": "evidence/tests.json", "sha256": _sha(evidence)}],
        "checks": checks if checks is not None else [{"id": "unit", "passed": True}, {"id": "policy", "passed": True}],
        "verdict": verdict,
        "harness_attestation": {"runner": "external-supervised", "network": "declared-deny"},
    }, indent=2), encoding="utf-8")
    return path


def test_verifier_plane_binds_distinct_worker_bundle_and_evidence(tmp_path: Path) -> None:
    root, session, candidate, bundle, evidence = _setup(tmp_path)
    worker = _worker(root, session, candidate)
    verifier = _verifier(root, session, worker, bundle, evidence)

    result = verify_verifier_result(Path(session["path"]), worker, verifier, root)

    assert result["valid"] is True
    assert result["verdict"] == "passed"
    assert result["worker_id"] == "worker-1"
    assert result["verifier_id"] == "verifier-1"
    assert result["authority"] == {"merge": False, "publish": False, "deploy": False, "credentials": False}
    assert "VERIFIER_HARNESS_ATTESTATION_BOUND" in result["markers"]


def test_verifier_plane_rejects_self_verification(tmp_path: Path) -> None:
    root, session, candidate, bundle, evidence = _setup(tmp_path)
    worker = _worker(root, session, candidate)
    verifier = _verifier(root, session, worker, bundle, evidence, verifier_id="worker-1")

    with pytest.raises(VerifierPlaneError, match="VERIFIER_IDENTITY_DISTINCT"):
        verify_verifier_result(Path(session["path"]), worker, verifier, root)


def test_verifier_plane_rejects_verifier_bundle_drift(tmp_path: Path) -> None:
    root, session, candidate, bundle, evidence = _setup(tmp_path)
    worker = _worker(root, session, candidate)
    verifier = _verifier(root, session, worker, bundle, evidence)
    bundle.write_text('{"checks":["unit","policy","tampered"]}\n', encoding="utf-8")

    with pytest.raises(VerifierPlaneError, match="VERIFIER_BUNDLE_DRIFT"):
        verify_verifier_result(Path(session["path"]), worker, verifier, root)


def test_verifier_plane_rejects_candidate_path_escape(tmp_path: Path) -> None:
    root, session, candidate, bundle, evidence = _setup(tmp_path)
    worker = _worker(root, session, candidate, writes=["../verification/checks.json"])
    verifier = _verifier(root, session, worker, bundle, evidence)

    with pytest.raises(VerifierPlaneError, match="VERIFIER_PATH_REJECTED"):
        verify_verifier_result(Path(session["path"]), worker, verifier, root)


def test_verifier_plane_classifies_worker_rejection_for_the_cli(tmp_path: Path) -> None:
    root, session, candidate, bundle, evidence = _setup(tmp_path)
    worker = _worker(root, session, candidate, writes=["../verification/checks.json"])
    verifier = _verifier(root, session, worker, bundle, evidence)

    with pytest.raises(VerifierPlaneError) as caught:
        verify_verifier_result(Path(session["path"]), worker, verifier, root)

    assert caught.value.marker == "VERIFIER_WORKER_RESULT_REJECTED"


def test_verifier_plane_rejects_usage_above_the_bound_token_ceiling(tmp_path: Path) -> None:
    root, session, candidate, bundle, evidence = _setup(tmp_path)
    worker = _worker(root, session, candidate)
    payload = json.loads(worker.read_text(encoding="utf-8"))
    payload["usage"]["tokens"] = 100001
    worker.write_text(json.dumps(payload), encoding="utf-8")
    verifier = _verifier(root, session, worker, bundle, evidence)

    with pytest.raises(VerifierPlaneError, match="VERIFIER_BUDGET_EXCEEDED") as caught:
        verify_verifier_result(Path(session["path"]), worker, verifier, root)

    assert caught.value.marker == "VERIFIER_WORKER_RESULT_REJECTED"


def test_verifier_plane_rejects_an_overlong_verifier_identity(tmp_path: Path) -> None:
    root, session, candidate, bundle, evidence = _setup(tmp_path)
    worker = _worker(root, session, candidate)
    verifier = _verifier(root, session, worker, bundle, evidence, verifier_id="v" * 97)

    with pytest.raises(VerifierPlaneError, match="VERIFIER_INPUT_INVALID") as caught:
        verify_verifier_result(Path(session["path"]), worker, verifier, root)

    assert caught.value.marker == "VERIFIER_RESULT_REJECTED"


def test_verifier_plane_rejects_passed_verdict_with_failed_check(tmp_path: Path) -> None:
    root, session, candidate, bundle, evidence = _setup(tmp_path)
    worker = _worker(root, session, candidate)
    verifier = _verifier(root, session, worker, bundle, evidence, checks=[{"id": "unit", "passed": False}])

    with pytest.raises(VerifierPlaneError, match="VERIFIER_VERDICT_INVALID"):
        verify_verifier_result(Path(session["path"]), worker, verifier, root)


def test_progress_stalls_on_repeated_signature_without_improvement() -> None:
    result = evaluate_progress([
        {"attempt": 1, "failure_signature": "pytest:17", "progress": {"passed_checks": 1, "failed_checks": 2, "criteria_covered": 1}},
        {"attempt": 2, "failure_signature": "pytest:17", "progress": {"passed_checks": 1, "failed_checks": 2, "criteria_covered": 1}},
    ])

    assert result["verdict"] == "stalled"
    assert result["owner_review_required"] is True
    assert result["markers"] == ["VERIFIER_PROGRESS_STALLED"]


def test_progress_continues_when_deterministic_check_count_improves() -> None:
    result = evaluate_progress([
        {"attempt": 1, "failure_signature": "pytest:17", "progress": {"passed_checks": 1, "failed_checks": 2, "criteria_covered": 1}},
        {"attempt": 2, "failure_signature": "pytest:17", "progress": {"passed_checks": 2, "failed_checks": 1, "criteria_covered": 2}},
    ])

    assert result["verdict"] == "continue"
    assert result["deterministic_progress"] is True


def test_verifier_cli_reports_stalled_progress_without_claiming_execution(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    attempts = tmp_path / "attempts.json"
    attempts.write_text(json.dumps([
        {"attempt": 1, "failure_signature": "pytest:17", "progress": {"passed_checks": 1, "failed_checks": 2, "criteria_covered": 1}},
        {"attempt": 2, "failure_signature": "pytest:17", "progress": {"passed_checks": 1, "failed_checks": 2, "criteria_covered": 1}},
    ]), encoding="utf-8")

    code = main(["verifier", "progress", str(attempts), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["verdict"] == "stalled"
    assert payload["next_action"] == "owner_review"


def test_verifier_cli_returns_zero_only_for_bound_evidence(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root, session, candidate, bundle, evidence = _setup(tmp_path)
    worker = _worker(root, session, candidate)
    verifier = _verifier(root, session, worker, bundle, evidence)

    code = main(["verifier", "verify", session["path"], str(worker), str(verifier), "--root", str(root), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["valid"] is True
    assert "VERIFIER_RESULT_BOUND" in payload["markers"]


def test_graph_ops_shows_bound_verifier_sessions_as_runtime_unattested(tmp_path: Path) -> None:
    root, session, _candidate, _bundle, _evidence = _setup(tmp_path)

    snapshot = graph_ops_snapshot(root)

    session_node = next(node for node in snapshot["nodes"] if node["kind"] == "verifier_session")
    assert session_node["status"] == "runtime-unattested"
    assert snapshot["facts"]["verifier_session_count"] == 1
    assert snapshot["recommendation"]["action"] == "collect_independent_verifier_evidence"
    assert "GRAPH_OPS_VERIFIER_SESSIONS_READ_ONLY" in snapshot["markers"]
    assert session["session_sha256"][:24] in session_node["id"]
