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
import hashlib
import pytest
from factoryline.graph_forensics import seal_graph_lineage
from factoryline.proofsearch import (
    ProofSearchError,
    create_proofsearch_plan,
    evaluate_proofsearch,
    verify_proofsearch_evaluation,
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _file_sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _ready_workspace(root: Path) -> tuple[Path, Path]:
    changed = root / "src" / "service.py"
    intent = root / "intent.md"
    output = root / "proof.txt"
    changed.parent.mkdir(parents=True, exist_ok=True)
    changed.write_text("answer = 42\n", encoding="utf-8")
    intent.write_text(
        "The service shall return the declared answer.\n", encoding="utf-8"
    )
    output.write_text("passed\n", encoding="utf-8")
    coverage = root / "coverage"
    smoke = root / "smoke"
    coverage.mkdir(exist_ok=True)
    smoke.mkdir(exist_ok=True)
    (coverage / "requirements.json").write_text(
        json.dumps({"requirements": [{"id": "REQ_SERVICE"}]}), encoding="utf-8"
    )
    (smoke / "service.json").write_text(
        json.dumps(
            {"checks": [{"covers": ["REQ_SERVICE"], "must_fail_on_stub": True}]}
        ),
        encoding="utf-8",
    )
    record_proof(
        root,
        {
            "name": "service-unit",
            "command": ["python", "-m", "pytest"],
            "read_only": True,
            "inputs": ["src/service.py"],
            "outputs": ["proof.txt"],
        },
        elapsed_ms=10,
        replace=True,
    )
    return changed, intent


def _session(root: Path, *, passed: bool, changed_path: str = "src/service.py") -> Path:
    directory = (
        root
        / ".factory"
        / "session-recorder"
        / ("passed-run" if passed else "failed-run")
    )
    directory.mkdir(parents=True, exist_ok=True)
    current = root / changed_path
    result = {
        "schema": "factory.session-recorder.result.v1",
        "workspace_delta": [
            {
                "path": changed_path,
                "status": "modified",
                "after_sha256": _file_sha(current),
            }
        ],
    }
    result_path = directory / "result.json"
    result_path.write_bytes(_canonical(result) + b"\n")
    verification = {
        "schema": "factory.session-recorder.validation.v1",
        "passed": passed,
    }
    verification_path = directory / "verification.json"
    verification_path.write_bytes(_canonical(verification) + b"\n")
    core = {
        "schema": "factory.observed-session.v1",
        "marker": "OBSERVED_SESSION_RECORDED",
        "run_id": directory.name,
        "recorded_at": "2026-08-29T12:00:00Z",
        "previous_session_sha256": None,
        "result": {
            "path": result_path.relative_to(root).as_posix(),
            "sha256": _file_sha(result_path),
        },
        "verification": {
            "path": verification_path.relative_to(root).as_posix(),
            "sha256": _file_sha(verification_path),
        },
        "agent_event": {
            "path": ".factory/agent-licenses/events/fake.json",
            "sha256": "0" * 64,
        },
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
        recorded_at=kwargs.pop(
            "recorded_at", datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)
        ),
        **kwargs,
    )


def test_core_missing_session_routes_to_evidence_required_and_writes_views(
    tmp_path: Path,
) -> None:
    receipt = _assess(tmp_path)

    assert receipt["schema"] == "factory.continuous-proof.v1"
    assert receipt["route"] == "evidence_required"
    assert receipt["next_action"]["action"] == "record_observed_session"
    assert receipt["final_approval"] is False
    assert all(value is False for value in receipt["authority"].values())
    assert all(Path(path).is_file() for path in receipt["artifacts"].values())
    assert (
        verify_continuous_proof(tmp_path, Path(receipt["artifacts"]["json"]))["ok"]
        is True
    )


def test_core_passing_session_routes_to_human_review_ready(tmp_path: Path) -> None:
    changed, intent = _ready_workspace(tmp_path)
    session = _session(tmp_path, passed=True)

    receipt = assess_continuous_proof(
        tmp_path,
        "passing-change",
        intent,
        [changed.relative_to(tmp_path).as_posix()],
        session_path=session,
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
        tmp_path,
        "failed-change",
        intent,
        [changed.relative_to(tmp_path).as_posix()],
        session_path=session,
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
        "schema": "factory.continuous-proof.v1",
        "marker": "CONTINUOUS_PROOF_STALE",
        "ok": False,
        "path": receipt_path.relative_to(tmp_path).as_posix(),
        "reason": "intent",
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
    scope_artifacts = write_repair_scope_artifacts(
        scope, tmp_path, tmp_path / ".factory" / "repair"
    )
    patch = tmp_path / ".factory" / "repair" / "candidate.patch"
    patch.write_text(
        "diff --git a/src/service.py b/src/service.py\n--- a/src/service.py\n+++ b/src/service.py\n@@ -1 +1 @@\n-answer = 42\n+answer = 43\n",
        encoding="utf-8",
    )

    receipt = assess_continuous_proof(
        tmp_path,
        "repair-change",
        intent,
        [changed.relative_to(tmp_path).as_posix()],
        repair_scope_path=Path(scope_artifacts["paths"]["json"]),
        repair_patch_path=patch,
        recorded_at=datetime(2026, 8, 29, 12, 3, tzinfo=timezone.utc),
    )

    assert receipt["repair"]["state"] == "candidate_scoped"
    assert receipt["route"] == "reverification_required"
    assert receipt["authority"]["patch_apply"] is False

    # A human applies the reviewed candidate outside FactoryLine, then a fresh
    # observed session binds the resulting bytes back to the prior receipt.
    changed.write_text("answer = 43\n", encoding="utf-8")
    (tmp_path / "proof.txt").write_text("passed again\n", encoding="utf-8")
    record_proof(
        tmp_path,
        {
            "name": "service-unit",
            "command": ["python", "-m", "pytest"],
            "read_only": True,
            "inputs": ["src/service.py"],
            "outputs": ["proof.txt"],
        },
        elapsed_ms=11,
        replace=True,
    )
    session = _session(tmp_path, passed=True)
    follow_up = assess_continuous_proof(
        tmp_path,
        "repair-change-follow-up",
        intent,
        [changed.relative_to(tmp_path).as_posix()],
        session_path=session,
        session_phase="post_repair",
        prior_receipt_path=Path(receipt["artifacts"]["json"]),
        recorded_at=datetime(2026, 8, 29, 12, 4, tzinfo=timezone.utc),
    )

    assert follow_up["repair"]["state"] == "candidate_scoped_prior"
    assert follow_up["repair_reverified"] is True
    assert follow_up["route"] == "review_ready"
    assert follow_up["prior"]["receipt_sha256"] == receipt["receipt_sha256"]
    assert follow_up["final_approval"] is False


def test_core_history_preserves_counts_and_claim_limits(tmp_path: Path) -> None:
    _assess(
        tmp_path,
        workflow_id="first",
        recorded_at=datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc),
    )
    changed, intent = _ready_workspace(tmp_path)
    session = _session(tmp_path, passed=True)
    assess_continuous_proof(
        tmp_path,
        "second",
        intent,
        [changed.relative_to(tmp_path).as_posix()],
        session_path=session,
        recorded_at=datetime(2026, 8, 29, 12, 1, tzinfo=timezone.utc),
    )

    history = continuous_proof_history(tmp_path)
    assert history["verified_record_count"] == 2
    assert history["route_counts"] == {"evidence_required": 1, "review_ready": 1}
    assert history["latest"]["workflow_id"] == "second"
    assert "not unique users" in history["claim_limits"][0]
    assert "savings" in history["claim_limits"][1]


def test_cli_assess_verify_and_history_are_machine_readable(
    tmp_path: Path, capsys
) -> None:
    changed, intent = _ready_workspace(tmp_path)
    assert (
        main(
            [
                "proof-ops",
                "assess",
                "--root",
                str(tmp_path),
                "--workflow-id",
                "cli-change",
                "--intent",
                str(intent),
                "--changed",
                changed.relative_to(tmp_path).as_posix(),
                "--json",
            ]
        )
        == 0
    )
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["route"] == "evidence_required"
    assert (
        main(
            [
                "proof-ops",
                "verify",
                receipt["artifacts"]["json"],
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
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
    assert all(
        value is False for value in snapshot["continuous_proof"]["authority"].values()
    )


# --- Merged from test_proofsearch.py; test definitions and fixtures retained ---


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _lineages(root: Path) -> tuple[Path, Path]:
    base_steps = [
        {
            "sequence": 1,
            "superstep": 0,
            "node_id": "builder",
            "checkpoint_id": "cp-1",
            "reads": [],
            "writes": [],
            "evidence": [],
            "side_effects": [],
            "decision": {"route": "verify", "reason": "implementation ready"},
        }
    ]
    candidate_steps = [
        {**base_steps[0], "decision": {"route": "repair", "reason": "proof failed"}}
    ]
    left_steps, right_steps = root / "left-steps.json", root / "right-steps.json"
    left_steps.write_text(json.dumps(base_steps), encoding="utf-8")
    right_steps.write_text(json.dumps(candidate_steps), encoding="utf-8")
    left, right = root / "left.lineage.json", root / "right.lineage.json"
    seal_graph_lineage("baseline", "checkout", left_steps, left)
    seal_graph_lineage("candidate", "checkout", right_steps, right)
    return left, right


def _plan(root: Path) -> Path:
    left, right = _lineages(root)
    destination = root / ".factory" / "proofsearch" / "plan.json"
    create_proofsearch_plan(
        root, left, right, ["src/service.py", "tests/test_service.py"], destination
    )
    return destination


def _candidate(
    root: Path,
    candidate_id: str,
    *,
    risk: int,
    lines: int,
    killed: int = 2,
    total: int = 2,
    changed: list[str] | None = None,
    status: str = "passed",
    tokens: int | None = None,
) -> dict:
    patch = root / f"{candidate_id}.patch"
    patch.write_text(
        f"diff --git a/src/service.py b/src/service.py\n+{candidate_id}\n",
        encoding="utf-8",
    )
    receipt = root / f"{candidate_id}-proof.json"
    receipt.write_text(
        json.dumps({"candidate": candidate_id, "passed": status == "passed"}),
        encoding="utf-8",
    )
    return {
        "candidate_id": candidate_id,
        "patch": {"path": patch.relative_to(root).as_posix(), "sha256": _sha(patch)},
        "changed_paths": changed or ["src/service.py"],
        "proofs": [
            {
                "name": "unit",
                "required": True,
                "status": status,
                "receipt": {
                    "path": receipt.relative_to(root).as_posix(),
                    "sha256": _sha(receipt),
                },
                "elapsed_ms": 100 + risk,
                "tokens": tokens,
                "cost_usd": None,
            }
        ],
        "mutation": {"killed": killed, "total": total},
        "guardrails": {
            "weakens_tests": False,
            "suppresses_errors": False,
            "expands_scope": False,
        },
        "risk_score": risk,
        "changed_lines": lines,
    }


def _request(
    root: Path, plan: Path, candidates: list[dict], *, baseline: dict | None = None
) -> Path:
    payload = {
        "schema": "factory.proofsearch-request.v1",
        "plan": {"path": plan.relative_to(root).as_posix(), "sha256": _sha(plan)},
        "candidates": candidates,
    }
    if baseline is not None:
        payload["paired_baseline"] = baseline
    path = root / "request.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_proofsearch_selects_smallest_low_risk_verified_candidate_and_explains_losers(
    tmp_path: Path,
):
    plan = _plan(tmp_path)
    request = _request(
        tmp_path,
        plan,
        [
            _candidate(tmp_path, "wide", risk=20, lines=80),
            _candidate(tmp_path, "winner", risk=5, lines=12),
            _candidate(tmp_path, "hollow", risk=1, lines=4, killed=1),
        ],
    )
    output = tmp_path / ".factory" / "proofsearch" / "evaluation.json"

    result = evaluate_proofsearch(tmp_path, request, output)

    assert result["marker"] == "PROOFSEARCH_WINNER_VERIFIED"
    assert result["winner"] == "winner"
    candidates = {item["candidate_id"]: item for item in result["candidates"]}
    assert candidates["hollow"]["reasons"] == ["HOLLOW_CANDIDATE_TESTS"]
    assert candidates["wide"]["reasons"] == ["PARETO_DOMINATED_BY_VERIFIED_WINNER"]
    assert result["apply"] is False
    assert all(value is False for value in result["authority"].values())
    assert result["savings"] == {
        "elapsed_ms": None,
        "tokens": None,
        "cost_usd": None,
        "productivity": None,
        "evidence": "unavailable",
    }
    assert verify_proofsearch_evaluation(tmp_path, output)["valid"] is True


def test_proofsearch_rejects_scope_escape_failed_proof_and_declared_unsafe_behavior(
    tmp_path: Path,
):
    plan = _plan(tmp_path)
    escaped = _candidate(
        tmp_path, "escaped", risk=1, lines=1, changed=["secrets.txt"], status="failed"
    )
    escaped["guardrails"]["weakens_tests"] = True
    escaped["guardrails"]["suppresses_errors"] = True
    request = _request(
        tmp_path,
        plan,
        [escaped, _candidate(tmp_path, "hollow", risk=2, lines=2, killed=0, total=1)],
    )

    result = evaluate_proofsearch(tmp_path, request, tmp_path / "evaluation.json")

    assert result["marker"] == "PROOFSEARCH_NO_ELIGIBLE_CANDIDATE"
    assert result["winner"] is None
    reasons = next(
        item["reasons"]
        for item in result["candidates"]
        if item["candidate_id"] == "escaped"
    )
    assert reasons == [
        "CANDIDATE_SCOPE_ESCAPE",
        "ERROR_SUPPRESSION_DECLARED",
        "REQUIRED_PROOF_FAILED",
        "TEST_WEAKENING_DECLARED",
    ]


def test_proofsearch_reports_exact_paired_savings_but_never_infers_productivity(
    tmp_path: Path,
):
    plan = _plan(tmp_path)
    request = _request(
        tmp_path,
        plan,
        [
            _candidate(tmp_path, "a", risk=1, lines=2, tokens=40),
            _candidate(tmp_path, "b", risk=2, lines=3, tokens=50),
        ],
        baseline={"elapsed_ms": 500, "tokens": 100, "cost_usd": 1.0},
    )

    result = evaluate_proofsearch(tmp_path, request, tmp_path / "evaluation.json")

    assert result["savings"] == {
        "elapsed_ms": 399,
        "tokens": 60,
        "cost_usd": None,
        "productivity": None,
        "evidence": "exact_paired_baseline",
    }


def test_proofsearch_fails_closed_for_tampered_evidence_and_candidate_bounds(
    tmp_path: Path,
):
    plan = _plan(tmp_path)
    candidate = _candidate(tmp_path, "a", risk=1, lines=2)
    other = _candidate(tmp_path, "b", risk=2, lines=3)
    request = _request(tmp_path, plan, [candidate, other])
    (tmp_path / "a.patch").write_text("tampered", encoding="utf-8")

    with pytest.raises(ProofSearchError) as failure:
        evaluate_proofsearch(tmp_path, request, tmp_path / "evaluation.json")
    assert failure.value.code == "PROOFSEARCH_EVIDENCE_HASH_MISMATCH"

    too_many = [
        _candidate(tmp_path, f"c{index}", risk=index, lines=index + 1)
        for index in range(13)
    ]
    bounded = _request(tmp_path, plan, too_many)
    with pytest.raises(ProofSearchError) as count_failure:
        evaluate_proofsearch(tmp_path, bounded, tmp_path / "evaluation.json")
    assert count_failure.value.code == "PROOFSEARCH_CANDIDATE_COUNT"


def test_proofsearch_rejects_a_declared_pass_that_the_receipt_does_not_support(
    tmp_path: Path,
):
    plan = _plan(tmp_path)
    dishonest = _candidate(tmp_path, "dishonest", risk=1, lines=2)
    receipt = tmp_path / "dishonest-proof.json"
    receipt.write_text(
        json.dumps({"candidate": "dishonest", "passed": False}), encoding="utf-8"
    )
    dishonest["proofs"][0]["receipt"]["sha256"] = _sha(receipt)
    request = _request(
        tmp_path, plan, [dishonest, _candidate(tmp_path, "honest", risk=2, lines=3)]
    )

    result = evaluate_proofsearch(tmp_path, request, tmp_path / "evaluation.json")

    candidates = {item["candidate_id"]: item for item in result["candidates"]}
    assert result["winner"] == "honest"
    assert candidates["dishonest"]["eligible"] is False
    assert candidates["dishonest"]["reasons"] == ["PROOF_RECEIPT_STATUS_MISMATCH"]


def test_proofsearch_cli_plan_evaluate_and_verify(tmp_path: Path, capsys):
    left, right = _lineages(tmp_path)
    plan = tmp_path / ".factory" / "proofsearch" / "plan.json"
    assert (
        main(
            [
                "proofsearch",
                "plan",
                "--root",
                str(tmp_path),
                "--baseline",
                str(left),
                "--candidate",
                str(right),
                "--changed",
                "src/service.py",
                "--out",
                str(plan),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["marker"] == "PROOFSEARCH_PLAN_SEALED"
    request = _request(
        tmp_path,
        plan,
        [
            _candidate(tmp_path, "a", risk=1, lines=2),
            _candidate(tmp_path, "b", risk=2, lines=3),
        ],
    )
    evaluation = tmp_path / ".factory" / "proofsearch" / "evaluation.json"
    assert (
        main(
            [
                "proofsearch",
                "evaluate",
                str(request),
                "--root",
                str(tmp_path),
                "--out",
                str(evaluation),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["winner"] == "a"
    assert (
        main(
            [
                "proofsearch",
                "verify",
                str(evaluation),
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    assert (
        json.loads(capsys.readouterr().out)["marker"]
        == "PROOFSEARCH_EVALUATION_VERIFIED"
    )
