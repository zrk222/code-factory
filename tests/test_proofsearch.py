from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.graph_forensics import seal_graph_lineage
from factoryline.proofsearch import (
    ProofSearchError,
    create_proofsearch_plan,
    evaluate_proofsearch,
    verify_proofsearch_evaluation,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _lineages(root: Path) -> tuple[Path, Path]:
    base_steps = [{
        "sequence": 1, "superstep": 0, "node_id": "builder", "checkpoint_id": "cp-1",
        "reads": [], "writes": [], "evidence": [], "side_effects": [],
        "decision": {"route": "verify", "reason": "implementation ready"},
    }]
    candidate_steps = [{**base_steps[0], "decision": {"route": "repair", "reason": "proof failed"}}]
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
    create_proofsearch_plan(root, left, right, ["src/service.py", "tests/test_service.py"], destination)
    return destination


def _candidate(root: Path, candidate_id: str, *, risk: int, lines: int, killed: int = 2, total: int = 2, changed: list[str] | None = None, status: str = "passed", tokens: int | None = None) -> dict:
    patch = root / f"{candidate_id}.patch"
    patch.write_text(f"diff --git a/src/service.py b/src/service.py\n+{candidate_id}\n", encoding="utf-8")
    receipt = root / f"{candidate_id}-proof.json"
    receipt.write_text(json.dumps({"candidate": candidate_id, "passed": status == "passed"}), encoding="utf-8")
    return {
        "candidate_id": candidate_id,
        "patch": {"path": patch.relative_to(root).as_posix(), "sha256": _sha(patch)},
        "changed_paths": changed or ["src/service.py"],
        "proofs": [{
            "name": "unit", "required": True, "status": status,
            "receipt": {"path": receipt.relative_to(root).as_posix(), "sha256": _sha(receipt)},
            "elapsed_ms": 100 + risk, "tokens": tokens, "cost_usd": None,
        }],
        "mutation": {"killed": killed, "total": total},
        "guardrails": {"weakens_tests": False, "suppresses_errors": False, "expands_scope": False},
        "risk_score": risk, "changed_lines": lines,
    }


def _request(root: Path, plan: Path, candidates: list[dict], *, baseline: dict | None = None) -> Path:
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


def test_proofsearch_selects_smallest_low_risk_verified_candidate_and_explains_losers(tmp_path: Path):
    plan = _plan(tmp_path)
    request = _request(tmp_path, plan, [
        _candidate(tmp_path, "wide", risk=20, lines=80),
        _candidate(tmp_path, "winner", risk=5, lines=12),
        _candidate(tmp_path, "hollow", risk=1, lines=4, killed=1),
    ])
    output = tmp_path / ".factory" / "proofsearch" / "evaluation.json"

    result = evaluate_proofsearch(tmp_path, request, output)

    assert result["marker"] == "PROOFSEARCH_WINNER_VERIFIED"
    assert result["winner"] == "winner"
    candidates = {item["candidate_id"]: item for item in result["candidates"]}
    assert candidates["hollow"]["reasons"] == ["HOLLOW_CANDIDATE_TESTS"]
    assert candidates["wide"]["reasons"] == ["PARETO_DOMINATED_BY_VERIFIED_WINNER"]
    assert result["apply"] is False
    assert all(value is False for value in result["authority"].values())
    assert result["savings"] == {"elapsed_ms": None, "tokens": None, "cost_usd": None, "productivity": None, "evidence": "unavailable"}
    assert verify_proofsearch_evaluation(tmp_path, output)["valid"] is True


def test_proofsearch_rejects_scope_escape_failed_proof_and_declared_unsafe_behavior(tmp_path: Path):
    plan = _plan(tmp_path)
    escaped = _candidate(tmp_path, "escaped", risk=1, lines=1, changed=["secrets.txt"], status="failed")
    escaped["guardrails"]["weakens_tests"] = True
    escaped["guardrails"]["suppresses_errors"] = True
    request = _request(tmp_path, plan, [escaped, _candidate(tmp_path, "hollow", risk=2, lines=2, killed=0, total=1)])

    result = evaluate_proofsearch(tmp_path, request, tmp_path / "evaluation.json")

    assert result["marker"] == "PROOFSEARCH_NO_ELIGIBLE_CANDIDATE"
    assert result["winner"] is None
    reasons = next(item["reasons"] for item in result["candidates"] if item["candidate_id"] == "escaped")
    assert reasons == ["CANDIDATE_SCOPE_ESCAPE", "ERROR_SUPPRESSION_DECLARED", "REQUIRED_PROOF_FAILED", "TEST_WEAKENING_DECLARED"]


def test_proofsearch_reports_exact_paired_savings_but_never_infers_productivity(tmp_path: Path):
    plan = _plan(tmp_path)
    request = _request(tmp_path, plan, [
        _candidate(tmp_path, "a", risk=1, lines=2, tokens=40),
        _candidate(tmp_path, "b", risk=2, lines=3, tokens=50),
    ], baseline={"elapsed_ms": 500, "tokens": 100, "cost_usd": 1.0})

    result = evaluate_proofsearch(tmp_path, request, tmp_path / "evaluation.json")

    assert result["savings"] == {"elapsed_ms": 399, "tokens": 60, "cost_usd": None, "productivity": None, "evidence": "exact_paired_baseline"}


def test_proofsearch_fails_closed_for_tampered_evidence_and_candidate_bounds(tmp_path: Path):
    plan = _plan(tmp_path)
    candidate = _candidate(tmp_path, "a", risk=1, lines=2)
    other = _candidate(tmp_path, "b", risk=2, lines=3)
    request = _request(tmp_path, plan, [candidate, other])
    (tmp_path / "a.patch").write_text("tampered", encoding="utf-8")

    with pytest.raises(ProofSearchError) as failure:
        evaluate_proofsearch(tmp_path, request, tmp_path / "evaluation.json")
    assert failure.value.code == "PROOFSEARCH_EVIDENCE_HASH_MISMATCH"

    too_many = [_candidate(tmp_path, f"c{index}", risk=index, lines=index + 1) for index in range(13)]
    bounded = _request(tmp_path, plan, too_many)
    with pytest.raises(ProofSearchError) as count_failure:
        evaluate_proofsearch(tmp_path, bounded, tmp_path / "evaluation.json")
    assert count_failure.value.code == "PROOFSEARCH_CANDIDATE_COUNT"


def test_proofsearch_rejects_a_declared_pass_that_the_receipt_does_not_support(tmp_path: Path):
    plan = _plan(tmp_path)
    dishonest = _candidate(tmp_path, "dishonest", risk=1, lines=2)
    receipt = tmp_path / "dishonest-proof.json"
    receipt.write_text(json.dumps({"candidate": "dishonest", "passed": False}), encoding="utf-8")
    dishonest["proofs"][0]["receipt"]["sha256"] = _sha(receipt)
    request = _request(tmp_path, plan, [dishonest, _candidate(tmp_path, "honest", risk=2, lines=3)])

    result = evaluate_proofsearch(tmp_path, request, tmp_path / "evaluation.json")

    candidates = {item["candidate_id"]: item for item in result["candidates"]}
    assert result["winner"] == "honest"
    assert candidates["dishonest"]["eligible"] is False
    assert candidates["dishonest"]["reasons"] == ["PROOF_RECEIPT_STATUS_MISMATCH"]


def test_proofsearch_cli_plan_evaluate_and_verify(tmp_path: Path, capsys):
    left, right = _lineages(tmp_path)
    plan = tmp_path / ".factory" / "proofsearch" / "plan.json"
    assert main(["proofsearch", "plan", "--root", str(tmp_path), "--baseline", str(left), "--candidate", str(right), "--changed", "src/service.py", "--out", str(plan), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["marker"] == "PROOFSEARCH_PLAN_SEALED"
    request = _request(tmp_path, plan, [_candidate(tmp_path, "a", risk=1, lines=2), _candidate(tmp_path, "b", risk=2, lines=3)])
    evaluation = tmp_path / ".factory" / "proofsearch" / "evaluation.json"
    assert main(["proofsearch", "evaluate", str(request), "--root", str(tmp_path), "--out", str(evaluation), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["winner"] == "a"
    assert main(["proofsearch", "verify", str(evaluation), "--root", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["marker"] == "PROOFSEARCH_EVALUATION_VERIFIED"
