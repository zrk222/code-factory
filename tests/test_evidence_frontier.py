from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from factoryline.evidence_frontier import EvidenceFrontierError, plan_evidence_frontier, verify_evidence_frontier
from factoryline.cli import main
from factoryline.proofsearch import evaluate_proofsearch

from test_proofsearch import _candidate, _plan, _request as _proofsearch_request


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _evaluation(root: Path) -> Path:
    plan = _plan(root)
    request = _proofsearch_request(root, plan, [
        _candidate(root, "repair-a", risk=4, lines=9),
        _candidate(root, "repair-b", risk=5, lines=10),
        _candidate(root, "repair-c", risk=6, lines=11),
    ])
    output = root / ".factory" / "proofsearch" / "comparison.evaluation.json"
    evaluate_proofsearch(root, request, output)
    return output


def _request(root: Path, evaluation: Path, experiments: list[dict], maximum: int = 8) -> Path:
    value = {
        "schema": "factory.evidence-frontier-request.v1",
        "evaluation": {"path": evaluation.relative_to(root).as_posix(), "sha256": _sha(evaluation)},
        "max_experiments": maximum,
        "experiments": experiments,
    }
    path = root / "frontier.request.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _experiment(identifier: str, predictions: dict[str, str], *, elapsed: int | None = None, root: Path | None = None) -> dict:
    measurement = None
    if elapsed is not None:
        assert root is not None
        receipt = root / f"{identifier}.measurement.json"
        receipt.write_text(json.dumps({"historical": True, "elapsed_ms": elapsed}), encoding="utf-8")
        measurement = {"elapsed_ms": elapsed, "receipt": {"path": receipt.relative_to(root).as_posix(), "sha256": _sha(receipt)}}
    return {"experiment_id": identifier, "kind": "test", "description": f"Run {identifier} only.", "predictions": predictions, "measurement": measurement}


def test_frontier_selects_largest_separation_then_measured_elapsed_and_seals_output(tmp_path: Path):
    evaluation = _evaluation(tmp_path)
    request = _request(tmp_path, evaluation, [
        _experiment("b-slower", {"repair-a": "pass", "repair-b": "fail", "repair-c": "fail"}, elapsed=90, root=tmp_path),
        _experiment("a-faster", {"repair-a": "pass", "repair-b": "fail", "repair-c": "fail"}, elapsed=40, root=tmp_path),
        _experiment("low-value", {"repair-a": "pass", "repair-b": "pass", "repair-c": "fail"}, root=tmp_path),
    ])
    output = tmp_path / ".factory" / "proofsearch" / "comparison.frontier.json"

    result = plan_evidence_frontier(tmp_path, request, output)

    assert result["marker"] == "EVIDENCE_FRONTIER_NEXT_EXPERIMENT_SELECTED"
    assert result["next_experiment"] == "a-faster"
    assert [item["experiment_id"] for item in result["experiments"]] == ["a-faster", "b-slower", "low-value"]
    assert result["experiments"][0]["separation_count"] == 2
    assert result["savings"] == {"elapsed_ms": None, "tokens": None, "cost_usd": None, "productivity": None, "evidence": "unavailable"}
    assert all(value is False for value in result["authority"].values())
    assert verify_evidence_frontier(tmp_path, output)["valid"] is True


def test_frontier_halts_when_no_experiment_discriminates(tmp_path: Path):
    evaluation = _evaluation(tmp_path)
    request = _request(tmp_path, evaluation, [
        _experiment("same", {"repair-a": "pass", "repair-b": "pass", "repair-c": "unknown"}, root=tmp_path),
    ])

    result = plan_evidence_frontier(tmp_path, request, tmp_path / "frontier.json")

    assert result["marker"] == "EVIDENCE_FRONTIER_NO_DISCRIMINATING_EXPERIMENT"
    assert result["next_experiment"] is None
    assert result["decision"] == "no_discriminating_experiment"


def test_frontier_rejects_prediction_drift_and_evaluation_tampering(tmp_path: Path):
    evaluation = _evaluation(tmp_path)
    bad = _request(tmp_path, evaluation, [
        _experiment("incomplete", {"repair-a": "pass", "repair-b": "fail"}, root=tmp_path),
    ])
    with pytest.raises(EvidenceFrontierError) as prediction_error:
        plan_evidence_frontier(tmp_path, bad, tmp_path / "frontier.json")
    assert prediction_error.value.code == "EVIDENCE_FRONTIER_PREDICTION_INVALID"

    good = _request(tmp_path, evaluation, [
        _experiment("targeted", {"repair-a": "pass", "repair-b": "fail", "repair-c": "fail"}, root=tmp_path),
    ])
    evaluation.write_text("{}", encoding="utf-8")
    with pytest.raises(EvidenceFrontierError) as tamper_error:
        plan_evidence_frontier(tmp_path, good, tmp_path / "frontier.json")
    assert tamper_error.value.code == "EVIDENCE_FRONTIER_EVIDENCE_HASH_MISMATCH"


def test_frontier_verification_detects_changed_bound_evaluation(tmp_path: Path):
    evaluation = _evaluation(tmp_path)
    request = _request(tmp_path, evaluation, [
        _experiment("targeted", {"repair-a": "pass", "repair-b": "fail", "repair-c": "fail"}, root=tmp_path),
    ])
    output = tmp_path / "frontier.json"
    plan_evidence_frontier(tmp_path, request, output)
    evaluation.write_text(evaluation.read_text(encoding="utf-8") + " ", encoding="utf-8")

    result = verify_evidence_frontier(tmp_path, output)

    assert result["valid"] is False
    assert result["marker"] == "EVIDENCE_FRONTIER_INVALID"
    assert any("EVIDENCE_FRONTIER_EVIDENCE_HASH_MISMATCH" in item for item in result["errors"])


def test_frontier_cli_plans_and_verifies_without_execution(tmp_path: Path, capsys):
    evaluation = _evaluation(tmp_path)
    request = _request(tmp_path, evaluation, [
        _experiment("targeted", {"repair-a": "pass", "repair-b": "fail", "repair-c": "fail"}, root=tmp_path),
    ])
    frontier = tmp_path / ".factory" / "proofsearch" / "comparison.frontier.json"

    assert main(["proofsearch", "frontier", "plan", str(request), "--root", str(tmp_path), "--out", str(frontier), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["next_experiment"] == "targeted"
    assert main(["proofsearch", "frontier", "verify", str(frontier), "--root", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["marker"] == "EVIDENCE_FRONTIER_VERIFIED"
