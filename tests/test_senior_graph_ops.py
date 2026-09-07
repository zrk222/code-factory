import json
import hashlib
from pathlib import Path

from factoryline.graph_ops import graph_ops_snapshot
from factoryline.incremental_scheduler import plan_incremental
from factoryline.senior_engineering import senior_engineering_projection


def _manifest():
    return {
        "schema": "factory.incremental-plan.v1",
        "plan_id": "graph-plan",
        "assurance_level": "isolated_worker",
        "changed_paths": ["src/app.py"],
        "dependency_closure": {"lint": ["src/app.py"]},
        "gates": [{"id": "lint", "depends_on": [], "side_effects": False, "proof": None}],
    }


def test_empty_projection_is_explicitly_review_only(tmp_path: Path):
    result = senior_engineering_projection(tmp_path)
    assert result["receipt_count"] == 0
    assert result["authority_false"] is True
    assert result["authority"]["publication"] is False
    assert result["errors"] == []


def test_graph_ops_projects_valid_plan_and_fails_closed_on_tamper(tmp_path: Path):
    output = tmp_path / ".factory" / "senior" / "incremental.json"
    plan_incremental(tmp_path, _manifest(), out=output)
    snapshot = graph_ops_snapshot(tmp_path)
    assert snapshot["facts"]["senior_engineering_receipt_count"] == 1
    assert snapshot["facts"]["senior_engineering_invalid_count"] == 0
    assert "GRAPH_OPS_SENIOR_ENGINEERING_READ_ONLY" in snapshot["markers"]
    assert any(node["kind"] == "senior_engineering_evidence" for node in snapshot["nodes"])

    payload = json.loads(output.read_text(encoding="utf-8"))
    payload["counts"]["RUN"] = 99
    output.write_text(json.dumps(payload), encoding="utf-8")
    tampered = graph_ops_snapshot(tmp_path)
    assert tampered["facts"]["senior_engineering_invalid_count"] == 1
    assert "GRAPH_OPS_SENIOR_ENGINEERING_REVIEW_REQUIRED" in tampered["markers"]
    assert tampered["recommendation"]["action"] == "review_senior_engineering_evidence"


def test_projection_rejects_receipts_that_claim_authority(tmp_path: Path):
    directory = tmp_path / ".factory" / "senior"
    directory.mkdir(parents=True)
    (directory / "authority.json").write_text(
        json.dumps({"schema": "factory.incremental-shadow.v1", "authority": "publication", "shadow_equivalent": True}),
        encoding="utf-8",
    )
    result = senior_engineering_projection(tmp_path)
    assert result["invalid_count"] == 1
    assert result["errors"][0]["code"] == "AUTHORITY_NOT_NONE"


def test_projection_reads_failure_brief_as_review_only_evidence(tmp_path: Path):
    directory = tmp_path / ".factory" / "senior"
    directory.mkdir(parents=True)
    brief = {"schema": "factory.failure-brief.v1", "marker": "FAILURE_BRIEF_EVIDENCE_LINKED", "state": "ACTION_REQUIRED", "what_broke": [{"id": "x", "summary": "broken", "evidence": "a"}], "affected": ["src"], "reproduce": {"argv": ["python", "run.py"]}, "next_fix": "repair", "uncertainty": ["owner unknown"], "evidence": [{"receipt_sha256": "a"}], "authority": "none", "release_approval": False}
    brief["brief_sha256"] = hashlib.sha256(json.dumps({key: value for key, value in brief.items() if key != "brief_sha256"}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    (directory / "brief.json").write_text(json.dumps(brief), encoding="utf-8")
    result = senior_engineering_projection(tmp_path)
    assert result["receipt_count"] == 1
    assert result["invalid_count"] == 0
    assert result["receipts"][0]["schema"] == "factory.failure-brief.v1"
