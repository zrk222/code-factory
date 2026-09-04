from copy import deepcopy
from pathlib import Path
import json

import pytest

from test_deep_audit import inputs
from factoryline.deep_audit import execute_deep_audit, deep_audit_status
from factoryline.deep_audit_io import digest
from factoryline.deep_audit_loop import compare_deep_audits, deep_audit_lineage
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.cli import main


def write(root, receipt):
    body = deepcopy(receipt)
    body.pop("receipt_sha256", None)
    body["receipt_sha256"] = digest(body)
    path = root / ".factory" / "deep-audits" / (body["receipt_sha256"] + ".json")
    path.write_text(json.dumps(body), encoding="utf-8")
    return path.relative_to(root).as_posix()


def initial(root):
    args, _, _, _ = inputs(root)
    result = execute_deep_audit(*args)
    return result["receipt"], Path(result["receipt_path"]).relative_to(root).as_posix()


def test_same_receipt_stagnates_without_authority(tmp_path):
    _, path = initial(tmp_path)
    result = compare_deep_audits(tmp_path, path, path)
    assert result["state"] == "stagnated"
    assert result["authority"] == "none"


@pytest.mark.parametrize("key", ["ruleset_sha256", "canary_set_sha256"])
def test_changed_policy_blocks(tmp_path, key):
    receipt, path = initial(tmp_path)
    receipt[key] = "a" * 64
    result = compare_deep_audits(tmp_path, path, write(tmp_path, receipt))
    assert result["code"] == "E_DEEP_POLICY_CHANGED"


def test_lost_coverage_blocks(tmp_path):
    receipt, path = initial(tmp_path)
    receipt["report_hashes"] = {}
    assert compare_deep_audits(tmp_path, path, write(tmp_path, receipt))["state"] == "blocked"


def test_new_finding_and_new_blocker_regress(tmp_path):
    receipt, path = initial(tmp_path)
    added = deepcopy(receipt["findings"][0])
    added["finding_id"] = "b" * 64
    receipt["findings"].append(added)
    assert compare_deep_audits(tmp_path, path, write(tmp_path, receipt))["state"] == "regressed"
    receipt["findings"].pop()
    receipt["repair_queue"].append({"code": "DEEP_TRACE_INCOMPLETE"})
    assert compare_deep_audits(tmp_path, path, write(tmp_path, receipt))["state"] == "regressed"


def test_reduction_then_human_only_closure(tmp_path):
    receipt, _ = initial(tmp_path)
    added = deepcopy(receipt["findings"][0])
    added["finding_id"] = "b" * 64
    receipt["findings"].append(added)
    before = write(tmp_path, receipt)
    receipt["findings"].pop()
    assert compare_deep_audits(tmp_path, before, write(tmp_path, receipt))["state"] == "repair_required"
    receipt.update(findings=[], repair_queue=[], decision="READY_FOR_HUMAN_REVIEW")
    assert compare_deep_audits(tmp_path, before, write(tmp_path, receipt))["state"] == "approval_required"


def test_invalid_and_escaping_inputs_block(tmp_path):
    _, path = initial(tmp_path)
    assert compare_deep_audits(tmp_path, path, "../outside.json")["state"] == "blocked"
    (tmp_path / path).write_text("{}")
    assert compare_deep_audits(tmp_path, path, path)["state"] == "blocked"


def test_graph_has_six_non_authorizing_stages(tmp_path):
    initial(tmp_path)
    result = graph_ops_snapshot(tmp_path)
    nodes = [n for n in result["nodes"] if n["kind"].startswith("deep_audit_")]
    assert {n["kind"] for n in nodes} == {"deep_audit_" + k for k in ("source", "obligation", "finding", "evidence", "decision", "handoff")}
    assert all(n["status"] == "unassessed" for n in nodes)
    assert result["deep_audit"]["authority"] == "none"


def test_projection_bound_and_stale_observation(tmp_path):
    receipt, _ = initial(tmp_path)
    receipt["findings"] = [{**receipt["findings"][0], "finding_id": digest(i)} for i in range(51)]
    write(tmp_path, receipt)
    status = deep_audit_status(tmp_path)
    result = deep_audit_lineage(tmp_path, status)
    assert len(result["chains"]) == 50 and result["truncated"]
    status["receipt_sha256"] = "a" * 64
    assert deep_audit_lineage(tmp_path, status)["state"] == "INCOMPLETE"


def test_compare_cli(tmp_path, capsys):
    _, path = initial(tmp_path)
    assert main(["deep-audit", "compare", "--root", str(tmp_path), "--before", path, "--after", path]) == 1
    assert json.loads(capsys.readouterr().out)["state"] == "stagnated"
