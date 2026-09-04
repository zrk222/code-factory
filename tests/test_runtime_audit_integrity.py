import pytest
from factoryline.runtime_audit import evaluate_runtime_audit
from factoryline.runtime_audit_integrity import index_executions, repair_guidance
from factoryline.runtime_audit_common import RuntimeAuditError
from test_runtime_audit import _plan, _command


@pytest.mark.parametrize("mutation", ["duplicate", "unknown", "kind", "malformed", "overflow"])
def test_ambiguous_join_is_rejected(tmp_path, mutation):
    lane = _plan()["lanes"][0]
    entry = {"id": lane["id"], "kind": lane["kind"], "target": _command(lane["kind"]), "known_bad": _command(lane["kind"], True)}
    rows = [entry]
    if mutation == "duplicate": rows.append(dict(entry))
    elif mutation == "unknown": entry["id"] = "unapproved"
    elif mutation == "kind": entry["kind"] = "tenant_isolation"
    elif mutation == "malformed": rows.append(None)
    else: rows *= 7
    with pytest.raises(RuntimeAuditError) as error:
        evaluate_runtime_audit(_plan(), {"executions": rows}, tmp_path)
    assert error.value.code == "E_AUDIT_EXECUTION_SET"


def test_missing_evidence_stays_incomplete(tmp_path):
    result = evaluate_runtime_audit(_plan(), {"executions": []}, tmp_path)
    assert result["decision"] == "BLOCKED"
    assert all(lane["repair_guidance"]["repair_target"] == "audit_evidence" for lane in result["lanes"])


@pytest.mark.parametrize("lane", _plan()["lanes"])
def test_all_six_lanes_get_exact_replay_and_no_authority(lane):
    result = repair_guidance({"state": "FAIL", "finding": "REAL_DEFECT"}, lane)
    assert result["repair_target"] == "application_behavior"
    assert result["negative_argv"] == lane["known_bad_argv"]
    assert result["expected_negative_code"] == lane["expected_negative_code"]
    assert result["authority"] == "none"
    assert repair_guidance({"state": "FAIL", "finding": "HOLLOW_RUNTIME_AUDIT"}, lane)["repair_target"] == "audit_evidence"


def test_duplicate_plan_lane_cannot_claim_six_lane_coverage():
    plan = _plan()
    plan["lanes"][-1] = plan["lanes"][0]
    with pytest.raises(RuntimeAuditError):
        index_executions(plan, {"executions": []})
