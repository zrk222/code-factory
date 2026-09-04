from copy import deepcopy
import json

import pytest

from test_deep_audit_contract import fixture
from test_deep_audit_sarif import report
from factoryline.deep_audit import execute_deep_audit, evaluate_deep_audit, deep_audit_status
from factoryline.deep_audit_contract import verify_deep_audit_plan
from factoryline.deep_audit_sarif import normalize_sarif
from factoryline.deep_audit_io import digest
from factoryline.runtime_audit_common import RuntimeAuditError, sha256_bytes


def inputs(tmp_path, *, clean=False, canary_kind="fail", canary_suppressed=False):
    def bind(plan):
        for key, name in (("report", "scan.json"), ("canary_report", "canary.json")):
            payload = report()
            result = payload["runs"][0]["results"][0]
            result["ruleId"] = "leak"
            payload["runs"][0]["tool"]["driver"]["rules"][0]["id"] = "leak"
            result["partialFingerprints"]["primary/v1"] = key
            if key == "canary_report":
                result["kind"] = canary_kind
                if canary_suppressed:
                    result["suppressions"] = [{"kind": "external", "status": "accepted"}]
            elif clean:
                payload["runs"][0]["results"] = []
            raw = json.dumps(payload).encode()
            (tmp_path/name).write_bytes(raw)
            plan["analyzers"][0][key]["sha256"] = sha256_bytes(raw)
        plan["canaries"][0]["fingerprint_sha256"] = digest({"partialFingerprints:primary/v1": "canary_report"})
    args = fixture(tmp_path, bind)
    checked = verify_deep_audit_plan(*args)
    analyzer = checked["plan"]["analyzers"][0]
    targets = [normalize_sarif(tmp_path, analyzer["report"], analyzer, checked["source_hashes"])]
    canaries = [normalize_sarif(tmp_path, analyzer["canary_report"], analyzer, checked["source_hashes"])]
    return args, checked["plan"], targets, canaries


def rehash(report):
    report.pop("normalized_sha256", None)
    report["normalized_sha256"] = digest(report)


def codes(receipt):
    return {action["code"] for action in receipt["repair_queue"]}


def test_signed_execution_threshold_and_idempotent_receipt(tmp_path):
    args, plan, targets, canaries = inputs(tmp_path)
    result = execute_deep_audit(*args)
    receipt = result["receipt"]
    assert receipt["decision"] == "BLOCKED"
    assert codes(receipt) == {"DEEP_RULE_THRESHOLD"}
    assert receipt["repair_queue"][0]["remediation"] == "Close owned resources"
    assert execute_deep_audit(*args) == result
    assert deep_audit_status(tmp_path)["state"] == "BLOCKED"
    assert evaluate_deep_audit(plan, targets, canaries)["authority"] == "none"


def test_clean_with_detected_canary_requires_human_review(tmp_path):
    args, _, _, _ = inputs(tmp_path, clean=True)
    receipt = execute_deep_audit(*args)["receipt"]
    assert receipt["decision"] == "READY_FOR_HUMAN_REVIEW"
    assert receipt["repair_queue"] == []
    assert receipt["authority"] == "none"
    assert deep_audit_status(tmp_path)["verification"] == "self_hash_only_not_signature_or_freshness"


@pytest.mark.parametrize("kind", ["pass", "notApplicable", "review", "open", "informational"])
def test_nonfailure_canary_cannot_validate_analyzer(tmp_path, kind):
    args, _, _, _ = inputs(tmp_path, clean=True, canary_kind=kind)
    assert "HOLLOW_DEEP_AUDIT" in codes(execute_deep_audit(*args)["receipt"])


def test_suppressed_canary_cannot_validate_analyzer(tmp_path):
    args, _, _, _ = inputs(tmp_path, clean=True, canary_suppressed=True)
    assert "HOLLOW_DEEP_AUDIT" in codes(execute_deep_audit(*args)["receipt"])


def test_missing_fingerprint_canary_fails_closed(tmp_path):
    _, plan, targets, canaries = inputs(tmp_path, clean=True)
    canaries[0]["findings"] = []
    rehash(canaries[0])
    assert "HOLLOW_DEEP_AUDIT" in codes(evaluate_deep_audit(plan, targets, canaries))


def test_trace_order_and_suppression_require_review(tmp_path):
    _, plan, targets, canaries = inputs(tmp_path)
    finding = targets[0]["findings"][0]
    finding["flows"][0].reverse()
    finding["suppressed"] = True
    rehash(targets[0])
    result = evaluate_deep_audit(plan, targets, canaries)
    assert {"DEEP_TRACE_INCOMPLETE", "DEEP_SUPPRESSION_UNAPPROVED"} <= codes(result)


def test_unknown_new_error_is_not_ignored(tmp_path):
    _, plan, targets, canaries = inputs(tmp_path)
    targets[0]["findings"][0]["rule_id"] = "unmapped"
    rehash(targets[0])
    assert "DEEP_UNKNOWN_ERROR" in codes(evaluate_deep_audit(plan, targets, canaries))


def test_missing_duplicate_and_changed_reports_rejected(tmp_path):
    _, plan, targets, canaries = inputs(tmp_path)
    with pytest.raises(RuntimeAuditError, match="E_ANALYZER_INCOMPLETE"):
        evaluate_deep_audit(plan, [], canaries)
    with pytest.raises(RuntimeAuditError, match="E_DEEP_REPORT"):
        evaluate_deep_audit(plan, targets*2, canaries)
    targets[0]["findings"] = []
    with pytest.raises(RuntimeAuditError, match="E_DEEP_REPORT"):
        evaluate_deep_audit(plan, targets, canaries)


def test_tampered_receipt_never_falls_back_to_green(tmp_path):
    args, _, _, _ = inputs(tmp_path, clean=True)
    result = execute_deep_audit(*args)
    from pathlib import Path
    Path(result["receipt_path"]).write_text("{}")
    assert deep_audit_status(tmp_path)["state"] == "INCOMPLETE"
    with pytest.raises(RuntimeAuditError, match="E_RECEIPT_COLLISION"):
        execute_deep_audit(*args)


def test_absent_and_pass_labels_do_not_hide_signed_threshold_findings(tmp_path):
    _, plan, targets, canaries = inputs(tmp_path)
    targets[0]["findings"][0].update(baseline="absent", kind="pass")
    rehash(targets[0])
    assert "DEEP_RULE_THRESHOLD" in codes(evaluate_deep_audit(plan, targets, canaries))


def test_cluster_signals_do_not_claim_causation(tmp_path):
    from factoryline.deep_audit import _clusters
    _, _, targets, _ = inputs(tmp_path)
    first = {**targets[0]["findings"][0], "obligation_id": "o", "category": "memory"}
    second = {**deepcopy(first), "analyzer_id": "second", "finding_id": "b"*64, "category": "security"}
    clusters = _clusters([first, second])
    assert {item["kind"] for item in clusters} == {"corroboration", "compound_risk"}
    assert all(item["claim"] == "routing_signal_not_causation" for item in clusters)


def test_status_rejects_oversize_receipt(tmp_path, monkeypatch):
    args, _, _, _ = inputs(tmp_path, clean=True)
    execute_deep_audit(*args)
    monkeypatch.setattr("factoryline.deep_audit.LIMIT", 10)
    assert deep_audit_status(tmp_path)["state"] == "INCOMPLETE"


def test_status_rejects_non_directory_history(tmp_path):
    (tmp_path / ".factory").write_text("not a directory")
    assert deep_audit_status(tmp_path)["state"] == "INCOMPLETE"


def test_status_without_history_is_not_run(tmp_path):
    assert deep_audit_status(tmp_path)["state"] == "NOT_RUN"
