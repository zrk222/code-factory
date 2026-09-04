"""Unambiguous six-lane evidence joins and advisory repair routing."""
from .runtime_audit_common import RuntimeAuditError
from .runtime_audit_contract import LANES


def _expected_lanes(plan):
    lanes = plan["lanes"]
    expected = {lane["id"]: lane["kind"] for lane in lanes}
    if len(lanes) != len(LANES) or len(expected) != len(LANES) or sorted(expected.values()) != sorted(LANES):
        raise RuntimeAuditError("E_AUDIT_LANE_SET", "exactly one signed lane of each kind required")
    return expected


def index_executions(plan, executions):
    """Reject ambiguous execution collections rather than silently overwriting evidence."""
    expected = _expected_lanes(plan)
    entries = executions.get("executions", [])
    if not isinstance(entries, list) or len(entries) > len(LANES):
        raise RuntimeAuditError("E_AUDIT_EXECUTION_SET", "bounded execution list required")
    result = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise RuntimeAuditError("E_AUDIT_EXECUTION_SET", "execution identity required")
        key = entry["id"]
        if key in result or key not in expected or entry.get("kind") != expected[key]:
            raise RuntimeAuditError("E_AUDIT_EXECUTION_SET", "duplicate, unknown or mismatched execution identity")
        result[key] = entry
    return result


def repair_guidance(result, lane):
    """Separate evidence repair from application repair without granting execution authority."""
    evidence_problem = result["state"] == "INCOMPLETE" or result["finding"] == "HOLLOW_RUNTIME_AUDIT"
    return {"action_summary": "Repair audit evidence before judging the application." if evidence_problem else "Review the observed application behavior against the signed obligation.",
            "repair_target": "audit_evidence" if evidence_problem else "application_behavior",
            "required": result["state"] != "PASS", "authority": "none",
            "target_argv": list(lane["target_argv"]), "negative_argv": list(lane["known_bad_argv"]),
            "expected_negative_code": lane["expected_negative_code"],
            "acceptance": "Target must pass and known-bad control must trigger the unchanged signed expected finding.",
            "execution_boundary": "Suggestions only; replay requires the verified plan and supervised runner."}


def validate_receipt_decision(receipt):
    """Reject false readiness even when a local author recomputes the self-hash."""
    lanes = receipt.get("lanes")
    if not isinstance(lanes, list) or len(lanes) != len(LANES):
        raise RuntimeAuditError("E_RECEIPT_LANES", "complete six-lane receipt required")
    _validate_receipt_lanes(lanes)
    if receipt.get("authority") != "none" or receipt.get("release_approval") is not False:
        raise RuntimeAuditError("E_RECEIPT_AUTHORITY", "runtime audit cannot authorize release")
    expected = "READY_FOR_HUMAN_REVIEW" if all(lane["state"] == "PASS" for lane in lanes) else "BLOCKED"
    if receipt.get("decision") != expected:
        raise RuntimeAuditError("E_RECEIPT_DECISION", "decision contradicts lane results")


def _validate_receipt_lanes(lanes):
    ids, kinds = set(), set()
    for lane in lanes:
        if not isinstance(lane, dict):
            raise RuntimeAuditError("E_RECEIPT_LANES", "lane object required")
        identity, kind = lane.get("id"), lane.get("lane")
        if not isinstance(identity, str) or not identity.strip() or identity in ids:
            raise RuntimeAuditError("E_RECEIPT_LANES", "distinct nonempty lane identities required")
        if not isinstance(kind, str) or kind not in LANES or kind in kinds:
            raise RuntimeAuditError("E_RECEIPT_LANES", "distinct recognized lane kinds required")
        if lane.get("state") not in ("PASS", "FAIL", "INCOMPLETE"):
            raise RuntimeAuditError("E_RECEIPT_LANES", "recognized lane state required")
        ids.add(identity)
        kinds.add(kind)
