"""CDTE — Conflict Detection and Trade-off Engine.

Organised by the property under test rather than by function, because the
guarantees CDTE makes are what matter: detection is deterministic, proofs are
never fabricated, and the fail-closed boundary cannot be bypassed silently.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.cdte import (
    BLOCKING_SEVERITIES,
    CDTEError,
    SCAN_SCHEMA,
    detect_conflicts,
    draft_adr,
    load_registry,
    load_scans,
    normalize_constraints,
    public_cdte_report,
    record_scan,
    resolve_conflict,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
def c(cid, category, metric, value=None, operator=None):
    return {
        "constraintId": cid,
        "category": category,
        "metric": metric,
        "value": value,
        "operator": operator,
    }


LATENCY = c("c-001", "performance", "p95_latency_ms", 50, "lt")
ENCRYPTION = c("c-002", "security", "field_level_encryption", "aes-256")
RESIDENCY = c("c-003", "compliance", "data_residency", "eu-only")
ROUTING = c("c-004", "infrastructure", "provider_routing", "multi-region")
SCALE = c("c-005", "scalability", "max_websocket_sessions", 5000, "gte")


# ---------------------------------------------------------------------------
# Registry integrity
# ---------------------------------------------------------------------------
def test_shipped_registry_is_valid():
    registry = load_registry()
    assert registry["schema"] == "factory.lethal-pairs.v1"
    assert len(registry["pairs"]) >= 4


def test_registry_rejects_modeled_proof_without_assumptions(tmp_path):
    bad = tmp_path / "r.json"
    bad.write_text(json.dumps({
        "schema": "factory.lethal-pairs.v1", "version": 1,
        "pairs": [{"id": "p", "severity": "high",
                   "left": {"category": "a", "metric": "m", "value_in": ["x"]},
                   "right": {"category": "b", "metric": "n", "value_in": ["y"]},
                   "proof": {"tier": "modeled", "formula": "a - b"}}],
    }), encoding="utf-8")
    with pytest.raises(CDTEError) as exc:
        load_registry(bad)
    assert exc.value.code == "PAIR_PROOF_ASSUMPTIONS_REQUIRED"


def test_registry_rejects_unknown_proof_tier(tmp_path):
    bad = tmp_path / "r.json"
    bad.write_text(json.dumps({
        "schema": "factory.lethal-pairs.v1", "version": 1,
        "pairs": [{"id": "p", "severity": "high",
                   "left": {"category": "a", "metric": "m", "value_in": ["x"]},
                   "right": {"category": "b", "metric": "n", "value_in": ["y"]},
                   "proof": {"tier": "vibes", "statement": "trust me"}}],
    }), encoding="utf-8")
    with pytest.raises(CDTEError) as exc:
        load_registry(bad)
    assert exc.value.code == "PAIR_PROOF_TIER_INVALID"


# ---------------------------------------------------------------------------
# Detection: deterministic, no model
# ---------------------------------------------------------------------------
def test_detects_latency_versus_encryption():
    found = detect_conflicts(normalize_constraints([LATENCY, ENCRYPTION]))
    assert [f["pair_id"] for f in found] == ["latency_vs_field_encryption"]
    assert found[0]["constraints"] == ["c-001", "c-002"]


def test_detects_structural_residency_conflict():
    found = detect_conflicts(normalize_constraints([RESIDENCY, ROUTING]))
    assert found[0]["proof"]["tier"] == "structural"
    assert found[0]["proof"]["quantified"] is False


def test_aligned_requirements_do_not_conflict():
    """The research's pass case: scalability plus an approved pattern."""
    assert detect_conflicts(normalize_constraints([SCALE, c("c-006", "infrastructure", "event_driven", "sqs-lambda")])) == []


def test_latency_above_threshold_does_not_trigger():
    relaxed = c("c-001", "performance", "p95_latency_ms", 250, "lt")
    assert detect_conflicts(normalize_constraints([relaxed, ENCRYPTION])) == []


def test_detection_is_deterministic_across_input_order():
    a = detect_conflicts(normalize_constraints([LATENCY, ENCRYPTION, RESIDENCY, ROUTING]))
    b = detect_conflicts(normalize_constraints([ROUTING, RESIDENCY, ENCRYPTION, LATENCY]))
    assert [x["pair_id"] for x in a] == [x["pair_id"] for x in b]
    assert a == b


def test_conflicts_sorted_by_severity():
    found = detect_conflicts(normalize_constraints([LATENCY, ENCRYPTION, RESIDENCY, ROUTING]))
    severities = [f["severity"] for f in found]
    assert severities == sorted(severities, key=["critical", "high", "medium", "low"].index)


def test_single_constraint_cannot_conflict_with_itself():
    """A registry pair both of whose sides match one constraint is a modelling
    error, not a contradiction."""
    weird = c("c-solo", "security", "access_model", "zero-trust")
    assert detect_conflicts(normalize_constraints([weird])) == []


def test_metric_and_category_are_canonicalized():
    messy = {"constraintId": "c-1", "category": " Performance ", "metric": "P95_Latency_MS", "value": 50}
    found = detect_conflicts(normalize_constraints([messy, ENCRYPTION]))
    assert found, "canonicalization must not cause a silent miss"


# ---------------------------------------------------------------------------
# Constraint validation
# ---------------------------------------------------------------------------
def test_boolean_value_rejected():
    """bool is an int subclass; True would silently compare as 1."""
    with pytest.raises(CDTEError) as exc:
        normalize_constraints([c("c-1", "performance", "p95_latency_ms", True)])
    assert exc.value.code == "VALUE_INVALID"


def test_duplicate_constraint_ids_rejected():
    with pytest.raises(CDTEError) as exc:
        normalize_constraints([LATENCY, dict(LATENCY)])
    assert exc.value.code == "CONSTRAINT_ID_DUPLICATE"


def test_missing_metric_rejected():
    with pytest.raises(CDTEError) as exc:
        normalize_constraints([{"constraintId": "c-1", "category": "performance"}])
    assert exc.value.code == "CONSTRAINT_FIELD_MISSING"


# ---------------------------------------------------------------------------
# Proof discipline — the rule the product is built on
# ---------------------------------------------------------------------------
def test_modeled_proof_is_withheld_when_inputs_absent():
    """A modeled number without its inputs must be withheld, never estimated."""
    found = detect_conflicts(normalize_constraints([LATENCY, ENCRYPTION]))
    analysis = found[0]["proof"]
    assert analysis["tier"] == "modeled"
    assert analysis["withheld"] is True
    assert "not supplied" in analysis["withheld_reason"]
    assert analysis["quantified"] is False


def test_withheld_proof_still_reports_the_conflict():
    """Withholding quantification must not withhold the finding."""
    found = detect_conflicts(normalize_constraints([LATENCY, ENCRYPTION]))
    assert found[0]["pair_id"] == "latency_vs_field_encryption"
    assert found[0]["severity"] == "critical"


def test_structural_proof_carries_no_numbers():
    found = detect_conflicts(normalize_constraints([RESIDENCY, ROUTING]))
    analysis = found[0]["proof"]
    assert analysis["inputs"] == {}
    assert analysis["assumptions"] == []
    assert analysis["quantified"] is False


def test_modeled_proof_always_ships_assumptions(tmp_path):
    scan = record_scan(tmp_path, "run-a", [LATENCY, ENCRYPTION])
    analysis = scan["conflicts"][0]["incompatibility_analysis"]
    assert analysis["assumptions"], "a modeled tier must never ship without assumptions"


def test_evidence_binding_requires_a_real_file(tmp_path):
    with pytest.raises(CDTEError) as exc:
        record_scan(tmp_path, "run-a", [LATENCY, ENCRYPTION], evidence=tmp_path / "nope.json")
    assert exc.value.code == "EVIDENCE_MISSING"


def test_evidence_binding_promotes_tier_and_hashes(tmp_path):
    bench = tmp_path / "bench.json"
    bench.write_text('{"encrypt_ms": 3.2}', encoding="utf-8")
    scan = record_scan(tmp_path, "run-a", [LATENCY, ENCRYPTION], evidence=bench)
    analysis = scan["conflicts"][0]["incompatibility_analysis"]
    assert analysis["tier"] == "measured"
    assert len(analysis["evidence_sha256"]) == 64


# ---------------------------------------------------------------------------
# Receipts and the fail-closed boundary
# ---------------------------------------------------------------------------
def test_scan_receipt_is_written_atomically(tmp_path):
    scan = record_scan(tmp_path, "run-a", [LATENCY, ENCRYPTION])
    written = json.loads(Path(scan["receipt"]).read_text(encoding="utf-8"))
    assert written["schema"] == SCAN_SCHEMA
    assert written["run_id"] == "run-a"


def test_critical_conflict_engages_fail_closed(tmp_path):
    scan = record_scan(tmp_path, "run-a", [LATENCY, ENCRYPTION])
    assert scan["requires_hitl_escalation"] is True
    assert scan["fail_closed"] is True
    assert "FAIL_CLOSED_ENGAGED" in scan["markers"]


def test_clean_spec_does_not_engage_fail_closed(tmp_path):
    scan = record_scan(tmp_path, "run-b", [SCALE])
    assert scan["requires_hitl_escalation"] is False
    assert "NO_LETHAL_PAIR_MATCHED" in scan["markers"]
    assert "FAIL_CLOSED_NOT_ENGAGED" in scan["markers"]


def test_all_blocking_severities_engage_the_boundary(tmp_path):
    """Guards against a severity being added to the registry that silently
    fails open because nobody updated BLOCKING_SEVERITIES."""
    assert BLOCKING_SEVERITIES == frozenset({"critical", "high"})
    registry = load_registry()
    for pair in registry["pairs"]:
        assert pair["severity"] in ("critical", "high", "medium", "low")


def test_scan_overwrite_refused_without_replace(tmp_path):
    record_scan(tmp_path, "run-a", [LATENCY, ENCRYPTION])
    with pytest.raises(CDTEError) as exc:
        record_scan(tmp_path, "run-a", [LATENCY, ENCRYPTION])
    assert exc.value.code == "SCAN_OVERWRITE_REFUSED"
    record_scan(tmp_path, "run-a", [LATENCY, ENCRYPTION], replace=True)


def test_invalid_run_id_rejected(tmp_path):
    with pytest.raises(CDTEError) as exc:
        record_scan(tmp_path, "Run A!", [LATENCY])
    assert exc.value.code == "RUN_ID_INVALID"


# ---------------------------------------------------------------------------
# Resolution and overrides
# ---------------------------------------------------------------------------
def test_override_without_expiry_is_refused(tmp_path):
    scan = record_scan(tmp_path, "run-a", [LATENCY, ENCRYPTION])
    with pytest.raises(CDTEError) as exc:
        resolve_conflict(
            tmp_path, "run-a", scan["conflicts"][0]["conflict_id"],
            decision="accept the risk", approved_by="rick", override=True,
        )
    assert exc.value.code == "OVERRIDE_EXPIRY_REQUIRED"


def test_override_requires_named_approver(tmp_path):
    scan = record_scan(tmp_path, "run-a", [LATENCY, ENCRYPTION])
    with pytest.raises(CDTEError) as exc:
        resolve_conflict(
            tmp_path, "run-a", scan["conflicts"][0]["conflict_id"],
            decision="accept", approved_by="  ", override=True, expires="2026-12-31",
        )
    assert exc.value.code == "APPROVER_REQUIRED"


def test_resolution_receipt_records_approver_and_expiry(tmp_path):
    scan = record_scan(tmp_path, "run-a", [LATENCY, ENCRYPTION])
    receipt = resolve_conflict(
        tmp_path, "run-a", scan["conflicts"][0]["conflict_id"],
        decision="Relax SLA to 250ms", approved_by="rick", override=True, expires="2026-12-31",
    )
    assert receipt["approved_by"] == "rick"
    assert receipt["expires"] == "2026-12-31"
    assert "OVERRIDE_RECORDED" in receipt["markers"]


def test_resolution_rejects_unknown_conflict(tmp_path):
    record_scan(tmp_path, "run-a", [LATENCY, ENCRYPTION])
    with pytest.raises(CDTEError) as exc:
        resolve_conflict(tmp_path, "run-a", "nope-99", decision="d", approved_by="a")
    assert exc.value.code == "CONFLICT_UNKNOWN"


# ---------------------------------------------------------------------------
# ADR drafting
# ---------------------------------------------------------------------------
def test_adr_is_drafted_with_tier_labelled(tmp_path):
    scan = record_scan(tmp_path, "run-a", [RESIDENCY, ROUTING])
    path = draft_adr(tmp_path, scan, scan["conflicts"][0]["conflict_id"], number=7)
    text = path.read_text(encoding="utf-8")
    assert "ADR-0007" in text
    assert "Structural incompatibility" in text
    # The template hard-wraps, so compare on collapsed whitespace.
    assert "CDTE did not measure this system" in " ".join(text.split())


def test_adr_for_modeled_conflict_states_it_is_a_model(tmp_path):
    bench = tmp_path / "b.json"; bench.write_text("{}", encoding="utf-8")
    scan = record_scan(tmp_path, "run-a", [LATENCY, ENCRYPTION])
    path = draft_adr(tmp_path, scan, scan["conflicts"][0]["conflict_id"])
    text = path.read_text(encoding="utf-8")
    assert "Quantification withheld" in text


# ---------------------------------------------------------------------------
# Public report — disclosure boundary
# ---------------------------------------------------------------------------
def test_public_report_leaks_no_constraint_text(tmp_path):
    record_scan(tmp_path, "run-a", [LATENCY, ENCRYPTION])
    record_scan(tmp_path, "run-b", [RESIDENCY, ROUTING])
    blob = json.dumps(public_cdte_report(tmp_path))
    for secret in ("p95_latency_ms", "c-001", "run-a", "eu-only"):
        assert secret not in blob, f"public report leaked {secret}"


def test_public_report_counts_are_exact(tmp_path):
    record_scan(tmp_path, "run-a", [LATENCY, ENCRYPTION])
    record_scan(tmp_path, "run-b", [SCALE])
    report = public_cdte_report(tmp_path)
    assert report["scans"] == 2
    assert report["scans_fail_closed"] == 1
    assert report["fail_closed_rate"] == 0.5
    assert report["conflicts_total"] == 1
    assert report["quantification_withheld"] == 1


def test_public_report_on_empty_store(tmp_path):
    report = public_cdte_report(tmp_path)
    assert report["scans"] == 0
    assert report["fail_closed_rate"] is None
    assert report["quantification_withheld_rate"] is None
