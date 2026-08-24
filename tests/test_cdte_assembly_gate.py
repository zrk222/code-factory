"""Integration: the CDTE gate inside the assembly line.

These exercise `_cdte_gate` directly. Without them the gate's import and regex
paths are never executed by the suite, and a NameError would ship silently.
"""
from __future__ import annotations

import json

from factoryline.assembly import _cdte_gate
from factoryline.continuation import _next_action


def _write(root, feature, constraints):
    (root / "specs").mkdir(parents=True, exist_ok=True)
    (root / "specs" / f"{feature}.nfr.json").write_text(
        json.dumps({"constraints": constraints}), encoding="utf-8"
    )


CONFLICTING = [
    {"constraintId": "c-001", "category": "performance", "metric": "p95_latency_ms", "value": 50, "operator": "lt"},
    {"constraintId": "c-002", "category": "security", "metric": "field_level_encryption", "value": "aes-256"},
]
CLEAN = [
    {"constraintId": "c-001", "category": "scalability", "metric": "max_websocket_sessions", "value": 5000, "operator": "gte"},
]


def test_gate_is_skipped_when_no_constraints_file(tmp_path):
    """Additive by design: existing repos keep working untouched."""
    assert _cdte_gate(tmp_path, "checkout") is None


def test_gate_blocks_on_a_critical_conflict(tmp_path):
    _write(tmp_path, "checkout", CONFLICTING)
    outcome = _cdte_gate(tmp_path, "checkout")
    assert outcome["blocking"] is True
    assert outcome["stage"]["status"] == "blocked"
    assert outcome["stage"]["marker"] == "FAIL_CLOSED_ENGAGED"
    assert outcome["summary"]["requires_hitl_escalation"] is True


def test_gate_passes_a_clean_spec(tmp_path):
    _write(tmp_path, "checkout", CLEAN)
    outcome = _cdte_gate(tmp_path, "checkout")
    assert outcome["blocking"] is False
    assert outcome["stage"]["status"] == "ok"
    assert outcome["summary"]["conflicts"] == []


def test_gate_degrades_gracefully_on_unreadable_constraints(tmp_path):
    """A broken constraints file must not halt the line with a stack trace."""
    (tmp_path / "specs").mkdir(parents=True)
    (tmp_path / "specs" / "checkout.nfr.json").write_text("{not json", encoding="utf-8")
    outcome = _cdte_gate(tmp_path, "checkout")
    assert outcome["blocking"] is False
    assert outcome["stage"]["status"] == "skipped"


def test_gate_degrades_on_malformed_constraints(tmp_path):
    _write(tmp_path, "checkout", [{"category": "performance"}])  # no metric
    outcome = _cdte_gate(tmp_path, "checkout")
    assert outcome["stage"]["status"] == "skipped"
    assert "CONSTRAINT_FIELD_MISSING" in outcome["stage"]["reason"]


def test_feature_names_are_sanitized_into_run_ids(tmp_path):
    """Feature names allow characters a run id does not; the gate must not
    raise RUN_ID_INVALID on a legitimate feature name."""
    _write(tmp_path, "Checkout API v2", CONFLICTING)
    outcome = _cdte_gate(tmp_path, "Checkout API v2")
    assert outcome["blocking"] is True
    assert outcome["summary"]["run_id"] == "checkout-api-v2"


def test_gate_is_rerunnable(tmp_path):
    """Assembly reruns constantly; the gate must not refuse its own receipt."""
    _write(tmp_path, "checkout", CONFLICTING)
    first = _cdte_gate(tmp_path, "checkout")
    second = _cdte_gate(tmp_path, "checkout")
    assert first["summary"]["conflicts"] == second["summary"]["conflicts"]


def test_continuation_offers_a_resolve_command(tmp_path):
    action = _next_action("nfr_conflict", "checkout")
    assert action["kind"] == "command"
    assert "cdte resolve" in action["command"]
    assert action["requires_human"] is True
