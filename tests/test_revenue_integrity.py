"""Tests for the deterministic RevenueForge integrity control plane."""
from __future__ import annotations

from pathlib import Path
import hashlib
import json

import pytest
import yaml

from factoryline.revenue_integrity import (
    evaluate_revenue_integrity,
    plan_revenue_experiment,
    reconcile_billing_events,
    revenue_integrity_projection,
)
from factoryline.revenueforge import RevenueForgeError


def _manifest() -> dict:
    """Return a valid monetization manifest."""
    return {
        "app": {"name": "Example", "bundle_id": "com.example.app"},
        "products": [{"id": "com.example.pro.monthly", "display_name": "Pro", "type": "auto_renewable", "duration": "P1M", "group": "pro", "entitlements": ["pro"]}],
        "paywall": {"value_before_price": True, "price_and_duration_before_cta": True, "single_primary_cta": True, "restore_purchases": True, "patterns": []},
        "legal": {"privacy_policy_url": "https://example.com/privacy", "terms_url": "https://example.com/terms"},
        "privacy": {"purchase_history_linked": True, "purpose": "app_functionality"},
    }


def _write_yaml(path: Path, value: dict) -> Path:
    """Write a YAML fixture."""
    path.write_text(yaml.safe_dump(value, sort_keys=True), encoding="utf-8")
    return path


def _write_json(path: Path, value: object) -> Path:
    """Write a JSON fixture."""
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _events(*, conflict: bool = False, refund: bool = False) -> dict:
    """Build verified, build-bound billing observations."""
    events = [
        {"event_id": "purchase-1", "provider": "app_store", "transaction_id": "tx-1", "event_type": "purchase", "product_id": "com.example.pro.monthly", "entitlement": "pro", "occurred_at": "2026-09-13T12:00:00Z", "verified": True},
        {"event_id": "purchase-1-retry", "provider": "app_store", "transaction_id": "tx-1", "event_type": "purchase", "product_id": "com.example.pro.monthly", "entitlement": "pro", "occurred_at": "2026-09-13T12:00:00Z", "verified": True},
    ]
    if conflict:
        events[1]["product_id"] = "com.example.other"
    if refund:
        events.append({"event_id": "refund-1", "provider": "app_store", "transaction_id": "tx-1", "event_type": "refund", "product_id": "com.example.pro.monthly", "entitlement": "pro", "occurred_at": "2026-09-14T12:00:00Z", "verified": True})
    return {"build": {"id": "build-42", "bundle_id": "com.example.app", "environment": "testflight"}, "events": events}


def test_reconcile_collapses_retry_and_revokes_refund(tmp_path: Path) -> None:
    """Collapse an exact retry and apply a refund transition deterministically."""
    products = _write_yaml(tmp_path / "products.yaml", _manifest())
    events = _write_json(tmp_path / "events.json", _events(refund=True))
    result = reconcile_billing_events(tmp_path, products, events, Path(".factory/revenueforge/default/billing-ledger.json"))
    assert result["marker"] == "REVENUEFORGE_BILLING_RECONCILED"
    assert result["verdict"] == "PASS"
    assert result["summary"]["duplicates"] == 1
    assert result["grant_candidates"] == []
    assert result["entitlement_states"][0]["state"] == "inactive"
    assert all(value is False for value in result["authority"].values())


def test_reconcile_conflict_emits_no_grant(tmp_path: Path) -> None:
    """Block a conflicting idempotency retry and suppress grant candidates."""
    value = _manifest()
    value["products"].append({"id": "com.example.team.monthly", "display_name": "Team", "type": "auto_renewable", "duration": "P1M", "group": "team", "entitlements": ["team"]})
    products = _write_yaml(tmp_path / "products.yaml", value)
    events_value = _events()
    events_value["events"][1]["product_id"] = "com.example.team.monthly"
    events_value["events"][1]["entitlement"] = "team"
    events = _write_json(tmp_path / "events.json", events_value)
    result = reconcile_billing_events(tmp_path, products, events, Path("ledger.json"))
    assert result["marker"] == "REVENUEFORGE_BILLING_CONFLICT"
    assert result["grant_candidates"] == []
    assert result["conflicts"][0]["type"] == "idempotency_conflict"


def test_reconcile_transaction_product_conflict(tmp_path: Path) -> None:
    """Block one transaction id observed for different declared products."""
    value = _manifest()
    value["products"].append({"id": "com.example.team.monthly", "display_name": "Team", "type": "auto_renewable", "duration": "P1M", "group": "team", "entitlements": ["team"]})
    products = _write_yaml(tmp_path / "products.yaml", value)
    events_value = _events()
    events_value["events"][1]["event_id"] = "other-event"
    events_value["events"][1]["occurred_at"] = "2026-09-14T12:00:00Z"
    events_value["events"][1]["product_id"] = "com.example.team.monthly"
    events_value["events"][1]["entitlement"] = "team"
    events = _write_json(tmp_path / "events.json", events_value)
    result = reconcile_billing_events(tmp_path, products, events, Path("ledger.json"))
    assert result["marker"] == "REVENUEFORGE_BILLING_CONFLICT"
    assert result["grant_candidates"] == []
    assert result["conflicts"][0]["type"] == "transaction_product_conflict"


def _experiment(approved: bool = False) -> dict:
    """Return a valid experiment input."""
    value = {
        "id": "paywall-copy-v1",
        "proposed_by": "agent-1",
        "provenance": "agent_proposed",
        "hypothesis": "Clearer benefit-first copy improves purchase conversion without raising refunds.",
        "primary_metric": "purchase_conversion",
        "treatments": [{"id": "control", "role": "control", "product_ids": ["com.example.pro.monthly"], "label": "Current"}, {"id": "variant", "role": "variant", "product_ids": ["com.example.monthly"], "label": "Benefit first"}],
        "guardrails": [{"metric": "refund_rate", "operator": "lte", "threshold": 0.05}],
        "cohort": {"name": "new_subscribers", "allocation_percent": 50},
        "window_days": 14,
        "minimum_sample_size": 100,
    }
    value["treatments"][1]["product_ids"] = ["com.example.pro.monthly"]
    if approved:
        approved_at = "2026-09-13T12:00:00Z"
        value["approval"] = {"approved_by": "human-1", "decision": "approved", "approved_at": approved_at, "approval_sha256": hashlib.sha256(json.dumps({"approved_by": "human-1", "approved_at": approved_at, "experiment_id": value["id"]}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
    return value


def test_experiment_requires_separate_approval(tmp_path: Path) -> None:
    """Keep agent-proposed experiments non-startable until approved."""
    products = _write_yaml(tmp_path / "products.yaml", _manifest())
    experiment = _write_json(tmp_path / "experiment.json", _experiment())
    result = plan_revenue_experiment(tmp_path, products, experiment, Path(".factory/revenueforge/default/experiment-plan.json"))
    assert result["status"] == "AWAITING_HUMAN_APPROVAL"
    assert result["next_action"] == "obtain_independent_human_approval"
    assert result["receipt_sha256"]
    assert all(value is False for value in result["authority"].values())


def test_approved_experiment_is_ready_but_not_started(tmp_path: Path) -> None:
    """Allow a separately approved plan to reach a human-start boundary only."""
    products = _write_yaml(tmp_path / "products.yaml", _manifest())
    experiment = _write_json(tmp_path / "experiment.json", _experiment(approved=True))
    result = plan_revenue_experiment(tmp_path, products, experiment, Path("plan.json"))
    assert result["status"] == "READY_FOR_HUMAN_START"
    assert result["authority"]["experiment_start"] is False


def test_experiment_rejects_price_or_winner_instruction(tmp_path: Path) -> None:
    """Reject agent attempts to turn planning into a provider mutation."""
    products = _write_yaml(tmp_path / "products.yaml", _manifest())
    value = _experiment()
    value["winner"] = "variant"
    with pytest.raises(RevenueForgeError) as error:
        plan_revenue_experiment(tmp_path, products, _write_json(tmp_path / "experiment.json", value), Path("plan.json"))
    assert error.value.code == "REVENUEFORGE_EXPERIMENT_AUTHORITY_REJECTED"


def test_integrity_evaluation_surfaces_manifest_drift_and_projection(tmp_path: Path) -> None:
    """Bind a ledger to its manifest and project integrity receipts read-only."""
    products = _write_yaml(tmp_path / "products.yaml", _manifest())
    events = _write_json(tmp_path / "events.json", _events())
    ledger = reconcile_billing_events(tmp_path, products, events, Path(".factory/revenueforge/default/billing-ledger.json"))
    baseline = _write_json(tmp_path / "baseline.json", {"manifest_sha256": "f" * 64})
    result = evaluate_revenue_integrity(tmp_path, products, Path(ledger["path"]), baseline_path=baseline, out=Path(".factory/revenueforge/default/integrity.json"))
    assert result["decision"] == "REVIEW_REQUIRED"
    assert result["next_action"] == "human_manifest_reassessment"
    projection = revenue_integrity_projection(tmp_path)
    assert projection["counts"]["ledger"] == 1
    assert projection["counts"]["integrity"] == 1


def test_integrity_rejects_tampered_ledger(tmp_path: Path) -> None:
    """Reject a ledger whose canonical receipt digest no longer matches."""
    products = _write_yaml(tmp_path / "products.yaml", _manifest())
    events = _write_json(tmp_path / "events.json", _events())
    ledger = reconcile_billing_events(tmp_path, products, events, Path("ledger.json"))
    path = tmp_path / ledger["path"]
    value = json.loads(path.read_text(encoding="utf-8"))
    value["grant_candidates"] = [{"product_id": "forged"}]
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(RevenueForgeError, match="receipt hash or schema"):
        evaluate_revenue_integrity(tmp_path, products, Path(ledger["path"]))
