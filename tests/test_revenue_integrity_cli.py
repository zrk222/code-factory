"""CLI tests for RevenueForge integrity controls."""
from __future__ import annotations

from pathlib import Path
import json
import subprocess
import sys

import yaml


def test_revenue_integrity_cli_commands(tmp_path: Path) -> None:
    """Run billing, experiment, and integrity commands through the public CLI."""
    manifest = {"app": {"name": "Example", "bundle_id": "com.example.app"}, "products": [{"id": "com.example.pro.monthly", "display_name": "Pro", "type": "auto_renewable", "duration": "P1M", "group": "pro", "entitlements": ["pro"]}], "paywall": {"value_before_price": True, "price_and_duration_before_cta": True, "single_primary_cta": True, "restore_purchases": True, "patterns": []}, "legal": {"privacy_policy_url": "https://example.com/privacy", "terms_url": "https://example.com/terms"}, "privacy": {"purchase_history_linked": True, "purpose": "app_functionality"}}
    (tmp_path / "products.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    events = {"build": {"id": "42", "bundle_id": "com.example.app", "environment": "sandbox"}, "events": [{"event_id": "e1", "provider": "app_store", "transaction_id": "tx", "event_type": "purchase", "product_id": "com.example.pro.monthly", "entitlement": "pro", "occurred_at": "2026-09-13T12:00:00Z", "verified": True}]}
    (tmp_path / "events.json").write_text(json.dumps(events), encoding="utf-8")
    billing = subprocess.run([sys.executable, "-m", "factoryline.cli", "revenue", "billing-reconcile", "--root", str(tmp_path), "--products", "products.yaml", "--events", "events.json", "--json"], capture_output=True, text=True, check=False)
    assert billing.returncode == 0, billing.stderr
    ledger = json.loads(billing.stdout)
    assert ledger["marker"] == "REVENUEFORGE_BILLING_RECONCILED"
    experiment = {"id": "x", "proposed_by": "agent", "hypothesis": "test", "primary_metric": "purchase_conversion", "treatments": [{"id": "control", "role": "control", "product_ids": ["com.example.pro.monthly"]}, {"id": "variant", "role": "variant", "product_ids": ["com.example.pro.monthly"]}], "guardrails": [{"metric": "refund_rate", "operator": "lte", "threshold": 0.05}], "cohort": {"name": "new", "allocation_percent": 50}, "window_days": 7, "minimum_sample_size": 20}
    (tmp_path / "experiment.json").write_text(json.dumps(experiment), encoding="utf-8")
    planned = subprocess.run([sys.executable, "-m", "factoryline.cli", "revenue", "experiment-plan", "--root", str(tmp_path), "--products", "products.yaml", "--experiment", "experiment.json", "--json"], capture_output=True, text=True, check=False)
    assert planned.returncode == 0, planned.stderr
    assert json.loads(planned.stdout)["status"] == "AWAITING_HUMAN_APPROVAL"
    integrity = subprocess.run([sys.executable, "-m", "factoryline.cli", "revenue", "integrity", "--root", str(tmp_path), "--products", "products.yaml", "--ledger", ledger["path"], "--json"], capture_output=True, text=True, check=False)
    assert integrity.returncode == 0, integrity.stderr
    assert json.loads(integrity.stdout)["decision"] == "READY_FOR_HUMAN_REVIEW"
