"""CLI coverage for the approachable RevenueForge command family."""
from __future__ import annotations

from pathlib import Path
import json
import subprocess
import sys

import yaml


def test_revenue_validate_and_build_cli(tmp_path: Path) -> None:
    """Validate and build a local bundle through the shipped CLI."""
    manifest = {"app": {"name": "Example", "bundle_id": "com.example.app"}, "products": [{"id": "com.example.monthly", "display_name": "Pro", "type": "auto_renewable", "duration": "P1M", "group": "main", "entitlements": ["pro"]}], "paywall": {"value_before_price": True, "price_and_duration_before_cta": True, "single_primary_cta": True, "restore_purchases": True, "patterns": []}, "legal": {"privacy_policy_url": "https://example.com/privacy", "terms_url": "https://example.com/terms"}, "privacy": {"purchase_history_linked": True, "purpose": "app_functionality"}}
    (tmp_path / "products.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    validate = subprocess.run([sys.executable, "-m", "factoryline.cli", "revenue", "validate", "--root", str(tmp_path), "--products", "products.yaml", "--json"], capture_output=True, text=True, check=False)
    assert validate.returncode == 0, validate.stderr
    assert json.loads(validate.stdout)["marker"] == "REVENUEFORGE_MANIFEST_VALIDATED"
    build = subprocess.run([sys.executable, "-m", "factoryline.cli", "revenue", "build", "--root", str(tmp_path), "--products", "products.yaml", "--json"], capture_output=True, text=True, check=False)
    assert build.returncode == 0, build.stderr
    assert json.loads(build.stdout)["marker"] == "REVENUEFORGE_BUNDLE_WRITTEN"


def test_revenue_evidence_cli_commands(tmp_path: Path) -> None:
    manifest = {"app": {"name": "Example", "bundle_id": "com.example.app"}, "products": [{"id": "com.example.monthly", "display_name": "Pro", "type": "auto_renewable", "duration": "P1M", "group": "main", "entitlements": ["pro"]}], "paywall": {"value_before_price": True, "price_and_duration_before_cta": True, "single_primary_cta": True, "restore_purchases": True, "patterns": []}, "legal": {"privacy_policy_url": "https://example.com/privacy", "terms_url": "https://example.com/terms"}, "privacy": {"purchase_history_linked": True, "purpose": "app_functionality"}}
    (tmp_path / "products.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    events = {"build": {"id": "1", "bundle_id": "com.example.app", "environment": "sandbox"}, "events": [{"id": "e1", "sequence": 1, "type": "paywall_presented"}]}
    (tmp_path / "events.json").write_text(json.dumps(events), encoding="utf-8")
    replay = subprocess.run([sys.executable, "-m", "factoryline.cli", "revenue", "replay", "--root", str(tmp_path), "--products", "products.yaml", "--events", "events.json", "--json"], capture_output=True, text=True, check=False)
    assert replay.returncode == 0, replay.stderr
    assert json.loads(replay.stdout)["verdict"] == "blocked"
    feedback = {"items": [{"id": "f1", "build_id": "1", "kind": "feedback", "summary": "Restore failed"}]}
    (tmp_path / "feedback.json").write_text(json.dumps(feedback), encoding="utf-8")
    sync = subprocess.run([sys.executable, "-m", "factoryline.cli", "revenue", "testflight-sync", "--root", str(tmp_path), "--feedback", "feedback.json", "--json"], capture_output=True, text=True, check=False)
    assert sync.returncode == 0, sync.stderr
    assert json.loads(sync.stdout)["marker"] == "REVENUEFORGE_TESTFLIGHT_EVIDENCE_SYNCED"
