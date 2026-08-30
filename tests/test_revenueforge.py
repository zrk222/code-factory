"""Deterministic coverage for RevenueForge generation and authority boundaries."""
from __future__ import annotations

from pathlib import Path
import json

import pytest
import yaml

from factoryline.revenueforge import (
    RevenueForgeError,
    benchmark_cell,
    build_revenue_bundle,
    plan_growth,
    revenueforge_projection,
    validate_products,
)
from factoryline.revenue_evidence import (
    FAILURE_SCENARIOS,
    evaluate_failure_matrix,
    promote_evidence_memory,
    query_evidence_memory,
    replay_purchase_journey,
    sync_testflight_evidence,
    watch_policy_drift,
)


def manifest() -> dict:
    """Return one complete products manifest."""
    return {
        "app": {"name": "Example", "bundle_id": "com.example.app"},
        "products": [{"id": "com.example.pro.monthly", "display_name": "Pro", "type": "auto_renewable", "duration": "P1M", "group": "pro", "entitlements": ["pro"], "offers": [{"id": "trial", "type": "free_trial", "duration": "P1W"}]}],
        "paywall": {"value_before_price": True, "price_and_duration_before_cta": True, "single_primary_cta": True, "restore_purchases": True, "patterns": []},
        "legal": {"privacy_policy_url": "https://example.com/privacy", "terms_url": "https://example.com/terms"},
        "privacy": {"purchase_history_linked": True, "purpose": "app_functionality"},
    }


def write_yaml(path: Path, value: dict) -> Path:
    """Write test YAML and return its path."""
    path.write_text(yaml.safe_dump(value, sort_keys=True), encoding="utf-8")
    return path


def write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    return path


def test_validate_and_build_full_bundle(tmp_path: Path) -> None:
    """Generate every requested local artifact from one valid manifest."""
    source = write_yaml(tmp_path / "products.yaml", manifest())
    validated = validate_products(tmp_path, source)
    assert validated["marker"] == "REVENUEFORGE_MANIFEST_VALIDATED"
    assert validated["ok"] is True
    receipt = build_revenue_bundle(tmp_path, source, Path(".factory/revenueforge/example"))
    assert receipt["marker"] == "REVENUEFORGE_BUNDLE_WRITTEN"
    for relative in receipt["artifacts"].values():
        assert (tmp_path / relative).is_file()
    swift = (tmp_path / receipt["artifacts"]["revenuekit"]).read_text(encoding="utf-8")
    server = (tmp_path / receipt["artifacts"]["server"]).read_text(encoding="utf-8")
    paywall = (tmp_path / receipt["artifacts"]["paywall"]).read_text(encoding="utf-8")
    assert "Transaction.currentEntitlements" in swift
    assert ".pending" in swift
    assert "verifyAndDecodeNotification" in server
    assert server.index("verifyAndDecodeNotification") < server.index("entitlementTransition")
    assert "Restore Purchases" in paywall
    assert "Privacy Policy" in paywall and "Terms of Use" in paywall


@pytest.mark.parametrize("pattern", ["countdown", "false_scarcity", "hidden_cancel", "preselected_upsell"])
def test_dark_patterns_fail_closed(tmp_path: Path, pattern: str) -> None:
    """Reject each explicitly forbidden paywall manipulation."""
    value = manifest()
    value["paywall"]["patterns"] = [pattern]
    with pytest.raises(RevenueForgeError, match="dark-pattern") as error:
        validate_products(tmp_path, write_yaml(tmp_path / "products.yaml", value))
    assert error.value.code == "REVENUEFORGE_DARK_PATTERN_REJECTED"


def test_missing_restore_blocks_generation(tmp_path: Path) -> None:
    """Withhold the bundle when restore purchases is not declared."""
    value = manifest()
    value["paywall"]["restore_purchases"] = False
    source = write_yaml(tmp_path / "products.yaml", value)
    assert validate_products(tmp_path, source)["ok"] is False
    with pytest.raises(RevenueForgeError) as error:
        build_revenue_bundle(tmp_path, source, Path("out"))
    assert error.value.code == "REVENUEFORGE_GATES_BLOCKED"


def test_duplicate_product_id_is_rejected(tmp_path: Path) -> None:
    """Reject ambiguous duplicate product identifiers."""
    value = manifest()
    value["products"].append(dict(value["products"][0]))
    with pytest.raises(RevenueForgeError) as error:
        validate_products(tmp_path, write_yaml(tmp_path / "products.yaml", value))
    assert error.value.code == "REVENUEFORGE_MANIFEST_INVALID"


def test_phase8_is_bounded_and_human_governed(tmp_path: Path) -> None:
    """Compile at most three PPO treatments and lock consequential actions."""
    products = write_yaml(tmp_path / "products.yaml", manifest())
    growth = write_yaml(tmp_path / "growth.yaml", {"experiments": [{"id": "hero", "treatments": [{"id": "a"}, {"id": "b"}, {"id": "c"}]}], "offers": [{"id": "return"}], "custom_product_pages": [{"id": "teams"}]})
    result = plan_growth(tmp_path, products, growth)
    assert result["marker"] == "REVENUEFORGE_PHASE8_PLANNED"
    assert result["experiments"][0]["promotion"] == "human_required"
    assert result["offers"][0]["send"] == "human_required"
    assert all(value is False for value in result["authority"].values())


def test_four_ppo_treatments_are_rejected(tmp_path: Path) -> None:
    """Reject experiments beyond Apple's three-treatment bound."""
    products = write_yaml(tmp_path / "products.yaml", manifest())
    growth = write_yaml(tmp_path / "growth.yaml", {"experiments": [{"id": "hero", "treatments": [{"id": str(i)} for i in range(4)]}]})
    with pytest.raises(RevenueForgeError) as error:
        plan_growth(tmp_path, products, growth)
    assert error.value.code == "REVENUEFORGE_EXPERIMENT_REJECTED"


def test_benchmark_withheld_below_k20_and_published_at_k20() -> None:
    """Prevent re-identifying small fleet cells while allowing bounded medians."""
    assert benchmark_cell([{"app_id": f"a{i}", "value": i} for i in range(19)])["median"] is None
    result = benchmark_cell([{"app_id": f"a{i}", "value": i} for i in range(20)])
    assert result["published"] is True
    assert result["median"] == 9.5


def test_graph_projection_rejects_tampered_receipt(tmp_path: Path) -> None:
    """Exclude a generated receipt after its bound content changes."""
    source = write_yaml(tmp_path / "products.yaml", manifest())
    receipt = build_revenue_bundle(tmp_path, source, Path(".factory/revenueforge/example"))
    assert revenueforge_projection(tmp_path)["current_count"] == 1
    path = tmp_path / receipt["artifacts"]["receipt"]
    value = json.loads(path.read_text(encoding="utf-8"))
    value["manifest"]["app"]["name"] = "Tampered"
    path.write_text(json.dumps(value), encoding="utf-8")
    projection = revenueforge_projection(tmp_path)
    assert projection["current_count"] == 0
    assert projection["invalid_count"] == 1


def test_paths_cannot_escape_workspace(tmp_path: Path) -> None:
    """Reject generation targets outside the selected workspace."""
    source = write_yaml(tmp_path / "products.yaml", manifest())
    with pytest.raises(RevenueForgeError) as error:
        build_revenue_bundle(tmp_path, source, tmp_path.parent / "outside")
    assert error.value.code == "REVENUEFORGE_PATH_REJECTED"


def test_purchase_replay_requires_complete_verified_ordered_journey(tmp_path: Path) -> None:
    products = write_yaml(tmp_path / "products.yaml", manifest())
    types = ["paywall_presented", "purchase_started", "transaction_verified", "server_notification_verified", "entitlement_active", "app_restarted", "entitlement_restored"]
    events = []
    for sequence, event_type in enumerate(types, 1):
        events.append({"id": f"e{sequence}", "sequence": sequence, "type": event_type, "product_id": "com.example.pro.monthly", "verified": True, "entitlement": "pro"})
    source = write_json(tmp_path / "events.json", {"build": {"id": "42", "bundle_id": "com.example.app", "environment": "testflight"}, "events": events})
    result = replay_purchase_journey(tmp_path, products, source, Path(".factory/revenueforge/example/replay.json"))
    assert result["verdict"] == "matched"
    assert result["summary"] == {"matched": 7, "mismatch": 0, "unknown": 0}
    assert result["action_summary"].startswith("Compare one sandbox")
    events[2]["verified"] = False
    source = write_json(tmp_path / "events.json", {"build": {"id": "42", "bundle_id": "com.example.app", "environment": "testflight"}, "events": events})
    result = replay_purchase_journey(tmp_path, products, source, Path(".factory/revenueforge/example/replay.json"))
    assert result["verdict"] == "blocked"
    assert result["summary"]["mismatch"] == 1


def test_testflight_inbox_redacts_identity_and_groups_journey(tmp_path: Path) -> None:
    feedback = {"items": [
        {"id": "abc", "build_id": "42", "kind": "feedback", "comment": "Restore did not unlock access", "tester_email": "private@example.com", "device_family": "iPhone", "os_version": "19.0", "app_version": "1.0"},
        {"id": "abc", "build_id": "42", "kind": "feedback", "comment": "duplicate"},
        {"id": "crash", "build_id": "42", "kind": "crash", "summary": "Crash after purchase"},
    ]}
    result = sync_testflight_evidence(tmp_path, write_json(tmp_path / "feedback.json", feedback), Path(".factory/revenueforge/example/testflight-inbox.json"))
    assert len(result["items"]) == 2
    assert result["groups"]["restore"] == 1
    assert all("tester_email" not in item for item in result["items"])
    assert "de-identified" in result["action_summary"]


def test_failure_matrix_never_promotes_unknown_to_pass(tmp_path: Path) -> None:
    products = write_yaml(tmp_path / "products.yaml", manifest())
    incomplete = write_json(tmp_path / "matrix.json", {"scenarios": {"cancel": {"observed": True, "passed": True}}})
    result = evaluate_failure_matrix(tmp_path, products, incomplete, Path(".factory/revenueforge/example/failure-matrix.json"))
    assert result["verdict"] == "blocked"
    assert result["summary"] == {"pass": 1, "fail": 0, "unknown": 9}
    assert "ten monetization failure paths" in result["action_summary"]
    complete = {name: {"observed": True, "passed": True, "evidence_ref": f"test:{name}"} for name in FAILURE_SCENARIOS}
    result = evaluate_failure_matrix(tmp_path, products, write_json(tmp_path / "matrix.json", {"scenarios": complete}), Path(".factory/revenueforge/example/failure-matrix.json"))
    assert result["verdict"] == "pass"


def test_policy_watch_invalidates_only_impacted_rules(tmp_path: Path) -> None:
    impact = [{"rule_id": "subscription-disclosure", "apps": ["com.example.app"], "artifacts": ["DSPaywall.swift"]}]
    baseline = {"sources": [{"id": "subscriptions", "url": "https://developer.apple.com/app-store/subscriptions/", "retrieved_at": "2026-08-29", "sha256": "a" * 64, "impacts": impact}, {"id": "testflight", "url": "https://developer.apple.com/testflight/", "retrieved_at": "2026-08-29", "sha256": "b" * 64, "impacts": [{"rule_id": "beta-feedback", "apps": [], "artifacts": ["inbox"]}]}]}
    current = json.loads(json.dumps(baseline))
    current["sources"][0]["sha256"] = "c" * 64
    result = watch_policy_drift(tmp_path, write_json(tmp_path / "registry.json", baseline), write_json(tmp_path / "snapshot.json", current), Path(".factory/revenueforge/example/policy-drift.json"))
    assert result["verdict"] == "reassessment_required"
    assert result["affected"]["rules"] == ["subscription-disclosure"]
    assert result["affected"]["apps"] == ["com.example.app"]
    assert "human reassessment" in result["action_summary"]


def test_graph_projection_reads_all_revenue_evidence_receipts(tmp_path: Path) -> None:
    products = write_yaml(tmp_path / "products.yaml", manifest())
    build_revenue_bundle(tmp_path, products, Path(".factory/revenueforge/example"))
    scenarios = {name: {"observed": True, "passed": True} for name in FAILURE_SCENARIOS}
    evaluate_failure_matrix(tmp_path, products, write_json(tmp_path / "matrix.json", {"scenarios": scenarios}), Path(".factory/revenueforge/example/failure-matrix.json"))
    projection = revenueforge_projection(tmp_path)
    assert projection["evidence"]["matrix"]["count"] == 1
    assert projection["evidence"]["matrix"]["latest"]["verdict"] == "pass"


def test_evidence_memory_requires_sealed_receipt_and_quarantines_contradictions(tmp_path: Path) -> None:
    products = write_yaml(tmp_path / "products.yaml", manifest())
    scenarios = {name: {"observed": True, "passed": True} for name in FAILURE_SCENARIOS}
    matrix = evaluate_failure_matrix(tmp_path, products, write_json(tmp_path / "matrix.json", {"scenarios": scenarios}), Path(".factory/revenueforge/example/failure-matrix.json"))
    for index, decision in enumerate(("retry restore", "do not retry restore"), 1):
        entry = {"app_id": "com.example.app", "journey": "restore", "decision": decision, "resolution": "show an explicit recovery path", "approved_by": "reviewer", "expires_at": "2027-01-01T00:00:00Z", "evidence_receipts": [matrix["path"]]}
        promote_evidence_memory(tmp_path, write_json(tmp_path / f"entry-{index}.json", entry), Path(f".factory/revenueforge/memory/{index}.json"))
    result = query_evidence_memory(tmp_path, "com.example.app", "restore", "2026-08-29T00:00:00Z")
    assert result["status"] == "quarantined"
    assert result["matches"] == []
    assert result["next_action"] == "human contradiction review"
    assert "quarantine contradictory decisions" in result["action_summary"]
