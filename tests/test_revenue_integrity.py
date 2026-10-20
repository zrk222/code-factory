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
import subprocess
import sys
import factoryline.revenueforge as revenueforge_module
from factoryline.revenueforge import (
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


def _manifest() -> dict:
    """Return a valid monetization manifest."""
    return {
        "app": {"name": "Example", "bundle_id": "com.example.app"},
        "products": [
            {
                "id": "com.example.pro.monthly",
                "display_name": "Pro",
                "type": "auto_renewable",
                "duration": "P1M",
                "group": "pro",
                "entitlements": ["pro"],
            }
        ],
        "paywall": {
            "value_before_price": True,
            "price_and_duration_before_cta": True,
            "single_primary_cta": True,
            "restore_purchases": True,
            "patterns": [],
        },
        "legal": {
            "privacy_policy_url": "https://example.com/privacy",
            "terms_url": "https://example.com/terms",
        },
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
        {
            "event_id": "purchase-1",
            "provider": "app_store",
            "transaction_id": "tx-1",
            "event_type": "purchase",
            "product_id": "com.example.pro.monthly",
            "entitlement": "pro",
            "occurred_at": "2026-09-13T12:00:00Z",
            "verified": True,
        },
        {
            "event_id": "purchase-1-retry",
            "provider": "app_store",
            "transaction_id": "tx-1",
            "event_type": "purchase",
            "product_id": "com.example.pro.monthly",
            "entitlement": "pro",
            "occurred_at": "2026-09-13T12:00:00Z",
            "verified": True,
        },
    ]
    if conflict:
        events[1]["product_id"] = "com.example.other"
    if refund:
        events.append(
            {
                "event_id": "refund-1",
                "provider": "app_store",
                "transaction_id": "tx-1",
                "event_type": "refund",
                "product_id": "com.example.pro.monthly",
                "entitlement": "pro",
                "occurred_at": "2026-09-14T12:00:00Z",
                "verified": True,
            }
        )
    return {
        "build": {
            "id": "build-42",
            "bundle_id": "com.example.app",
            "environment": "testflight",
        },
        "events": events,
    }


def test_reconcile_collapses_retry_and_revokes_refund(tmp_path: Path) -> None:
    """Collapse an exact retry and apply a refund transition deterministically."""
    products = _write_yaml(tmp_path / "products.yaml", _manifest())
    events = _write_json(tmp_path / "events.json", _events(refund=True))
    result = reconcile_billing_events(
        tmp_path,
        products,
        events,
        Path(".factory/revenueforge/default/billing-ledger.json"),
    )
    assert result["marker"] == "REVENUEFORGE_BILLING_RECONCILED"
    assert result["verdict"] == "PASS"
    assert result["summary"]["duplicates"] == 1
    assert result["grant_candidates"] == []
    assert result["entitlement_states"][0]["state"] == "inactive"
    assert all(value is False for value in result["authority"].values())


def test_reconcile_conflict_emits_no_grant(tmp_path: Path) -> None:
    """Block a conflicting idempotency retry and suppress grant candidates."""
    value = _manifest()
    value["products"].append(
        {
            "id": "com.example.team.monthly",
            "display_name": "Team",
            "type": "auto_renewable",
            "duration": "P1M",
            "group": "team",
            "entitlements": ["team"],
        }
    )
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
    value["products"].append(
        {
            "id": "com.example.team.monthly",
            "display_name": "Team",
            "type": "auto_renewable",
            "duration": "P1M",
            "group": "team",
            "entitlements": ["team"],
        }
    )
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
        "treatments": [
            {
                "id": "control",
                "role": "control",
                "product_ids": ["com.example.pro.monthly"],
                "label": "Current",
            },
            {
                "id": "variant",
                "role": "variant",
                "product_ids": ["com.example.monthly"],
                "label": "Benefit first",
            },
        ],
        "guardrails": [{"metric": "refund_rate", "operator": "lte", "threshold": 0.05}],
        "cohort": {"name": "new_subscribers", "allocation_percent": 50},
        "window_days": 14,
        "minimum_sample_size": 100,
    }
    value["treatments"][1]["product_ids"] = ["com.example.pro.monthly"]
    if approved:
        approved_at = "2026-09-13T12:00:00Z"
        value["approval"] = {
            "approved_by": "human-1",
            "decision": "approved",
            "approved_at": approved_at,
            "approval_sha256": hashlib.sha256(
                json.dumps(
                    {
                        "approved_by": "human-1",
                        "approved_at": approved_at,
                        "experiment_id": value["id"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
        }
    return value


def test_experiment_requires_separate_approval(tmp_path: Path) -> None:
    """Keep agent-proposed experiments non-startable until approved."""
    products = _write_yaml(tmp_path / "products.yaml", _manifest())
    experiment = _write_json(tmp_path / "experiment.json", _experiment())
    result = plan_revenue_experiment(
        tmp_path,
        products,
        experiment,
        Path(".factory/revenueforge/default/experiment-plan.json"),
    )
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
        plan_revenue_experiment(
            tmp_path,
            products,
            _write_json(tmp_path / "experiment.json", value),
            Path("plan.json"),
        )
    assert error.value.code == "REVENUEFORGE_EXPERIMENT_AUTHORITY_REJECTED"


def test_integrity_evaluation_surfaces_manifest_drift_and_projection(
    tmp_path: Path,
) -> None:
    """Bind a ledger to its manifest and project integrity receipts read-only."""
    products = _write_yaml(tmp_path / "products.yaml", _manifest())
    events = _write_json(tmp_path / "events.json", _events())
    ledger = reconcile_billing_events(
        tmp_path,
        products,
        events,
        Path(".factory/revenueforge/default/billing-ledger.json"),
    )
    baseline = _write_json(tmp_path / "baseline.json", {"manifest_sha256": "f" * 64})
    result = evaluate_revenue_integrity(
        tmp_path,
        products,
        Path(ledger["path"]),
        baseline_path=baseline,
        out=Path(".factory/revenueforge/default/integrity.json"),
    )
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


"""CLI tests for RevenueForge integrity controls."""


def test_revenue_integrity_cli_commands(tmp_path: Path) -> None:
    """Run billing, experiment, and integrity commands through the public CLI."""
    manifest = {
        "app": {"name": "Example", "bundle_id": "com.example.app"},
        "products": [
            {
                "id": "com.example.pro.monthly",
                "display_name": "Pro",
                "type": "auto_renewable",
                "duration": "P1M",
                "group": "pro",
                "entitlements": ["pro"],
            }
        ],
        "paywall": {
            "value_before_price": True,
            "price_and_duration_before_cta": True,
            "single_primary_cta": True,
            "restore_purchases": True,
            "patterns": [],
        },
        "legal": {
            "privacy_policy_url": "https://example.com/privacy",
            "terms_url": "https://example.com/terms",
        },
        "privacy": {"purchase_history_linked": True, "purpose": "app_functionality"},
    }
    (tmp_path / "products.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    events = {
        "build": {"id": "42", "bundle_id": "com.example.app", "environment": "sandbox"},
        "events": [
            {
                "event_id": "e1",
                "provider": "app_store",
                "transaction_id": "tx",
                "event_type": "purchase",
                "product_id": "com.example.pro.monthly",
                "entitlement": "pro",
                "occurred_at": "2026-09-13T12:00:00Z",
                "verified": True,
            }
        ],
    }
    (tmp_path / "events.json").write_text(json.dumps(events), encoding="utf-8")
    billing = subprocess.run(
        [
            sys.executable,
            "-m",
            "factoryline.cli",
            "revenue",
            "billing-reconcile",
            "--root",
            str(tmp_path),
            "--products",
            "products.yaml",
            "--events",
            "events.json",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert billing.returncode == 0, billing.stderr
    ledger = json.loads(billing.stdout)
    assert ledger["marker"] == "REVENUEFORGE_BILLING_RECONCILED"
    experiment = {
        "id": "x",
        "proposed_by": "agent",
        "hypothesis": "test",
        "primary_metric": "purchase_conversion",
        "treatments": [
            {
                "id": "control",
                "role": "control",
                "product_ids": ["com.example.pro.monthly"],
            },
            {
                "id": "variant",
                "role": "variant",
                "product_ids": ["com.example.pro.monthly"],
            },
        ],
        "guardrails": [{"metric": "refund_rate", "operator": "lte", "threshold": 0.05}],
        "cohort": {"name": "new", "allocation_percent": 50},
        "window_days": 7,
        "minimum_sample_size": 20,
    }
    (tmp_path / "experiment.json").write_text(json.dumps(experiment), encoding="utf-8")
    planned = subprocess.run(
        [
            sys.executable,
            "-m",
            "factoryline.cli",
            "revenue",
            "experiment-plan",
            "--root",
            str(tmp_path),
            "--products",
            "products.yaml",
            "--experiment",
            "experiment.json",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert planned.returncode == 0, planned.stderr
    assert json.loads(planned.stdout)["status"] == "AWAITING_HUMAN_APPROVAL"
    integrity = subprocess.run(
        [
            sys.executable,
            "-m",
            "factoryline.cli",
            "revenue",
            "integrity",
            "--root",
            str(tmp_path),
            "--products",
            "products.yaml",
            "--ledger",
            ledger["path"],
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert integrity.returncode == 0, integrity.stderr
    assert json.loads(integrity.stdout)["decision"] == "READY_FOR_HUMAN_REVIEW"


"""Deterministic coverage for RevenueForge generation and authority boundaries."""


def manifest() -> dict:
    """Return one complete products manifest."""
    return {
        "app": {"name": "Example", "bundle_id": "com.example.app"},
        "products": [
            {
                "id": "com.example.pro.monthly",
                "display_name": "Pro",
                "type": "auto_renewable",
                "duration": "P1M",
                "group": "pro",
                "entitlements": ["pro"],
                "offers": [{"id": "trial", "type": "free_trial", "duration": "P1W"}],
            }
        ],
        "paywall": {
            "value_before_price": True,
            "price_and_duration_before_cta": True,
            "single_primary_cta": True,
            "restore_purchases": True,
            "patterns": [],
        },
        "legal": {
            "privacy_policy_url": "https://example.com/privacy",
            "terms_url": "https://example.com/terms",
        },
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
    receipt = build_revenue_bundle(
        tmp_path, source, Path(".factory/revenueforge/example")
    )
    assert receipt["marker"] == "REVENUEFORGE_BUNDLE_WRITTEN"
    for relative in receipt["artifacts"].values():
        assert (tmp_path / relative).is_file()
    swift = (tmp_path / receipt["artifacts"]["revenuekit"]).read_text(encoding="utf-8")
    server = (tmp_path / receipt["artifacts"]["server"]).read_text(encoding="utf-8")
    paywall = (tmp_path / receipt["artifacts"]["paywall"]).read_text(encoding="utf-8")
    assert "Transaction.currentEntitlements" in swift
    assert ".pending" in swift
    assert "verifyAndDecodeNotification" in server
    assert server.index("verifyAndDecodeNotification") < server.index(
        "entitlementTransition"
    )
    assert "Restore Purchases" in paywall
    assert "Privacy Policy" in paywall and "Terms of Use" in paywall


def test_repeated_bundle_skips_identical_replacements_and_repairs_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = write_yaml(tmp_path / "products.yaml", manifest())
    output = Path(".factory/revenueforge/example")
    first = build_revenue_bundle(tmp_path, source, output)
    artifact_paths = [tmp_path / path for path in first["artifacts"].values()]
    original = {path: path.read_bytes() for path in artifact_paths}

    def reject_replace(*_args: object, **_kwargs: object) -> None:
        pytest.fail("an unchanged RevenueForge artifact was replaced")

    with monkeypatch.context() as patch:
        patch.setattr(revenueforge_module.os, "replace", reject_replace)
        repeated = build_revenue_bundle(tmp_path, source, output)

    assert repeated["receipt_sha256"] == first["receipt_sha256"]
    assert {path: path.read_bytes() for path in artifact_paths} == original

    changed_path = artifact_paths[0]
    changed_path.write_bytes(b"tampered")
    repaired = build_revenue_bundle(tmp_path, source, output)
    assert repaired["receipt_sha256"] == first["receipt_sha256"]
    assert {path: path.read_bytes() for path in artifact_paths} == original


@pytest.mark.parametrize(
    "pattern", ["countdown", "false_scarcity", "hidden_cancel", "preselected_upsell"]
)
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
    growth = write_yaml(
        tmp_path / "growth.yaml",
        {
            "experiments": [
                {"id": "hero", "treatments": [{"id": "a"}, {"id": "b"}, {"id": "c"}]}
            ],
            "offers": [{"id": "return"}],
            "custom_product_pages": [{"id": "teams"}],
        },
    )
    result = plan_growth(tmp_path, products, growth)
    assert result["marker"] == "REVENUEFORGE_PHASE8_PLANNED"
    assert result["experiments"][0]["promotion"] == "human_required"
    assert result["offers"][0]["send"] == "human_required"
    assert all(value is False for value in result["authority"].values())


def test_four_ppo_treatments_are_rejected(tmp_path: Path) -> None:
    """Reject experiments beyond Apple's three-treatment bound."""
    products = write_yaml(tmp_path / "products.yaml", manifest())
    growth = write_yaml(
        tmp_path / "growth.yaml",
        {
            "experiments": [
                {"id": "hero", "treatments": [{"id": str(i)} for i in range(4)]}
            ]
        },
    )
    with pytest.raises(RevenueForgeError) as error:
        plan_growth(tmp_path, products, growth)
    assert error.value.code == "REVENUEFORGE_EXPERIMENT_REJECTED"


def test_benchmark_withheld_below_k20_and_published_at_k20() -> None:
    """Prevent re-identifying small fleet cells while allowing bounded medians."""
    assert (
        benchmark_cell([{"app_id": f"a{i}", "value": i} for i in range(19)])["median"]
        is None
    )
    result = benchmark_cell([{"app_id": f"a{i}", "value": i} for i in range(20)])
    assert result["published"] is True
    assert result["median"] == 9.5


def test_graph_projection_rejects_tampered_receipt(tmp_path: Path) -> None:
    """Exclude a generated receipt after its bound content changes."""
    source = write_yaml(tmp_path / "products.yaml", manifest())
    receipt = build_revenue_bundle(
        tmp_path, source, Path(".factory/revenueforge/example")
    )
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


def test_purchase_replay_requires_complete_verified_ordered_journey(
    tmp_path: Path,
) -> None:
    products = write_yaml(tmp_path / "products.yaml", manifest())
    types = [
        "paywall_presented",
        "purchase_started",
        "transaction_verified",
        "server_notification_verified",
        "entitlement_active",
        "app_restarted",
        "entitlement_restored",
    ]
    events = []
    for sequence, event_type in enumerate(types, 1):
        events.append(
            {
                "id": f"e{sequence}",
                "sequence": sequence,
                "type": event_type,
                "product_id": "com.example.pro.monthly",
                "verified": True,
                "entitlement": "pro",
            }
        )
    source = write_json(
        tmp_path / "events.json",
        {
            "build": {
                "id": "42",
                "bundle_id": "com.example.app",
                "environment": "testflight",
            },
            "events": events,
        },
    )
    result = replay_purchase_journey(
        tmp_path, products, source, Path(".factory/revenueforge/example/replay.json")
    )
    assert result["verdict"] == "matched"
    assert result["summary"] == {"matched": 7, "mismatch": 0, "unknown": 0}
    assert result["action_summary"].startswith("Compare one sandbox")
    events[2]["verified"] = False
    source = write_json(
        tmp_path / "events.json",
        {
            "build": {
                "id": "42",
                "bundle_id": "com.example.app",
                "environment": "testflight",
            },
            "events": events,
        },
    )
    result = replay_purchase_journey(
        tmp_path, products, source, Path(".factory/revenueforge/example/replay.json")
    )
    assert result["verdict"] == "blocked"
    assert result["summary"]["mismatch"] == 1


def test_testflight_inbox_redacts_identity_and_groups_journey(tmp_path: Path) -> None:
    feedback = {
        "items": [
            {
                "id": "abc",
                "build_id": "42",
                "kind": "feedback",
                "comment": "Restore did not unlock access",
                "tester_email": "private@example.com",
                "device_family": "iPhone",
                "os_version": "19.0",
                "app_version": "1.0",
            },
            {"id": "abc", "build_id": "42", "kind": "feedback", "comment": "duplicate"},
            {
                "id": "crash",
                "build_id": "42",
                "kind": "crash",
                "summary": "Crash after purchase",
            },
        ]
    }
    result = sync_testflight_evidence(
        tmp_path,
        write_json(tmp_path / "feedback.json", feedback),
        Path(".factory/revenueforge/example/testflight-inbox.json"),
    )
    assert len(result["items"]) == 2
    assert result["groups"]["restore"] == 1
    assert all("tester_email" not in item for item in result["items"])
    assert "de-identified" in result["action_summary"]


def test_failure_matrix_never_promotes_unknown_to_pass(tmp_path: Path) -> None:
    products = write_yaml(tmp_path / "products.yaml", manifest())
    incomplete = write_json(
        tmp_path / "matrix.json",
        {"scenarios": {"cancel": {"observed": True, "passed": True}}},
    )
    result = evaluate_failure_matrix(
        tmp_path,
        products,
        incomplete,
        Path(".factory/revenueforge/example/failure-matrix.json"),
    )
    assert result["verdict"] == "blocked"
    assert result["summary"] == {"pass": 1, "fail": 0, "unknown": 9}
    assert "ten monetization failure paths" in result["action_summary"]
    complete = {
        name: {"observed": True, "passed": True, "evidence_ref": f"test:{name}"}
        for name in FAILURE_SCENARIOS
    }
    result = evaluate_failure_matrix(
        tmp_path,
        products,
        write_json(tmp_path / "matrix.json", {"scenarios": complete}),
        Path(".factory/revenueforge/example/failure-matrix.json"),
    )
    assert result["verdict"] == "pass"


def test_policy_watch_invalidates_only_impacted_rules(tmp_path: Path) -> None:
    impact = [
        {
            "rule_id": "subscription-disclosure",
            "apps": ["com.example.app"],
            "artifacts": ["DSPaywall.swift"],
        }
    ]
    baseline = {
        "sources": [
            {
                "id": "subscriptions",
                "url": "https://developer.apple.com/app-store/subscriptions/",
                "retrieved_at": "2026-08-29",
                "sha256": "a" * 64,
                "impacts": impact,
            },
            {
                "id": "testflight",
                "url": "https://developer.apple.com/testflight/",
                "retrieved_at": "2026-08-29",
                "sha256": "b" * 64,
                "impacts": [
                    {"rule_id": "beta-feedback", "apps": [], "artifacts": ["inbox"]}
                ],
            },
        ]
    }
    current = json.loads(json.dumps(baseline))
    current["sources"][0]["sha256"] = "c" * 64
    result = watch_policy_drift(
        tmp_path,
        write_json(tmp_path / "registry.json", baseline),
        write_json(tmp_path / "snapshot.json", current),
        Path(".factory/revenueforge/example/policy-drift.json"),
    )
    assert result["verdict"] == "reassessment_required"
    assert result["affected"]["rules"] == ["subscription-disclosure"]
    assert result["affected"]["apps"] == ["com.example.app"]
    assert "human reassessment" in result["action_summary"]


def test_graph_projection_reads_all_revenue_evidence_receipts(tmp_path: Path) -> None:
    products = write_yaml(tmp_path / "products.yaml", manifest())
    build_revenue_bundle(tmp_path, products, Path(".factory/revenueforge/example"))
    scenarios = {name: {"observed": True, "passed": True} for name in FAILURE_SCENARIOS}
    evaluate_failure_matrix(
        tmp_path,
        products,
        write_json(tmp_path / "matrix.json", {"scenarios": scenarios}),
        Path(".factory/revenueforge/example/failure-matrix.json"),
    )
    projection = revenueforge_projection(tmp_path)
    assert projection["evidence"]["matrix"]["count"] == 1
    assert projection["evidence"]["matrix"]["latest"]["verdict"] == "pass"


def test_evidence_memory_requires_sealed_receipt_and_quarantines_contradictions(
    tmp_path: Path,
) -> None:
    products = write_yaml(tmp_path / "products.yaml", manifest())
    scenarios = {name: {"observed": True, "passed": True} for name in FAILURE_SCENARIOS}
    matrix = evaluate_failure_matrix(
        tmp_path,
        products,
        write_json(tmp_path / "matrix.json", {"scenarios": scenarios}),
        Path(".factory/revenueforge/example/failure-matrix.json"),
    )
    for index, decision in enumerate(("retry restore", "do not retry restore"), 1):
        entry = {
            "app_id": "com.example.app",
            "journey": "restore",
            "decision": decision,
            "resolution": "show an explicit recovery path",
            "approved_by": "reviewer",
            "expires_at": "2027-01-01T00:00:00Z",
            "evidence_receipts": [matrix["path"]],
        }
        promote_evidence_memory(
            tmp_path,
            write_json(tmp_path / f"entry-{index}.json", entry),
            Path(f".factory/revenueforge/memory/{index}.json"),
        )
    result = query_evidence_memory(
        tmp_path, "com.example.app", "restore", "2026-08-29T00:00:00Z"
    )
    assert result["status"] == "quarantined"
    assert result["matches"] == []
    assert result["next_action"] == "human contradiction review"
    assert "quarantine contradictory decisions" in result["action_summary"]


def test_revenue_shared_local_preserves_path_and_error_contract(tmp_path):
    import ast
    import inspect
    import factoryline.revenue_evidence as evidence
    import factoryline.revenueforge as forge

    assert evidence._local is forge._local
    assert not any(
        isinstance(n, ast.FunctionDef) and n.name == "_local"
        for n in ast.parse(inspect.getsource(evidence)).body
    )
    source = tmp_path / "input.json"
    source.write_text("{}", encoding="utf-8")
    assert evidence._local(tmp_path, Path("input.json")) == source.resolve()
    assert evidence._local(tmp_path, source) == source.resolve()
    assert (
        evidence._local(tmp_path, Path("new.json"), exists=False)
        == tmp_path / "new.json"
    )
    with pytest.raises(forge.RevenueForgeError) as missing:
        evidence._local(tmp_path, Path("missing.json"))
    assert missing.value.code == "REVENUEFORGE_INPUT_UNAVAILABLE"
    with pytest.raises(forge.RevenueForgeError) as escaping:
        evidence._local(tmp_path, Path("../outside.json"), exists=False)
    assert escaping.value.code == "REVENUEFORGE_PATH_REJECTED"


"""CLI coverage for the approachable RevenueForge command family."""


def test_revenue_dispatch_covers_exactly_registered_commands(
    tmp_path, monkeypatch, capsys
):
    import argparse
    from types import SimpleNamespace
    from factoryline import cli_revenue

    parser = argparse.ArgumentParser()
    groups = parser.add_subparsers()
    cli_revenue.add_parser(groups)
    revenue = groups.choices["revenue"]
    subcommands = next(
        action
        for action in revenue._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    assert set(subcommands.choices) == set(cli_revenue._COMMANDS)
    calls = []
    for command in subcommands.choices:
        args = SimpleNamespace(revenue_cmd=command, root=str(tmp_path), json=True)

        def handler(received, root):
            calls.append((received, root))
            return {"ok": True, "command": received.revenue_cmd}

        monkeypatch.setitem(cli_revenue._COMMANDS, command, handler)
        assert cli_revenue.run(args) == 0
        assert calls[-1] == (args, tmp_path.resolve())
        assert json.loads(capsys.readouterr().out)["command"] == command
    args.revenue_cmd = "unknown"
    assert cli_revenue.run(args) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "REVENUEFORGE_INPUT_INVALID"


def test_revenue_dispatch_and_private_handlers_stay_bounded():
    import ast
    import inspect
    from factoryline import cli_revenue

    for function in [cli_revenue.run, *cli_revenue._COMMANDS.values()]:
        tree = ast.parse(inspect.getsource(function))
        count = 1
        for node in ast.walk(tree):
            if isinstance(
                node,
                (
                    ast.If,
                    ast.For,
                    ast.While,
                    ast.ExceptHandler,
                    ast.With,
                    ast.Assert,
                    ast.IfExp,
                ),
            ):
                count += 1
            elif isinstance(node, ast.BoolOp):
                count += len(node.values) - 1
        assert count <= 10, (function.__name__, count)


def test_revenue_validate_and_build_cli(tmp_path: Path) -> None:
    """Validate and build a local bundle through the shipped CLI."""
    manifest = {
        "app": {"name": "Example", "bundle_id": "com.example.app"},
        "products": [
            {
                "id": "com.example.monthly",
                "display_name": "Pro",
                "type": "auto_renewable",
                "duration": "P1M",
                "group": "main",
                "entitlements": ["pro"],
            }
        ],
        "paywall": {
            "value_before_price": True,
            "price_and_duration_before_cta": True,
            "single_primary_cta": True,
            "restore_purchases": True,
            "patterns": [],
        },
        "legal": {
            "privacy_policy_url": "https://example.com/privacy",
            "terms_url": "https://example.com/terms",
        },
        "privacy": {"purchase_history_linked": True, "purpose": "app_functionality"},
    }
    (tmp_path / "products.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    validate = subprocess.run(
        [
            sys.executable,
            "-m",
            "factoryline.cli",
            "revenue",
            "validate",
            "--root",
            str(tmp_path),
            "--products",
            "products.yaml",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert validate.returncode == 0, validate.stderr
    assert json.loads(validate.stdout)["marker"] == "REVENUEFORGE_MANIFEST_VALIDATED"
    build = subprocess.run(
        [
            sys.executable,
            "-m",
            "factoryline.cli",
            "revenue",
            "build",
            "--root",
            str(tmp_path),
            "--products",
            "products.yaml",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert build.returncode == 0, build.stderr
    assert json.loads(build.stdout)["marker"] == "REVENUEFORGE_BUNDLE_WRITTEN"


def test_revenue_evidence_cli_commands(tmp_path: Path) -> None:
    manifest = {
        "app": {"name": "Example", "bundle_id": "com.example.app"},
        "products": [
            {
                "id": "com.example.monthly",
                "display_name": "Pro",
                "type": "auto_renewable",
                "duration": "P1M",
                "group": "main",
                "entitlements": ["pro"],
            }
        ],
        "paywall": {
            "value_before_price": True,
            "price_and_duration_before_cta": True,
            "single_primary_cta": True,
            "restore_purchases": True,
            "patterns": [],
        },
        "legal": {
            "privacy_policy_url": "https://example.com/privacy",
            "terms_url": "https://example.com/terms",
        },
        "privacy": {"purchase_history_linked": True, "purpose": "app_functionality"},
    }
    (tmp_path / "products.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    events = {
        "build": {"id": "1", "bundle_id": "com.example.app", "environment": "sandbox"},
        "events": [{"id": "e1", "sequence": 1, "type": "paywall_presented"}],
    }
    (tmp_path / "events.json").write_text(json.dumps(events), encoding="utf-8")
    replay = subprocess.run(
        [
            sys.executable,
            "-m",
            "factoryline.cli",
            "revenue",
            "replay",
            "--root",
            str(tmp_path),
            "--products",
            "products.yaml",
            "--events",
            "events.json",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert replay.returncode == 0, replay.stderr
    assert json.loads(replay.stdout)["verdict"] == "blocked"
    feedback = {
        "items": [
            {
                "id": "f1",
                "build_id": "1",
                "kind": "feedback",
                "summary": "Restore failed",
            }
        ]
    }
    (tmp_path / "feedback.json").write_text(json.dumps(feedback), encoding="utf-8")
    sync = subprocess.run(
        [
            sys.executable,
            "-m",
            "factoryline.cli",
            "revenue",
            "testflight-sync",
            "--root",
            str(tmp_path),
            "--feedback",
            "feedback.json",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert sync.returncode == 0, sync.stderr
    assert (
        json.loads(sync.stdout)["marker"] == "REVENUEFORGE_TESTFLIGHT_EVIDENCE_SYNCED"
    )
