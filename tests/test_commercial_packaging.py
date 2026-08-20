from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
UTF8 = "utf_8"


def _packaging() -> dict:
    return json.loads((ROOT / "docs" / "COMMERCIAL_PACKAGING.json").read_text(encoding=UTF8))


def test_commercial_packaging_marks_only_free_core_as_available():
    packaging = _packaging()

    assert packaging["schema"] == "factory.commercial-packaging.v1"
    assert packaging["governance"] == {
        "classification": "human_controlled",
        "commercial_activation_authority": ["product_owner", "chosen_billing_or_contracting_system"],
        "automation_may_activate": False,
    }
    assert packaging["claim_boundary"] == {
        "state_marker": "COMMERCIAL_CAPABILITY_BOUNDARY_PRESERVED",
        "managed_service_claim": False,
        "compliance_certification_claim": False,
        "sso_or_scim_product_claim": False,
        "external_kms_claim": False,
        "sla_claim": False,
    }
    tiers = packaging["tiers"]
    assert tiers["free_core"]["availability"] == "available"
    assert tiers["free_core"]["state_marker"] == "COMMERCIAL_FREE_CORE_AVAILABLE"
    assert tiers["free_core"]["commercial_account_required"] is False
    assert tiers["team_proof_hub"]["availability"] == "design_partner_only"
    assert tiers["team_proof_hub"]["state_marker"] == "COMMERCIAL_TEAM_NOT_SELLABLE"
    assert tiers["team_proof_hub"]["purchasable"] is False
    assert tiers["team_proof_hub"]["pricing"] == {
        "state_marker": "COMMERCIAL_TEAM_PRICE_PROPOSED",
        "status": "proposed",
        "currency": "USD",
        "range_per_active_pr_author_month": [12, 15],
        "minimum_active_pr_authors": 5,
    }
    assert tiers["enterprise_assurance"]["availability"] == "discovery_only"
    assert tiers["enterprise_assurance"]["state_marker"] == "COMMERCIAL_ENTERPRISE_DISCOVERY_ONLY"
    assert tiers["enterprise_assurance"]["purchasable"] is False
    assert tiers["managed_proof_runner"]["availability"] == "not_offered"
    assert tiers["managed_proof_runner"]["state_marker"] == "COMMERCIAL_MANAGED_RUNNER_NOT_OFFERED"
    assert tiers["managed_proof_runner"]["purchasable"] is False
    assert packaging["promotion_trigger"]["minimum_selected_design_partners"] == 3
    assert packaging["design_partner_intake"] == {
        "state_marker": "COMMERCIAL_INTAKE_DISCOVERY_ONLY",
        "path": ".github/ISSUE_TEMPLATE/design-partner.yml",
        "acceptance_authority": False,
        "source_collection_authority": False,
        "contact_authority": False,
    }
    assert packaging["separate_marketplace_plan"] == "docs/JETBRAINS_MONETIZATION_2027.json"
    assert packaging["marketplace_reference"] == {
        "state_marker": "COMMERCIAL_MARKETPLACE_SEPARATE",
        "path": "docs/JETBRAINS_MONETIZATION_2027.json",
        "activation_authority": False,
        "revision_authority": False,
    }
    assert packaging["github_pricing_reference"] == {
        "state_marker": "COMMERCIAL_GITHUB_PRICE_SCHEDULED_NOT_ACTIVE",
        "path": "docs/GITHUB_MONETIZATION_2026.json",
        "activation_authority": False,
        "revision_authority": False,
    }
    assert packaging["current_verdict"] == "COMMERCIALIZATION_STAGED_NOT_SELLABLE"


def test_design_partner_intake_has_no_sales_or_source_collection_authority():
    guide = (ROOT / "docs" / "COMMERCIAL_PACKAGING.md").read_text(encoding=UTF8)
    intake = (ROOT / ".github" / "ISSUE_TEMPLATE" / "design-partner.yml").read_text(encoding=UTF8)

    assert "not purchasable today" in guide
    assert "planning hypothesis" in guide
    assert "purchase offer" in guide
    assert "human-controlled" in guide
    assert "There is no" in guide
    assert "customer support commitment" in guide
    assert "does not accept a partner, create a contract, start a trial, or grant access" in intake
    assert "Do not include source code, credentials, tokens, customer data" in intake
    assert "design-partner" in intake


def test_github_per_seat_plan_is_scheduled_but_not_active_or_enforced():
    plan = json.loads((ROOT / "docs" / "GITHUB_MONETIZATION_2026.json").read_text(encoding=UTF8))
    guide = (ROOT / "docs" / "GITHUB_MONETIZATION_2026.md").read_text(encoding=UTF8)
    readme = (ROOT / "README.md").read_text(encoding=UTF8)

    assert plan["schema"] == "factory.github-monetization-plan.v1"
    assert plan["offer"] == {
        "free_through": "2026-12-31T23:59:59-05:00",
        "paid_from": "2027-01-01",
        "price_per_named_seat_usd_month": 5.95,
        "price_per_named_seat_usd_year": 60.0,
        "price_status": "owner_approved_future_price_not_active",
        "billing_status": "not_configured",
        "checkout_status": "not_live",
        "taxes_and_currency_conversion": "must_be_shown_by_the_chosen_billing_or_contracting_system_before_purchase",
    }
    assert plan["scope"]["source_license"] == "MIT OR Apache-2.0 remains unchanged"
    assert plan["scope"]["repository_access"] == "not_restricted_by_this_plan"
    assert plan["scope"]["automatic_license_enforcement"] is False
    assert plan["value_contract"]["state_marker"] == "GITHUB_ASSURANCE_SEAT_VALUE_DEFINED"
    assert plan["value_contract"]["included_when_activated"] == [
        "commit-bound GitHub Proof Review Check and walkthrough",
        "human-approved Plan-to-Proof scope envelope and visible Proof Debt",
        "supplied-policy drift dossier bound to the exact commit and named expiring exceptions",
        "organization-authored policy bundles with named, expiring exception receipts",
        "exportable hash-bound evidence, attestations, and review packets",
        "customer-managed local evidence and no Code Factory source upload",
    ]
    assert "automatic merge" in plan["value_contract"]["does_not_include"][0]
    assert len(plan["activation_gates"]) == 6
    assert plan["current_verdict"] == "GITHUB_PER_SEAT_PRICE_SCHEDULED_NOT_ACTIVE"
    assert "$5.95 USD per named seat per month" in guide
    assert "The $5.95 Assurance Seat value contract" in guide
    assert "feature-by-feature availability matrix" in guide
    assert "not active yet" in guide
    assert "GitHub repository metadata cannot collect payment" in guide
    assert "$5.95 USD per named seat/month" in readme
    assert "$60 USD per named seat/year" in readme
