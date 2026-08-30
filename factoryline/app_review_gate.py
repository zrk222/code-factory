"""Fail-closed, build-bound App Store review-readiness gate for AppForge."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import hashlib
import json

from .revenueforge import AUTHORITY, RevenueForgeError
from .revenue_evidence import _local, _read_json, _seal


SCHEMA = "factory.appforge.app-review-gate.v2"
GUIDELINES = "https://developer.apple.com/app-store/review/guidelines/"
APP_INFO = "https://developer.apple.com/help/app-store-connect/reference/app-information/app-information"
ACCESSIBILITY = "https://developer.apple.com/design/human-interface-guidelines/accessibility"
EXPORT = "https://developer.apple.com/help/app-store-connect/manage-app-information/overview-of-export-compliance"

# key, policy area, applicability, remediation, official source
RULES: tuple[tuple[str, str, str, str, str], ...] = (
    ("signed_candidate", "2.1 App Completeness", "always", "Bind all evidence to the exact signed candidate.", GUIDELINES),
    ("launch_and_core_paths_stable", "2.1 App Completeness", "always", "Exercise launch and every advertised core path without crashes, placeholders, or dead ends.", GUIDELINES),
    ("review_notes_complete", "2.1 App Completeness", "always", "Provide accurate review notes, contact information, setup steps, and non-obvious feature guidance.", GUIDELINES),
    ("reviewer_access_ready", "2.1 App Completeness", "always", "Provide a working review path and production-safe reviewer access when required.", GUIDELINES),
    ("metadata_matches_build", "2.3 Accurate Metadata", "always", "Reconcile claims, features, prices, and screenshots with the selected build.", GUIDELINES),
    ("authentic_screenshots", "2.3 Accurate Metadata", "always", "Bind authentic store screenshots to the selected build and supported devices.", GUIDELINES),
    ("age_rating_complete", "App information", "always", "Complete the age-rating questionnaire against actual content and capabilities.", APP_INFO),
    ("privacy_policy_reachable", "5.1 Privacy", "always", "Publish a reachable privacy-policy URL and make the policy available inside the app where required.", GUIDELINES),
    ("privacy_attestation_complete", "5.1 Privacy", "always", "Reconcile runtime collection, SDKs, tracking, retention, deletion, and processors with App Store privacy disclosures.", GUIDELINES),
    ("permissions_minimized", "5.1.1 Data Collection and Storage", "always", "Request only permissions required for the feature and provide a usable alternative when practical.", GUIDELINES),
    ("security_controls_verified", "1.6 Data Security", "always", "Verify appropriate transport, storage, authorization, and sensitive-data handling controls.", GUIDELINES),
    ("accessibility_tasks_verified", "Accessibility", "always", "Exercise core tasks with VoiceOver, Dynamic Type, contrast, non-color cues, and Reduce Motion as applicable.", ACCESSIBILITY),
    ("minimum_functionality_verified", "4.2 Minimum Functionality", "always", "Demonstrate durable app-specific value beyond a repackaged website or marketing surface.", GUIDELINES),
    ("processor_terms_verified", "5.2.2 Third-Party Services", "always", "Record authority to use material third-party services and content.", GUIDELINES),
    ("export_compliance_determined", "Export Compliance", "always", "Complete the encryption/export determination and attach required documentation to the build.", EXPORT),
    ("physical_iphone_authentication", "2.1 App Completeness", "conditional", "Exercise authentication on the current build and a physical iPhone.", GUIDELINES),
    ("physical_ipad_navigation", "4 Design", "conditional", "Exercise the reviewer iPad path, including explicit accessible return actions and layout checks.", GUIDELINES),
    ("physical_iphone_purchase", "2.1(b) In-App Purchases", "conditional", "Complete a Sandbox purchase on the current build and a physical iPhone.", GUIDELINES),
    ("physical_iphone_restore", "2.1(b) In-App Purchases", "conditional", "Restore the purchase on the current build and a physical iPhone.", GUIDELINES),
    ("sandbox_products_verified", "2.1(b) In-App Purchases", "conditional", "Verify every reviewed product is available in Apple's Sandbox catalog.", GUIDELINES),
    ("restore_available", "3.1.2 Subscriptions", "conditional", "Expose and exercise a restore path for restorable purchases.", GUIDELINES),
    ("subscription_disclosures_complete", "3.1.2 Subscriptions", "conditional", "Show price, duration, renewal, cancellation, and required terms without misleading hierarchy.", GUIDELINES),
    ("account_deletion_available", "5.1.1 Account Sign-In", "conditional", "Provide in-app account deletion when the app supports account creation.", GUIDELINES),
    ("login_services_compliant", "4.8 Login Services", "conditional", "When third-party login creates the primary account, provide an equivalent privacy-preserving option or record an allowed exception.", GUIDELINES),
    ("ugc_moderation_controls", "1.2 User-Generated Content", "conditional", "Provide filtering, reporting, blocking, and reachable support for user-generated content.", GUIDELINES),
    ("kids_controls_verified", "1.3 Kids Category", "conditional", "Verify parental gates, data restrictions, ads, and age-appropriate content when targeting children.", GUIDELINES),
    ("health_claims_supported", "1.4 Physical Harm", "conditional", "Bind health or medical claims to appropriate evidence, disclaimers, and regulatory authority.", GUIDELINES),
    ("financial_services_authorized", "3.2.1 Financial Services", "conditional", "Record required licensing and entity authority for regulated financial functionality.", GUIDELINES),
    ("location_background_use_justified", "5.1 Privacy", "conditional", "Demonstrate that location and background modes are directly relevant and accurately disclosed.", GUIDELINES),
    ("ai_content_controls_verified", "1 Safety and 5.1 Privacy", "conditional", "Verify AI disclosures, unsafe-content handling, user control, and data-use boundaries for generated content.", GUIDELINES),
)


def _candidate(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise RevenueForgeError("APP_REVIEW_CANDIDATE_INVALID", f"{label} must be an object")
    required = ("bundle_identifier", "version", "build_number", "source_commit")
    normalized: dict[str, str] = {}
    for key in required:
        item = value.get(key)
        if not isinstance(item, str) or not item.strip() or len(item) > 200:
            raise RevenueForgeError("APP_REVIEW_CANDIDATE_INVALID", f"{label}.{key} must be a non-empty string")
        normalized[key] = item.strip()
    return normalized


def verify_app_review_readiness(root: Path, contract_path: Path, evidence_path: Path, out_path: Path) -> dict[str, Any]:
    """Compare reviewed requirements with exact-build observations; unknown fails closed."""
    workspace = Path(root).resolve()
    contract, contract_source = _read_json(workspace, contract_path)
    evidence, evidence_source = _read_json(workspace, evidence_path)
    expected = _candidate(contract.get("candidate"), "contract.candidate")
    observed = _candidate(evidence.get("candidate"), "evidence.candidate")
    checks = evidence.get("checks")
    if not isinstance(checks, dict):
        raise RevenueForgeError("APP_REVIEW_EVIDENCE_INVALID", "evidence.checks must be an object")
    applicability = contract.get("applicability")
    if not isinstance(applicability, dict):
        raise RevenueForgeError("APP_REVIEW_APPLICABILITY_INVALID", "contract.applicability must classify every conditional rule")

    findings: list[dict[str, str]] = []
    if observed != expected:
        findings.append({
            "code": "APP_REVIEW_BUILD_BINDING_MISMATCH",
            "policy_area": "2.1 App Completeness",
            "remediation": "Collect every observation again from the exact candidate declared in the reviewed contract.",
        })
    applied: list[dict[str, str]] = []
    not_applicable: list[dict[str, str]] = []
    for key, policy_area, mode, remediation, source in RULES:
        required = mode == "always"
        if mode == "conditional":
            classification = applicability.get(key)
            if not isinstance(classification, dict) or classification.get("status") not in {"required", "not_applicable"}:
                findings.append({"code": f"APP_REVIEW_{key.upper()}_APPLICABILITY_UNREVIEWED", "policy_area": policy_area, "remediation": "Classify this conditional rule as required or not_applicable with a named reviewer and concrete rationale."})
                continue
            reviewer = classification.get("reviewed_by")
            rationale = classification.get("rationale")
            if not isinstance(reviewer, str) or not reviewer.strip() or not isinstance(rationale, str) or len(rationale.strip()) < 20:
                findings.append({"code": f"APP_REVIEW_{key.upper()}_APPLICABILITY_UNREVIEWED", "policy_area": policy_area, "remediation": "Record a named reviewer and a rationale of at least 20 characters."})
                continue
            required = classification["status"] == "required"
            if not required:
                not_applicable.append({"rule": key, "reviewed_by": reviewer.strip(), "rationale": rationale.strip(), "source": source})
        if required:
            applied.append({"rule": key, "policy_area": policy_area, "source": source})
            if checks.get(key) is not True:
                findings.append({"code": f"APP_REVIEW_{key.upper()}_UNPROVEN", "policy_area": policy_area, "remediation": remediation})

    destination = _local(workspace, out_path, exists=False)
    receipt: dict[str, Any] = {
        "schema": SCHEMA,
        "marker": "APP_REVIEW_READY" if not findings else "APP_REVIEW_BLOCKED",
        "ok": not findings,
        "action_summary": "Check exact-build App Store evidence against rejection-derived completeness, commerce, device, metadata, privacy, and reviewer-access gates; never submit or claim Apple approval.",
        "candidate": expected,
        "contract_sha256": hashlib.sha256(contract_source.read_bytes()).hexdigest(),
        "evidence_sha256": hashlib.sha256(evidence_source.read_bytes()).hexdigest(),
        "checks_required": [item["rule"] for item in applied],
        "applicable_rules": applied,
        "not_applicable_rules": not_applicable,
        "policy_registry": {"rule_count": len(RULES), "official_sources": sorted({source for _, _, _, _, source in RULES})},
        "findings": findings,
        "provenance": {"basis": "sanitized regression classes derived from prior real App Review findings and release-readiness failures", "private_app_data_copied": False},
        "release_authority": {"app_review_submit": False, "testflight_upload": False, "apple_approval_claim": False},
        "claim_boundary": "local, build-bound readiness evidence only; not Apple policy certification, TestFlight upload, App Review submission, or approval",
    }
    return _seal(workspace, destination, receipt)


def app_review_gate_projection(root: Path) -> dict[str, Any]:
    """Read bounded, hash-valid App Review gate receipts without granting authority."""
    workspace = Path(root).resolve()
    current = 0
    invalid = 0
    latest: dict[str, Any] | None = None
    for path in sorted((workspace / ".factory" / "appforge").rglob("app-review*.json"))[:100]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            expected = value.pop("receipt_sha256")
            valid = (
                value.get("schema") == SCHEMA
                and isinstance(expected, str)
                and len(expected) == 64
                and hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest() == expected
            )
            value["receipt_sha256"] = expected
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            valid = False
            value = None
        if valid:
            current += 1
            latest = value
        else:
            invalid += 1
    return {
        "schema": "factory.appforge.app-review-projection.v1",
        "marker": "APP_REVIEW_GATE_READ_ONLY",
        "current_count": current,
        "invalid_count": invalid,
        "latest": latest,
        "authority": AUTHORITY,
        "claim_boundary": "hash-verified local readiness receipts only; not Apple approval or submission state",
    }
