"""Deterministic, human-governed monetization planning and scaffold generation."""
from __future__ import annotations

from copy import deepcopy
from html import escape
from pathlib import Path
from typing import Any
import hashlib
import json
import os
import tempfile

import yaml


SCHEMA = "factory.revenueforge.v1"
MAX_INPUT_BYTES = 1_048_576
MAX_PRODUCTS = 50
MAX_EXPERIMENT_TREATMENTS = 3
MIN_BENCHMARK_CELL = 20
ALLOWED_PRODUCT_TYPES = {"auto_renewable", "non_consumable"}
ALLOWED_DURATIONS = {"P1W", "P1M", "P2M", "P3M", "P6M", "P1Y"}
ALLOWED_OFFER_TYPES = {"free_trial", "pay_as_you_go", "pay_up_front"}
FORBIDDEN_PATTERNS = {"countdown", "false_scarcity", "hidden_cancel", "preselected_upsell"}
AUTHORITY = {
    "app_store_connect_write": False,
    "offer_send": False,
    "experiment_start": False,
    "winner_promotion": False,
    "review_response_publish": False,
    "price_change": False,
    "deployment": False,
    "credential_access": False,
}


class RevenueForgeError(ValueError):
    """Represent a stable fail-closed RevenueForge error."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _local(root: Path, value: Path, *, exists: bool = True) -> Path:
    workspace = Path(root).resolve()
    candidate = Path(value)
    resolved = candidate.resolve() if candidate.is_absolute() else (workspace / candidate).resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise RevenueForgeError("REVENUEFORGE_PATH_REJECTED", "path must remain inside the workspace") from exc
    if exists and not resolved.is_file():
        raise RevenueForgeError("REVENUEFORGE_INPUT_UNAVAILABLE", "input must be a regular file")
    return resolved


def _read_yaml(root: Path, path: Path) -> dict[str, Any]:
    source = _local(root, path)
    if source.stat().st_size > MAX_INPUT_BYTES:
        raise RevenueForgeError("REVENUEFORGE_INPUT_TOO_LARGE", "products input exceeds 1 MiB")
    try:
        value = yaml.safe_load(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise RevenueForgeError("REVENUEFORGE_INPUT_INVALID", "products input is not valid YAML") from exc
    if not isinstance(value, dict):
        raise RevenueForgeError("REVENUEFORGE_INPUT_INVALID", "products input must be an object")
    return value


def _required_text(value: object, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise RevenueForgeError("REVENUEFORGE_MANIFEST_INVALID", f"{field} is required")
    return text


def _normalize_product(raw: object, seen: set[str]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise RevenueForgeError("REVENUEFORGE_MANIFEST_INVALID", "each product must be an object")
    product_id = _required_text(raw.get("id"), "product.id")
    if product_id in seen:
        raise RevenueForgeError("REVENUEFORGE_MANIFEST_INVALID", f"duplicate product id: {product_id}")
    seen.add(product_id)
    product_type = _required_text(raw.get("type"), f"{product_id}.type")
    if product_type not in ALLOWED_PRODUCT_TYPES:
        raise RevenueForgeError("REVENUEFORGE_MANIFEST_INVALID", f"unsupported product type: {product_type}")
    duration = raw.get("duration")
    if product_type == "auto_renewable" and duration not in ALLOWED_DURATIONS:
        raise RevenueForgeError("REVENUEFORGE_MANIFEST_INVALID", f"{product_id}.duration must be an ISO-8601 subscription duration")
    entitlements = raw.get("entitlements")
    if not isinstance(entitlements, list) or not entitlements or not all(isinstance(v, str) and v.strip() for v in entitlements):
        raise RevenueForgeError("REVENUEFORGE_MANIFEST_INVALID", f"{product_id}.entitlements must be a non-empty string list")
    offers: list[dict[str, str]] = []
    for offer in raw.get("offers", []):
        if not isinstance(offer, dict) or offer.get("type") not in ALLOWED_OFFER_TYPES or offer.get("duration") not in ALLOWED_DURATIONS:
            raise RevenueForgeError("REVENUEFORGE_MANIFEST_INVALID", f"{product_id} has an invalid offer")
        offers.append({"id": _required_text(offer.get("id"), "offer.id"), "type": offer["type"], "duration": offer["duration"]})
    return {
        "id": product_id,
        "display_name": _required_text(raw.get("display_name"), f"{product_id}.display_name"),
        "type": product_type,
        "duration": duration if product_type == "auto_renewable" else None,
        "group": _required_text(raw.get("group"), f"{product_id}.group") if product_type == "auto_renewable" else None,
        "entitlements": sorted(set(v.strip() for v in entitlements)),
        "offers": sorted(offers, key=lambda item: item["id"]),
    }


def _sections(raw: dict[str, Any]) -> tuple[list[Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    products = raw.get("products")
    paywall = raw.get("paywall")
    legal = raw.get("legal")
    privacy = raw.get("privacy")
    if not isinstance(products, list) or not products or len(products) > MAX_PRODUCTS:
        raise RevenueForgeError("REVENUEFORGE_MANIFEST_INVALID", f"products must contain 1-{MAX_PRODUCTS} entries")
    if not all(isinstance(value, dict) for value in (paywall, legal, privacy)):
        raise RevenueForgeError("REVENUEFORGE_MANIFEST_INVALID", "paywall, legal, and privacy objects are required")
    return products, paywall, legal, privacy


def _policy_gates(raw: dict[str, Any], paywall: dict[str, Any], legal: dict[str, Any], privacy: dict[str, Any]) -> tuple[dict[str, bool], dict[str, bool], dict[str, bool], set[str]]:
    patterns = set(paywall.get("patterns", []))
    if patterns & FORBIDDEN_PATTERNS:
        raise RevenueForgeError("REVENUEFORGE_DARK_PATTERN_REJECTED", "dark-pattern paywall controls are not permitted")
    if any(raw.get(field) for field in ("ad_sdk", "crypto_payments", "alternative_payments")):
        raise RevenueForgeError("REVENUEFORGE_PAYMENT_LANE_REJECTED", "ads, crypto, and alternative payments are outside this safe lane")
    ui = {"value_before_price": paywall.get("value_before_price") is True, "price_and_duration_before_cta": paywall.get("price_and_duration_before_cta") is True, "single_primary_cta": paywall.get("single_primary_cta") is True, "restore_purchases": paywall.get("restore_purchases") is True}
    legal_gates = {"privacy_policy_url": bool(str(legal.get("privacy_policy_url", "")).startswith("https://")), "terms_url": bool(str(legal.get("terms_url", "")).startswith("https://"))}
    privacy_gates = {"purchase_history_linked": privacy.get("purchase_history_linked") is True, "purpose_app_functionality": privacy.get("purpose") == "app_functionality"}
    return ui, legal_gates, privacy_gates, patterns


def validate_products(root: Path, products_path: Path) -> dict[str, Any]:
    """Normalize one products manifest and return deterministic readiness gates."""
    raw = _read_yaml(root, products_path)
    products_raw, ui, legal, privacy = _sections(raw)
    required_ui, required_legal, required_privacy, patterns = _policy_gates(raw, ui, legal, privacy)
    seen: set[str] = set()
    products = [_normalize_product(item, seen) for item in products_raw]
    products.sort(key=lambda item: item["id"])
    gates = {
        "monetization_ready": all(required_ui.values()) and all(required_legal.values()) and all(required_privacy.values()),
        "subscription_disclosure": required_ui["value_before_price"] and required_ui["price_and_duration_before_cta"] and all(required_legal.values()),
        "experiment_integrity": True,
    }
    normalized = {
        "schema": SCHEMA,
        "app": {
            "name": _required_text(raw.get("app", {}).get("name") if isinstance(raw.get("app"), dict) else None, "app.name"),
            "bundle_id": _required_text(raw.get("app", {}).get("bundle_id") if isinstance(raw.get("app"), dict) else None, "app.bundle_id"),
        },
        "products": products,
        "paywall": {**required_ui, "patterns": sorted(patterns)},
        "legal": {"privacy_policy_url": str(legal.get("privacy_policy_url", "")), "terms_url": str(legal.get("terms_url", ""))},
        "privacy": {"purchase_history_linked": privacy.get("purchase_history_linked") is True, "purpose": privacy.get("purpose")},
        "entitlement_server": {"jws_verify_before_decode": True, "separate_environments": True, "tls_minimum": "1.2"},
        "authority": AUTHORITY,
        "gates": gates,
    }
    normalized["manifest_sha256"] = _sha(normalized)
    return {"marker": "REVENUEFORGE_MANIFEST_VALIDATED", "ok": all(gates.values()), "manifest": normalized}


def _atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _swift_kit(manifest: dict[str, Any]) -> str:
    ids = ", ".join(json.dumps(item["id"]) for item in manifest["products"])
    return f'''import StoreKit

@MainActor
final class RevenueKit: ObservableObject {{
    @Published private(set) var products: [Product] = []
    @Published private(set) var entitledProductIDs: Set<String> = []
    private let productIDs: Set<String> = [{ids}]

    func load() async throws {{ products = try await Product.products(for: productIDs).sorted {{ $0.price < $1.price }} }}

    func purchase(_ product: Product) async throws -> Product.PurchaseResult {{
        let result = try await product.purchase()
        if case .success(let verification) = result {{
            guard case .verified(let transaction) = verification else {{ throw RevenueError.unverified }}
            await transaction.finish()
            await refreshEntitlements()
        }}
        // .pending and .userCancelled remain visible states; access is never granted here.
        return result
    }}

    func refreshEntitlements() async {{
        var current = Set<String>()
        for await result in Transaction.currentEntitlements {{
            if case .verified(let transaction) = result {{ current.insert(transaction.productID) }}
        }}
        entitledProductIDs = current
    }}

    func restore() async throws {{ try await AppStore.sync(); await refreshEntitlements() }}
    enum RevenueError: Error {{ case unverified }}
}}
'''


def _swift_paywall(manifest: dict[str, Any]) -> str:
    privacy = manifest["legal"]["privacy_policy_url"]
    terms = manifest["legal"]["terms_url"]
    return f'''import StoreKit
import SwiftUI

struct DSPaywall: View {{
    @StateObject var revenue: RevenueKit
    @State private var purchaseState = "Choose the plan that fits your work."

    var body: some View {{
        ScrollView {{ VStack(spacing: 20) {{
            Text("Unlock the complete experience").font(.largeTitle.bold())
            Text("See every included benefit before choosing a price.")
            ForEach(revenue.products) {{ product in
                VStack {{ Text(product.displayName).font(.headline); Text(product.description)
                    Text(product.displayPrice + " · " + (product.subscription?.subscriptionPeriod.debugDescription ?? "one-time"))
                    Button("Continue with " + product.displayName) {{ Task {{ purchaseState = String(describing: try await revenue.purchase(product)) }} }}
                        .buttonStyle(.borderedProminent).frame(minHeight: 44)
                }}.accessibilityElement(children: .contain)
            }}
            Text(purchaseState).accessibilityLabel("Purchase status")
            Button("Restore Purchases") {{ Task {{ try await revenue.restore() }} }}.frame(minHeight: 44)
            HStack {{ Link("Privacy Policy", destination: URL(string: "{privacy}")!); Link("Terms of Use", destination: URL(string: "{terms}")!) }}
        }}.padding(24) }}
    }}
}}
'''


def _server_scaffold(manifest: dict[str, Any]) -> str:
    bundle = manifest["app"]["bundle_id"]
    return f'''import {{ Environment, SignedDataVerifier }} from "@apple/app-store-server-library";

// Load Apple root certificates and app identifiers from runtime secrets. Never commit credentials.
export async function verifyNotification(signedPayload: string, roots: Buffer[], environment: Environment, appAppleId?: number) {{
  const verifier = new SignedDataVerifier(roots, true, environment, "{bundle}", appAppleId);
  // This call verifies the JWS and certificate chain before any field is trusted.
  return await verifier.verifyAndDecodeNotification(signedPayload);
}}

export function entitlementTransition(current: string, notificationType: string): string {{
  const transitions: Record<string, string> = {{
    SUBSCRIBED: "active", DID_RENEW: "active", DID_FAIL_TO_RENEW: "billing_retry",
    EXPIRED: "expired", REFUND: "revoked", GRACE_PERIOD_EXPIRED: "expired", REVOKE: "revoked"
  }};
  return transitions[notificationType] ?? current;
}}

export function environmentDatabaseName(environment: Environment): string {{
  return environment === Environment.PRODUCTION ? "entitlements_production" : "entitlements_sandbox";
}}
'''


def _evidence_html(receipt: dict[str, Any]) -> str:
    gates = receipt["manifest"]["gates"]
    cards = "".join(f'<article><span>{escape(key.replace("_", " ").title())}</span><strong>{"PASS" if value else "BLOCKED"}</strong></article>' for key, value in gates.items())
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RevenueForge Evidence</title><style>:root{{--ink:#14213d;--blue:#2563eb;--paper:#f8fafc;--ok:#067647;--line:#cbd5e1}}*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:16px/1.65 Inter,system-ui,sans-serif}}main{{max-width:980px;margin:auto;padding:clamp(24px,6vw,72px)}}h1{{font-size:clamp(2rem,6vw,4.5rem);line-height:1.02;max-width:12ch}}p{{max-width:68ch}}section{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:40px 0}}article{{background:white;border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:0 16px 40px #14213d10}}article span,article strong{{display:block}}article strong{{margin-top:12px;color:var(--ok);font-size:1.4rem}}code{{overflow-wrap:anywhere}}.boundary{{border-left:5px solid var(--blue);padding:18px;background:#eff6ff}}@media(max-width:768px){{section{{grid-template-columns:1fr}}}}</style></head><body><main><p>Code Factory · local evidence</p><h1>Monetization readiness you can inspect.</h1><p>Generated from a hash-bound product manifest. No credential was accessed and no App Store action was performed.</p><section>{cards}</section><p class="boundary"><strong>Human control boundary:</strong> App Store submission, pricing, offers, experiments, review responses, and deployment remain locked.</p><p>Manifest SHA-256<br><code>{receipt["manifest"]["manifest_sha256"]}</code></p></main></body></html>'''


def build_revenue_bundle(root: Path, products_path: Path, out_dir: Path) -> dict[str, Any]:
    """Generate a bounded RevenueKit, server, disclosure, and evidence bundle."""
    workspace = Path(root).resolve()
    validated = validate_products(workspace, products_path)
    if not validated["ok"]:
        raise RevenueForgeError("REVENUEFORGE_GATES_BLOCKED", "manifest does not pass all deterministic monetization gates")
    destination = _local(workspace, out_dir, exists=False)
    manifest = validated["manifest"]
    files = {
        "revenuekit": destination / "ios" / "RevenueKit.swift",
        "paywall": destination / "ios" / "DSPaywall.swift",
        "server": destination / "server" / "entitlements.ts",
        "dataflow": destination / "evidence" / "dataflow.json",
        "privacy_label": destination / "evidence" / "privacy-label.json",
        "privacy_clause": destination / "evidence" / "privacy-policy-clause.md",
        "review_notes": destination / "evidence" / "subscription-review-notes.md",
        "evidence": destination / "revenue-evidence.html",
        "receipt": destination / "revenueforge.json",
    }
    dataflow = {"schema": "factory.dataflow.monetization.v1", "monetization": {"kind": "purchase_history", "linked_to_identity": True, "purpose": "app_functionality", "source": "StoreKit", "recipients": ["app_developer", "Apple"]}}
    receipt = {"schema": SCHEMA, "marker": "REVENUEFORGE_BUNDLE_WRITTEN", "markers": ["REVENUEFORGE_SERVER_SCAFFOLD_WRITTEN", "REVENUEFORGE_PAYWALL_SCAFFOLD_WRITTEN"], "manifest": manifest, "artifacts": {key: path.relative_to(workspace).as_posix() for key, path in files.items()}, "authority": AUTHORITY, "claim_boundary": "generated scaffold and deterministic local checks; not Apple approval, deployed entitlement-server proof, legal advice, or observed revenue"}
    receipt["receipt_sha256"] = _sha(receipt)
    _atomic(files["revenuekit"], _swift_kit(manifest))
    _atomic(files["paywall"], _swift_paywall(manifest))
    _atomic(files["server"], _server_scaffold(manifest))
    _atomic(files["dataflow"], json.dumps(dataflow, indent=2, sort_keys=True) + "\n")
    _atomic(files["privacy_label"], json.dumps({"data_type": "Purchases", "linked_to_user": True, "tracking": False, "purpose": "App Functionality", "requires_human_app_store_connect_confirmation": True}, indent=2, sort_keys=True) + "\n")
    _atomic(files["privacy_clause"], "## Purchases\n\nThe app processes purchase history linked to your account to provide paid features and restore access. Apple processes App Store transactions under its own terms. Confirm this clause with qualified counsel before publication.\n")
    _atomic(files["review_notes"], "# Subscription review notes\n\n- Products, benefits, prices, and durations appear before purchase.\n- Restore Purchases is available on the paywall.\n- Privacy Policy and Terms links are visible on the paywall.\n- Entitlements come from verified StoreKit transactions and a server designed to verify Apple-signed JWS before decoding.\n- Reviewer must supply live App Store Connect product IDs and a test account if required.\n")
    _atomic(files["evidence"], _evidence_html(receipt))
    _atomic(files["receipt"], json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return receipt


def plan_growth(root: Path, products_path: Path, growth_path: Path) -> dict[str, Any]:
    """Compile Phase 8 experiments and operations without performing provider writes."""
    manifest = validate_products(root, products_path)["manifest"]
    raw = _read_yaml(root, growth_path)
    experiments = raw.get("experiments", [])
    if not isinstance(experiments, list):
        raise RevenueForgeError("REVENUEFORGE_GROWTH_INVALID", "experiments must be a list")
    normalized_experiments = []
    for experiment in experiments:
        if not isinstance(experiment, dict):
            raise RevenueForgeError("REVENUEFORGE_GROWTH_INVALID", "each experiment must be an object")
        treatments = experiment.get("treatments", [])
        if not isinstance(treatments, list) or not 1 <= len(treatments) <= MAX_EXPERIMENT_TREATMENTS:
            raise RevenueForgeError("REVENUEFORGE_EXPERIMENT_REJECTED", "each PPO experiment requires 1-3 treatments")
        normalized_experiments.append({"id": _required_text(experiment.get("id"), "experiment.id"), "treatments": deepcopy(treatments), "promotion": "human_required", "provider_write": False})
    offers = raw.get("offers", [])
    if not isinstance(offers, list):
        raise RevenueForgeError("REVENUEFORGE_GROWTH_INVALID", "offers must be a list")
    result = {
        "schema": "factory.revenueforge.growth-plan.v1",
        "marker": "REVENUEFORGE_PHASE8_PLANNED",
        "manifest_sha256": manifest["manifest_sha256"],
        "experiments": sorted(normalized_experiments, key=lambda item: item["id"]),
        "custom_product_pages": sorted(raw.get("custom_product_pages", []), key=lambda item: str(item.get("id", ""))) if isinstance(raw.get("custom_product_pages", []), list) else [],
        "offers": [{**offer, "send": "human_required"} for offer in offers if isinstance(offer, dict)],
        "ratings_ops": {"prompt_after_success_only": True, "draft_response_only": True, "publication": "human_required"},
        "localization": {"storefront_price_schedule": "proposal_only", "human_confirmation": True},
        "aso": {"keyword_refresh": "proposal_only", "no_rank_claim_without_observation": True},
        "android_lane": {"status": "planned", "ruleset": "google-play-separate", "ios_policy_reuse_forbidden": True},
        "authority": AUTHORITY,
    }
    result["plan_sha256"] = _sha(result)
    return result


def benchmark_cell(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Publish a median only when at least twenty distinct apps contribute."""
    if not isinstance(records, list):
        raise RevenueForgeError("REVENUEFORGE_BENCHMARK_INVALID", "records must be a list")
    by_app: dict[str, float] = {}
    for record in records:
        if not isinstance(record, dict) or isinstance(record.get("value"), bool):
            raise RevenueForgeError("REVENUEFORGE_BENCHMARK_INVALID", "each record needs app_id and numeric value")
        app_id = _required_text(record.get("app_id"), "record.app_id")
        value = record.get("value")
        if not isinstance(value, (int, float)):
            raise RevenueForgeError("REVENUEFORGE_BENCHMARK_INVALID", "record.value must be numeric")
        by_app[app_id] = float(value)
    if len(by_app) < MIN_BENCHMARK_CELL:
        return {"schema": "factory.revenueforge.benchmark.v1", "marker": "REVENUEFORGE_BENCHMARK_WITHHELD", "published": False, "contributor_count": len(by_app), "minimum": MIN_BENCHMARK_CELL, "median": None}
    values = sorted(by_app.values())
    middle = len(values) // 2
    median = values[middle] if len(values) % 2 else (values[middle - 1] + values[middle]) / 2
    return {"schema": "factory.revenueforge.benchmark.v1", "marker": "REVENUEFORGE_BENCHMARK_PUBLISHED", "published": True, "contributor_count": len(by_app), "minimum": MIN_BENCHMARK_CELL, "median": median}


def revenueforge_projection(root: Path) -> dict[str, Any]:
    """Read generated RevenueForge receipts for a bounded Graph Ops projection."""
    workspace = Path(root).resolve()
    candidates = sorted((workspace / ".factory" / "revenueforge").glob("*/revenueforge.json"))[:100]
    current = 0
    invalid = 0
    latest: dict[str, Any] | None = None
    for path in candidates:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            expected = value.pop("receipt_sha256")
            valid = value.get("schema") == SCHEMA and _sha(value) == expected
            value["receipt_sha256"] = expected
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            valid = False
            value = None
        if valid:
            current += 1
            latest = value
        else:
            invalid += 1
    return {"marker": "GRAPH_OPS_REVENUEFORGE_READ_ONLY", "current_count": current, "invalid_count": invalid, "latest": latest, "authority": AUTHORITY}
