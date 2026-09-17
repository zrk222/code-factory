"""Deterministic RevenueForge billing, experiment, and integrity controls."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import hashlib
import json
import math
import os
import re
import tempfile

from .revenueforge import (
    AUTHORITY,
    FORBIDDEN_PATTERNS,
    MAX_INPUT_BYTES,
    RevenueForgeError,
    validate_products,
)


LEDGER_SCHEMA = "factory.revenueforge.billing-ledger.v1"
EXPERIMENT_SCHEMA = "factory.revenueforge.experiment-plan.v1"
INTEGRITY_SCHEMA = "factory.revenueforge.integrity.v1"
EVENT_TYPES = {
    "purchase",
    "renewal",
    "refund",
    "revocation",
    "restore",
    "billing_retry",
    "grace",
}
VERIFIED_EVENTS = {"purchase", "renewal", "refund", "revocation", "restore"}
METRICS = {
    "purchase_conversion",
    "retention",
    "refund_rate",
    "crash_free_rate",
    "restore_success_rate",
}
OPERATORS = {"lt", "lte", "eq", "gte", "gt"}
PROVENANCE = {
    "human_confirmed",
    "trusted_source",
    "observed_production",
    "agent_proposed",
}
MAX_EVENTS = 1000
MAX_TREATMENTS = 3
MAX_GUARDRAILS = 8
MIN_SAMPLE = 20
MAX_SAMPLE = 1_000_000
EXTERNAL_AUTHORITY = {
    **AUTHORITY,
    "provider_write": False,
    "entitlement_grant": False,
    "experiment_start": False,
    "winner_promotion": False,
    "price_change": False,
}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _workspace_path(root: Path, value: Path, *, exists: bool = True) -> Path:
    workspace = Path(root).resolve()
    candidate = value if value.is_absolute() else workspace / value
    resolved = candidate.resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise RevenueForgeError(
            "REVENUEFORGE_PATH_REJECTED", "path must remain inside the workspace"
        ) from exc
    if exists and not resolved.is_file():
        raise RevenueForgeError(
            "REVENUEFORGE_INPUT_UNAVAILABLE", "input must be a regular file"
        )
    return resolved


def _read_json(root: Path, value: Path) -> tuple[dict[str, Any], Path]:
    source = _workspace_path(root, value)
    if source.stat().st_size > MAX_INPUT_BYTES:
        raise RevenueForgeError("REVENUEFORGE_INPUT_TOO_LARGE", "input exceeds 1 MiB")
    try:
        payload = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RevenueForgeError(
            "REVENUEFORGE_INPUT_INVALID", "input is not valid JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise RevenueForgeError("REVENUEFORGE_INPUT_INVALID", "input must be an object")
    return payload, source


def _write_json(root: Path, value: Path, payload: dict[str, Any]) -> dict[str, Any]:
    destination = _workspace_path(root, value, exists=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {**payload, "path": destination.relative_to(Path(root).resolve()).as_posix()}


def _sealed(root: Path, out: Path, payload: dict[str, Any]) -> dict[str, Any]:
    sealed = {**payload, "authority": EXTERNAL_AUTHORITY}
    sealed["receipt_sha256"] = _sha(sealed)
    return _write_json(root, out, sealed)


def _iso(value: object, field: str) -> str:
    text = str(value or "").strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise RevenueForgeError(
            "REVENUEFORGE_BILLING_INVALID", f"{field} must be an ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise RevenueForgeError(
            "REVENUEFORGE_BILLING_INVALID", f"{field} must include a timezone"
        )
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _build_binding(payload: dict[str, Any], manifest: dict[str, Any]) -> dict[str, str]:
    build = payload.get("build")
    if not isinstance(build, dict):
        raise RevenueForgeError(
            "REVENUEFORGE_BUILD_BINDING_INVALID", "build object is required"
        )
    result = {
        "id": str(build.get("id") or "").strip(),
        "bundle_id": str(build.get("bundle_id") or "").strip(),
        "environment": str(build.get("environment") or "").strip().lower(),
    }
    if (
        not result["id"]
        or result["bundle_id"] != manifest["app"]["bundle_id"]
        or result["environment"] not in {"sandbox", "testflight"}
    ):
        raise RevenueForgeError(
            "REVENUEFORGE_BUILD_BINDING_INVALID",
            "build id, matching bundle id, and sandbox/testflight environment are required",
        )
    return result


def _normalize_billing_event(
    raw: object, product_map: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise RevenueForgeError(
            "REVENUEFORGE_BILLING_INVALID", "each billing event must be an object"
        )
    provider = str(raw.get("provider") or "").strip().lower()
    event_type = str(raw.get("event_type") or "").strip().lower()
    transaction_id = str(raw.get("transaction_id") or "").strip()
    product_id = str(raw.get("product_id") or "").strip()
    event_id = str(raw.get("event_id") or raw.get("id") or "").strip()
    if (
        provider not in {"app_store", "play_store", "server"}
        or event_type not in EVENT_TYPES
        or not transaction_id
        or not product_id
        or not event_id
    ):
        raise RevenueForgeError(
            "REVENUEFORGE_BILLING_INVALID",
            "provider, event_id, transaction_id, product_id, and supported event_type are required",
        )
    if product_id not in product_map:
        raise RevenueForgeError(
            "REVENUEFORGE_BILLING_PRODUCT_UNDECLARED",
            f"product is not declared: {product_id}",
        )
    verified = raw.get("verified")
    if event_type in VERIFIED_EVENTS and verified is not True:
        raise RevenueForgeError(
            "REVENUEFORGE_BILLING_UNVERIFIED",
            f"{event_type} event must be cryptographically verified",
        )
    if not isinstance(verified, bool):
        raise RevenueForgeError(
            "REVENUEFORGE_BILLING_UNVERIFIED", "verified must be a boolean"
        )
    occurred_at = _iso(raw.get("occurred_at"), "occurred_at")
    entitlement = str(raw.get("entitlement") or "").strip()
    entitlements = set(product_map[product_id]["entitlements"])
    if entitlement and entitlement not in entitlements:
        raise RevenueForgeError(
            "REVENUEFORGE_BILLING_ENTITLEMENT_INVALID",
            f"entitlement is not declared for {product_id}: {entitlement}",
        )
    identity = f"{provider}\0{transaction_id}\0{occurred_at}"
    idempotency_key = _sha(identity)
    return {
        "event_id": event_id,
        "provider": provider,
        "event_type": event_type,
        "transaction_id": transaction_id,
        "product_id": product_id,
        "entitlement": entitlement or None,
        "occurred_at": occurred_at,
        "verified": verified,
        "idempotency_key": idempotency_key,
        "identity_key": _sha(identity),
    }


def _atomic_reconcile(
    events: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    unique: dict[str, dict[str, Any]] = {}
    duplicate_rows: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    by_identity: dict[str, dict[str, Any]] = {}
    for event in events:
        prior = unique.get(event["idempotency_key"])
        if prior is not None:
            comparable = ("product_id", "entitlement", "event_type", "verified")
            if any(prior[key] != event[key] for key in comparable):
                conflicts.append(
                    {
                        "type": "idempotency_conflict",
                        "idempotency_key": event["idempotency_key"],
                        "event_ids": [prior["event_id"], event["event_id"]],
                    }
                )
            else:
                duplicate_rows.append(
                    {
                        "event_id": event["event_id"],
                        "idempotency_key": event["idempotency_key"],
                        "duplicate_of": prior["event_id"],
                    }
                )
            continue
        identity = by_identity.get(event["identity_key"])
        if identity and identity["event_type"] != event["event_type"]:
            conflicts.append(
                {
                    "type": "timestamp_event_type_conflict",
                    "identity_key": event["identity_key"],
                    "event_ids": [identity["event_id"], event["event_id"]],
                }
            )
        by_identity[event["identity_key"]] = event
        unique[event["idempotency_key"]] = event
    by_transaction: dict[str, dict[str, Any]] = {}
    for event in unique.values():
        prior = by_transaction.get(event["transaction_id"])
        if prior and prior["product_id"] != event["product_id"]:
            conflicts.append(
                {
                    "type": "transaction_product_conflict",
                    "transaction_id": event["transaction_id"],
                    "event_ids": [prior["event_id"], event["event_id"]],
                }
            )
        by_transaction[event["transaction_id"]] = event
    ordered = sorted(
        unique.values(), key=lambda item: (item["occurred_at"], item["event_id"])
    )
    return ordered, duplicate_rows, conflicts


def _derive_states(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    states: dict[tuple[str, str], dict[str, Any]] = {}
    seen_purchase: set[tuple[str, str]] = set()
    for event in events:
        key = (event["transaction_id"], event["entitlement"] or event["product_id"])
        state = states.setdefault(
            key,
            {
                "transaction_id": event["transaction_id"],
                "product_id": event["product_id"],
                "entitlement": event["entitlement"],
                "state": "inactive",
                "last_event_type": None,
            },
        )
        if event["event_type"] in {"purchase", "renewal"}:
            state["state"] = "active"
            seen_purchase.add(key)
        elif event["event_type"] in {"refund", "revocation"}:
            state["state"] = "inactive"
        elif event["event_type"] == "restore" and key in seen_purchase:
            state["state"] = "active"
        state["last_event_type"] = event["event_type"]
    return [states[key] for key in sorted(states)]


def reconcile_billing_events(
    root: Path | str,
    products_path: Path | str,
    events_path: Path | str,
    out: Path | str,
) -> dict[str, Any]:
    """Reconcile verified billing observations with idempotent, read-only rules."""
    workspace = Path(root).resolve()
    manifest = validate_products(workspace, Path(products_path))["manifest"]
    payload, source = _read_json(workspace, Path(events_path))
    build = _build_binding(payload, manifest)
    raw_events = payload.get("events")
    if not isinstance(raw_events, list) or not 1 <= len(raw_events) <= MAX_EVENTS:
        raise RevenueForgeError(
            "REVENUEFORCE_BILLING_INVALID", "events must contain 1-1000 objects"
        )
    product_map = {item["id"]: item for item in manifest["products"]}
    normalized = [_normalize_billing_event(item, product_map) for item in raw_events]
    unique, duplicates, conflicts = _atomic_reconcile(normalized)
    states = _derive_states(unique)
    blocked = bool(conflicts)
    candidates = (
        []
        if blocked
        else [
            {
                "transaction_id": item["transaction_id"],
                "product_id": item["product_id"],
                "entitlement": item["entitlement"],
            }
            for item in states
            if item["state"] == "active"
        ]
    )
    result = {
        "schema": LEDGER_SCHEMA,
        "marker": "REVENUEFORGE_BILLING_CONFLICT"
        if blocked
        else "REVENUEFORGE_BILLING_RECONCILED",
        "control_id": "revenue.billing.reconciliation",
        "verdict": "BLOCKED" if blocked else "PASS",
        "action_summary": "Reconcile verified StoreKit, Play Billing, and server observations, collapse exact retries, and derive read-only entitlement states; do not grant access or contact a provider.",
        "build": build,
        "manifest_sha256": manifest["manifest_sha256"],
        "source_sha256": _sha_bytes(source.read_bytes()),
        "events": unique,
        "duplicates": duplicates,
        "conflicts": conflicts,
        "entitlement_states": states,
        "grant_candidates": candidates,
        "summary": {
            "input": len(normalized),
            "applied": len(unique),
            "duplicates": len(duplicates),
            "conflicts": len(conflicts),
            "active_entitlements": len(candidates),
        },
        "claim_boundary": "verified local observations and deterministic state transitions only; no entitlement write, provider request, customer identity, revenue, or production correctness claim",
    }
    return _sealed(workspace, Path(out), result)


def _contains_forbidden(value: object) -> bool:
    if isinstance(value, str):
        lowered = value.lower()
        return any(pattern in lowered for pattern in FORBIDDEN_PATTERNS)
    if isinstance(value, dict):
        return any(_contains_forbidden(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_forbidden(item) for item in value)
    return False


def _experiment_approval(
    raw: object, experiment_id: str, proposed_by: str
) -> dict[str, str] | None:
    if raw is None:
        return None
    if not isinstance(raw, dict) or str(raw.get("decision") or "") != "approved":
        raise RevenueForgeError(
            "REVENUEFORGE_EXPERIMENT_APPROVAL_INVALID",
            "approval must contain decision=approved",
        )
    approver = str(raw.get("approved_by") or "").strip()
    approved_at = _iso(raw.get("approved_at"), "approval.approved_at")
    digest = str(raw.get("approval_sha256") or "").strip().lower()
    if (
        not approver
        or approver == proposed_by
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
    ):
        raise RevenueForgeError(
            "REVENUEFORGE_EXPERIMENT_SOD_VIOLATION",
            "approver must be distinct and approval_sha256 must be 64 hex characters",
        )
    expected = _sha(
        {
            "experiment_id": experiment_id,
            "approved_by": approver,
            "approved_at": approved_at,
        }
    )
    if digest != expected:
        raise RevenueForgeError(
            "REVENUEFORGE_EXPERIMENT_APPROVAL_INVALID",
            "approval hash does not match the approved experiment",
        )
    return {
        "approved_by": approver,
        "approved_at": approved_at,
        "approval_sha256": digest,
        "decision": "approved",
    }


def plan_revenue_experiment(
    root: Path | str,
    products_path: Path | str,
    experiment_path: Path | str,
    out: Path | str,
) -> dict[str, Any]:
    """Compile a guarded experiment plan without starting or promoting it."""
    workspace = Path(root).resolve()
    manifest = validate_products(workspace, Path(products_path))["manifest"]
    raw, source = _read_json(workspace, Path(experiment_path))
    forbidden_authority = {
        "price",
        "price_change",
        "winner",
        "promote_winner",
        "release_decision",
        "start_now",
    }
    if forbidden_authority.intersection(raw):
        raise RevenueForgeError(
            "REVENUEFORGE_EXPERIMENT_AUTHORITY_REJECTED",
            "experiment plans cannot change prices, choose winners, or start provider work",
        )
    experiment_id = str(raw.get("id") or "").strip()
    proposed_by = str(raw.get("proposed_by") or "").strip()
    hypothesis = str(raw.get("hypothesis") or "").strip()
    primary_metric = str(raw.get("primary_metric") or "").strip()
    provenance = str(raw.get("provenance") or "agent_proposed").strip()
    if (
        not experiment_id
        or not proposed_by
        or not hypothesis
        or primary_metric not in METRICS
        or provenance not in PROVENANCE
    ):
        raise RevenueForgeError(
            "REVENUEFORGE_EXPERIMENT_INVALID",
            "id, proposed_by, hypothesis, and supported primary_metric are required",
        )
    if _contains_forbidden(raw):
        raise RevenueForgeError(
            "REVENUEFORGE_DARK_PATTERN_REJECTED",
            "experiment content contains a forbidden paywall pattern",
        )
    treatments = raw.get("treatments")
    if not isinstance(treatments, list) or not 2 <= len(treatments) <= MAX_TREATMENTS:
        raise RevenueForgeError(
            "REVENUEFORGE_EXPERIMENT_INVALID", "treatments must contain 2-3 variants"
        )
    product_ids = {item["id"] for item in manifest["products"]}
    normalized_treatments: list[dict[str, Any]] = []
    treatment_ids: set[str] = set()
    roles: Counter[str] = Counter()
    for treatment in treatments:
        if not isinstance(treatment, dict):
            raise RevenueForgeError(
                "REVENUEFORGE_EXPERIMENT_INVALID", "each treatment must be an object"
            )
        treatment_id = str(treatment.get("id") or "").strip()
        role = str(treatment.get("role") or "").strip().lower()
        ids = treatment.get("product_ids", [])
        if (
            not treatment_id
            or treatment_id in treatment_ids
            or role not in {"control", "variant"}
            or not isinstance(ids, list)
            or not ids
            or not set(ids).issubset(product_ids)
        ):
            raise RevenueForgeError(
                "REVENUEFORGE_EXPERIMENT_INVALID",
                "treatments need unique ids, one control/variant role, and declared product_ids",
            )
        treatment_ids.add(treatment_id)
        roles[role] += 1
        normalized_treatments.append(
            {
                "id": treatment_id,
                "role": role,
                "product_ids": sorted(set(str(item) for item in ids)),
                "label": str(treatment.get("label") or treatment_id).strip()[:200],
            }
        )
    if roles["control"] != 1 or roles["variant"] < 1:
        raise RevenueForgeError(
            "REVENUEFORGE_EXPERIMENT_INVALID",
            "exactly one control and at least one variant are required",
        )
    guardrails = raw.get("guardrails")
    if not isinstance(guardrails, list) or not 1 <= len(guardrails) <= MAX_GUARDRAILS:
        raise RevenueForgeError(
            "REVENUEFORGE_EXPERIMENT_INVALID", "1-8 numeric guardrails are required"
        )
    normalized_guardrails: list[dict[str, Any]] = []
    for guardrail in guardrails:
        if (
            not isinstance(guardrail, dict)
            or str(guardrail.get("metric") or "") not in METRICS
            or str(guardrail.get("operator") or "") not in OPERATORS
        ):
            raise RevenueForgeError(
                "REVENUEFORGE_EXPERIMENT_INVALID",
                "guardrails need supported metric and operator",
            )
        threshold = guardrail.get("threshold")
        if (
            isinstance(threshold, bool)
            or not isinstance(threshold, (int, float))
            or not math.isfinite(float(threshold))
        ):
            raise RevenueForgeError(
                "REVENUEFORGE_EXPERIMENT_INVALID",
                "guardrail threshold must be finite numeric",
            )
        normalized_guardrails.append(
            {
                "metric": str(guardrail["metric"]),
                "operator": str(guardrail["operator"]),
                "threshold": float(threshold),
            }
        )
    cohort = raw.get("cohort")
    if (
        not isinstance(cohort, dict)
        or not str(cohort.get("name") or "").strip()
        or isinstance(cohort.get("allocation_percent"), bool)
        or not isinstance(cohort.get("allocation_percent"), (int, float))
        or not 1 <= float(cohort["allocation_percent"]) <= 100
    ):
        raise RevenueForgeError(
            "REVENUEFORGE_EXPERIMENT_INVALID",
            "cohort name and allocation_percent 1-100 are required",
        )
    window_days = raw.get("window_days")
    sample_size = raw.get("minimum_sample_size")
    if (
        isinstance(window_days, bool)
        or not isinstance(window_days, int)
        or not 1 <= window_days <= 90
        or isinstance(sample_size, bool)
        or not isinstance(sample_size, int)
        or not MIN_SAMPLE <= sample_size <= MAX_SAMPLE
    ):
        raise RevenueForgeError(
            "REVENUEFORGE_EXPERIMENT_INVALID",
            "window_days must be 1-90 and minimum_sample_size must be 20-1000000",
        )
    approval = _experiment_approval(raw.get("approval"), experiment_id, proposed_by)
    normalized = {
        "schema": EXPERIMENT_SCHEMA,
        "marker": "REVENUEFORGE_EXPERIMENT_PLAN_COMPILED",
        "action_summary": "Compile a hypothesis-led, guardrail-bounded experiment plan; do not start traffic, change prices, promote a winner, or contact a provider.",
        "experiment_id": experiment_id,
        "proposed_by": proposed_by,
        "provenance": provenance,
        "hypothesis": hypothesis,
        "primary_metric": primary_metric,
        "treatments": sorted(normalized_treatments, key=lambda item: item["id"]),
        "guardrails": sorted(
            normalized_guardrails,
            key=lambda item: (item["metric"], item["operator"], item["threshold"]),
        ),
        "cohort": {
            "name": str(cohort["name"]).strip(),
            "allocation_percent": float(cohort["allocation_percent"]),
        },
        "window_days": window_days,
        "minimum_sample_size": sample_size,
        "approval": approval,
        "status": "READY_FOR_HUMAN_START" if approval else "AWAITING_HUMAN_APPROVAL",
        "next_action": "human_start_approval"
        if approval
        else "obtain_independent_human_approval",
        "results": None,
        "authority": EXTERNAL_AUTHORITY,
        "source_sha256": _sha_bytes(source.read_bytes()),
        "claim_boundary": "plan-only; no observed lift, revenue result, provider write, price change, experiment start, or winner promotion",
    }
    normalized["plan_sha256"] = _sha(normalized)
    return _sealed(workspace, Path(out), normalized)


def _verify_sealed(root: Path, path: Path, schema: str) -> tuple[dict[str, Any], str]:
    payload, source = _read_json(root, path)
    expected = str(payload.get("receipt_sha256") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise RevenueForgeError(
            "REVENUEFORGE_RECEIPT_INVALID", f"{path} lacks a valid receipt_sha256"
        )
    body = dict(payload)
    body.pop("receipt_sha256", None)
    if payload.get("schema") != schema or _sha(body) != expected:
        raise RevenueForgeError(
            "REVENUEFORGE_RECEIPT_INVALID", f"receipt hash or schema is invalid: {path}"
        )
    return payload, _sha_bytes(source.read_bytes())


def evaluate_revenue_integrity(
    root: Path | str,
    products_path: Path | str,
    ledger_path: Path | str,
    experiment_path: Path | str | None = None,
    baseline_path: Path | str | None = None,
    out: Path | str = ".factory/revenueforge/default/integrity.json",
) -> dict[str, Any]:
    """Evaluate manifest, billing, experiment, and baseline integrity without provider actions."""
    workspace = Path(root).resolve()
    manifest = validate_products(workspace, Path(products_path))["manifest"]
    ledger, ledger_file_sha = _verify_sealed(
        workspace, Path(ledger_path), LEDGER_SCHEMA
    )
    findings: list[dict[str, Any]] = []
    controls = [
        {
            "id": "revenue.manifest",
            "status": "PASSED",
            "reason": "current manifest validated",
        }
    ]
    if ledger.get("manifest_sha256") != manifest["manifest_sha256"]:
        findings.append(
            {
                "code": "E_MANIFEST_DRIFT",
                "message": "billing evidence is bound to a different manifest",
                "expected": manifest["manifest_sha256"],
                "actual": ledger.get("manifest_sha256"),
            }
        )
    if ledger.get("verdict") != "PASS":
        findings.append(
            {
                "code": "E_BILLING_RECONCILIATION_BLOCKED",
                "message": "billing ledger contains a conflict or blocked observation",
            }
        )
    billing_blocked = (
        ledger.get("verdict") != "PASS"
        or ledger.get("manifest_sha256") != manifest["manifest_sha256"]
    )
    controls.append(
        {
            "id": "revenue.billing.reconciliation",
            "status": "BLOCKED" if billing_blocked else "PASSED",
            "receipt_sha256": ledger.get("receipt_sha256"),
        }
    )
    experiment = None
    experiment_file_sha = None
    if experiment_path is not None:
        experiment, experiment_file_sha = _verify_sealed(
            workspace, Path(experiment_path), EXPERIMENT_SCHEMA
        )
        if experiment.get("status") == "AWAITING_HUMAN_APPROVAL":
            findings.append(
                {
                    "code": "E_EXPERIMENT_APPROVAL_REQUIRED",
                    "message": "experiment plan is not independently approved",
                }
            )
        controls.append(
            {
                "id": "revenue.experiment.guardrails",
                "status": "PASSED"
                if experiment.get("status") == "READY_FOR_HUMAN_START"
                else "BLOCKED",
                "receipt_sha256": experiment.get("receipt_sha256"),
            }
        )
    else:
        controls.append(
            {
                "id": "revenue.experiment.guardrails",
                "status": "ADVISORY",
                "reason": "no experiment plan supplied",
            }
        )
    if baseline_path is not None:
        baseline_raw, _ = _read_json(workspace, Path(baseline_path))
        baseline_hash = str(
            baseline_raw.get("manifest_sha256")
            if isinstance(baseline_raw, dict)
            else baseline_raw
        ).strip()
        if baseline_hash and baseline_hash != manifest["manifest_sha256"]:
            findings.append(
                {
                    "code": "E_MANIFEST_DRIFT",
                    "message": "current manifest differs from the approved baseline",
                    "expected": baseline_hash,
                    "actual": manifest["manifest_sha256"],
                }
            )
    blocked = bool(findings)
    next_action = (
        "human_manifest_reassessment"
        if any(item["code"] == "E_MANIFEST_DRIFT" for item in findings)
        else (
            "review_billing_conflict"
            if any(
                item["code"] == "E_BILLING_RECONCILIATION_BLOCKED" for item in findings
            )
            else (
                "obtain_independent_human_approval"
                if any(
                    item["code"] == "E_EXPERIMENT_APPROVAL_REQUIRED"
                    for item in findings
                )
                else "human_release_review"
            )
        )
    )
    result = {
        "schema": INTEGRITY_SCHEMA,
        "marker": "REVENUEFORGE_INTEGRITY_REVIEW_REQUIRED"
        if blocked
        else "REVENUEFORGE_INTEGRITY_READY",
        "control_id": "revenue.integrity",
        "verdict": "BLOCKED" if blocked else "PASS",
        "decision": "REVIEW_REQUIRED" if blocked else "READY_FOR_HUMAN_REVIEW",
        "action_summary": "Compare the current monetization manifest with hash-bound billing and experiment evidence, surface drift, and return one human remediation; do not publish, price, deploy, or grant access.",
        "manifest_sha256": manifest["manifest_sha256"],
        "evidence": {
            "ledger_sha256": ledger_file_sha,
            "experiment_sha256": experiment_file_sha,
        },
        "controls": controls,
        "findings": findings,
        "next_action": next_action,
        "claim_boundary": "local integrity review only; no revenue, legal, App Review, provider, entitlement, or production claim",
    }
    return _sealed(workspace, Path(out), result)


def revenue_integrity_projection(root: Path | str = ".") -> dict[str, Any]:
    """Read bounded RevenueForge integrity receipts for Graph Ops projection."""
    workspace = Path(root).resolve()
    candidates = sorted((workspace / ".factory" / "revenueforge").rglob("*.json"))[:200]
    latest: dict[str, dict[str, Any] | None] = {
        "ledger": None,
        "experiment": None,
        "integrity": None,
    }
    counts = {"ledger": 0, "experiment": 0, "integrity": 0}
    invalid = 0
    schemas = {
        LEDGER_SCHEMA: "ledger",
        EXPERIMENT_SCHEMA: "experiment",
        INTEGRITY_SCHEMA: "integrity",
    }
    for path in candidates:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            expected = str(payload.get("receipt_sha256") or "")
            body = dict(payload)
            body.pop("receipt_sha256", None)
            kind = schemas.get(str(payload.get("schema")))
            if kind is None or _sha(body) != expected:
                continue
            counts[kind] += 1
            existing = latest[kind]
            if existing is None or str(
                payload.get("evaluated_at", payload.get("generated_at", ""))
            ) >= str(existing.get("evaluated_at", existing.get("generated_at", ""))):
                latest[kind] = {
                    **payload,
                    "path": path.relative_to(workspace).as_posix(),
                }
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError):
            invalid += 1
    return {
        "marker": "GRAPH_OPS_REVENUEFORGE_INTEGRITY_READ_ONLY",
        "counts": counts,
        "invalid_count": invalid,
        "latest": latest,
        "authority": EXTERNAL_AUTHORITY,
    }
