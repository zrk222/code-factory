"""Deterministic post-build evidence for RevenueForge purchase operations."""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import tempfile

from .revenueforge import AUTHORITY, MAX_INPUT_BYTES, RevenueForgeError, validate_products


REPLAY_SCHEMA = "factory.revenueforge.purchase-replay.v1"
INBOX_SCHEMA = "factory.revenueforge.testflight-inbox.v1"
MATRIX_SCHEMA = "factory.revenueforge.failure-matrix.v1"
DRIFT_SCHEMA = "factory.revenueforge.policy-drift.v1"
MEMORY_SCHEMA = "factory.revenueforge.evidence-memory.v1"
REQUIRED_JOURNEY = (
    "paywall_presented",
    "purchase_started",
    "transaction_verified",
    "server_notification_verified",
    "entitlement_active",
    "app_restarted",
    "entitlement_restored",
)
FAILURE_SCENARIOS = (
    "cancel",
    "pending",
    "unverified_transaction",
    "restore_empty",
    "duplicate_notification",
    "out_of_order_notification",
    "refund_or_revocation",
    "billing_retry_or_grace",
    "offline_stale_entitlement",
    "storefront_price_mismatch",
)
SENSITIVE_KEYS = {
    "email", "tester_email", "name", "first_name", "last_name", "phone",
    "ip", "ip_address", "device_name", "comment_raw", "signed_payload", "jws",
}


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


def _read_json(root: Path, value: Path) -> tuple[dict[str, Any], Path]:
    source = _local(root, value)
    if source.stat().st_size > MAX_INPUT_BYTES:
        raise RevenueForgeError("REVENUEFORGE_INPUT_TOO_LARGE", "evidence input exceeds 1 MiB")
    try:
        payload = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RevenueForgeError("REVENUEFORGE_EVIDENCE_INVALID", "evidence input is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise RevenueForgeError("REVENUEFORGE_EVIDENCE_INVALID", "evidence input must be an object")
    return payload, source


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _seal(root: Path, out: Path, payload: dict[str, Any]) -> dict[str, Any]:
    destination = _local(root, out, exists=False)
    sealed = {**payload, "authority": AUTHORITY}
    sealed["receipt_sha256"] = _sha(sealed)
    _atomic_json(destination, sealed)
    return {**sealed, "path": destination.relative_to(Path(root).resolve()).as_posix()}


def _required_object(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise RevenueForgeError("REVENUEFORGE_EVIDENCE_INVALID", f"{key} must be an object")
    return value


def _normalize_events(raw_events: object) -> list[dict[str, Any]]:
    if not isinstance(raw_events, list) or not raw_events or len(raw_events) > 500:
        raise RevenueForgeError("REVENUEFORGE_EVIDENCE_INVALID", "events must contain 1-500 objects")
    events: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    last_sequence = -1
    for raw in raw_events:
        if not isinstance(raw, dict) or isinstance(raw.get("sequence"), bool) or not isinstance(raw.get("sequence"), int):
            raise RevenueForgeError("REVENUEFORGE_EVIDENCE_INVALID", "each event needs an integer sequence")
        event_id, event_type = str(raw.get("id") or "").strip(), str(raw.get("type") or "").strip()
        if not event_id or event_id in seen_ids or raw["sequence"] <= last_sequence or not event_type:
            raise RevenueForgeError("REVENUEFORGE_EVENT_ORDER_INVALID", "event ids must be unique and sequence must strictly increase")
        seen_ids.add(event_id)
        last_sequence = raw["sequence"]
        events.append({"id": event_id, "sequence": raw["sequence"], "type": event_type, "product_id": str(raw.get("product_id") or "") or None, "verified": raw.get("verified") if isinstance(raw.get("verified"), bool) else None, "entitlement": str(raw.get("entitlement") or "") or None})
    return events


def _replay_step(event_type: str, candidates: list[dict[str, Any]], product_ids: set[str], prior_sequence: int) -> tuple[dict[str, Any], int]:
    if not candidates:
        return {"step": event_type, "status": "unknown", "reason": "no build-bound observation supplied"}, prior_sequence
    event, reasons = candidates[0], []
    if event["sequence"] <= prior_sequence:
        reasons.append("observed out of lifecycle order")
    if event_type in {"purchase_started", "transaction_verified", "server_notification_verified"} and event["product_id"] not in product_ids:
        reasons.append("product is not declared in the manifest")
    if event_type in {"transaction_verified", "server_notification_verified"} and event["verified"] is not True:
        reasons.append("cryptographic verification was not observed")
    status = "mismatch" if reasons else "matched"
    return {"step": event_type, "status": status, "event_id": event["id"], "sequence": event["sequence"], "reason": "; ".join(reasons) if reasons else "observed and manifest-consistent"}, max(prior_sequence, event["sequence"])


def _replay_steps(events: list[dict[str, Any]], product_ids: set[str]) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        by_type[event["type"]].append(event)
    steps, prior_sequence = [], -1
    for event_type in REQUIRED_JOURNEY:
        step, prior_sequence = _replay_step(event_type, by_type.get(event_type, []), product_ids, prior_sequence)
        steps.append(step)
    return steps, by_type


def _validated_build(payload: dict[str, Any], manifest: dict[str, Any]) -> dict[str, str]:
    build = _required_object(payload, "build")
    result = {
        "id": str(build.get("id") or "").strip(),
        "bundle_id": str(build.get("bundle_id") or "").strip(),
        "environment": str(build.get("environment") or "").strip().lower(),
    }
    valid = result["id"] and result["bundle_id"] == manifest["app"]["bundle_id"] and result["environment"] in {"sandbox", "testflight"}
    if not valid:
        raise RevenueForgeError("REVENUEFORGE_BUILD_BINDING_INVALID", "build id, matching bundle id, and sandbox/testflight environment are required")
    return result


def _replay_summary(steps: list[dict[str, Any]]) -> tuple[Counter[str], str, list[str]]:
    counts = Counter(step["status"] for step in steps)
    verdict = "matched" if counts["matched"] == len(REQUIRED_JOURNEY) else "blocked"
    markers = ["REVENUEFORGE_VERIFICATION_MISMATCH"] if counts["mismatch"] else []
    return counts, verdict, markers


def replay_purchase_journey(root: Path, products_path: Path, events_path: Path, out: Path) -> dict[str, Any]:
    """Compare observed purchase events with the required lifecycle without inference."""
    workspace = Path(root).resolve()
    manifest = validate_products(workspace, products_path)["manifest"]
    payload, source = _read_json(workspace, events_path)
    build = _validated_build(payload, manifest)
    events = _normalize_events(payload.get("events"))
    product_ids = {item["id"] for item in manifest["products"]}
    steps, by_type = _replay_steps(events, product_ids)
    optional = {event_type: "observed" if by_type.get(event_type) else "not_observed" for event_type in ("entitlement_expired", "entitlement_revoked")}
    counts, verdict, markers = _replay_summary(steps)
    core = {
        "schema": REPLAY_SCHEMA,
        "marker": "REVENUEFORGE_PURCHASE_REPLAYED",
        "action_summary": "Compare one sandbox or TestFlight build's observed purchase lifecycle with the reviewed product manifest; do not purchase, deploy, or contact Apple.",
        "markers": markers,
        "verdict": verdict,
        "build": build,
        "manifest_sha256": manifest["manifest_sha256"],
        "evidence_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "steps": steps,
        "optional_terminal_states": optional,
        "summary": {"matched": counts["matched"], "mismatch": counts["mismatch"], "unknown": counts["unknown"]},
        "claim_boundary": "observed build-bound event comparison only; not proof of App Review approval, production behavior, or revenue",
    }
    return _seal(workspace, out, core)


def _journey_for(text: str) -> str:
    value = text.lower()
    for key, terms in {
        "purchase": ("purchase", "paywall", "price", "subscribe"),
        "restore": ("restore", "reinstall"),
        "entitlement": ("access", "entitlement", "locked", "unlock"),
        "stability": ("crash", "freeze", "hang"),
        "cancellation": ("cancel", "renewal"),
    }.items():
        if any(term in value for term in terms):
            return key
    return "other"


def _feedback_item(raw: object) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise RevenueForgeError("REVENUEFORGE_TESTFLIGHT_INVALID", "each feedback item must be an object")
    if any(key in raw for key in ("signed_payload", "jws")):
        raise RevenueForgeError("REVENUEFORGE_TESTFLIGHT_SECRET_REJECTED", "signed payloads and JWS values are not accepted in the feedback inbox")
    external_id, build_id = str(raw.get("id") or "").strip(), str(raw.get("build_id") or "").strip()
    kind, summary = str(raw.get("kind") or "feedback").strip().lower(), str(raw.get("summary") or raw.get("comment") or "").strip()[:1000]
    if not external_id or not build_id or kind not in {"feedback", "screenshot", "crash"}:
        raise RevenueForgeError("REVENUEFORGE_TESTFLIGHT_INVALID", "id, build_id, and a supported kind are required")
    return {"id": hashlib.sha256(f"{external_id}\0{build_id}".encode()).hexdigest()[:24], "build_id": build_id, "kind": kind, "journey": _journey_for(summary), "summary": summary, "device_family": str(raw.get("device_family") or "unknown")[:80], "os_version": str(raw.get("os_version") or "unknown")[:40], "app_version": str(raw.get("app_version") or "unknown")[:40], "screenshot_ref": str(raw.get("screenshot_ref") or "")[:300] or None}


def sync_testflight_evidence(root: Path, feedback_path: Path, out: Path) -> dict[str, Any]:
    """Normalize an authorized TestFlight export into a privacy-bounded local inbox."""
    workspace = Path(root).resolve()
    payload, source = _read_json(workspace, feedback_path)
    items = payload.get("items")
    if not isinstance(items, list) or len(items) > 1000:
        raise RevenueForgeError("REVENUEFORGE_TESTFLIGHT_INVALID", "items must be a list of at most 1000 feedback records")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in items:
        item = _feedback_item(raw)
        if item["id"] in seen:
            continue
        seen.add(item["id"])
        normalized.append(item)
    normalized.sort(key=lambda item: (item["journey"], item["build_id"], item["id"]))
    groups = Counter(item["journey"] for item in normalized)
    kinds = Counter(item["kind"] for item in normalized)
    core = {
        "schema": INBOX_SCHEMA,
        "marker": "REVENUEFORGE_TESTFLIGHT_EVIDENCE_SYNCED",
        "action_summary": "Normalize an authorized local TestFlight export into a de-identified, build-bound issue inbox; do not fetch, reply, delete, or publish.",
        "source": {"kind": "authorized_local_export", "sha256": hashlib.sha256(source.read_bytes()).hexdigest()},
        "items": normalized,
        "groups": dict(sorted(groups.items())),
        "kinds": dict(sorted(kinds.items())),
        "redacted_fields": sorted(SENSITIVE_KEYS),
        "claim_boundary": "read-only local import; no App Store Connect request, tester reply, deletion, or publication was performed",
    }
    return _seal(workspace, out, core)


def evaluate_failure_matrix(root: Path, products_path: Path, evidence_path: Path, out: Path) -> dict[str, Any]:
    """Fail closed across deterministic monetization failure scenarios."""
    workspace = Path(root).resolve()
    manifest = validate_products(workspace, products_path)["manifest"]
    payload, source = _read_json(workspace, evidence_path)
    supplied = _required_object(payload, "scenarios")
    rows = [_matrix_row(scenario, supplied.get(scenario)) for scenario in FAILURE_SCENARIOS]
    counts = Counter(row["status"] for row in rows)
    verdict = "pass" if counts["pass"] == len(FAILURE_SCENARIOS) else "blocked"
    core = {
        "schema": MATRIX_SCHEMA,
        "marker": "REVENUEFORGE_FAILURE_MATRIX_EVALUATED",
        "action_summary": "Evaluate ten monetization failure paths from supplied observations; keep every absent or malformed result unknown.",
        "verdict": verdict,
        "manifest_sha256": manifest["manifest_sha256"],
        "evidence_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "rows": rows,
        "summary": {"pass": counts["pass"], "fail": counts["fail"], "unknown": counts["unknown"]},
        "claim_boundary": "green only when every declared negative path has observed passing evidence; unknown is never inferred as pass",
    }
    return _seal(workspace, out, core)


def _matrix_row(scenario: str, raw: object) -> dict[str, Any]:
    if raw is None:
        return {"scenario": scenario, "status": "unknown", "reason": "no observed negative-path evidence supplied"}
    if not isinstance(raw, dict) or raw.get("observed") is not True or not isinstance(raw.get("passed"), bool):
        return {"scenario": scenario, "status": "unknown", "reason": "observed=true and boolean passed are required"}
    return {"scenario": scenario, "status": "pass" if raw["passed"] else "fail", "evidence_ref": str(raw.get("evidence_ref") or "")[:300] or None, "reason": str(raw.get("reason") or "observed result")[:500]}


def _policy_sources(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    sources = payload.get("sources")
    if not isinstance(sources, list) or not sources or len(sources) > 200:
        raise RevenueForgeError("REVENUEFORGE_POLICY_INVALID", "sources must contain 1-200 objects")
    result: dict[str, dict[str, Any]] = {}
    for raw in sources:
        if not isinstance(raw, dict):
            raise RevenueForgeError("REVENUEFORGE_POLICY_INVALID", "each policy source must be an object")
        source_id = str(raw.get("id") or "").strip()
        url = str(raw.get("url") or "").strip()
        digest = str(raw.get("sha256") or "").strip().lower()
        retrieved_at = str(raw.get("retrieved_at") or "").strip()
        impacts = raw.get("impacts", [])
        if not source_id or source_id in result or not url.startswith("https://developer.apple.com/") or not re.fullmatch(r"[0-9a-f]{64}", digest) or not retrieved_at or not isinstance(impacts, list):
            raise RevenueForgeError("REVENUEFORGE_POLICY_INVALID", "policy source needs unique id, official Apple URL, retrieval date, sha256, and impacts")
        clean_impacts = []
        for impact in impacts:
            if not isinstance(impact, dict) or not str(impact.get("rule_id") or "").strip():
                raise RevenueForgeError("REVENUEFORGE_POLICY_INVALID", "each impact needs a rule_id")
            clean_impacts.append({
                "rule_id": str(impact["rule_id"]),
                "apps": sorted({str(v) for v in impact.get("apps", []) if str(v).strip()}),
                "artifacts": sorted({str(v) for v in impact.get("artifacts", []) if str(v).strip()}),
            })
        result[source_id] = {"id": source_id, "url": url, "retrieved_at": retrieved_at, "sha256": digest, "impacts": clean_impacts}
    return result


def watch_policy_drift(root: Path, registry_path: Path, snapshot_path: Path, out: Path) -> dict[str, Any]:
    """Invalidate only conclusions bound to changed official-source hashes."""
    workspace = Path(root).resolve()
    registry_raw, registry_source = _read_json(workspace, registry_path)
    snapshot_raw, snapshot_source = _read_json(workspace, snapshot_path)
    baseline = _policy_sources(registry_raw)
    current = _policy_sources(snapshot_raw)
    rows, affected = _policy_drift_rows(baseline, current)
    core = {
        "schema": DRIFT_SCHEMA,
        "marker": "REVENUEFORGE_POLICY_DRIFT_EVALUATED",
        "action_summary": "Compare reviewed official-Apple source hashes and identify only the declared conclusions that need human reassessment.",
        "verdict": "reassessment_required" if affected["rules"] else "current",
        "sources": rows,
        "affected": {key: sorted(values) for key, values in affected.items()},
        "registry_sha256": hashlib.sha256(registry_source.read_bytes()).hexdigest(),
        "snapshot_sha256": hashlib.sha256(snapshot_source.read_bytes()).hexdigest(),
        "claim_boundary": "content-hash drift detection only; changed sources require human policy interpretation and do not imply noncompliance",
    }
    return _seal(workspace, out, core)


def _accumulate_impacts(affected: dict[str, set[str]], impacts: list[dict[str, Any]]) -> None:
    for impact in impacts:
        affected["rules"].add(impact["rule_id"])
        affected["apps"].update(impact["apps"])
        affected["artifacts"].update(impact["artifacts"])


def _policy_drift_rows(baseline: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, set[str]]]:
    rows: list[dict[str, Any]] = []
    affected: dict[str, set[str]] = {"rules": set(), "apps": set(), "artifacts": set()}
    for source_id in sorted(set(baseline) | set(current)):
        before = baseline.get(source_id)
        after = current.get(source_id)
        status = "unchanged" if before and after and before["sha256"] == after["sha256"] else "changed"
        impacts = (before or after or {}).get("impacts", [])
        if status == "changed":
            _accumulate_impacts(affected, impacts)
        rows.append({"source_id": source_id, "status": status, "before_sha256": before and before["sha256"], "after_sha256": after and after["sha256"], "impacts": impacts if status == "changed" else []})
    return rows, affected


def _parse_time(value: object, field: str) -> datetime:
    text = str(value or "").strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise RevenueForgeError("REVENUEFORGE_MEMORY_INVALID", f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise RevenueForgeError("REVENUEFORGE_MEMORY_INVALID", f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _memory_fields(entry: dict[str, Any]) -> tuple[str, str, str, str, str, datetime, list[Any]]:
    values = (str(entry.get("app_id") or "").strip(), str(entry.get("journey") or "").strip().lower(), str(entry.get("decision") or "").strip(), str(entry.get("resolution") or "").strip(), str(entry.get("approved_by") or "").strip())
    expires_at, receipts = _parse_time(entry.get("expires_at"), "expires_at"), entry.get("evidence_receipts")
    if not all(values) or not isinstance(receipts, list) or not receipts:
        raise RevenueForgeError("REVENUEFORGE_MEMORY_INVALID", "app_id, journey, decision, resolution, approved_by, expiry, and evidence receipts are required")
    return (*values, expires_at, receipts)


def _memory_binding(workspace: Path, value: object) -> dict[str, str]:
    receipt_path = _local(workspace, Path(str(value)))
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        expected = receipt.pop("receipt_sha256")
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RevenueForgeError("REVENUEFORGE_MEMORY_EVIDENCE_INVALID", "each evidence receipt must be sealed JSON") from exc
    if _sha(receipt) != expected or not str(receipt.get("schema", "")).startswith("factory.revenueforge."):
        raise RevenueForgeError("REVENUEFORGE_MEMORY_EVIDENCE_INVALID", "receipt hash or schema is invalid")
    return {"path": receipt_path.relative_to(workspace).as_posix(), "sha256": expected, "schema": receipt["schema"]}


def promote_evidence_memory(root: Path, entry_path: Path, out: Path) -> dict[str, Any]:
    """Promote one human-approved, receipt-backed operational lesson."""
    workspace = Path(root).resolve()
    entry, source = _read_json(workspace, entry_path)
    app_id, journey, decision, resolution, approved_by, expires_at, receipt_paths = _memory_fields(entry)
    bindings = [_memory_binding(workspace, value) for value in receipt_paths]
    core = {
        "schema": MEMORY_SCHEMA,
        "marker": "REVENUEFORGE_EVIDENCE_MEMORY_PROMOTED",
        "action_summary": "Promote one named-human-approved, receipt-backed lesson for this exact app journey; do not reuse it across tenants or treat it as current-build proof.",
        "memory_id": _sha({"app_id": app_id, "journey": journey, "decision": decision, "bindings": bindings})[:24],
        "scope": {"app_id": app_id, "journey": journey, "cross_tenant_reuse": False},
        "decision": decision,
        "resolution": resolution,
        "approved_by": approved_by,
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "evidence": bindings,
        "entry_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "claim_boundary": "verified prior lesson for recommendation only; current builds require fresh evidence and human approval",
    }
    return _seal(workspace, out, core)


def query_evidence_memory(root: Path, app_id: str, journey: str, at: str | None = None) -> dict[str, Any]:
    """Retrieve exact-scope, unexpired lessons and quarantine contradictions."""
    workspace = Path(root).resolve()
    app = str(app_id or "").strip()
    lane = str(journey or "").strip().lower()
    now = _parse_time(at, "at") if at else datetime.now(timezone.utc)
    if not app or not lane:
        raise RevenueForgeError("REVENUEFORGE_MEMORY_INVALID", "app_id and journey are required")
    candidates, invalid = _memory_candidates(workspace, app, lane, now)
    status = _memory_status(candidates)
    return {
        "schema": "factory.revenueforge.evidence-memory-query.v1",
        "marker": "REVENUEFORGE_EVIDENCE_MEMORY_QUERIED",
        "action_summary": "Retrieve unexpired lessons for this exact app journey and quarantine contradictory decisions; always require fresh build evidence.",
        "status": status,
        "app_id": app,
        "journey": lane,
        "matches": [] if status == "quarantined" else candidates,
        "quarantined_count": len(candidates) if status == "quarantined" else 0,
        "invalid_count": invalid,
        "next_action": _memory_next_action(status),
        "authority": AUTHORITY,
        "claim_boundary": "retrieved prior evidence guides the next check; it never proves the current build",
    }


def _memory_candidates(workspace: Path, app: str, lane: str, now: datetime) -> tuple[list[dict[str, Any]], int]:
    candidates: list[dict[str, Any]] = []
    invalid = 0
    expected_scope = {"app_id": app, "journey": lane, "cross_tenant_reuse": False}
    for path in sorted((workspace / ".factory" / "revenueforge" / "memory").glob("*.json"))[:500]:
        value = _read_memory(path)
        if value is None:
            invalid += 1
        elif value["scope"] == expected_scope and _parse_time(value["expires_at"], "expires_at") > now:
            candidates.append(value)
    return candidates, invalid


def _memory_status(candidates: list[dict[str, Any]]) -> str:
    decisions = {item["decision"] for item in candidates}
    return "quarantined" if len(decisions) > 1 else "available" if candidates else "empty"


def _memory_next_action(status: str) -> str:
    return {"quarantined": "human contradiction review", "available": "collect fresh build evidence"}.get(status, "run the evidence workflow")


def _read_memory(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        expected = value.pop("receipt_sha256")
        valid = value.get("schema") == MEMORY_SCHEMA and _sha(value) == expected
        value["receipt_sha256"] = expected
        return value if valid else None
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return None


def revenue_evidence_projection(root: Path) -> dict[str, Any]:
    """Read at most 400 sealed evidence receipts for Graph Ops."""
    workspace = Path(root).resolve()
    patterns = {
        "replay": ("replay.json", REPLAY_SCHEMA),
        "testflight": ("testflight-inbox.json", INBOX_SCHEMA),
        "matrix": ("failure-matrix.json", MATRIX_SCHEMA),
        "policy": ("policy-drift.json", DRIFT_SCHEMA),
    }
    result: dict[str, Any] = {"marker": "GRAPH_OPS_REVENUE_EVIDENCE_READ_ONLY", "invalid_count": 0}
    for key, (filename, schema) in patterns.items():
        latest = None
        count = 0
        for path in sorted((workspace / ".factory" / "revenueforge").glob(f"*/{filename}"))[:100]:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                expected = value.pop("receipt_sha256")
                valid = value.get("schema") == schema and _sha(value) == expected
                value["receipt_sha256"] = expected
            except (OSError, json.JSONDecodeError, KeyError, TypeError):
                valid = False
                value = None
            if valid:
                count += 1
                latest = value
            else:
                result["invalid_count"] += 1
        result[key] = {"count": count, "latest": latest}
    result["authority"] = AUTHORITY
    return result
