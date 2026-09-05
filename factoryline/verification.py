"""Fail-closed local readiness decisions over receipt-backed factory stages.

``shippable`` means every required local gate has a current passing receipt. It
does not mean an external provider accepted, deployed, signed, or approved a
release. Incomplete pipelines therefore stay non-shippable.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .assembly import rollup_receipts


LABELS = {"specline": "SPEC", "forgeline": "FORGE", "hsf": "COMPILE", "prestige": "DESIGN"}
BASE_REQUIRED = {
    "specline": frozenset({"strict", "verify-validators", "gate-spec", "tasks", "gate-plan"}),
    "forgeline": frozenset({"architect", "review", "arch-gate", "verify-tests", "smoke", "ship"}),
}


def _release_declares(root: Path, feature: str, path: Path | None, stage: str) -> bool:
    """Read one declared required stage without treating the file as valid.

    Strict verification subsequently validates the whole Oracle-bound release
    contract.  This early, bounded read only ensures a declared UI/compiler
    gate cannot be silently omitted while that validation is underway.
    """
    source = path or root / ".factory" / "release-contracts" / f"{feature}.json"
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    stages = value.get("required_stages") if isinstance(value, dict) else None
    return isinstance(stages, list) and stage in stages


def _declares_ui(root: Path, feature: str, rows: list[dict[str, Any]], declared: set[str]) -> bool:
    return (root / "smoke" / f"{feature}.ui").is_file() or any(row["module"] == "prestige" for row in rows) or "prestige:score" in declared


def _declares_hsf(root: Path, feature: str, rows: list[dict[str, Any]], declared: set[str]) -> bool:
    return (root / "specs" / f"{feature}.yaml").is_file() or any(row["module"] == "hsf" for row in rows) or "hsf:compile" in declared


def _required_stages(root: Path, feature: str, rows: list[dict[str, Any]], declared: set[str] | None = None) -> dict[str, frozenset[str]]:
    required = dict(BASE_REQUIRED)
    declared = declared or set()
    if _declares_ui(root, feature, rows, declared):
        required["prestige"] = frozenset({"score"})
    if _declares_hsf(root, feature, rows, declared):
        required["hsf"] = frozenset({"compile"})
    return required


def _ship_intent_failure(rows: list[dict[str, Any]]) -> dict[str, str] | None:
    ships = [row for row in rows if row["module"] == "forgeline" and row["stage"] == "ship"]
    if not ships:
        return {"code": "REQUIRED_STAGE_MISSING", "detail": "forgeline:ship receipt is missing"}
    outputs = ships[-1].get("outputs")
    if not isinstance(outputs, dict):
        return {"code": "INTENT_TRACE_MISSING", "detail": "ship receipt outputs are not an object"}
    trace = outputs.get("intent_trace")
    if not isinstance(trace, dict):
        return {"code": "INTENT_TRACE_MISSING", "detail": "ship receipt lacks a bound intent trace"}
    if trace.get("intent_traceable") is not True or trace.get("shipped") is not True:
        return {"code": "INTENT_TRACE_UNVERIFIED", "detail": "ship receipt does not prove traceable intent"}
    return None


def verify_feature(root: Path, feature: str, *, strict_release: bool = False,
                   release_contract_path: Path | None = None) -> dict:
    """Fail closed for absent, failed, malformed, or incomplete gate evidence."""
    workspace = Path(root)
    rollup = rollup_receipts(workspace, feature)
    rows = rollup["stages"]
    by_module = {module: [] for module in LABELS}
    for stage in rows:
        by_module.setdefault(stage["module"], []).append(stage)
    contract_path = release_contract_path or workspace / ".factory" / "release-contracts" / f"{feature}.json"
    declared = {
        stage for stage in ("prestige:score", "hsf:compile")
        if strict_release and _release_declares(workspace, feature, contract_path, stage)
    }
    required = _required_stages(workspace, feature, rows, declared)
    blockers: list[dict[str, str]] = []
    snapshot = rollup.get("receipt_snapshot", {})
    if snapshot.get("truncated"):
        blockers.append({"code": "RECEIPT_SNAPSHOT_TRUNCATED", "detail": "receipt scan was bounded before the complete evidence set was observed"})
    for invalid in rollup.get("receipt_snapshot", {}).get("invalid", []):
        blockers.append({"code": "RECEIPT_INVALID", "detail": f"{invalid['path']}: {invalid['reason']}"})
    modules = []
    for module, label in LABELS.items():
        module_rows = by_module[module]
        failed = [row for row in module_rows if row["status"] == "failed" or (row.get("rate") is not None and row["rate"] < 1.0)]
        expected = required.get(module, frozenset())
        passing = {row["stage"] for row in module_rows if row["status"] == "ok"}
        missing = sorted(expected - passing)
        for stage in missing:
            blockers.append({"code": "REQUIRED_STAGE_MISSING", "detail": f"{module}:{stage} receipt is missing or non-passing"})
        for row in failed:
            blockers.append({"code": "STAGE_FAILED", "detail": f"{module}:{row['stage']} is failing"})
        modules.append({"module": module, "label": label, "required": sorted(expected), "missing": missing,
                        "status": "failed" if failed else "incomplete" if missing else "passed" if expected else "not_applicable",
                        "stages": module_rows})
    intent_failure = _ship_intent_failure(rows)
    if intent_failure is not None:
        blockers.append(intent_failure)
    declared_stage_ids = {f"{module}:{stage}" for module, stages in required.items() for stage in stages}
    release_contract: dict[str, Any] = {"status": "not_requested"}
    if strict_release:
        from .release_contract import verify_release_contract

        release_contract = verify_release_contract(workspace, feature, contract_path, declared_stage_ids)
        if not release_contract.get("ok"):
            blockers.append({"code": str(release_contract.get("marker", "RELEASE_CONTRACT_INVALID")),
                             "detail": str(release_contract.get("reason", "release contract is not valid"))})
        else:
            # Every selected gate receipt must carry the same sealed Oracle and
            # policy digests.  A valid contract with empty/unbound stage files
            # is not a release proof; it is merely a collection of green claims.
            expected_oracle = release_contract.get("oracle_contract_sha256")
            expected_policy = release_contract.get("policy_digest")
            for module_name, stages in required.items():
                for stage_name in stages:
                    matches = [row for row in by_module.get(module_name, []) if row.get("stage") == stage_name and row.get("status") == "ok"]
                    for row in matches[-1:]:
                        inputs = row.get("inputs")
                        if not isinstance(inputs, dict):
                            blockers.append({"code": "RECEIPT_ORACLE_BINDING_MISSING", "detail": f"{module_name}:{stage_name} receipt inputs are not an object"})
                            continue
                        if inputs.get("oracle_contract_sha256") != expected_oracle:
                            blockers.append({"code": "RECEIPT_ORACLE_BINDING_MISMATCH", "detail": f"{module_name}:{stage_name} is not bound to the current Oracle contract"})
                        if inputs.get("release_contract_policy_digest") != expected_policy:
                            blockers.append({"code": "RECEIPT_POLICY_BINDING_MISMATCH", "detail": f"{module_name}:{stage_name} is not bound to the current release policy"})
    earliest = rollup.get("earliest_failing_stage")
    if earliest:
        next_action = f"factory risk-diff --root {workspace} --changed <changed-path>"
    elif blockers:
        next_action = f"factory assemble {feature} --root {workspace}"
    else:
        next_action = f"factory trace {feature} --root {workspace}"
    shippable = bool(rows) and not earliest and not blockers
    return {
        "schema": "factory.verify.v2", "feature": feature, "root": str(workspace),
        "shippable": shippable, "release_ready": shippable and (not strict_release or release_contract.get("ok") is True),
        "strict_release": strict_release, "release_contract": release_contract, "modules": modules, "rollup": rollup,
        "blockers": blockers, "next_action": next_action,
        "scope_limits": [
            "Evaluates stable local receipt evidence only; it does not run missing gates.",
            "A passing local decision is not an external deployment, signing, publication, provider-state readback, or approval.",
            "AppForge is required only when the feature declares a mobile decision spec; Prestige is required only when UI scope is declared.",
        ],
    }
