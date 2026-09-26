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


LABELS = {
    "specline": "SPEC",
    "forgeline": "FORGE",
    "hsf": "COMPILE",
    "prestige": "DESIGN",
}
BASE_REQUIRED = {
    "specline": frozenset(
        {"strict", "verify-validators", "gate-spec", "tasks", "gate-plan"}
    ),
    "forgeline": frozenset(
        {"architect", "review", "arch-gate", "verify-tests", "smoke", "ship"}
    ),
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


def _declares_ui(
    root: Path, feature: str, rows: list[dict[str, Any]], declared: set[str]
) -> bool:
    return (
        (root / "smoke" / f"{feature}.ui").is_file()
        or any(row["module"] == "prestige" for row in rows)
        or "prestige:score" in declared
    )


def _declares_hsf(
    root: Path, feature: str, rows: list[dict[str, Any]], declared: set[str]
) -> bool:
    return (
        (root / "specs" / f"{feature}.yaml").is_file()
        or any(row["module"] == "hsf" for row in rows)
        or "hsf:compile" in declared
    )


def _required_stages(
    root: Path,
    feature: str,
    rows: list[dict[str, Any]],
    declared: set[str] | None = None,
) -> dict[str, frozenset[str]]:
    required = dict(BASE_REQUIRED)
    declared = declared or set()
    if _declares_ui(root, feature, rows, declared):
        required["prestige"] = frozenset({"score"})
    if _declares_hsf(root, feature, rows, declared):
        required["hsf"] = frozenset({"compile"})
    return required


def _ship_intent_failure(rows: list[dict[str, Any]]) -> dict[str, str] | None:
    ships = [
        row for row in rows if row["module"] == "forgeline" and row["stage"] == "ship"
    ]
    if not ships:
        return {
            "code": "REQUIRED_STAGE_MISSING",
            "detail": "forgeline:ship receipt is missing",
        }
    outputs = ships[-1].get("outputs")
    if not isinstance(outputs, dict):
        return {
            "code": "INTENT_TRACE_MISSING",
            "detail": "ship receipt outputs are not an object",
        }
    trace = outputs.get("intent_trace")
    if not isinstance(trace, dict):
        return {
            "code": "INTENT_TRACE_MISSING",
            "detail": "ship receipt lacks a bound intent trace",
        }
    if trace.get("intent_traceable") is not True or trace.get("shipped") is not True:
        return {
            "code": "INTENT_TRACE_UNVERIFIED",
            "detail": "ship receipt does not prove traceable intent",
        }
    return None


def _stages_by_module(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    by_module = {module: [] for module in LABELS}
    for stage in rows:
        by_module.setdefault(stage["module"], []).append(stage)
    return by_module


def _snapshot_blockers(rollup: dict[str, Any]) -> list[dict[str, str]]:
    snapshot = rollup.get("receipt_snapshot", {})
    blockers = []
    if snapshot.get("truncated"):
        blockers.append(
            {
                "code": "RECEIPT_SNAPSHOT_TRUNCATED",
                "detail": "receipt scan was bounded before the complete evidence set was observed",
            }
        )
    blockers.extend(
        {"code": "RECEIPT_INVALID", "detail": f"{item['path']}: {item['reason']}"}
        for item in snapshot.get("invalid", [])
    )
    return blockers


def _module_result(
    module: str, label: str, rows: list[dict[str, Any]], expected: frozenset[str]
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    failed = [
        row
        for row in rows
        if row["status"] == "failed"
        or (row.get("rate") is not None and row["rate"] < 1.0)
    ]
    passing = {row["stage"] for row in rows if row["status"] == "ok"}
    missing = sorted(expected - passing)
    blockers = _module_blockers(module, failed, missing)
    status = _module_status(failed, missing, expected)
    return {
        "module": module,
        "label": label,
        "required": sorted(expected),
        "missing": missing,
        "status": status,
        "stages": rows,
    }, blockers


def _module_blockers(
    module: str, failed: list[dict[str, Any]], missing: list[str]
) -> list[dict[str, str]]:
    blockers = [
        {
            "code": "REQUIRED_STAGE_MISSING",
            "detail": f"{module}:{stage} receipt is missing or non-passing",
        }
        for stage in missing
    ]
    blockers.extend(
        {"code": "STAGE_FAILED", "detail": f"{module}:{row['stage']} is failing"}
        for row in failed
    )
    return blockers


def _module_status(
    failed: list[dict[str, Any]], missing: list[str], expected: frozenset[str]
) -> str:
    if failed:
        return "failed"
    if missing:
        return "incomplete"
    return "passed" if expected else "not_applicable"


def _module_audit(
    by_module: dict[str, list[dict[str, Any]]], required: dict[str, frozenset[str]]
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    modules, blockers = [], []
    for module, label in LABELS.items():
        result, module_blockers = _module_result(
            module, label, by_module[module], required.get(module, frozenset())
        )
        modules.append(result)
        blockers.extend(module_blockers)
    return modules, blockers


def _stage_contract_binding_blockers(
    module: str,
    stage: str,
    rows: list[dict[str, Any]],
    expected_oracle: Any,
    expected_policy: Any,
) -> list[dict[str, str]]:
    matches = [
        row for row in rows if row.get("stage") == stage and row.get("status") == "ok"
    ][-1:]
    blockers = []
    for row in matches:
        inputs = row.get("inputs")
        if not isinstance(inputs, dict):
            return [
                {
                    "code": "RECEIPT_ORACLE_BINDING_MISSING",
                    "detail": f"{module}:{stage} receipt inputs are not an object",
                }
            ]
        if inputs.get("oracle_contract_sha256") != expected_oracle:
            blockers.append(
                {
                    "code": "RECEIPT_ORACLE_BINDING_MISMATCH",
                    "detail": f"{module}:{stage} is not bound to the current Oracle contract",
                }
            )
        if inputs.get("release_contract_policy_digest") != expected_policy:
            blockers.append(
                {
                    "code": "RECEIPT_POLICY_BINDING_MISMATCH",
                    "detail": f"{module}:{stage} is not bound to the current release policy",
                }
            )
    return blockers


def _contract_binding_blockers(
    required: dict[str, frozenset[str]],
    by_module: dict[str, list[dict[str, Any]]],
    release_contract: dict[str, Any],
) -> list[dict[str, str]]:
    blockers = []
    oracle, policy = (
        release_contract.get("oracle_contract_sha256"),
        release_contract.get("policy_digest"),
    )
    for module, stages in required.items():
        for stage in stages:
            blockers.extend(
                _stage_contract_binding_blockers(
                    module, stage, by_module.get(module, []), oracle, policy
                )
            )
    return blockers


def _strict_release_contract(
    workspace: Path,
    feature: str,
    contract_path: Path,
    declared_stage_ids: set[str],
    required: dict[str, frozenset[str]],
    by_module: dict[str, list[dict[str, Any]]],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    from .release_contract import verify_release_contract

    result = verify_release_contract(
        workspace, feature, contract_path, declared_stage_ids
    )
    if not result.get("ok"):
        return result, [
            {
                "code": str(result.get("marker", "RELEASE_CONTRACT_INVALID")),
                "detail": str(result.get("reason", "release contract is not valid")),
            }
        ]
    return result, _contract_binding_blockers(required, by_module, result)


def _next_verify_action(
    workspace: Path,
    feature: str,
    rollup: dict[str, Any],
    blockers: list[dict[str, str]],
) -> str:
    if rollup.get("earliest_failing_stage"):
        return f"factory risk-diff --root {workspace} --changed <changed-path>"
    if blockers:
        return f"factory assemble {feature} --root {workspace}"
    return f"factory trace {feature} --root {workspace}"


def verify_feature(
    root: Path,
    feature: str,
    *,
    strict_release: bool = False,
    release_contract_path: Path | None = None,
) -> dict:
    """Fail closed for absent, failed, malformed, or incomplete gate evidence."""
    workspace = Path(root)
    rollup = rollup_receipts(workspace, feature)
    rows = rollup["stages"]
    by_module = _stages_by_module(rows)
    contract_path = (
        release_contract_path
        or workspace / ".factory" / "release-contracts" / f"{feature}.json"
    )
    declared = {
        stage
        for stage in ("prestige:score", "hsf:compile")
        if strict_release
        and _release_declares(workspace, feature, contract_path, stage)
    }
    required = _required_stages(workspace, feature, rows, declared)
    blockers = _snapshot_blockers(rollup)
    modules, module_blockers = _module_audit(by_module, required)
    blockers.extend(module_blockers)
    intent_failure = _ship_intent_failure(rows)
    if intent_failure is not None:
        blockers.append(intent_failure)
    declared_stage_ids = {
        f"{module}:{stage}" for module, stages in required.items() for stage in stages
    }
    release_contract: dict[str, Any] = {"status": "not_requested"}
    if strict_release:
        release_contract, contract_blockers = _strict_release_contract(
            workspace,
            feature,
            contract_path,
            declared_stage_ids,
            required,
            by_module,
        )
        blockers.extend(contract_blockers)
    next_action = _next_verify_action(workspace, feature, rollup, blockers)
    shippable = bool(rows) and not rollup.get("earliest_failing_stage") and not blockers
    return {
        "schema": "factory.verify.v2",
        "feature": feature,
        "root": str(workspace),
        "shippable": shippable,
        "release_ready": shippable
        and (not strict_release or release_contract.get("ok") is True),
        "strict_release": strict_release,
        "release_contract": release_contract,
        "modules": modules,
        "rollup": rollup,
        "blockers": blockers,
        "next_action": next_action,
        "scope_limits": [
            "Evaluates stable local receipt evidence only; it does not run missing gates.",
            "A passing local decision is not an external deployment, signing, publication, provider-state readback, or approval.",
            "AppForge is required only when the feature declares a mobile decision spec; Prestige is required only when UI scope is declared.",
        ],
    }
