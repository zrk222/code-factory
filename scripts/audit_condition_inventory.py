"""Deterministically inventory runtime-assurance rejection conditions."""
from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LANE_MODULES = {
    "stateful workflows": "runtime_audit_stateful.py",
    "tenant isolation": "runtime_audit_tenant.py",
    "failure and recovery": "runtime_audit_recovery.py",
    "consumer compatibility": "runtime_audit_compatibility.py",
    "migration integrity": "runtime_audit_migration.py",
    "performance and resources": "runtime_audit_performance.py",
}
CROSSCUT_MODULES = (
    "runtime_audit_contract.py",
    "runtime_audit_common.py",
    "runtime_audit_policy.py",
    "runtime_audit_runner.py",
    "runtime_audit_integrity.py",
    "runtime_audit.py",
)
NON_CONDITION_MODULES = {"runtime_audit_process.py"}
REJECTION_PREFIXES = ("E_", "RUNTIME_", "CROSS_", "HOLLOW_", "INCOMPLETE_")
LANE_LABELS = {
    "stateful workflows": "Stateful workflows and business invariants",
    "tenant isolation": "Authorization and tenant isolation",
    "failure and recovery": "Failure, concurrency, retries and recovery",
    "consumer compatibility": "API and consumer compatibility",
    "migration integrity": "Database migration and data integrity",
    "performance and resources": "Performance, memory and resource regression",
}
NON_REJECTION_MARKERS = {
    "PASS", "FAIL", "INCOMPLETE", "STATEFUL_INVARIANTS_HELD",
    "TENANT_MATRIX_HELD", "RECOVERY_INVARIANTS_HELD",
    "CONSUMER_CONTRACTS_HELD", "MIGRATION_REHEARSAL_HELD",
    "PERFORMANCE_AND_RESOURCES_HELD",
}


def _markers(module: str) -> set[str]:
    tree = ast.parse((ROOT / "factoryline" / module).read_text(encoding="utf-8"))
    values = {
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and len(node.value) >= 4
        and node.value.replace("_", "").isalnum()
        and node.value.upper() == node.value
    }
    return values - NON_REJECTION_MARKERS


def inventory() -> dict[str, object]:
    classified_modules = set(LANE_MODULES.values()) | set(CROSSCUT_MODULES) | NON_CONDITION_MODULES
    discovered_modules = {
        path.name for path in (ROOT / "factoryline").glob("runtime_audit*.py")
    }
    unclassified_modules = sorted(discovered_modules - classified_modules)
    if unclassified_modules:
        raise ValueError(
            "classify new runtime-audit modules before publishing counts: "
            + ", ".join(unclassified_modules)
        )
    condition_codes_in_helpers = {
        module: sorted(code for code in _markers(module) if code.startswith(REJECTION_PREFIXES))
        for module in NON_CONDITION_MODULES
    }
    condition_codes_in_helpers = {
        module: codes for module, codes in condition_codes_in_helpers.items() if codes
    }
    if condition_codes_in_helpers:
        raise ValueError(
            "condition-free runtime-audit helpers now contain rejection codes: "
            + json.dumps(condition_codes_in_helpers, sort_keys=True)
        )
    lane_codes = {name: sorted(_markers(module)) for name, module in LANE_MODULES.items()}
    crosscut = set()
    for module in CROSSCUT_MODULES:
        crosscut.update(code for code in _markers(module) if code.startswith(REJECTION_PREFIXES))
    lane_total = sum(len(codes) for codes in lane_codes.values())
    return {
        "schema": "factory.runtime-audit-condition-inventory.v1",
        "mandatory_audit_lanes": len(lane_codes),
        "lane_specific_rejection_conditions": lane_total,
        "crosscutting_rejection_conditions": len(crosscut),
        "total_coded_rejection_conditions": lane_total + len(crosscut),
        "lanes": {name: len(codes) for name, codes in lane_codes.items()},
        "lane_condition_codes": lane_codes,
        "crosscutting_condition_codes": sorted(crosscut),
    }


def public_claim(result: dict[str, object]) -> str:
    return (
        f"{result['mandatory_audit_lanes']} mandatory audit lanes. "
        f"{result['total_coded_rejection_conditions']} coded rejection conditions. "
        "One human-owned release decision."
    )


def public_breakdown(result: dict[str, object]) -> str:
    return (
        f"{result['lane_specific_rejection_conditions']} lane-specific and "
        f"{result['crosscutting_rejection_conditions']} cross-cutting"
    )


def markdown_table(result: dict[str, object]) -> str:
    lanes = result["lanes"]
    rows = [
        "| Audit area | Coded rejection conditions |",
        "| --- | ---: |",
    ]
    rows.extend(f"| {LANE_LABELS[name]} | {lanes[name]} |" for name in LANE_MODULES)
    rows.extend((
        "| Cross-cutting contract, policy, provenance, evidence and execution integrity "
        f"| {result['crosscutting_rejection_conditions']} |",
        f"| **Total** | **{result['total_coded_rejection_conditions']}** |",
    ))
    return "\n".join(rows)


if __name__ == "__main__":
    print(json.dumps(inventory(), indent=2, sort_keys=True))
