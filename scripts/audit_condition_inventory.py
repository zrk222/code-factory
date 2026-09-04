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
    "runtime_audit_runner.py",
    "runtime_audit_integrity.py",
    "runtime_audit.py",
)
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
    lane_codes = {name: sorted(_markers(module)) for name, module in LANE_MODULES.items()}
    crosscut = set()
    for module in CROSSCUT_MODULES:
        crosscut.update(code for code in _markers(module) if code.startswith((
            "E_", "RUNTIME_", "CROSS_", "HOLLOW_", "INCOMPLETE_",
        )))
    lane_total = sum(len(codes) for codes in lane_codes.values())
    return {
        "schema": "factory.runtime-audit-condition-inventory.v1",
        "mandatory_audit_lanes": len(lane_codes),
        "lane_specific_rejection_conditions": lane_total,
        "crosscutting_rejection_conditions": len(crosscut),
        "total_coded_rejection_conditions": lane_total + len(crosscut),
        "lanes": {name: len(codes) for name, codes in lane_codes.items()},
    }


if __name__ == "__main__":
    print(json.dumps(inventory(), indent=2, sort_keys=True))
