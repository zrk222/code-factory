"""One coherent, receipt-backed factory decision for a feature."""
from __future__ import annotations

from pathlib import Path

from .assembly import rollup_receipts


LABELS = {"specline": "SPEC", "forgeline": "FORGE", "hsf": "COMPILE", "prestige": "DESIGN"}


def verify_feature(root: Path, feature: str) -> dict:
    """Summarize existing receipts; this command never invents a pass for absent work."""
    rollup = rollup_receipts(root, feature)
    stages = rollup["stages"]
    by_module = {module: [] for module in LABELS}
    for stage in stages:
        by_module.setdefault(stage["module"], []).append(stage)
    modules = []
    for module, label in LABELS.items():
        rows = by_module[module]
        failed = [row for row in rows if row["status"] == "failed" or (row.get("rate") is not None and row["rate"] < 1.0)]
        modules.append({
            "module": module, "label": label,
            "status": "failed" if failed else "passed" if rows else "not_run",
            "stages": rows,
        })
    earliest = rollup.get("earliest_failing_stage")
    if earliest:
        next_action = f"factory risk-diff --root {Path(root)} --changed <changed-path>"
    elif not stages:
        next_action = f"factory assemble {feature} --root {Path(root)}"
    else:
        next_action = f"factory trace {feature} --root {Path(root)}"
    required = {"specline", "forgeline"}
    if by_module["prestige"]:
        required.add("prestige")
    shippable = bool(stages) and not earliest and all(item["status"] == "passed" for item in modules if item["module"] in required)
    return {
        "schema": "factory.verify.v1", "feature": feature, "root": str(Path(root)),
        "shippable": shippable, "modules": modules, "rollup": rollup,
        "next_action": next_action,
        "scope_limits": [
            "Summarizes receipts already present under the factory root; it does not run missing gates.",
            "HSF is optional when the feature has no deterministic decision specification.",
            "Prestige is required when the feature has design receipts; use project policy to require it for UI work.",
        ],
    }
