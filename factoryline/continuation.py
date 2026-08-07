"""State-aware continuation of the Code Factory assembly line."""
from __future__ import annotations

import json
from pathlib import Path
import re
import time
from typing import Any

from .assembly import assemble
from .run_metrics import retry_count, write_run_receipt


FEATURE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}")


class ContinuationError(ValueError):
    def __init__(self, code: str, message: str, candidates: list[str] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.candidates = candidates or []


def discover_features(root: Path) -> list[str]:
    """Return exact feature identifiers found in specs or Forge state directories."""
    root = Path(root).resolve()
    names = {path.stem for path in (root / "specs").glob("*.md") if FEATURE_PATTERN.fullmatch(path.stem)}
    names.update(path.name for path in (root / ".forge").glob("*") if path.is_dir() and FEATURE_PATTERN.fullmatch(path.name))
    return sorted(names)


def resolve_feature(root: Path, feature: str | None) -> tuple[str, bool]:
    """Validate an explicit feature or infer one only from a single exact candidate."""
    if feature:
        if not FEATURE_PATTERN.fullmatch(feature):
            raise ContinuationError("FEATURE_INVALID", "feature must use letters, digits, hyphens, or underscores")
        return feature, False
    candidates = discover_features(root)
    if len(candidates) != 1:
        raise ContinuationError(
            "FEATURE_SELECTION_REQUIRED",
            f"expected exactly one discoverable feature; found {len(candidates)}",
            candidates,
        )
    return candidates[0], True


def resolve_ssat(root: Path, feature: str) -> Path | None:
    """Return the first supported exact SSAT contract path, never a fuzzy match."""
    root = Path(root).resolve()
    for path in (
        root / "specs" / f"{feature}.ssat.yaml",
        root / f"{feature}.ssat.yaml",
        root / f"{feature}.adoption.ssat.yaml",
    ):
        if path.is_file():
            return path
    return None


def _next_action(paused_at: str, feature: str) -> dict[str, Any]:
    actions = {
        "author_spec": ("human", "Complete the feature spec and plan", None),
        "architecture_contract": ("human", "Complete the SSAT architecture contract", None),
        "architecture_approval": ("command", "Approve the architecture gate", f"forge gate architected {feature}"),
        "implementation_fill": ("human", "Implement the scaffold and record the fill gate", None),
        "nfr_conflict": (
            "command",
            "Resolve the NFR contradiction or record an expiring override",
            f"factory cdte resolve {feature} <conflict-id> --decision ... --approved-by ...",
        ),
    }
    kind, label, command = actions.get(paused_at, ("human", "Review the assembly boundary", None))
    return {"kind": kind, "label": label, "command": command, "requires_human": True}


def continue_assembly(
    root: Path,
    feature: str | None = None,
    *,
    dry_run: bool = False,
    usage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run installed safe stages and return at completion, failure, or a human boundary."""
    resolved_root = Path(root).resolve()
    selected, inferred = resolve_feature(resolved_root, feature)
    started = time.monotonic()
    report = assemble(resolved_root, selected, dry_run=dry_run)
    elapsed_ms = round((time.monotonic() - started) * 1000)
    if report.get("halted_at"):
        terminal = "halted"
        next_action = {
            "kind": "inspect",
            "label": f"Inspect failed stage {report['halted_at']}",
            "command": None,
            "requires_human": True,
        }
    elif report.get("paused_at"):
        terminal = "waiting_for_human"
        next_action = _next_action(report["paused_at"], selected)
    else:
        terminal = "completed"
        next_action = None
    result = {
        **report,
        "schema": "factory.assembly-continuation.v1",
        "marker": "ASSEMBLY_CONTINUE_COMMAND",
        "markers": [
            "ASSEMBLY_CONTINUE_COMMAND",
            *([] if not inferred else ["FEATURE_AUTO_SELECTED"]),
            "SAFE_STAGE_EXECUTED",
            "HUMAN_BOUNDARY_EXPLICIT" if terminal == "waiting_for_human" else "ASSEMBLY_HALTED_EXACT" if terminal == "halted" else "ASSEMBLY_COMPLETED",
        ],
        "status": terminal,
        "next_action": next_action,
        "elapsed_ms": elapsed_ms,
    }
    encoded = json.dumps(result, sort_keys=True).encode("utf-8")
    if not dry_run:
        receipt = write_run_receipt(resolved_root, {
            "run_id": report["run_id"],
            "feature": selected,
            "terminal": terminal,
            "elapsed_ms": elapsed_ms,
            "command_count": sum(stage.get("status") in {"ok", "failed"} for stage in report["stages"]),
            "stage_count": len(report["stages"]),
            "retry_count": retry_count(resolved_root, selected),
            "result_bytes": len(encoded),
            "usage": usage,
        })
        result["receipt"] = str(receipt)
        result["markers"].append("ASSEMBLY_RUN_RECEIPTED")
    return result
