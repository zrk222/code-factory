"""Factory-scope deterministic refinement and rejection accounting."""

from __future__ import annotations
from dataclasses import asdict, dataclass
from pathlib import Path
import json

from .attribution import FailureClass


@dataclass(frozen=True)
class Edit:
    edit_class: str
    target_stage: str
    failure_class: FailureClass
    description: str


def select_edit(target_stage: str, failure_class: FailureClass) -> Edit:
    """Select the smallest permitted corrective edit for a classified stage failure."""
    structural = {
        FailureClass.AMBIGUOUS_REQUIREMENT,
        FailureClass.SCOPE_ESCAPE,
        FailureClass.SIGNATURE_DRIFT,
        FailureClass.STUB_UNFILLED,
        FailureClass.INCONSISTENT_LOGIC,
        FailureClass.HOLLOW_TEST,
        FailureClass.HOLLOW_MANIFEST,
        FailureClass.HOLLOW_VALIDATOR,
    }
    configuration = {
        FailureClass.RUNTIME_CRASH,
        FailureClass.RUNTIME_TIMEOUT,
        FailureClass.SECURITY_FINDING,
    }
    edit_class = (
        "structural"
        if failure_class in structural
        else "configuration"
        if failure_class in configuration
        else "parametric"
    )
    return Edit(
        edit_class, target_stage, failure_class, "localized deterministic correction"
    )


def pareto_win(
    current: dict[str, float], previous: dict[str, float], target: str
) -> bool:
    """Return whether the target improved without regressing any guarded metric."""
    return current.get(target, 0.0) > previous.get(target, 0.0) and all(
        current.get(stage, 0.0) >= rate for stage, rate in previous.items()
    )


class RejectionLedger:
    def __init__(self, root: Path):
        self.path = Path(root) / ".factory" / "rejection_ledger.jsonl"

    def log(self, edit: Edit, before: dict, after: dict):
        """Append one refinement decision and its before/after evidence to the ledger."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "edit": {**asdict(edit), "failure_class": edit.failure_class.value},
            "before_rates": before,
            "after_rates": after,
        }
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, sort_keys=True) + "\n")


def refine(evaluate, propose, apply, revert, root: Path, max_iters: int = 6) -> dict:
    """Run a bounded loop, reverting edits that are not Pareto improvements."""
    previous = evaluate()
    no_win_streak = 0
    ledger = RejectionLedger(root)
    for iteration in range(max_iters):
        if previous and all(rate == 1.0 for rate in previous.values()):
            return {"converged": True, "iters": iteration}
        target, failure_class = propose(previous)
        edit = select_edit(target, failure_class)
        snapshot = apply(edit)
        current = evaluate()
        if pareto_win(current, previous, target):
            previous = current
            no_win_streak = 0
            continue
        revert(snapshot)
        ledger.log(edit, previous, current)
        no_win_streak += 1
        if no_win_streak >= 2:
            return {"converged": False, "reason": "plateau", "iters": iteration + 1}
    return {"converged": False, "reason": "budget", "iters": max_iters}


BUILD_TIME_ONLY = {"attribution", "refine", "rejection_ledger", "edit_selection"}


def assert_no_attribution_in_artifact(artifact_path: Path) -> None:
    """Reject generated artifacts that leak build-time learning symbols."""
    source = Path(artifact_path).read_text(encoding="utf-8")
    leaked = sorted(symbol for symbol in BUILD_TIME_ONLY if symbol in source)
    if leaked:
        raise ValueError(
            f"build-time symbols leaked into artifact: {', '.join(leaked)}"
        )


def assert_build_metadata_locations(root: Path) -> None:
    """Reject build-only metadata files found beneath the runtime registry."""
    registry = Path(root) / "registry"
    if not registry.exists():
        return
    offenders = [
        path
        for path in registry.rglob("*")
        if path.is_file() and any(token in path.name for token in BUILD_TIME_ONLY)
    ]
    if offenders:
        raise ValueError(f"build metadata found in registry: {offenders}")
