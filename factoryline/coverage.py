"""Requirement coverage checks for factory-generated app starters."""
from __future__ import annotations

import json
from pathlib import Path

from .attribution import Attribution, FailureClass, UnitResult


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _covered_requirement_ids(root: Path) -> set[str]:
    covered: set[str] = set()
    smoke_dir = Path(root) / "smoke"
    if not smoke_dir.exists():
        return covered
    for manifest in smoke_dir.glob("*.json"):
        payload = _load_json(manifest)
        for check in payload.get("checks", []):
            if check.get("must_fail_on_stub", True):
                covered.update(str(item) for item in check.get("covers", []))
    return covered


def requirement_coverage(root: Path) -> dict:
    """Return fail-closed coverage for requirement-to-test mapping."""
    root = Path(root)
    manifest = root / "coverage" / "requirements.json"
    if not manifest.exists():
        unit = UnitResult(
            "coverage:manifest",
            "coverage",
            False,
            "missing coverage/requirements.json",
            FailureClass.HOLLOW_COVERAGE,
        )
        attr = Attribution("coverage", 1, 0, [unit])
        return {
            "ok": False,
            "manifest": str(manifest),
            "covered": [],
            "uncovered": ["coverage:manifest"],
            "attribution": attr.to_dict(),
        }

    payload = _load_json(manifest)
    covered_ids = _covered_requirement_ids(root)
    units: list[UnitResult] = []
    uncovered: list[str] = []
    for req in payload.get("requirements", []):
        req_id = str(req["id"])
        passed = req_id in covered_ids
        if not passed:
            uncovered.append(req_id)
        units.append(UnitResult(
            unit=f"coverage:{req_id}",
            stage="coverage",
            passed=passed,
            evidence=(
                "covered by a non-hollow smoke check"
                if passed
                else "no non-hollow smoke check declares this requirement in covers[]"
            ),
            failure_class=None if passed else FailureClass.HOLLOW_COVERAGE,
        ))

    attr = Attribution("coverage", len(units), sum(unit.passed for unit in units), units)
    return {
        "ok": attr.n_checked > 0 and attr.rate == 1.0,
        "manifest": str(manifest),
        "covered": sorted(covered_ids),
        "uncovered": uncovered,
        "attribution": attr.to_dict(),
    }
