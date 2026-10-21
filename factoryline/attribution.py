"""Deterministic, build-time failure attribution shared by factory modules."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable


class FailureClass(str, Enum):
    AMBIGUOUS_REQUIREMENT = "ambiguous_requirement"
    UNTYPED_INPUT = "untyped_input"
    SCOPE_ESCAPE = "scope_escape"
    INVENTED_PARAM = "invented_param"
    SIGNATURE_DRIFT = "signature_drift"
    STUB_UNFILLED = "stub_unfilled"
    COMPLEXITY_EXCEEDED = "complexity_exceeded"
    INCONSISTENT_LOGIC = "inconsistent_logic"
    RUNTIME_CRASH = "runtime_crash"
    RUNTIME_TIMEOUT = "runtime_timeout"
    WRONG_OUTPUT = "wrong_output"
    HOLLOW_TEST = "hollow_test"
    HOLLOW_MANIFEST = "hollow_manifest"
    HOLLOW_VALIDATOR = "hollow_validator"
    HOLLOW_COVERAGE = "hollow_coverage"
    ORACLE_WEAKENING = "oracle_weakening"
    ACCURACY_REGRESSION = "accuracy_regression"
    NONDETERMINISM = "nondeterminism"
    SECURITY_FINDING = "security_finding"


@dataclass(frozen=True)
class UnitResult:
    unit: str
    stage: str
    passed: bool
    evidence: str
    failure_class: FailureClass | None = None

    def __post_init__(self) -> None:
        if not self.unit.strip() or not self.stage.strip():
            raise ValueError("unit and stage are required")
        if not self.passed and self.failure_class is None:
            raise ValueError("failed units require a failure_class")
        if not self.passed and not self.evidence.strip():
            raise ValueError("failed units require concrete evidence")
        if self.passed and self.failure_class is not None:
            raise ValueError("passed units cannot carry a failure_class")


@dataclass
class Attribution:
    stage: str
    n_checked: int
    n_passed: int
    units: list[UnitResult]

    def __post_init__(self) -> None:
        if self.n_checked != len(self.units):
            raise ValueError("n_checked must equal the number of units")
        actual_passed = sum(unit.passed for unit in self.units)
        if self.n_passed != actual_passed:
            raise ValueError("n_passed must equal the number of passing units")

    @property
    def rate(self) -> float:
        """Return the passing-unit ratio, using zero for empty attribution."""
        return self.n_passed / self.n_checked if self.n_checked else 0.0

    @property
    def failures(self) -> list[UnitResult]:
        """Return failed units while preserving their original order."""
        return [unit for unit in self.units if not unit.passed]

    def dominant_failure_class(self) -> FailureClass | None:
        """Return the most frequent failure class with deterministic ties."""
        counts = {failure_class: 0 for failure_class in FailureClass}
        for unit in self.failures:
            counts[unit.failure_class] += 1
        maximum = max(counts.values(), default=0)
        if maximum == 0:
            return None
        return next(kind for kind in FailureClass if counts[kind] == maximum)

    def to_dict(self) -> dict:
        """Serialize units with derived rate and dominant failure class."""
        payload = asdict(self)
        payload["rate"] = self.rate
        dominant = self.dominant_failure_class()
        payload["dominant_failure_class"] = dominant.value if dominant else None
        return payload

    @classmethod
    def from_dict(cls, payload: dict) -> "Attribution":
        """Reconstruct validated attribution data from a dictionary payload."""
        units = [
            UnitResult(
                unit=item["unit"],
                stage=item.get("stage", payload["stage"]),
                passed=item["passed"],
                evidence=item.get("evidence", ""),
                failure_class=(
                    FailureClass(item["failure_class"])
                    if item.get("failure_class")
                    else None
                ),
            )
            for item in payload.get("units", [])
        ]
        return cls(
            stage=payload["stage"],
            n_checked=payload.get("n_checked", len(units)),
            n_passed=payload.get("n_passed", sum(unit.passed for unit in units)),
            units=units,
        )


def attribution(stage: str, units: Iterable[UnitResult]) -> Attribution:
    """Materialize unit results and compute checked and passing counts."""
    materialized = list(units)
    return Attribution(
        stage,
        len(materialized),
        sum(unit.passed for unit in materialized),
        materialized,
    )


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
        if not (root / "app_blueprint.json").is_file():
            return {
                "ok": True,
                "applicable": False,
                "status": "not_applicable",
                "manifest": str(manifest),
                "covered": [],
                "uncovered": [],
                "attribution": {
                    "stage": "coverage",
                    "n_checked": 0,
                    "n_passed": 0,
                    "rate": None,
                    "units": [],
                },
            }
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
            "applicable": True,
            "status": "incomplete",
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
        units.append(
            UnitResult(
                unit=f"coverage:{req_id}",
                stage="coverage",
                passed=passed,
                evidence=(
                    "covered by a non-hollow smoke check"
                    if passed
                    else "no non-hollow smoke check declares this requirement in covers[]"
                ),
                failure_class=None if passed else FailureClass.HOLLOW_COVERAGE,
            )
        )

    attr = Attribution(
        "coverage", len(units), sum(unit.passed for unit in units), units
    )
    return {
        "ok": attr.n_checked > 0 and attr.rate == 1.0,
        "applicable": True,
        "status": "complete"
        if attr.n_checked > 0 and attr.rate == 1.0
        else "incomplete",
        "manifest": str(manifest),
        "covered": sorted(covered_ids),
        "uncovered": uncovered,
        "attribution": attr.to_dict(),
    }
