"""Deterministic, build-time failure attribution shared by factory modules."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
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
        return self.n_passed / self.n_checked if self.n_checked else 0.0

    @property
    def failures(self) -> list[UnitResult]:
        return [unit for unit in self.units if not unit.passed]

    def dominant_failure_class(self) -> FailureClass | None:
        counts = {failure_class: 0 for failure_class in FailureClass}
        for unit in self.failures:
            counts[unit.failure_class] += 1
        maximum = max(counts.values(), default=0)
        if maximum == 0:
            return None
        return next(kind for kind in FailureClass if counts[kind] == maximum)

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["rate"] = self.rate
        dominant = self.dominant_failure_class()
        payload["dominant_failure_class"] = dominant.value if dominant else None
        return payload

    @classmethod
    def from_dict(cls, payload: dict) -> "Attribution":
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
    materialized = list(units)
    return Attribution(stage, len(materialized), sum(unit.passed for unit in materialized), materialized)
