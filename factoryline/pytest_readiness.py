"""Exact pytest outcome collection for release-readiness smoke gates."""
from __future__ import annotations

import pytest


class _Results:
    def __init__(self) -> None:
        self.passed = 0
        self.skipped = 0
        self.xfailed = 0

    def pytest_collectreport(self, report) -> None:
        """Count collection skips that prevent an entire module from running."""
        if report.skipped:
            self.skipped += 1

    def pytest_runtest_logreport(self, report) -> None:
        """Count terminal test outcomes without overlooking setup-phase skips or xfails."""
        if report.skipped:
            if hasattr(report, "wasxfail"):
                self.xfailed += 1
            else:
                self.skipped += 1
        elif report.when == "call" and report.passed:
            if hasattr(report, "wasxfail"):
                self.xfailed += 1
            else:
                self.passed += 1


def collect_pytest_readiness(test_paths: list[str]) -> dict[str, int]:
    """Run strict pytest and count pass, skip, and xfail outcomes across phases."""
    results = _Results()
    # The readiness probe runs a nested pytest session from an arbitrary
    # temporary directory, so the repository's pyproject configuration is not
    # discovered.  Keep the async fixture scope explicit here as well; this
    # prevents pytest-asyncio's deprecation warning without globally filtering
    # warnings from the probe.
    exit_code = pytest.main(
        [
            "-q",
            "--strict-markers",
            "--strict-config",
            "-o",
            "asyncio_default_fixture_loop_scope=function",
            *test_paths,
        ],
        plugins=[results],
    )
    return {
        "exit_code": int(exit_code),
        "passed": results.passed,
        "skipped": results.skipped,
        "xfailed": results.xfailed,
    }
