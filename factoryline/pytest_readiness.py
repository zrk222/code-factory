"""Exact pytest outcome collection for release-readiness smoke gates."""

from __future__ import annotations

import pytest
from pathlib import Path


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
    # discovered. Load pytest-asyncio explicitly when available so its config
    # option is recognized even when plugin autoload is disabled by the caller.
    # Normalize absolute paths for Windows.  Pytest's nested invocation can
    # otherwise treat a backslash-containing drive path as a collection root
    # and walk the protected ``C:\\Documents and Settings`` junction.
    normalized_paths = [Path(path).resolve().as_posix() for path in test_paths]
    # Pin collection to the supplied suite directory.  On Windows, pytest's
    # upward root discovery can otherwise select the drive root and traverse
    # the protected ``Documents and Settings`` junction before it reaches the
    # explicit file path.  The readiness probe only needs the named suites,
    # so a local root is both safer and deterministic.
    probe_root = str(Path(normalized_paths[0]).parent) if normalized_paths else "."
    plugins: list[object] = [results]
    pytest_args = [
        "-q",
        "--strict-markers",
        "--strict-config",
        "--rootdir",
        probe_root,
    ]
    try:
        import pytest_asyncio.plugin
    except ImportError:
        pass
    else:
        plugins.append(pytest_asyncio.plugin)
        pytest_args.extend(["-o", "asyncio_default_fixture_loop_scope=function"])
    exit_code = pytest.main(
        [*pytest_args, *normalized_paths],
        plugins=plugins,
    )
    return {
        "exit_code": int(exit_code),
        "passed": results.passed,
        "skipped": results.skipped,
        "xfailed": results.xfailed,
    }
