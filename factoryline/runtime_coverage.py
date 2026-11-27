"""Bounded, read-only projections of local coverage and test reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from io import BytesIO
import json
import math
from os import fstat
from pathlib import Path, PurePosixPath
import subprocess
from typing import Any
from xml.etree import ElementTree
from . import file_sha256 as _file_sha256


REPORT_PATH = Path(".factory/test-reports/coverage.json")
RECEIPT_PATH = Path(".factory/test-reports/coverage.run.json")
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_RECEIPT_BYTES = 256 * 1024
MAX_FILES = 5_000
MAX_SOURCE_FILES = 5_000
MAX_GAP_LOCATIONS = 20
LIMITATION = "Executed-line counts do not establish test assertion quality or software correctness."
LOCAL_RUNNER = "local-powershell"
CI_RUNNER = "github-actions"
LOCAL_COVERAGE_COMMAND = (
    "rtk proxy python -m pytest -p pytest_asyncio.plugin -p xdist.plugin -q -n 2 "
    "-p pytest_cov.plugin --junitxml=.factory/test-reports/pytest.xml "
    "--durations=20 --cov=factoryline --cov-branch "
    "--cov-report=json:.factory/test-reports/coverage.json "
    "--cov-report=xml:.factory/test-reports/coverage.xml"
)
CI_COVERAGE_COMMAND = (
    "python -m pytest -p pytest_asyncio.plugin -p xdist.plugin -q -n 3 -p pytest_cov.plugin "
    "--junitxml=.factory/test-reports/pytest.xml --durations=20 "
    "--cov=factoryline --cov-branch "
    "--cov-report=json:.factory/test-reports/coverage.json "
    "--cov-report=xml:.factory/test-reports/coverage.xml"
)


def _snapshot() -> dict[str, Any]:
    return {
        "schema": "factory.runtime-coverage.v1",
        "state": "NOT_RUN",
        "source": REPORT_PATH.as_posix(),
        "source_sha256": None,
        "tool_version": None,
        "report_time": None,
        "source_mtime_utc": None,
        "statements": None,
        "branches": None,
        "file_count": None,
        "candidate_binding": "UNBOUND",
        "receipt_status": "MISSING",
        "receipt_sha256": None,
        "receipt_reason": "No local run receipt is available.",
        "RUNTIME_COVERAGE_LIMITATION": LIMITATION,
        "reason_code": None,
        "reason": "No runtime coverage report was found at the documented path.",
        "truncated": False,
        "limits": {
            "max_bytes": MAX_REPORT_BYTES,
            "max_files": MAX_FILES,
            "max_gap_locations_per_module": MAX_GAP_LOCATIONS,
        },
        "files": [],
    }


def _contained_file(root: Path, relative: Path) -> Path:
    workspace = root.resolve()
    target = (workspace / relative).resolve()
    target.relative_to(workspace)
    return target


def _python_source_paths(root: Path, relative_root: str) -> dict[str, Path]:
    source_root = _contained_file(root, Path(relative_root))
    paths = sorted(source_root.rglob("*.py"))
    if len(paths) > MAX_SOURCE_FILES:
        raise ValueError("Python source inventory exceeds 5,000 files.")
    manifest: dict[str, Path] = {}
    for path in paths:
        resolved = path.resolve()
        resolved.relative_to(root.resolve())
        if path.is_file():
            relative = resolved.relative_to(root.resolve()).as_posix()
            manifest[relative] = path
    if not manifest and relative_root == "factoryline":
        raise ValueError("No factoryline Python source files were found.")
    return manifest


def _python_manifest(root: Path, relative_root: str) -> dict[str, str]:
    return {
        relative: sha256(path.read_bytes()).hexdigest()
        for relative, path in _python_source_paths(root, relative_root).items()
    }


def _manifest_digest(root: Path, relative_root: str) -> str:
    encoded = json.dumps(
        _python_manifest(root, relative_root), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def source_code_digest(root: Path) -> str:
    """Return a deterministic digest for current production Python source."""
    return _manifest_digest(root, "factoryline")


def digest_test_sources(root: Path) -> str:
    """Return a deterministic digest for current Python test sources."""
    return _manifest_digest(root, "tests")


def _integer(value: object, name: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer.")
    return value


def _number(value: object, name: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(f"{name} must be a finite number.")
    if value < 0 or value > 100:
        raise ValueError(f"{name} must be between 0 and 100.")
    return float(value)


def _rate(covered: int, total: int, reported: object, name: str) -> float | None:
    if total == 0:
        return None
    rate = _number(reported, name)
    expected = covered * 100 / total
    if not math.isclose(rate, expected, rel_tol=0.0, abs_tol=0.01):
        raise ValueError(f"{name} conflicts with its coverage counts.")
    return rate


def _count_set(summary: dict[str, Any], *, branches: bool = False) -> dict[str, Any]:
    if branches:
        covered_key, total_key, missing_key = (
            "covered_branches",
            "num_branches",
            "missing_branches",
        )
        rate_key = "percent_branches_covered"
        label = "branch"
    else:
        covered_key, total_key, missing_key = (
            "covered_lines",
            "num_statements",
            "missing_lines",
        )
        rate_key = "percent_statements_covered"
        label = "statement"
    covered = _integer(summary.get(covered_key), covered_key)
    total = _integer(summary.get(total_key), total_key)
    missing = _integer(summary.get(missing_key), missing_key)
    if covered + missing != total:
        raise ValueError(f"{label} counts do not add up.")
    reported_rate = _rate(covered, total, summary.get(rate_key), rate_key)
    return {
        "covered": covered,
        "total": total,
        "missing": missing,
        "percent": reported_rate,
    }


def _line_locations(value: object, name: str) -> list[int]:
    if not isinstance(value, list) or any(
        type(item) is not int or item < 1 for item in value
    ):
        raise ValueError(f"{name} must contain positive line numbers.")
    return value


def _validate_line_bounds(lines: list[int], line_count: int, name: str) -> None:
    if any(line > line_count for line in lines):
        raise ValueError(f"{name} includes a line beyond the current source file.")


def _branch_location_list(
    value: object, name: str, *, line_count: int
) -> list[list[int]]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be an array.")
    branches: list[list[int]] = []
    for item in value:
        if not isinstance(item, list) or len(item) != 2:
            raise ValueError(f"{name} must contain source and destination line pairs.")
        source, destination = item
        if (
            type(source) is not int
            or source < 1
            or source > line_count
            or type(destination) is not int
            or destination == 0
            or (destination > 0 and destination > line_count)
        ):
            raise ValueError(f"{name} contains an invalid branch location.")
        branches.append([source, destination])
    return branches


def _branch_locations(value: object, *, line_count: int) -> list[list[int]]:
    return _branch_location_list(value, "missing_branches", line_count=line_count)


def _report_module_path(root: Path, raw_path: object) -> str:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("coverage file path must be a non-empty string.")
    relative = PurePosixPath(raw_path.replace("\\", "/"))
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ValueError("coverage file path escapes the workspace.")
    if relative.parts[0] != "factoryline" or relative.suffix != ".py":
        raise ValueError(
            "coverage report includes a path outside factoryline Python source."
        )
    target = _contained_file(root, Path(*relative.parts))
    if not target.is_file():
        raise ValueError("coverage report references a missing workspace source file.")
    return relative.as_posix()


def _module_row(root: Path, raw_path: object, raw_data: object) -> dict[str, Any]:
    path = _report_module_path(root, raw_path)
    source_path = _contained_file(root, Path(*PurePosixPath(path).parts))
    line_count = len(source_path.read_bytes().splitlines())
    if not isinstance(raw_data, dict) or not isinstance(raw_data.get("summary"), dict):
        raise ValueError("coverage module summary is missing.")
    summary = raw_data["summary"]
    statements = _count_set(summary)
    branches = _count_set(summary, branches=True)
    executed_lines = _line_locations(raw_data.get("executed_lines"), "executed_lines")
    missing_lines = _line_locations(raw_data.get("missing_lines"), "missing_lines")
    _validate_line_bounds(executed_lines, line_count, "executed_lines")
    _validate_line_bounds(missing_lines, line_count, "missing_lines")
    executed_branches = _branch_location_list(
        raw_data.get("executed_branches"), "executed_branches", line_count=line_count
    )
    missing_branches = _branch_locations(
        raw_data.get("missing_branches"), line_count=line_count
    )
    if (
        len(set(executed_lines)) != len(executed_lines)
        or len(set(missing_lines)) != len(missing_lines)
        or set(executed_lines) & set(missing_lines)
        or len(executed_lines) < statements["covered"]
        or len(missing_lines) != statements["missing"]
    ):
        raise ValueError("line locations conflict with the module summary.")
    if (
        len(set(map(tuple, executed_branches))) != len(executed_branches)
        or len(set(map(tuple, missing_branches))) != len(missing_branches)
        or set(map(tuple, executed_branches)) & set(map(tuple, missing_branches))
        or len(executed_branches) != branches["covered"]
        or len(missing_branches) != branches["missing"]
    ):
        raise ValueError("branch locations conflict with the module summary.")
    return {
        "path": path,
        "statements": statements,
        "branches": branches,
        "missing_lines": missing_lines[:MAX_GAP_LOCATIONS],
        "missing_branches": missing_branches[:MAX_GAP_LOCATIONS],
        "detail_truncated": len(missing_lines) > MAX_GAP_LOCATIONS
        or len(missing_branches) > MAX_GAP_LOCATIONS,
    }


def _report_datetime(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("coverage report timestamp is missing.")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    # Coverage.py emits a naive local timestamp. Resolve it using the runner's
    # local timezone so it can be compared with the timezone-aware run receipt.
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    return parsed


def _validated_report(
    root: Path, payload: object
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(payload, dict):
        raise ValueError("coverage report must be a JSON object.")
    meta = payload.get("meta")
    totals = payload.get("totals")
    raw_files = payload.get("files")
    if (
        not isinstance(meta, dict)
        or not isinstance(totals, dict)
        or not isinstance(raw_files, dict)
    ):
        raise ValueError("coverage report is missing meta, totals, or files.")
    version = meta.get("version")
    if (
        not isinstance(version, str)
        or not version.startswith("7.")
        or meta.get("branch_coverage") is not True
    ):
        raise ValueError(
            "coverage report must be Coverage.py version 7 with branch coverage enabled."
        )
    if not 0 < len(raw_files) <= MAX_FILES:
        raise ValueError("coverage report must contain between 1 and 5,000 files.")
    total_statements = _count_set(totals)
    total_branches = _count_set(totals, branches=True)
    files = [_module_row(root, path, data) for path, data in sorted(raw_files.items())]
    reported_paths = {item["path"] for item in files}
    source_paths = set(_python_source_paths(root, "factoryline"))
    if len(reported_paths) != len(files) or reported_paths != source_paths:
        missing = sorted(source_paths - reported_paths)
        unexpected = sorted(reported_paths - source_paths)
        raise ValueError(
            "coverage module inventory differs from current factoryline Python source: "
            f"{len(missing)} missing, {len(unexpected)} unexpected."
        )
    _validate_aggregate_totals(total_statements, total_branches, files)
    report_time = meta.get("timestamp")
    parsed_report_time = _report_datetime(report_time)
    return {
        "statements": total_statements,
        "branches": total_branches,
        "report_time": parsed_report_time.isoformat(),
        "report_datetime": parsed_report_time,
        "tool_version": version,
    }, files


def _validate_aggregate_totals(
    statements: dict[str, Any], branches: dict[str, Any], files: list[dict[str, Any]]
) -> None:
    for metric, expected in (("statements", statements), ("branches", branches)):
        for key in ("covered", "total", "missing"):
            observed = sum(item[metric][key] for item in files)
            if observed != expected[key]:
                raise ValueError(f"aggregate {metric} {key} differs from file totals.")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _git_identity(root: Path) -> tuple[str, bool]:
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError(
            "current Git commit and worktree state could not be verified."
        ) from exc
    if len(head) != 40 or any(
        character not in "0123456789abcdef" for character in head.lower()
    ):
        raise ValueError("current Git HEAD is not a full commit SHA.")
    return head, bool(status.strip())


def _receipt_status(
    root: Path,
    report_hash: str,
    current_code_hash: str,
    current_test_hash: str,
    report_time: datetime,
) -> dict[str, Any]:
    try:
        path = _contained_file(root, RECEIPT_PATH)
        if not path.exists():
            return {
                "candidate_binding": "UNBOUND",
                "receipt_status": "MISSING",
                "receipt_reason": "No local run receipt is available.",
            }
        raw = path.read_bytes()
        if len(raw) > MAX_RECEIPT_BYTES:
            raise ValueError("coverage run receipt exceeds 256 KiB.")
        receipt = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_object)
        _validate_receipt(
            root,
            receipt,
            report_hash,
            current_code_hash,
            current_test_hash,
            report_time,
        )
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        return {
            "candidate_binding": "UNBOUND",
            "receipt_status": "MISMATCHED",
            "receipt_sha256": None,
            "receipt_reason": str(exc)[:240],
        }
    runner = receipt.get("runner")
    return {
        "candidate_binding": "CI_SOURCE_HASH_MATCH"
        if runner == CI_RUNNER
        else "LOCAL_SOURCE_HASH_MATCH",
        "receipt_status": "MATCHED_UNAUTHENTICATED",
        "receipt_sha256": sha256(raw).hexdigest(),
        "receipt_reason": f"Report and current Python source hashes match; the {runner} receipt is unsigned and not provider-authenticated.",
    }


def _validate_receipt(
    root: Path,
    receipt: object,
    report_hash: str,
    code_hash: str,
    test_hash: str,
    report_time: datetime,
) -> None:
    if not isinstance(receipt, dict):
        raise ValueError("coverage run receipt has an unsupported schema.")
    commit, runner = _validate_receipt_header(receipt)
    _validate_runner_command(receipt, runner, commit)
    _validate_source_hashes(receipt, code_hash, test_hash)
    _validate_checkout_binding(root, receipt, commit)
    started, finished = _receipt_timestamps(receipt)
    _validate_receipt_time_window(started, finished, report_time)
    _validate_receipt_artifacts(root, receipt, report_hash)


def _validate_receipt_header(receipt: dict[str, Any]) -> tuple[str, str]:
    if receipt.get("schema") != "factory.runtime-coverage-run.v1":
        raise ValueError("coverage run receipt has an unsupported schema.")
    if receipt.get("authentication") != "UNAUTHENTICATED":
        raise ValueError(
            "coverage run receipt must disclose unauthenticated provenance."
        )
    commit = receipt.get("commit")
    runner = receipt.get("runner")
    environment = receipt.get("environment")
    if (
        not isinstance(commit, str)
        or len(commit) != 40
        or not isinstance(environment, dict)
    ):
        raise ValueError("coverage run receipt lacks commit or environment identity.")
    _validate_runner_environment(environment)
    if not isinstance(runner, str):
        raise ValueError("coverage run receipt has an unsupported runner identity.")
    return commit, runner


def _validate_runner_environment(environment: dict[str, Any]) -> None:
    pytest_cov = environment.get("pytest_cov")
    if (
        environment.get("pytest_plugin_autoload") != "disabled"
        or not isinstance(pytest_cov, str)
        or not pytest_cov.startswith("7.")
    ):
        raise ValueError(
            "coverage run receipt lacks the pinned test-runner environment."
        )


def _validate_runner_command(receipt: dict[str, Any], runner: str, commit: str) -> None:
    supported = {
        LOCAL_RUNNER: LOCAL_COVERAGE_COMMAND,
        CI_RUNNER: CI_COVERAGE_COMMAND,
    }
    if runner not in supported:
        raise ValueError("coverage run receipt has an unsupported runner identity.")
    if receipt.get("command") != supported[runner]:
        if runner == LOCAL_RUNNER:
            raise ValueError(
                "local coverage receipt command does not exactly match the supported full-suite command."
            )
        raise ValueError(
            "CI coverage receipt command does not exactly match the supported full-suite command."
        )
    if runner != CI_RUNNER:
        return
    github = receipt.get("github_actions")
    required_fields = ("repository", "workflow", "run_id", "run_attempt", "ref")
    if (
        not isinstance(github, dict)
        or any(
            not isinstance(github.get(field), str) or not github[field]
            for field in required_fields
        )
        or github.get("commit") != commit
    ):
        raise ValueError(
            "GitHub Actions coverage receipt lacks run identity or matching commit."
        )
    if receipt.get("dirty_tree") is not False:
        raise ValueError(
            "GitHub Actions coverage receipt was not produced from a clean worktree."
        )


def _validate_source_hashes(
    receipt: dict[str, Any], code_hash: str, test_hash: str
) -> None:
    if not isinstance(receipt.get("dirty_tree"), bool):
        raise ValueError("coverage run receipt lacks worktree state.")
    if (
        receipt.get("exit_code") != 0
        or receipt.get("source_code_sha256_before") != code_hash
        or receipt.get("source_code_sha256_after") != code_hash
    ):
        raise ValueError(
            "coverage run receipt does not match the current Python source or a passing run."
        )
    if (
        receipt.get("test_code_sha256_before") != test_hash
        or receipt.get("test_code_sha256_after") != test_hash
    ):
        raise ValueError(
            "coverage run receipt does not match current Python test sources."
        )


def _validate_checkout_binding(
    root: Path, receipt: dict[str, Any], commit: str
) -> None:
    current_commit, current_dirty = _git_identity(root)
    if commit != current_commit or receipt["dirty_tree"] != current_dirty:
        raise ValueError(
            "coverage run receipt commit or worktree state differs from the current checkout."
        )


def _receipt_timestamps(receipt: dict[str, Any]) -> tuple[datetime, datetime]:
    started_value = receipt.get("started_at")
    finished_value = receipt.get("finished_at")
    if not isinstance(started_value, str) or not isinstance(finished_value, str):
        raise ValueError("coverage run receipt timestamps are missing.")
    started = datetime.fromisoformat(started_value.replace("Z", "+00:00"))
    finished = datetime.fromisoformat(finished_value.replace("Z", "+00:00"))
    if started.tzinfo is None or finished.tzinfo is None or finished < started:
        raise ValueError("coverage run receipt timestamps are invalid.")
    return started, finished


def _validate_receipt_time_window(
    started: datetime, finished: datetime, report_time: datetime
) -> None:
    age = datetime.now(timezone.utc) - finished.astimezone(timezone.utc)
    if age < timedelta(0) or age > timedelta(hours=24):
        raise ValueError("coverage run receipt is older than 24 hours or future-dated.")
    if report_time < started - timedelta(
        seconds=5
    ) or report_time > finished + timedelta(seconds=5):
        raise ValueError(
            "coverage report timestamp falls outside the recorded test run."
        )


def _validate_receipt_artifacts(
    root: Path, receipt: dict[str, Any], report_hash: str
) -> None:
    artifacts = receipt.get("artifacts")
    expected_paths = {
        "junit_xml": ".factory/test-reports/pytest.xml",
        "coverage_json": REPORT_PATH.as_posix(),
        "coverage_xml": ".factory/test-reports/coverage.xml",
    }
    if not isinstance(artifacts, dict):
        raise ValueError("coverage run receipt artifact hashes are missing.")
    for name, expected_path in expected_paths.items():
        item = artifacts.get(name)
        if not isinstance(item, dict) or item.get("path") != expected_path:
            raise ValueError(f"coverage run receipt has an invalid {name} path.")
        artifact_path = _contained_file(root, Path(expected_path))
        if not artifact_path.is_file() or _file_sha256(artifact_path) != item.get(
            "sha256"
        ):
            raise ValueError(
                f"coverage run receipt {name} digest does not match the artifact."
            )
    if artifacts["coverage_json"]["sha256"] != report_hash:
        raise ValueError("coverage run receipt digest does not match the JSON report.")


def _read_payload(path: Path) -> object:
    with path.open("rb") as stream:
        content = stream.read(MAX_REPORT_BYTES + 1)
    if len(content) > MAX_REPORT_BYTES:
        raise ValueError("coverage report exceeds 16 MiB.")
    text = content.decode("utf-8")
    return json.loads(
        text,
        object_pairs_hook=_unique_json_object,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"invalid JSON number {value}")
        ),
    )


def read_runtime_coverage_report(
    root: Path, *, include_files: bool = False
) -> dict[str, Any]:
    """Read and validate bounded local coverage evidence without executing tests."""
    snapshot = _snapshot()
    try:
        report_path = _contained_file(root, REPORT_PATH)
        if not report_path.exists():
            return snapshot
        payload = _read_payload(report_path)
        summary, files = _validated_report(root, payload)
        report_hash = _file_sha256(report_path)
        code_hash = source_code_digest(root)
        test_hash = digest_test_sources(root)
    except (OSError, ValueError, TypeError, RecursionError, OverflowError) as exc:
        snapshot.update(
            state="INCOMPLETE",
            reason_code="RUNTIME_COVERAGE_INVALID",
            reason=str(exc)[:240],
        )
        return snapshot
    snapshot.update(
        state="OBSERVED",
        source_sha256=report_hash,
        tool_version=summary["tool_version"],
        report_time=summary["report_time"],
        source_mtime_utc=datetime.fromtimestamp(
            report_path.stat().st_mtime, tz=timezone.utc
        ).isoformat(),
        statements=summary["statements"],
        branches=summary["branches"],
        file_count=len(files),
        truncated=any(item["detail_truncated"] for item in files),
        reason="Coverage.py runtime counts validated; they do not prove test quality or correctness.",
        **_receipt_status(
            root, report_hash, code_hash, test_hash, summary["report_datetime"]
        ),
    )
    if include_files:
        snapshot["files"] = files
    return snapshot


_JUNIT_REPORT_PATH = Path(".factory/test-reports/pytest.xml")
_JUNIT_MAX_REPORT_BYTES = 8 * 1024 * 1024
_JUNIT_MAX_CASES = 10_000
_JUNIT_MAX_XML_DEPTH = 64


class _DepthLimitError(ValueError):
    """Raised when a report exceeds the bounded XML nesting depth."""


class _CountMismatch(ValueError):
    """Raised when declared suite outcomes omit or contradict parsed cases."""


class _UnknownTestStatus(ValueError):
    """Raised when a runner supplies an outcome this reader cannot classify."""


def _base_snapshot() -> dict:
    return {
        "state": "NOT_RUN",
        "counts": {"passed": 0, "failed": 0, "error": 0, "skipped": 0},
        "total_count": 0,
        "cases": [],
        "source": _JUNIT_REPORT_PATH.as_posix(),
        "source_sha256": None,
        "report_time": None,
        "source_mtime_utc": None,
        "truncated": False,
        "limits": {
            "max_bytes": _JUNIT_MAX_REPORT_BYTES,
            "max_cases": _JUNIT_MAX_CASES,
            "max_xml_depth": _JUNIT_MAX_XML_DEPTH,
        },
        "candidate_binding": "UNBOUND",
        "reason": "No test report was found at the documented path.",
    }


def _bounded(value: object, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _local_tag(tag: object) -> str:
    return str(tag).rsplit("}", 1)[-1]


def _duration(value: object) -> float | None:
    try:
        duration = float(str(value))
    except (TypeError, ValueError):
        return None
    if duration != duration or duration < 0 or duration == float("inf"):
        return None
    return duration


def _line(value: object) -> int | None:
    try:
        line = int(str(value))
    except (TypeError, ValueError):
        return None
    return line if line > 0 else None


def _case_result(
    element: ElementTree.Element,
) -> tuple[str, ElementTree.Element | None]:
    markers = {_local_tag(child.tag): child for child in element}
    if "error" in markers:
        return "error", markers["error"]
    elif "failure" in markers:
        return "failed", markers["failure"]
    elif "skipped" in markers:
        return "skipped", markers["skipped"]
    declared_status = str(element.get("status") or "passed").lower()
    if declared_status not in {"passed", "failed", "error", "skipped"}:
        raise _UnknownTestStatus
    return declared_status, None


def _case_failure_summary(result: ElementTree.Element | None) -> str | None:
    if result is None:
        return None
    return _bounded(result.get("message") or result.text, 400) or None


def _case(element: ElementTree.Element, suite_name: str) -> dict:
    status, result = _case_result(element)
    return {
        "suite": _bounded(element.get("classname") or suite_name, 240),
        "name": _bounded(element.get("name"), 300),
        "status": status,
        "file": _bounded(element.get("file"), 500) or None,
        "line": _line(element.get("line")),
        "duration_seconds": _duration(element.get("time")),
        "failure_summary": _case_failure_summary(result),
    }


def _declared_count(value: object) -> int | None:
    if value is None:
        return None
    try:
        number = int(str(value))
    except (TypeError, ValueError) as exc:
        raise _CountMismatch from exc
    if number < 0:
        raise _CountMismatch
    return number


def _read_junit_content(root: Path, snapshot: dict) -> bytes | None:
    """Read one bounded report from a path contained by the workspace."""
    try:
        workspace = root.resolve()
        source = (workspace / _JUNIT_REPORT_PATH).resolve()
        source.relative_to(workspace)
    except (OSError, RuntimeError, ValueError):
        snapshot.update(
            state="INCOMPLETE",
            reason="The report path escapes the workspace or cannot be resolved.",
        )
        return None

    try:
        if not source.exists():
            return None
        if not source.is_file():
            snapshot.update(
                state="INCOMPLETE", reason="The report path is not a regular file."
            )
            return None
        with source.open("rb") as handle:
            content = handle.read(_JUNIT_MAX_REPORT_BYTES + 1)
            metadata = fstat(handle.fileno())
    except OSError:
        snapshot.update(state="INCOMPLETE", reason="The report could not be read.")
        return None

    snapshot["source_mtime_utc"] = (
        datetime.fromtimestamp(metadata.st_mtime, timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    if len(content) > _JUNIT_MAX_REPORT_BYTES:
        snapshot.update(
            state="INCOMPLETE",
            truncated=True,
            reason="The report exceeds the byte limit; no partial file was parsed.",
        )
        return None
    snapshot["source_sha256"] = sha256(content).hexdigest()
    return content


def _validate_junit_content(content: bytes, snapshot: dict) -> bool:
    """Reject unsupported encodings and entity expansion before XML parsing."""
    try:
        content.decode("utf-8-sig")
    except UnicodeError:
        snapshot.update(
            state="INCOMPLETE", reason="The XML report must be UTF-8 encoded."
        )
        return False
    if b"\x00" in content:
        snapshot.update(state="INCOMPLETE", reason="The XML report contains NUL bytes.")
        return False
    if b"<!DOCTYPE" in content.upper() or b"<!ENTITY" in content.upper():
        snapshot.update(
            state="INCOMPLETE",
            reason="XML declarations with entities or DTDs are not accepted.",
        )
        return False
    return True


@dataclass
class _JUnitParseState:
    """Declared counts and suite nesting observed while streaming one report."""

    depth: int = 0
    suite_names: list[str] = field(default_factory=list)
    suite_checks: list[tuple[int, dict[str, int], dict[str, int | None]]] = field(
        default_factory=list
    )
    declared: int | None = None
    declared_results: dict[str, int] = field(default_factory=dict)
    root_tag: str | None = None


def _junit_suite_start(
    element: ElementTree.Element, snapshot: dict, state: _JUnitParseState
) -> None:
    """Record a suite's declared outcomes before counting its cases."""
    state.suite_names.append(_bounded(element.get("name"), 240))
    state.suite_checks.append(
        (
            snapshot["total_count"],
            dict(snapshot["counts"]),
            {
                "tests": _declared_count(element.get("tests")),
                "failed": _declared_count(element.get("failures")),
                "error": _declared_count(element.get("errors")),
                "skipped": _declared_count(element.get("skipped")),
            },
        )
    )
    if snapshot["report_time"] is None:
        snapshot["report_time"] = _bounded(element.get("timestamp"), 80) or None


def _junit_start(
    tag: str, element: ElementTree.Element, snapshot: dict, state: _JUnitParseState
) -> None:
    """Enforce nesting bounds and read root and suite declarations."""
    state.depth += 1
    if state.depth > _JUNIT_MAX_XML_DEPTH:
        raise _DepthLimitError
    if state.depth == 1:
        state.root_tag = tag
        state.declared = _declared_count(element.get("tests"))
        for attribute, status in (
            ("failures", "failed"),
            ("errors", "error"),
            ("skipped", "skipped"),
        ):
            count = _declared_count(element.get(attribute))
            if count is not None:
                state.declared_results[status] = count
        snapshot["report_time"] = _bounded(element.get("timestamp"), 80) or None
    if tag == "testsuite":
        _junit_suite_start(element, snapshot, state)


def _junit_suite_end(
    element: ElementTree.Element, snapshot: dict, state: _JUnitParseState
) -> None:
    """Require each suite's parsed cases to match its declared counts."""
    before_total, before_counts, suite_declared = state.suite_checks.pop()
    if suite_declared["tests"] is not None and (
        snapshot["total_count"] - before_total != suite_declared["tests"]
    ):
        raise _CountMismatch
    if any(
        count is not None
        and snapshot["counts"][status] - before_counts[status] != count
        for status, count in suite_declared.items()
        if status != "tests"
    ):
        raise _CountMismatch
    if state.suite_names:
        state.suite_names.pop()
    element.clear()


def _junit_end(
    tag: str, element: ElementTree.Element, snapshot: dict, state: _JUnitParseState
) -> None:
    """Count test cases and close a suite after validating its declaration."""
    if tag == "testcase":
        case = _case(element, state.suite_names[-1] if state.suite_names else "")
        snapshot["counts"][case["status"]] += 1
        snapshot["total_count"] += 1
        if len(snapshot["cases"]) < _JUNIT_MAX_CASES:
            snapshot["cases"].append(case)
        else:
            snapshot["truncated"] = True
        element.clear()
    elif tag == "testsuite":
        _junit_suite_end(element, snapshot, state)
    state.depth -= 1


def _parse_junit_xml(content: bytes, snapshot: dict) -> _JUnitParseState:
    """Stream bounded XML into a case snapshot and declaration state."""
    state = _JUnitParseState()
    for event, element in ElementTree.iterparse(
        BytesIO(content), events=("start", "end")
    ):
        tag = _local_tag(element.tag)
        if event == "start":
            _junit_start(tag, element, snapshot, state)
        else:
            _junit_end(tag, element, snapshot, state)
    return state


def _junit_parse_failure(snapshot: dict, exc: Exception) -> None:
    """Discard partial cases and explain the failed XML interpretation."""
    snapshot.update(
        state="INCOMPLETE",
        counts={"passed": 0, "failed": 0, "error": 0, "skipped": 0},
        total_count=0,
        cases=[],
        truncated=False,
        reason=(
            "The XML nesting depth exceeds the limit."
            if isinstance(exc, _DepthLimitError)
            else "Declared JUnit counts differ from parsed cases."
            if isinstance(exc, _CountMismatch)
            else "A JUnit test case has an unrecognized status."
            if isinstance(exc, _UnknownTestStatus)
            else "The XML report is malformed."
        ),
    )


def _finalize_junit_snapshot(snapshot: dict, state: _JUnitParseState) -> None:
    """Reconcile the parsed cases with root declarations and display limits."""
    if state.root_tag not in {"testsuite", "testsuites"}:
        snapshot.update(
            state="INCOMPLETE",
            reason="The XML root is not a JUnit testsuite or testsuites element.",
        )
    elif snapshot["truncated"]:
        snapshot.update(
            state="INCOMPLETE",
            reason="Some cases exceed the display limit; the complete count remains visible.",
        )
    elif state.declared is not None and state.declared != snapshot["total_count"]:
        snapshot.update(
            state="INCOMPLETE",
            reason="The declared test count differs from parsed test cases.",
        )
    elif any(
        snapshot["counts"][status] != count
        for status, count in state.declared_results.items()
    ):
        snapshot.update(
            state="INCOMPLETE",
            reason="Declared test outcomes differ from parsed case outcomes.",
        )
    else:
        snapshot.update(
            state="OBSERVED",
            reason="Report cases were read; this report is not bound to the current candidate.",
        )


def read_junit_report(root: Path) -> dict:
    """Read one local JUnit XML report and retain every case within limits.

    ``INCOMPLETE`` means the report is unreadable, malformed, inconsistent, or
    exceeds a stated limit. The function never executes code or follows a
    report path outside the resolved workspace. Case metadata is untrusted.
    """
    snapshot = _base_snapshot()
    content = _read_junit_content(root, snapshot)
    if content is None or not _validate_junit_content(content, snapshot):
        return snapshot
    try:
        state = _parse_junit_xml(content, snapshot)
    except (
        _DepthLimitError,
        _CountMismatch,
        _UnknownTestStatus,
        ElementTree.ParseError,
        ValueError,
    ) as exc:
        _junit_parse_failure(snapshot, exc)
        return snapshot
    _finalize_junit_snapshot(snapshot, state)
    return snapshot
