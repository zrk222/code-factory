from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from factoryline.runtime_coverage import (
    MAX_GAP_LOCATIONS,
    REPORT_PATH,
    RECEIPT_PATH,
    LOCAL_COVERAGE_COMMAND,
    read_runtime_coverage_report,
    source_code_digest,
    digest_test_sources,
)


def _summary(
    *, covered: int, total: int, branches_covered: int = 0, branches_total: int = 0
) -> dict:
    missing = total - covered
    branch_missing = branches_total - branches_covered
    return {
        "covered_lines": covered,
        "num_statements": total,
        "missing_lines": missing,
        "percent_statements_covered": covered * 100 / total if total else 100,
        "covered_branches": branches_covered,
        "num_branches": branches_total,
        "missing_branches": branch_missing,
        "percent_branches_covered": (
            branches_covered * 100 / branches_total if branches_total else 100
        ),
    }


def _fixture(root: Path, *, missing_lines: list[int] | None = None) -> dict:
    source = root / "factoryline" / "demo.py"
    source.parent.mkdir(parents=True, exist_ok=True)
    contents = "def demo(value):\n    if value:\n        return 1\n    return 0\n"
    if missing_lines:
        contents += "\n" + "\n".join("# gap" for _ in range(max(missing_lines))) + "\n"
    source.write_text(contents, encoding="utf-8")
    total = 3 if missing_lines is None else len(missing_lines) + 1
    covered = total - 1
    row = {
        "summary": _summary(
            covered=covered, total=total, branches_covered=1, branches_total=2
        ),
        "executed_lines": [1, 2],
        "missing_lines": [3] if missing_lines is None else missing_lines,
        "executed_branches": [[2, 3]],
        "missing_branches": [[2, -4]],
    }
    totals = _summary(
        covered=covered, total=total, branches_covered=1, branches_total=2
    )
    return {
        "meta": {
            "format": 3,
            "version": "7.13.0",
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
            "branch_coverage": True,
        },
        "totals": totals,
        "files": {"factoryline/demo.py": row},
    }


def _write_report(root: Path, report: dict) -> Path:
    path = root / REPORT_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def _initialize_git(root: Path) -> str:
    (root / ".gitignore").write_text(".factory/\n", encoding="utf-8")
    tests = root / "tests" / "test_demo.py"
    tests.parent.mkdir(parents=True, exist_ok=True)
    tests.write_text("def test_demo():\n    assert True\n", encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", str(root)], check=True)
    for key, value in (
        ("user.name", "Coverage Fixture"),
        ("user.email", "coverage@example.invalid"),
    ):
        subprocess.run(["git", "-C", str(root), "config", key, value], check=True)
    subprocess.run(
        ["git", "-C", str(root), "add", ".gitignore", "factoryline", "tests"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(root), "commit", "--quiet", "-m", "fixture"], check=True
    )
    return subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_missing_runtime_coverage_is_not_reported_as_zero(tmp_path: Path) -> None:
    observed = read_runtime_coverage_report(tmp_path)

    assert observed["state"] == "NOT_RUN"
    assert observed["statements"] is None
    assert observed["branches"] is None
    assert observed["file_count"] is None
    assert observed["files"] == []


def test_valid_coverage_reports_separate_lines_branches_and_module_gaps(
    tmp_path: Path,
) -> None:
    _write_report(tmp_path, _fixture(tmp_path))

    summary = read_runtime_coverage_report(tmp_path)
    detail = read_runtime_coverage_report(tmp_path, include_files=True)

    assert summary["schema"] == "factory.runtime-coverage.v1"
    assert summary["state"] == "OBSERVED"
    assert summary["statements"] == {
        "covered": 2,
        "total": 3,
        "missing": 1,
        "percent": 200 / 3,
    }
    assert summary["branches"] == {
        "covered": 1,
        "total": 2,
        "missing": 1,
        "percent": 50.0,
    }
    assert summary["files"] == []
    assert detail["files"][0]["path"] == "factoryline/demo.py"
    assert detail["files"][0]["missing_lines"] == [3]
    assert detail["files"][0]["missing_branches"] == [[2, -4]]
    assert detail["candidate_binding"] == "UNBOUND"
    assert detail["RUNTIME_COVERAGE_LIMITATION"].startswith("Executed-line counts")


def test_zero_branch_inventory_uses_unavailable_rate(tmp_path: Path) -> None:
    report = _fixture(tmp_path)
    row = report["files"]["factoryline/demo.py"]
    row["summary"] = _summary(covered=2, total=3)
    row["executed_branches"] = []
    row["missing_branches"] = []
    report["totals"] = _summary(covered=2, total=3)
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path)

    assert observed["state"] == "OBSERVED"
    assert observed["branches"]["percent"] is None


def test_invalid_report_hides_file_details_and_returns_actionable_code(
    tmp_path: Path,
) -> None:
    report = _fixture(tmp_path)
    report["totals"]["covered_lines"] = 99
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path, include_files=True)

    assert observed["state"] == "INCOMPLETE"
    assert observed["reason_code"] == "RUNTIME_COVERAGE_INVALID"
    assert observed["files"] == []
    assert "counts" in observed["reason"] or "differs" in observed["reason"]


def test_report_outside_factoryline_fails_closed(tmp_path: Path) -> None:
    report = _fixture(tmp_path)
    report["files"]["other/secret.py"] = report["files"].pop("factoryline/demo.py")
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path, include_files=True)

    assert observed["state"] == "INCOMPLETE"
    assert observed["files"] == []
    assert "outside factoryline" in observed["reason"]


def test_missing_branch_flag_fails_closed(tmp_path: Path) -> None:
    report = _fixture(tmp_path)
    report["meta"]["branch_coverage"] = False
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path)

    assert observed["state"] == "INCOMPLETE"
    assert "branch coverage enabled" in observed["reason"]


def test_oversized_report_fails_closed_with_no_details(
    tmp_path: Path, monkeypatch
) -> None:
    import factoryline.runtime_coverage as coverage_module

    path = tmp_path / REPORT_PATH
    path.parent.mkdir(parents=True)
    path.write_text("{}" * 20, encoding="utf-8")
    monkeypatch.setattr(coverage_module, "MAX_REPORT_BYTES", 8)

    observed = read_runtime_coverage_report(tmp_path, include_files=True)

    assert observed["state"] == "INCOMPLETE"
    assert observed["files"] == []
    assert "16 MiB" in observed["reason"]


def test_report_file_count_limit_fails_closed(tmp_path: Path, monkeypatch) -> None:
    import factoryline.runtime_coverage as coverage_module

    report = _fixture(tmp_path)
    source = tmp_path / "factoryline" / "other.py"
    source.write_text("value = 1\n", encoding="utf-8")
    first = report["files"]["factoryline/demo.py"]
    report["files"]["factoryline/other.py"] = first
    monkeypatch.setattr(coverage_module, "MAX_FILES", 1)
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path, include_files=True)

    assert observed["state"] == "INCOMPLETE"
    assert observed["files"] == []
    assert "5,000 files" in observed["reason"]


def test_report_rejects_disagreeing_executed_locations(tmp_path: Path) -> None:
    report = _fixture(tmp_path)
    report["files"]["factoryline/demo.py"]["executed_lines"] = [1]
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path, include_files=True)

    assert observed["state"] == "INCOMPLETE"
    assert observed["files"] == []
    assert "line locations" in observed["reason"]


def test_report_rejects_executed_line_beyond_source_file(tmp_path: Path) -> None:
    report = _fixture(tmp_path)
    report["files"]["factoryline/demo.py"]["executed_lines"] = [1, 999]
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path, include_files=True)

    assert observed["state"] == "INCOMPLETE"
    assert observed["files"] == []
    assert "beyond the current source file" in observed["reason"]


def test_report_rejects_branch_location_beyond_source_file(tmp_path: Path) -> None:
    report = _fixture(tmp_path)
    report["files"]["factoryline/demo.py"]["missing_branches"] = [[2, 999]]
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path, include_files=True)

    assert observed["state"] == "INCOMPLETE"
    assert observed["files"] == []
    assert "invalid branch location" in observed["reason"]


def test_duplicate_json_keys_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / REPORT_PATH
    path.parent.mkdir(parents=True)
    path.write_text('{"meta":{},"meta":{},"totals":{},"files":{}}', encoding="utf-8")

    observed = read_runtime_coverage_report(tmp_path)

    assert observed["state"] == "INCOMPLETE"
    assert observed["reason_code"] == "RUNTIME_COVERAGE_INVALID"
    assert "duplicate JSON object key" in observed["reason"]


def test_report_must_cover_the_exact_factoryline_source_inventory(
    tmp_path: Path,
) -> None:
    report = _fixture(tmp_path)
    (tmp_path / "factoryline" / "second.py").write_text("value = 2\n", encoding="utf-8")
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path, include_files=True)

    assert observed["state"] == "INCOMPLETE"
    assert observed["files"] == []
    assert "1 missing" in observed["reason"]


def test_missing_gap_details_are_bounded_and_marked(tmp_path: Path) -> None:
    missing = list(range(2, 28))
    report = _fixture(tmp_path, missing_lines=missing)
    report["files"]["factoryline/demo.py"]["summary"] = _summary(
        covered=1, total=len(missing) + 1, branches_covered=1, branches_total=2
    )
    report["files"]["factoryline/demo.py"]["executed_lines"] = [1]
    report["totals"] = report["files"]["factoryline/demo.py"]["summary"]
    _write_report(tmp_path, report)

    observed = read_runtime_coverage_report(tmp_path, include_files=True)
    module = observed["files"][0]

    assert observed["state"] == "OBSERVED"
    assert len(module["missing_lines"]) == MAX_GAP_LOCATIONS
    assert module["detail_truncated"] is True
    assert observed["truncated"] is True


def test_matching_local_receipt_reports_source_hash_match_but_not_authenticity(
    tmp_path: Path,
) -> None:
    _write_report(tmp_path, _fixture(tmp_path))
    artifacts = {
        "junit_xml": ".factory/test-reports/pytest.xml",
        "coverage_json": REPORT_PATH.as_posix(),
        "coverage_xml": ".factory/test-reports/coverage.xml",
    }
    hashed_artifacts = {}
    for name, relative in artifacts.items():
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if name != "coverage_json":
            target.write_text("<testsuites/>\n", encoding="utf-8")
        hashed_artifacts[name] = {
            "path": relative,
            "sha256": sha256(target.read_bytes()).hexdigest(),
        }
    commit = _initialize_git(tmp_path)
    code_hash = source_code_digest(tmp_path)
    started = datetime.now(timezone.utc) - timedelta(minutes=1)
    finished = datetime.now(timezone.utc)
    receipt = {
        "schema": "factory.runtime-coverage-run.v1",
        "runner": "local-powershell",
        "authentication": "UNAUTHENTICATED",
        "commit": commit,
        "dirty_tree": False,
        "command": LOCAL_COVERAGE_COMMAND,
        "exit_code": 0,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "source_code_sha256_before": code_hash,
        "source_code_sha256_after": code_hash,
        "test_code_sha256_before": digest_test_sources(tmp_path),
        "test_code_sha256_after": digest_test_sources(tmp_path),
        "environment": {
            "python": "Python 3.11.9",
            "pytest_plugin_autoload": "disabled",
            "pytest_cov": "7.0.0",
        },
        "artifacts": hashed_artifacts,
    }
    receipt_path = tmp_path / RECEIPT_PATH
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    observed = read_runtime_coverage_report(tmp_path)

    assert observed["candidate_binding"] == "LOCAL_SOURCE_HASH_MATCH"
    assert observed["receipt_status"] == "MATCHED_UNAUTHENTICATED"
    assert "unsigned" in observed["receipt_reason"]
    receipt_data = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt_data["finished_at"] = (
        datetime.now(timezone.utc) - timedelta(hours=25)
    ).isoformat()
    receipt_data["started_at"] = (
        datetime.now(timezone.utc) - timedelta(hours=25, minutes=1)
    ).isoformat()
    receipt_path.write_text(json.dumps(receipt_data), encoding="utf-8")
    stale = read_runtime_coverage_report(tmp_path)
    assert stale["candidate_binding"] == "UNBOUND"
    assert stale["receipt_status"] == "MISMATCHED"
    assert "older than 24 hours" in stale["receipt_reason"]
    receipt_data["finished_at"] = datetime.now(timezone.utc).isoformat()
    receipt_data["started_at"] = (
        datetime.now(timezone.utc) - timedelta(minutes=1)
    ).isoformat()
    receipt_path.write_text(json.dumps(receipt_data), encoding="utf-8")
    target = tmp_path / "factoryline" / "demo.py"
    target.write_text(
        target.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8"
    )

    changed = read_runtime_coverage_report(tmp_path)

    assert changed["state"] == "OBSERVED"
    assert changed["candidate_binding"] == "UNBOUND"
    assert changed["receipt_status"] == "MISMATCHED"
    assert "current Python source" in changed["receipt_reason"]
