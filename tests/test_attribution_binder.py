"""Behavior checks for hash-bound local run receipts."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import runpy

import pytest

_BINDER_PATH = Path(__file__).parents[1] / "tools" / "workflow-audit" / "bind-local.py"
valid_run_receipt = runpy.run_path(str(_BINDER_PATH))["valid_run_receipt"]
candidate_hashes = runpy.run_path(str(_BINDER_PATH))["_candidate_hashes"]
valid_runtime_coverage_evidence = runpy.run_path(str(_BINDER_PATH))[
    "valid_runtime_coverage_evidence"
]


def test_candidate_hashes_cover_repo_source_and_test_inventory(tmp_path: Path) -> None:
    source = tmp_path / "factoryline" / "module.py"
    source.parent.mkdir()
    source.write_text("def production():\n    return 1\n", encoding="utf-8")
    test = tmp_path / "tests" / "test_module.py"
    test.parent.mkdir()
    test.write_text("def test_production():\n    assert production() == 1\n", encoding="utf-8")
    policy = tmp_path / "spec.md"
    policy.write_text("Reviewed policy.\n", encoding="utf-8")

    hashes = candidate_hashes(tmp_path, ("spec.md",))

    assert set(hashes) == {"factoryline/module.py", "tests/test_module.py", "spec.md"}
    assert hashes["factoryline/module.py"] == sha256(source.read_bytes()).hexdigest()
    assert hashes["tests/test_module.py"] == sha256(test.read_bytes()).hexdigest()


def _write_run(tmp_path: Path) -> tuple[Path, dict[str, str], str]:
    log_path = "run.log"
    log = tmp_path / log_path
    log.write_text("2 passed in 0.01s\n", encoding="utf-8")
    source_hashes = {"module.py": "a" * 64}
    now = datetime.now(timezone.utc)
    receipt = {
        "schema": "factory.local-test-run.v1",
        "commit": "f" * 40,
        "dirty_tree": True,
        "command": "rtk proxy python -m pytest -q",
        "exit_code": 0,
        "source_unchanged": True,
        "source_sha256_before": source_hashes,
        "source_sha256_after": source_hashes,
        "source_sha256": source_hashes,
        "log_path": log_path,
        "log_sha256": sha256(log.read_bytes()).hexdigest(),
        "report_sha256": None,
        "started_at": (now - timedelta(seconds=3)).isoformat(),
        "finished_at": now.isoformat(),
        "environment": {
            "python": "Python 3.11.9",
            "pytest_plugin_autoload": "disabled",
            "pytest_cov": "7.0.0",
        },
    }
    path = tmp_path / "run.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    return path, source_hashes, log_path


def test_valid_run_receipt_accepts_fresh_hash_bound_pass(tmp_path: Path) -> None:
    receipt, hashes, log_path = _write_run(tmp_path)

    assert valid_run_receipt(
        receipt,
        tmp_path,
        command="rtk proxy python -m pytest -q",
        log_path=log_path,
        source_hashes=hashes,
        commit="f" * 40,
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("exit_code", 1),
        ("commit", "0" * 40),
        ("source_unchanged", False),
        ("source_sha256_before", {"module.py": "b" * 64}),
        ("command", "python -m pytest -q"),
    ],
)
def test_valid_run_receipt_rejects_identity_or_execution_drift(
    tmp_path: Path, field: str, value: object
) -> None:
    receipt, hashes, log_path = _write_run(tmp_path)
    data = json.loads(receipt.read_text(encoding="utf-8"))
    data[field] = value
    receipt.write_text(json.dumps(data), encoding="utf-8")

    assert not valid_run_receipt(
        receipt,
        tmp_path,
        command="rtk proxy python -m pytest -q",
        log_path=log_path,
        source_hashes=hashes,
        commit="f" * 40,
    )


def test_valid_run_receipt_binds_forgeline_report_to_exact_log(tmp_path: Path) -> None:
    receipt, hashes, log_path = _write_run(tmp_path)
    data = json.loads(receipt.read_text(encoding="utf-8"))
    report_hash = data["log_sha256"]
    data["report_sha256"] = report_hash
    receipt.write_text(json.dumps(data), encoding="utf-8")

    assert valid_run_receipt(
        receipt,
        tmp_path,
        command="rtk proxy python -m pytest -q",
        log_path=log_path,
        source_hashes=hashes,
        commit="f" * 40,
        require_report_hash=True,
    )


def _write_runtime_evidence(tmp_path: Path) -> tuple[str, str]:
    from test_runtime_coverage import _fixture, _initialize_git, _write_report
    from factoryline.runtime_coverage import LOCAL_COVERAGE_COMMAND
    from factoryline.runtime_coverage import digest_test_sources, source_code_digest

    _write_report(tmp_path, _fixture(tmp_path))
    artifact_paths = {
        "junit_xml": ".factory/test-reports/pytest.xml",
        "coverage_json": ".factory/test-reports/coverage.json",
        "coverage_xml": ".factory/test-reports/coverage.xml",
    }
    artifacts = {}
    for name, relative in artifact_paths.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if name != "coverage_json":
            path.write_text("<testsuites/>\n", encoding="utf-8")
        artifacts[name] = {"path": relative, "sha256": sha256(path.read_bytes()).hexdigest()}
    commit = _initialize_git(tmp_path)
    command = LOCAL_COVERAGE_COMMAND
    source_hash = source_code_digest(tmp_path)
    tests_hash = digest_test_sources(tmp_path)
    finished = datetime.now(timezone.utc)
    receipt = {
        "schema": "factory.runtime-coverage-run.v1",
        "runner": "local-powershell",
        "authentication": "UNAUTHENTICATED",
        "commit": commit,
        "dirty_tree": False,
        "command": command,
        "exit_code": 0,
        "started_at": (finished - timedelta(minutes=1)).isoformat(),
        "finished_at": finished.isoformat(),
        "source_code_sha256_before": source_hash,
        "source_code_sha256_after": source_hash,
        "test_code_sha256_before": tests_hash,
        "test_code_sha256_after": tests_hash,
        "environment": {
            "python": "Python 3.11.9",
            "pytest_plugin_autoload": "disabled",
            "pytest_cov": "7.0.0",
        },
        "artifacts": artifacts,
    }
    (tmp_path / ".factory/test-reports/coverage.run.json").write_text(
        json.dumps(receipt), encoding="utf-8"
    )
    return commit, command


def test_runtime_coverage_binder_requires_matching_hashes_and_exact_run(
    tmp_path: Path,
) -> None:
    commit, command = _write_runtime_evidence(tmp_path)

    assert valid_runtime_coverage_evidence(tmp_path, commit=commit, command=command)
    assert not valid_runtime_coverage_evidence(
        tmp_path, commit=commit, command=command + " --mutated"
    )

    coverage_xml = tmp_path / ".factory/test-reports/coverage.xml"
    coverage_xml.write_text("<changed/>\n", encoding="utf-8")
    assert not valid_runtime_coverage_evidence(tmp_path, commit=commit, command=command)
