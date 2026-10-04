from __future__ import annotations

import json
from pathlib import Path
import runpy
import subprocess


_WRITER_PATH = Path(__file__).parents[1] / "tools" / "workflow-audit" / "write-ci-runtime-coverage.py"


def _git_fixture(root: Path) -> str:
    (root / ".gitignore").write_text(".factory/\n__pycache__/\n*.py[cod]\n", encoding="utf-8")
    (root / "factoryline").mkdir()
    (root / "factoryline" / "demo.py").write_text("value = 1\n", encoding="utf-8")
    (root / "tests").mkdir()
    (root / "tests" / "test_demo.py").write_text(
        "def test_demo():\n    assert True\n", encoding="utf-8"
    )
    subprocess.run(["git", "init", "--quiet", str(root)], check=True)
    for key, value in (("user.name", "CI Fixture"), ("user.email", "ci@example.invalid")):
        subprocess.run(["git", "-C", str(root), "config", key, value], check=True)
    subprocess.run(["git", "-C", str(root), "add", ".gitignore", "factoryline", "tests"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "--quiet", "-m", "fixture"], check=True)
    return subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _reports(root: Path) -> None:
    directory = root / ".factory" / "test-reports"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "pytest.xml").write_text("<testsuites/>\n", encoding="utf-8")
    (directory / "coverage.json").write_text("{}\n", encoding="utf-8")
    (directory / "coverage.xml").write_text("<coverage/>\n", encoding="utf-8")


def _writer(root: Path, monkeypatch, commit: str, outcome: str):
    writer = runpy.run_path(str(_WRITER_PATH))
    for key, value in {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "example/repo",
        "GITHUB_WORKFLOW": "CI",
        "GITHUB_RUN_ID": "12345",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_REF": "refs/pull/1/merge",
        "GITHUB_SHA": commit,
        "TEST_OUTCOME": outcome,
    }.items():
        monkeypatch.setenv(key, value)
    return writer


def test_ci_receipt_binds_clean_commit_exact_command_and_required_artifacts(
    tmp_path: Path, monkeypatch
) -> None:
    commit = _git_fixture(tmp_path)
    writer = _writer(tmp_path, monkeypatch, commit, "success")

    assert writer["_start"](tmp_path) == 0
    _reports(tmp_path)
    assert writer["_finish"](tmp_path) == 0

    receipt = json.loads(
        (tmp_path / ".factory/test-reports/coverage.run.json").read_text(encoding="utf-8")
    )
    assert receipt["runner"] == "github-actions"
    assert receipt["authentication"] == "UNAUTHENTICATED"
    assert receipt["commit"] == commit
    assert receipt["dirty_tree"] is False
    assert receipt["exit_code"] == 0
    assert receipt["command"].endswith("--cov-report=xml:.factory/test-reports/coverage.xml")
    assert receipt["github_actions"]["run_id"] == "12345"
    assert set(receipt["artifacts"]) == {"junit_xml", "coverage_json", "coverage_xml"}
def test_failed_ci_run_writes_a_nonpassing_receipt(tmp_path: Path, monkeypatch) -> None:
    commit = _git_fixture(tmp_path)
    writer = _writer(tmp_path, monkeypatch, commit, "failure")

    assert writer["_start"](tmp_path) == 0
    _reports(tmp_path)
    assert writer["_finish"](tmp_path) == 1

    receipt = json.loads(
        (tmp_path / ".factory/test-reports/coverage.run.json").read_text(encoding="utf-8")
    )
    assert receipt["exit_code"] == 1
    assert receipt["failure_reason"] == "test, clean-checkout, commit, or source binding failed"
