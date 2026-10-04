"""Write a source-bound, explicitly unsigned GitHub Actions coverage receipt."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys

from factoryline.runtime_coverage import (
    CI_COVERAGE_COMMAND,
    digest_test_sources,
    source_code_digest,
)


ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = {
    "junit_xml": ".factory/test-reports/pytest.xml",
    "coverage_json": ".factory/test-reports/coverage.json",
    "coverage_xml": ".factory/test-reports/coverage.xml",
}


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def _write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _artifact_hashes(root: Path) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for name, relative in ARTIFACTS.items():
        path = root / relative
        if not path.is_file():
            raise FileNotFoundError(f"required CI artifact is missing: {relative}")
        result[name] = {
            "path": relative,
            "sha256": sha256(path.read_bytes()).hexdigest(),
        }
    return result


def _start(root: Path = ROOT) -> int:
    start_path = root / ".factory" / "test-reports" / "coverage.start.json"
    head = _git(root, "rev-parse", "HEAD")
    dirty = bool(_git(root, "status", "--porcelain"))
    if dirty:
        raise RuntimeError("coverage CI must start from a clean checkout")
    import pytest_cov

    payload = {
        "commit": head,
        "dirty_tree": False,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "source_code_sha256_before": source_code_digest(root),
        "test_code_sha256_before": digest_test_sources(root),
        "python": sys.version.split()[0],
        "pytest_cov": pytest_cov.__version__,
    }
    _write(start_path, payload)
    print("CI_COVERAGE_RUN_STARTED")
    return 0


def _finish(root: Path = ROOT) -> int:
    start_path = root / ".factory" / "test-reports" / "coverage.start.json"
    receipt_path = root / ".factory" / "test-reports" / "coverage.run.json"
    start = json.loads(start_path.read_text(encoding="utf-8"))
    finished = datetime.now(timezone.utc)
    head = _git(root, "rev-parse", "HEAD")
    dirty = bool(_git(root, "status", "--porcelain"))
    source_after = source_code_digest(root)
    tests_after = digest_test_sources(root)
    outcome = os.environ.get("TEST_OUTCOME", "").lower()
    github = {
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "workflow": os.environ.get("GITHUB_WORKFLOW", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "ref": os.environ.get("GITHUB_REF", ""),
        "commit": os.environ.get("GITHUB_SHA", ""),
    }
    artifacts: dict[str, dict[str, str]] = {}
    artifact_error: str | None = None
    try:
        artifacts = _artifact_hashes(root)
    except (OSError, ValueError) as exc:
        artifact_error = str(exc)
    passed = all(
        (
            os.environ.get("GITHUB_ACTIONS", "").lower() == "true",
            outcome == "success",
            not dirty,
            head == start.get("commit") == github["commit"],
            source_after == start.get("source_code_sha256_before"),
            tests_after == start.get("test_code_sha256_before"),
            all(github.values()),
            start.get("dirty_tree") is False,
            artifact_error is None,
        )
    )
    receipt = {
        "schema": "factory.runtime-coverage-run.v1",
        "runner": "github-actions",
        "authentication": "UNAUTHENTICATED",
        "commit": head,
        "dirty_tree": dirty,
        "command": CI_COVERAGE_COMMAND,
        "exit_code": 0 if passed else 1,
        "started_at": start.get("started_at"),
        "finished_at": finished.isoformat(),
        "source_code_sha256_before": start.get("source_code_sha256_before"),
        "source_code_sha256_after": source_after,
        "test_code_sha256_before": start.get("test_code_sha256_before"),
        "test_code_sha256_after": tests_after,
        "environment": {
            "os": sys.platform,
            "python": f"Python {start.get('python', '')}",
            "pytest_plugin_autoload": "disabled",
            "pytest_cov": start.get("pytest_cov"),
        },
        "github_actions": github,
        "artifacts": artifacts,
        "failure_reason": artifact_error
        or (
            None if passed else "test, clean-checkout, commit, or source binding failed"
        ),
    }
    _write(receipt_path, receipt)
    if not passed:
        print(
            f"CI_COVERAGE_RECEIPT_FAILED: {receipt['failure_reason']}", file=sys.stderr
        )
        return 1
    print("CI_COVERAGE_RECEIPT_WRITTEN_UNAUTHENTICATED")
    return 0


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"start", "finish"}:
        print("usage: write-ci-runtime-coverage.py start|finish", file=sys.stderr)
        return 2
    try:
        return _start() if sys.argv[1] == "start" else _finish()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"CI_COVERAGE_RECEIPT_ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
