"""Bounded mutation adequacy audit; selected checks are not certification."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

MUTMUT_VERSION = "3.8.0"
MUTANT_STATUSES = (
    "killed",
    "survived",
    "total",
    "no_tests",
    "skipped",
    "suspicious",
    "timeout",
    "check_was_interrupted_by_user",
    "segfault",
)


def _git(root: Path, *args: str) -> list[str]:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return [path for path in result.stdout.split("\0") if path]


def _safe_file(root: Path, relative: str, prefix: str) -> Path:
    if not relative.startswith(prefix) or not relative.endswith(".py"):
        raise ValueError(f"expected a Python file under {prefix}: {relative}")
    path = root / relative
    if ".." in Path(relative).parts or path.is_symlink():
        raise ValueError(f"unsafe path: {relative}")
    if not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError(f"missing or escaped path: {relative}")
    return path


def changed_production_sources(root: Path, base: str) -> list[str]:
    """Compare endpoint snapshots without needing a merge base."""
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", base) or set(base) == {"0"}:
        raise ValueError("MUTATION_BASE must be a nonzero full Git commit SHA")
    paths = set(
        _git(
            root,
            "diff",
            "--name-only",
            "-z",
            "--diff-filter=ACMR",
            base,
            "HEAD",
            "--",
            "factoryline",
        )
    )
    paths.update(
        _git(
            root, "diff", "--name-only", "-z", "--diff-filter=ACMR", "--", "factoryline"
        )
    )
    paths.update(
        _git(
            root,
            "diff",
            "--cached",
            "--name-only",
            "-z",
            "--diff-filter=ACMR",
            "--",
            "factoryline",
        )
    )
    sources = sorted(path for path in paths if path.endswith(".py"))
    for relative in sources:
        _safe_file(root, relative, "factoryline/")
    return sources


def _selected_paths(root: Path, variable: str, prefix: str) -> list[str]:
    paths = json.loads(os.environ.get(variable, "[]"))
    if not isinstance(paths, list) or not paths:
        raise ValueError(f"{variable} must be a nonempty JSON list of Python files")
    for relative in paths:
        if not isinstance(relative, str):
            raise ValueError(f"{variable} contains a non-string path")
        _safe_file(root, relative, prefix)
    return sorted(set(paths))


def _valid_stats(stats: Any) -> tuple[bool, str]:
    if not isinstance(stats, dict) or any(
        type(stats.get(key)) is not int or stats[key] < 0 for key in MUTANT_STATUSES
    ):
        return False, "mutation report is missing nonnegative integer counters"
    if stats["total"] == 0:
        return False, "no mutants were executed; test adequacy is unproven"
    counted = sum(stats[key] for key in MUTANT_STATUSES if key != "total")
    if counted != stats["total"]:
        return False, "mutation report is incomplete or contains unclassified mutants"
    if stats["survived"]:
        return (
            False,
            f"{stats['survived']} scoped mutants survived; inspect findings.txt",
        )
    failures = {
        key: stats[key]
        for key in MUTANT_STATUSES
        if key not in {"killed", "total"} and stats[key]
    }
    if failures:
        return False, f"mutations were not rejected cleanly: {failures}"
    return True, "all scoped mutants were rejected by the selected checks"


def _write_summary(receipt: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        stats = receipt.get("stats", {})
        with Path(summary).open("a", encoding="utf-8") as stream:
            stream.write(
                "\n### Code Factory scoped mutation audit\n\n"
                f"- State: **{receipt['state']}**\n"
                f"- Source files: {len(receipt['source_files'])}\n"
                f"- Mutants: {stats.get('killed', 0)}/{stats.get('total', 0)} rejected\n"
                f"- Result: {receipt['message']}\n"
                "- This is scoped adequacy evidence, not full-code certification.\n"
            )


def _copy_snapshot(root: Path, target: Path) -> str:
    """Copy tracked current bytes only, including required root fixtures."""
    digest = hashlib.sha256()
    total = 0
    for relative in sorted(_git(root, "ls-files", "-z")):
        path = root / relative
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError(f"tracked path escaped checkout: {relative}")
        if not path.is_file():
            raise ValueError(f"tracked file unavailable: {relative}")
        size = path.stat().st_size
        total += size
        if size > 50_000_000 or total > 500_000_000:
            raise ValueError("tracked snapshot exceeded its byte limit")
        data = path.read_bytes()
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        digest.update(relative.encode("utf-8") + b"\0" + hashlib.sha256(data).digest())
    return digest.hexdigest()


def _configure(target: Path, sources: list[str], tests: list[str]) -> None:
    config_path = target / "pyproject.toml"
    original = config_path.read_text(encoding="utf-8")
    if "[tool.mutmut]" in original or (target / "mutants").exists():
        raise ValueError("snapshot already has mutation configuration or cache")
    extras = sorted(
        path.name for path in target.iterdir() if path.name != "factoryline"
    )
    settings = {
        "source_paths": ["factoryline/"],
        "only_mutate": sources,
        "also_copy": extras,
        "pytest_add_cli_args_test_selection": tests,
        "pytest_add_cli_args": ["-p", "no:xdist", "-p", "pytest_asyncio.plugin"],
        "use_git_change_detection": False,
    }
    lines = [f"{key} = {json.dumps(value)}" for key, value in settings.items()]
    config_path.write_text(
        original + "\n[tool.mutmut]\n" + "\n".join(lines) + "\n", encoding="utf-8"
    )


def _run(command: list[str], cwd: Path, log: Path, timeout: int) -> int:
    env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
    with log.open("w", encoding="utf-8") as stream:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise


def _read_stats(target: Path) -> dict[str, int]:
    path = target / "mutants" / "mutmut-cicd-stats.json"
    if not path.is_file() or path.stat().st_size > 100_000:
        return {}
    stats = json.loads(path.read_text(encoding="utf-8"))
    return stats if isinstance(stats, dict) else {}


def _save_findings(target: Path, directory: Path) -> bool:
    listing = directory / "findings.txt"
    deadline = time.monotonic() + 120
    if _run([sys.executable, "-m", "mutmut", "results"], target, listing, 30):
        return False
    mutants = re.findall(
        r"^\s*(\S+): survived\s*$", listing.read_text(encoding="utf-8"), re.MULTILINE
    )
    for index, mutant in enumerate(mutants[:50]):
        remaining = deadline - time.monotonic()
        if remaining < 1:
            with listing.open("a", encoding="utf-8") as stream:
                stream.write(
                    "\nSurvivor diff budget exhausted; all IDs remain above.\n"
                )
            break
        if _run(
            [sys.executable, "-m", "mutmut", "show", mutant],
            target,
            directory / f"survivor-{index + 1}.diff",
            min(30, int(remaining)),
        ):
            return False
    return True


def _execute(root: Path, receipt: dict[str, Any], directory: Path) -> None:
    if os.name != "posix":
        raise ValueError("mutmut needs Linux/macOS; use the Linux CI workflow")
    if importlib.metadata.version("mutmut") != MUTMUT_VERSION:
        raise ValueError(f"mutmut {MUTMUT_VERSION} is required")
    tests = _selected_paths(root, "MUTATION_TESTS", "tests/")
    receipt["oracle_files"] = tests
    with tempfile.TemporaryDirectory(prefix="cf-mutation-") as temporary:
        target = Path(temporary)
        receipt["snapshot_sha256"] = _copy_snapshot(root, target)
        _configure(target, receipt["source_files"], tests)
        command = [sys.executable, "-m", "mutmut"]
        run_code = _run(
            command + ["run", "--max-children", "2"],
            target,
            directory / "execution.log",
            20 * 60,
        )
        export_code = _run(
            command + ["export-cicd-stats"], target, directory / "export.log", 30
        )
        receipt.update(
            stats=_read_stats(target),
            mutmut_exit_code=run_code,
            export_exit_code=export_code,
        )
        diagnostics_ok = _save_findings(target, directory)
        passed, message = _valid_stats(receipt["stats"])
        if run_code or export_code:
            passed, message = False, "mutation engine failed; inspect execution.log"
        if not diagnostics_ok:
            passed, message = (
                False,
                "mutation findings export failed; inspect findings.txt",
            )
        receipt.update(state="PASS" if passed else "BLOCKED", message=message)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    output = Path(os.environ.get("MUTATION_OUTPUT", "tmp/mutation-audit/receipt.json"))
    output.parent.mkdir(parents=True, exist_ok=True)
    receipt: dict[str, Any] = {
        "schema": "factory.ci_mutation_adequacy.v1",
        "tool": {"name": "mutmut", "version": MUTMUT_VERSION},
        "source_files": [],
        "stats": {},
        "state": "BLOCKED",
        "authority": "scoped-evidence-only",
    }
    try:
        base = os.environ.get("MUTATION_BASE", "")
        receipt.update(
            base_sha=base, head_sha=_git(root, "rev-parse", "HEAD")[0].strip()
        )
        receipt["source_files"] = (
            _selected_paths(root, "MUTATION_SOURCES", "factoryline/")
            if os.environ.get("MUTATION_SOURCES")
            else changed_production_sources(root, base)
        )
        if not receipt["source_files"]:
            raise ValueError(
                "no scoped production sources; no mutation evidence produced"
            )
        _execute(root, receipt, output.parent)
    except (
        OSError,
        ValueError,
        subprocess.SubprocessError,
        importlib.metadata.PackageNotFoundError,
    ) as error:
        receipt.update(state="BLOCKED", message=f"{type(error).__name__}: {error}")
    _write_summary(receipt, output)
    print(receipt["message"])
    return 0 if receipt["state"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
