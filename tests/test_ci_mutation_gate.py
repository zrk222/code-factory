from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.ci_mutation_gate import (
    _configure,
    _copy_snapshot,
    _safe_file,
    _selected_paths,
    _valid_stats,
    changed_production_sources,
)


def test_changed_production_sources_limits_to_python_and_local_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "factoryline" / "changed.py"
    source.parent.mkdir()
    source.write_text("value = True\n", encoding="utf-8")
    (tmp_path / "factoryline" / "changed.md").write_text("docs", encoding="utf-8")
    for name in ("staged.py", "local.py"):
        (source.parent / name).write_text("value = False\n", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if command[1] == "diff":
            if "--cached" in command:
                output = "factoryline/staged.py\0"
            elif "HEAD" in command:
                output = "factoryline/changed.py\0factoryline/changed.md\0"
            else:
                output = "factoryline/local.py\0"
        else:
            output = ""
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr("scripts.ci_mutation_gate.subprocess.run", fake_run)
    result = changed_production_sources(tmp_path, "a" * 40)

    assert result == [
        "factoryline/changed.py",
        "factoryline/local.py",
        "factoryline/staged.py",
    ]
    assert len(calls) == 3
    assert "...HEAD" not in calls[0]
    assert "a" * 40 in calls[0] and "HEAD" in calls[0]


@pytest.mark.parametrize(
    ("overrides", "expected", "message"),
    [
        ({}, True, "all scoped mutants"),
        ({"survived": 1, "killed": 2}, False, "scoped mutants survived"),
        ({"no_tests": 1, "killed": 2}, False, "not rejected cleanly"),
        ({"total": 0, "killed": 0}, False, "no mutants were executed"),
        ({"segfault": 1, "killed": 2}, False, "not rejected cleanly"),
        ({"killed": -1, "survived": 4}, False, "nonnegative integer"),
        ({"killed": True}, False, "nonnegative integer"),
    ],
)
def test_mutation_gate_requires_complete_clean_survival_results(
    overrides: dict[str, int], expected: bool, message: str
) -> None:
    stats = {
        "killed": 3,
        "survived": 0,
        "total": 3,
        "no_tests": 0,
        "skipped": 0,
        "suspicious": 0,
        "timeout": 0,
        "check_was_interrupted_by_user": 0,
        "segfault": 0,
    }
    stats.update(overrides)

    passed, reason = _valid_stats(stats)

    assert passed is expected
    assert message in reason


def test_mutation_gate_rejects_incomplete_or_untyped_counters() -> None:
    assert _valid_stats({"total": 0}) == (
        False,
        "mutation report is missing nonnegative integer counters",
    )
    stats = {
        "killed": 1,
        "survived": 0,
        "total": 2,
        "no_tests": 0,
        "skipped": 0,
        "suspicious": 0,
        "timeout": 0,
        "check_was_interrupted_by_user": 0,
        "segfault": 0,
    }
    assert _valid_stats(stats) == (
        False,
        "mutation report is incomplete or contains unclassified mutants",
    )


def test_mutation_scope_rejects_missing_files_and_invalid_base(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="nonzero full Git"):
        changed_production_sources(tmp_path, "0" * 40)
    with pytest.raises(ValueError, match="unsafe path"):
        _safe_file(tmp_path, "factoryline/../outside.py", "factoryline/")
    with pytest.raises(ValueError, match="missing or escaped"):
        _safe_file(tmp_path, "factoryline/missing.py", "factoryline/")


def test_explicit_behavioral_oracles_required(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MUTATION_TESTS", raising=False)
    with pytest.raises(ValueError, match="nonempty JSON"):
        _selected_paths(tmp_path, "MUTATION_TESTS", "tests/")
    test = tmp_path / "tests" / "test_boundary.py"
    test.parent.mkdir()
    test.write_text("def test_boundary(): assert 1 == 1\n", encoding="utf-8")
    monkeypatch.setenv("MUTATION_TESTS", '["tests/test_boundary.py"]')
    assert _selected_paths(tmp_path, "MUTATION_TESTS", "tests/") == [
        "tests/test_boundary.py"
    ]


def test_snapshot_copies_only_tracked_files_and_binds_current_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    (source / "tracked.py").write_text("value = 1\n", encoding="utf-8")
    (source / "private.env").write_text("private", encoding="utf-8")
    monkeypatch.setattr("scripts.ci_mutation_gate._git", lambda *_args: ["tracked.py"])
    digest = _copy_snapshot(source.resolve(), target)
    assert (target / "tracked.py").read_text(encoding="utf-8") == "value = 1\n"
    assert not (target / "private.env").exists()
    (source / "tracked.py").write_text("value = 2\n", encoding="utf-8")
    assert _copy_snapshot(source.resolve(), target) != digest


def test_mutation_configuration_preserves_fixture_paths(tmp_path: Path) -> None:
    import json

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="example"\n', encoding="utf-8"
    )
    (tmp_path / "factoryline").mkdir()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "architecture-policy.json").write_text("{}", encoding="utf-8")
    _configure(tmp_path, ["factoryline/boundary.py"], ["tests/test_boundary.py"])
    table = (
        (tmp_path / "pyproject.toml")
        .read_text(encoding="utf-8")
        .split("[tool.mutmut]\n")[1]
    )
    settings = dict(
        (key.strip(), json.loads(value))
        for key, value in (line.split("=", 1) for line in table.splitlines() if line)
    )
    assert settings["only_mutate"] == ["factoryline/boundary.py"]
    assert settings["pytest_add_cli_args_test_selection"] == ["tests/test_boundary.py"]
    assert "scripts" in settings["also_copy"]
    assert "architecture-policy.json" in settings["also_copy"]
    assert settings["use_git_change_detection"] is False


def test_endpoint_diff_works_without_shallow_merge_base(tmp_path: Path) -> None:
    def git(cwd: Path, *args: str) -> str:
        result = subprocess.run(
            ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
        )
        return result.stdout.strip()

    origin = tmp_path / "origin"
    origin.mkdir()
    git(origin, "init")
    git(origin, "config", "user.name", "CI fixture")
    git(origin, "config", "user.email", "ci@example.invalid")
    module = origin / "factoryline" / "boundary.py"
    module.parent.mkdir()
    module.write_text("value = True\n", encoding="utf-8")
    git(origin, "add", ".")
    git(origin, "commit", "-m", "base")
    base = git(origin, "rev-parse", "HEAD")
    module.write_text("value = False\n", encoding="utf-8")
    git(origin, "commit", "-am", "candidate")
    checkout = tmp_path / "shallow"
    git(tmp_path, "clone", "--depth=1", origin.as_uri(), str(checkout))
    git(checkout, "fetch", "--depth=1", "origin", base)
    assert git(checkout, "rev-parse", "--is-shallow-repository") == "true"
    assert changed_production_sources(checkout, base) == ["factoryline/boundary.py"]
