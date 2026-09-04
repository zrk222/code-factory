from __future__ import annotations

import subprocess
from pathlib import Path

from factoryline import provenance as provenance_module


def test_source_commit_fails_closed_when_git_status_times_out(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "factoryline-code-factory"\n',
        encoding="utf-8",
    )
    module_dir = tmp_path / "factoryline"
    module_dir.mkdir()

    calls = 0

    def run(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(args[0], 0, stdout="abc123\n", stderr="")
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(provenance_module.subprocess, "run", run)
    assert provenance_module._source_commit(module_dir) is None
