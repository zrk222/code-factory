import builtins
import json
import subprocess
from pathlib import Path

from factoryline import bootstrap
from factoryline import provenance as provenance_module


def test_version_fast_path_does_not_import_command_registry(monkeypatch, capsys):
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "factoryline.cli":
            raise AssertionError("version probes must not import the full CLI registry")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    assert bootstrap.main(["--version", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "factoryline.provenance.v1"
    assert payload["package"] == "factoryline-code-factory"


def test_non_version_commands_delegate_to_full_cli(monkeypatch):
    calls = []

    class StubCli:
        @staticmethod
        def main(values):
            calls.append(values)
            return 7

    monkeypatch.setitem(__import__("sys").modules, "factoryline.cli", StubCli)
    assert bootstrap.main(["plan"]) == 7
    assert calls == [["plan"]]


def test_source_commit_fails_closed_when_git_status_times_out(
    tmp_path: Path, monkeypatch
) -> None:
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
