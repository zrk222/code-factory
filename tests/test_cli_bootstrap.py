import builtins
import json

from factoryline import bootstrap


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
