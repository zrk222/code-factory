from __future__ import annotations

import json
from pathlib import Path

from factoryline.cli import main
from factoryline.ops_telemetry import lifecycle_inventory


def test_cli_writes_privacy_safe_lifecycle_receipt(tmp_path: Path, capsys) -> None:
    assert main(["home", "--root", str(tmp_path), "--json"]) == 0
    capsys.readouterr()
    inventory = lifecycle_inventory(tmp_path)
    assert inventory["receipt_count"] == 1
    receipt = next((tmp_path / ".factory" / "ops" / "lifecycle").glob("*.json"))
    value = json.loads(receipt.read_text(encoding="utf-8"))
    assert value["schema"] == "factory.ops-lifecycle.v1"
    assert value["command_family"] == "home"
    assert str(tmp_path) not in json.dumps(value)
    assert "root" not in json.dumps(value)
    assert "provenance" in value


def test_lifecycle_command_family_never_retains_free_form_prompt(
    tmp_path: Path,
) -> None:
    from factoryline.ops_telemetry import _command_family

    assert (
        _command_family(
            ["create", "a private customer prompt", "--root", str(tmp_path)]
        )
        == "create"
    )


def test_lifecycle_failure_is_recorded_without_changing_exit_semantics(
    tmp_path: Path, capsys
) -> None:
    assert (
        main(
            [
                "architecture",
                "health",
                "--root",
                str(tmp_path),
                "--policy",
                "missing.json",
            ]
        )
        == 2
    )
    capsys.readouterr()
    inventory = lifecycle_inventory(tmp_path)
    assert inventory["receipt_count"] == 1
    assert inventory["statuses"] == {"blocked": 1}
