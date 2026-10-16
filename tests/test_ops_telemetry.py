from __future__ import annotations

import json
from pathlib import Path

from factoryline.cli import main
from factoryline.ops_telemetry import lifecycle_inventory


def test_github_overview_cli_does_not_write_lifecycle_or_snapshot_data(
    tmp_path: Path, capsys
) -> None:
    assert main(["github", "overview", "--root", str(tmp_path), "--json"]) == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] == "UNAVAILABLE"
    assert payload["origin_state"] == "UNRESOLVED"
    assert lifecycle_inventory(tmp_path)["receipt_count"] == 0


def test_cli_writes_privacy_safe_lifecycle_receipt(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["plan"]) == 0
    capsys.readouterr()
    inventory = lifecycle_inventory(tmp_path)
    assert inventory["receipt_count"] == 1
    receipt = next((tmp_path / ".factory" / "ops" / "lifecycle").glob("*.json"))
    value = json.loads(receipt.read_text(encoding="utf-8"))
    assert value["schema"] == "factory.ops-lifecycle.v1"
    assert value["command_family"] == "plan"
    assert str(tmp_path) not in json.dumps(value)
    assert "root" not in json.dumps(value)
    assert "provenance" in value


def test_entrypoint_phase_receipt_preserves_cli_output_and_bounds_fields(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    from factoryline import provenance

    monkeypatch.chdir(tmp_path)
    assert main(["plan"]) == 0
    baseline = capsys.readouterr().out
    assert provenance.main(["plan"]) == 0
    observed = capsys.readouterr().out
    assert observed == baseline

    receipts = list((tmp_path / ".factory" / "ops" / "lifecycle").glob("*.json"))
    values = [json.loads(path.read_text(encoding="utf-8")) for path in receipts]
    measured = next(value for value in values if "phase_telemetry" in value)
    telemetry = measured["phase_telemetry"]
    assert telemetry["status"] == "complete"
    assert len(telemetry["phases"]) <= 12
    phases = {item["phase"]: item for item in telemetry["phases"]}
    assert phases["entrypoint_startup"]["calls"] == 1
    assert phases["receipt_payload"]["calls"] == 1
    assert all(
        isinstance(item[field], int) and item[field] >= 0
        for item in telemetry["phases"]
        for field in ("elapsed_ms", "calls", "completed", "incomplete")
    )
    assert str(tmp_path) not in json.dumps(measured)


def test_receipt_write_failure_preserves_cli_result_and_output(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    from factoryline import ops_telemetry, provenance

    monkeypatch.chdir(tmp_path)
    assert main(["plan"]) == 0
    expected_output = capsys.readouterr().out

    writes = []

    def fail_write(path, payload):
        writes.append((path, payload))
        raise OSError("PRIVATE RECEIPT WRITE DETAIL")

    monkeypatch.setattr(ops_telemetry, "_atomic_json", fail_write)
    assert provenance.main(["plan"]) == 0
    assert capsys.readouterr().out == expected_output

    assert len(writes) == 1
    path, payload = writes[0]
    serialized = json.dumps(payload)
    assert path.parent.name == "lifecycle"
    assert str(tmp_path) not in serialized
    assert "PRIVATE RECEIPT WRITE DETAIL" not in serialized
    assert payload["command_family"] == "plan"
    assert payload["exit_code"] == 0
    assert payload["phase_telemetry"]["status"] == "complete"


def test_nested_phase_telemetry_restores_outer_context_after_inner_error() -> None:
    from factoryline.ops_telemetry import _measure_phase, _phase_telemetry

    with _phase_telemetry(0) as outer:
        with _measure_phase("cli_parse"):
            pass

        try:
            with _phase_telemetry(0) as inner:
                with _measure_phase("proof_evaluation"):
                    raise RuntimeError("private phase detail")
        except RuntimeError:
            pass

        with _measure_phase("cli_dispatch"):
            pass

    outer_snapshot = outer.snapshot()
    inner_snapshot = inner.snapshot()
    assert outer_snapshot["status"] == "complete"
    assert {phase["phase"] for phase in outer_snapshot["phases"]} == {
        "cli_parse",
        "cli_dispatch",
    }
    assert inner_snapshot["status"] == "incomplete"
    assert inner_snapshot["phases"] == [
        {
            "phase": "proof_evaluation",
            "elapsed_ms": inner_snapshot["phases"][0]["elapsed_ms"],
            "calls": 1,
            "completed": 0,
            "incomplete": 1,
        }
    ]


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
