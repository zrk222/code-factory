from __future__ import annotations

import json
from pathlib import Path

from factoryline.run_metrics import write_run_receipt
from factoryline.telemetry import telemetry_inventory, public_inventory_summary


def test_telemetry_reconciles_sources_and_hides_workspace_details(tmp_path: Path):
    (tmp_path / "receipts").mkdir()
    (tmp_path / "receipts" / "specline.json").write_text(json.dumps({
        "module": "specline", "stage": "strict", "feature": "private-feature", "ok": True,
        "run_id": "run-1", "outputs": {"prompt": "must not be public"},
    }), encoding="utf-8")
    write_run_receipt(tmp_path, {"run_id": "run-1", "feature": "private-feature", "terminal": "completed"})
    (tmp_path / ".factory").mkdir(exist_ok=True)
    (tmp_path / ".factory" / "meter.jsonl").write_text(json.dumps({
        "run_id": "run-1", "tokens_in": None, "tokens_out": None, "cost_usd": None,
    }) + "\n", encoding="utf-8")
    inventory = telemetry_inventory(tmp_path)
    assert inventory["schema"] == "factory.telemetry-inventory.v1"
    assert inventory["quality"] == "exact"
    assert inventory["runs"]["distinct"] == 1
    public = public_inventory_summary(tmp_path)
    assert "private-feature" not in json.dumps(public)
    assert "prompt" not in json.dumps(public)


def test_telemetry_marks_conflicting_run_identity(tmp_path: Path):
    runs = tmp_path / ".factory" / "runs"
    runs.mkdir(parents=True)
    for name, terminal in (("one.json", "completed"), ("two.json", "failed")):
        (runs / name).write_text(json.dumps({
            "schema": "factory.assembly-run.v1", "run_id": "same-run", "terminal": terminal,
        }), encoding="utf-8")
    inventory = telemetry_inventory(tmp_path)
    assert inventory["quality"] == "conflicted"
    assert inventory["conflicts"] == ["same-run"]
