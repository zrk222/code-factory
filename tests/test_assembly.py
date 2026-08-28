from __future__ import annotations

import json
from pathlib import Path

from factoryline.assembly import DEFAULT_CHAIN, assemble


def test_default_chain_contains_conditional_prestige_gate():
    assert ("prestige", ["score", "smoke/{f}.ui", "--json", "--strict"]) in DEFAULT_CHAIN


def test_assembly_marks_prestige_not_applicable_without_ui_scope(tmp_path: Path, monkeypatch):
    class Present:
        installed = True

    monkeypatch.setattr("factoryline.assembly.detect", lambda: [
        type("Module", (), {"name": name, "installed": True, "cli": name, "role": "test"})()
        for name in ("specline", "forgeline", "hsf", "prestige")
    ])
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "feature.md").write_text("# feature\n", encoding="utf-8")
    report = assemble(tmp_path, "feature", chain=[("prestige", ["score", "smoke/{f}.ui", "--json", "--strict"])])
    assert report["stages"][0]["status"] == "skipped"
    assert report["stages"][0]["reason"] == "ui_scope_not_declared"


def test_assembly_preserves_explicit_forge_intent_trace_in_standard_receipt(tmp_path: Path, monkeypatch):
    class Module:
        def __init__(self, name: str):
            self.name = name
            self.installed = True
            self.cli = name
            self.role = "test"

    monkeypatch.setattr("factoryline.assembly.detect", lambda: [Module(name) for name in ("specline", "forgeline", "hsf", "prestige")])
    ship_line = {
        "phase": "ship",
        "ts": "2026-08-24T12:01:00Z",
        "shipped": True,
        "intent_hash": "a" * 64,
        "obligations": "1/1",
    }
    forge_receipts = tmp_path / ".forge" / "adapter-feature" / "receipts.jsonl"
    forge_receipts.parent.mkdir(parents=True)
    forge_receipts.write_text(json.dumps(ship_line) + "\n", encoding="utf-8")
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "adapter-feature.md").write_text("# adapter\n", encoding="utf-8")
    cli_output = json.dumps({
        "shipped": True,
        "intent_traceable": True,
        "intent_hash": "a" * 64,
        "obligations_met": "1/1",
    })
    monkeypatch.setattr("factoryline.assembly._run_cli", lambda *args, **kwargs: (True, cli_output))

    report = assemble(tmp_path, "adapter-feature", chain=[("forgeline", ["ship", "{f}"])])

    assert report["stages"][0]["status"] == "ok"
    receipts = list((tmp_path / "receipts").glob("forgeline-adapter-feature-ship-*.json"))
    assert len(receipts) == 1
    payload = json.loads(receipts[0].read_text(encoding="utf-8"))
    adapter = payload["outputs"]["intent_trace"]
    assert adapter["schema"] == "factoryline.intent-trace.v1"
    assert adapter["intent_traceable"] is True
    assert adapter["shipped"] is True
    assert adapter["intent_hash"] == "a" * 64
    assert adapter["obligations"] == "1/1"
    assert len(adapter["forge_receipt_sha256"]) == 64
    assert adapter["authority"]["execution"] is False


def test_assembly_omits_inferred_forge_intent_trace_when_cli_flag_is_missing(tmp_path: Path, monkeypatch):
    class Module:
        def __init__(self, name: str):
            self.name = name
            self.installed = True
            self.cli = "forge" if name == "forgeline" else name
            self.role = "test"

    monkeypatch.setattr("factoryline.assembly.detect", lambda: [Module(name) for name in ("specline", "forgeline", "hsf", "prestige")])
    forge_receipts = tmp_path / ".forge" / "missing-adapter" / "receipts.jsonl"
    forge_receipts.parent.mkdir(parents=True)
    forge_receipts.write_text(json.dumps({"phase": "ship", "shipped": True}) + "\n", encoding="utf-8")
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "missing-adapter.md").write_text("# adapter\n", encoding="utf-8")
    monkeypatch.setattr("factoryline.assembly._run_cli", lambda *args, **kwargs: (True, '{"shipped":true}'))

    assemble(tmp_path, "missing-adapter", chain=[("forgeline", ["ship", "{f}"])])

    receipts = list((tmp_path / "receipts").glob("forgeline-missing-adapter-ship-*.json"))
    payload = json.loads(receipts[0].read_text(encoding="utf-8"))
    assert "intent_trace" not in payload["outputs"]
