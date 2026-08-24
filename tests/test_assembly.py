from __future__ import annotations

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
