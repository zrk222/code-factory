from __future__ import annotations

import json
from pathlib import Path

from factoryline.assembly import DEFAULT_CHAIN, assemble


def _detailed_result(output, *, ok=True, exit_code=0, cleanup=True, streams=True):
    raw = output.encode("utf-8")
    return {
        "ok": ok,
        "output": output,
        "stdout": raw,
        "stderr": b"",
        "exit_code": exit_code,
        "cleanup_confirmed": cleanup,
        "streams_closed": streams,
        "reason": None if ok else "process failed",
    }


def test_default_chain_contains_conditional_prestige_gate():
    assert (
        "prestige",
        ["score", "smoke/{f}.ui", "--json", "--strict"],
    ) in DEFAULT_CHAIN


def test_assembly_marks_prestige_not_applicable_without_ui_scope(
    tmp_path: Path, monkeypatch
):
    class Present:
        installed = True

    monkeypatch.setattr(
        "factoryline.assembly.detect",
        lambda: [
            type(
                "Module",
                (),
                {"name": name, "installed": True, "cli": name, "role": "test"},
            )()
            for name in ("specline", "forgeline", "hsf", "prestige")
        ],
    )
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "feature.md").write_text("# feature\n", encoding="utf-8")
    report = assemble(
        tmp_path,
        "feature",
        chain=[("prestige", ["score", "smoke/{f}.ui", "--json", "--strict"])],
    )
    assert report["stages"][0]["status"] == "skipped"
    assert report["stages"][0]["reason"] == "ui_scope_not_declared"


def test_assembly_fails_closed_when_release_contract_declares_missing_ui_scope(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setattr(
        "factoryline.assembly.detect",
        lambda: [
            type(
                "Module",
                (),
                {"name": name, "installed": True, "cli": name, "role": "test"},
            )()
            for name in ("specline", "forgeline", "hsf", "prestige")
        ],
    )
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "feature.md").write_text("# feature\n", encoding="utf-8")
    contract = tmp_path / ".factory/release-contracts/feature.json"
    contract.parent.mkdir(parents=True)
    contract.write_text(
        json.dumps({"required_stages": ["prestige:score"]}), encoding="utf-8"
    )

    report = assemble(
        tmp_path,
        "feature",
        chain=[("prestige", ["score", "smoke/{f}.ui", "--json", "--strict"])],
    )

    assert report["stages"][0]["marker"] == "UI_SCOPE_REQUIRED_EVIDENCE_MISSING"
    assert report["halted_at"] == "prestige:score"


def test_assembly_preserves_explicit_forge_intent_trace_in_standard_receipt(
    tmp_path: Path, monkeypatch
):
    class Module:
        def __init__(self, name: str):
            self.name = name
            self.installed = True
            self.cli = name
            self.role = "test"

    monkeypatch.setattr(
        "factoryline.assembly.detect",
        lambda: [Module(name) for name in ("specline", "forgeline", "hsf", "prestige")],
    )
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
    (tmp_path / "specs" / "adapter-feature.md").write_text(
        "# adapter\n", encoding="utf-8"
    )
    cli_output = json.dumps(
        {
            "shipped": True,
            "intent_traceable": True,
            "intent_hash": "a" * 64,
            "obligations_met": "1/1",
        }
    )
    monkeypatch.setattr(
        "factoryline.assembly.run_cli_detailed",
        lambda *args, **kwargs: _detailed_result(cli_output),
    )

    report = assemble(
        tmp_path, "adapter-feature", chain=[("forgeline", ["ship", "{f}"])]
    )

    assert report["stages"][0]["status"] == "ok"
    receipts = list(
        (tmp_path / "receipts").glob("forgeline-adapter-feature-ship-*.json")
    )
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


def test_assembly_omits_inferred_forge_intent_trace_when_cli_flag_is_missing(
    tmp_path: Path, monkeypatch
):
    class Module:
        def __init__(self, name: str):
            self.name = name
            self.installed = True
            self.cli = "forge" if name == "forgeline" else name
            self.role = "test"

    monkeypatch.setattr(
        "factoryline.assembly.detect",
        lambda: [Module(name) for name in ("specline", "forgeline", "hsf", "prestige")],
    )
    forge_receipts = tmp_path / ".forge" / "missing-adapter" / "receipts.jsonl"
    forge_receipts.parent.mkdir(parents=True)
    forge_receipts.write_text(
        json.dumps({"phase": "ship", "shipped": True}) + "\n", encoding="utf-8"
    )
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "missing-adapter.md").write_text(
        "# adapter\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        "factoryline.assembly.run_cli_detailed",
        lambda *args, **kwargs: _detailed_result('{"shipped":true}'),
    )

    assemble(tmp_path, "missing-adapter", chain=[("forgeline", ["ship", "{f}"])])

    receipts = list(
        (tmp_path / "receipts").glob("forgeline-missing-adapter-ship-*.json")
    )
    payload = json.loads(receipts[0].read_text(encoding="utf-8"))
    assert "intent_trace" not in payload["outputs"]


def test_assembly_enrolls_and_records_detailed_cli_attempts(tmp_path, monkeypatch):
    class Module:
        def __init__(self, name):
            self.name = name
            self.installed = True
            self.cli = name
            self.role = "test"

    monkeypatch.setattr(
        "factoryline.assembly.detect",
        lambda: [Module(name) for name in ("specline", "forgeline", "hsf", "prestige")],
    )
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "repeat.md").write_text("# repeat\n", encoding="utf-8")
    seen = []

    def run_detailed(*args, **kwargs):
        receipts = list((tmp_path / "receipts").glob("forgeline-repeat-ship-*.json"))
        assert len(receipts) == len(seen) + 1
        enrolled_rows = [
            json.loads(path.read_text(encoding="utf-8")) for path in receipts
        ]
        enrolled = next(
            row
            for row in enrolled_rows
            if row["outputs"]["cli_action"]["action_id"]
            not in {action["action_id"] for action in seen}
        )
        assert enrolled["ok"] is False
        assert enrolled["outputs"]["cli_action"]["state"] == "ENROLLED"
        seen.append(enrolled["outputs"]["cli_action"])
        return _detailed_result("out", ok=True)

    monkeypatch.setattr("factoryline.assembly.run_cli_detailed", run_detailed)
    report = assemble(
        tmp_path,
        "repeat",
        chain=[("forgeline", ["ship", "{f}"]), ("forgeline", ["ship", "{f}"])],
    )
    assert [row["status"] for row in report["stages"]] == ["ok", "ok"]
    assert [row["attempt"] for row in seen] == [1, 2]
    assert seen[0]["action_id"] != seen[1]["action_id"]
    receipts = list((tmp_path / "receipts").glob("forgeline-repeat-ship-*.json"))
    assert len(receipts) == 2
    for path in receipts:
        payload = json.loads(path.read_text(encoding="utf-8"))
        action = payload["outputs"]["cli_action"]
        assert payload["ok"] is True
        assert payload["run_id"] == action["action_id"]
        assert payload["outputs"]["assembly_run_id"] == report["run_id"]
        assert action["state"] == "COMPLETED"
        assert action["stdout_bytes"] == 3
        assert len(action["stdout_sha256"]) == 64
        assert action["stderr_bytes"] == 0
        assert action["cleanup_confirmed"] is True
        assert action["streams_closed"] is True
        assert "args" not in action


def test_assembly_cleanup_failure_does_not_mark_cli_action_success(
    tmp_path, monkeypatch
):
    class Module:
        def __init__(self, name):
            self.name = name
            self.installed = True
            self.cli = name
            self.role = "test"

    monkeypatch.setattr(
        "factoryline.assembly.detect",
        lambda: [Module(name) for name in ("specline", "forgeline", "hsf", "prestige")],
    )
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "bad.md").write_text("# bad\n", encoding="utf-8")
    monkeypatch.setattr(
        "factoryline.assembly.run_cli_detailed",
        lambda *args, **kwargs: _detailed_result(
            "out", ok=False, exit_code=0, cleanup=False
        ),
    )
    report = assemble(tmp_path, "bad", chain=[("forgeline", ["ship", "{f}"])])
    assert report["stages"][0]["status"] == "failed"
    path = next((tmp_path / "receipts").glob("forgeline-bad-ship-*.json"))
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["ok"] is False
    assert payload["outputs"]["cli_action"]["state"] == "INCOMPLETE"


def test_cli_action_rejects_malformed_detailed_result():
    from factoryline.assembly import _cli_action_result

    ok, facts = _cli_action_result({"ok": True, "exit_code": False, "stdout": "raw"})
    assert ok is False
    assert facts["state"] == "INCOMPLETE"
    assert facts["stdout_bytes"] is None
    assert facts["stdout_sha256"] is None


def test_cli_action_id_binds_release_binding():
    from factoryline.assembly import _AssemblyStage, _cli_action_id

    stage = _AssemblyStage(
        "forgeline", "forgeline", ["ship", "{f}"], "ship", "forgeline:ship", True, True
    )
    first = _cli_action_id("run", stage, 1, {"release": "a" * 64})
    changed = _cli_action_id("run", stage, 1, {"release": "b" * 64})

    assert first != changed
