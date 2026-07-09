"""Tests for the factoryline connector — Lego assembly + honest metering."""
import json
from pathlib import Path
from factoryline.contract import ensure_layout, LAYOUT, Receipt, Meter, MODULES, STAGES
from factoryline.assembly import detect, assemble, DEFAULT_CHAIN
from factoryline.meter import summarize, summary_table, MeterLog, StageTiming
from factoryline.attribution import Attribution, FailureClass, UnitResult
from factoryline.assembly import rollup_attributions
from factoryline.boundary import assert_no_attribution_in_artifact


def test_layout_created(tmp_path):
    ensure_layout(tmp_path)
    for sub in LAYOUT.values():
        assert (tmp_path / sub).is_dir()


def test_detect_returns_all_four_modules():
    names = {m.name for m in detect()}
    assert names == {"specline", "forgeline", "hsf", "prestige"}


def test_receipt_roundtrip(tmp_path):
    ensure_layout(tmp_path)
    r = Receipt(module="specline", stage="strict", feature="f", ok=True,
                meter=Meter(wall_ms=12))
    p = r.write(tmp_path)
    data = json.loads(p.read_text())
    assert data["module"] == "specline" and data["ok"] is True
    assert data["meter"]["wall_ms"] == 12


def test_meter_refuses_percentage_with_no_runs(tmp_path):
    ensure_layout(tmp_path)
    summ = summarize(tmp_path)
    assert summ["stages_measured"] == 0
    assert "pct_tokens_saved" not in summ           # honesty guard: no fake %
    assert "no measured runs" in summ["status"]


def test_meter_labels_modeled_vs_measured(tmp_path):
    ensure_layout(tmp_path)
    log = MeterLog(tmp_path)
    log.record(StageTiming("specline", "new", 40, 0, 0, 0, True))
    log.record(StageTiming("hsf", "compile", 100, 0, 0, 0, True))
    summ = summarize(tmp_path, baseline_tokens_per_run=3500, runs_projected=1000)
    assert summ["stages_measured"] == 2
    assert summ["build_wall_ms"] == 140                  # wall time is real
    assert summ["tokens_reported_by_modules"] is False   # honest: no tokens seen
    table = summary_table(summ)
    assert "(model)" in table                            # savings labeled as modeled
    assert "Nothing here is fabricated" in table


def test_dry_run_assemble_plans_all_stages(tmp_path):
    ensure_layout(tmp_path)
    report = assemble(tmp_path, "feat", dry_run=True)
    stages = [s for s in report["stages"] if s["status"] in ("would-run", "skipped")]
    assert len(stages) == len(DEFAULT_CHAIN)


def test_missing_module_is_skipped_not_fatal(tmp_path, monkeypatch):
    ensure_layout(tmp_path)
    # force one module to look uninstalled
    import factoryline.assembly as asm
    real_detect = asm.detect
    def fake_detect():
        mods = real_detect()
        for m in mods:
            if m.name == "hsf":
                m.installed = False
        return mods
    monkeypatch.setattr(asm, "detect", fake_detect)
    report = assemble(tmp_path, "feat", dry_run=True)
    hsf_stages = [s for s in report["stages"] if s["module"] == "hsf"]
    assert all(s["status"] == "skipped" for s in hsf_stages)


def test_attribution_validation_and_deterministic_tie():
    empty = Attribution("smoke", 0, 0, [])
    assert empty.rate == 0.0
    units = [
        UnitResult("a", "smoke", False, "timeout after 1s", FailureClass.RUNTIME_TIMEOUT),
        UnitResult("b", "smoke", False, "exit 1", FailureClass.RUNTIME_CRASH),
    ]
    attr = Attribution("smoke", 2, 0, units)
    assert attr.rate == 0.0
    assert attr.dominant_failure_class() is FailureClass.RUNTIME_CRASH
    assert attr.dominant_failure_class() is FailureClass.RUNTIME_CRASH


def test_failed_unit_requires_class_and_evidence():
    import pytest
    with pytest.raises(ValueError):
        UnitResult("a", "smoke", False, "", None)


def test_receipt_without_attribution_is_backward_compatible(tmp_path):
    path = Receipt("hsf", "compile", "f", True).write(tmp_path)
    assert json.loads(path.read_text())["attribution"] is None


def test_rollup_recommends_earliest_failure_not_worst_rate():
    early = Attribution("strict", 10, 9, [
        *[UnitResult(f"r{i}", "strict", True, "typed") for i in range(9)],
        UnitResult("r9", "strict", False, "vague", FailureClass.AMBIGUOUS_REQUIREMENT),
    ]).to_dict()
    late = Attribution("smoke", 2, 0, [
        UnitResult("a", "smoke", False, "exit 1", FailureClass.RUNTIME_CRASH),
        UnitResult("b", "smoke", False, "exit 1", FailureClass.RUNTIME_CRASH),
    ]).to_dict()
    result = rollup_attributions([
        {"module": "specline", "stage": "strict", "attribution": early},
        {"module": "forgeline", "stage": "smoke", "attribution": late},
    ])
    assert result["earliest_failing_stage"] == "specline:strict"


def test_h0_boundary_rejects_learning_symbols(tmp_path):
    artifact = tmp_path / "artifact.py"
    artifact.write_text("def decide(x): return x\n")
    assert_no_attribution_in_artifact(artifact)
    artifact.write_text("attribution = {}\n")
    import pytest
    with pytest.raises(ValueError):
        assert_no_attribution_in_artifact(artifact)
