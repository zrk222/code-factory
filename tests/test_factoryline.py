"""Tests for the factoryline connector — Lego assembly + honest metering."""
import json
from pathlib import Path
from factoryline.contract import ensure_layout, LAYOUT, Receipt, Meter, MODULES, STAGES
from factoryline.assembly import detect, assemble, DEFAULT_CHAIN
from factoryline.meter import summarize, summary_table, MeterLog, StageTiming
from factoryline.attribution import Attribution, FailureClass, UnitResult
from factoryline.assembly import rollup_attributions, rollup_receipts, _attribution_from_output
from factoryline.boundary import assert_no_attribution_in_artifact, assert_build_metadata_locations
from factoryline.proof import (
    build_trace,
    export_attestations,
    public_evidence,
    public_evidence_text,
    replay_plan,
    risk_for_paths,
    verify_trace,
)


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
    payload = json.loads(path.read_text())
    assert payload["attribution"] is None
    assert Receipt.from_dict(payload).ok is True


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


def test_rollup_prioritizes_verify_tests_before_smoke_even_if_displayed_later():
    smoke = Attribution("smoke", 4, 2, [
        UnitResult("runtime", "smoke", False, "timeout after 300s", FailureClass.RUNTIME_TIMEOUT),
        UnitResult("output", "smoke", False, "wrong output", FailureClass.WRONG_OUTPUT),
        UnitResult("boot", "smoke", True, "started"),
        UnitResult("route", "smoke", True, "served"),
    ]).to_dict()
    verify_tests = Attribution("verify_tests", 3, 2, [
        UnitResult("real_behavior", "verify_tests", True, "failed on stub"),
        UnitResult("imports", "verify_tests", True, "exempt structural check"),
        UnitResult(
            "assert_true",
            "verify_tests",
            False,
            "check passed against generated empty SSAT scaffold",
            FailureClass.HOLLOW_TEST,
        ),
    ]).to_dict()
    result = rollup_attributions([
        {"module": "forgeline", "stage": "smoke", "attribution": smoke},
        {"module": "forgeline", "stage": "verify_tests", "attribution": verify_tests},
    ])
    assert result["earliest_failing_stage"] == "forgeline:verify_tests"
    assert result["recommended_edit_class"] == "structural"


def test_h0_boundary_rejects_learning_symbols(tmp_path):
    artifact = tmp_path / "artifact.py"
    artifact.write_text("def decide(x): return x\n")
    assert_no_attribution_in_artifact(artifact)
    artifact.write_text("attribution = {}\n")
    import pytest
    with pytest.raises(ValueError):
        assert_no_attribution_in_artifact(artifact)


def test_output_ingestion_and_receipt_rollup(tmp_path):
    attr = Attribution("strict", 1, 0, [
        UnitResult("R1", "strict", False, "vague", FailureClass.AMBIGUOUS_REQUIREMENT)
    ]).to_dict()
    assert _attribution_from_output("note\n" + json.dumps({"attribution": attr})) == attr
    Receipt("specline", "strict", "f", False, attribution=attr).write(tmp_path)
    result = rollup_receipts(tmp_path, "f")
    assert result["earliest_failing_stage"] == "specline:strict"


def test_factory_refine_plateau_and_rejection_rates(tmp_path):
    from factoryline.refinement import refine
    state = {"rates": {"specline:strict": 0.5}, "tree": b"before"}
    result = refine(
        lambda: dict(state["rates"]),
        lambda rates: ("specline:strict", FailureClass.AMBIGUOUS_REQUIREMENT),
        lambda edit: state["tree"],
        lambda snapshot: state.__setitem__("tree", snapshot),
        tmp_path,
    )
    assert result == {"converged": False, "reason": "plateau", "iters": 2}
    entries = [json.loads(line) for line in
               (tmp_path / ".factory" / "rejection_ledger.jsonl").read_text().splitlines()]
    assert entries[0]["before_rates"] == entries[0]["after_rates"]
    assert entries[0]["edit"]["edit_class"] == "structural"


def test_hollow_test_attribution_round_trips_and_selects_structural_edit():
    from factoryline.refinement import select_edit

    payload = Attribution("forgeline:verify_tests", 1, 0, [
        UnitResult(
            "verify_tests:assert_true",
            "forgeline:verify_tests",
            False,
            "passed against an empty stub",
            FailureClass.HOLLOW_TEST,
        )
    ]).to_dict()
    attr = Attribution.from_dict(payload)
    assert attr.dominant_failure_class() is FailureClass.HOLLOW_TEST
    assert select_edit("forgeline:verify_tests", FailureClass.HOLLOW_TEST).edit_class == "structural"


def test_hollow_validator_attribution_round_trips_and_selects_structural_edit():
    from factoryline.refinement import select_edit

    payload = Attribution("validator_mutation", 1, 0, [
        UnitResult(
            "R4",
            "validator_mutation",
            False,
            "deletion mutant survived strict",
            FailureClass.HOLLOW_VALIDATOR,
        )
    ]).to_dict()
    attr = Attribution.from_dict(payload)
    assert attr.dominant_failure_class() is FailureClass.HOLLOW_VALIDATOR
    assert select_edit("specline:verify-validators", FailureClass.HOLLOW_VALIDATOR).edit_class == "structural"


def test_rollup_prioritizes_verify_validators_before_spec_gate():
    hollow = Attribution("validator_mutation", 2, 1, [
        UnitResult("R1", "validator_mutation", True, "mutant killed"),
        UnitResult("R2", "validator_mutation", False, "mutant survived", FailureClass.HOLLOW_VALIDATOR),
    ]).to_dict()
    smoke = Attribution("smoke", 1, 0, [
        UnitResult("runtime", "smoke", False, "timeout", FailureClass.RUNTIME_TIMEOUT),
    ]).to_dict()
    result = rollup_attributions([
        {"module": "forgeline", "stage": "smoke", "attribution": smoke},
        {"module": "specline", "stage": "verify-validators", "attribution": hollow},
    ])
    assert result["earliest_failing_stage"] == "specline:verify-validators"
    assert result["recommended_edit_class"] == "structural"


def test_build_metadata_never_lives_in_registry(tmp_path):
    registry = tmp_path / "registry"
    registry.mkdir()
    (registry / "artifact.py").write_text("def decide(): return True")
    assert_build_metadata_locations(tmp_path)
    (registry / "rejection_ledger.json").write_text("{}")
    import pytest
    with pytest.raises(ValueError):
        assert_build_metadata_locations(tmp_path)


def test_meter_identical_with_attribution_receipts(tmp_path):
    from factoryline.meter import summarize, MeterLog, StageTiming
    MeterLog(tmp_path).record(StageTiming("hsf", "compile", 10, 0, 0, 0, True))
    before = summarize(tmp_path)
    Receipt("hsf", "compile", "f", True, attribution=Attribution(
        "compile", 1, 1, [UnitResult("compile", "compile", True, "green")]
    ).to_dict()).write(tmp_path)
    after = summarize(tmp_path)
    assert before["build_tokens"] == after["build_tokens"]
    assert before["build_model_calls"] == after["build_model_calls"]


def _write_proof_fixture(root: Path) -> dict:
    ensure_layout(root)
    artifact = root / "registry" / "f-output.py"
    artifact.write_text("def run():\n    return 'ok'\n")
    MeterLog(root).record(StageTiming("forgeline", "verify-tests", 12, 1, 100, 20, True))
    Receipt(
        "forgeline",
        "verify-tests",
        "f",
        True,
        attribution=Attribution(
            "verify_tests",
            1,
            1,
            [UnitResult("behavior", "verify_tests", True, "failed on generated stub")],
        ).to_dict(),
    ).write(root)
    Receipt(
        "hsf",
        "compile",
        "f",
        True,
        outputs={"paths": ["registry/f-output.py"]},
        attribution=Attribution(
            "compile",
            1,
            1,
            [UnitResult("compile", "compile", True, "artifact built")],
        ).to_dict(),
    ).write(root)
    return build_trace(root, "f")


def test_proof_trace_hash_chain_verifies_receipts_and_artifacts(tmp_path):
    trace = _write_proof_fixture(tmp_path)
    trace_path = tmp_path / ".factory" / "traces" / "f.trace.json"
    result = verify_trace(trace_path, root=tmp_path)
    assert result["valid"] is True
    assert result["trace_sha256"] == trace["trace_sha256"]
    assert result["nodes_verified"] == 2


def test_proof_trace_detects_receipt_tampering(tmp_path):
    trace = _write_proof_fixture(tmp_path)
    receipt_path = tmp_path / trace["nodes"][0]["receipt_path"]
    receipt_path.write_text(receipt_path.read_text() + "\n")
    result = verify_trace(tmp_path / ".factory" / "traces" / "f.trace.json", root=tmp_path)
    assert result["valid"] is False
    assert any("receipt hash mismatch" in error for error in result["errors"])


def test_proof_trace_detects_stage_order_tampering(tmp_path):
    _write_proof_fixture(tmp_path)
    trace_path = tmp_path / ".factory" / "traces" / "f.trace.json"
    payload = json.loads(trace_path.read_text())
    payload["nodes"][0]["order"] = 99
    trace_path.write_text(json.dumps(payload))
    result = verify_trace(trace_path, root=tmp_path)
    assert result["valid"] is False
    assert any("stage order mismatch" in error for error in result["errors"])


def test_replay_plan_starts_smoke_manifest_changes_at_verify_tests(tmp_path):
    trace = _write_proof_fixture(tmp_path)
    plan = replay_plan(trace, ["smoke/f.json"])
    commands = [item["command"] for item in plan["commands"]]
    assert commands[:2] == [
        "forge verify-tests f f.ssat.yaml",
        "forge smoke f",
    ]


def test_risk_diff_maps_ssat_changes_to_stub_identity_and_smoke():
    risk = risk_for_paths(["f.ssat.yaml"])
    stages = [f"{item['module']}:{item['stage']}" for item in risk["rerun_stages"]]
    assert "forgeline:verify-tests" in stages
    assert "forgeline:smoke" in stages


def test_risk_diff_maps_spec_changes_to_validator_mutation():
    risk = risk_for_paths(["specs/f.md"])
    stages = [f"{item['module']}:{item['stage']}" for item in risk["rerun_stages"]]
    assert stages[:2] == ["specline:strict", "specline:verify-validators"]


def test_public_evidence_is_human_readable_and_public_safe(tmp_path):
    trace = _write_proof_fixture(tmp_path)
    evidence = public_evidence(tmp_path, "f")
    rendered = public_evidence_text(evidence)
    assert evidence["verified"] is True
    assert trace["trace_sha256"] in rendered
    assert "PROOF-CARRYING PR EVIDENCE" in rendered
    assert "log_tail" not in rendered


def test_attestation_export_writes_in_toto_and_slsa_statements(tmp_path):
    trace = _write_proof_fixture(tmp_path)
    outputs = export_attestations(trace, out_dir=tmp_path / "attestations")
    in_toto = json.loads(Path(outputs["in_toto"]).read_text())
    slsa = json.loads(Path(outputs["slsa"]).read_text())
    assert in_toto["_type"] == "https://in-toto.io/Statement/v1"
    assert in_toto["predicate"]["trace_sha256"] == trace["trace_sha256"]
    assert slsa["predicateType"] == "https://slsa.dev/provenance/v1"


def test_cli_replay_execute_refuses_tampered_trace(tmp_path, capsys):
    from factoryline.cli import main

    _write_proof_fixture(tmp_path)
    trace_path = tmp_path / ".factory" / "traces" / "f.trace.json"
    payload = json.loads(trace_path.read_text())
    payload["chain_head"] = "bad"
    trace_path.write_text(json.dumps(payload))
    code = main(["replay", str(trace_path), "--root", str(tmp_path), "--changed", "smoke/f.json", "--execute"])
    assert code == 1
    assert "trace verification failed" in capsys.readouterr().out


def test_cli_doctor_is_windows_console_safe(capsys):
    from factoryline.cli import main

    assert main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "installed" in out or "missing" in out
