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
from factoryline.passport import build_passport, verify_passport
from factoryline.protocol import CHALLENGE_SCHEMA, MINIMUM_VERSIONS, RECEIPT_SCHEMA


def test_runtime_version_matches_the_release():
    import factoryline

    assert factoryline.__version__ == "0.10.1"


def test_layout_created(tmp_path):
    ensure_layout(tmp_path)
    for sub in LAYOUT.values():
        assert (tmp_path / sub).is_dir()


def test_detect_returns_all_four_modules():
    names = {m.name for m in detect()}
    assert names == {"specline", "forgeline", "hsf", "prestige"}


def test_factory_verify_refuses_to_call_missing_receipts_shippable(tmp_path):
    from factoryline.verification import verify_feature

    result = verify_feature(tmp_path, "f")
    assert result["shippable"] is False
    assert result["next_action"] == f"factory assemble f --root {tmp_path}"


def test_protocol_requires_design_md_compatible_prestige():
    assert MINIMUM_VERSIONS["prestige"] == "0.7.0"


def test_receipt_roundtrip(tmp_path):
    ensure_layout(tmp_path)
    r = Receipt(module="specline", stage="strict", feature="f", ok=True,
                meter=Meter(wall_ms=12))
    p = r.write(tmp_path)
    data = json.loads(p.read_text())
    assert data["module"] == "specline" and data["ok"] is True
    assert data["meter"]["wall_ms"] == 12
    assert data["schema"] == RECEIPT_SCHEMA
    assert data["tenant_id"] == "local"
    assert data["run_id"]


def test_trace_refuses_empty_receipt_set(tmp_path):
    ensure_layout(tmp_path)
    import pytest
    with pytest.raises(ValueError, match="no receipts"):
        build_trace(tmp_path, "empty")


def test_long_cli_output_keeps_structured_attribution():
    attr = Attribution("strict_lint", 1, 0, [
        UnitResult("R1", "strict_lint", False, "ambiguous", FailureClass.AMBIGUOUS_REQUIREMENT)
    ]).to_dict()
    output = json.dumps({"passed": False, "attribution": attr}) + ("x" * 5000)
    assert _attribution_from_output(output)["dominant_failure_class"] == "ambiguous_requirement"


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


def test_overhead_reports_measured_gate_times(tmp_path):
    from factoryline.meter import MeterLog, StageTiming, overhead

    log = MeterLog(tmp_path)
    log.record(StageTiming("forgeline", "verify-tests", 20, 0, 0, 0, True))
    log.record(StageTiming("forgeline", "verify-tests", 40, 0, 0, 0, False))
    payload = overhead(tmp_path)
    assert payload["gates"][0]["avg_wall_ms"] == 30.0
    assert payload["gates"][0]["failed_runs"] == 1


def test_override_is_append_only_owned_receipt(tmp_path):
    from factoryline.overrides import record_override

    payload = record_override(tmp_path, "forgeline:verify-tests", reason="Vendor test harness unavailable", approved_by="platform-team", expires="2026-12-01")
    assert Path(payload["path"]).exists()
    assert Path(payload["receipt_path"]).exists()
    assert payload["approved_by"] == "platform-team"
    assert payload["scope_limits"]


def test_ci_template_comments_without_masking_failed_verification():
    from factoryline.overrides import ci_template

    workflow = ci_template("checkout")
    assert "continue-on-error: true" in workflow
    assert "if: always()" in workflow
    assert "if: steps.verify.outcome == 'failure'" in workflow
    assert "|| true" not in workflow


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


def test_factory_passport_emits_verified_mermaid_and_detects_tampering(tmp_path):
    trace = _write_proof_fixture(tmp_path)
    challenge = tmp_path / "specline.challenge.json"
    challenge.write_text(json.dumps({
        "schema": CHALLENGE_SCHEMA,
        "brick": "specline",
        "feature": "f",
        "stage": "validator_mutation",
        "passed": True,
        "mutants_total": 3,
        "mutants_killed": 3,
    }))
    passport = build_passport(
        tmp_path,
        "f",
        tmp_path / trace["trace_path"],
        [challenge],
    )
    assert passport["verified"] is True
    assert Path(passport["paths"]["mermaid"]).read_text().startswith("flowchart LR")
    assert verify_passport(Path(passport["paths"]["json"]))["valid"] is True
    challenge.write_text(challenge.read_text() + "\n")
    assert verify_passport(Path(passport["paths"]["json"]))["valid"] is False


def test_factory_passport_accepts_distinct_challenge_stages_from_one_brick(tmp_path):
    trace = _write_proof_fixture(tmp_path)
    receipts = []
    for stage in ("design_counterfactual", "design_tokens"):
        receipt = tmp_path / f"prestige-{stage}.json"
        receipt.write_text(json.dumps({
            "schema": CHALLENGE_SCHEMA, "brick": "prestige", "feature": "f",
            "stage": stage, "passed": True, "mutants_total": 1, "mutants_killed": 1,
        }))
        receipts.append(receipt)
    passport = build_passport(tmp_path, "f", tmp_path / trace["trace_path"], receipts)
    assert passport["verified"] is True
    assert len(passport["challenges"]) == 2


def test_factoryline_challenge_kills_trace_integrity_mutants(tmp_path):
    from factoryline.challenge import challenge_trace
    trace = _write_proof_fixture(tmp_path)
    payload = challenge_trace(tmp_path / trace["trace_path"], root=tmp_path)
    assert payload["passed"] is True
    assert payload["mutants_total"] == payload["mutants_killed"] == 3


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
    assert any(word in out for word in ("compatible", "incompatible", "missing"))


def test_cli_no_args_returns_agent_home_with_definitive_empty_states(tmp_path, capsys, monkeypatch):
    from factoryline.cli import main

    monkeypatch.chdir(tmp_path)
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "description: Five-brick spec-to-proof software factory" in out
    assert "receipts: 0" in out
    assert "passports: 0" in out
    assert "factory doctor --strict --json" in out


def test_policy_writes_hollow_gate_defaults(tmp_path):
    from factoryline.optimizer import write_policy

    path = write_policy(tmp_path)
    payload = json.loads(path.read_text())
    assert payload["quality"]["require_hollow_tests"] is True
    assert payload["quality"]["require_hollow_validators"] is True
    assert payload["risk"]["default"] == "supervised"


def test_optimize_pr_adds_design_and_release_stages(tmp_path):
    from factoryline.optimizer import optimize_pr

    plan = optimize_pr(tmp_path, changed=["app/page.tsx", "pyproject.toml"], feature="f")
    assert "prestige:audit" in plan["recommended_stages"]
    assert "factoryline:release-readiness" in plan["recommended_stages"]
    assert plan["loop"]["max_iterations"] == 5
    assert "must not merge" in plan["loop"]["authority"]


def test_pr_pack_writes_reviewer_markdown(tmp_path):
    from factoryline.optimizer import pr_pack

    _write_proof_fixture(tmp_path)
    packet = pr_pack(tmp_path, "f")
    text = Path(packet["packet_path"]).read_text()
    assert packet["evidence"]["verified"] is True
    assert "PR Evidence: f" in text
    assert "Deterministic gates run before AI review loops." in text


def test_app_builder_scaffolds_full_stack_repo(tmp_path):
    from factoryline.app_builder import app_from_prompt

    result = app_from_prompt(
        "Build a clinical prior auth portal with patient status and audit logs.",
        out_dir=tmp_path / "prior-auth",
        purpose="auto",
    )
    files = set(result["files"])
    assert "app_blueprint.json" in files
    assert "frontend/app/page.tsx" in files
    assert "backend/main.py" in files
    assert "db/schema.sql" in files
    assert "smoke/clinical-prior-auth-portal-patient.json" in files
    assert "clinical-prior-auth-portal-patient.ssat.yaml" in files
    assert "coverage/requirements.json" in files
    assert ".forge/clinical-prior-auth-portal-patient/state.json" in files
    blueprint = json.loads((tmp_path / "prior-auth" / "app_blueprint.json").read_text())
    assert blueprint["app"]["purpose"] == "healthcare"
    assert "hollow_tests" in blueprint["app"]["required_gates"]
    smoke = json.loads((tmp_path / "prior-auth" / "smoke" / "clinical-prior-auth-portal-patient.json").read_text())
    assert smoke["checks"][0]["must_fail_on_stub"] is True
    assert smoke["checks"][0]["covers"] == ["RUNTIME_HEALTH"]
    state = json.loads((tmp_path / "prior-auth" / ".forge" / "clinical-prior-auth-portal-patient" / "state.json").read_text())
    assert state["state"] == "blocked"


def test_app_builder_requirement_coverage_blocks_uncovered_product_reqs(tmp_path):
    from factoryline.app_builder import app_from_prompt
    from factoryline.coverage import requirement_coverage

    app_from_prompt(
        "Build a clinical prior auth portal with patient status and audit logs.",
        out_dir=tmp_path / "prior-auth",
        purpose="auto",
    )
    result = requirement_coverage(tmp_path / "prior-auth")
    assert result["ok"] is False
    assert "RUNTIME_HEALTH" in result["covered"]
    assert "WORKFLOW_SUBMIT_REQUEST" in result["uncovered"]
    assert result["attribution"]["dominant_failure_class"] == "hollow_coverage"


def test_app_builder_stacks_generate_truthful_frontend_and_database(tmp_path):
    from factoryline.app_builder import app_from_prompt

    react_pg = tmp_path / "react-pg"
    app_from_prompt("Build an expense app.", out_dir=react_pg, stack="react-fastapi-postgres")
    assert (react_pg / "frontend" / "src" / "App.tsx").exists()
    assert "bigserial" in (react_pg / "db" / "schema.sql").read_text()

    react_sqlite = tmp_path / "react-sqlite"
    app_from_prompt("Build an expense app.", out_dir=react_sqlite, stack="react-fastapi-sqlite")
    assert (react_sqlite / "frontend" / "src" / "App.tsx").exists()
    schema = (react_sqlite / "db" / "schema.sql").read_text()
    assert "autoincrement" in schema and "jsonb" not in schema


def test_cli_app_from_prompt_outputs_json(tmp_path, capsys):
    from factoryline.cli import main

    code = main([
        "app",
        "from-prompt",
        "Build a developer API dashboard with GitHub receipts.",
        "--out",
        str(tmp_path / "api-dash"),
        "--json",
    ])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["app"] == "developer-api-dashboard-github-receipts"
    assert (tmp_path / "api-dash" / "docs" / "WORKFLOW.md").exists()
    assert (tmp_path / "api-dash" / "developer-api-dashboard-github-receipts.ssat.yaml").exists()


def test_cli_coverage_outputs_json_and_fails_closed(tmp_path, capsys):
    from factoryline.app_builder import app_from_prompt
    from factoryline.cli import main

    app_from_prompt("Build an expense app with approval rules.", out_dir=tmp_path / "expense")
    code = main(["coverage", "--root", str(tmp_path / "expense"), "--json"])
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["attribution"]["dominant_failure_class"] == "hollow_coverage"
