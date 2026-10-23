import json
import hashlib
from pathlib import Path
import pytest
from factoryline.assembly import ModuleStatus
from factoryline.continuation import (
    ContinuationError,
    continue_assembly,
    resolve_feature,
    resolve_ssat,
)
from factoryline.run_metrics import public_metrics
import sys
from factoryline.fix_workflow import (
    FixWorkflowError,
    run_fix_workflow,
    run_repair_branch_comparison,
)
from factoryline.live_feedback import LiveFeedbackError, run_live_feedback
from factoryline.senior_assurance import _source_digest


def _release_contract_fixture(root, feature, required_stages, *, path=None):
    from factoryline.oracle_firewall import capture_intent_handoff, seal_oracle_contract
    from factoryline.release_contract import _sha

    agent = {
        "schema": "factory.agent-identity.v1",
        "subject": "release-owner",
        "provider": "local",
        "model": "test-reviewer",
    }
    brief = root / "brief.md"
    brief.write_text("Keep each required release gate traceable.", encoding="utf-8")
    handoff = capture_intent_handoff(
        root,
        brief,
        agent,
        "release",
        Path(f".factory/oracles/handoffs/{feature}.json"),
    )

    def rule(identifier, statement, **extra):
        return {
            "id": identifier,
            "statement": statement,
            "origin": "human_confirmed",
            "effect": "blocking",
            "source_id": "original-intent",
            "critical": True,
            **extra,
        }

    oracle_input = {
        "schema": "factory.oracle-contract-input.v1",
        "id": f"release-{feature}",
        "version": 1,
        "approved_by": "Release Owner",
        "approval_rationale": "A human reviewed the release boundary.",
        "scope_paths": ["."],
        "handoff": handoff["path"],
        "sources": [],
        "requirements": [rule("intent", "Preserve the approved intent.")],
        "forbidden_behaviors": [rule("weaken", "Do not weaken a required gate.")],
        "gates": [
            rule(
                "proof",
                "A proof receipt is required.",
                comparison="present",
                value=True,
            )
        ],
        "exceptions": [
            {
                "id": "note",
                "statement": "A future policy note remains advisory.",
                "origin": "human_confirmed",
                "effect": "advisory",
                "source_id": "original-intent",
                "critical": False,
            }
        ],
        "negative_cases": [rule("negative", "A missing receipt cannot pass.")],
        "invariants": [rule("bound", "Evidence stays bound to this feature.")],
        "tests": [
            rule(
                "test",
                "The required proof test must run.",
                path="tests/test_release.py",
            )
        ],
    }
    source = root / "oracle-input.json"
    source.write_text(json.dumps(oracle_input), encoding="utf-8")
    oracle_path = Path(
        seal_oracle_contract(
            root, source, Path(f".factory/oracles/contracts/{feature}.json")
        )["path"]
    )
    oracle = json.loads((root / oracle_path).read_text(encoding="utf-8"))
    core = {
        "schema": "factory.release-contract.v1",
        "feature": feature,
        "oracle_contract": oracle_path.as_posix(),
        "oracle_contract_sha256": oracle["contract_sha256"],
        "required_stages": required_stages,
        "approved_by": "Release Owner",
    }
    contract = {**core, "policy_digest": _sha(core)}
    destination = path or root / "custom" / f"{feature}.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(contract), encoding="utf-8")
    return destination, contract


def _pause_custom_contract(tmp_path, monkeypatch):
    from factoryline.assembly import assemble

    feature = "feature"
    contract_path, _ = _release_contract_fixture(tmp_path, feature, ["specline:strict"])
    modules = [
        ModuleStatus(name, name, True, "test")
        for name in ("specline", "forgeline", "hsf", "prestige")
    ]
    monkeypatch.setattr("factoryline.assembly.detect", lambda: modules)
    calls = []

    def run_cli(*args, **kwargs):
        calls.append(args)
        return True, ""

    monkeypatch.setattr("factoryline.assembly.run_cli", run_cli)
    (tmp_path / "specs").mkdir(exist_ok=True)
    report = assemble(
        tmp_path, feature, release_contract_path=Path("custom/feature.json")
    )
    assert report["paused_at"] == "author_spec"
    return contract_path, calls


def test_feature_inference_requires_exactly_one_candidate(tmp_path):
    with pytest.raises(ContinuationError) as error:
        resolve_feature(tmp_path, None)
    assert error.value.code == "FEATURE_SELECTION_REQUIRED"
    (tmp_path / "specs").mkdir(exist_ok=True)
    (tmp_path / "specs" / "only.md").write_text("# only", encoding="utf-8")
    assert resolve_feature(tmp_path, None) == ("only", True)
    (tmp_path / "specs" / "other.md").write_text("# other", encoding="utf-8")
    with pytest.raises(ContinuationError) as error:
        resolve_feature(tmp_path, None)
    assert error.value.candidates == ["only", "other"]


def test_ssat_resolution_prefers_specs_and_never_fuzzy_matches(tmp_path):
    (tmp_path / "specs").mkdir()
    expected = tmp_path / "specs" / "feature.ssat.yaml"
    expected.write_text("schema: x", encoding="utf-8")
    (tmp_path / "feature-old.ssat.yaml").write_text("schema: wrong", encoding="utf-8")
    assert resolve_ssat(tmp_path, "feature") == expected
    assert resolve_ssat(tmp_path, "missing") is None


def test_continue_writes_unknown_usage_receipt_and_safe_aggregate(
    tmp_path, monkeypatch
):
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "feature.md").write_text("# feature", encoding="utf-8")
    monkeypatch.setattr(
        "factoryline.continuation.assemble",
        lambda root, feature, dry_run=False: {
            "feature": feature,
            "root": str(root),
            "run_id": "run-1",
            "stages": [{"module": "specline", "stage": "strict", "status": "ok"}],
            "paused_at": "architecture_approval",
            "rollup": {},
            "dry_run": dry_run,
        },
    )
    result = continue_assembly(tmp_path, "feature")
    assert result["status"] == "waiting_for_human"
    assert result["next_action"]["command"] == "forge gate architected feature"
    receipt = json.loads(
        (tmp_path / ".factory" / "runs" / "run-1.json").read_text(encoding="utf-8")
    )
    assert receipt["usage"]["quality"] == "unknown"
    assert receipt["usage"]["tokens_in"] is None
    aggregate = public_metrics(tmp_path)
    assert aggregate["marker"] == "PUBLIC_METRICS_AGGREGATE_SAFE"
    assert aggregate["usage"]["quality"] == "unknown"
    assert aggregate["savings"]["tokens_saved"] is None
    encoded = json.dumps(aggregate)
    assert "feature" not in encoded
    assert str(tmp_path) not in encoded


def test_dry_run_does_not_write_receipt(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "factoryline.continuation.assemble",
        lambda root, feature, dry_run=False: {
            "feature": feature,
            "root": str(root),
            "run_id": "dry",
            "stages": [],
            "rollup": {},
            "dry_run": dry_run,
        },
    )
    result = continue_assembly(tmp_path, "feature", dry_run=True)
    assert result["status"] == "completed"
    assert not (tmp_path / ".factory" / "runs").exists()


def test_custom_release_contract_survives_pause_and_resume(
    tmp_path, monkeypatch, capsys
):
    from factoryline.cli import main

    feature = "feature"
    outside = tmp_path.parent / f"{tmp_path.name}-external"
    outside.mkdir()
    contract_path, contract = _release_contract_fixture(
        tmp_path,
        feature,
        ["specline:strict"],
        path=outside / "feature.json",
    )
    modules = [
        ModuleStatus(name, name, True, "test")
        for name in ("specline", "forgeline", "hsf", "prestige")
    ]
    monkeypatch.setattr("factoryline.assembly.detect", lambda: modules)
    monkeypatch.setattr(
        "factoryline.assembly.run_cli_detailed",
        lambda *args, **kwargs: {
            "ok": True,
            "stdout": b"",
            "stderr": b"",
            "exit_code": 0,
            "cleanup_confirmed": True,
            "streams_closed": True,
            "output": "",
        },
    )
    monkeypatch.setattr(
        "factoryline.assembly.run_cli", lambda *args, **kwargs: (True, "")
    )

    assert (
        main(
            [
                "assemble",
                feature,
                "--root",
                str(tmp_path),
                "--release-contract",
                str(contract_path),
            ]
        )
        == 0
    )
    assemble_report = json.loads(capsys.readouterr().out)
    assert assemble_report["paused_at"] == "author_spec"
    assert assemble_report["release_contract_path"] == str(contract_path)

    (tmp_path / "specs").mkdir(exist_ok=True)
    (tmp_path / "specs" / f"{feature}.md").write_text("# Feature", encoding="utf-8")
    monkeypatch.setattr(
        "factoryline.assembly.detect",
        lambda: [
            ModuleStatus(item.name, item.cli, item.name != "specline", item.role)
            for item in modules
        ],
    )
    assert main(["continue", feature, "--root", str(tmp_path), "--json"]) == 1
    continuation_report = json.loads(capsys.readouterr().out)
    assert continuation_report["halted_at"] == "specline:strict"
    checkpoints = list(
        (tmp_path / "receipts").glob(
            "factoryline-feature-continuation-release-checkpoint-*.json"
        )
    )
    assert len(checkpoints) == 2
    checkpoint = max(
        (json.loads(path.read_text(encoding="utf-8")) for path in checkpoints),
        key=lambda item: item["inputs"]["checkpoint"]["revision"],
    )
    assert checkpoint["inputs"]["checkpoint"]["state"] == "waiting_for_human"
    assert (
        checkpoint["inputs"]["checkpoint"]["policy_sha256"]
        == hashlib.sha256(contract_path.read_bytes()).hexdigest()
    )
    assert checkpoint["inputs"]["checkpoint"]["policy_path"] == {
        "kind": "absolute",
        "value": str(contract_path),
    }
    initial_receipt = next((tmp_path / "receipts").glob("specline-feature-new-*.json"))
    stage_receipt = json.loads(initial_receipt.read_text(encoding="utf-8"))
    assert (
        stage_receipt["inputs"]["release_contract_policy_digest"]
        == contract["policy_digest"]
    )
    assert str(contract_path) not in json.dumps(public_metrics(tmp_path))
    contract_path.unlink()
    outside.rmdir()


def test_resolve_continuation_release_contract_binds_policy_and_rejects_invalid(
    tmp_path,
):
    from factoryline.assembly import resolve_continuation_release_contract

    contract_path, contract = _release_contract_fixture(
        tmp_path, "feature", ["specline:strict"]
    )
    resolved_path, snapshot, digest = resolve_continuation_release_contract(
        tmp_path, "feature", Path("custom/feature.json")
    )
    assert resolved_path == contract_path
    assert snapshot["policy_digest"] == contract["policy_digest"]
    assert digest == hashlib.sha256(contract_path.read_bytes()).hexdigest()

    malformed_path = tmp_path / "custom" / "malformed.json"
    malformed_path.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError):
        resolve_continuation_release_contract(tmp_path, "other", malformed_path)


def test_assemble_cli_returns_report_and_structured_policy_error(tmp_path, monkeypatch):
    from factoryline.assembly import assemble_cli

    contract_path, _ = _release_contract_fixture(
        tmp_path, "feature", ["specline:strict"]
    )
    modules = [
        ModuleStatus(name, name, True, "test")
        for name in ("specline", "forgeline", "hsf", "prestige")
    ]
    monkeypatch.setattr("factoryline.assembly.detect", lambda: modules)
    report = assemble_cli(
        str(tmp_path),
        "feature",
        dry_run=True,
        release_contract_path=str(contract_path),
    )
    assert report["dry_run"] is True
    assert report["release_contract_path"] == str(contract_path)

    malformed = assemble_cli(
        tmp_path,
        "feature",
        dry_run=True,
        release_contract_path=tmp_path / "missing.json",
    )
    assert malformed["schema"] == "factory.release-contract.error.v1"
    assert malformed["code"] == "RELEASE_CONTRACT_INPUT_INVALID"


def test_continue_cli_normalizes_inputs_and_propagates_invalid_policy(
    tmp_path, monkeypatch
):
    from factoryline.continuation import continue_cli

    contract_path = tmp_path / "custom" / "policy.json"
    usage = {"tokens_in": 7}
    expected = {"status": "waiting_for_human"}
    observed = {}

    def capture(root, feature, **kwargs):
        observed.update(root=root, feature=feature, **kwargs)
        return expected

    monkeypatch.setattr("factoryline.continuation.continue_assembly", capture)
    result = continue_cli(str(tmp_path), "feature", True, usage, str(contract_path))
    assert result is expected
    assert observed == {
        "root": tmp_path,
        "feature": "feature",
        "dry_run": True,
        "usage": usage,
        "release_contract_path": contract_path,
    }

    monkeypatch.undo()
    malformed_path = tmp_path / "malformed.json"
    malformed_path.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError):
        continue_cli(tmp_path, "feature", True, None, malformed_path)


@pytest.mark.parametrize("change", ["missing", "stale"])
def test_resume_rejects_missing_or_changed_release_contract_before_stages(
    tmp_path, monkeypatch, change
):
    contract_path, calls = _pause_custom_contract(tmp_path, monkeypatch)
    if change == "missing":
        contract_path.unlink()
    else:
        contract_path.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="resume release contract"):
        continue_assembly(tmp_path, "feature")
    assert len(calls) == 1


def test_continue_rejects_rebound_contract_path_before_stages(
    tmp_path, monkeypatch, capsys
):
    from factoryline.cli import main

    contract_path, calls = _pause_custom_contract(tmp_path, monkeypatch)
    rebound_path = contract_path.with_name("rebound.json")
    rebound_path.write_bytes(contract_path.read_bytes())
    assert (
        main(
            [
                "continue",
                "feature",
                "--root",
                str(tmp_path),
                "--release-contract",
                str(contract_path),
                "--dry-run",
                "--json",
            ]
        )
        == 0
    )
    dry_run_report = json.loads(capsys.readouterr().out)
    assert dry_run_report["dry_run"] is True
    assert (
        main(
            [
                "continue",
                "feature",
                "--root",
                str(tmp_path),
                "--release-contract",
                str(rebound_path),
                "--json",
            ]
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().err)
    assert payload["code"] == "CONTINUATION_INPUT_INVALID"
    assert "differs from the paused run" in payload["message"]
    assert str(tmp_path) not in payload["message"]
    assert len(calls) == 1


def test_assemble_rejects_missing_custom_contract_before_stages(
    tmp_path, monkeypatch, capsys
):
    from factoryline.cli import main

    calls = []
    monkeypatch.setattr(
        "factoryline.assembly.detect",
        lambda: [ModuleStatus("specline", "specline", True, "test")],
    )
    monkeypatch.setattr(
        "factoryline.assembly.run_cli",
        lambda *args, **kwargs: calls.append(args) or (True, ""),
    )
    missing = tmp_path / "custom" / "missing.json"
    assert (
        main(
            [
                "assemble",
                "feature",
                "--root",
                str(tmp_path),
                "--release-contract",
                str(missing),
            ]
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().err)
    assert payload["code"] == "RELEASE_CONTRACT_INPUT_INVALID"
    assert str(tmp_path) not in payload["message"]
    assert calls == []


def test_checkpoint_inventory_ambiguity_blocks_before_stages(tmp_path, monkeypatch):
    contract_path, calls = _pause_custom_contract(tmp_path, monkeypatch)
    original = next(
        (tmp_path / "receipts").glob(
            "factoryline-feature-continuation-release-checkpoint-*.json"
        )
    )
    duplicate = original.with_name(original.stem + "-duplicate.json")
    duplicate.write_bytes(original.read_bytes())
    with pytest.raises(ValueError, match="ambiguous"):
        continue_assembly(tmp_path, "feature")
    assert len(calls) == 1


def test_changed_policy_before_lock_acquisition_is_revalidated(tmp_path, monkeypatch):
    import factoryline.assembly as assembly

    contract_path, calls = _pause_custom_contract(tmp_path, monkeypatch)
    real_open = assembly.os.open
    changed = False

    def change_policy_before_lock(path, flags, mode=0o600, *, dir_fd=None):
        nonlocal changed
        if not changed and Path(path).name.startswith("assembly-"):
            assert mode == 0o600
            contract_path.write_text("{}", encoding="utf-8")
            changed = True
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(assembly.os, "open", change_policy_before_lock)
    with pytest.raises(ValueError, match="resume release contract"):
        continue_assembly(tmp_path, "feature")
    assert changed
    assert len(calls) == 1


def test_huge_checkpoint_revision_fails_without_unbounded_allocation(
    tmp_path, monkeypatch
):
    contract_path, calls = _pause_custom_contract(tmp_path, monkeypatch)
    checkpoint_path = next(
        (tmp_path / "receipts").glob(
            "factoryline-feature-continuation-release-checkpoint-*.json"
        )
    )
    receipt = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    receipt["inputs"]["checkpoint"]["revision"] = 10**12
    checkpoint_path.write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(ValueError, match="history is incomplete"):
        continue_assembly(tmp_path, "feature")
    assert len(calls) == 1


def test_release_contract_dry_run_preserves_workspace_state(tmp_path, monkeypatch):
    from factoryline.assembly import assemble

    feature = "feature"
    contract_path, _ = _release_contract_fixture(tmp_path, feature, ["specline:strict"])
    before = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    monkeypatch.setattr(
        "factoryline.assembly.detect",
        lambda: [
            ModuleStatus(name, name, True, "test")
            for name in ("specline", "forgeline", "hsf", "prestige")
        ],
    )
    report = assemble(
        tmp_path, feature, dry_run=True, release_contract_path=contract_path
    )
    after = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    assert report["dry_run"] is True
    assert after == before


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _live(tmp_path, *, command=None):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("value = 1\n", encoding="utf-8")
    return {
        "schema": "factory.live-feedback.v1",
        "live_id": "live-test",
        "contract_sha256": _digest("contract"),
        "changed_paths": ["src/app.py"],
        "checks": [
            {
                "id": "app-check",
                "paths": ["src/app.py"],
                "argv": command or [sys.executable, "check.py"],
                "expected_exit": 0,
                "timeout_seconds": 10,
                "max_output_bytes": 4096,
                "env": {"PYTHONIOENCODING": "utf-8"},
            },
            {
                "id": "unrelated-check",
                "paths": ["docs/guide.md"],
                "argv": [sys.executable, "check.py"],
                "expected_exit": 0,
                "timeout_seconds": 10,
                "max_output_bytes": 4096,
                "env": {},
            },
        ],
    }


def test_live_feedback_plans_only_affected_checks(tmp_path):
    (tmp_path / "check.py").write_text("print('ok')\n", encoding="utf-8")
    result = run_live_feedback(tmp_path, _live(tmp_path))
    assert result["mode"] == "plan"
    assert result["counts"] == {
        "PASS": 0,
        "FAIL": 0,
        "READY": 1,
        "SKIPPED": 1,
        "BLOCKED": 0,
    }
    assert result["checks"][0]["next_action"].startswith("Run the same manifest")


def test_live_feedback_executes_affected_check_in_replay_workspace(tmp_path):
    (tmp_path / "check.py").write_text("print('ok')\n", encoding="utf-8")
    result = run_live_feedback(tmp_path, _live(tmp_path), execute=True)
    assert result["counts"]["PASS"] == 1
    assert result["counts"]["SKIPPED"] == 1
    assert result["checks"][0]["receipt_sha256"]
    assert result["authority"] == "none"


def test_live_feedback_rejects_network_or_publication_commands(tmp_path):
    (tmp_path / "check.py").write_text("print('ok')\n", encoding="utf-8")
    with pytest.raises(LiveFeedbackError) as error:
        run_live_feedback(
            tmp_path, _live(tmp_path, command=["curl", "https://example.test"])
        )
    assert error.value.code == "E_LIVE_SIDE_EFFECT"


def _replay(root, name, exit_code, contract):
    source = root / name
    source.mkdir()
    (source / "run.py").write_text(
        f"import sys; sys.exit({exit_code})\n", encoding="utf-8"
    )
    source_sha, _ = _source_digest(source)
    return {
        "schema": "factory.replay-manifest.v1",
        "replay_id": name,
        "source_root": name,
        "source_sha256": source_sha,
        "dependencies_sha256": contract,
        "policy_sha256": contract,
        "input_files": [],
        "argv": [sys.executable, "run.py"],
        "expected_exit": exit_code,
        "timeout_seconds": 10,
        "max_output_bytes": 4096,
        "contract_sha256": contract,
    }


def test_fix_workflow_provides_one_repair_handoff(tmp_path):
    contract = _digest("contract")
    manifest = {
        "schema": "factory.repair-comparison.v1",
        "comparison_id": "fix-1",
        "contract_sha256": contract,
        "buggy": _replay(tmp_path, "buggy", 1, contract),
        "fixed": _replay(tmp_path, "fixed", 0, contract),
        "negative_controls": [_replay(tmp_path, "control", 1, contract)],
    }
    result = run_fix_workflow(tmp_path, manifest)
    assert result["schema"] == "factory.fix-workflow.v1"
    assert result["state"] == "PLAN_ONLY"
    assert result["reproduction"]["required"] is True
    assert "--execute" in result["next_action"]
    assert result["release_approval"] is False
    intervention = result["behavioral_intervention"]
    assert intervention["status"] == "NOT_EXECUTED"
    assert intervention["original"]["observed"] is False
    assert intervention["negative_control_counts"] == {
        "required": 1,
        "receipts_present": 0,
        "executed": 0,
        "observed": 0,
        "expected_failures_preserved": 0,
        "unexpected_outcomes": 0,
        "incomplete": 0,
        "unsupported": 0,
    }
    assert any(
        "Not detection-accuracy" in claim for claim in intervention["claim_boundary"]
    )


def test_fix_workflow_summarizes_hash_bound_executed_intervention(tmp_path):
    contract = _digest("contract")
    manifest = {
        "schema": "factory.repair-comparison.v1",
        "comparison_id": "fix-executed",
        "contract_sha256": contract,
        "buggy": _replay(tmp_path, "buggy", 1, contract),
        "fixed": _replay(tmp_path, "fixed", 0, contract),
        "negative_controls": [_replay(tmp_path, "control", 1, contract)],
    }

    result = run_fix_workflow(tmp_path, manifest, execute=True)

    intervention = result["behavioral_intervention"]
    assert intervention["schema"] == "factory.behavioral-intervention-summary.v1"
    assert intervention["status"] == "OBSERVED"
    assert intervention["input_manifest_sha256"] == _digest(manifest)
    assert len(intervention["comparison_receipt_sha256"]) == 64
    assert intervention["what_broke"] == "REPRODUCED_EXPECTED_FAILURE"
    assert intervention["what_restored"] == "RESTORED_EXPECTED_SUCCESS"
    assert intervention["original"]["expected_outcome_observed"] is True
    assert intervention["original"]["observed_exit"] == 1
    assert intervention["repaired"]["expected_outcome_observed"] is True
    assert intervention["repaired"]["observed_exit"] == 0
    assert intervention["negative_control_counts"] == {
        "required": 1,
        "receipts_present": 1,
        "executed": 1,
        "observed": 1,
        "expected_failures_preserved": 1,
        "unexpected_outcomes": 0,
        "incomplete": 0,
        "unsupported": 0,
    }
    assert intervention["negative_controls"][0]["receipt_sha256"]
    assert intervention["negative_controls"][0]["observed_exit"] == 1
    assert result["authority"] == "none"
    assert result["release_approval"] is False


def _branch_manifest(tmp_path, *, branch_count=2, shared_contract=True):
    contract = _digest("same-contract")
    manifest = {
        "schema": "factory.repair-branch-comparison.v1",
        "comparison_id": "branch-batch",
        "contract_sha256": contract,
        "original": _replay(tmp_path, "branch-original", 1, contract),
        "negative_controls": [_replay(tmp_path, "branch-control", 1, contract)],
        "branches": [],
    }
    for index in range(branch_count):
        candidate_contract = (
            contract if shared_contract or index == 0 else _digest("other-contract")
        )
        manifest["branches"].append(
            {
                "branch_id": f"branch-{index + 1}",
                "candidate": _replay(
                    tmp_path,
                    f"branch-candidate-{index + 1}",
                    0,
                    candidate_contract,
                ),
            }
        )
    return manifest


def test_repair_branch_comparison_plan_is_explicit_and_keeps_common_bindings(tmp_path):
    result = run_fix_workflow(tmp_path, _branch_manifest(tmp_path))
    assert result["schema"] == "factory.repair-branch-comparison-receipt.v1"
    assert result["state"] == "PLAN_ONLY"
    assert result["branch_count"] == 2
    assert result["candidate_selection"] is None
    assert result["promotion"] == "NONE"
    assert len({row["shared_binding_sha256"] for row in result["branches"]}) == 1
    assert all(row["status"] == "PLAN_ONLY" for row in result["branches"])
    assert all(row["raw_comparison"]["executed"] is False for row in result["branches"])
    assert result["release_approval"] is False


def test_public_repair_branch_api_plans_common_baseline_without_execution(tmp_path):
    manifest = _branch_manifest(tmp_path)

    result = run_repair_branch_comparison(tmp_path, manifest)

    assert result["state"] == "PLAN_ONLY"
    assert result["contract_sha256"] == manifest["contract_sha256"]
    assert result["candidate_selection"] is None
    assert result["promotion"] == "NONE"
    assert result["release_approval"] is False
    assert all(branch["status"] == "PLAN_ONLY" for branch in result["branches"])
    assert all(
        branch["raw_comparison"]["executed"] is False for branch in result["branches"]
    )
    assert all(
        branch["raw_comparison"]["state"] == "PLAN_ONLY"
        for branch in result["branches"]
    )


def test_repair_branch_comparison_preserves_raw_isolated_outcomes(tmp_path):
    result = run_fix_workflow(tmp_path, _branch_manifest(tmp_path), execute=True)
    assert result["state"] == "COMPARED"
    assert result["candidate_selection"] is None
    assert len(result["branches"]) == 2
    for row in result["branches"]:
        raw = row["raw_comparison"]
        assert row["status"] == "OBSERVED"
        assert raw["executed"] is True
        assert raw["original"]["observed_exit"] == 1
        assert raw["repaired"]["observed_exit"] == 0
        assert raw["negative_controls"][0]["observed_exit"] == 1
        assert raw["original"]["isolation"] == "fresh_temporary_workspace_and_process"
        assert raw["repaired"]["isolation"] == "fresh_temporary_workspace_and_process"
    assert result["authority"] == "none"
    assert result["promotion"] == result["application"] == "NONE"


def test_repair_branch_contract_mismatch_preflights_before_any_execution(
    monkeypatch, tmp_path
):
    from factoryline import fix_workflow

    calls = []
    original = fix_workflow.compare_repair

    def observe(*args, **kwargs):
        calls.append(kwargs.get("execute", False))
        return original(*args, **kwargs)

    monkeypatch.setattr(fix_workflow, "compare_repair", observe)
    with pytest.raises(FixWorkflowError, match="E_REPAIR_CONTRACT"):
        run_fix_workflow(
            tmp_path,
            _branch_manifest(tmp_path, shared_contract=False),
            execute=True,
        )
    assert calls
    assert True not in calls


def test_repair_branch_execution_failure_is_incomplete_not_plan_only(
    monkeypatch, tmp_path
):
    from factoryline import fix_workflow
    from factoryline.senior_assurance import SeniorAssuranceError

    def compare(_root, manifest, *, execute=False):
        if execute:
            raise SeniorAssuranceError(
                "E_REPLAY_INTERRUPTED", "replay did not complete"
            )
        return {
            "comparison_id": manifest["comparison_id"],
            "contract_sha256": manifest["contract_sha256"],
            "state": "PLAN_ONLY",
            "executed": False,
        }

    monkeypatch.setattr(fix_workflow, "compare_repair", compare)
    result = run_fix_workflow(tmp_path, _branch_manifest(tmp_path), execute=True)
    assert result["state"] == "INCOMPLETE"
    assert all(row["status"] == "INCOMPLETE" for row in result["branches"])
    assert all(
        row["raw_comparison"]["state"] == "INCOMPLETE" for row in result["branches"]
    )
    assert all(row["raw_comparison"]["executed"] is False for row in result["branches"])


def test_repair_branch_runner_failure_cannot_be_hidden_by_comparison_state(
    monkeypatch, tmp_path
):
    from factoryline import fix_workflow

    def compare(_root, _manifest, *, execute=False):
        return {
            "state": "FAIL" if execute else "PLAN_ONLY",
            "executed": execute,
        }

    monkeypatch.setattr(fix_workflow, "compare_repair", compare)
    monkeypatch.setattr(
        fix_workflow,
        "_behavioral_intervention",
        lambda *_args, **_kwargs: {"status": "INCOMPLETE"},
    )
    result = run_fix_workflow(tmp_path, _branch_manifest(tmp_path), execute=True)

    assert result["state"] == "INCOMPLETE"
    assert result["branches"][0]["comparison_state"] == "FAIL"
    assert result["branches"][0]["status"] == "INCOMPLETE"


def test_repair_branch_comparison_rejects_more_than_eight_candidates(
    monkeypatch, tmp_path
):
    from factoryline import fix_workflow

    monkeypatch.setattr(
        fix_workflow,
        "compare_repair",
        lambda *_args, **_kwargs: pytest.fail("must reject before comparison"),
    )
    manifest = {
        "schema": "factory.repair-branch-comparison.v1",
        "comparison_id": "too-many",
        "contract_sha256": _digest("contract"),
        "original": {},
        "negative_controls": [],
        "branches": [{"branch_id": f"b{i}", "candidate": {}} for i in range(9)],
    }
    with pytest.raises(FixWorkflowError, match="E_BRANCH_LIMIT"):
        run_fix_workflow(tmp_path, manifest, execute=True)


def test_repair_branch_existing_cli_defaults_to_plan_only(tmp_path, capsys):
    from factoryline.cli import main

    manifest = _branch_manifest(tmp_path)
    manifest_path = tmp_path / "repair-branches.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    exit_code = main(
        ["senior", "fix", str(manifest_path), "--root", str(tmp_path), "--json"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["state"] == "PLAN_ONLY"
    assert payload["mode"] == "plan"
    assert all(
        row["raw_comparison"]["executed"] is False for row in payload["branches"]
    )
    assert payload["candidate_selection"] is None


def test_repair_branch_existing_cli_executes_only_with_explicit_flag(tmp_path, capsys):
    from factoryline.cli import main

    manifest = _branch_manifest(tmp_path)
    manifest_path = tmp_path / "repair-branches.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    exit_code = main(
        [
            "senior",
            "fix",
            str(manifest_path),
            "--root",
            str(tmp_path),
            "--execute",
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["state"] == "COMPARED"
    assert payload["mode"] == "execute"
    assert all(row["raw_comparison"]["executed"] is True for row in payload["branches"])
    assert payload["candidate_selection"] is None
    assert payload["promotion"] == payload["application"] == "NONE"


def test_repair_branch_existing_cli_returns_nonzero_for_incomplete_execution(
    monkeypatch, tmp_path, capsys
):
    from factoryline import fix_workflow
    from factoryline.cli import main
    from factoryline.senior_assurance import SeniorAssuranceError

    def compare(_root, manifest, *, execute=False):
        if execute:
            raise SeniorAssuranceError(
                "E_REPLAY_INTERRUPTED", "replay did not complete"
            )
        return {
            "comparison_id": manifest["comparison_id"],
            "contract_sha256": manifest["contract_sha256"],
            "state": "PLAN_ONLY",
            "executed": False,
        }

    monkeypatch.setattr(fix_workflow, "compare_repair", compare)
    manifest_path = tmp_path / "repair-branches.json"
    manifest_path.write_text(json.dumps(_branch_manifest(tmp_path)), encoding="utf-8")

    exit_code = main(
        [
            "senior",
            "fix",
            str(manifest_path),
            "--root",
            str(tmp_path),
            "--execute",
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert payload["state"] == "INCOMPLETE"
    assert all(row["status"] == "INCOMPLETE" for row in payload["branches"])


def test_fix_workflow_marks_missing_replay_facts_unsupported(monkeypatch, tmp_path):
    from factoryline import fix_workflow

    monkeypatch.setattr(
        fix_workflow,
        "compare_repair",
        lambda *_args, **_kwargs: {
            "comparison_id": "incomplete-receipt",
            "contract_sha256": _digest("contract"),
            "receipt_sha256": _digest("comparison"),
            "executed": True,
            "state": "FAIL",
            "original": {"executed": True},
            "repaired": {"executed": True},
            "negative_controls": [{"executed": True}],
            "negative_controls_required": 1,
        },
    )
    result = fix_workflow.run_fix_workflow(
        tmp_path,
        {"manifest": "bound"},
        execute=True,
    )

    intervention = result["behavioral_intervention"]
    assert intervention["status"] == "UNSUPPORTED"
    assert intervention["original"]["status"] == "UNSUPPORTED"
    assert intervention["negative_control_counts"]["executed"] == 1
    assert intervention["negative_control_counts"]["unsupported"] == 1


@pytest.mark.parametrize("failure_reason", ["STDOUT_LIMIT_EXCEEDED", "STOP_REQUESTED"])
def test_fix_workflow_does_not_count_runner_stops_as_reproduced_failures(
    monkeypatch, tmp_path, failure_reason
):
    from factoryline import fix_workflow

    def receipt(expected, actual, state, reason=None):
        digest = _digest("receipt")
        return {
            "executed": True,
            "receipt_sha256": digest,
            "source_sha256": _digest("source"),
            "argv_sha256": _digest("argv"),
            "dependencies_sha256": _digest("dependencies"),
            "policy_sha256": _digest("policy"),
            "stdout_sha256": _digest("stdout"),
            "stderr_sha256": _digest("stderr"),
            "expected_exit": expected,
            "observed_exit": actual,
            "timed_out": False,
            "cleanup": True,
            "failure_reason": reason,
            "state": state,
        }

    monkeypatch.setattr(
        fix_workflow,
        "compare_repair",
        lambda *_args, **_kwargs: {
            "comparison_id": "runner-stopped",
            "contract_sha256": _digest("contract"),
            "receipt_sha256": _digest("comparison"),
            "executed": True,
            "state": "FAIL",
            "original": receipt(1, 1, "FAIL", failure_reason),
            "repaired": receipt(0, 0, "PASS"),
            "negative_controls": [receipt(1, 1, "PASS")],
            "negative_controls_required": 1,
        },
    )

    result = fix_workflow.run_fix_workflow(
        tmp_path,
        {"manifest": "bound"},
        execute=True,
    )

    intervention = result["behavioral_intervention"]
    assert intervention["status"] == "INCOMPLETE"
    assert intervention["original"]["status"] == "INCOMPLETE"
    assert intervention["original"]["observed"] is False
    assert intervention["original"]["expected_outcome_observed"] is False
    assert intervention["what_broke"] == "NOT_CONFIRMED"
    assert intervention["negative_control_counts"]["expected_failures_preserved"] == 1
