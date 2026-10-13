import hashlib
import json
import sys

import pytest

from factoryline.fix_workflow import (
    FixWorkflowError,
    run_fix_workflow,
    run_repair_branch_comparison,
)
from factoryline.live_feedback import LiveFeedbackError, run_live_feedback
from factoryline.senior_assurance import _source_digest


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
