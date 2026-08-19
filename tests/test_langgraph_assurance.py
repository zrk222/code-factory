from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.langgraph_assurance import (
    CAPSULE_MARKER,
    DIVERGENCE_MARKER,
    INPUT_MARKER,
    MCP_MARKER,
    PARITY_MARKER,
    TRANSITION_MARKER,
    LangGraphAssuranceError,
    LangGraphTransitionRecorder,
    verify_langgraph_resume_parity,
)


def _record(root: Path, run_id: str, final_status: str = "accepted") -> Path:
    recorder = LangGraphTransitionRecorder("support-agent", run_id)
    recorder.record_transition(
        "classify",
        superstep=1,
        checkpoint_id="checkpoint-1",
        before_state={"request": "super-secret-request"},
        after_state={"request": "super-secret-request", "status": "classified"},
        decision={"route": "triage", "reason": "private-prompt-text"},
    )
    recorder.record_transition(
        "respond",
        superstep=2,
        checkpoint_id="checkpoint-2",
        before_state={"request": "super-secret-request", "status": "classified"},
        after_state={"request": "super-secret-request", "status": final_status},
        decision={"route": final_status, "reason": "private-response-text"},
        side_effects=[{"effect_id": "customer-message", "idempotency_key": "secret-key", "status": "completed"}],
    )
    output = Path(".factory/langgraph") / f"{run_id}.json"
    sealed = recorder.seal(root, output)
    assert sealed["marker"] == TRANSITION_MARKER
    return root / output


def test_hash_only_recorder_and_parity_receipt_do_not_retain_source_values(tmp_path: Path) -> None:
    reference = _record(tmp_path, "reference")
    resumed = _record(tmp_path, "resumed")
    out = Path(".factory/langgraph/assurance.json")

    payload = verify_langgraph_resume_parity(tmp_path, reference.relative_to(tmp_path), resumed.relative_to(tmp_path), out)

    assert payload["marker"] == PARITY_MARKER
    assert payload["verdict"] == "VERIFIED"
    assert payload["recovery_plan"]["action"] == "no_recovery_required"
    assert all(value is False for value in payload["authority"].values())
    written = (tmp_path / out).read_text(encoding="utf-8")
    assert "super-secret-request" not in written
    assert "private-prompt-text" not in written
    assert "secret-key" not in written
    assert "time" in " ".join(payload["scope_limits"])


def test_divergence_emits_a_shareable_hash_only_incident_capsule(tmp_path: Path) -> None:
    reference = _record(tmp_path, "reference")
    resumed = _record(tmp_path, "resumed", final_status="rejected")

    payload = verify_langgraph_resume_parity(tmp_path, reference.relative_to(tmp_path), resumed.relative_to(tmp_path))

    assert payload["marker"] == DIVERGENCE_MARKER
    assert payload["verdict"] == "REVIEW_REQUIRED"
    assert CAPSULE_MARKER in payload["markers"]
    capsule = payload["incident_capsule"]
    assert capsule["marker"] == CAPSULE_MARKER
    assert capsule["first_divergence"]["candidate_node"] == "respond"
    assert "flowchart LR" in capsule["mermaid"]
    assert "rejected" not in json.dumps(payload)
    assert "super-secret-request" not in json.dumps(payload)
    assert payload["recovery_plan"]["execute"] is False
    assert payload["recovery_plan"]["requires_human_approval"] is True


def test_duplicate_effect_and_parallel_write_are_replay_anomalies(tmp_path: Path) -> None:
    recorder = LangGraphTransitionRecorder("support-agent", "reference")
    recorder.record_transition(
        "left", superstep=1, checkpoint_id="cp-1", before_state={"state": "new"}, after_state={"state": "left"},
        decision={"route": "left", "reason": "one"}, side_effects=[{"effect_id": "mail", "idempotency_key": "one", "status": "completed"}],
    )
    recorder.record_transition(
        "right", superstep=1, checkpoint_id="cp-2", before_state={"state": "new"}, after_state={"state": "right"},
        decision={"route": "right", "reason": "two"}, side_effects=[{"effect_id": "mail", "idempotency_key": "two", "status": "completed"}],
    )
    reference = recorder.seal(tmp_path, ".factory/langgraph/reference.json")["lineage"]["path"]
    resumed = _record(tmp_path, "resumed")

    payload = verify_langgraph_resume_parity(tmp_path, Path(reference).relative_to(tmp_path), resumed.relative_to(tmp_path))

    assert payload["marker"] == DIVERGENCE_MARKER
    codes = {item["code"] for item in payload["anomalies"]}
    assert {"DUPLICATE_SIDE_EFFECT", "PARALLEL_WRITE_CONFLICT"} <= codes
    assert payload["incident_capsule"]["marker"] == CAPSULE_MARKER


def test_invalid_state_or_workspace_escape_fails_before_output(tmp_path: Path) -> None:
    recorder = LangGraphTransitionRecorder("support-agent", "bad-run")
    with pytest.raises(LangGraphAssuranceError) as state_error:
        recorder.record_transition(
            "bad", superstep=1, checkpoint_id="cp", before_state={"value": object()}, after_state={},
            decision={"route": "bad", "reason": "bad"},
        )
    assert state_error.value.code == INPUT_MARKER
    with pytest.raises(LangGraphAssuranceError) as escape_error:
        recorder.seal(tmp_path, "../escape.json")
    assert escape_error.value.code == INPUT_MARKER
    assert not (tmp_path.parent / "escape.json").exists()


def test_cli_is_workspace_bound_machine_readable_and_nonzero_for_divergence(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    reference = _record(tmp_path, "reference")
    resumed = _record(tmp_path, "resumed", final_status="rejected")
    out = ".factory/langgraph/cli-assurance.json"

    code = main([
        "langgraph", "replay-verify", "--root", str(tmp_path),
        "--reference", reference.relative_to(tmp_path).as_posix(),
        "--resumed", resumed.relative_to(tmp_path).as_posix(),
        "--out", out, "--json",
    ])

    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["marker"] == DIVERGENCE_MARKER
    assert (tmp_path / out).is_file()
    assert MCP_MARKER == "LANGGRAPH_MCP_READ_ONLY"


def test_module_has_no_langgraph_or_execution_dependency() -> None:
    source = (Path(__file__).parents[1] / "factoryline" / "langgraph_assurance.py").read_text(encoding="utf-8")
    forbidden = ("import langgraph", "subprocess", "requests", "httpx", "urllib", "socket", "os.system")
    assert not any(token in source for token in forbidden)


def test_github_action_is_opt_in_and_never_requests_merge_or_write_authority() -> None:
    action = (Path(__file__).parents[1] / "action.yml").read_text(encoding="utf-8")

    assert "factory langgraph replay-verify" in action
    assert "GITHUB_STEP_SUMMARY" in action
    assert "pull_request_target" not in action
    assert "checks: write" not in action
    assert "pull-requests: write" not in action
    assert "merge" not in action.lower().replace("does not invoke a graph, replay an effect, approve, merge", "")
