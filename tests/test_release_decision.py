from __future__ import annotations

import json
from pathlib import Path

import pytest

import factoryline.release_decision as decision
import factoryline.mission_control_status as mission_control
from factoryline.cli import main
from factoryline.mcp import dispatch
from factoryline.release_decision import release_decision_card, release_workflow_decision_projection, render_release_decision_card


def _integrity(*, ok: bool) -> dict[str, object]:
    checks = [
        {"id": "RELEASE_FAN_IN_EXACT", "passed": ok, "evidence": "fan-in is exact"},
        {"id": "OPENVSX_AUTHORIZATION_EARLY", "passed": True, "evidence": "authorization is early"},
    ]
    return {
        "ok": ok,
        "marker": "RELEASE_INTEGRITY_READ_ONLY" if ok else "RELEASE_INTEGRITY_FAILURE",
        "checks": checks,
        "external_requirements": ["protected provider credentials remain external"],
    }


def _verification(*, release_ready: bool) -> dict[str, object]:
    return {
        "release_ready": release_ready,
        "shippable": release_ready,
        "release_contract": {"marker": "RELEASE_CONTRACT_VALID" if release_ready else "RELEASE_CONTRACT_ORACLE_BLOCKED"},
        "blockers": [] if release_ready else [
            {"code": "RECEIPT_POLICY_BINDING_MISMATCH", "detail": "verify:strict is not bound to the current policy"},
            {"code": "RELEASE_CONTRACT_ORACLE_BLOCKED", "detail": "sealed Oracle binding is stale"},
        ],
        "next_action": "recreate current strict local receipts",
    }


def test_release_decision_prioritizes_workflow_failure_and_never_runs_feature_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    before = {path.relative_to(tmp_path).as_posix(): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    monkeypatch.setattr(decision, "release_integrity", lambda _: _integrity(ok=False))

    def _unexpected(*_args, **_kwargs):
        raise AssertionError("feature verification must not run behind a workflow failure")

    monkeypatch.setattr(decision, "verify_feature", _unexpected)
    card = release_decision_card(tmp_path, "payments")

    assert card["schema"] == "factory.release-decision-card.v1"
    assert card["state"] == "LOCAL_WORKFLOW_BLOCKED"
    assert card["local_evidence"]["evaluated"] is False
    assert card["blockers"] == [{"source": "release_integrity", "code": "RELEASE_FAN_IN_EXACT", "detail": "fan-in is exact"}]
    assert "not a provider rejection" in card["explanation"]
    assert all(value is False for value in card["authority"].values())
    assert {path.relative_to(tmp_path).as_posix(): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()} == before


def test_release_workflow_projection_is_read_only_and_requires_feature_evidence() -> None:
    blocked = release_workflow_decision_projection({
        "applicable": True,
        "ok": False,
        "marker": "RELEASE_INTEGRITY_FAILURE",
        "checks": [{"id": "RELEASE_FAN_IN_EXACT", "passed": False, "evidence": "fan-in missing"}],
    })
    assert blocked["marker"] == "RELEASE_DECISION_GRAPH_READ_ONLY"
    assert blocked["facts"]["state"] == "LOCAL_WORKFLOW_BLOCKED"
    assert blocked["facts"]["failed_check_ids"] == ["RELEASE_FAN_IN_EXACT"]
    assert blocked["facts"]["provider_state"] == "unobserved"
    assert all(value is False for value in blocked["facts"]["authority"].values())

    healthy = release_workflow_decision_projection({
        "applicable": True,
        "ok": True,
        "marker": "RELEASE_INTEGRITY_READ_ONLY",
        "checks": [],
    })
    assert healthy["facts"]["state"] == "FEATURE_DECISION_REQUIRED"
    assert healthy["facts"]["feature_required"] is True
    assert healthy["facts"]["next_action"] == "factory release decision <feature> --root . --json"

    absent = release_workflow_decision_projection({"applicable": False, "ok": True, "checks": []})
    assert absent["facts"]["state"] == "RELEASE_WORKFLOW_NOT_APPLICABLE"
    assert absent["source"] is None


def test_release_decision_requires_a_local_contract_before_feature_verification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(decision, "release_integrity", lambda _: _integrity(ok=True))

    def _unexpected(*_args, **_kwargs):
        raise AssertionError("missing contracts must not be verified as if they existed")

    monkeypatch.setattr(decision, "verify_feature", _unexpected)
    card = release_decision_card(tmp_path, "payments")

    assert card["state"] == "LOCAL_EVIDENCE_MISSING"
    assert card["blockers"][0]["code"] == "RELEASE_CONTRACT_MISSING"
    assert card["next_action"]["action"] == "create_or_restore_release_contract"
    assert card["external_gates"][0]["state"] == "unobserved"


def test_release_decision_reports_ordered_local_evidence_blockers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / ".factory" / "release-contracts" / "payments.json"
    path.parent.mkdir(parents=True)
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(decision, "release_integrity", lambda _: _integrity(ok=True))
    monkeypatch.setattr(decision, "verify_feature", lambda *_args, **_kwargs: _verification(release_ready=False))

    card = release_decision_card(tmp_path, "payments")

    assert card["state"] == "LOCAL_EVIDENCE_BLOCKED"
    assert [item["code"] for item in card["blockers"]] == [
        "RECEIPT_POLICY_BINDING_MISMATCH",
        "RELEASE_CONTRACT_ORACLE_BLOCKED",
    ]
    assert card["next_action"]["action"] == "repair_local_evidence_chain"
    assert "not a provider rejection" in render_release_decision_card(card)


def test_release_decision_exposes_local_pass_without_external_provider_claim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / ".factory" / "release-contracts" / "payments.json"
    path.parent.mkdir(parents=True)
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(decision, "release_integrity", lambda _: _integrity(ok=True))
    monkeypatch.setattr(decision, "verify_feature", lambda *_args, **_kwargs: _verification(release_ready=True))

    card = release_decision_card(tmp_path, "payments")

    assert card["state"] == "EXTERNAL_GATES_UNOBSERVED"
    assert card["blockers"] == []
    assert card["external_gates"][0]["id"] == "PROVIDER_STATE_UNOBSERVED"
    assert "does not contact a provider" in card["claim_boundary"]
    assert all(value is False for value in card["authority"].values())


def test_release_decision_never_hides_an_unexplained_local_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / ".factory" / "release-contracts" / "payments.json"
    path.parent.mkdir(parents=True)
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(decision, "release_integrity", lambda _: _integrity(ok=True))
    monkeypatch.setattr(decision, "verify_feature", lambda *_args, **_kwargs: {
        "release_ready": False,
        "shippable": False,
        "release_contract": {"marker": "RELEASE_CONTRACT_VALID"},
        "blockers": [],
        "next_action": "inspect strict verification",
    })

    card = release_decision_card(tmp_path, "payments")

    assert card["state"] == "LOCAL_EVIDENCE_BLOCKED"
    assert card["blockers"] == [{
        "source": "strict_release_verification",
        "code": "LOCAL_RELEASE_NOT_READY",
        "detail": "strict local verification returned release_ready=false without an individual blocker",
    }]


@pytest.mark.parametrize("feature", ["Payments", "-payments", "payment space", "x" * 65])
def test_release_decision_rejects_unbounded_or_ambiguous_feature_ids(tmp_path: Path, feature: str) -> None:
    with pytest.raises(ValueError, match="feature must use"):
        release_decision_card(tmp_path, feature)


def test_release_decision_cli_and_mcp_expose_the_same_local_missing_contract_boundary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setattr(decision, "release_integrity", lambda _: _integrity(ok=True))
    monkeypatch.setattr("factoryline.cli.release_decision_card", decision.release_decision_card)
    monkeypatch.setattr("factoryline.mcp.release_decision_card", decision.release_decision_card)

    assert main(["release", "decision", "payments", "--root", str(tmp_path), "--json"]) == 1
    cli = json.loads(capsys.readouterr().out)
    response = dispatch({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "factory.release_decision", "arguments": {"feature": "payments"}},
    }, tmp_path)
    mcp = json.loads(response["result"]["content"][0]["text"])

    assert cli["state"] == "LOCAL_EVIDENCE_MISSING"
    assert mcp["marker"] == "MCP_RELEASE_DECISION_READ_ONLY"
    assert mcp["card"] == cli
    rejected = dispatch({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "factory.release_decision", "arguments": {}},
    }, tmp_path)
    assert rejected["error"]["data"]["marker"] == "RELEASE_DECISION_INPUT_REJECTED"


def test_mission_control_prioritizes_declared_release_workflow_repair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mission_control, "_release_workflow_integrity", lambda _: {
        "schema": "factory.release_integrity.v1",
        "marker": "RELEASE_INTEGRITY_FAILURE",
        "applicable": True,
        "ok": False,
        "checks": [{"id": "RELEASE_FAN_IN_EXACT", "passed": False, "evidence": "fan-in missing"}],
        "failed_check_ids": ["RELEASE_FAN_IN_EXACT"],
    })

    status = mission_control.mission_control_status(tmp_path)

    assert status["blockers"]["release_workflow_blocked"] == 1
    assert status["human_control_plane"]["next_action"] == "repair_release_workflow"
    assert status["evidence"]["release_workflow_integrity"]["failed_check_ids"] == ["RELEASE_FAN_IN_EXACT"]
