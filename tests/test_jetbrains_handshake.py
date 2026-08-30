from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.appforge_design import compile_appforge_design
from factoryline.e2e_proof import verify_e2e_proof
from factoryline.intent_ledger import capture_intent_ledger
from factoryline.jetbrains_handshake import JetBrainsHandshakeError, build_agent_proof_mission, evaluate_jetbrains_handshake
from factoryline.repair_sandbox import create_repair_scope


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _scope(root: Path) -> Path:
    (root / "app.py").write_text("print('before')", encoding="utf-8")
    scope = create_repair_scope(root, "Checkout hardening", ["app.py"])
    return _write(root / ".factory/repair-sandboxes/scope.json", {key: value for key, value in scope.items() if key not in {"scope_markdown", "mermaid"}})


def _sarif(root: Path, *, results: list[dict[str, object]] | None = None, success: bool = True, tool: str = "JetBrains Qodana") -> Path:
    return _write(root / "qodana.sarif.json", {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": tool}}, "invocations": [{"executionSuccessful": success}], "results": results or []}]})


def _e2e(root: Path, *, hollow: bool = False) -> Path:
    manifest = _write(root / "proof.json", {
        "schema": "factory.e2e_proof_manifest.v1", "id": "checkout", "approval": {"state": "approved", "approved_by": "Ada"},
        "working_directory": ".", "timeout_seconds": 5, "network_egress": "not_granted",
        "positive": {"argv": ["python", "-c", "pass"]},
        "negative": {"argv": ["python", "-c", "pass" if hollow else "import sys; sys.exit(1)"]}, "artifact_paths": [],
    })
    receipt = verify_e2e_proof(root, manifest)
    return _write(root / ".factory/e2e-proof/receipt.json", {key: value for key, value in receipt.items() if key != "_captures"})


def _intent(root: Path) -> None:
    capture_intent_ledger(root, change_list="Checkout hardening", changed=["app.py"], confirmed_by="Ada", promise="Checkout rejects expired cards.", non_goal="No billing migration.", failure_case="An expired card is rejected.", confirmation="CAPTURE Checkout hardening")


def test_mission_is_scope_bound_and_tells_junie_not_to_weaken_tests(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    _intent(tmp_path)
    mission = build_agent_proof_mission(tmp_path, scope)
    assert mission["scope"]["sealed_paths"] == ["app.py"]
    assert mission["intent"]["promise"] == "Checkout rejects expired cards."
    assert "Do not delete, skip, weaken" in mission["mission_text"]
    assert all(value is False for value in mission["authority"].values())


def test_mission_binds_hash_valid_appforge_context_without_granting_agent_authority(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    brief = _write(tmp_path / "appforge-brief.json", {
        "app_name": "Checkout Guard",
        "audience": "independent developers",
        "primary_job": "review a risky change",
        "desired_emotion": "calm confidence",
        "screens": [{"id": "review", "user_goal": "understand whether evidence is complete"}],
    })
    compile_appforge_design(tmp_path, brief, Path(".factory/appforge/checkout"))
    mission = build_agent_proof_mission(tmp_path, scope)
    assert mission["product_proof"]["appforge"]["state"] == "bound"
    assert len(mission["product_proof"]["appforge"]["receipt_sha256"]) == 64
    assert mission["product_proof"]["saas"]["state"] == "not_supplied"
    assert "AppForge design proof: bound" in mission["mission_text"]
    assert mission["authority"]["deployment"] is False


def test_handshake_blocks_scope_escape_analysis_regression_and_hollow_test(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    sarif = _sarif(tmp_path, results=[{"ruleId": "UnsafeCall", "level": "error", "baselineState": "new"}])
    receipt = _e2e(tmp_path, hollow=True)
    result = evaluate_jetbrains_handshake(tmp_path, scope, ["app.py", "release.yml"], sarif, receipt)
    assert result["verdict"] == "blocked"
    assert result["blockers"] == ["scope_escape", "analysis_gate", "hollow_e2e"]
    assert result["scope"]["escaped_paths"] == ["release.yml"]


def test_handshake_ready_requires_intent_analysis_execution_and_non_hollow_e2e(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scope = _scope(tmp_path)
    _intent(tmp_path)
    sarif = _sarif(tmp_path)
    receipt = _e2e(tmp_path)
    monkeypatch.setattr("factoryline.jetbrains_handshake.inspect_intent_ledger", lambda *_args, **_kwargs: {"state": "ready_for_human_review", "inspection_sha256": "a" * 64, "next_action": {"action": "review_packet"}, "record": None})
    result = evaluate_jetbrains_handshake(tmp_path, scope, ["app.py"], sarif, receipt)
    assert result["verdict"] == "ready_for_human_review"
    assert result["next_action"] == "human_review"
    assert result["blockers"] == [] and result["unknowns"] == []
    assert result["analysis"]["provider"] == "qodana"


def test_handshake_accepts_sonarqube_as_a_verified_analysis_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scope = _scope(tmp_path)
    receipt = _e2e(tmp_path)
    monkeypatch.setattr("factoryline.jetbrains_handshake.inspect_intent_ledger", lambda *_args, **_kwargs: {"state": "ready_for_human_review", "inspection_sha256": "b" * 64, "next_action": {"action": "review_packet"}, "record": None})
    result = evaluate_jetbrains_handshake(tmp_path, scope, ["app.py"], _sarif(tmp_path, tool="SonarQube for IDE"), receipt)
    assert result["verdict"] == "ready_for_human_review"
    assert result["analysis"]["provider"] == "sonarqube"


def test_handshake_fails_closed_on_tampered_scope_and_missing_evidence(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    value = json.loads(scope.read_text(encoding="utf-8"))
    value["change_list"] = "tampered"
    _write(scope, value)
    with pytest.raises(JetBrainsHandshakeError, match="scope_sha256"):
        build_agent_proof_mission(tmp_path, scope)

    scope = _scope(tmp_path)
    result = evaluate_jetbrains_handshake(tmp_path, scope, ["app.py"], _sarif(tmp_path, success=False))
    assert result["verdict"] == "review_required"
    assert "e2e_receipt_missing" in result["unknowns"]
    assert "analysis_execution_unverified" in result["unknowns"]
