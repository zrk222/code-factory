from __future__ import annotations

from pathlib import Path
import hashlib
import json
import subprocess

import pytest

from factoryline.product_missions import (
    ProductMissionError,
    bind_mission_candidate,
    compile_product_prd,
    close_mission,
    create_mission,
    decide_mission,
    draft_pr,
    outcome_summary,
    plan_value_slices,
    record_outcome,
    verify_mission,
    verify_mission_candidate,
    verify_mission_completion,
    verify_product_graph,
)
from factoryline.meter import MeterLog, StageTiming, live_snapshot
from factoryline.cli import main


PRD = """# Signal Desk

## Actors
- Operator: reviews customer signals.

## Outcomes
- Reduce signal triage time below five minutes.

## Jobs and pains
- Job: prioritize incoming customer signals.
- Pain: fragmented context slows the operator.

## Journeys and business rules
- Journey: capture a signal, review its priority reason, then export the audit report.
- Business rule: private signals require an authenticated operator.

## Data ownership and trust boundaries
- Data ownership: the workspace owner controls retention, export, and deletion.
- Trust boundary: signal content stays inside the selected workspace.

## External effects and approvals
- External effect: exporting a report writes a user-selected local file.
- Approval: publishing, deployment, credentials, and external messages require a human owner.

## Success events
- signal_review_completed within five minutes.

## Requirements
- REQ-LOGIN: The operator must log in before viewing private signals.
- REQ-DASH: The dashboard must show prioritized signals and depends on REQ-LOGIN.
- REQ-EXPORT: The operator must export an audit report for a selected signal.

## Experience states
- Loading: show progress without moving the dashboard layout.
- Empty: explain how to connect the first signal source.
- Error: preserve the last safe view and offer retry.
- Success: confirm the completed action.
- Permission: explain which role is required.
- Offline: preserve read-only cached signals.
- Recovery: resume the interrupted action without duplication.
- Accessibility: expose names, roles, focus order, and keyboard operation.

## Acceptance
Scenario: Review the most important signal
  Given an authenticated operator with prioritized signals
  When the operator opens the dashboard
  Then the highest-priority signal is visible with its reason
"""


def _pipeline(tmp_path: Path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    prd = tmp_path / "PRD.md"
    prd.write_text(PRD, encoding="utf-8")
    graph = compile_product_prd(prd, tmp_path)
    slices = plan_value_slices(Path(graph["path"]), tmp_path, max_requirements=2)
    mission = create_mission(
        Path(slices["path"]), slices["slices"][-1]["id"], tmp_path, "release-owner"
    )
    return graph, slices, mission


def _candidate_workspace(root: Path, workspace: str = "candidate") -> tuple[Path, dict]:
    candidate = root / workspace
    candidate.mkdir(parents=True)
    (candidate / "README.md").write_text("candidate base\n", encoding="utf-8")
    (candidate / ".gitignore").write_text("src/signal-review.py\n", encoding="utf-8")

    def git(*args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(candidate), *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    git("init", "--quiet")
    git("add", "README.md", ".gitignore")
    git(
        "-c",
        "user.name=Test Owner",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "candidate base",
    )
    lanes = {
        lane: {"applicable": True, "reason": f"{lane} applies to this candidate"}
        for lane in (
            "static",
            "secrets",
            "configuration",
            "dependencies",
            "runtime",
            "fuzz",
        )
    }
    declaration = {
        "schema": "factory.mission.candidate-declaration.v1",
        "workspace": workspace,
        "base_commit": git("rev-parse", "HEAD"),
        # The target is intentionally absent at binding time; it is an exact path.
        "paths": ["src/signal-review.py"],
        "interfaces": ["GET /signals returns prioritized signals"],
        "profiles": ["python-3.11-windows"],
        "commands": [{"id": "unit", "argv": ["python", "-m", "pytest", "-q"]}],
        "audit_lanes": lanes,
    }
    return candidate, declaration


def _approved_binding_inputs(tmp_path: Path):
    _graph, _slices, mission = _pipeline(tmp_path)
    decision = decide_mission(
        Path(mission["path"]),
        tmp_path,
        owner="release-owner",
        decision="approved_execution",
        rationale="Approve this bounded candidate slice.",
    )
    candidate, declaration = _candidate_workspace(tmp_path)
    return mission, decision, candidate, declaration


def _bound_candidate(tmp_path: Path):
    mission, decision, candidate, declaration = _approved_binding_inputs(tmp_path)
    declaration["commands"][0]["argv"] = [
        "python",
        "-c",
        "from pathlib import Path; "
        f"Path({str(candidate / 'executed-marker')!r}).write_text('ran')",
    ]
    binding = bind_mission_candidate(
        Path(mission["path"]),
        Path(decision["path"]),
        tmp_path,
        owner="release-owner",
        declaration=declaration,
    )
    return mission, decision, candidate, declaration, binding


def _reseal_candidate_binding(path: Path, mutate) -> None:
    receipt = json.loads(path.read_text(encoding="utf-8"))
    mutate(receipt)
    core = {key: value for key, value in receipt.items() if key != "binding_sha256"}
    canonical = json.dumps(
        core, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    receipt["binding_sha256"] = hashlib.sha256(canonical).hexdigest()
    path.write_text(json.dumps(receipt), encoding="utf-8")


def test_product_graph_is_stable_bound_and_ux_complete(tmp_path: Path):
    prd = tmp_path / "PRD.md"
    prd.write_text(PRD, encoding="utf-8")
    first = compile_product_prd(prd, tmp_path)
    second = compile_product_prd(prd, tmp_path)
    assert second["idempotent"] is True
    assert first["graph_sha256"] == second["graph_sha256"]
    assert [item["id"] for item in first["requirements"]] == [
        "REQ-LOGIN",
        "REQ-DASH",
        "REQ-EXPORT",
    ]
    assert set(first["ux_states"].values()) == {"declared"}
    assert first["journeys"] and first["business_rules"]
    assert first["data_ownership"] and first["trust_boundaries"]
    assert first["external_effects"] and first["approval_requirements"]
    assert first["success_events"] == ["signal_review_completed within five minutes."]
    assert verify_product_graph(Path(first["path"]))["valid"] is True


def _validation_for(mission: dict, creator: str, verifier: str, evidence: Path) -> dict:
    criteria = []
    for item in mission["completion_contract"]["criteria"]:
        proof = evidence
        if item.get("verification_kind") == "browser_control":
            screenshot = evidence.parent / "browser-flow.png"
            screenshot.write_bytes(b"png evidence")
            proof = evidence.parent / "browser-flow.json"
            proof.write_text(
                json.dumps(
                    {
                        "schema": "factory.browser-flow.evidence.v1",
                        "mission_id": mission["id"],
                        "criterion_id": item["id"],
                        "verifier_id": verifier,
                        "start_url": "http://127.0.0.1:3000/",
                        "expected_url": "http://127.0.0.1:3000/dashboard",
                        "observed_url": "http://127.0.0.1:3000/dashboard",
                        "clicks": 2,
                        "steps": [
                            {"action": "open", "passed": True},
                            {"action": "submit", "passed": True},
                        ],
                        "assertions": [{"name": "dashboard visible", "passed": True}],
                        "artifacts": [str(screenshot)],
                    }
                ),
                encoding="utf-8",
            )
        criteria.append({"id": item["id"], "passed": True, "evidence": [str(proof)]})
    return {
        "schema": "factory.mission.validation-input.v1",
        "creator_id": creator,
        "verifier_id": verifier,
        "verifier_context": ["mission.json", "candidate_diff", "evidence_manifest"],
        "adapter_attestation": {
            "schema": "factory.verifier-attestation.v1",
            "mission_digest": mission["mission_sha256"],
            "contract_digest": "c" * 64,
            "creator_id": creator,
            "verifier_id": verifier,
            "verifier_context": ["mission.json", "candidate_diff", "evidence_manifest"],
            "fresh_session": True,
            "context_wall": "isolated",
            "evidence_digest": "d" * 64,
            "adapter_id": "test-adapter",
        },
        "criteria": criteria,
    }


def test_mission_completion_requires_fresh_context_and_all_evidence(tmp_path: Path):
    _graph, _slices, mission = _pipeline(tmp_path)
    assert mission["orchestration"]["context_wall"]["same_identity_allowed"] is False
    evidence = tmp_path / "test-results.json"
    evidence.write_text('{"passed": true}\n')
    validation = tmp_path / "validation.json"
    validation.write_text(
        json.dumps(_validation_for(mission, "worker-1", "worker-1", evidence))
    )
    with pytest.raises(ProductMissionError, match="VERIFIER_IDENTITY_DISTINCT"):
        close_mission(Path(mission["path"]), validation, tmp_path)
    assert not (Path(mission["path"]).parent / "completion.json").exists()

    incomplete = _validation_for(mission, "worker-1", "verifier-1", evidence)
    incomplete["criteria"].pop()
    validation.write_text(json.dumps(incomplete))
    with pytest.raises(ProductMissionError, match="NO_FINISH_CONTRACT"):
        close_mission(Path(mission["path"]), validation, tmp_path)

    validation.write_text(
        json.dumps(_validation_for(mission, "worker-1", "verifier-1", evidence))
    )
    completion = close_mission(Path(mission["path"]), validation, tmp_path)
    assert completion["status"] == "completed"
    assert completion["creator_id"] != completion["verifier_id"]
    assert verify_mission_completion(Path(completion["path"]))["valid"] is True
    evidence.write_text('{"passed": false}\n')
    check = verify_mission_completion(Path(completion["path"]))
    assert check["valid"] is False
    assert check["marker"] == "MISSION_COMPLETION_DRIFT"


def test_browser_control_is_a_bounded_no_finish_criterion(tmp_path: Path):
    _graph, _slices, mission = _pipeline(tmp_path)
    browser = next(
        item
        for item in mission["completion_contract"]["criteria"]
        if item["verification_kind"] == "browser_control"
    )
    assert browser["evidence_contract"]["max_clicks"] == 3
    assert mission["completion_contract"]["hypotheses"]
    assert mission["orchestration"]["attempt_policy"]["fresh_session_required"] is True
    assert (
        mission["orchestration"]["routing_policy"]["provider_binding"]
        == "external_adapter_required"
    )
    evidence = tmp_path / "test-results.json"
    evidence.write_text('{"passed": true}\n')
    payload = _validation_for(mission, "worker", "verifier", evidence)
    browser_row = next(
        item for item in payload["criteria"] if item["id"] == browser["id"]
    )
    browser_path = Path(browser_row["evidence"][0])
    receipt = json.loads(browser_path.read_text(encoding="utf-8"))
    receipt["clicks"] = 4
    receipt["steps"].extend([{"action": "extra", "passed": True}] * 2)
    browser_path.write_text(json.dumps(receipt), encoding="utf-8")
    validation = tmp_path / "validation-browser.json"
    validation.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ProductMissionError, match="BROWSER_FLOW_INVALID"):
        close_mission(Path(mission["path"]), validation, tmp_path)


def test_mission_decision_is_owner_bound_and_cannot_authorize_release(tmp_path: Path):
    _graph, _slices, mission = _pipeline(tmp_path)
    with pytest.raises(ProductMissionError, match="MISSION_DECISION_OWNER_MISMATCH"):
        decide_mission(
            Path(mission["path"]),
            tmp_path,
            owner="someone-else",
            decision="approved_execution",
            rationale="Approve.",
        )
    decision = decide_mission(
        Path(mission["path"]),
        tmp_path,
        owner="release-owner",
        decision="approved_execution",
        rationale="The bounded slice is ready for its executor.",
    )
    assert decision["execution_authorized"] is True
    assert decision["authority"] == {
        "execute_bounded_mission": True,
        "merge": False,
        "publish": False,
        "deploy": False,
        "external_message": False,
        "connector_grant": False,
        "credential_access": False,
    }


def test_candidate_binding_is_hash_bound_and_does_not_dispatch(tmp_path: Path):
    mission, decision, candidate, declaration = _approved_binding_inputs(tmp_path)
    mission_before = Path(mission["path"]).read_bytes()
    decision_before = Path(decision["path"]).read_bytes()

    binding = bind_mission_candidate(
        Path(mission["path"]),
        Path(decision["path"]),
        tmp_path,
        owner="release-owner",
        declaration=declaration,
    )

    assert binding["schema"] == "factory.mission.candidate-binding.v1"
    assert binding["state"] == "bound_not_executed"
    assert binding["execution_authorized"] is False
    assert binding["dispatched"] is False
    assert len(binding["candidate_sha256"]) == 64
    assert len(binding["binding_sha256"]) == 64
    assert Path(binding["path"]).is_file()
    assert candidate.joinpath("src", "signal-review.py").exists() is False
    assert Path(mission["path"]).read_bytes() == mission_before
    assert Path(decision["path"]).read_bytes() == decision_before


def test_candidate_binding_rejects_missing_approval_and_owner_mismatch(tmp_path: Path):
    _graph, _slices, mission = _pipeline(tmp_path)
    decision = decide_mission(
        Path(mission["path"]),
        tmp_path,
        owner="release-owner",
        decision="deferred",
        rationale="Wait for candidate inspection.",
    )
    _candidate, declaration = _candidate_workspace(tmp_path)
    with pytest.raises(ProductMissionError):
        bind_mission_candidate(
            Path(mission["path"]),
            Path(decision["path"]),
            tmp_path,
            owner="release-owner",
            declaration=declaration,
        )

    _mission, approved, _candidate, approved_declaration = _approved_binding_inputs(
        tmp_path / "owner-mismatch"
    )
    with pytest.raises(ProductMissionError):
        bind_mission_candidate(
            Path(_mission["path"]),
            Path(approved["path"]),
            tmp_path / "owner-mismatch",
            owner="another-owner",
            declaration=approved_declaration,
        )


@pytest.mark.parametrize(
    "path_value",
    [
        "../outside.py",
        "src/*.py",
        ".git/config",
        ".factory/state.json",
        ".GIT/config",
        ".Factory/state.json",
        ".git./config",
        ".factory./state.json",
        str(Path.cwd() / "outside.py"),
    ],
)
def test_candidate_binding_rejects_unsafe_scope_paths(tmp_path: Path, path_value: str):
    mission, decision, _candidate, declaration = _approved_binding_inputs(tmp_path)
    declaration["paths"] = [path_value]
    with pytest.raises(ProductMissionError):
        bind_mission_candidate(
            Path(mission["path"]),
            Path(decision["path"]),
            tmp_path,
            owner="release-owner",
            declaration=declaration,
        )


@pytest.mark.parametrize(
    "path_value",
    [".GIT/config", ".Factory/state.json", ".git./config", ".factory./state.json"],
)
def test_candidate_binding_rejects_casefolded_and_trailing_dot_reserved_paths(
    tmp_path: Path, path_value: str
):
    mission, decision, _candidate, declaration = _approved_binding_inputs(tmp_path)
    declaration["paths"] = [path_value]
    with pytest.raises(ProductMissionError):
        bind_mission_candidate(
            Path(mission["path"]),
            Path(decision["path"]),
            tmp_path,
            owner="release-owner",
            declaration=declaration,
        )


@pytest.mark.parametrize("dirty_kind", ["tracked", "untracked"])
def test_candidate_binding_rejects_dirty_candidate(tmp_path: Path, dirty_kind: str):
    mission, decision, candidate, declaration = _approved_binding_inputs(tmp_path)
    if dirty_kind == "tracked":
        (candidate / "README.md").write_text("changed after base\n", encoding="utf-8")
    else:
        (candidate / "untracked.txt").write_text("untracked\n", encoding="utf-8")
    with pytest.raises(ProductMissionError):
        bind_mission_candidate(
            Path(mission["path"]),
            Path(decision["path"]),
            tmp_path,
            owner="release-owner",
            declaration=declaration,
        )


def test_candidate_binding_rejects_base_commit_and_mission_drift(tmp_path: Path):
    mission, decision, _candidate, declaration = _approved_binding_inputs(tmp_path)
    declaration["base_commit"] = "0" * 40
    with pytest.raises(ProductMissionError):
        bind_mission_candidate(
            Path(mission["path"]),
            Path(decision["path"]),
            tmp_path,
            owner="release-owner",
            declaration=declaration,
        )
    declaration["base_commit"] = _candidate_workspace_head(tmp_path / "candidate")
    Path(mission["path"]).write_text("{}\n", encoding="utf-8")
    with pytest.raises(ProductMissionError):
        bind_mission_candidate(
            Path(mission["path"]),
            Path(decision["path"]),
            tmp_path,
            owner="release-owner",
            declaration=declaration,
        )


@pytest.mark.parametrize("invalid_part", ["audit_lanes", "commands", "workspace"])
def test_candidate_binding_rejects_incomplete_declaration(
    tmp_path: Path, invalid_part: str
):
    mission, decision, candidate, declaration = _approved_binding_inputs(tmp_path)
    if invalid_part == "audit_lanes":
        declaration["audit_lanes"].pop("fuzz")
    elif invalid_part == "commands":
        declaration["commands"] = []
    else:
        nested = candidate / "nested"
        nested.mkdir()
        declaration["workspace"] = "candidate/nested"
    with pytest.raises(ProductMissionError):
        bind_mission_candidate(
            Path(mission["path"]),
            Path(decision["path"]),
            tmp_path,
            owner="release-owner",
            declaration=declaration,
        )


def test_candidate_binding_rejects_decision_hash_drift_and_symlink_scope(
    tmp_path: Path,
):
    mission, decision, candidate, declaration = _approved_binding_inputs(tmp_path)
    decision_path = Path(decision["path"])
    changed_decision = json.loads(decision_path.read_text(encoding="utf-8"))
    changed_decision["rationale"] = "tampered after approval"
    decision_path.write_text(json.dumps(changed_decision), encoding="utf-8")
    with pytest.raises(ProductMissionError):
        bind_mission_candidate(
            Path(mission["path"]),
            decision_path,
            tmp_path,
            owner="release-owner",
            declaration=declaration,
        )

    # Recreate an approved, clean binding context for the filesystem-link case.
    linked_root = tmp_path / "symlink-case"
    linked_mission, linked_decision, linked_candidate, linked_declaration = (
        _approved_binding_inputs(linked_root)
    )
    source = tmp_path / "outside-target.py"
    source.write_text("outside\n", encoding="utf-8")
    source_dir = linked_candidate / "src"
    source_dir.mkdir()
    try:
        (source_dir / "linked.py").symlink_to(source)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    linked_declaration["paths"] = ["src/linked.py"]
    with pytest.raises(ProductMissionError):
        bind_mission_candidate(
            Path(linked_mission["path"]),
            Path(linked_decision["path"]),
            linked_root,
            owner="release-owner",
            declaration=linked_declaration,
        )


def test_candidate_binding_accepts_worktree_under_factory_worktrees(tmp_path: Path):
    _graph, _slices, mission = _pipeline(tmp_path)
    decision = decide_mission(
        Path(mission["path"]),
        tmp_path,
        owner="release-owner",
        decision="approved_execution",
        rationale="Approve a candidate below the designated worktree directory.",
    )
    candidate, declaration = _candidate_workspace(
        tmp_path, ".factory/worktrees/candidate"
    )
    declaration["commands"][0]["argv"] = ["python", "-m", "pytest", "-q", "-q"]

    binding = bind_mission_candidate(
        Path(mission["path"]),
        Path(decision["path"]),
        tmp_path,
        owner="release-owner",
        declaration=declaration,
    )

    assert binding["workspace"] == str(candidate.resolve())
    assert binding["state"] == "bound_not_executed"
    assert binding["dispatched"] is False


def test_candidate_binding_rejects_other_factory_workspace(tmp_path: Path):
    _graph, _slices, mission = _pipeline(tmp_path)
    decision = decide_mission(
        Path(mission["path"]),
        tmp_path,
        owner="release-owner",
        decision="approved_execution",
        rationale="Approve the mission before checking workspace scope.",
    )
    _candidate, declaration = _candidate_workspace(
        tmp_path, ".factory/private-candidate"
    )
    with pytest.raises(ProductMissionError):
        bind_mission_candidate(
            Path(mission["path"]),
            Path(decision["path"]),
            tmp_path,
            owner="release-owner",
            declaration=declaration,
        )


def test_candidate_binding_rejects_scope_beneath_file_ancestor(tmp_path: Path):
    mission, decision, _candidate, declaration = _approved_binding_inputs(tmp_path)
    declaration["paths"] = ["README.md/child.py"]
    with pytest.raises(ProductMissionError):
        bind_mission_candidate(
            Path(mission["path"]),
            Path(decision["path"]),
            tmp_path,
            owner="release-owner",
            declaration=declaration,
        )


def test_mission_candidate_verification_is_read_only_and_bound(tmp_path: Path):
    mission, decision, candidate, _declaration, binding = _bound_candidate(tmp_path)
    before = {
        path: Path(path).read_bytes()
        for path in (
            mission["path"],
            decision["path"],
            binding["path"],
            candidate / "README.md",
        )
    }
    candidate_files = sorted(
        path.relative_to(candidate).as_posix()
        for path in candidate.rglob("*")
        if path.is_file()
    )

    result = verify_mission_candidate(
        Path(binding["path"]), tmp_path, owner="release-owner"
    )

    assert result["schema"] == "factory.mission.candidate-verification.v1"
    assert result["valid"] is True
    assert result["state"] == "bound_not_executed"
    assert result["execution_authorized"] is False
    assert result["dispatched"] is False
    assert result["binding_sha256"] == binding["binding_sha256"]
    assert result["candidate_sha256"] == binding["candidate_sha256"]
    assert all(Path(path).read_bytes() == value for path, value in before.items())
    assert candidate_files == sorted(
        path.relative_to(candidate).as_posix()
        for path in candidate.rglob("*")
        if path.is_file()
    )
    assert not (candidate / "executed-marker").exists()


@pytest.mark.parametrize("tamper", ["binding_hash", "authority", "snapshot"])
def test_mission_candidate_verification_rejects_binding_tampering(
    tmp_path: Path, tamper: str
):
    _mission, _decision, _candidate, _declaration, binding = _bound_candidate(tmp_path)
    path = Path(binding["path"])
    if tamper == "binding_hash":
        receipt = json.loads(path.read_text(encoding="utf-8"))
        receipt["binding_sha256"] = "0" * 64
        path.write_text(json.dumps(receipt), encoding="utf-8")
    elif tamper == "authority":
        _reseal_candidate_binding(
            path, lambda receipt: receipt.update(execution_authorized=True)
        )
    else:
        _reseal_candidate_binding(
            path,
            lambda receipt: receipt["files"][0].update(sha256="a" * 64),
        )
    with pytest.raises(ProductMissionError, match="MISSION_CANDIDATE_INVALID"):
        verify_mission_candidate(path, tmp_path, owner="release-owner")


@pytest.mark.parametrize("artifact", ["mission", "decision"])
def test_mission_candidate_verification_rejects_approval_drift(
    tmp_path: Path, artifact: str
):
    mission, decision, _candidate, _declaration, binding = _bound_candidate(tmp_path)
    path = Path(mission["path"] if artifact == "mission" else decision["path"])
    value = path.read_text(encoding="utf-8")
    path.write_text(value + "\n", encoding="utf-8")
    with pytest.raises(ProductMissionError, match="MISSION_CANDIDATE_INVALID"):
        verify_mission_candidate(Path(binding["path"]), tmp_path, owner="release-owner")


def test_mission_candidate_verification_rejects_wrong_owner(tmp_path: Path):
    _mission, _decision, _candidate, _declaration, binding = _bound_candidate(tmp_path)
    with pytest.raises(ProductMissionError, match="MISSION_CANDIDATE_INVALID"):
        verify_mission_candidate(Path(binding["path"]), tmp_path, owner="another-owner")


@pytest.mark.parametrize("change", ["tracked", "untracked", "head"])
def test_mission_candidate_verification_rejects_git_drift(tmp_path: Path, change: str):
    _mission, _decision, candidate, _declaration, binding = _bound_candidate(tmp_path)
    if change == "tracked":
        (candidate / "README.md").write_text(
            "changed after binding\n", encoding="utf-8"
        )
    elif change == "untracked":
        (candidate / "new-untracked.txt").write_text(
            "changed after binding\n", encoding="utf-8"
        )
    else:
        (candidate / "README.md").write_text("new committed base\n", encoding="utf-8")
        subprocess.run(
            [
                "git",
                "-C",
                str(candidate),
                "-c",
                "user.name=Test Owner",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "--all",
                "--quiet",
                "-m",
                "changed base",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    with pytest.raises(ProductMissionError, match="MISSION_CANDIDATE_INVALID"):
        verify_mission_candidate(Path(binding["path"]), tmp_path, owner="release-owner")


def test_mission_candidate_verification_detects_ignored_scoped_file_change(
    tmp_path: Path,
):
    _mission, _decision, candidate, _declaration, binding = _bound_candidate(tmp_path)
    scoped = candidate / "src" / "signal-review.py"
    scoped.parent.mkdir()
    scoped.write_text("ignored but scope-bound\n", encoding="utf-8")
    status = subprocess.run(
        ["git", "-C", str(candidate), "status", "--porcelain=v1"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert status.stdout.strip() == ""
    with pytest.raises(ProductMissionError, match="MISSION_CANDIDATE_INVALID"):
        verify_mission_candidate(Path(binding["path"]), tmp_path, owner="release-owner")


def test_mission_candidate_cli_binds_verifies_and_rejects_tampering(
    tmp_path: Path, capsys
):
    mission, decision, _candidate, declaration = _approved_binding_inputs(tmp_path)
    declaration_path = tmp_path / "candidate-declaration.json"
    declaration_path.write_text(json.dumps(declaration), encoding="utf-8")
    bad_declaration = json.loads(json.dumps(declaration))
    bad_declaration["paths"] = ["../outside.py"]
    bad_declaration_path = tmp_path / "bad-candidate-declaration.json"
    bad_declaration_path.write_text(json.dumps(bad_declaration), encoding="utf-8")
    assert (
        main(
            [
                "mission",
                "bind-candidate",
                mission["path"],
                decision["path"],
                str(bad_declaration_path),
                "--root",
                str(tmp_path),
                "--owner",
                "release-owner",
                "--json",
            ]
        )
        != 0
    )
    capsys.readouterr()

    assert (
        main(
            [
                "mission",
                "bind-candidate",
                mission["path"],
                decision["path"],
                str(declaration_path),
                "--root",
                str(tmp_path),
                "--owner",
                "release-owner",
                "--json",
            ]
        )
        == 0
    )
    binding = json.loads(capsys.readouterr().out)
    assert (
        main(
            [
                "mission",
                "verify-candidate",
                binding["path"],
                "--root",
                str(tmp_path),
                "--owner",
                "release-owner",
                "--json",
            ]
        )
        == 0
    )
    verified = json.loads(capsys.readouterr().out)
    assert verified["valid"] is True

    tampered = json.loads(Path(binding["path"]).read_text(encoding="utf-8"))
    tampered["dispatched"] = True
    Path(binding["path"]).write_text(json.dumps(tampered), encoding="utf-8")
    assert (
        main(
            [
                "mission",
                "verify-candidate",
                binding["path"],
                "--root",
                str(tmp_path),
                "--owner",
                "release-owner",
                "--json",
            ]
        )
        != 0
    )
    failure = capsys.readouterr()
    assert failure.err or failure.out


def _candidate_workspace_head(candidate: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(candidate), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def test_product_graph_blocks_slicing_when_acceptance_is_missing(tmp_path: Path):
    prd = tmp_path / "thin.md"
    prd.write_text(
        "# Thin\n\n## Requirements\n- The system must save a draft.\n", encoding="utf-8"
    )
    graph = compile_product_prd(prd, tmp_path)
    assert graph["status"] == "needs_input"
    with pytest.raises(ProductMissionError, match="MISSION_BLOCKED_BY_PRODUCT_GAPS"):
        plan_value_slices(Path(graph["path"]), tmp_path)
    assert not list((tmp_path / ".factory" / "missions").glob("**/*"))


def test_value_slices_cover_every_requirement_once_and_preserve_dependencies(
    tmp_path: Path,
):
    graph, slices, _mission = _pipeline(tmp_path)
    assigned = [req for item in slices["slices"] for req in item["requirement_ids"]]
    assert sorted(assigned) == sorted(item["id"] for item in graph["requirements"])
    assert len(assigned) == len(set(assigned))
    owner = {
        req: item["id"] for item in slices["slices"] for req in item["requirement_ids"]
    }
    dash = next(
        item for item in slices["slices"] if "REQ-DASH" in item["requirement_ids"]
    )
    if owner["REQ-DASH"] != owner["REQ-LOGIN"]:
        assert owner["REQ-LOGIN"] in dash["depends_on"]
    assert all(
        set(item["score"])
        == {
            "user_value",
            "uncertainty_retired",
            "dependency_unlock",
            "security_change_risk",
            "implementation_review_cost",
            "priority",
        }
        for item in slices["slices"]
    )
    assert all(
        set(item["vertical_contract"])
        == {
            "ui",
            "behavior",
            "api_data",
            "tests",
            "observability",
            "rollback",
        }
        for item in slices["slices"]
    )
    assert [item["score"]["priority"] for item in slices["slices"]] == sorted(
        (item["score"]["priority"] for item in slices["slices"]),
        reverse=True,
    )


def test_mission_is_supervised_budgeted_and_hash_bound(tmp_path: Path):
    _graph, _slices, mission = _pipeline(tmp_path)
    assert mission["approval_state"] == "required_before_execution"
    assert mission["authority"] == {
        "execute": "human_approval",
        "merge": False,
        "publish": False,
        "deploy": False,
        "external_message": False,
    }
    assert mission["loop"]["verdict"] == "VERIFIED"
    assert mission["workspace_contract"]["mode"] == "worktree"
    assert mission["workspace_contract"]["count"] == 1
    assert mission["workspace_contract"]["branch"].startswith("codex/")
    assert set(mission["role_permissions"]) == {"builder", "checker", "ux_reviewer"}
    assert (
        mission["context_packet"]["requirement_ids"]
        == mission["slice"]["requirement_ids"]
    )
    assert verify_mission(Path(mission["path"]))["valid"] is True


def test_small_agent_packet_is_prepared_bound_and_scope_gated(tmp_path: Path):
    _graph, _slices, mission = _pipeline(tmp_path)
    packet = mission["task_packet"]
    rendered = Path(mission["context"]).read_text(encoding="utf-8")
    assert packet["schema"] == "factory.small_agent_task_packet.v1"
    assert packet["status"] == "prepared_needs_candidate_binding"
    assert [item["id"] for item in packet["requirements"]] == mission["context_packet"][
        "requirement_ids"
    ]
    assert all(item["statement"] and item["kind"] for item in packet["requirements"])
    assert all("depends_on_requirements" in item for item in packet["requirements"])
    assert (
        packet["acceptance_examples"][0]["id"]
        in mission["context_packet"]["acceptance_refs"]
    )
    assert packet["interfaces"]["relevant_files"] == {
        "status": "unknown_until_candidate_inspection",
        "paths": [],
    }
    assert packet["permitted_source_scope"]["paths"] == []
    assert packet["acceptance_commands"]["commands"] == []
    assert {item["lane"] for item in packet["audit_lanes"]} == {
        "static",
        "secrets",
        "configuration",
        "dependencies",
        "runtime",
        "fuzz",
    }
    assert all(
        item["applicability"] == "requires_candidate_declaration"
        for item in packet["audit_lanes"]
    )
    assert packet["regression_controls"]["positive"]["required"] is True
    assert packet["regression_controls"]["negative"]["required"] is True
    assert packet["execution"] == {
        "state": "preparation_only",
        "candidate_sha256": None,
        "requires_candidate_binding": True,
        "requires_human_execution_decision": True,
        "executed_audit": False,
        "release_authority": False,
    }
    assert packet["packet_sha256"] in rendered
    assert packet["requirements"][0]["statement"] in rendered
    assert packet["acceptance_examples"][0]["title"] in rendered
    assert "## Dependencies" in rendered
    assert "## Budgets" in rendered
    assert "## Audit lane applicability" in rendered
    assert "## Preparation and stop condition" in rendered
    assert "Preparation only" in rendered
    assert "Stop before edits" in rendered
    assert "does not signal readiness" in rendered


def _reseal_mission(path: Path, mission: dict) -> None:
    packet = mission.get("task_packet")
    if isinstance(packet, dict):
        packet_core = {
            key: value for key, value in packet.items() if key != "packet_sha256"
        }
        packet["packet_sha256"] = hashlib.sha256(
            json.dumps(
                packet_core, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
    mission_core = {
        key: value
        for key, value in mission.items()
        if key
        not in {"mission_sha256", "generated_at", "path", "context", "idempotent"}
    }
    mission["mission_sha256"] = hashlib.sha256(
        json.dumps(
            mission_core, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    path.write_text(json.dumps(mission, sort_keys=True), encoding="utf-8")


def test_small_agent_packet_rejects_missing_authority_and_malformed_controls(
    tmp_path: Path,
):
    _graph, _slices, mission = _pipeline(tmp_path)
    path = Path(mission["path"])
    stored = json.loads(path.read_text(encoding="utf-8"))
    del stored["task_packet"]
    _reseal_mission(path, stored)
    assert verify_mission(path)["valid"] is False

    stored = json.loads(json.dumps(mission))
    stored["task_packet"]["execution"]["candidate_sha256"] = "a" * 64
    _reseal_mission(path, stored)
    check = verify_mission(path)
    assert check["valid"] is False
    assert "execution authority invalid" in " ".join(check["errors"])

    stored = json.loads(json.dumps(mission))
    stored["task_packet"]["regression_controls"]["negative"]["required"] = False
    _reseal_mission(path, stored)
    check = verify_mission(path)
    assert check["valid"] is False
    assert "regression controls invalid" in " ".join(check["errors"])

    stored = json.loads(json.dumps(mission))
    stored["task_packet"]["requirements"][0]["statement"] = "A weakened requirement"
    _reseal_mission(path, stored)
    check = verify_mission(path)
    assert check["valid"] is False
    assert "requirement or acceptance content drift" in " ".join(check["errors"])


def test_small_agent_packet_rejects_changed_source_binding(tmp_path: Path):
    _graph, _slices, mission = _pipeline(tmp_path)
    path = Path(mission["path"])
    stored = json.loads(path.read_text(encoding="utf-8"))
    stored["task_packet"]["source_bindings"]["product_graph"]["file_sha256"] = "0" * 64
    _reseal_mission(path, stored)
    check = verify_mission(path)
    assert check["valid"] is False
    assert "product_graph binding invalid" in " ".join(check["errors"])


def test_legacy_v1_mission_remains_verifiable_without_task_packet(tmp_path: Path):
    _graph, _slices, mission = _pipeline(tmp_path)
    path = Path(mission["path"])
    legacy = json.loads(path.read_text(encoding="utf-8"))
    legacy["schema"] = "factory.mission.v1"
    legacy.pop("contract_revision")
    legacy.pop("task_packet")
    _reseal_mission(path, legacy)

    result = verify_mission(path)
    assert result["valid"] is True
    assert result["contract_version"] == "factory.mission.v1/revision-1"
    assert result["task_packet_status"] == "legacy_unavailable"


@pytest.mark.parametrize("revision", [99, True, "2", None, {}])
def test_mission_verifier_rejects_unknown_or_malformed_revision(
    tmp_path: Path, revision
):
    _graph, _slices, mission = _pipeline(tmp_path)
    path = Path(mission["path"])
    stored = json.loads(path.read_text(encoding="utf-8"))
    stored["contract_revision"] = revision
    stored.pop("task_packet")
    _reseal_mission(path, stored)

    with pytest.raises(ProductMissionError, match="SCHEMA_UNSUPPORTED"):
        verify_mission(path)


def test_mission_refuses_excess_budget_and_detects_input_drift(tmp_path: Path):
    _graph, slices, mission = _pipeline(tmp_path)
    with pytest.raises(ProductMissionError, match="MISSION_BUDGET_INVALID"):
        create_mission(
            Path(slices["path"]),
            slices["slices"][0]["id"],
            tmp_path,
            "owner",
            max_tokens=100001,
        )
    graph_path = Path(mission["inputs"]["graph_path"])
    graph_path.write_text(
        graph_path.read_text(encoding="utf-8") + "\n", encoding="utf-8"
    )
    result = verify_mission(Path(mission["path"]))
    assert result["valid"] is False
    assert result["marker"] == "MISSION_INPUT_DRIFT"


def test_pr_draft_links_local_evidence_but_has_no_promotion_authority(tmp_path: Path):
    _graph, _slices, mission = _pipeline(tmp_path)
    evidence = tmp_path / "test-results.json"
    evidence.write_text('{"passed": true}\n', encoding="utf-8")
    draft = draft_pr(Path(mission["path"]), tmp_path, [evidence])
    assert draft["evidence"][0]["sha256"]
    assert draft["before_after"]["before"] != draft["before_after"]["after"]
    assert draft["requirement_coverage"]["added"] == draft["requirements"]
    assert draft["architecture_changes"] and draft["data_contract_changes"]
    assert draft["budget_consumption"]["measured"] is None
    assert set(draft["review_evidence"]) == {
        "screenshots",
        "responsive",
        "accessibility",
        "tests",
        "mutations",
        "gates",
        "traces",
    }
    assert draft["outcome_events"] == ["signal_review_completed within five minutes."]
    assert all(
        value is False
        for key, value in draft["authority"].items()
        if key != "draft_only"
    )
    assert draft["authority"]["draft_only"] is True
    outside = tmp_path.parent / "outside-evidence.txt"
    outside.write_text("outside", encoding="utf-8")
    try:
        with pytest.raises(ProductMissionError, match="EVIDENCE_OUTSIDE_ROOT"):
            draft_pr(Path(mission["path"]), tmp_path, [outside], force=True)
    finally:
        outside.unlink(missing_ok=True)


def test_outcomes_preserve_evidence_class_and_hash_chain(tmp_path: Path):
    _graph, _slices, mission = _pipeline(tmp_path)
    with pytest.raises(ProductMissionError, match="MEASURED_SOURCE_REQUIRED"):
        record_outcome(
            Path(mission["path"]), tmp_path, "completion_rate", 0.8, 0.7, "measured"
        )
    first = record_outcome(
        Path(mission["path"]),
        tmp_path,
        "completion_rate",
        0.8,
        0.7,
        "measured",
        "analytics/run-42",
    )
    second = record_outcome(
        Path(mission["path"]),
        tmp_path,
        "qualitative_fit",
        None,
        None,
        "observed",
        "research/session-7",
    )
    assert second["previous_sha256"] == first["record_sha256"]
    summary = outcome_summary(tmp_path, mission["id"])
    assert summary["chain_valid"] is True
    assert summary["evidence_classes"]["measured"] == 1
    log = Path(first["path"])
    rows = log.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(rows[0])
    tampered["value"] = 0.1
    rows[0] = json.dumps(tampered, sort_keys=True)
    log.write_text("\n".join(rows) + "\n", encoding="utf-8")
    assert outcome_summary(tmp_path, mission["id"])["chain_valid"] is False


def test_requirement_change_invalidates_existing_mission(tmp_path: Path):
    graph, _slices, mission = _pipeline(tmp_path)
    prd = tmp_path / "PRD.md"
    prd.write_text(
        PRD.replace("prioritized signals", "ranked customer signals"), encoding="utf-8"
    )
    changed = compile_product_prd(prd, tmp_path, force=True)
    assert changed["graph_sha256"] != graph["graph_sha256"]
    assert verify_mission(Path(mission["path"]))["valid"] is False


def test_requirement_change_invalidates_stale_slice_plan_before_new_mission(
    tmp_path: Path,
):
    graph, slices, _mission = _pipeline(tmp_path)
    prd = tmp_path / "PRD.md"
    prd.write_text(PRD.replace("REQ-EXPORT:", "REQ-ARCHIVE:"), encoding="utf-8")
    changed = compile_product_prd(prd, tmp_path, force=True)
    assert changed["graph_sha256"] != graph["graph_sha256"]
    with pytest.raises(ProductMissionError, match="MISSION_INPUT_DRIFT"):
        create_mission(
            Path(slices["path"]), slices["slices"][0]["id"], tmp_path, "owner"
        )


def test_meter_v2_preserves_unknowns_and_computes_complete_flow(tmp_path: Path):
    MeterLog(tmp_path).record(
        StageTiming(
            "factoryline",
            "compile-product",
            100,
            1,
            600,
            400,
            True,
            mission_id="mission-1",
            queue_ms=50,
            human_review_ms=25,
            rework_lines=3,
            cache_hits=2,
            invalidated_stages=1,
            outcome_status="achieved",
            usage_quality="exact",
            agent_ms=60,
            deterministic_tool_ms=40,
            changed_lines=30,
            replay_hits=1,
            model_calls_avoided=2,
            first_pass=True,
            retry_count=0,
            requirements_accepted=2,
            cost_usd=0.02,
            cost_quality="exact",
            escaped_defects=0,
            releases=1,
            rollbacks=0,
        )
    )
    snapshot = live_snapshot(tmp_path)
    flow = snapshot["summary"]["flow"]
    assert snapshot["schema"] == "factory.meter.live.v2"
    assert flow["flow_efficiency"] == 0.5714
    assert flow["queue_ms"] == {"value": 50, "known": 1, "unknown": 0}
    assert flow["agent_ms"]["value"] == 60
    assert flow["deterministic_tool_ms"]["value"] == 40
    assert flow["rework_ratio"] == 0.1
    assert flow["first_pass_gate_rate"]["value"] == 1.0
    assert flow["requirements_per_token"] == 0.002
    assert flow["requirements_per_engineering_hour"] == 57600.0
    assert flow["rollback_rate"] == 0.0
    assert flow["token_quality"] == {"exact": 1, "estimated": 0, "unknown": 0}
    assert flow["cost_quality"] == {"exact": 1, "estimated": 0, "unknown": 0}
    legacy = tmp_path / "legacy"
    MeterLog(legacy).record(StageTiming("factoryline", "legacy", 10, 0, 0, 0, True))
    assert live_snapshot(legacy)["summary"]["flow"]["queue_ms"]["value"] is None


def test_product_mission_cli_runs_the_local_compile_chain(tmp_path: Path, capsys):
    prd = tmp_path / "PRD.md"
    prd.write_text(PRD, encoding="utf-8")
    assert (
        main(["product", "compile", str(prd), "--root", str(tmp_path), "--json"]) == 0
    )
    graph = json.loads(capsys.readouterr().out)
    assert main(["product", "verify", graph["path"], "--json"]) == 0
    capsys.readouterr()
    assert (
        main(["product", "slices", graph["path"], "--root", str(tmp_path), "--json"])
        == 0
    )
    slices = json.loads(capsys.readouterr().out)
    assert (
        main(
            [
                "mission",
                "create",
                slices["path"],
                slices["slices"][0]["id"],
                "--root",
                str(tmp_path),
                "--owner",
                "cli-owner",
                "--executor",
                "codex",
                "--json",
            ]
        )
        == 0
    )
    mission = json.loads(capsys.readouterr().out)
    assert main(["mission", "verify", mission["path"], "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
