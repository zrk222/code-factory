from __future__ import annotations

from pathlib import Path
import hashlib
import json
import subprocess
import sys

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
import factoryline.product_missions as product_missions
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


def test_candidate_git_uses_bounded_runner_and_returns_clean_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    calls = []

    def run_cli_detailed(cli, args, cwd, **kwargs):
        calls.append((cli, args, cwd, kwargs))
        return {
            "ok": True,
            "cleanup_confirmed": True,
            "streams_closed": True,
            "stdout": b"  abc123\n",
        }

    monkeypatch.setattr(product_missions, "run_cli_detailed", run_cli_detailed)
    assert product_missions._candidate_git(tmp_path, ["rev-parse", "HEAD"]) == "abc123"
    cli, args, cwd, kwargs = calls[0]
    assert cli == "git"
    assert args[:4] == ["--no-optional-locks", "-c", "core.fsmonitor=false", "-C"]
    assert cwd == tmp_path
    assert kwargs == {"timeout": 10, "max_stream_bytes": 1_000_000}


@pytest.mark.parametrize(
    "result",
    [
        {
            "ok": True,
            "cleanup_confirmed": False,
            "streams_closed": True,
            "stdout": b"x",
        },
        {
            "ok": False,
            "cleanup_confirmed": True,
            "streams_closed": True,
            "stdout": b"x",
            "reason": "stage timed out",
        },
        {
            "ok": False,
            "cleanup_confirmed": True,
            "streams_closed": True,
            "stdout": b"x",
            "reason": "output limit exceeded",
        },
        {
            "ok": True,
            "cleanup_confirmed": True,
            "streams_closed": False,
            "stdout": b"x",
        },
    ],
)
def test_candidate_git_rejects_unverified_process_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, result: dict
):
    monkeypatch.setattr(
        product_missions, "run_cli_detailed", lambda *args, **kwargs: result
    )
    with pytest.raises(ProductMissionError, match="MISSION_CANDIDATE_INVALID"):
        product_missions._candidate_git(tmp_path, ["rev-parse", "HEAD"])


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


def _daily_verification_for(
    mission, root, *, timeout=False, omit_candidate_artifact=False
):
    from factoryline.e2e_proof import public_e2e_proof_receipt, verify_e2e_proof

    source = root / "candidate.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    manifest_path = root / "e2e-manifest.json"
    candidate_artifacts = [] if omit_candidate_artifact else ["candidate.py"]
    positive_argv = (
        [sys.executable, "-c", "import time; time.sleep(2)"]
        if timeout
        else [sys.executable, "-c", "pass"]
    )
    manifest_path.write_text(
        json.dumps(
            {
                "schema": "factory.e2e_proof_manifest.v1",
                "id": "mission-verification",
                "approval": {"state": "approved", "approved_by": "test-owner"},
                "working_directory": ".",
                "timeout_seconds": 1 if timeout else 10,
                "network_egress": "not_granted",
                "positive": {"argv": positive_argv},
                "negative": {"argv": [sys.executable, "-c", "raise SystemExit(1)"]},
                "artifact_paths": candidate_artifacts,
            }
        ),
        encoding="utf-8",
    )
    receipt = verify_e2e_proof(root, manifest_path)
    receipt_path = root / "e2e-receipt.json"
    receipt_path.write_text(
        json.dumps(public_e2e_proof_receipt(receipt)), encoding="utf-8"
    )
    source_rows = [
        {
            "path": "candidate.py",
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        }
    ]
    candidate_sha = product_missions._sha_bytes(
        product_missions._canonical(source_rows)
    )
    evidence = {
        "kind": "e2e_command_pair",
        "path": str(receipt_path),
        "sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
    }
    criteria = []
    for criterion_index, criterion in enumerate(
        mission["completion_contract"]["criteria"]
    ):
        cases = []
        for polarity, outcome in (
            ("positive", "exit_zero"),
            ("negative", "exit_nonzero"),
        ):
            cases.append(
                {
                    "case_id": f"case-{criterion_index}-{polarity}",
                    "polarity": polarity,
                    "input_paths": ["candidate.py"],
                    "input_sha256": product_missions._sha_bytes(
                        product_missions._canonical(source_rows)
                    ),
                    "expected_outcome": outcome,
                    "observed_outcome": "unknown"
                    if timeout and polarity == "positive"
                    else outcome,
                    "evidence": {**evidence, "result": polarity},
                }
            )
        criteria.append({"criterion_id": criterion["id"], "cases": cases})
    return {
        "schema": product_missions.DAILY_VERIFICATION_SCHEMA,
        "candidate_sha256": candidate_sha,
        "source_manifest": source_rows,
        "scope_closure": "declared_only",
        "criteria": criteria,
    }


def _daily_oracle_verification_for(mission, root):
    import runpy

    sources = {
        "candidate.py": b"VALUE = 1\n",
        "tests/test_feature.py": b"def test_feature():\n    assert True\n",
    }
    for relative, content in sources.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    rows = [
        {"path": path, "sha256": hashlib.sha256(content).hexdigest()}
        for path, content in sorted(sources.items())
    ]
    receipt_path, trust_path = root / "oracle.json", root / "trust.json"
    test_sha = next(row["sha256"] for row in rows if row["path"].startswith("tests/"))
    source_sha = next(row["sha256"] for row in rows if row["path"] == "candidate.py")
    case_ids = [
        f"tests/test_feature.py::test_feature[{criterion['id']}-{polarity}]"
        for criterion in mission["completion_contract"]["criteria"]
        for polarity in ("positive", "negative")
    ]
    config = {
        "status": "PASS",
        "phase": "collection",
        "complete": True,
        "scope": "test_function",
        "source_path": "tests/test_feature.py",
        "source_sha256": test_sha,
        "config_manifest": [],
        "config_identity": "pytest-default",
        "case_ids": case_ids,
    }
    assertions = [
        {
            "case_id": case_id,
            "outcome": "PASS",
            "failure_visible": False,
        }
        for case_id in case_ids
    ]
    mutation_assertions = [
        {**row, "outcome": "FAIL", "failure_visible": True} for row in assertions
    ]
    oracle_row = {
        "path": "tests/test_feature.py",
        "line": 1,
        "symbol": "test_feature",
        "test_sha256": test_sha,
        "baseline": {
            "status": "PASS",
            "phase": "call",
            "setup_status": "PASS",
            "teardown_status": "PASS",
            "case_ids": case_ids,
            "collection_catalog": config,
            "assertion_observations": assertions,
        },
        "mutation": {
            "source_path": "candidate.py",
            "source_sha256": source_sha,
            "mutant_sha256": "a" * 64,
            "status": "FAIL",
            "phase": "call",
            "setup_status": "PASS",
            "teardown_status": "PASS",
            "failure_kind": "assertion",
            "case_ids": case_ids,
            "collection_catalog": config,
            "assertion_observations": mutation_assertions,
        },
    }
    # Use the same real v3 payload/signing helpers as runtime-attestation tests;
    # this exercises product-mission verification without mocking the verifier.
    runtime_fixtures = runpy.run_path(
        str(Path(__file__).with_name("test_runtime_attestation.py"))
    )
    payload = runtime_fixtures["_oracle_payload_v3"]()
    payload["source_manifest_sha256"] = product_missions._sha_bytes(
        product_missions._canonical(rows)
    )
    payload["environment_sha256"] = "b" * 64
    signed_test = payload["tests"][0]
    signed_test["path"] = "tests/test_feature.py"
    signed_test["line"] = 1
    signed_test["symbol"] = "test_feature"
    signed_test["test_sha256"] = test_sha
    signed_test["baseline"]["collection_catalog"].update(
        {
            "source_path": "tests/test_feature.py",
            "source_sha256": test_sha,
            "case_ids": list(case_ids),
        }
    )
    signed_test["mutation"].update(
        {"source_path": "candidate.py", "source_sha256": source_sha}
    )
    signed_test["baseline"]["case_ids"] = list(case_ids)
    signed_test["mutation"]["case_ids"] = list(case_ids)
    for run_name in ("baseline", "mutation"):
        run = signed_test[run_name]
        observation = run["assertion_observations"][0]
        run["assertion_observations"] = [
            {
                **observation,
                "case_id": case_id,
                "source_path": "tests/test_feature.py",
                "source_sha256": test_sha,
            }
            for case_id in case_ids
        ]
        run["module_origins"] = [
            {
                **origin,
                "case_id": case_id,
                "source_path": "tests/test_feature.py"
                if origin["source_path"] == "tests/test_example.py"
                else "candidate.py",
                "source_sha256": test_sha
                if origin["source_path"] == "tests/test_example.py"
                else source_sha
                if run_name == "baseline"
                else signed_test["mutation"]["mutant_sha256"],
            }
            for origin in run["module_origins"]
            for case_id in case_ids
        ]
        catalog = run["collection_catalog"]
        catalog.update(
            {
                "source_path": "tests/test_feature.py",
                "source_sha256": test_sha,
                "case_ids": list(case_ids),
            }
        )
    receipt, trust, _, _ = runtime_fixtures["_signed_oracle"](root, payload)
    receipt_path.write_bytes(receipt.read_bytes())
    trust_path.write_bytes(trust.read_bytes())
    criteria = []
    for criterion_index, criterion in enumerate(
        mission["completion_contract"]["criteria"]
    ):
        cases = []
        for polarity in ("positive", "negative"):
            oracle_case_id = (
                f"tests/test_feature.py::test_feature[{criterion['id']}-{polarity}]"
            )
            evidence = {
                "kind": "signed_test_oracle_v3",
                "path": "oracle.json",
                "sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
                "trust_root_path": "trust.json",
                "trust_root_sha256": hashlib.sha256(
                    trust_path.read_bytes()
                ).hexdigest(),
                "environment_sha256": "b" * 64,
                "test_path": "tests/test_feature.py",
                "test_line": 1,
                "test_symbol": "test_feature",
                "oracle_case_id": oracle_case_id,
            }
            input_rows = [
                row
                for row in rows
                if row["path"] in {"candidate.py", "tests/test_feature.py"}
            ]
            cases.append(
                {
                    "case_id": f"case-{criterion_index}-{polarity}",
                    "polarity": polarity,
                    "input_paths": [row["path"] for row in input_rows],
                    "input_sha256": product_missions._sha_bytes(
                        product_missions._canonical(input_rows)
                    ),
                    "expected_outcome": "baseline_assertion_pass_mutant_assertion_fail",
                    "observed_outcome": "baseline_assertion_pass_mutant_assertion_fail",
                    "evidence": evidence,
                }
            )
        criteria.append({"criterion_id": criterion["id"], "cases": cases})
    source_sha = product_missions._sha_bytes(product_missions._canonical(rows))
    return (
        {
            "schema": product_missions.DAILY_VERIFICATION_SCHEMA,
            "candidate_sha256": source_sha,
            "source_manifest": rows,
            "scope_closure": "declared_only",
            "criteria": criteria,
        },
        oracle_row,
        source_sha,
    )


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
    legacy_check = verify_mission_completion(Path(completion["path"]))
    assert legacy_check["valid"] is True
    assert legacy_check["complete"] is False
    assert legacy_check["status"] == "legacy_claimed"
    assert legacy_check["marker"] == "MISSION_COMPLETION_INCOMPLETE"
    evidence.write_text('{"passed": false}\n')
    check = verify_mission_completion(Path(completion["path"]))
    assert check["valid"] is False
    assert check["marker"] == "MISSION_COMPLETION_DRIFT"


def test_mission_completion_graph_projection_separates_integrity_and_completion():
    incomplete = product_missions.mission_completion_graph_projection(
        {
            "valid": False,
            "integrity_valid": True,
            "complete": False,
            "errors": ["completion remains incomplete"],
        }
    )
    assert incomplete == {
        "status": "incomplete",
        "integrity_valid": True,
        "complete": False,
        "errors": ["completion remains incomplete"],
    }
    complete = product_missions.mission_completion_graph_projection(
        {"valid": True, "integrity_valid": True, "complete": True, "errors": []}
    )
    assert complete["status"] == "verified"
    assert complete["complete"] is True
    assert (
        product_missions.mission_completion_graph_projection(None)["status"]
        == "invalid"
    )


def test_capture_mission_local_mutation_rejects_outside_mission_before_execution(
    tmp_path: Path,
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside_mission = tmp_path / "outside-mission.json"
    outside_mission.write_text("{}", encoding="utf-8")

    with pytest.raises(ProductMissionError, match="outside the workspace"):
        product_missions.capture_mission_local_mutation(
            outside_mission,
            workspace / "daily-contract.json",
            workspace,
            "criterion",
            "target",
            "control",
            "test_target",
            1,
            "test_control",
            1,
            "src/app.py",
            "run",
            "before",
            "after",
            "evidence",
        )


def test_daily_verification_binds_case_facts_but_keeps_behavior_incomplete(tmp_path):
    _graph, _slices, mission = _pipeline(tmp_path)
    evidence = tmp_path / "test-results.json"
    evidence.write_text('{"passed": true}\n', encoding="utf-8")
    validation = _validation_for(mission, "worker", "verifier", evidence)
    validation["daily_verification"] = _daily_verification_for(mission, tmp_path)
    path = tmp_path / "daily-validation.json"
    path.write_text(json.dumps(validation), encoding="utf-8")

    completion = close_mission(Path(mission["path"]), path, tmp_path)
    assert completion["status"] == "incomplete"
    assert completion["daily_verification"]["status"] == "INCOMPLETE"
    assert completion["daily_verification"]["execution_verified"] is False
    assert completion["daily_verification"]["command_pair_receipts_verified"] is True
    assert completion["daily_verification"]["scope_closure"] == (
        "declared_verified_scope"
    )
    assert completion["daily_verification"]["scope_limitations"]
    assert "behavioral_assertion_unverified" in completion["daily_verification"]["gaps"]
    case = completion["daily_verification"]["criteria"][0]["cases"][0]
    assert case["disposition"] == "command_pair_observed"
    assert case["observed_outcome"] == "exit_zero"
    check = verify_mission_completion(Path(completion["path"]))
    assert check["valid"] is False
    assert check["integrity_valid"] is True
    assert check["complete"] is False
    assert check["marker"] == "MISSION_COMPLETION_INCOMPLETE"
    from factoryline.mission_graph import MissionGraphError, _completion_receipt

    with pytest.raises(MissionGraphError, match="completion remains incomplete"):
        _completion_receipt(
            Path(completion["path"]), completion, mission, "verifier", "worker"
        )


def test_operator_local_mutation_capture_runs_bound_target_and_control(
    tmp_path, capsys
):
    from factoryline.pytest_readiness import (
        _challenge_source_inventory,
        main as probe_main,
    )

    _graph, _slices, mission = _pipeline(tmp_path)
    production = tmp_path / "app.py"
    test_file = tmp_path / "test_app.py"
    production.write_text("def value():\n    return 1\n", encoding="utf-8")
    test_lines = ["import app", ""]
    selectors = []
    for index, criterion in enumerate(mission["completion_contract"]["criteria"]):
        target_name, control_name = f"test_target_{index}", f"test_control_{index}"
        target_line = len(test_lines) + 2
        test_lines.extend([f"def {target_name}():", "    assert app.value() == 1", ""])
        control_line = len(test_lines) + 2
        test_lines.extend([f"def {control_name}():", "    assert app.value() >= 0", ""])
        selectors.append(
            (criterion["id"], target_name, target_line, control_name, control_line)
        )
    test_file.write_text("\n".join(test_lines), encoding="utf-8")
    original_sources = {
        path: (tmp_path / path).read_bytes() for path in ("app.py", "test_app.py")
    }
    source_map = _challenge_source_inventory(tmp_path)
    rows = [
        {"path": path, "sha256": digest} for path, digest in sorted(source_map.items())
    ]
    candidate_sha = product_missions._sha_bytes(product_missions._canonical(rows))
    case_paths = ["app.py", "test_app.py"]
    case_rows = [{"path": path, "sha256": source_map[path]} for path in case_paths]
    case_sha = product_missions._sha_bytes(product_missions._canonical(case_rows))
    criteria = []
    for criterion_index, criterion in enumerate(
        mission["completion_contract"]["criteria"]
    ):
        cases = []
        for polarity, outcome in (
            ("positive", "baseline_assertion_pass_mutant_assertion_fail"),
            ("negative", "baseline_assertion_pass_mutant_assertion_pass"),
        ):
            cases.append(
                {
                    "case_id": f"case-{criterion_index}-{polarity}",
                    "polarity": polarity,
                    "input_paths": case_paths,
                    "input_sha256": case_sha,
                    "expected_outcome": outcome,
                    "observed_outcome": "unknown",
                    "evidence": {},
                }
            )
        criteria.append({"criterion_id": criterion["id"], "cases": cases})
    contract_path = tmp_path / "daily-contract.json"
    contract_path.write_text(
        json.dumps(
            {
                "schema": product_missions.DAILY_VERIFICATION_SCHEMA,
                "candidate_sha256": candidate_sha,
                "source_manifest": rows,
                "scope_closure": "declared_only",
                "criteria": criteria,
            }
        ),
        encoding="utf-8",
    )
    captures = []
    for index, (
        criterion_id,
        target_name,
        target_line,
        control_name,
        control_line,
    ) in enumerate(selectors[:1]):
        target_case, control_case = f"case-{index}-positive", f"case-{index}-negative"
        rc = probe_main(
            [
                "--root",
                str(tmp_path),
                "--kind",
                "production-mutation",
                "--nodeid",
                f"test_app.py::{target_name}",
                "--line",
                str(target_line),
                "--production-path",
                "app.py",
                "--production-symbol",
                "value",
                "--mutation-before",
                "return 1",
                "--mutation-after",
                "return 0",
                "--evidence",
                f".factory/local-capture/case-{index}",
                "--mission-path",
                mission["path"],
                "--daily-contract",
                str(contract_path),
                "--criterion-id",
                criterion_id,
                "--target-case-id",
                target_case,
                "--control-nodeid",
                f"test_app.py::{control_name}",
                "--control-line",
                str(control_line),
                "--control-case-id",
                control_case,
                "--timeout",
                "20",
                "--python",
                sys.executable,
            ]
        )
        capture = json.loads(capsys.readouterr().out)
        assert rc == 0, capture
        assert capture["status"] == "OBSERVED"
        assert capture["local_execution_observed"] is True
        assert capture["authority"] == "none"
        assert capture["execution_budget"]["maximum_child_processes"] == 4
        captures.append(capture)
    assert {
        path: (tmp_path / path).read_bytes() for path in original_sources
    } == original_sources
    updated_contract = json.loads(contract_path.read_text(encoding="utf-8"))
    selected_cases = {
        case["case_id"]: case
        for criterion in updated_contract["criteria"]
        for case in criterion["cases"]
    }
    assert selected_cases["case-0-positive"]["observed_outcome"] == (
        "baseline_assertion_pass_mutant_assertion_fail"
    )
    assert selected_cases["case-0-negative"]["observed_outcome"] == (
        "baseline_assertion_pass_mutant_assertion_pass"
    )

    evidence = tmp_path / "validation-evidence.json"
    evidence.write_text('{"passed": true}\n', encoding="utf-8")
    validation = _validation_for(mission, "worker", "verifier", evidence)
    validation["daily_verification"] = updated_contract
    validation_path = tmp_path / "validation-with-capture.json"
    validation_path.write_text(json.dumps(validation), encoding="utf-8")
    completion = close_mission(Path(mission["path"]), validation_path, tmp_path)
    selected_rows = {
        case["case_id"]: case
        for criterion in completion["daily_verification"]["criteria"]
        for case in criterion["cases"]
    }
    assert selected_rows["case-0-positive"]["disposition"] == (
        "local_mutation_target_observed"
    )
    assert selected_rows["case-0-negative"]["disposition"] == (
        "local_mutation_control_observed"
    )
    assert completion["daily_verification"]["execution_verified"] is False
    assert completion["daily_verification"]["status"] == "INCOMPLETE"
    assert completion["daily_verification"]["local_execution_observed"] is False
    unsupported_gates = {
        "native_gate_unsupported:" + criterion["id"]
        for criterion in mission["completion_contract"]["criteria"]
        if criterion.get("verification_kind") == "deterministic_tool"
        and criterion["id"].partition(":")[2]
        not in {"unit", "requirement-mutation", "receipt-trace"}
    }
    assert unsupported_gates <= set(completion["daily_verification"]["gaps"])
    verified = verify_mission_completion(Path(completion["path"]))
    assert verified["valid"] is False
    assert verified["integrity_valid"] is True
    assert verified["complete"] is False
    assert verified["marker"] == "MISSION_COMPLETION_INCOMPLETE"
    target_capture = (
        tmp_path / ".factory" / "local-capture" / "case-0" / "target" / "capture.json"
    )
    target_capture.write_bytes(target_capture.read_bytes() + b" ")
    tampered = verify_mission_completion(Path(completion["path"]))
    assert tampered["integrity_valid"] is False
    assert tampered["marker"] == "MISSION_COMPLETION_DRIFT"


def test_operator_local_mutation_capture_verifies_typed_native_gates(tmp_path, capsys):
    from factoryline.pytest_readiness import (
        _challenge_source_inventory,
        main as probe_main,
    )

    prd = tmp_path / "PRD.md"
    prd.write_text(
        "# Record Service\n\n"
        "## Actors\n- Record service: serializes signal records.\n\n"
        "## Outcomes\n- Produce a stable signal record.\n\n"
        "## Jobs and pains\n- Job: serialize a signal record.\n\n"
        "## Journeys and business rules\n"
        "- Journey: serialize a record with identity, state, and trace.\n"
        "- Business rule: record identity and trace remain stable.\n\n"
        "## Data ownership and trust boundaries\n"
        "- Data ownership: the service owns the serialized record.\n"
        "- Trust boundary: record input remains within the service.\n\n"
        "## External effects and approvals\n"
        "- External effect: none.\n- Approval: none.\n\n"
        "## Success events\n- record_serialized.\n\n"
        "## Requirements\n"
        "- REQ-RECORD: The service shall return a record with a stable identity.\n\n"
        "## Acceptance\nScenario: Serialize a stable record\n"
        "  Given a signal record\n  When the service serializes it\n"
        "  Then identity, state, and trace are present\n",
        encoding="utf-8",
    )
    graph = compile_product_prd(prd, tmp_path, project="record-service")
    slices = product_missions.plan_value_slices(Path(graph["path"]), tmp_path, 1)
    mission = create_mission(
        Path(slices["path"]), slices["slices"][0]["id"], tmp_path, "release-owner"
    )
    production = tmp_path / "app.py"
    test_file = tmp_path / "test_app.py"
    production.write_text(
        'def value():\n    return {"record_id": "signal-17", "state": "ready", "trace": "trace-1"}\n\n'
        "def healthy_control():\n    return True\n",
        encoding="utf-8",
    )
    assertions = {
        "requirement:REQ-RECORD": 'assert app.value()["record_id"] == "signal-17"',
        "acceptance:AC-001": (
            'assert app.value() == {"record_id": "signal-17", '
            '"state": "ready", "trace": "trace-1"}'
        ),
        "gate:unit": (
            "assert isinstance(app.value(), dict) and "
            'set(app.value()) == {"record_id", "state", "trace"} and '
            'app.value()["record_id"] == "signal-17"'
        ),
        "gate:requirement-mutation": 'assert app.value()["state"] == "ready"',
        "gate:receipt-trace": 'assert app.value()["trace"] == "trace-1"',
    }
    criterion_ids = [item["id"] for item in mission["completion_contract"]["criteria"]]
    assert set(criterion_ids) == set(assertions)
    test_lines = ["import app", ""]
    selectors = []
    for index, criterion in enumerate(mission["completion_contract"]["criteria"]):
        target_name, control_name = f"test_target_{index}", f"test_control_{index}"
        target_line = len(test_lines) + 2
        test_lines.extend(
            [f"def {target_name}():", f"    {assertions[criterion['id']]}", ""]
        )
        control_line = len(test_lines) + 2
        test_lines.extend(
            [f"def {control_name}():", "    assert app.healthy_control() is True", ""]
        )
        selectors.append(
            (criterion["id"], target_name, target_line, control_name, control_line)
        )
    test_file.write_text("\n".join(test_lines), encoding="utf-8")
    source_map = _challenge_source_inventory(tmp_path)
    rows = [
        {"path": path, "sha256": digest} for path, digest in sorted(source_map.items())
    ]
    candidate_sha = product_missions._sha_bytes(product_missions._canonical(rows))
    input_paths = ["app.py", "test_app.py"]
    input_rows = [{"path": path, "sha256": source_map[path]} for path in input_paths]
    input_sha = product_missions._sha_bytes(product_missions._canonical(input_rows))
    contract = _local_mutation_daily_contract(
        mission, rows, candidate_sha, input_paths, input_sha
    )
    contract_path = tmp_path / "daily-contract.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")

    for index, (
        criterion_id,
        target_name,
        target_line,
        control_name,
        control_line,
    ) in enumerate(selectors):
        target_case, control_case = (
            f"{criterion_id}:positive",
            f"{criterion_id}:negative",
        )
        rc = probe_main(
            [
                "--root",
                str(tmp_path),
                "--kind",
                "production-mutation",
                "--nodeid",
                f"test_app.py::{target_name}",
                "--line",
                str(target_line),
                "--production-path",
                "app.py",
                "--production-symbol",
                "value",
                "--mutation-before",
                'return {"record_id": "signal-17", "state": "ready", "trace": "trace-1"}',
                "--mutation-after",
                'return {"record_id": "signal-0", "state": "broken", "trace": "trace-0"}',
                "--evidence",
                f".factory/local-capture/case-{index}",
                "--mission-path",
                mission["path"],
                "--daily-contract",
                str(contract_path),
                "--criterion-id",
                criterion_id,
                "--target-case-id",
                target_case,
                "--control-nodeid",
                f"test_app.py::{control_name}",
                "--control-line",
                str(control_line),
                "--control-case-id",
                control_case,
                "--timeout",
                "20",
                "--python",
                sys.executable,
            ]
        )
        capture = json.loads(capsys.readouterr().out)
        assert rc == 0, capture
        assert capture["status"] == "OBSERVED"

    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    validation_evidence = tmp_path / "validation-evidence.json"
    validation_evidence.write_text('{"passed": true}\n', encoding="utf-8")
    validation = _validation_for(mission, "worker", "verifier", validation_evidence)
    daily_criteria = {item["criterion_id"]: item for item in contract["criteria"]}
    for item in validation["criteria"]:
        positive = next(
            case
            for case in daily_criteria[item["id"]]["cases"]
            if case["polarity"] == "positive"
        )
        receipt_path = tmp_path / positive["evidence"]["path"]
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        assert receipt["criterion_id"] == item["id"]
        assert receipt["captures_same_candidate_and_mutation"] is True
        item["evidence"] = [str(receipt_path)]
    validation["daily_verification"] = contract
    validation_path = tmp_path / "validation-with-capture.json"
    validation_path.write_text(json.dumps(validation), encoding="utf-8")
    completion = close_mission(Path(mission["path"]), validation_path, tmp_path)
    check = verify_mission_completion(Path(completion["path"]))
    assert len(selectors) == len(assertions) == 5
    assert completion["daily_verification"]["status"] == "COMPLETE"
    assert completion["daily_verification"]["local_execution_observed"] is True
    assert completion["daily_verification"]["execution_verified"] is False
    assert check["valid"] is True
    assert check["integrity_valid"] is True
    assert check["complete"] is True
    assert check["marker"] == "MISSION_COMPLETION_VERIFIED"
    gates = {
        row["criterion_id"]: row["native_gate_observation"]
        for row in completion["daily_verification"]["criteria"]
        if "native_gate_observation" in row
    }
    assert set(gates) == {
        "gate:unit",
        "gate:requirement-mutation",
        "gate:receipt-trace",
    }
    assert all(
        row["schema"] == "factory.daily-native-gate-observation.v1"
        and row["status"] == "OBSERVED"
        and row["mission_sha256"] == mission["mission_sha256"]
        and row["candidate_sha256"] == candidate_sha
        for row in gates.values()
    )
    from factoryline.adoption import completion_card_from_receipt

    local_card = completion_card_from_receipt(
        tmp_path, Path(completion["path"]), Path("completion-details")
    )["card"]
    assert local_card["status"] == "COMPLETE"
    assert local_card["integrity_valid"] is True
    assert local_card["local_execution_observed"] is True
    assert local_card["independent_execution_verified"] is False
    assert local_card["authority"]["share"] is False
    assert any(
        "writable-host assumption" in limitation
        for limitation in local_card["unexamined_scope"]
    )
    assert not any(
        "signer-claimed" in limitation for limitation in local_card["unexamined_scope"]
    )
    receipt_refs = gates["gate:unit"]["evidence"]
    target_receipt_path = Path(
        next(row["path"] for row in receipt_refs if row["role"] == "mission_case")
    )
    target_receipt = json.loads(target_receipt_path.read_text(encoding="utf-8"))
    snapshot_path = Path(
        next(
            row["path"]
            for row in receipt_refs
            if row["role"] == "daily_contract_snapshot"
        )
    )
    pristine_snapshot = snapshot_path.read_bytes()
    pristine_sha = hashlib.sha256(pristine_snapshot).hexdigest()
    assert pristine_sha == target_receipt["daily_contract_sha256_before_capture"]
    snapshot_path.write_bytes(snapshot_path.read_bytes() + b" ")
    tampered = verify_mission_completion(Path(completion["path"]))
    assert tampered["integrity_valid"] is False
    assert tampered["complete"] is False
    assert tampered["marker"] == "MISSION_COMPLETION_DRIFT"
    assert (
        hashlib.sha256(pristine_snapshot).hexdigest()
        == (target_receipt["daily_contract_sha256_before_capture"])
    )
    snapshot_path.write_bytes(pristine_snapshot)
    restored = verify_mission_completion(Path(completion["path"]))
    assert restored["integrity_valid"] is True
    assert restored["complete"] is True
    assert restored["marker"] == "MISSION_COMPLETION_VERIFIED"


def _local_mutation_daily_contract(
    mission, rows, candidate_sha, input_paths, input_sha
):
    criteria = []
    for criterion in mission["completion_contract"]["criteria"]:
        cases = []
        for polarity, outcome in (
            ("positive", "baseline_assertion_pass_mutant_assertion_fail"),
            ("negative", "baseline_assertion_pass_mutant_assertion_pass"),
        ):
            cases.append(
                {
                    "case_id": f"{criterion['id']}:{polarity}",
                    "polarity": polarity,
                    "input_paths": input_paths,
                    "input_sha256": input_sha,
                    "expected_outcome": outcome,
                    "observed_outcome": "unknown",
                    "evidence": {},
                }
            )
        criteria.append({"criterion_id": criterion["id"], "cases": cases})
    return {
        "schema": product_missions.DAILY_VERIFICATION_SCHEMA,
        "candidate_sha256": candidate_sha,
        "source_manifest": rows,
        "scope_closure": "declared_only",
        "criteria": criteria,
    }


def test_daily_verification_malformed_case_and_missing_negative_stay_incomplete(
    tmp_path,
):
    _graph, _slices, mission = _pipeline(tmp_path)
    evidence = tmp_path / "test-results.json"
    evidence.write_text('{"passed": true}\n', encoding="utf-8")
    validation = _validation_for(mission, "worker", "verifier", evidence)
    daily = _daily_verification_for(mission, tmp_path)
    cases = daily["criteria"][0]["cases"]
    cases.pop()
    cases[0]["input_sha256"] = "bad-digest"
    cases[0]["evidence"]["kind"] = "proof_reuse"
    validation["daily_verification"] = daily
    path = tmp_path / "daily-validation.json"
    path.write_text(json.dumps(validation), encoding="utf-8")

    completion = close_mission(Path(mission["path"]), path, tmp_path)
    summary = completion["daily_verification"]
    assert summary["status"] == "INCOMPLETE"
    assert "required_positive_negative_cases_missing" in summary["gaps"]
    assert "case_input_digest_mismatch" in summary["gaps"]
    assert "execution_evidence_unsupported" in summary["gaps"]
    assert completion["status"] == "incomplete"


def test_daily_verification_keeps_signed_v3_claims_separate_from_execution(tmp_path):
    _graph, _slices, mission = _pipeline(tmp_path)
    evidence = tmp_path / "test-results.json"
    evidence.write_text('{"passed": true}\n', encoding="utf-8")
    validation = _validation_for(mission, "worker", "verifier", evidence)
    daily, _oracle_row, _source_sha = _daily_oracle_verification_for(mission, tmp_path)
    validation["daily_verification"] = daily
    path = tmp_path / "daily-validation.json"
    path.write_text(json.dumps(validation), encoding="utf-8")

    completion = close_mission(Path(mission["path"]), path, tmp_path)
    assert completion["status"] == "incomplete"
    summary = completion["daily_verification"]
    assert summary["status"] == "INCOMPLETE"
    assert summary["complete"] is False
    assert summary["attestation_verified"] is True
    assert summary["execution_verified"] is False
    assert summary["behavioral_verification"] == "unverified"
    assert "signer claims only" in summary["attestation_claim_boundary"]
    assert "behavioral_assertion_unverified" in summary["gaps"]
    assert summary["scope_limitations"]
    cases = [case for criterion in summary["criteria"] for case in criterion["cases"]]
    assert {case["disposition"] for case in cases} == {
        "signer_attested_baseline_and_mutant"
    }
    assert all(case["application_output_observed"] is None for case in cases)
    assert all(case["trust_root_sha256"] for case in cases)
    assert all(case["environment_sha256"] == "b" * 64 for case in cases)
    checked = verify_mission_completion(Path(completion["path"]))
    assert checked["valid"] is False
    assert checked["integrity_valid"] is True
    assert checked["complete"] is False
    assert checked["marker"] == "MISSION_COMPLETION_INCOMPLETE"
    (tmp_path / "candidate.py").write_text("VALUE = 2\n", encoding="utf-8")
    post_capture = verify_mission_completion(Path(completion["path"]))
    assert post_capture["valid"] is False
    assert post_capture["complete"] is False
    assert post_capture["marker"] == "MISSION_COMPLETION_DRIFT"
    assert any("evidence drift" in error for error in post_capture["errors"])


def test_daily_verification_rejects_invalid_signature_after_digest_refresh(
    tmp_path,
):
    _graph, _slices, mission = _pipeline(tmp_path)
    evidence = tmp_path / "test-results.json"
    evidence.write_text('{"passed": true}\n', encoding="utf-8")
    validation = _validation_for(mission, "worker", "verifier", evidence)
    daily, _oracle_row, _source_sha = _daily_oracle_verification_for(mission, tmp_path)
    (tmp_path / "oracle.json").write_text('{"tampered": true}', encoding="utf-8")
    receipt_sha = hashlib.sha256((tmp_path / "oracle.json").read_bytes()).hexdigest()
    for criterion in daily["criteria"]:
        for case in criterion["cases"]:
            case["evidence"]["sha256"] = receipt_sha
    validation["daily_verification"] = daily
    path = tmp_path / "daily-validation.json"
    path.write_text(json.dumps(validation), encoding="utf-8")

    completion = close_mission(Path(mission["path"]), path, tmp_path)
    summary = completion["daily_verification"]
    assert summary["status"] == "INCOMPLETE"
    assert "execution_oracle_invalid_or_stale" in summary["gaps"]
    assert completion["status"] == "incomplete"


def test_daily_verification_rejects_reused_v3_case_for_positive_and_negative(tmp_path):
    _graph, _slices, mission = _pipeline(tmp_path)
    evidence = tmp_path / "test-results.json"
    evidence.write_text('{"passed": true}\n', encoding="utf-8")
    validation = _validation_for(mission, "worker", "verifier", evidence)
    daily, _oracle_row, _source_sha = _daily_oracle_verification_for(mission, tmp_path)
    cases = daily["criteria"][0]["cases"]
    cases[1]["evidence"]["oracle_case_id"] = cases[0]["evidence"]["oracle_case_id"]
    validation["daily_verification"] = daily
    path = tmp_path / "daily-validation.json"
    path.write_text(json.dumps(validation), encoding="utf-8")

    completion = close_mission(Path(mission["path"]), path, tmp_path)
    assert completion["status"] == "incomplete"
    assert "execution_oracle_case_reused" in completion["daily_verification"]["gaps"]


def test_daily_verification_rejects_stale_candidate_and_missing_receipt_binding(
    tmp_path,
):
    _graph, _slices, mission = _pipeline(tmp_path)
    evidence = tmp_path / "test-results.json"
    evidence.write_text('{"passed": true}\n', encoding="utf-8")
    validation = _validation_for(mission, "worker", "verifier", evidence)
    daily = _daily_verification_for(mission, tmp_path, omit_candidate_artifact=True)
    (tmp_path / "candidate.py").write_text("VALUE = 2\n", encoding="utf-8")
    validation["daily_verification"] = daily
    path = tmp_path / "daily-validation.json"
    path.write_text(json.dumps(validation), encoding="utf-8")

    completion = close_mission(Path(mission["path"]), path, tmp_path)
    gaps = completion["daily_verification"]["gaps"]
    assert "candidate_source_stale:candidate.py" in gaps
    assert "execution_candidate_source_binding_missing" in gaps
    assert completion["status"] == "incomplete"


def test_daily_verification_infrastructure_failure_is_not_behavioral_evidence(
    tmp_path,
):
    _graph, _slices, mission = _pipeline(tmp_path)
    evidence = tmp_path / "test-results.json"
    evidence.write_text('{"passed": true}\n', encoding="utf-8")
    validation = _validation_for(mission, "worker", "verifier", evidence)
    validation["daily_verification"] = _daily_verification_for(
        mission, tmp_path, timeout=True
    )
    path = tmp_path / "daily-validation.json"
    path.write_text(json.dumps(validation), encoding="utf-8")

    completion = close_mission(Path(mission["path"]), path, tmp_path)
    summary = completion["daily_verification"]
    assert summary["status"] == "INCOMPLETE"
    assert "execution_infrastructure_failure" in summary["gaps"]
    assert "behavioral_assertion_unverified" in summary["gaps"]
    positive = summary["criteria"][0]["cases"][0]
    assert positive["disposition"] == "unverified"
    assert positive["observed_outcome"] is None


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


def _mission_repair_inputs(tmp_path: Path):
    mission, decision, candidate, declaration = _approved_binding_inputs(tmp_path)
    with (candidate / ".gitignore").open("a", encoding="utf-8") as stream:
        stream.write(".factory/\n")
    subprocess.run(["git", "-C", str(candidate), "add", ".gitignore"], check=True)
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
            "--quiet",
            "-m",
            "ignore evidence",
        ],
        check=True,
    )
    declaration["base_commit"] = _candidate_workspace_head(candidate)
    declaration["paths"] = ["README.md"]
    declaration["profiles"] = ["docker-linux"]
    checks = [
        {
            "id": "repaired",
            "kind": "positive",
            "argv": [
                "python",
                "-c",
                "from pathlib import Path; assert Path('README.md').read_text() == 'candidate repaired\\n', 'repair not applied'",
            ],
            "failure": {"exit_code": 1, "signature": "repair not applied"},
        },
        {
            "id": "baseline-removed",
            "kind": "negative",
            "argv": [
                "python",
                "-c",
                "from pathlib import Path; assert Path('README.md').read_text() == 'candidate base\\n', 'old value absent'",
            ],
            "failure": {"exit_code": 1, "signature": "old value absent"},
        },
    ]
    declaration["commands"] = [{"id": row["id"], "argv": row["argv"]} for row in checks]
    binding = bind_mission_candidate(
        Path(mission["path"]),
        Path(decision["path"]),
        tmp_path,
        owner="release-owner",
        declaration=declaration,
    )
    approval = {
        "workspace": str(candidate).casefold(),
        "base_commit": declaration["base_commit"],
        "touched_paths": ["README.md"],
        "tool_contract": {"checks": checks, "total_timeout_seconds": 600},
    }
    return candidate, binding, approval


def test_mission_repair_binding_matches_exact_scope_commands_and_budget(tmp_path: Path):
    from factoryline.product_missions import verify_mission_repair_binding

    candidate, binding, approval = _mission_repair_inputs(tmp_path)
    result = verify_mission_repair_binding(
        Path(binding["path"]), tmp_path, owner="release-owner", approval=approval
    )
    assert result["schema"] == "factory.mission.repair-binding.v1"
    assert result["workspace"] == str(candidate)
    assert result["binding_sha256"] == binding["binding_sha256"]
    assert result["mission_sha256"] == binding["mission"]["mission_sha256"]
    assert (
        result["binding_file_sha256"]
        == hashlib.sha256(Path(binding["path"]).read_bytes()).hexdigest()
    )


@pytest.mark.parametrize(
    "mutation", ["workspace", "base", "paths", "empty", "command", "budget"]
)
def test_mission_repair_binding_rejects_contract_expansion(
    tmp_path: Path, mutation: str
):
    from factoryline.product_missions import verify_mission_repair_binding

    _candidate, binding, approval = _mission_repair_inputs(tmp_path)
    if mutation == "workspace":
        approval["workspace"] += "-other"
    elif mutation == "base":
        approval["base_commit"] = "0" * 40
    elif mutation == "paths":
        approval["touched_paths"] = ["unapproved.py"]
    elif mutation == "empty":
        approval["touched_paths"] = []
    elif mutation == "command":
        approval["tool_contract"]["checks"][0]["argv"] = ["unapproved"]
    else:
        approval["tool_contract"]["total_timeout_seconds"] = 3601
    with pytest.raises(ProductMissionError, match="MISSION_CANDIDATE_INVALID"):
        verify_mission_repair_binding(
            Path(binding["path"]), tmp_path, owner="release-owner", approval=approval
        )


def test_mission_repair_cli_dispatches_existing_approval_without_synthesis(
    tmp_path: Path, monkeypatch, capsys
):
    import factoryline.repair_sandbox as sandbox

    candidate, binding, _approval = _mission_repair_inputs(tmp_path)
    approval_path = candidate / ".factory" / "exact-approval.json"
    calls = []

    def execute(root, path, *, mission_binding):
        calls.append((root, path, mission_binding))
        return {"state": "TEST_DISPATCH", "mission_binding": mission_binding}

    monkeypatch.setattr(sandbox, "execute_approved_repair", execute)
    assert (
        main(
            [
                "mission",
                "execute-repair",
                binding["path"],
                str(approval_path),
                "--root",
                str(tmp_path),
                "--owner",
                "release-owner",
                "--json",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "TEST_DISPATCH"
    assert calls == [
        (
            candidate,
            approval_path,
            {"path": binding["path"], "root": str(tmp_path), "owner": "release-owner"},
        )
    ]
    assert not approval_path.exists()


def test_mission_repair_cli_rejects_wrong_owner_before_dispatch(
    tmp_path: Path, monkeypatch, capsys
):
    import factoryline.repair_sandbox as sandbox

    _candidate, binding, _approval = _mission_repair_inputs(tmp_path)

    def forbidden(*_args, **_kwargs):
        pytest.fail("unapproved owner reached executor")

    monkeypatch.setattr(sandbox, "execute_approved_repair", forbidden)
    assert (
        main(
            [
                "mission",
                "execute-repair",
                binding["path"],
                "missing-approval.json",
                "--root",
                str(tmp_path),
                "--owner",
                "another-owner",
                "--json",
            ]
        )
        != 0
    )
    assert "MISSION_CANDIDATE_INVALID" in capsys.readouterr().err


def test_mission_repair_real_docker_preserves_primary_and_bound_journal(tmp_path: Path):
    import os
    from datetime import datetime, timedelta, timezone
    from factoryline.product_missions import execute_mission_repair
    from factoryline.repair_sandbox import (
        create_repair_scope,
        write_repair_scope_artifacts,
        inspect_repair_candidate,
        create_repair_approval,
        verify_repair_attempt_journal,
    )

    image, digest = (
        os.environ.get("FACTORY_REPAIR_TEST_IMAGE"),
        os.environ.get("FACTORY_REPAIR_TEST_DIGEST"),
    )
    if not image or not digest:
        pytest.skip("explicit local digest-pinned operator image required")
    candidate, binding, contract = _mission_repair_inputs(tmp_path)
    scope = create_repair_scope(candidate, "Mission repair", ["README.md"])
    artifacts = write_repair_scope_artifacts(
        scope, candidate, candidate / ".factory" / "scope"
    )
    scope_path = Path(artifacts["paths"]["json"])
    patch = candidate / ".factory" / "candidate.patch"
    patch.write_text(
        "diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-candidate base\n+candidate repaired\n",
        encoding="utf-8",
    )
    inspected = inspect_repair_candidate(candidate, scope_path, patch)
    approval = create_repair_approval(
        candidate,
        scope_path,
        patch,
        approved_by="authorized disposable operator test",
        confirmation="APPROVE REPAIR " + inspected["candidate_sha256"],
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        container_image=image,
        container_digest=digest,
        checks=contract["tool_contract"]["checks"],
    )
    result = execute_mission_repair(
        Path(binding["path"]),
        candidate / approval["path"],
        tmp_path,
        owner="release-owner",
    )
    assert result["status"] == "VERIFIED", result
    assert result["cleanup_confirmed"] is True
    assert result["primary_checkout_unchanged"] is True
    assert (candidate / "README.md").read_text(encoding="utf-8") == "candidate base\n"
    assert result["mission_binding"]["binding_sha256"] == binding["binding_sha256"]
    assert result["mission_budget"]["admission"]["action"]["status"] == "ADMITTED"
    assert result["mission_budget"]["settlement"]["action"]["status"] == "SETTLED"
    assert result["mission_budget"]["settlement"]["usage"]["iterations"] == 1
    assert float(result["mission_budget"]["settlement"]["usage"]["wall_seconds"]) > 0
    journal = verify_repair_attempt_journal(candidate, approval["approval_sha256"])
    assert journal["state"]["mission_binding"] == result["mission_binding"]
    assert journal["state"]["mission_budget"] == result["mission_budget"]
    assert [row["stage"] for row in result["checks"]] == [
        "baseline",
        "repaired",
        "repaired",
    ]


def test_mission_repair_binding_requires_declared_docker_profile(tmp_path: Path):
    from factoryline.product_missions import verify_mission_repair_binding

    _candidate, binding, approval = _mission_repair_inputs(tmp_path)
    path = Path(binding["path"])
    _reseal_candidate_binding(
        path, lambda value: value["declaration"].update(profiles=["windows-only"])
    )
    with pytest.raises(ProductMissionError, match="docker-linux"):
        verify_mission_repair_binding(
            path, tmp_path, owner="release-owner", approval=approval
        )


def _mission_repair_budget_context(
    tmp_path: Path, *, max_iterations=3, max_wall_seconds=1600
):
    from factoryline.product_missions import verify_mission_repair_binding

    _candidate, binding, approval = _mission_repair_inputs(tmp_path)
    context = verify_mission_repair_binding(
        Path(binding["path"]), tmp_path, owner="release-owner", approval=approval
    )
    # Keep the mission and binding hash gates untouched. Build a separate valid
    # passport/manifest pair with tight runtime limits for ledger boundary cases.
    from factoryline.loop_passport import build_loop_passport

    source = json.loads(
        Path(context["budget_passport_path"]).read_text(encoding="utf-8")
    )
    source_manifest = Path(source["manifest_path"])
    manifest = json.loads(source_manifest.read_text(encoding="utf-8"))
    manifest["id"] = f"test-{max_iterations}-{max_wall_seconds}"
    manifest["budgets"].update(
        max_iterations=max_iterations, max_wall_seconds=max_wall_seconds
    )
    manifest_path = tmp_path / f"{manifest['id']}.manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    passport = build_loop_passport(tmp_path, manifest_path)
    context["budget_passport_path"] = passport["paths"]["json"]
    return context, approval


def test_mission_repair_budget_pending_and_replay_are_durable(tmp_path: Path):
    import factoryline.repair_sandbox as sandbox

    context, approval = _mission_repair_budget_context(tmp_path)
    approval_one, approval_two = "1" * 64, "2" * 64
    first = sandbox._admit_mission_repair(context, approval_one, approval)
    assert first["status"] == "ADMITTED"
    assert first["usage"]["wall_seconds"] == 1200
    with pytest.raises(sandbox.RepairSandboxError) as blocked:
        sandbox._admit_mission_repair(context, approval_two, approval)
    assert blocked.value.code == "MISSION_BUDGET_BLOCKED"
    # A helper re-entry simulates process restart; the SQLite reservation remains.
    with pytest.raises(sandbox.RepairSandboxError) as blocked:
        sandbox._admit_mission_repair(context, approval_two, approval)
    assert blocked.value.code == "MISSION_BUDGET_BLOCKED"
    with pytest.raises(sandbox.RepairSandboxError) as blocked:
        sandbox._admit_mission_repair(context, approval_one, approval)
    assert blocked.value.code == "MISSION_BUDGET_BLOCKED"


def test_mission_repair_budget_enforces_iterations_and_wall_reservation(
    tmp_path: Path, monkeypatch
):
    import factoryline.repair_sandbox as sandbox

    context, approval = _mission_repair_budget_context(
        tmp_path, max_iterations=1, max_wall_seconds=1201
    )
    monkeypatch.setattr(sandbox, "_persist_attempt", lambda *_args: None)
    monkeypatch.setattr(sandbox.time, "monotonic", lambda: 10.0)
    approval_sha = "3" * 64
    admission = sandbox._admit_mission_repair(context, approval_sha, approval)
    state = {
        "cleanup_confirmed": True,
        "mission_budget": {"admission": admission},
        "status": "VERIFIED",
    }
    sandbox._settle_mission_repair("attempt", state, context, approval_sha, 9.0)
    assert state["mission_budget"]["settlement"]["status"] == "SETTLED"
    with pytest.raises(sandbox.RepairSandboxError) as blocked:
        sandbox._admit_mission_repair(context, "4" * 64, approval)
    assert blocked.value.code == "MISSION_BUDGET_BLOCKED"

    wall_context, wall_approval = _mission_repair_budget_context(
        tmp_path / "wall", max_iterations=3, max_wall_seconds=1199
    )
    with pytest.raises(sandbox.RepairSandboxError) as blocked:
        sandbox._admit_mission_repair(wall_context, "5" * 64, wall_approval)
    assert blocked.value.code == "MISSION_BUDGET_BLOCKED"


def test_mission_repair_budget_rejects_altered_passport_budget(tmp_path: Path):
    import factoryline.repair_sandbox as sandbox

    context, approval = _mission_repair_budget_context(tmp_path)
    passport_path = Path(context["budget_passport_path"])
    passport = json.loads(passport_path.read_text(encoding="utf-8"))
    passport["budgets"]["max_iterations"] += 1
    passport_path.write_text(json.dumps(passport), encoding="utf-8")
    with pytest.raises(sandbox.RepairSandboxError) as blocked:
        sandbox._admit_mission_repair(context, "6" * 64, approval)
    assert blocked.value.code == "MISSION_BUDGET_BLOCKED"


def test_mission_repair_binding_rejects_passport_budget_mismatch(
    tmp_path: Path, monkeypatch
):
    _candidate, binding, approval = _mission_repair_inputs(tmp_path)
    from factoryline.product_missions import verify_mission_repair_binding

    _reseal_candidate_binding(
        Path(binding["path"]),
        lambda value: value["budgets"].update(max_iterations=999),
    )
    with pytest.raises(ProductMissionError, match="MISSION_CANDIDATE_INVALID"):
        verify_mission_repair_binding(
            Path(binding["path"]), tmp_path, owner="release-owner", approval=approval
        )


def test_mission_repair_budget_serializes_competing_approvals(tmp_path: Path):
    from concurrent.futures import ThreadPoolExecutor
    import factoryline.repair_sandbox as sandbox

    context, approval = _mission_repair_budget_context(tmp_path)

    def reserve(approval_sha):
        try:
            return sandbox._admit_mission_repair(context, approval_sha, approval)[
                "status"
            ]
        except sandbox.RepairSandboxError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(reserve, ("7" * 64, "8" * 64)))
    assert sorted(results) == ["ADMITTED", "MISSION_BUDGET_BLOCKED"]


def test_mission_repair_budget_records_cleanup_overrun_and_stops(
    tmp_path: Path, monkeypatch
):
    import factoryline.repair_sandbox as sandbox

    context, approval = _mission_repair_budget_context(tmp_path, max_wall_seconds=1200)
    admission = sandbox._admit_mission_repair(context, "9" * 64, approval)
    state = {
        "cleanup_confirmed": True,
        "mission_budget": {"admission": admission},
        "status": "VERIFIED",
    }
    monkeypatch.setattr(sandbox, "_persist_attempt", lambda *_: None)
    monkeypatch.setattr(sandbox.time, "monotonic", lambda: 1201.0000001)
    sandbox._settle_mission_repair("attempt", state, context, "9" * 64, 0)
    receipt = state["mission_budget"]["settlement"]
    assert receipt["status"] == "BUDGET_EXCEEDED"
    assert receipt["usage"]["wall_seconds"] == "1201.000001"
    assert state["status"] == "STOPPED"
    with pytest.raises(sandbox.RepairSandboxError) as blocked:
        sandbox._admit_mission_repair(context, "a" * 64, approval)
    assert blocked.value.code == "MISSION_BUDGET_BLOCKED"
