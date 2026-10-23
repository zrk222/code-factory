from __future__ import annotations
import json
from pathlib import Path
from factoryline.assembly import DEFAULT_CHAIN, assemble
import sys
import pytest
from factoryline.assurance import (
    AssuranceError,
    GateNode,
    RiskDAG,
    build_cyclonedx_sbom,
    build_evidence_graph,
    build_vex,
    private_challenge_manifest,
    run_constrained,
    verify_policy_mutations,
    verify_policy_command,
)
from factoryline.blueprint import (
    BlueprintError,
    access_profile,
    build_artifact_chain,
    blueprint_projection,
    librarian_promotion,
    recall_observations,
    reflect_observations,
    retain_observation,
    signal_intent_proposal,
    team_plan,
    verify_artifact_chain,
)
from factoryline.signal_loop import capture_signal
import hashlib
from factoryline.candidate_lineage import (
    CandidateLineageError,
    verify_candidate_lineage,
)
from factoryline.cli import main
from factoryline.deep_audit import execute_deep_audit
from factoryline.graph_forensics import seal_graph_lineage
from test_deep_audit import inputs
from test_oracle_firewall import _contract
import shutil
from factoryline import capability_packs
from factoryline.capability_packs import (
    BUILTIN_ROOT,
    CapabilityPackError,
    builtin_packs,
    compose_packs,
    install_pack,
    target_inventory,
    validate_pack,
)
from factoryline.assembly import _cdte_gate
from factoryline.continuation import _next_action


def _detailed_result(output, *, ok=True, exit_code=0, cleanup=True, streams=True):
    raw = output.encode("utf-8")
    return {
        "ok": ok,
        "output": output,
        "stdout": raw,
        "stderr": b"",
        "exit_code": exit_code,
        "cleanup_confirmed": cleanup,
        "streams_closed": streams,
        "reason": None if ok else "process failed",
    }


def test_default_chain_contains_conditional_prestige_gate():
    assert (
        "prestige",
        ["score", "smoke/{f}.ui", "--json", "--strict"],
    ) in DEFAULT_CHAIN


def test_assembly_marks_prestige_not_applicable_without_ui_scope(
    tmp_path: Path, monkeypatch
):
    class Present:
        installed = True

    monkeypatch.setattr(
        "factoryline.assembly.detect",
        lambda: [
            type(
                "Module",
                (),
                {"name": name, "installed": True, "cli": name, "role": "test"},
            )()
            for name in ("specline", "forgeline", "hsf", "prestige")
        ],
    )
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "feature.md").write_text("# feature\n", encoding="utf-8")
    report = assemble(
        tmp_path,
        "feature",
        chain=[("prestige", ["score", "smoke/{f}.ui", "--json", "--strict"])],
    )
    assert report["stages"][0]["status"] == "skipped"
    assert report["stages"][0]["reason"] == "ui_scope_not_declared"


def test_assembly_fails_closed_when_release_contract_declares_missing_ui_scope(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setattr(
        "factoryline.assembly.detect",
        lambda: [
            type(
                "Module",
                (),
                {"name": name, "installed": True, "cli": name, "role": "test"},
            )()
            for name in ("specline", "forgeline", "hsf", "prestige")
        ],
    )
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "feature.md").write_text("# feature\n", encoding="utf-8")
    contract = tmp_path / ".factory/release-contracts/feature.json"
    contract.parent.mkdir(parents=True)
    contract.write_text(
        json.dumps({"required_stages": ["prestige:score"]}), encoding="utf-8"
    )

    report = assemble(
        tmp_path,
        "feature",
        chain=[("prestige", ["score", "smoke/{f}.ui", "--json", "--strict"])],
    )

    assert report["stages"][0]["marker"] == "UI_SCOPE_REQUIRED_EVIDENCE_MISSING"
    assert report["halted_at"] == "prestige:score"


def test_assembly_preserves_explicit_unverified_forge_intent_status_in_standard_receipt(
    tmp_path: Path, monkeypatch
):
    class Module:
        def __init__(self, name: str):
            self.name = name
            self.installed = True
            self.cli = name
            self.role = "test"

    monkeypatch.setattr(
        "factoryline.assembly.detect",
        lambda: [Module(name) for name in ("specline", "forgeline", "hsf", "prestige")],
    )
    ship_line = {
        "phase": "ship",
        "ts": "2026-08-24T12:01:00Z",
        "shipped": True,
        "intent_hash": "a" * 64,
        "obligations": "1/1",
    }
    forge_receipts = tmp_path / ".forge" / "adapter-feature" / "receipts.jsonl"
    forge_receipts.parent.mkdir(parents=True)
    forge_receipts.write_text(json.dumps(ship_line) + "\n", encoding="utf-8")
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "adapter-feature.md").write_text(
        "# adapter\n", encoding="utf-8"
    )
    cli_output = json.dumps(
        {
            "shipped": True,
            "intent_traceable": False,
            "intent_hash": "a" * 64,
            "obligations_met": "1/1",
        }
    )
    monkeypatch.setattr(
        "factoryline.assembly.run_cli_detailed",
        lambda *args, **kwargs: _detailed_result(cli_output),
    )

    report = assemble(
        tmp_path, "adapter-feature", chain=[("forgeline", ["ship", "{f}"])]
    )

    assert report["stages"][0]["status"] == "ok"
    receipts = list(
        (tmp_path / "receipts").glob("forgeline-adapter-feature-ship-*.json")
    )
    assert len(receipts) == 1
    payload = json.loads(receipts[0].read_text(encoding="utf-8"))
    adapter = payload["outputs"]["intent_trace"]
    assert adapter["schema"] == "factoryline.intent-trace.v1"
    assert adapter["intent_traceable"] is False
    assert adapter["shipped"] is True
    assert adapter["intent_hash"] == "a" * 64
    assert adapter["obligations"] == "1/1"
    assert len(adapter["forge_receipt_sha256"]) == 64
    assert adapter["authority"]["execution"] is False


def test_assembly_omits_inferred_forge_intent_trace_when_cli_flag_is_missing(
    tmp_path: Path, monkeypatch
):
    class Module:
        def __init__(self, name: str):
            self.name = name
            self.installed = True
            self.cli = "forge" if name == "forgeline" else name
            self.role = "test"

    monkeypatch.setattr(
        "factoryline.assembly.detect",
        lambda: [Module(name) for name in ("specline", "forgeline", "hsf", "prestige")],
    )
    forge_receipts = tmp_path / ".forge" / "missing-adapter" / "receipts.jsonl"
    forge_receipts.parent.mkdir(parents=True)
    forge_receipts.write_text(
        json.dumps({"phase": "ship", "shipped": True}) + "\n", encoding="utf-8"
    )
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "missing-adapter.md").write_text(
        "# adapter\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        "factoryline.assembly.run_cli_detailed",
        lambda *args, **kwargs: _detailed_result('{"shipped":true}'),
    )

    assemble(tmp_path, "missing-adapter", chain=[("forgeline", ["ship", "{f}"])])

    receipts = list(
        (tmp_path / "receipts").glob("forgeline-missing-adapter-ship-*.json")
    )
    payload = json.loads(receipts[0].read_text(encoding="utf-8"))
    assert "intent_trace" not in payload["outputs"]


def test_assembly_enrolls_and_records_detailed_cli_attempts(tmp_path, monkeypatch):
    class Module:
        def __init__(self, name):
            self.name = name
            self.installed = True
            self.cli = name
            self.role = "test"

    monkeypatch.setattr(
        "factoryline.assembly.detect",
        lambda: [Module(name) for name in ("specline", "forgeline", "hsf", "prestige")],
    )
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "repeat.md").write_text("# repeat\n", encoding="utf-8")
    seen = []

    def run_detailed(*args, **kwargs):
        receipts = list((tmp_path / "receipts").glob("forgeline-repeat-ship-*.json"))
        assert len(receipts) == len(seen) + 1
        enrolled_rows = [
            json.loads(path.read_text(encoding="utf-8")) for path in receipts
        ]
        enrolled = next(
            row
            for row in enrolled_rows
            if row["outputs"]["cli_action"]["action_id"]
            not in {action["action_id"] for action in seen}
        )
        assert enrolled["ok"] is False
        assert enrolled["outputs"]["cli_action"]["state"] == "ENROLLED"
        seen.append(enrolled["outputs"]["cli_action"])
        return _detailed_result("out", ok=True)

    monkeypatch.setattr("factoryline.assembly.run_cli_detailed", run_detailed)
    report = assemble(
        tmp_path,
        "repeat",
        chain=[("forgeline", ["ship", "{f}"]), ("forgeline", ["ship", "{f}"])],
    )
    assert [row["status"] for row in report["stages"]] == ["ok", "ok"]
    assert [row["attempt"] for row in seen] == [1, 2]
    assert seen[0]["action_id"] != seen[1]["action_id"]
    receipts = list((tmp_path / "receipts").glob("forgeline-repeat-ship-*.json"))
    assert len(receipts) == 2
    for path in receipts:
        payload = json.loads(path.read_text(encoding="utf-8"))
        action = payload["outputs"]["cli_action"]
        assert payload["ok"] is True
        assert payload["run_id"] == action["action_id"]
        assert payload["outputs"]["assembly_run_id"] == report["run_id"]
        assert action["state"] == "COMPLETED"
        assert action["stdout_bytes"] == 3
        assert len(action["stdout_sha256"]) == 64
        assert action["stderr_bytes"] == 0
        assert action["cleanup_confirmed"] is True
        assert action["streams_closed"] is True
        assert "args" not in action


def test_assembly_cleanup_failure_does_not_mark_cli_action_success(
    tmp_path, monkeypatch
):
    class Module:
        def __init__(self, name):
            self.name = name
            self.installed = True
            self.cli = name
            self.role = "test"

    monkeypatch.setattr(
        "factoryline.assembly.detect",
        lambda: [Module(name) for name in ("specline", "forgeline", "hsf", "prestige")],
    )
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "bad.md").write_text("# bad\n", encoding="utf-8")
    monkeypatch.setattr(
        "factoryline.assembly.run_cli_detailed",
        lambda *args, **kwargs: _detailed_result(
            "out", ok=False, exit_code=0, cleanup=False
        ),
    )
    report = assemble(tmp_path, "bad", chain=[("forgeline", ["ship", "{f}"])])
    assert report["stages"][0]["status"] == "failed"
    path = next((tmp_path / "receipts").glob("forgeline-bad-ship-*.json"))
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["ok"] is False
    assert payload["outputs"]["cli_action"]["state"] == "INCOMPLETE"


def test_cli_action_rejects_malformed_detailed_result():
    from factoryline.assembly import _cli_action_result

    ok, facts = _cli_action_result({"ok": True, "exit_code": False, "stdout": "raw"})
    assert ok is False
    assert facts["state"] == "INCOMPLETE"
    assert facts["stdout_bytes"] is None
    assert facts["stdout_sha256"] is None


def test_cli_action_id_binds_release_binding():
    from factoryline.assembly import _AssemblyStage, _cli_action_id

    stage = _AssemblyStage(
        "forgeline", "forgeline", ["ship", "{f}"], "ship", "forgeline:ship", True, True
    )
    first = _cli_action_id("run", stage, 1, {"release": "a" * 64})
    changed = _cli_action_id("run", stage, 1, {"release": "b" * 64})

    assert first != changed


def _records():
    return [
        {
            "evidence_id": "root",
            "tenant_id": "acme",
            "stage": "strict",
            "verdict": "VERIFIED",
            "parent_ids": [],
        },
        {
            "evidence_id": "child",
            "tenant_id": "acme",
            "stage": "compile",
            "verdict": "VERIFIED",
            "parent_ids": ["root"],
        },
    ]


def test_evidence_graph_is_deterministic_and_rejects_cycles():
    first = build_evidence_graph(_records(), tenant_id="acme")
    second = build_evidence_graph(list(reversed(_records())), tenant_id="acme")
    assert first["graph_sha256"] == second["graph_sha256"]
    assert first["roots"] == ["root"] and first["heads"] == ["child"]
    cyclic = [
        {"evidence_id": "a", "tenant_id": "acme", "parent_ids": ["b"]},
        {"evidence_id": "b", "tenant_id": "acme", "parent_ids": ["a"]},
    ]
    with pytest.raises(AssuranceError) as error:
        build_evidence_graph(cyclic, tenant_id="acme")
    assert error.value.code == "E_GRAPH_CYCLE"


def test_risk_dag_selects_impacted_gates_and_dependencies():
    dag = RiskDAG(
        [
            GateNode("contract", 5, paths=("factoryline/",)),
            GateNode("tests", 3, depends_on=("contract",), paths=("tests/",)),
            GateNode("docs", 1, paths=("docs/",)),
        ]
    )
    plan = dag.plan(["tests/test_api.py"], minimum_risk=3)
    assert plan["selected"] == ["contract", "tests"]
    with pytest.raises(AssuranceError) as error:
        RiskDAG(
            [GateNode("a", 1, depends_on=("b",)), GateNode("b", 1, depends_on=("a",))]
        )
    assert error.value.code == "E_DAG_CYCLE"


def test_runner_contains_cwd_and_reports_process_boundary(tmp_path):
    result = run_constrained([sys.executable, "-c", "print('ok')"], root=tmp_path)
    assert result["ok"] is True
    assert result["isolation"] == "process-boundary"
    with pytest.raises(AssuranceError) as error:
        run_constrained([sys.executable, "-c", "print('no')"], root=tmp_path, cwd="..")
    assert error.value.code == "E_RUNNER_CWD"


def test_sbom_and_vex_are_sorted_and_hashed():
    sbom = build_cyclonedx_sbom(
        [
            {"name": "z", "version": "1"},
            {"name": "a", "version": "2"},
        ]
    )
    assert [item["name"] for item in sbom["components"]] == ["a", "z"]
    assert sbom["bom_sha256"]
    vex = build_vex(
        [{"vulnerability": "CVE-1", "component": "a", "status": "not_affected"}]
    )
    assert vex["entries"][0]["status"] == "not_affected"


def test_policy_mutation_challenge_detects_hollow_policy_and_private_manifest_hides_payload():
    policy = {
        "rules": [{"id": "tests", "required": True}, {"id": "review", "required": True}]
    }
    result = verify_policy_mutations(
        policy,
        lambda value: len(value["rules"]) == 2
        and all(rule.get("required") for rule in value["rules"]),
    )
    assert result["status"] == "VERIFIED"
    hollow = verify_policy_mutations(policy, lambda value: True)
    assert hollow["status"] == "HOLLOW_POLICY"
    manifest = private_challenge_manifest(
        "private", [{"input": "secret"}], tenant_id="acme"
    )
    assert "secret" not in str(manifest)
    assert manifest["challenge_count"] == 1


def test_policy_command_challenge_proves_default_shaped_policy_rules(tmp_path):
    script = tmp_path / "evaluate_policy.py"
    script.write_text(
        "import json, sys\n"
        "p = json.load(open(sys.argv[1], encoding='utf-8'))\n"
        "ok = p.get('release', {}).get('require_ci') is True and p.get('quality', {}).get('require_hollow_tests') is True\n"
        "raise SystemExit(0 if ok else 1)\n",
        encoding="utf-8",
    )
    policy = {
        "schema": "factory.policy.v1",
        "release": {"require_ci": True},
        "quality": {"require_hollow_tests": True},
    }
    verified = verify_policy_command(
        policy,
        [sys.executable, str(script), "{policy}"],
        root=tmp_path,
    )
    assert verified["status"] == "VERIFIED"
    hollow = verify_policy_command(
        policy,
        [sys.executable, "-c", "raise SystemExit(0)", "{policy}"],
        root=tmp_path,
    )
    assert hollow["status"] == "HOLLOW_POLICY"


def test_cli_verify_policy_writes_a_receipt(tmp_path, capsys):
    from factoryline.cli import main

    (tmp_path / "factory.policy.json").write_text(
        json.dumps({"release": {"require_ci": True}}), encoding="utf-8"
    )
    script = tmp_path / "evaluate.py"
    script.write_text(
        "import json, sys\n"
        "p = json.load(open(sys.argv[1], encoding='utf-8'))\n"
        "raise SystemExit(0 if p.get('release', {}).get('require_ci') is True else 1)\n",
        encoding="utf-8",
    )
    challenge = tmp_path / "policy.challenge.json"
    challenge.write_text(
        json.dumps(
            {"command": [sys.executable, str(script), "{policy}"], "timeout": 30}
        ),
        encoding="utf-8",
    )
    assert (
        main(["verify-policy", "--root", str(tmp_path), "--challenge", str(challenge)])
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "VERIFIED"
    assert (tmp_path / ".factory" / "policy-challenges" / "verify-policy.json").exists()


def _observation(**overrides):
    payload = {
        "source": "run-1",
        "source_digest": "a" * 64,
        "project": "factory",
        "subject": "release gate",
        "classification": "fact",
        "entities": ["cadence"],
        "tags": ["release"],
        "observed_at": "2026-09-22T12:00:00Z",
        "summary": "The release cadence gate is enforced during preflight.",
    }
    payload.update(overrides)
    return retain_observation(**payload)


def test_memory_retain_recall_reflect_and_librarian_promotion() -> None:
    observation = _observation()
    recalled = recall_observations([observation], project="factory", query="cadence")
    assert recalled["marker"] == "BLUEPRINT_MEMORY_RECALLED"
    assert len(recalled["matches"]) == 1
    reflection = reflect_observations([observation])
    assert reflection["projects"][0]["classes"] == {"fact": 1}
    gold = librarian_promotion(
        observation,
        reviewer="human-release-authority",
        stage="gold",
        source_digest="a" * 64,
        feedback="Confirmed against the release receipt.",
    )
    assert gold["stage"] == "gold"
    assert gold["human_approved"] is True


def test_librarian_rejects_source_drift_and_contested_gold() -> None:
    observation = _observation()
    with pytest.raises(BlueprintError, match="source digest"):
        librarian_promotion(
            observation,
            reviewer="reviewer",
            stage="silver",
            source_digest="b" * 64,
        )
    with pytest.raises(BlueprintError, match="contested"):
        librarian_promotion(
            observation,
            reviewer="reviewer",
            stage="gold",
            source_digest="a" * 64,
            contested=True,
        )


def test_signal_becomes_agent_proposed_intent_not_an_automatic_task(tmp_path) -> None:
    signal = capture_signal(
        tmp_path,
        source="sentry",
        title="Checkout timeout",
        body="Observed timeout in the checkout journey.",
        authorization="owner_supplied",
        outcomes=["Restore checkout completion"],
    )
    proposal = signal_intent_proposal(signal, owner="product-owner")
    assert proposal["status"] == "agent_proposed"
    assert proposal["requires_human_confirmation"] is True
    assert proposal["authority"]["create_intent"] is False


def test_access_profile_is_disjoint_and_explicitly_non_enforcing() -> None:
    profile = access_profile(
        workspace="repo",
        read_write=["src"],
        read_only=["reference"],
        masked=["strategy"],
    )
    assert profile["enforcement"] == "declaration_only"
    with pytest.raises(BlueprintError, match="disjoint"):
        access_profile(workspace="repo", read_write=["src"], masked=["src"])


def test_team_plan_is_typed_and_never_dispatches() -> None:
    plan = team_plan(
        plan_id="release-review",
        intent_digest="c" * 64,
        workers=[
            {
                "id": "planner",
                "kind": "bot",
                "model_tier": "frontier",
                "tools": ["spec"],
            },
            {
                "id": "builder",
                "kind": "subagent",
                "model_tier": "workhorse",
                "tools": ["edit"],
            },
        ],
        tasks=[
            {"id": "plan", "worker_id": "planner", "acceptance": "sealed plan exists"},
            {
                "id": "build",
                "worker_id": "builder",
                "dependencies": ["plan"],
                "acceptance": "candidate exists",
            },
        ],
    )
    assert plan["dispatcher"]["started"] is False
    assert all(value is False for value in plan["authority"].values())
    with pytest.raises(BlueprintError, match="worker_id"):
        team_plan(
            plan_id="bad",
            intent_digest="c" * 64,
            workers=[{"id": "planner", "model_tier": "frontier"}],
            tasks=[{"id": "build", "worker_id": "missing", "acceptance": "x"}],
        )


def test_projection_counts_only_hash_valid_receipts(tmp_path) -> None:
    directory = tmp_path / ".factory" / "blueprint"
    directory.mkdir(parents=True)
    (directory / "memory.json").write_text(
        __import__("json").dumps(_observation()), encoding="utf-8"
    )
    (directory / "bad.json").write_text("{}", encoding="utf-8")
    projection = blueprint_projection(tmp_path)
    assert projection["counts"]["factory.blueprint-memory.v1"] == 1
    assert projection["invalid_count"] == 1


def test_artifact_chain_binds_intent_spec_and_plan_and_detects_drift() -> None:
    chain = build_artifact_chain(
        intent="# Intent\nShip a safe checkout.",
        spec="# Spec\nThe checkout must be idempotent.",
        plan="# Plan\nRun the six audit lanes.",
        author="product-owner",
        project="checkout",
        intent_status="approved",
        files_changed=["src/checkout.py"],
        work_order=["implement", "audit", "review"],
        risks=["duplicate charge"],
        proof_of_completion=["pytest tests/test_checkout.py", "factory proof-review"],
    )
    verified = verify_artifact_chain(chain)
    assert verified["marker"] == "BLUEPRINT_ARTIFACT_CHAIN_VERIFIED"
    assert verified["lineage"] == "intent -> spec -> plan"
    assert all(value is False for value in verified["authority"].values())
    chain["documents"]["plan"]["text"] = "changed"
    with pytest.raises(BlueprintError, match="TAMPERED|drift"):
        verify_artifact_chain(chain)


def test_artifact_chain_requires_proof_contract() -> None:
    with pytest.raises(BlueprintError, match="required"):
        build_artifact_chain(
            intent="intent",
            spec="spec",
            plan="plan",
            author="owner",
            project="demo",
            files_changed=[],
            work_order=["build"],
            proof_of_completion=[],
        )


def _steps() -> list[dict]:
    return [
        {
            "sequence": 1,
            "superstep": 1,
            "node_id": "verify",
            "checkpoint_id": "cp-1",
            "reads": [],
            "writes": [],
            "evidence": [{"path": "evidence/verify.json", "sha256": "a" * 64}],
            "side_effects": [],
            "decision": {"route": "next", "reason": "candidate evidence checked"},
        }
    ]


def _manifest(
    root: Path, oracle: Path, candidate: str, deep: Path, graph: Path
) -> Path:
    rows = []
    for identifier, kind, path in (
        ("deep", "deep_audit", deep),
        ("graph", "graph_lineage", graph),
    ):
        rows.append(
            {
                "id": identifier,
                "kind": kind,
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    path = root / "continuity.json"
    path.write_text(
        json.dumps(
            {
                "schema": "factory.candidate-lineage-input.v1",
                "id": "candidate-review",
                "candidate_sha256": candidate,
                "oracle_contract": {
                    "path": oracle.relative_to(root).as_posix(),
                    "contract_sha256": json.loads(oracle.read_text())[
                        "contract_sha256"
                    ],
                },
                "evidence": rows,
                "authority": "none",
            }
        ),
        encoding="utf-8",
    )
    return path


def _fixture(root: Path) -> tuple[Path, Path, Path, Path, str]:
    oracle = _contract(root)
    args, *_ = inputs(root, clean=True)
    audit = execute_deep_audit(*args)
    deep = Path(audit["receipt_path"])
    candidate = audit["receipt"]["candidate_sha256"]
    steps = root / "steps.json"
    steps.write_text(json.dumps(_steps()), encoding="utf-8")
    graph = root / "graph.json"
    seal_graph_lineage("run-1", "review", steps, graph, candidate_sha256=candidate)
    return (
        oracle,
        deep,
        graph,
        _manifest(root, oracle, candidate, deep, graph),
        candidate,
    )


def test_candidate_lineage_verifies_one_current_candidate(tmp_path: Path):
    _, _, _, manifest, candidate = _fixture(tmp_path)
    result = verify_candidate_lineage(tmp_path, manifest)
    assert result["marker"] == "CANDIDATE_LINEAGE_VERIFIED"
    assert result["candidate_sha256"] == candidate
    assert result["evidence_kinds"] == ["deep_audit", "graph_lineage"]
    assert result["release_approval"] is False
    assert all(value is False for value in result["authority"].values())


def test_cli_surfaces_continuity_receipt_without_authority(tmp_path: Path, capsys):
    _, _, _, manifest, _ = _fixture(tmp_path)
    assert (
        main(
            [
                "graph",
                "lineage-continuity",
                str(manifest),
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["marker"] == "CANDIDATE_LINEAGE_VERIFIED"
    assert payload["release_approval"] is False


def test_legacy_graph_is_readable_but_not_strictly_candidate_bound(tmp_path: Path):
    oracle, deep, _, _, candidate = _fixture(tmp_path)
    steps = tmp_path / "legacy-steps.json"
    steps.write_text(json.dumps(_steps()), encoding="utf-8")
    legacy = tmp_path / "legacy.json"
    seal_graph_lineage("run-legacy", "review", steps, legacy)
    manifest = _manifest(tmp_path, oracle, candidate, deep, legacy)
    with pytest.raises(CandidateLineageError) as raised:
        verify_candidate_lineage(tmp_path, manifest)
    assert raised.value.code == "E_CANDIDATE_LINEAGE_GRAPH"


def test_mixed_candidate_graph_fails_closed(tmp_path: Path):
    oracle, deep, _, _, candidate = _fixture(tmp_path)
    steps = tmp_path / "other-steps.json"
    steps.write_text(json.dumps(_steps()), encoding="utf-8")
    graph = tmp_path / "other.json"
    seal_graph_lineage("run-other", "review", steps, graph, candidate_sha256="b" * 64)
    manifest = _manifest(tmp_path, oracle, candidate, deep, graph)
    with pytest.raises(CandidateLineageError) as raised:
        verify_candidate_lineage(tmp_path, manifest)
    assert raised.value.code == "E_CANDIDATE_LINEAGE_GRAPH"


def test_stale_evidence_digest_and_incomplete_kinds_fail_closed(tmp_path: Path):
    oracle, deep, graph, manifest, _ = _fixture(tmp_path)
    payload = json.loads(manifest.read_text())
    payload["evidence"][0]["sha256"] = "c" * 64
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CandidateLineageError) as raised:
        verify_candidate_lineage(tmp_path, manifest)
    assert raised.value.code == "E_CANDIDATE_LINEAGE_EVIDENCE"

    payload["evidence"] = [payload["evidence"][1]]
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CandidateLineageError) as raised:
        verify_candidate_lineage(tmp_path, manifest)
    assert raised.value.code == "E_CANDIDATE_LINEAGE_EVIDENCE"


def test_oracle_authority_and_workspace_paths_fail_closed(tmp_path: Path):
    oracle, deep, graph, manifest, candidate = _fixture(tmp_path)
    payload = json.loads(manifest.read_text())
    payload["authority"] = {"publish": True}
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CandidateLineageError) as raised:
        verify_candidate_lineage(tmp_path, manifest)
    assert raised.value.code == "E_CANDIDATE_LINEAGE_AUTHORITY"

    payload["authority"] = "none"
    payload["oracle_contract"]["path"] = "../outside.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CandidateLineageError) as raised:
        verify_candidate_lineage(tmp_path, manifest)
    assert raised.value.code == "E_CANDIDATE_LINEAGE_PATH"

    link = tmp_path / "oracle-link.json"
    try:
        link.symlink_to(oracle)
    except OSError:
        pytest.skip("symlink creation is unavailable on this Windows host")
    payload["oracle_contract"]["path"] = link.name
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CandidateLineageError) as raised:
        verify_candidate_lineage(tmp_path, manifest)
    assert raised.value.code == "E_CANDIDATE_LINEAGE_PATH"


EXPECTED_TARGETS = {"agent-ui", "api", "cli", "mcp", "mobile", "web", "worker"}
EXPECTED_KINDS = {"target", "surface", "language", "capability", "data", "ops"}


def test_builtin_target_packs_are_signed_and_mutation_tested():
    packs = builtin_packs()
    assert len(packs) == 29
    assert {item["kind"] for item in packs} == EXPECTED_KINDS
    assert {
        item["target_kind"] for item in packs if item["kind"] == "target"
    } == EXPECTED_TARGETS
    for item in packs:
        result = validate_pack(Path(item["path"]))
        assert result["valid"] is True
        assert result["signature"]["verified"] is True
        assert result["mutations"]["attempted"] == 10
        assert result["mutations"]["rejected"] == 10


def test_target_inventory_is_derived_from_packs():
    inventory = target_inventory()
    assert set(inventory) == EXPECTED_TARGETS
    assert inventory["agent-ui"]["pack_id"] == "target-agent-ui"
    assert inventory["worker"]["entrypoint"] == "python -m worker.main"


def test_builtin_discovery_ignores_python_cache_directories(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    root = tmp_path / "builtin_packs"
    shutil.copytree(BUILTIN_ROOT / "target-worker", root / "target-worker")
    (root / "__pycache__").mkdir()
    monkeypatch.setattr(capability_packs, "BUILTIN_ROOT", root)

    packs = builtin_packs()

    assert [item["id"] for item in packs] == ["target-worker"]


def test_tampered_pack_fails_closed(tmp_path: Path):
    source = BUILTIN_ROOT / "target-worker"
    tampered = tmp_path / "target-worker"
    shutil.copytree(source, tampered)
    manifest = json.loads((tampered / "pack.yaml").read_text(encoding="utf-8"))
    manifest["summary"] = "tampered"
    (tampered / "pack.yaml").write_text(json.dumps(manifest), encoding="utf-8")

    result = validate_pack(tampered)

    assert result["valid"] is False
    assert any(
        "signed pack payload does not match current files" in item
        for item in result["errors"]
    )
    assert result["failure"]["causal_code"] == "PACK_VALIDATION_FAILED"


def test_pack_signatures_are_portable_across_text_line_endings(tmp_path: Path):
    source = BUILTIN_ROOT / "target-worker"
    copied = tmp_path / "target-worker"
    shutil.copytree(source, copied)
    for path in copied.rglob("*"):
        if not path.is_file() or path.name == "pack.signature.json":
            continue
        data = path.read_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        path.write_bytes(
            text.replace("\r\n", "\n")
            .replace("\r", "\n")
            .replace("\n", "\r\n")
            .encode("utf-8")
        )

    result = validate_pack(copied)

    assert result["valid"] is True
    assert result["signature"]["verified"] is True


def test_hollow_canary_manifest_is_rejected_before_install(tmp_path: Path):
    source = BUILTIN_ROOT / "target-web"
    broken = tmp_path / "target-web"
    shutil.copytree(source, broken)
    canaries = broken / "canaries" / "manifest.json"
    canaries.write_text(
        '{"schema":"factory.pack.canaries.v1","canaries":[]}', encoding="utf-8"
    )

    result = validate_pack(broken)

    assert result["valid"] is False
    assert "canary manifest must be non-empty" in result["errors"]


def test_install_is_verified_and_refuses_implicit_replacement(tmp_path: Path):
    source = BUILTIN_ROOT / "target-mobile"
    result = install_pack(source, tmp_path)
    installed = tmp_path / ".factory" / "packs" / "target-mobile"
    assert result["marker"] == "PACK_INSTALLED_VERIFIED"
    assert installed.is_dir()
    assert validate_pack(installed)["valid"] is True

    with pytest.raises(CapabilityPackError, match="PACK_EXISTS"):
        install_pack(source, tmp_path)


def test_install_rejects_pack_id_path_escape(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setattr(
        capability_packs,
        "validate_pack",
        lambda *args, **kwargs: {
            "valid": True,
            "pack_id": "../escape",
            "version": "1.0.0",
            "signature": {"verified": True},
            "mutations": {"attempted": 5, "rejected": 5},
            "errors": [],
        },
    )
    with pytest.raises(CapabilityPackError, match="PACK_PATH_INVALID"):
        install_pack(BUILTIN_ROOT / "target-worker", tmp_path)
    assert not (tmp_path / ".factory" / "escape").exists()


def test_force_install_restores_previous_pack_when_swap_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    source = BUILTIN_ROOT / "target-worker"
    install_pack(source, tmp_path)
    destination = tmp_path / ".factory" / "packs" / "target-worker"
    sentinel = destination / "local-sentinel.txt"
    sentinel.write_text("previous-install", encoding="utf-8")
    original_replace = capability_packs.os.replace
    calls = 0

    def fail_final_swap(src, dst):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated final swap failure")
        return original_replace(src, dst)

    monkeypatch.setattr(capability_packs.os, "replace", fail_final_swap)
    with pytest.raises(CapabilityPackError) as caught:
        install_pack(source, tmp_path, force=True)
    assert caught.value.code == "PACK_INSTALL_FAILED"
    assert "PACK_ROLLBACK_RESTORED" in caught.value.markers
    assert sentinel.read_text(encoding="utf-8") == "previous-install"


def test_cli_lists_verified_packs(capsys: pytest.CaptureFixture[str]):
    assert main(["pack", "list"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["packs"]) == 29
    assert all(
        item["valid"] and item["signature"]["verified"] for item in payload["packs"]
    )


def test_pack_composition_is_hash_bound_and_has_no_execution_authority(tmp_path: Path):
    result = compose_packs(
        [
            BUILTIN_ROOT / "target-web",
            BUILTIN_ROOT / "surface-nextjs",
            BUILTIN_ROOT / "language-typescript",
            BUILTIN_ROOT / "capability-auth",
        ],
        tmp_path,
        name="review-portal",
    )

    assert result["marker"] == "PACK_COMPOSITION_VERIFIED"
    assert result["pack_count"] == 4
    assert result["target_kind"] == "web"
    assert result["authority"] == {
        "generate": False,
        "execute": False,
        "deploy": False,
        "publish": False,
    }
    assert len(result["composition_sha256"]) == 64
    assert Path(result["path"]).is_file()
    assert {item["id"] for item in result["packs"]} == {
        "target-web",
        "surface-nextjs",
        "language-typescript",
        "capability-auth",
    }


def test_pack_composition_rejects_incompatible_target(tmp_path: Path):
    with pytest.raises(CapabilityPackError, match="PACK_COMPOSITION_INCOMPATIBLE"):
        compose_packs(
            [
                BUILTIN_ROOT / "target-worker",
                BUILTIN_ROOT / "surface-expo",
            ],
            tmp_path,
        )


def test_pack_composition_preserves_existing_file_when_atomic_swap_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    composition_root = tmp_path / ".factory" / "pack-compositions"
    composition_root.mkdir(parents=True)
    destination = composition_root / "api-stack.json"
    destination.write_text('{"previous": true}\n', encoding="utf-8")

    def fail_swap(_source, _destination):
        raise OSError("simulated composition swap failure")

    monkeypatch.setattr(capability_packs.os, "replace", fail_swap)
    with pytest.raises(CapabilityPackError) as caught:
        compose_packs(
            [
                BUILTIN_ROOT / "target-api",
                BUILTIN_ROOT / "language-python",
            ],
            tmp_path,
            name="api-stack",
            force=True,
        )

    assert caught.value.code == "PACK_COMPOSITION_WRITE_FAILED"
    assert "PACK_COMPOSITION_ROLLBACK_PRESERVED" in caught.value.markers
    assert destination.read_text(encoding="utf-8") == '{"previous": true}\n'
    assert not list(composition_root.glob(".api-stack.json.*.tmp"))


def test_pack_compose_cli_writes_review_plan(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    assert (
        main(
            [
                "pack",
                "compose",
                str(BUILTIN_ROOT / "target-api"),
                str(BUILTIN_ROOT / "language-python"),
                str(BUILTIN_ROOT / "capability-auth"),
                "--root",
                str(tmp_path),
                "--name",
                "api-stack",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["target_kind"] == "api"
    assert "PACK_COMPOSITION_NO_EXECUTION_AUTHORITY" in payload["markers"]


"""Integration: the CDTE gate inside the assembly line.

These exercise `_cdte_gate` directly. Without them the gate's import and regex
paths are never executed by the suite, and a NameError would ship silently.
"""


def _write(root, feature, constraints):
    (root / "specs").mkdir(parents=True, exist_ok=True)
    (root / "specs" / f"{feature}.nfr.json").write_text(
        json.dumps({"constraints": constraints}), encoding="utf-8"
    )


CONFLICTING = [
    {
        "constraintId": "c-001",
        "category": "performance",
        "metric": "p95_latency_ms",
        "value": 50,
        "operator": "lt",
    },
    {
        "constraintId": "c-002",
        "category": "security",
        "metric": "field_level_encryption",
        "value": "aes-256",
    },
]
CLEAN = [
    {
        "constraintId": "c-001",
        "category": "scalability",
        "metric": "max_websocket_sessions",
        "value": 5000,
        "operator": "gte",
    },
]


def test_gate_is_skipped_when_no_constraints_file(tmp_path):
    """Additive by design: existing repos keep working untouched."""
    assert _cdte_gate(tmp_path, "checkout") is None


def test_gate_blocks_on_a_critical_conflict(tmp_path):
    _write(tmp_path, "checkout", CONFLICTING)
    outcome = _cdte_gate(tmp_path, "checkout")
    assert outcome["blocking"] is True
    assert outcome["stage"]["status"] == "blocked"
    assert outcome["stage"]["marker"] == "FAIL_CLOSED_ENGAGED"
    assert outcome["summary"]["requires_hitl_escalation"] is True


def test_gate_passes_a_clean_spec(tmp_path):
    _write(tmp_path, "checkout", CLEAN)
    outcome = _cdte_gate(tmp_path, "checkout")
    assert outcome["blocking"] is False
    assert outcome["stage"]["status"] == "ok"
    assert outcome["summary"]["conflicts"] == []


def test_gate_fails_closed_on_unreadable_declared_constraints(tmp_path):
    """A declared constraints file is an obligation, not an optional hint."""
    (tmp_path / "specs").mkdir(parents=True)
    (tmp_path / "specs" / "checkout.nfr.json").write_text("{not json", encoding="utf-8")
    outcome = _cdte_gate(tmp_path, "checkout")
    assert outcome["blocking"] is True
    assert outcome["stage"]["status"] == "blocked"
    assert outcome["stage"]["marker"] == "CDTE_INPUT_INVALID"


def test_gate_degrades_on_malformed_constraints(tmp_path):
    _write(tmp_path, "checkout", [{"category": "performance"}])  # no metric
    outcome = _cdte_gate(tmp_path, "checkout")
    assert outcome["blocking"] is True
    assert outcome["stage"]["status"] == "blocked"
    assert "CONSTRAINT_FIELD_MISSING" in outcome["stage"]["reason"]


def test_feature_names_are_sanitized_into_run_ids(tmp_path):
    """Feature names allow characters a run id does not; the gate must not
    raise RUN_ID_INVALID on a legitimate feature name."""
    _write(tmp_path, "Checkout API v2", CONFLICTING)
    outcome = _cdte_gate(tmp_path, "Checkout API v2")
    assert outcome["blocking"] is True
    assert outcome["summary"]["run_id"] == "checkout-api-v2"


def test_gate_is_rerunnable(tmp_path):
    """Assembly reruns constantly; the gate must not refuse its own receipt."""
    _write(tmp_path, "checkout", CONFLICTING)
    first = _cdte_gate(tmp_path, "checkout")
    second = _cdte_gate(tmp_path, "checkout")
    assert first["summary"]["conflicts"] == second["summary"]["conflicts"]


def test_continuation_offers_a_resolve_command(tmp_path):
    action = _next_action("nfr_conflict", "checkout")
    assert action["kind"] == "command"
    assert "cdte resolve" in action["command"]
    assert action["requires_human"] is True
