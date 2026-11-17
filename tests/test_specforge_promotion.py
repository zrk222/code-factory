import hashlib
import json
import os
import runpy
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
import pytest
from factoryline.agentic_control import (
    INCIDENT_PHASES,
    DurableIncidentDriver,
    WorkflowEventStore,
)
from factoryline.mission_graph import (
    MissionGraphError,
    apply_mission_event,
    mission_graph_history,
)
from factoryline.specforge_promotion import (
    _job_candidate_observed,
    advance_factory_mission_job,
    bind_factory_mission_job,
    complete_factory_mission_job,
    factory_mission_timeline,
    factory_proof_action_sha256,
    run_factory_mission_proofs,
    verify_specforge_promotion,
)
from factoryline.revenueforge import RevenueForgeError
from test_agentic_control import _IncidentTestDriver, _incident_success_evidence
from test_continuity import _approve, _pipeline


def test_native_promotion_rejects_unverified_ship_claim(tmp_path):
    spec = {"schema": "specline.intent-envelope.v1", "feature": "refunds"}
    spec_path = tmp_path / "spec.json"
    forge_path = tmp_path / "forge.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    forge_path.write_text(
        json.dumps(
            {"shipped": True, "intent_traceable": True, "intent_evidence": spec}
        ),
        encoding="utf-8",
    )
    receipt = verify_specforge_promotion(
        tmp_path, spec_path, forge_path, Path("promotion.json")
    )
    assert receipt["ok"] is False
    assert receipt["evidence_level"] == "native_trace_unverified"
    assert receipt["findings"] == ["E_SPECFORGE_NATIVE_HANDOFF_UNVERIFIED"]
    assert receipt["authority"]["release"] is False


@pytest.mark.parametrize("required_gates", [[], ["unrelated_gate"]])
def test_specforge_promotion_requires_each_obligation_gate(tmp_path, required_gates):
    from factoryline.specforge_promotion import _sha

    intent = {"mission": "review code"}
    spec = tmp_path / "spec.json"
    forge = tmp_path / "forge.json"
    spec.write_text(
        json.dumps(
            {
                "schema": "factory.specline.delivery-packet.v1",
                "intent": intent,
                "approval": {"origin": "human_confirmed"},
                "obligations": [
                    {
                        "id": "proof",
                        "forbidden_behavior": "hollow test",
                        "gate": "first_proof",
                    }
                ],
                "required_gates": required_gates,
            }
        ),
        encoding="utf-8",
    )
    forge.write_text(
        json.dumps(
            {
                "schema": "factory.forgeline.delivery-state.v1",
                "intent_sha256": _sha(intent),
                "state": "verified",
                "gates": dict.fromkeys(required_gates, True),
            }
        ),
        encoding="utf-8",
    )

    output = tmp_path / "promotion.json"
    receipt = verify_specforge_promotion(tmp_path, spec, forge, output)
    assert receipt["marker"] == "SPECFORGE_PROMOTION_BLOCKED"
    assert receipt["evidence_level"] == "declared_topology"
    assert receipt["findings"] == ["E_SPECLINE_OBLIGATION_LOOSE"]
    assert json.loads(output.read_text(encoding="utf-8"))["ok"] is False


def test_specforge_promotion_fails_closed_on_intent_drift_and_missing_selected_gates(
    tmp_path: Path,
):
    spec = {
        "schema": "factory.specline.delivery-packet.v1",
        "intent": {"mission": "ship proven app"},
        "approval": {"origin": "human_confirmed"},
        "obligations": [
            {
                "id": "tests",
                "forbidden_behavior": "weaken oracle",
                "gate": "oracle_firewall",
            }
        ],
        "required_gates": ["oracle_firewall", "independent_challenge"],
    }
    sp = tmp_path / "spec.json"
    sp.write_text(json.dumps(spec))
    fp = tmp_path / "forge.json"
    fp.write_text(
        json.dumps(
            {
                "schema": "factory.forgeline.delivery-state.v1",
                "intent_sha256": "wrong",
                "state": "running",
                "gates": {},
            }
        )
    )
    receipt = verify_specforge_promotion(
        tmp_path, sp, fp, Path(".factory/specforge.json")
    )
    assert receipt["ok"] is False
    assert "E_FORGELINE_INTENT_DRIFT" in receipt["findings"]
    assert any(
        x.startswith("E_FORGELINE_REQUIRED_GATE_MISSING") for x in receipt["findings"]
    )


def test_specforge_promotion_only_requires_appforge_when_spec_selects_it(
    tmp_path: Path,
):
    spec = {
        "schema": "factory.specline.delivery-packet.v1",
        "intent": {"mission": "review code"},
        "approval": {"origin": "human_confirmed"},
        "obligations": [
            {"id": "proof", "forbidden_behavior": "hollow test", "gate": "first_proof"}
        ],
        "required_gates": ["first_proof", "oracle_firewall"],
    }
    sp = tmp_path / "spec.json"
    sp.write_text(json.dumps(spec))
    from factoryline.specforge_promotion import _sha

    fp = tmp_path / "forge.json"
    fp.write_text(
        json.dumps(
            {
                "schema": "factory.forgeline.delivery-state.v1",
                "intent_sha256": _sha(spec["intent"]),
                "state": "verified",
                "gates": {"first_proof": True, "oracle_firewall": True},
            }
        )
    )
    assert (
        verify_specforge_promotion(tmp_path, sp, fp, Path(".factory/ready.json"))["ok"]
        is True
    )


def test_specforge_promotion_rejects_an_output_path_outside_the_workspace(
    tmp_path: Path,
):
    spec = {
        "schema": "factory.specline.delivery-packet.v1",
        "intent": {"mission": "review code"},
        "approval": {"origin": "human_confirmed"},
        "obligations": [
            {"id": "proof", "forbidden_behavior": "hollow test", "gate": "first_proof"}
        ],
        "required_gates": ["first_proof"],
    }
    sp = tmp_path / "spec.json"
    sp.write_text(json.dumps(spec))
    from factoryline.specforge_promotion import _sha

    fp = tmp_path / "forge.json"
    fp.write_text(
        json.dumps(
            {
                "schema": "factory.forgeline.delivery-state.v1",
                "intent_sha256": _sha(spec["intent"]),
                "state": "verified",
                "gates": {"first_proof": True},
            }
        )
    )
    with pytest.raises(RevenueForgeError) as exc_info:
        verify_specforge_promotion(tmp_path, sp, fp, tmp_path.parent / "outside.json")
    assert exc_info.value.code == "SPECFORGE_PATH_REJECTED"


if fixture_path := os.environ.get("FACTORY_COORDINATED_SPEC_FIXTURES"):
    fixtures = runpy.run_path(fixture_path)
    project, evidence_project = fixtures["project"], fixtures["evidence_project"]

    _REFUND_MODULE = "slices/refunds/intake.py"
    _REFUND_TEST = "tests/test_bound_refund.py"
    _NATIVE_REFUND_SPEC = """# Spec: refunds
Status: approved

## MUST — Functional core
### Description
Refund intake preserves the supplied identifier.

### User roles
- customer

### Requirements (EARS)
- The system shall return the submitted identifier unchanged, verified by `test_accept`.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Preserve the refund identifier
  Given a refund identifier of 7
  When the customer submits the identifier
  Then `test_accept` observes the returned identifier 7
```

## SHOULD — Technical/structural
- Intake has one typed integer argument and no external calls.

## SHOULD NOT — Implementation details
- Do not persist identifiers.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | else | Return the submitted identifier unchanged |
"""
    _REFUND_PRD = """# Refund Intake

## Actors
- Intake service: accepts refund identifiers.

## Outcomes
- Return the submitted refund identifier unchanged.

## Jobs and pains
- Job: accept an explicitly identified refund request.

## Journeys and business rules
- Journey: submit a refund identifier and read it back.
- Business rule: intake preserves the submitted identifier.

## Data ownership and trust boundaries
- Data ownership: the caller owns the refund identifier.
- Trust boundary: the request remains inside intake.

## External effects and approvals
- External effect: none.
- Approval: none.

## Success events
- refund_identifier_preserved.

## Requirements
- REQ-REFUND: Intake shall return the submitted refund identifier unchanged.

## Acceptance
Scenario: Preserve the refund identifier
  Given a refund identifier of 7
  When the service accepts the request
  Then the service returns the identifier 7
"""

    def _native_git(root, *args):
        return subprocess.check_output(
            ["git", *args], cwd=root, text=True, stderr=subprocess.STDOUT, timeout=15
        ).strip()

    def _native_commit(root, *paths):
        _native_git(root, "init", "--quiet")
        _native_git(root, "add", *paths)
        _native_git(
            root,
            "-c",
            "user.name=Factory Mission Test",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "Native fixture",
        )
        return _native_git(root, "rev-parse", "HEAD")

    def _native_refund_mission(root):
        from factoryline.product_missions import (
            compile_product_prd,
            create_mission,
            plan_value_slices,
        )

        prd = root / "PRD.md"
        prd.write_text(_REFUND_PRD, encoding="utf-8")
        graph = compile_product_prd(prd, root, project="refund-intake")
        slices = plan_value_slices(Path(graph["path"]), root, 1)
        return create_mission(
            Path(slices["path"]), slices["slices"][0]["id"], root, "mission-owner"
        )

    def _native_factory_inputs(root, mission, source_commit, driver_id):
        return {
            "root": root,
            "mission_path": Path(mission["path"]),
            "intent_path": root / "envelopes/refunds.json",
            "owner": mission["owner"],
            "repository": "fixture/refunds",
            "source_commit": source_commit,
            "phase_plan": {
                phase: {
                    "driver_id": driver_id,
                    "policy_sha256": hashlib.sha256(
                        b"fixture local-only approval"
                    ).hexdigest(),
                    "action_sha256": hashlib.sha256(phase.encode()).hexdigest(),
                }
                for phase in INCIDENT_PHASES
            },
        }

    def _native_candidate(root, mission, decision, candidate_head):
        from factoryline.product_missions import bind_mission_candidate

        return Path(
            bind_mission_candidate(
                Path(mission["path"]),
                decision,
                root,
                owner=mission["owner"],
                declaration={
                    "schema": "factory.mission.candidate-declaration.v1",
                    "workspace": "slices/refunds",
                    "base_commit": candidate_head,
                    "paths": ["intake.py"],
                    "interfaces": ["accept returns its integer input"],
                    "profiles": ["native-python"],
                    "commands": [
                        {
                            "id": "unit",
                            "argv": [
                                sys.executable,
                                "-m",
                                "pytest",
                                "-q",
                                _REFUND_TEST,
                            ],
                        }
                    ],
                    "audit_lanes": {
                        name: {
                            "applicable": name in {"static", "runtime"},
                            "reason": "One local deterministic Python function with no I/O.",
                        }
                        for name in (
                            "static",
                            "secrets",
                            "configuration",
                            "dependencies",
                            "runtime",
                            "fuzz",
                        )
                    },
                },
            )["path"]
        )

    def _write_refund_mutation_cases(root, mission):
        lines = ["from slices.refunds.intake import accept", ""]
        selectors = []
        for index, criterion in enumerate(mission["completion_contract"]["criteria"]):
            target = len(lines) + 2
            lines.extend(
                [
                    f"def test_refund_{index}():",
                    f"    assert accept({7 + index}) == {7 + index}",
                    "",
                ]
            )
            control = len(lines) + 2
            lines.extend(
                [
                    f"def test_type_control_{index}():",
                    "    assert isinstance(accept(7), int)",
                    "",
                ]
            )
            selectors.append((criterion["id"], target, control))
        (root / _REFUND_TEST).write_text("\n".join(lines), encoding="utf-8")
        return selectors

    def _capture_refund_mutations(root, mission, selectors, capsys):
        from factoryline.pytest_readiness import (
            _challenge_source_inventory,
            main as probe,
        )
        from factoryline.product_missions import _canonical
        from test_product_missions import _local_mutation_daily_contract

        sources = _challenge_source_inventory(root)
        rows = [
            {"path": path, "sha256": digest} for path, digest in sorted(sources.items())
        ]
        scope = [_REFUND_MODULE, _REFUND_TEST]
        digest = hashlib.sha256(_canonical(rows)).hexdigest()
        input_digest = hashlib.sha256(
            _canonical([{"path": path, "sha256": sources[path]} for path in scope])
        ).hexdigest()
        contract = root / "refund-mutations.json"
        contract.write_text(
            json.dumps(
                _local_mutation_daily_contract(
                    mission, rows, digest, scope, input_digest
                )
            ),
            encoding="utf-8",
        )
        for index, (criterion, target, control) in enumerate(selectors):
            capsys.readouterr()
            code = probe(
                [
                    "--root",
                    str(root),
                    "--kind",
                    "production-mutation",
                    "--nodeid",
                    f"{_REFUND_TEST}::test_refund_{index}",
                    "--line",
                    str(target),
                    "--production-path",
                    _REFUND_MODULE,
                    "--production-symbol",
                    "accept",
                    "--mutation-before",
                    "return value",
                    "--mutation-after",
                    "return value + 1",
                    "--evidence",
                    f".factory/refund-mutation/{index}",
                    "--mission-path",
                    mission["path"],
                    "--daily-contract",
                    str(contract),
                    "--criterion-id",
                    criterion,
                    "--target-case-id",
                    f"{criterion}:positive",
                    "--control-nodeid",
                    f"{_REFUND_TEST}::test_type_control_{index}",
                    "--control-line",
                    str(control),
                    "--control-case-id",
                    f"{criterion}:negative",
                    "--timeout",
                    "20",
                    "--python",
                    sys.executable,
                ]
            )
            capture = json.loads(capsys.readouterr().out)
            assert code == 0 and capture["status"] == "OBSERVED", capture
        return contract

    def _close_native_refund(root, mission, candidate, forge_result, contract):
        from factoryline.product_missions import (
            close_mission,
            verify_mission_completion,
        )
        from test_product_missions import _validation_for

        validation = _validation_for(
            mission, "native-builder", "native-verifier", contract
        )
        attestation = validation["adapter_attestation"]
        attestation["contract_digest"] = hashlib.sha256(
            contract.read_bytes()
        ).hexdigest()
        attestation["evidence_digest"] = hashlib.sha256(
            forge_result.read_bytes() + candidate.read_bytes()
        ).hexdigest()
        attestation["adapter_id"] = "native-pytest-mutation"
        for criterion in validation["criteria"]:
            criterion["evidence"].extend([str(forge_result), str(candidate)])
        validation["daily_verification"] = json.loads(contract.read_bytes())
        path = root / "refund-validation.json"
        path.write_text(json.dumps(validation), encoding="utf-8")
        completed = close_mission(Path(mission["path"]), path, root)
        proof = Path(completed["path"])
        assert completed["daily_verification"]["complete"], completed[
            "daily_verification"
        ]["gaps"]
        assert verify_mission_completion(proof)["complete"] is True
        return proof

    def _native_forge_cli(root, *args):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from forgeline.cli import main; main()",
                *args,
                "--root",
                str(root),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr

    def _refresh_refund_envelope(root, contract, observations):
        from specline.acceptance import catalogue, digest, export_acceptance_envelope
        from specline.loop import mark_done

        for task in ("T1", "T2"):
            assert mark_done(root, "refunds", task)["verified"]
        contract_path, observed_path = root / contract, root / observations
        checks = json.loads(contract_path.read_bytes())
        for row in checks["candidate"]:
            row["sha256"] = hashlib.sha256(
                (root / row["path"]).read_bytes()
            ).hexdigest()
        checks["checks"] = [
            {
                "id": item["id"],
                "requirement": item["text"],
                "category": "happy_path",
                "profiles": ["local-python"],
            }
            for item in catalogue(root, "refunds")
        ]
        contract_path.write_text(json.dumps(checks), encoding="utf-8")
        observed = json.loads(observed_path.read_bytes())
        observed["contract_sha256"] = hashlib.sha256(
            contract_path.read_bytes()
        ).hexdigest()
        observed["candidate_sha256"] = digest(checks["candidate"])
        baseline = observed["observations"][0]
        for artifact in baseline["artifacts"]:
            artifact["sha256"] = hashlib.sha256(
                (root / artifact["path"]).read_bytes()
            ).hexdigest()
        observed["observations"] = [
            {
                **baseline,
                "id": row["id"],
                "observed_at": datetime.now(timezone.utc).isoformat(),
            }
            for row in checks["checks"]
        ]
        observed_path.write_text(json.dumps(observed), encoding="utf-8")
        return export_acceptance_envelope(root, "refunds", contract, observations)

    def _native_refund_preflight(root):
        from factoryline.assembly import DEFAULT_CHAIN, assemble

        (root / "specs/refunds.md").write_text(_NATIVE_REFUND_SPEC, encoding="utf-8")
        (root / _REFUND_MODULE).write_text(
            '"""Local refund intake."""\n\ndef accept(value: int) -> int:\n'
            '    """Preserve the submitted refund identifier."""\n    return value\n',
            encoding="utf-8",
        )
        (root / "slices/refunds/status.py").write_text(
            '"""Local refund status."""\n\ndef status() -> str:\n'
            '    """Return the default status for a new refund."""\n    return "pending"\n',
            encoding="utf-8",
        )

        def assembly_pass(chain):
            report = assemble(root, "refunds", chain=chain)
            assert len(report["stages"]) == len(chain), report
            assert all(stage["status"] == "ok" for stage in report["stages"]), report

        assembly_pass(DEFAULT_CHAIN[:5])
        ssat = {
            "name": "refunds",
            "modules": [
                {
                    "name": "intake",
                    "path": _REFUND_MODULE,
                    "imports": [],
                    "functions": [
                        {
                            "name": "accept",
                            "args": ["value: int"],
                            "returns": "int",
                            "doc": "Preserve the submitted refund identifier.",
                        }
                    ],
                },
                {
                    "name": "status",
                    "path": "slices/refunds/status.py",
                    "imports": [],
                    "functions": [
                        {
                            "name": "status",
                            "args": [],
                            "returns": "str",
                            "doc": "Return the default status for a new refund.",
                        }
                    ],
                },
            ],
            "dependencies": [],
            "invariants": [],
        }
        (root / "refunds.ssat.yaml").write_text(json.dumps(ssat), encoding="utf-8")
        (root / "smoke").mkdir(exist_ok=True)
        smoke = {
            "checks": [
                {
                    "name": "preserve_identifier",
                    "kind": "python",
                    "expect_exit": 0,
                    "timeout_s": 15,
                    "run": "from slices.refunds.intake import accept\nassert accept(7) == 7\n",
                }
            ]
        }
        (root / "smoke/refunds.json").write_text(json.dumps(smoke), encoding="utf-8")
        _native_forge_cli(root, "expand", "refunds")
        _native_forge_cli(root, "gate", "architected", "refunds")
        assembly_pass(
            [("forgeline", ["architect", "{f}", "{f}.ssat.yaml", "--adopt-existing"])]
        )
        _native_forge_cli(root, "fill", "refunds", str(root / "refunds.ssat.yaml"))
        assembly_pass(DEFAULT_CHAIN[6:10])

    class _RegisteredNativeRefundEffects:
        """Fixture host persists one observation per launch; proof uses actual files."""

        def __init__(self, store_path, handlers):
            self.path = store_path
            self.handlers = handlers
            self.calls = []
            self.last_error = None

        def _effect_path(self, intent_id):
            return self.path / (intent_id + ".json")

        def _record(self, intent_id):
            path = self._effect_path(intent_id)
            return json.loads(path.read_bytes()) if path.is_file() else None

        def lookup(self, intent_id, _intent):
            record = self._record(intent_id)
            return {
                "action_intent_sha256": intent_id,
                "state": "terminal" if record else "missing",
                "handle": record["run_id"] if record else None,
                "authoritative": True,
            }

        def launch(self, run_id, action_intent_id, intent):
            phase = intent["phase"]
            self.calls.append(phase)
            try:
                output = self.handlers[phase](run_id, intent)
                digest = hashlib.sha256(output.read_bytes()).hexdigest()
                with self._effect_path(action_intent_id).open(
                    "x", encoding="utf-8"
                ) as stream:
                    json.dump(
                        {"run_id": run_id, "path": str(output), "digest": digest},
                        stream,
                    )
            except Exception as error:
                self.last_error = error
                raise
            if phase == "repair":
                raise OSError("simulated lost acknowledgement after real native ship")
            return run_id

        def verify(self, evidence):
            row = self._record(evidence["action_intent_sha256"])
            if (
                row is not None
                and row["run_id"] == evidence["run_id"]
                and (
                    hashlib.sha256(Path(row["path"]).read_bytes()).hexdigest()
                    == evidence["result_sha256"]
                    == row["digest"]
                )
            ):
                return evidence
            return None

    def _native_refund_handlers(
        inputs, mission, candidate, selectors, capsys, get_driver, paths
    ):
        from factoryline.product_missions import verify_mission_completion
        from factoryline.specforge_promotion import run_factory_mission_forge
        from factoryline.verification import verify_feature
        from specline.acceptance import validate_acceptance_envelope

        root = inputs["root"]

        def save(name, result):
            path = root / f"refund-{name}.json"
            path.write_text(json.dumps(result), encoding="utf-8")
            return path

        def detect(_run_id, _intent):
            result = validate_acceptance_envelope(
                root, "refunds", json.loads(inputs["intent_path"].read_bytes())
            )
            assert result["state"] == "PASS", result
            return save("detected", result)

        def investigate(_run_id, _intent):
            result = verify_feature(root, "refunds")
            assert result["shippable"] is False, result
            return save("pre-ship", result)

        def reproduce(_run_id, _intent):
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from slices.refunds.intake import accept; assert accept(7) == 7; print(accept(7))",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=15,
                check=True,
            )
            return save(
                "reproduced", {"exit": result.returncode, "stdout": result.stdout}
            )

        def repair(run_id, intent):
            paths["forge"] = run_factory_mission_forge(
                root,
                inputs["mission_path"],
                get_driver(),
                mission["owner"],
                run_id,
                intent,
            )
            return paths["forge"]

        def verify(_run_id, _intent):
            assert verify_feature(root, "refunds")["shippable"] is True
            contract = _capture_refund_mutations(root, mission, selectors, capsys)
            paths["proof"] = _close_native_refund(
                root, mission, candidate, paths["forge"], contract
            )
            return paths["proof"]

        def review(_run_id, _intent):
            assert verify_mission_completion(paths["proof"])["complete"] is True
            return paths["proof"]

        return dict(
            detect=detect,
            investigate=investigate,
            reproduce=reproduce,
            repair=repair,
            verify=verify,
            review=review,
        )

    def _finish_native_refund_phases(inputs, mission, candidate, selectors, capsys):
        store = _job_store(inputs)
        paths = {}

        def get_supervisor():
            return supervisor

        handlers = _native_refund_handlers(
            inputs, mission, candidate, selectors, capsys, get_supervisor, paths
        )
        effects = inputs["root"] / ".factory/refund-effects"
        effects.mkdir()
        host = _RegisteredNativeRefundEffects(effects, handlers)

        def reopen(current_host):
            return DurableIncidentDriver(
                _job_store(inputs),
                {"native-refund-host": current_host},
                authorizer=lambda caller, _intent: caller == mission["owner"],
                phase_verifiers={
                    phase: {"test-verifier": current_host.verify}
                    for phase in INCIDENT_PHASES
                },
                source_observer=lambda source: source,
            )

        bound = bind_factory_mission_job(**inputs, store=store)
        supervisor = reopen(host)
        root, path, owner = inputs["root"], inputs["mission_path"], mission["owner"]
        calls = []
        for phase in INCIDENT_PHASES:
            started = advance_factory_mission_job(
                root, path, supervisor, owner, ttl=180
            )
            assert host.last_error is None, repr(host.last_error)
            assert started["phase"] == phase
            if phase == "repair":
                assert (
                    started["status"] == "unknown"
                    and started["item"]["run"]["handle"] is None
                )
                calls.extend(host.calls)
                host = _RegisteredNativeRefundEffects(effects, handlers)
                supervisor = reopen(host)
            else:
                assert started["status"] == "launched", started
            retired = advance_factory_mission_job(
                root, path, supervisor, owner, ttl=180
            )
            assert retired["status"] == "retired", retired
            result = retired["item"]["last_run"]["driver_binding"][
                "action_intent_sha256"
            ]
            evidence = _incident_success_evidence(
                retired["item"], host._record(result)["digest"]
            )
            checkpoint = advance_factory_mission_job(
                root, path, supervisor, owner, phase_evidence=evidence
            )
            assert checkpoint["status"] == (
                "pending_review" if phase == "review" else "checkpointed"
            ), checkpoint
        assert calls + host.calls == list(INCIDENT_PHASES)
        assert len(list(effects.glob("*.json"))) == len(INCIDENT_PHASES)
        return store, paths, bound

    def test_native_factory_mission_completion_uses_real_forge_and_mutation_proof(
        evidence_project,
        capsys,
        monkeypatch,
    ):
        from factoryline.specforge_promotion import (
            factory_forge_action_sha256,
            factory_mission_timeline,
        )

        monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
        root, contract, observations = evidence_project
        root = root.resolve()
        mission = _native_refund_mission(root)
        selectors = _write_refund_mutation_cases(root, mission)
        _native_refund_preflight(root)
        _refresh_refund_envelope(root, contract, observations)
        source = _native_commit(
            root, "PRD.md", "specs/refunds.md", "plans/refunds.md", "slices/refunds"
        )
        nested = root / "slices/refunds"
        (nested / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
        candidate_head = _native_commit(nested, ".gitignore", "intake.py", "status.py")
        inputs = _native_factory_inputs(root, mission, source, "native-refund-host")
        inputs["phase_plan"]["repair"]["action_sha256"] = factory_forge_action_sha256()
        approved = _approve_job(inputs, mission)
        candidate = _native_candidate(
            root, mission, Path(approved["event"]["receipt"]["path"]), candidate_head
        )
        store, paths, bound = _finish_native_refund_phases(
            inputs, mission, candidate, selectors, capsys
        )
        arguments = {
            "forge_path": paths["forge"],
            "candidate_path": candidate,
            "completion_path": paths["proof"],
        }
        proof = complete_factory_mission_job(
            root, inputs["mission_path"], store, mission["owner"], **arguments
        )
        replay = complete_factory_mission_job(
            root,
            inputs["mission_path"],
            _job_store(inputs),
            mission["owner"],
            **arguments,
        )
        assert proof["state"] == replay["state"] == "completion_receipted"
        timeline = factory_mission_timeline(root, inputs["mission_path"], store)
        assert (
            timeline["job_proof_recorded"]
            and timeline["job_sha256"] == bound["binding"]["job_sha256"]
        )
        assert timeline["human_interventions"] == 1
        assert [row["event"] for row in timeline["events"]].count(
            "validation_passed"
        ) == 1

    @pytest.fixture
    def factory_mission_inputs(evidence_project):
        from specline.acceptance import export_acceptance_envelope

        root, contract, observations = evidence_project
        mission = _pipeline(root)
        root = root.resolve()

        def git(*args):
            return subprocess.check_output(
                ["git", *args],
                cwd=root,
                text=True,
                stderr=subprocess.STDOUT,
                timeout=15,
            ).strip()

        git("init", "--quiet")
        git("add", "PRD.md", "specs/refunds.md", "plans/refunds.md", "slices/refunds")
        git(
            "-c",
            "user.name=Factory Mission Test",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "Native intent fixture",
        )
        intent = export_acceptance_envelope(root, "refunds", contract, observations)
        return (
            {
                "root": root,
                "mission_path": Path(mission["path"]),
                "intent_path": root / "envelopes/refunds.json",
                "owner": mission["owner"],
                "repository": "fixture/refunds",
                "source_commit": git("rev-parse", "HEAD"),
                "phase_plan": {
                    phase: {
                        "driver_id": "fixture-driver",
                        "policy_sha256": "a" * 64,
                        "action_sha256": f"{index:064x}",
                    }
                    for index, phase in enumerate(INCIDENT_PHASES, start=1)
                },
            },
            mission,
            intent["sealed_hash"],
        )

    def _job_store(inputs):
        return WorkflowEventStore(
            inputs["root"], [("factoryline", "local", inputs["repository"])]
        )

    def _approve_job(inputs, mission):
        return apply_mission_event(
            inputs["mission_path"],
            inputs["root"],
            "approve",
            inputs["owner"],
            "owner",
            "approve-job",
            _approve(inputs["root"], mission),
        )

    def _job_history(inputs):
        return mission_graph_history(inputs["mission_path"], inputs["root"])

    def test_factory_mission_binding_requires_approval_and_owner(
        factory_mission_inputs, monkeypatch
    ):
        inputs, mission, _ = factory_mission_inputs
        store = _job_store(inputs)

        def unexpected_intake(*_args):
            pytest.fail("unapproved caller reached workflow intake")

        monkeypatch.setattr(store, "intake", unexpected_intake)
        with pytest.raises(MissionGraphError) as error:
            bind_factory_mission_job(**inputs, store=store)
        assert error.value.code == "MISSION_GRAPH_TRANSITION_INVALID"
        assert _job_history(inputs)["events"] == []

        _approve_job(inputs, mission)
        with pytest.raises(MissionGraphError) as error:
            bind_factory_mission_job(**{**inputs, "owner": "other-owner"}, store=store)
        assert error.value.code == "MISSION_GRAPH_OWNER_MISMATCH"
        assert [row["event"] for row in _job_history(inputs)["events"]] == ["approve"]

    def test_factory_mission_binding_replays_exactly_and_rejects_changed_plan(
        factory_mission_inputs,
    ):
        inputs, mission, intent_seal = factory_mission_inputs
        _approve_job(inputs, mission)
        bound = bind_factory_mission_job(**inputs, store=_job_store(inputs))
        reopened = _job_store(inputs)
        assert bind_factory_mission_job(**inputs, store=reopened) == bound
        assert not any(bound["authority"].values())
        assert bound["binding"]["mission_sha256"] == mission["mission_sha256"]
        assert bound["binding"]["intent_sha256"] == intent_seal
        item = reopened.get(bound["source_key"])
        assert item["source"]["external_id"] == bound["binding"]["job_sha256"]
        assert item["source"]["head_sha"] == inputs["source_commit"]
        assert item["source"]["kind"] == "mission"
        assert item["run"] is None

        modified = dict(inputs["phase_plan"])
        modified["verify"] = {**modified["verify"], "action_sha256": "e" * 64}
        with pytest.raises(MissionGraphError) as error:
            bind_factory_mission_job(
                **{**inputs, "phase_plan": modified}, store=reopened
            )
        assert error.value.code == "MISSION_GRAPH_IDEMPOTENCY_CONFLICT"
        graph = _job_history(inputs)
        assert [row["event"] for row in graph["events"]] == [
            "approve",
            "factory_job_bound",
        ]
        assert graph["chain_head"] == bound["mission_event_sha256"]
        assert len(reopened.history(bound["source_key"])["events"]) == 1

    def test_factory_mission_binding_resumes_after_interrupted_store_intake(
        factory_mission_inputs, monkeypatch
    ):
        inputs, mission, _ = factory_mission_inputs
        _approve_job(inputs, mission)
        store = _job_store(inputs)

        def interrupt_intake(*_args):
            raise OSError("simulated interruption after graph commit")

        monkeypatch.setattr(store, "intake", interrupt_intake)
        with pytest.raises(OSError, match="after graph commit"):
            bind_factory_mission_job(**inputs, store=store)
        interrupted = _job_history(inputs)
        assert [row["event"] for row in interrupted["events"]] == [
            "approve",
            "factory_job_bound",
        ]

        reopened = _job_store(inputs)
        resumed = bind_factory_mission_job(**inputs, store=reopened)
        assert resumed["mission_event_sha256"] == interrupted["chain_head"]
        assert resumed["binding"] == interrupted["events"][-1]["payload"]
        assert _job_history(inputs) == interrupted
        assert len(reopened.history(resumed["source_key"])["events"]) == 1

    def test_factory_mission_binding_rejects_drift_in_native_intent_sources(
        factory_mission_inputs,
    ):
        inputs, mission, _ = factory_mission_inputs
        _approve_job(inputs, mission)
        bound = bind_factory_mission_job(**inputs, store=_job_store(inputs))
        history = _job_history(inputs)
        source = inputs["root"] / "slices/refunds/intake.py"
        source.write_text("def accept(value):\n    return None\n", encoding="utf-8")
        reopened = _job_store(inputs)
        with pytest.raises(RevenueForgeError) as error:
            bind_factory_mission_job(**inputs, store=reopened)
        assert error.value.code == "SPECFORGE_JOB_BINDING"
        assert _job_history(inputs) == history
        assert len(reopened.history(bound["source_key"])["events"]) == 1

    def test_factory_mission_resumes_registered_effect_without_duplicate_launch(
        factory_mission_inputs,
        capsys,
    ):
        inputs, mission, _ = factory_mission_inputs
        _approve_job(inputs, mission)
        store = _job_store(inputs)
        bound = bind_factory_mission_job(**inputs, store=store)
        effect = inputs["root"] / "registered-effect.json"
        launches = []

        class FixtureDriver:
            def lookup(self, intent_id, _intent):
                recorded = json.loads(effect.read_text()) if effect.exists() else None
                matching = recorded is not None and recorded["intent_id"] == intent_id
                return {
                    "action_intent_sha256": intent_id,
                    "state": "live"
                    if matching
                    else "missing"
                    if recorded is None
                    else "unknown",
                    "handle": recorded["run_id"] if matching else None,
                    "authoritative": matching or recorded is None,
                }

            def launch(self, run_id, intent_id, _intent):
                launches.append(intent_id)
                with effect.open("x", encoding="utf-8") as stream:
                    json.dump({"run_id": run_id, "intent_id": intent_id}, stream)
                raise OSError("fixture effect accepted before launch acknowledgement")

        def supervisor(current_store):
            return DurableIncidentDriver(
                current_store,
                {"fixture-driver": FixtureDriver()},
                authorizer=lambda owner, _intent: owner == mission["owner"],
                phase_verifiers={
                    phase: {"unused-fixture-verifier": lambda _evidence: None}
                    for phase in INCIDENT_PHASES
                },
                source_observer=lambda source: source,
            )

        root, mission_path, owner = (
            inputs[key] for key in ("root", "mission_path", "owner")
        )
        interrupted = advance_factory_mission_job(
            root, mission_path, supervisor(store), owner
        )
        assert interrupted["status"] == "unknown"
        assert store.get(bound["source_key"])["run"]["handle"] is None
        recorded = json.loads(effect.read_text())
        assert launches == [recorded["intent_id"]]

        reopened = _job_store(inputs)
        resumed = advance_factory_mission_job(
            root, mission_path, supervisor(reopened), owner
        )
        assert resumed["status"] == "live"
        assert resumed["phase"] == "detect"
        assert resumed["item"]["run"]["handle"] == recorded["run_id"]
        assert (
            resumed["item"]["run"]["driver_binding"]["action_intent_sha256"]
            == recorded["intent_id"]
        )
        assert launches == [recorded["intent_id"]]
        assert json.loads(effect.read_text()) == recorded
        _assert_factory_job_cli_timeline(inputs, bound["binding"]["job_sha256"], capsys)

    def _assert_factory_job_cli_timeline(inputs, job_sha256, capsys):
        from factoryline.cli import main

        capsys.readouterr()
        assert (
            main(
                [
                    "langgraph",
                    "history",
                    str(inputs["mission_path"]),
                    "--root",
                    str(inputs["root"]),
                    "--factory-job",
                    "--json",
                ]
            )
            == 0
        )
        timeline = json.loads(capsys.readouterr().out)
        assert timeline == factory_mission_timeline(
            inputs["root"], inputs["mission_path"], _job_store(inputs)
        )
        assert timeline["schema"] == "factory.specforge.mission-timeline.v1"
        assert timeline["job_sha256"] == job_sha256
        assert timeline["state"] == "creator_running"
        assert timeline["human_interventions"] == 1
        assert [row["event"] for row in timeline["events"]] == [
            "approve",
            "factory_job_bound",
            "source_observed",
            "run_claimed",
            "run_handle_reconciled",
        ]
        assert (
            timeline["next_action"]
            == "Reconcile the current phase using its registered driver."
        )
        assert not any(timeline["authority"].values())

    def _proof_guard_fixture(inputs, mission, manifest):
        plan = {phase: dict(action) for phase, action in inputs["phase_plan"].items()}
        plan["verify"]["action_sha256"] = factory_proof_action_sha256(manifest, None)
        inputs = {**inputs, "phase_plan": plan}
        _approve_job(inputs, mission)
        store = _job_store(inputs)
        bound = bind_factory_mission_job(**inputs, store=store)
        key = bound["source_key"]
        registered = _IncidentTestDriver()
        permission = {"enabled": True}
        digest = hashlib.sha256(inputs["intent_path"].read_bytes()).hexdigest()

        def verify_fixture(evidence):
            current = hashlib.sha256(inputs["intent_path"].read_bytes()).hexdigest()
            return evidence if evidence["result_sha256"] == current else None

        driver = DurableIncidentDriver(
            store,
            {"fixture-driver": registered},
            authorizer=lambda owner, _intent: owner == inputs["owner"]
            and permission["enabled"],
            phase_verifiers={
                phase: {"test-verifier": verify_fixture} for phase in INCIDENT_PHASES
            },
            source_observer=lambda source: source,
        )
        owner = inputs["owner"]
        for phase in INCIDENT_PHASES[:4]:
            registered.state, registered.handle = "missing", None
            assert (
                driver.launch_phase(key, owner, phase, **plan[phase])["status"]
                == "launched"
            )
            registered.state = "terminal"
            retired = driver.launch_phase(key, owner, phase, **plan[phase])
            evidence = _incident_success_evidence(retired["item"], digest)
            assert (
                driver.checkpoint(key, owner, phase, evidence)["status"]
                == "checkpointed"
            )
        registered.state, registered.handle = "missing", None
        assert (
            driver.launch_phase(key, owner, "verify", **plan["verify"])["status"]
            == "launched"
        )
        return driver, registered, permission

    def test_factory_mission_proofs_reject_drift_and_revoked_host_authorization(
        factory_mission_inputs, monkeypatch
    ):
        from factoryline import incremental_scheduler

        inputs, mission, _ = factory_mission_inputs
        manifest = {"schema": "factory.pre-pr.v1", "feature": "refunds"}
        driver, registered, permission = _proof_guard_fixture(inputs, mission, manifest)
        run_id, _, intent = registered.launches[-1]

        def unexpected_dispatch(*_args, **_kwargs):
            pytest.fail("a rejected proof request reached the scheduler")

        monkeypatch.setattr(incremental_scheduler, "run_pre_pr", unexpected_dispatch)
        args = (
            inputs["root"],
            inputs["mission_path"],
            driver,
            inputs["owner"],
            run_id,
            intent,
        )
        with pytest.raises(RevenueForgeError) as error:
            run_factory_mission_proofs(*args, {**manifest, "feature": "other"})
        assert error.value.code == "SPECFORGE_JOB_PROOF"
        with pytest.raises(RevenueForgeError) as error:
            run_factory_mission_proofs(
                *args, manifest, execution_budget={"cpu_slots": 1}
            )
        assert error.value.code == "SPECFORGE_JOB_PROOF"
        permission["enabled"] = False
        with pytest.raises(RevenueForgeError) as error:
            run_factory_mission_proofs(*args, manifest)
        assert error.value.code == "SPECFORGE_JOB_STATE"

    def test_factory_mission_completion_rejects_unfinished_and_cross_mission_receipt(
        factory_mission_inputs,
    ):
        inputs, mission, _ = factory_mission_inputs
        _approve_job(inputs, mission)
        store = _job_store(inputs)
        bind_factory_mission_job(**inputs, store=store)
        root = inputs["root"]
        forge, candidate, completion = (
            root / "unverified-forge.json",
            root / "unfinished-candidate.json",
            root / "unfinished-completion.json",
        )
        forge.write_text(json.dumps({"shipped": False}), encoding="utf-8")
        candidate.write_text(
            json.dumps({"schema": "factory.mission.candidate-binding.v1"}),
            encoding="utf-8",
        )
        completion.write_text(
            json.dumps(
                {"schema": "factory.mission.completion.v1", "mission_id": mission["id"]}
            ),
            encoding="utf-8",
        )
        history = _job_history(inputs)
        arguments = (root, inputs["mission_path"], store, inputs["owner"])
        paths = {
            "forge_path": forge,
            "candidate_path": candidate,
            "completion_path": completion,
        }
        with pytest.raises(RevenueForgeError) as error:
            complete_factory_mission_job(*arguments, **paths)
        assert error.value.code == "SPECFORGE_JOB_PROOF"

        completion.write_text(
            json.dumps(
                {
                    "schema": "factory.mission.completion.v1",
                    "mission_id": "other-mission",
                }
            ),
            encoding="utf-8",
        )
        with pytest.raises(MissionGraphError) as error:
            complete_factory_mission_job(*arguments, **paths)
        assert error.value.code == "MISSION_GRAPH_RECEIPT_INVALID"
        assert _job_history(inputs) == history

    def test_factory_mission_candidate_requires_native_coverage_of_the_exact_path(
        factory_mission_inputs,
    ):
        inputs, _, _ = factory_mission_inputs
        root = inputs["root"]
        envelope = json.loads(inputs["intent_path"].read_text(encoding="utf-8"))
        source = root / "slices/refunds/intake.py"
        unrelated = root / "unrelated"
        unrelated.mkdir()
        (unrelated / source.name).write_bytes(source.read_bytes())
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        candidate = {
            "workspace": str(source.parent),
            "files": [{"path": source.name, "sha256": digest, "state": "existing"}],
        }
        rows = [
            {"path": source.relative_to(root).as_posix(), "sha256": digest},
            {"path": "unrelated/intake.py", "sha256": digest},
        ]
        completion = {"daily_verification": {"source_manifest": rows}}
        assert _job_candidate_observed(root, candidate, completion, envelope)
        assert not _job_candidate_observed(
            root, {**candidate, "workspace": str(unrelated)}, completion, envelope
        )

    def test_native_promotion_end_to_end(evidence_project):
        from forgeline.intent_thread import verify_against_intent
        from forgeline.orchestrator import Orchestrator
        from forgeline.states import State
        from specline.acceptance import export_acceptance_envelope

        root, contract, observations = evidence_project
        export_acceptance_envelope(root, "refunds", contract, observations)
        trace = verify_against_intent(root, "refunds", root)
        assert trace.traceable
        forge = Orchestrator(root, "refunds")
        forge.store.set_state(State.SMOKED)
        result = forge._record_ship_success(trace, {})
        forge_path = root / "forge-result.json"
        forge_path.write_text(json.dumps(result), encoding="utf-8")
        spec_path = Path("envelopes/refunds.json")
        output_path = Path("promotion.json")
        receipt = verify_specforge_promotion(root, spec_path, forge_path, output_path)
        assert receipt["ok"]
        assert receipt["intent_trace"]["intent_traceable"]
        assert not receipt["authority"]["release"]
        (root / "slices/refunds/intake.py").write_text(
            "def accept(value):\n    return None\n", encoding="utf-8"
        )
        assert not verify_specforge_promotion(root, spec_path, forge_path, output_path)[
            "ok"
        ]
