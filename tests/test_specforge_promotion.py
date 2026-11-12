import json
import os
import runpy
from pathlib import Path
import pytest
from factoryline.specforge_promotion import verify_specforge_promotion
from factoryline.revenueforge import RevenueForgeError


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
