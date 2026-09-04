from __future__ import annotations

import hashlib
import json
from pathlib import Path

from factoryline.cli import main
from factoryline.ide_playbook import AdoptionGuideError, adoption_guide


def test_default_guide_has_exactly_three_journeys_and_one_primary_action():
    result = adoption_guide()

    assert result["schema"] == "factory.adoption-guide.v1"
    assert result["marker"] == "ADOPTION_GUIDE_RENDERED"
    assert [item["id"] for item in result["journeys"]] == ["solo", "team", "enterprise"]
    assert [item["first_command"] for item in result["journeys"] if item["primary"]] == [
        "factory first-proof --root ."
    ]
    assert result["recommended"] == "solo"
    assert result["actions_executed"] is False
    assert result["action_count"] == 0
    assert result["triggered_capabilities"][0]["id"] == "mobile_delivery"
    assert [item["maturity"] for item in result["journeys"]] == [
        "locally_verified_core",
        "controlled_pilot",
        "reference_pilot",
    ]
    assert result["triggered_capabilities"][0]["maturity"] == "candidate_bound_preflight"
    for item in result["journeys"]:
        assert item["verification"]
        assert all(path.startswith("tests/") for path in item["verification"])
        assert all((Path(__file__).parents[1] / path).is_file() for path in item["verification"])
    assert "No independent production-scale" in result["battle_testing"]
    assert all(value is False for value in result["authority"].values())


def test_team_guide_explains_intent_delta_independent_proof_and_human_control():
    result = adoption_guide("team")

    assert result["marker"] == "TEAM_GUIDE_RENDERED"
    assert [item["id"] for item in result["journeys"]] == ["team"]
    text = " ".join(str(value) for value in result["journeys"][0].values()).lower()
    for phrase in ("original intent", "file delta", "independent validation", "agents cannot approve"):
        assert phrase in text


def test_invalid_journey_refuses_without_action():
    try:
        adoption_guide("mobile")
    except AdoptionGuideError as exc:
        assert exc.code == "E_GUIDE_JOURNEY"
        assert "solo, team, enterprise" in str(exc)
    else:
        raise AssertionError("unsupported journey was accepted")


def test_cli_guide_json_and_stable_invalid_error(capsys):
    assert main(["guide", "--journey", "team", "--json"]) == 0
    success = json.loads(capsys.readouterr().out)
    assert success["marker"] == "TEAM_GUIDE_RENDERED"
    assert success["actions_executed"] is False

    assert main(["guide", "--journey", "unknown", "--json"]) == 2
    failure = json.loads(capsys.readouterr().err)
    assert failure == {
        "actions_executed": False,
        "code": "E_GUIDE_JOURNEY",
        "message": "unsupported journey 'unknown'; choose one of: solo, team, enterprise",
        "schema": "factory.adoption-guide.error.v1",
        "supported": ["solo", "team", "enterprise"],
    }


def test_public_evidence_map_withholds_unproven_maturity_claims():
    text = (Path(__file__).parents[1] / "docs" / "CAPABILITY_EVIDENCE.md").read_text(encoding="utf-8")

    for maturity in ("Locally verified core", "Controlled pilot", "Reference pilot", "Candidate-bound preflight"):
        assert maturity in text
    for withheld in ("No hosted multi-tenant service", "No universal sandbox", "no upload", "or approval guarantee"):
        assert withheld.lower() in text.lower()


def test_intent_envelope_is_bound_to_the_approved_spec_and_has_an_obligation():
    root = Path(__file__).parents[1]
    spec = root / "specs" / "adoption-simplification.md"
    envelope = json.loads((root / "envelopes" / "adoption-simplification.json").read_text(encoding="utf-8"))

    assert envelope["source"] == "specs/adoption-simplification.md"
    canonical_spec = spec.read_text(encoding="utf-8").replace("\r\n", "\n").encode("utf-8")
    assert envelope["sealed_hash"] == hashlib.sha256(canonical_spec).hexdigest()
    assert envelope["coherence_score"] == 100
    assert envelope["assumptions"]
