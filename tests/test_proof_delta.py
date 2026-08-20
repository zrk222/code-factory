from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

import pytest

from factoryline.mission_graph import MissionGraphError, apply_mission_event
from factoryline.proof_delta import ProofDeltaError, create_proof_delta, proof_delta_status, verify_proof_delta
from test_mission_graph import _approve, _pipeline, _receipt


def _candidate(root: Path, name: str, mission: dict, diff: str, evidence_name: str, evidence_text: str = "proof") -> Path:
    evidence = root / evidence_name
    evidence.write_text(evidence_text, encoding="utf-8")
    path = root / name
    path.write_text(json.dumps({
        "schema": "factory.mission.candidate.v1", "mission_id": mission["id"],
        "candidate": {"diff_sha256": diff, "changed_paths": ["src/approval.py"]},
        "evidence": [{"path": evidence_name, "sha256": sha256(evidence.read_bytes()).hexdigest(), "kind": "counterexample"}],
    }), encoding="utf-8")
    return path


def _failure(root: Path, mission: dict) -> Path:
    return _receipt(root, "failure.json", "factory.mission.validation-failure.v1", mission["id"])


def test_proof_delta_requires_changed_candidate_and_new_evidence(tmp_path: Path) -> None:
    mission = _pipeline(tmp_path)
    before = _candidate(tmp_path, "before.json", mission, "a" * 64, "before.txt")
    after = _candidate(tmp_path, "after.json", mission, "b" * 64, "after.txt")
    receipt = tmp_path / ".factory" / "proof-deltas" / "approval.json"

    result = create_proof_delta(
        tmp_path, Path(mission["path"]), before, after, _failure(tmp_path, mission),
        mission["completion_contract"]["criteria"][0]["id"], receipt,
    )

    assert result["marker"] == "PROOF_DELTA_ADVANCE"
    verified = verify_proof_delta(tmp_path, receipt)
    assert verified["valid"] is True
    assert verified["eligible"] is True
    assert verified["new_evidence"][0]["path"] == "after.txt"
    assert all(value is False for value in verified["authority"].values())


def test_proof_delta_halts_without_evidence_gain(tmp_path: Path) -> None:
    mission = _pipeline(tmp_path)
    before = _candidate(tmp_path, "before.json", mission, "a" * 64, "same.txt")
    after = _candidate(tmp_path, "after.json", mission, "b" * 64, "same.txt")
    receipt = tmp_path / ".factory" / "proof-deltas" / "halt.json"

    result = create_proof_delta(
        tmp_path, Path(mission["path"]), before, after, _failure(tmp_path, mission),
        mission["completion_contract"]["criteria"][0]["id"], receipt,
    )

    assert result["marker"] == "PROOF_DELTA_NO_EVIDENCE_GAIN"
    assert verify_proof_delta(tmp_path, receipt)["eligible"] is False
    assert proof_delta_status(tmp_path)["marker"] == "PROOF_DELTA_NO_EVIDENCE_GAIN"


def test_mission_graph_blocks_legacy_or_no_gain_retry(tmp_path: Path) -> None:
    mission = _pipeline(tmp_path)
    apply_mission_event(Path(mission["path"]), tmp_path, "approve", "mission-owner", "owner", "approve", _approve(tmp_path, mission))
    before = _candidate(tmp_path, "before.json", mission, "a" * 64, "same.txt")
    apply_mission_event(Path(mission["path"]), tmp_path, "candidate_ready", "worker", "worker", "candidate", before)
    failure = _failure(tmp_path, mission)
    criterion_id = mission["completion_contract"]["criteria"][0]["id"]
    apply_mission_event(Path(mission["path"]), tmp_path, "validation_failed", "verifier", "validator", "failure", failure, {"criterion_id": criterion_id})
    legacy = _receipt(tmp_path, "legacy-retry.json", "factory.mission.retry.v1", mission["id"])
    with pytest.raises(MissionGraphError, match="MISSION_GRAPH_PROOF_DELTA_REQUIRED"):
        apply_mission_event(Path(mission["path"]), tmp_path, "retry", "mission-owner", "owner", "legacy", legacy, {"fresh_context": True})

    after = _candidate(tmp_path, "after.json", mission, "b" * 64, "same.txt")
    delta = tmp_path / ".factory" / "proof-deltas" / "halt.json"
    create_proof_delta(tmp_path, Path(mission["path"]), before, after, failure, criterion_id, delta)
    with pytest.raises(MissionGraphError, match="MISSION_GRAPH_NO_EVIDENCE_GAIN"):
        apply_mission_event(Path(mission["path"]), tmp_path, "retry", "mission-owner", "owner", "halt", delta, {"fresh_context": True})


def test_proof_delta_rejects_tampered_receipt(tmp_path: Path) -> None:
    mission = _pipeline(tmp_path)
    before = _candidate(tmp_path, "before.json", mission, "a" * 64, "before.txt")
    after = _candidate(tmp_path, "after.json", mission, "b" * 64, "after.txt")
    receipt = tmp_path / ".factory" / "proof-deltas" / "tampered.json"
    create_proof_delta(tmp_path, Path(mission["path"]), before, after, _failure(tmp_path, mission), mission["completion_contract"]["criteria"][0]["id"], receipt)
    value = json.loads(receipt.read_text(encoding="utf-8")); value["criterion_id"] = "wrong"; receipt.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ProofDeltaError, match="PROOF_DELTA_INTEGRITY_INVALID"):
        verify_proof_delta(tmp_path, receipt)
