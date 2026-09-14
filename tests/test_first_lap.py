from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from factoryline.first_lap import (
    FirstLapError,
    classify_failure,
    initialize_first_lap,
    promote_incident,
    record_incident,
    verify_activation,
    verify_holdout_boundary,
    verify_observed_first_lap,
    verify_verifier_calibration,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _events():
    return [{"phase": phase, "evidence_sha256": "a" * 64} for phase in ("intake", "candidate_binding", "validation", "failure_handling", "cleanup", "handoff")]


def test_first_lap_init_writes_plain_language_files_and_receipt(tmp_path: Path):
    result = initialize_first_lap(tmp_path, mission="Ship a safe change", journeys=["Create an account", "Recover a failed request"], holdouts=["A revoked session is rejected"])
    assert (tmp_path / "MISSION.md").is_file()
    assert (tmp_path / "END-TO-END.md").is_file()
    assert (tmp_path / ".factory" / "holdouts" / "HOLDOUT.md").is_file()
    assert result["marker"] == "FIRST_LAP_FILES_READY"
    assert result["artifacts"][0]["sha256"] == _sha(tmp_path / "MISSION.md")


def test_first_lap_does_not_overwrite_existing_files(tmp_path: Path):
    (tmp_path / "MISSION.md").write_text("owner content\n", encoding="utf-8")
    initialize_first_lap(tmp_path)
    assert (tmp_path / "MISSION.md").read_text(encoding="utf-8") == "owner content\n"
    with pytest.raises(FirstLapError, match="receipt already exists"):
        initialize_first_lap(tmp_path)


def test_calibration_requires_three_point_oracle():
    result = verify_verifier_calibration(tmp_path := Path("."), {"approved_candidate": "pass", "defective_candidate": "fail", "wrong_candidate": "inconclusive"})
    assert result["state"] == "CALIBRATED"
    blocked = verify_verifier_calibration(tmp_path, {"approved_candidate": "pass", "defective_candidate": "pass", "wrong_candidate": "inconclusive"})
    assert blocked["code"] == "E_CALIBRATION_FAILED"


def test_incident_promotion_chain_is_complete(tmp_path: Path):
    incident = {"incident_id": "publish-timeout", "failure_code": "E_PROVIDER_TIMEOUT", "invariant": "a timeout is never reported as published", "reproducer": "run upload with a dropped connection", "mutation": "replace timeout classification with success", "owner": "release-team"}
    recorded = record_incident(tmp_path, incident)
    assert recorded["status"] == "PROMOTION_READY"
    promoted = promote_incident(tmp_path, incident)
    assert promoted["marker"] == "INCIDENT_PROMOTED_TO_GATE"
    assert json.loads((tmp_path / promoted["path"]).read_text(encoding="utf-8"))["gate"]["required"] is True


def test_incident_duplicate_and_missing_fields_fail_closed(tmp_path: Path):
    incident = {"incident_id": "x", "failure_code": "E_X", "invariant": "never lie", "reproducer": "steps", "mutation": "mutant", "owner": "owner"}
    record_incident(tmp_path, incident)
    with pytest.raises(FirstLapError, match="already recorded"):
        record_incident(tmp_path, incident)
    with pytest.raises(FirstLapError, match="full chain"):
        promote_incident(tmp_path, {"incident_id": "bad"})


def test_holdout_boundary_accepts_verifier_only_file_and_rejects_access(tmp_path: Path):
    holdout = tmp_path / ".factory" / "holdouts" / "HOLDOUT.md"
    holdout.parent.mkdir(parents=True)
    holdout.write_text("secret scenario\n", encoding="utf-8")
    verified = verify_holdout_boundary(tmp_path, {"path": ".factory/holdouts/HOLDOUT.md", "sha256": _sha(holdout), "builder_accessed_paths": []})
    assert verified["state"] == "VERIFIED"
    blocked = verify_holdout_boundary(tmp_path, {"path": str(holdout), "sha256": _sha(holdout), "builder_accessed_paths": [".factory/holdouts/HOLDOUT.md"]})
    assert blocked["code"] == "E_HOLDOUT_BUILDER_ACCESS"


def test_observed_first_lap_requires_exact_order_and_evidence():
    assert verify_observed_first_lap(_events())["state"] == "OBSERVED"
    assert verify_observed_first_lap(list(reversed(_events())))["code"] == "E_FIRST_LAP_SEQUENCE"
    missing = _events()
    missing[2]["evidence_sha256"] = "bad"
    assert verify_observed_first_lap(missing)["code"] == "E_FIRST_LAP_EVIDENCE"


def test_only_transient_provider_failure_is_retryable():
    assert classify_failure("transient_provider_failure", provider="openvsx", retry_after_seconds=10)["retry_allowed"] is True
    for kind in ("definitive_product_failure", "unverifiable_candidate_identity", "stale_evidence", "environment_setup_failure"):
        assert classify_failure(kind)["retry_allowed"] is False
        assert classify_failure(kind, retry_after_seconds=10)["retry_after_seconds"] is None


def test_activation_requires_all_three_controls():
    calibration = verify_verifier_calibration(Path("."), {"approved_candidate": "pass", "defective_candidate": "fail", "wrong_candidate": "blocked"})
    observed = verify_observed_first_lap(_events())
    blocked = verify_activation(Path("."), calibration=calibration, holdout={"state": "BLOCKED"}, observed=observed)
    assert blocked["state"] == "BLOCKED"
    holdout = {"state": "VERIFIED", "boundary_sha256": "b" * 64}
    ready = verify_activation(Path("."), calibration=calibration, holdout=holdout, observed=observed)
    assert ready["state"] == "READY"

