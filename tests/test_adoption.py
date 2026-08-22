from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from factoryline.adoption import (
    AdoptionError,
    adoption_status,
    export_adoption_status,
    proof_card_from_receipt,
    record_adoption_event,
    run_first_proof,
    verify_proof_card,
)
from factoryline.cli import main


def test_first_proof_catches_the_deliberately_hollow_check_and_writes_a_private_card(tmp_path: Path) -> None:
    result = run_first_proof(tmp_path, observed_at=datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc))

    assert result["activation"]["marker"] == "HOLLOW_TEST_DETECTED"
    assert result["proof"]["marker"] == "HOLLOW_E2E_TEST"
    assert result["proof_card"]["card"]["hollow_test_detected"] is True
    assert result["proof_card"]["card"]["negative_case_rejected"] is False
    assert Path(result["proof_card"]["paths"]["svg"]).is_file()
    assert result["adoption_status"]["milestones"] == {
        "first_proof_completed": 1,
        "proof_card_saved": 1,
        "proof_receipt_saved": 1,
        "seven_day_return": 0,
    }

    svg = Path(result["proof_card"]["paths"]["svg"]).read_text(encoding="utf-8")
    assert "HOLLOW_TEST_DETECTED" in svg
    assert str(tmp_path) not in svg
    assert "raise SystemExit" not in svg
    assert "local-first-proof-user" not in svg


def test_proof_card_reuses_only_verified_receipt_facts_and_rejects_tampering(tmp_path: Path) -> None:
    first = run_first_proof(tmp_path)
    receipt_path = Path(first["proof_artifacts"]["paths"]["json"])
    result = proof_card_from_receipt(tmp_path, receipt_path, Path("share-again"))

    assert result["card"]["source_receipt_sha256"] == first["proof"]["receipt_sha256"]
    tampered = dict(result["card"])
    tampered["headline"] = "Everything is production ready"
    with pytest.raises(AdoptionError, match="hash does not match"):
        verify_proof_card(tampered)


def test_local_adoption_funnel_withholds_provider_metrics_and_never_stores_identity(tmp_path: Path) -> None:
    observed = datetime(2026, 8, 1, tzinfo=timezone.utc)
    record_adoption_event(tmp_path, "first_proof_completed", observed_at=observed)
    record_adoption_event(tmp_path, "seven_day_return", observed_at=observed + timedelta(days=8))
    exported = export_adoption_status(tmp_path, Path(".factory/public-adoption.json"))

    assert exported["status"]["funnel"]["page_visit"] is None
    assert exported["status"]["funnel"]["install"] is None
    assert exported["status"]["funnel"]["first_proof"] == 1
    assert exported["status"]["funnel"]["seven_day_return"] == 1
    serialized = json.dumps(exported, sort_keys=True)
    assert str(tmp_path) not in serialized
    assert "user_id" not in serialized
    assert "repository" not in serialized


def test_adoption_event_rejects_unknown_milestones_and_bad_evidence(tmp_path: Path) -> None:
    with pytest.raises(AdoptionError, match="milestone must be"):
        record_adoption_event(tmp_path, "clicked_everything")
    with pytest.raises(AdoptionError, match="lowercase SHA-256"):
        record_adoption_event(tmp_path, "proof_card_saved", evidence_sha256="not-a-digest")


def test_first_proof_cli_is_successful_because_detection_is_the_demo_outcome(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["first-proof", "--root", str(tmp_path), "--json"])
    output = json.loads(capsys.readouterr().out)

    assert code == 0
    assert output["activation"]["demo"] is True
    assert output["activation"]["marker"] == "HOLLOW_TEST_DETECTED"


def test_adoption_cli_reports_local_counts_without_claiming_conversion(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["adoption", "record", "first_proof_completed", "--root", str(tmp_path), "--json"]) == 0
    capsys.readouterr()
    assert main(["adoption", "status", "--root", str(tmp_path), "--json"]) == 0
    status = json.loads(capsys.readouterr().out)

    assert status["events"] == 1
    assert status["funnel"]["first_proof"] == 1
    assert status["measurement"] == "local_opt_in_events_only"


def test_adoption_status_fails_closed_for_a_tampered_event(tmp_path: Path) -> None:
    event = record_adoption_event(tmp_path, "first_proof_completed")
    path = Path(event["path"])
    value = json.loads(path.read_text(encoding="utf-8"))
    value["milestone"] = "seven_day_return"
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(AdoptionError, match="malformed or tampered"):
        adoption_status(tmp_path)
