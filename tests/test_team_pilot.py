from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.team_pilot import (
    TeamPilotError,
    evaluate_team_pilot_readiness,
    validate_team_pilot_manifest,
    validate_team_pilot_receipt,
    write_team_pilot_artifacts,
)


REQUIRED_KINDS = [
    "commercial_terms_review",
    "data_retention_decision",
    "deployment_security_review",
    "design_partner_selection",
    "support_and_incident_owner",
]


def _sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _packaging(root: Path, *, team_purchasable: bool = False) -> None:
    docs = root / "docs"
    docs.mkdir(parents=True)
    payload = {
        "schema": "factory.commercial-packaging.v1",
        "governance": {"classification": "human_controlled", "automation_may_activate": False},
        "current_verdict": "COMMERCIALIZATION_STAGED_NOT_SELLABLE",
        "tiers": {"team_proof_hub": {"availability": "design_partner_only", "purchasable": team_purchasable}},
    }
    (docs / "COMMERCIAL_PACKAGING.json").write_text(json.dumps(payload), encoding="utf-8")


def _manifest(root: Path, **overrides: object) -> Path:
    _packaging(root)
    evidence: list[dict[str, str]] = []
    for kind in REQUIRED_KINDS:
        path = root / f"{kind}.json"
        path.write_text(json.dumps({"kind": kind, "reviewed": True}), encoding="utf-8")
        evidence.append({"kind": kind, "path": path.name, "sha256": _sha(path)})
    payload: dict[str, object] = {
        "schema": "factory.team-pilot-launch.v1",
        "pilot_id": "team-alpha",
        "owner": "pilot-owner",
        "partner_count": 3,
        "governance": "human_controlled",
        "delivery_mode": "customer_managed_reference",
        "evidence": evidence,
    }
    payload.update(overrides)
    path = root / "team-pilot.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_team_pilot_readiness_binds_all_required_evidence_and_writes_public_receipt(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    validated = validate_team_pilot_manifest(tmp_path, manifest)
    receipt = evaluate_team_pilot_readiness(tmp_path, manifest)

    assert [entry["kind"] for entry in validated["evidence"]] == REQUIRED_KINDS
    assert receipt["schema"] == "factory.team-pilot-readiness.v1"
    assert receipt["marker"] == "TEAM_PILOT_READY_FOR_OWNER_REVIEW"
    assert receipt["verdict"] == "READY_FOR_OWNER_REVIEW"
    assert receipt["commercial_boundary"]["purchasable"] is False
    assert receipt["authority"]["payment"] is False
    assert receipt["authority"]["marketplace_activation"] is False
    assert "does not accept a customer" in receipt["receipt_markdown"]
    assert validate_team_pilot_receipt(receipt) is receipt

    artifacts = write_team_pilot_artifacts(receipt, tmp_path / "packet")
    assert artifacts["marker"] == "TEAM_PILOT_ARTIFACTS_WRITTEN"
    assert set(artifacts["paths"]) == {"json", "markdown", "mermaid"}
    written = json.loads(Path(artifacts["paths"]["json"]).read_text(encoding="utf-8"))
    assert written["receipt_sha256"] == receipt["receipt_sha256"]


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"partner_count": 4}, "E_TEAM_PILOT_PARTNER_CAP"),
        ({"partner_count": True}, "E_TEAM_PILOT_PARTNER_CAP"),
        ({"governance": "supervised"}, "E_TEAM_PILOT_GOVERNANCE"),
        ({"delivery_mode": "factory_managed"}, "E_TEAM_PILOT_DELIVERY_MODE"),
        ({"evidence": []}, "E_TEAM_PILOT_EVIDENCE_KIND"),
    ],
)
def test_team_pilot_manifest_fails_closed_on_scope_and_governance_errors(
    tmp_path: Path, overrides: dict[str, object], code: str,
) -> None:
    manifest = _manifest(tmp_path, **overrides)

    with pytest.raises(TeamPilotError) as exc:
        evaluate_team_pilot_readiness(tmp_path, manifest)

    assert exc.value.code == code


def test_team_pilot_rejects_digest_drift_and_workspace_escape_before_owner_review(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    first = tmp_path / payload["evidence"][0]["path"]
    first.write_text("changed after review", encoding="utf-8")

    with pytest.raises(TeamPilotError) as exc:
        evaluate_team_pilot_readiness(tmp_path, manifest)
    assert exc.value.code == "E_TEAM_PILOT_EVIDENCE_DIGEST"

    manifest = _manifest(tmp_path / "escaped")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["evidence"][0]["path"] = "../outside.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(TeamPilotError) as exc:
        evaluate_team_pilot_readiness(manifest.parent, manifest)
    assert exc.value.code == "E_TEAM_PILOT_EVIDENCE_PATH"


def test_team_pilot_rejects_commercial_boundary_drift_and_tampered_receipts(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    packaging_path = tmp_path / "docs" / "COMMERCIAL_PACKAGING.json"
    packaging = json.loads(packaging_path.read_text(encoding="utf-8"))
    packaging["tiers"]["team_proof_hub"]["purchasable"] = True
    packaging_path.write_text(json.dumps(packaging), encoding="utf-8")

    with pytest.raises(TeamPilotError) as exc:
        evaluate_team_pilot_readiness(tmp_path, manifest)
    assert exc.value.code == "E_TEAM_PILOT_COMMERCIAL_BOUNDARY"

    manifest = _manifest(tmp_path / "tampered")
    receipt = evaluate_team_pilot_readiness(manifest.parent, manifest)
    receipt["authority"]["payment"] = True
    with pytest.raises(TeamPilotError) as exc:
        validate_team_pilot_receipt(receipt)
    assert exc.value.code == "E_TEAM_PILOT_RECEIPT_INVALID"


def test_team_pilot_cli_is_json_safe_and_receipt_verifiable(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = _manifest(tmp_path)

    code = main([
        "team-pilot", "readiness", "--root", str(tmp_path), "--manifest", manifest.name,
        "--out-dir", str(tmp_path / "packet"), "--json",
    ])
    output = json.loads(capsys.readouterr().out)
    receipt_path = Path(output["artifacts"]["paths"]["json"])
    assert code == 0
    assert output["receipt"]["marker"] == "TEAM_PILOT_READY_FOR_OWNER_REVIEW"

    code = main(["team-pilot", "verify", str(receipt_path), "--json"])
    verified = json.loads(capsys.readouterr().out)
    assert code == 0
    assert verified["receipt"]["verdict"] == "READY_FOR_OWNER_REVIEW"
