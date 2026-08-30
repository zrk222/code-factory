from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from factoryline.continuity import ContinuityPrincipal, ContinuityStore
from factoryline.enterprise_receipts import generate_key_material
from factoryline.cli import main
from factoryline.gauntlet import (
    GauntletError,
    _card_from_core,
    admit_gauntlet,
    challenge_survival_card,
    compile_gauntlet_proposal,
    gauntlet_status,
    run_gauntlet,
    seal_survival_card,
    validate_survival_card,
    verify_gauntlet_admission,
    verify_gauntlet_proposal,
    verify_survival_card,
    write_gauntlet_proposal,
    write_survival_card_artifacts,
)


def _e2e(*, hollow: bool = False) -> dict[str, object]:
    return {
        "schema": "factory.e2e_proof_manifest.v1",
        "id": "approval-sabotage",
        "approval": {"state": "approved", "approved_by": "qa-owner"},
        "working_directory": ".",
        "timeout_seconds": 10,
        "network_egress": "not_granted",
        "positive": {"argv": [sys.executable, "-c", "from pathlib import Path; Path('proof.txt').write_text('ok')"]},
        "negative": {"argv": [sys.executable, "-c", "pass"] if hollow else [sys.executable, "-c", "import sys; sys.exit(1)"]},
        "artifact_paths": ["proof.txt"],
    }


def _reality() -> dict[str, object]:
    return {
        "schema": "factory.reality-check-manifest.v1",
        "id": "approval-promise",
        "approval": {"state": "approved", "approved_by": "qa-owner"},
        "behavior": {
            "promise": "Only a manager can approve a request.",
            "happy_path": "A manager approval is recorded.",
            "failure_case": "A non-manager approval is rejected.",
        },
        "intent_assertions": [
            {"id": "manager-approved", "statement": "Manager approval is recorded.", "evidence": "positive"},
            {"id": "non-manager-blocked", "statement": "Non-manager approval is rejected.", "evidence": "negative"},
        ],
        "e2e_manifest": "approval.e2e.json",
    }


def _source() -> dict[str, object]:
    return {
        "schema": "factory.gauntlet-source.v1",
        "id": "approval-gauntlet",
        "promises": [
            {
                "id": "approval-authorization",
                "statement": "Only a manager can approve a request.",
                "reality_manifest": "approval.reality.json",
                "sabotage_cases": [
                    {
                        "id": "wrong-role",
                        "risk_tag": "authorization",
                        "summary": "A non-manager approval must be rejected.",
                        "e2e_manifest": "approval.e2e.json",
                    }
                ],
            }
        ],
    }


def _write(root: Path, *, hollow: bool = False, continuity: dict[str, object] | None = None) -> Path:
    (root / "approval.e2e.json").write_text(json.dumps(_e2e(hollow=hollow)), encoding="utf-8")
    (root / "approval.reality.json").write_text(json.dumps(_reality()), encoding="utf-8")
    source = root / "gauntlet.json"
    payload = _source()
    if continuity is not None:
        payload["continuity"] = continuity
    source.write_text(json.dumps(payload), encoding="utf-8")
    return source


def _proposal(root: Path, *, hollow: bool = False) -> Path:
    source = _write(root, hollow=hollow)
    proposal = compile_gauntlet_proposal(root, source)
    return write_gauntlet_proposal(root, proposal)


def _admission(root: Path, proposal: Path) -> Path:
    result = admit_gauntlet(
        root,
        proposal,
        approved_by="qa-owner",
        rationale="Run the declared local approval failure proof.",
        confirmation="ADMIT approval-gauntlet",
        valid_for_minutes=10,
    )
    return Path(result["path"])


def _verified_continuity(root: Path) -> dict[str, object]:
    store = ContinuityStore(root / ".factory" / "continuity.sqlite3")
    purpose = "delivery-review@1"
    writer = ContinuityPrincipal("continuity-writer", "team-a", ("writer",), (purpose,))
    promoter = ContinuityPrincipal("continuity-promoter", "team-a", ("promoter",), (purpose,))
    store.record(writer, {
        "schema": "factory.continuity.record.v1",
        "tenant_id": "team-a",
        "record_type": "decision",
        "memory_ref": "opaque://approved-proof-context",
        "purpose": {"id": "delivery-review", "version": "1"},
        "scope": {"repository_ref": "repo:approval"},
        "evidence_refs": ["receipt:approved-context"],
        "summary": "private continuity summary that must never enter the Gauntlet artifact",
        "expires_at": "2030-01-01T00:00:00Z",
    }, idempotency_key="approved-context", record_id="approved-context")
    store.promote(promoter, "team-a", "approved-context", reason="independent review")
    return {
        "db": ".factory/continuity.sqlite3",
        "tenant_id": "team-a",
        "purpose_ref": purpose,
        "scope_ref": "repo:approval",
        "principal": {"subject": "continuity-reader", "roles": ["reader"], "purposes": [purpose]},
        "record_ids": ["approved-context"],
    }


def test_gauntlet_proposal_binds_declared_intent_taxonomy_and_exact_e2e_bytes_without_execution(tmp_path: Path) -> None:
    proposal_path = _proposal(tmp_path)

    verification = verify_gauntlet_proposal(tmp_path, proposal_path)

    assert verification["ok"] is True
    assert verification["facts"]["case_count"] == 1
    payload = json.loads(proposal_path.read_text(encoding="utf-8"))
    case = payload["proposals"][0]
    assert case["sabotage"]["mutation"] == "missing_or_wrong_authority"
    assert case["e2e"]["negative_argv"][-1] == "import sys; sys.exit(1)"
    assert not (tmp_path / "proof.txt").exists()
    assert all(value is False for value in payload["authority"].values())


def test_gauntlet_proposal_fails_closed_when_declared_e2e_bytes_drift(tmp_path: Path) -> None:
    proposal_path = _proposal(tmp_path)
    e2e = _e2e(hollow=True)
    (tmp_path / "approval.e2e.json").write_text(json.dumps(e2e), encoding="utf-8")

    verification = verify_gauntlet_proposal(tmp_path, proposal_path)

    assert (verification["ok"], verification["marker"]) == (False, "GAUNTLET_PROPOSAL_STALE")


def test_gauntlet_optionally_binds_only_verified_redacted_continuity_metadata(tmp_path: Path) -> None:
    source = _write(tmp_path, continuity=_verified_continuity(tmp_path))
    proposal = compile_gauntlet_proposal(tmp_path, source)
    proposal_path = write_gauntlet_proposal(tmp_path, proposal)

    binding = proposal["continuity"]
    assert binding["marker"] == "GAUNTLET_CONTINUITY_METADATA_BOUND"
    assert binding["records"][0]["record_type"] == "decision"
    assert "private continuity summary" not in json.dumps(proposal)
    assert "opaque://approved-proof-context" not in json.dumps(proposal)
    assert verify_gauntlet_proposal(tmp_path, proposal_path)["ok"] is True
    result = run_gauntlet(tmp_path, proposal_path, _admission(tmp_path, proposal_path))
    assert result["card"]["continuity"]["records"][0]["record_type"] == "decision"
    assert gauntlet_status(tmp_path, "approval-gauntlet")["entries"][0]["continuity"]["bound"] is True

    store = ContinuityStore(tmp_path / ".factory" / "continuity.sqlite3")
    with store._session() as db:  # Test only: force stale metadata after a sealed proposal.
        db.execute("UPDATE continuity_records SET expires_at = ? WHERE record_id = ?", ("2020-01-01T00:00:00Z", "approved-context"))
    stale = verify_gauntlet_proposal(tmp_path, proposal_path)
    assert (stale["ok"], stale["reason"]) == (False, "GAUNTLET_CONTINUITY_STALE")


def test_gauntlet_requires_named_admission_before_running_any_command(tmp_path: Path) -> None:
    proposal_path = _proposal(tmp_path)

    with pytest.raises(GauntletError) as exc:
        run_gauntlet(tmp_path, proposal_path, None)

    assert exc.value.code == "GAUNTLET_ADMISSION_REQUIRED"
    assert not (tmp_path / "proof.txt").exists()


def test_admitted_gauntlet_survives_and_emits_public_offline_verifiable_card(tmp_path: Path) -> None:
    proposal_path = _proposal(tmp_path)
    admission = _admission(tmp_path, proposal_path)
    assert verify_gauntlet_admission(tmp_path, admission, proposal_path)["ok"] is True
    result = run_gauntlet(tmp_path, proposal_path, admission)

    card = result["card"]
    assert (card["marker"], card["ok"]) == ("GAUNTLET_SURVIVED", True)
    assert card["summary"] == {"case_count": 1, "survived_count": 1, "hollow_count": 0, "blocked_count": 0, "unproven_promise_count": 0}
    assert validate_survival_card(card) is card
    verification = verify_survival_card(Path(result["path"]))
    assert verification["signature"] == "not_supplied"
    assert Path(result["artifacts"]["svg"]).read_text(encoding="utf-8").startswith("<svg")
    assert Path(write_survival_card_artifacts(card, tmp_path / "copied-card")["markdown"]).is_file()
    assert challenge_survival_card(Path(result["path"]))["marker"] == "GAUNTLET_CARD_MUTATION_REJECTED"
    with pytest.raises(GauntletError) as exc:
        run_gauntlet(tmp_path, proposal_path, admission)
    assert exc.value.code == "GAUNTLET_ADMISSION_CONSUMED"


def test_hollow_case_is_visible_on_card_and_never_claims_survival(tmp_path: Path) -> None:
    proposal_path = _proposal(tmp_path, hollow=True)
    result = run_gauntlet(tmp_path, proposal_path, _admission(tmp_path, proposal_path))

    card = result["card"]
    assert (card["marker"], card["ok"]) == ("GAUNTLET_HOLLOW", False)
    assert card["outcomes"][0]["status"] == "hollow"
    assert card["unproven_promises"] == ["approval-authorization"]
    assert "production readiness" in card["scope_limits"][1]


def test_survival_card_rejects_tamper_and_optional_dsse_binds_exact_card_hash(tmp_path: Path) -> None:
    proposal_path = _proposal(tmp_path)
    result = run_gauntlet(tmp_path, proposal_path, _admission(tmp_path, proposal_path))
    card_path = Path(result["path"])
    tampered = json.loads(card_path.read_text(encoding="utf-8"))
    tampered["summary"]["survived_count"] = 2
    with pytest.raises(GauntletError) as exc:
        validate_survival_card(tampered)
    assert exc.value.code == "SURVIVAL_CARD_INVALID"

    try:
        material = generate_key_material(out_dir=tmp_path / "keys", keyid="qa-key", identity="qa@example.test", issuer="https://issuer.example.test")
    except Exception as exc:  # pragma: no cover - optional enterprise extra may be absent.
        pytest.skip(f"enterprise crypto unavailable: {exc}")
    envelope = tmp_path / "gauntlet.dsse.json"
    seal_survival_card(
        card_path,
        private_key_path=Path(material["private_key"]),
        keyid="qa-key",
        identity="qa@example.test",
        issuer="https://issuer.example.test",
        tenant_id="local",
        out=envelope,
    )
    verified = verify_survival_card(card_path, envelope_path=envelope, trust_root_path=Path(material["trust_root"]))
    assert verified["signature"]["verification"] == "offline_dsse_ed25519"


def test_survival_card_rejects_resealed_promise_reality_mismatch(tmp_path: Path) -> None:
    proposal_path = _proposal(tmp_path)
    result = run_gauntlet(tmp_path, proposal_path, _admission(tmp_path, proposal_path))
    card = result["card"]
    core = {key: value for key, value in card.items() if key not in {"card_sha256", "card_markdown", "card_svg"}}
    core["outcomes"][0]["promise"]["statement"] = "A different promise is being tested."
    forged = _card_from_core(core)
    with pytest.raises(GauntletError) as exc:
        validate_survival_card(forged)
    assert exc.value.code == "SURVIVAL_CARD_INVALID"
    assert "Reality Check promise" in str(exc.value)


def test_gauntlet_status_is_read_only_and_projects_existing_card(tmp_path: Path) -> None:
    proposal_path = _proposal(tmp_path)
    run_gauntlet(tmp_path, proposal_path, _admission(tmp_path, proposal_path))

    status = gauntlet_status(tmp_path, "approval-gauntlet")

    assert status["marker"] == "GAUNTLET_STATUS_READ_ONLY"
    assert status["entries"][0]["marker"] == "GAUNTLET_SURVIVED"
    assert status["entries"][0]["continuity"] == {"bound": False, "marker": "GAUNTLET_CONTINUITY_NOT_BOUND", "record_count": 0}
    assert all(value is False for value in status["authority"].values())


def test_gauntlet_cli_requires_admission_then_exposes_only_public_card_facts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = _write(tmp_path)
    assert main(["gauntlet", "plan", "--root", str(tmp_path), "--source", source.name, "--json"]) == 0
    planned = json.loads(capsys.readouterr().out)
    proposal = Path(planned["path"])
    assert main([
        "gauntlet", "run", str(proposal.relative_to(tmp_path)), "--root", str(tmp_path), "--json",
    ]) == 2
    assert json.loads(capsys.readouterr().err)["marker"] == "GAUNTLET_ADMISSION_REQUIRED"
    assert main([
        "gauntlet", "admit", str(proposal.relative_to(tmp_path)), "--root", str(tmp_path),
        "--approved-by", "qa-owner", "--rationale", "Run the declared local proof.",
        "--confirmation", "ADMIT approval-gauntlet", "--json",
    ]) == 0
    admission = Path(json.loads(capsys.readouterr().out)["path"])
    assert main([
        "gauntlet", "run", str(proposal.relative_to(tmp_path)), "--root", str(tmp_path),
        "--admission", str(admission.relative_to(tmp_path)), "--json",
    ]) == 0
    card = json.loads(capsys.readouterr().out)["card"]
    assert card["marker"] == "GAUNTLET_SURVIVED"
    assert "_captures" not in json.dumps(card)
