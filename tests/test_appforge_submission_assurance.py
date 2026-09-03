from __future__ import annotations

import hashlib
import json
import struct
import zlib
from pathlib import Path

from factoryline.app_review_gate import RULES, verify_app_review_readiness
from factoryline.appforge_store_media import verify_store_media
from factoryline.appforge_submission_assurance import verify_submission_assurance
from factoryline.appforge_quality_audit import CONDITIONAL_CHECKS, DESIGN_CHECKS, STACK_CHECKS, verify_quality_audit
from factoryline.oracle_firewall import capture_intent_handoff, seal_oracle_contract
from factoryline.saas_proof import verify_saas_proof
from factoryline.saas_proof import _sha as _receipt_sha


CANDIDATE = {"bundle_identifier": "com.example.assured", "version": "2.0.0", "build_number": "200", "source_commit": "b" * 40}
AGENT = {"schema": "factory.agent-identity.v1", "subject": "assurance-owner", "provider": "local", "model": "declared-model"}


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _png(path: Path, width: int, height: int, *, color_type: int = 2, seed: bytes = b"\x00") -> Path:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    channels = 4 if color_type == 6 else 3
    raw = b"\x00" + (seed * width * channels)
    value = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    return path


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _app_review(tmp_path: Path) -> Path:
    conditional = [key for key, _, mode, _, _ in RULES if mode == "conditional"]
    applicability = {key: {"status": "required", "reviewed_by": "Release Owner", "rationale": "This capability is present in the reviewed candidate."} for key in conditional}
    contract = _write(tmp_path / "review-contract.json", {"candidate": CANDIDATE, "applicability": applicability})
    evidence = _write(tmp_path / "review-evidence.json", {"candidate": CANDIDATE, "checks": {key: True for key, _, _, _, _ in RULES}})
    verify_app_review_readiness(tmp_path, contract, evidence, Path(".factory/appforge/app-review.json"))
    return tmp_path / ".factory/appforge/app-review.json"


def _media(tmp_path: Path) -> Path:
    first, second = _png(tmp_path / "media" / "launch.png", 10, 20), _png(tmp_path / "media" / "value.png", 10, 20, seed=b"\x01")
    intent = "a" * 64
    contract = _write(tmp_path / "media-contract.json", {
        "schema": "factory.appforge.store-media-contract.v1", "candidate": CANDIDATE, "intent_sha256": intent, "require_no_alpha": True,
        "media_sets": [{"id": "iphone", "min_count": 2, "max_count": 2, "accepted_dimensions": [{"width": 10, "height": 20}], "required_journeys": ["launch", "value"], "allowed_capture_sources": ["physical_device"]}],
    })
    evidence = _write(tmp_path / "media-evidence.json", {
        "schema": "factory.appforge.store-media-evidence.v1", "candidate": CANDIDATE, "intent_sha256": intent,
        "review": {"representative_confirmed_by": "Design Owner", "storyboard_confirmed_by": "Product Owner", "confirmed_at": "2026-08-31T12:00:00Z"},
        "captures": [
            {"id": "launch", "set_id": "iphone", "path": "media/launch.png", "sha256": _sha(first), "route": "/", "journey": "launch", "capture_source": "physical_device"},
            {"id": "value", "set_id": "iphone", "path": "media/value.png", "sha256": _sha(second), "route": "/value", "journey": "value", "capture_source": "physical_device"},
        ],
    })
    verify_store_media(tmp_path, contract, evidence, Path(".factory/appforge/store-media.json"))
    return tmp_path / ".factory/appforge/store-media.json"


def _saas(tmp_path: Path) -> Path:
    types = ["auth_success", "authorization_bound", "checkout_completed", "webhook_verified", "entitlement_granted", "feature_access"]
    events = [{"id": f"e{index}", "provider_event_id": f"provider-{index}", "sequence": index, "type": event_type, "subject": "user", "tenant": "tenant", "role": "member", "sku": "pro", "entitlement": "pro", "verified": True, "issuer": "https://issuer.example" if event_type == "auth_success" else None, "audience": "app" if event_type == "auth_success" else None, "token_active": True if event_type == "auth_success" else None} for index, event_type in enumerate(types, 1)]
    contract = _write(tmp_path / "saas-contract.json", {"schema": "factory.saas-proof.contract.v1", "app_id": "assured", "release_candidate": CANDIDATE, "provider": {"name": "oidc", "protocol": "oidc", "flow": "authorization_code_pkce", "issuer": "https://issuer.example", "audience": "app", "pkce_required": True, "claims": {"subject": "sub", "tenant": "tenant", "roles": "roles"}}, "promises": [{"id": "pro", "sku": "pro", "entitlement": "pro"}]})
    evidence = _write(tmp_path / "saas-evidence.json", {"schema": "factory.saas-proof.evidence.v1", "app_id": "assured", "build_id": "200", "release_candidate": CANDIDATE, "events": events})
    verify_saas_proof(tmp_path, contract, evidence, Path(".factory/saas-proof/latest.json"))
    return tmp_path / ".factory/saas-proof/latest.json"


def _assurance_contract(tmp_path: Path) -> Path:
    return _write(tmp_path / "assurance-contract.json", {"schema": "factory.appforge.submission-assurance-contract.v1", "candidate": CANDIDATE, "reviewer_packet": {"support_url": "https://example.com/support", "privacy_url": "https://example.com/privacy", "review_notes_sha256": "c" * 64, "reviewer_access_instructions_sha256": "d" * 64, "approved_by": "Release Owner", "approved_at": "2026-08-31T12:00:00Z"}})


def _oracle_authority(tmp_path: Path) -> Path:
    intent = tmp_path / "original-intent.md"
    policy = tmp_path / "sources" / "apple-policy.md"
    intent.write_text("The app must restore eligible subscriptions safely.", encoding="utf-8")
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text("Trusted policy snapshot.", encoding="utf-8")
    handoff = capture_intent_handoff(tmp_path, intent, AGENT, "appforge-assurance", Path(".factory/oracles/handoffs/appforge-assurance.json"))
    def rule(identifier, statement, **extra):
        return {"id": identifier, "statement": statement, "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True, **extra}
    contract = _write(tmp_path / "oracle-contract-input.json", {"schema": "factory.oracle-contract-input.v1", "id": "appforge-assurance", "version": 1, "approved_by": "Release Owner", "approval_rationale": "The owner reviewed policy, intent, and the submission candidate.", "scope_paths": ["."], "handoff": handoff["path"], "sources": [{"id": "apple-policy", "origin": "trusted_source", "path": "sources/apple-policy.md"}], "requirements": [rule("restore", "Restore works for an eligible user.")], "forbidden_behaviors": [rule("double-charge", "Restore does not create another charge.")], "gates": [rule("accessibility", "Accessibility review is complete.", comparison="present", value=True)], "exceptions": [{"id": "offline", "statement": "Offline recovery needs future review.", "origin": "human_confirmed", "effect": "advisory", "source_id": "original-intent", "critical": False}], "negative_cases": [rule("expired", "Expired access cannot restore.")], "invariants": [rule("candidate", "Evidence stays candidate-bound.")], "tests": [rule("restore-test", "Restore test fails if expired access is accepted.", path="tests/test_restore.py")]})
    sealed = seal_oracle_contract(tmp_path, contract, Path(".factory/oracles/contracts/appforge-assurance.json"))
    return _write(tmp_path / "oracle-authority.json", {"schema": "factory.appforge.oracle-authority.v1", "contract_path": sealed["path"], "candidate": CANDIDATE, "policy_sources": [{"source_id": "apple-policy"}], "human_reviewer": "Release Owner"})


def _quality(tmp_path: Path) -> Path:
    intent = "e" * 64
    contract = _write(tmp_path / "quality-contract.json", {"schema": "factory.appforge.quality-audit-contract.v1", "candidate": CANDIDATE, "user_design_input_sha256": intent, "conditional": {check: {"status": "required", "reviewed_by": "Release Owner", "rationale": "The reviewed candidate includes subscriptions and restoration."} for check in CONDITIONAL_CHECKS}})
    checks = []
    for index, check_id in enumerate((*DESIGN_CHECKS, *STACK_CHECKS, *CONDITIONAL_CHECKS)):
        artifact = tmp_path / "quality-artifacts" / f"{index:02d}-{check_id}.txt"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(f"passed {check_id}\n", encoding="utf-8")
        checks.append({"id": check_id, "status": "passed", "artifact_path": artifact.relative_to(tmp_path).as_posix(), "artifact_sha256": _sha(artifact), "performed_by": "Release Owner", "performed_at": "2026-08-31T12:00:00Z"})
    evidence = _write(tmp_path / "quality-evidence.json", {"schema": "factory.appforge.quality-audit-evidence.v1", "candidate": CANDIDATE, "user_design_input_sha256": intent, "design_review": {"reviewed_by": "Design Owner", "reviewed_at": "2026-08-31T12:00:00Z", "user_design_input_considered": True, "storyboard_sha256": "f" * 64}, "checks": checks})
    verify_quality_audit(tmp_path, contract, evidence, Path(".factory/appforge/quality-audit.json"))
    return tmp_path / ".factory/appforge/quality-audit.json"


def test_submission_dossier_only_emits_markdown_and_pdf_after_all_build_bound_gates_pass(tmp_path: Path) -> None:
    receipt = verify_submission_assurance(tmp_path, _assurance_contract(tmp_path), _app_review(tmp_path), _media(tmp_path), _saas(tmp_path), _quality(tmp_path), Path(".factory/appforge/submission-assurance.json"), Path(".factory/appforge/reports"))
    assert receipt["marker"] == "APPFORGE_SUBMISSION_DOSSIER_READY"
    assert receipt["ok"] is True
    assert len(receipt["audit"]) == 4
    markdown = tmp_path / receipt["reports"]["markdown"]
    pdf = tmp_path / receipt["reports"]["pdf"]
    assert "Audited and passed" in markdown.read_text(encoding="utf-8")
    assert CANDIDATE["bundle_identifier"] in markdown.read_text(encoding="utf-8")
    assert pdf.read_bytes().startswith(b"%PDF-")


def test_submission_dossier_blocks_candidate_mismatch_without_emitting_final_reports(tmp_path: Path) -> None:
    saas = _saas(tmp_path)
    value = json.loads(saas.read_text(encoding="utf-8")); value["release_candidate"]["build_number"] = "wrong"; value["receipt_sha256"] = _receipt_sha({key: item for key, item in value.items() if key != "receipt_sha256"}); saas.write_text(json.dumps(value), encoding="utf-8")
    receipt = verify_submission_assurance(tmp_path, _assurance_contract(tmp_path), _app_review(tmp_path), _media(tmp_path), saas, _quality(tmp_path), Path(".factory/appforge/submission-assurance.json"), Path(".factory/appforge/reports"))
    assert receipt["marker"] == "APPFORGE_SUBMISSION_DOSSIER_BLOCKED"
    assert receipt["ok"] is False
    assert any(item["code"] == "APPFORGE_ASSURANCE_CANDIDATE_MISMATCH" for item in receipt["findings"])
    assert not (tmp_path / ".factory/appforge/reports").exists()


def test_submission_dossier_fails_closed_when_the_contract_requires_oracle_authority(tmp_path: Path) -> None:
    contract = _assurance_contract(tmp_path)
    payload = json.loads(contract.read_text(encoding="utf-8"))
    payload["oracle_authority"] = {"required": True, "path": "missing-oracle-authority.json"}
    contract.write_text(json.dumps(payload), encoding="utf-8")

    receipt = verify_submission_assurance(tmp_path, contract, _app_review(tmp_path), _media(tmp_path), _saas(tmp_path), _quality(tmp_path), Path(".factory/appforge/submission-assurance.json"), Path(".factory/appforge/reports"))

    assert receipt["ok"] is False
    assert receipt["marker"] == "APPFORGE_SUBMISSION_DOSSIER_BLOCKED"
    assert any(item["gate"] == "Oracle authority" for item in receipt["findings"])
    assert any(item["code"] == "APPFORGE_ORACLE_INPUT_UNAVAILABLE" for item in receipt["findings"])


def test_submission_dossier_binds_each_audit_digest_to_its_referenced_receipt(tmp_path: Path) -> None:
    contract = _assurance_contract(tmp_path)
    payload = json.loads(contract.read_text(encoding="utf-8"))
    payload["oracle_authority"] = {"required": True, "path": _oracle_authority(tmp_path).relative_to(tmp_path).as_posix()}
    contract.write_text(json.dumps(payload), encoding="utf-8")

    receipt = verify_submission_assurance(tmp_path, contract, _app_review(tmp_path), _media(tmp_path), _saas(tmp_path), _quality(tmp_path), Path(".factory/appforge/submission-assurance.json"), Path(".factory/appforge/reports"))

    assert receipt["ok"] is True
    for item in receipt["audit"]:
        evidence = json.loads((tmp_path / item["receipt_path"]).read_text(encoding="utf-8"))
        assert evidence["receipt_sha256"] == item["receipt_sha256"]
    oracle = receipt["oracle_authority"]
    oracle_audit = next(item for item in receipt["audit"] if item["name"] == "Oracle authority")
    assert oracle_audit["receipt_path"] == oracle["path"]
    assert oracle_audit["receipt_sha256"] == oracle["receipt_sha256"]
    assert oracle["path"] != oracle["source_path"]
    assert oracle["source_sha256"] == hashlib.sha256((tmp_path / oracle["source_path"]).read_bytes()).hexdigest()


def test_store_media_rejects_truncated_or_alpha_pngs(tmp_path: Path) -> None:
    valid = _media(tmp_path)
    assert json.loads(valid.read_text(encoding="utf-8"))["ok"] is True
    alpha = _png(tmp_path / "media" / "alpha.png", 10, 20, color_type=6)
    evidence = json.loads((tmp_path / "media-evidence.json").read_text(encoding="utf-8"))
    evidence["captures"][0].update({"path": "media/alpha.png", "sha256": _sha(alpha)})
    _write(tmp_path / "alpha-evidence.json", evidence)
    receipt = verify_store_media(tmp_path, tmp_path / "media-contract.json", tmp_path / "alpha-evidence.json", Path(".factory/appforge/alpha.json"))
    assert receipt["ok"] is False
    assert any(item["code"] == "APPFORGE_MEDIA_ALPHA_REJECTED" for item in receipt["findings"])


def test_quality_audit_rejects_missing_user_design_confirmation_and_unbound_artifact(tmp_path: Path) -> None:
    _quality(tmp_path)
    evidence_path = tmp_path / "quality-evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["design_review"]["user_design_input_considered"] = False
    evidence["checks"][0]["artifact_sha256"] = "0" * 64
    _write(tmp_path / "quality-invalid-evidence.json", evidence)
    receipt = verify_quality_audit(tmp_path, tmp_path / "quality-contract.json", tmp_path / "quality-invalid-evidence.json", Path(".factory/appforge/quality-invalid.json"))
    assert receipt["marker"] == "APPFORGE_QUALITY_AUDIT_BLOCKED"
    assert {item["code"] for item in receipt["findings"]} >= {"APPFORGE_QUALITY_USER_DESIGN_UNCONFIRMED", "APPFORGE_QUALITY_ARTIFACT_HASH_MISMATCH"}
