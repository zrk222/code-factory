from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.codex_metadata import MetadataAuditError, audit_metadata, write_metadata_audit


def _bound(provider: str = "github") -> dict:
    return {
        "status": "published",
        "provider": provider,
        "command": "release-command --verified",
        "provider_receipt": {"url": f"https://example.test/{provider}/run/42", "sha256": "a" * 64},
        "agent": "coder",
        "independent_verifier": "reviewer",
        "intent_id": "REQ-42",
        "intent_status": "confirmed",
    }


def test_bound_terminal_records_are_verified_and_authority_free(tmp_path: Path):
    metadata = tmp_path / "metadata.json"
    metadata.write_text(json.dumps(_bound()), encoding="utf-8")
    history = tmp_path / "history.jsonl"
    history.write_text(json.dumps({**_bound("pypi"), "status": "verified"}) + "\n", encoding="utf-8")

    result = audit_metadata(tmp_path, [metadata, history])

    assert result["status"] == "VERIFIED"
    assert result["findings"] == []
    assert result["markers"] == [
        "CODEX_METADATA_INPUT_ACCEPTED",
        "CODEX_METADATA_HASHED",
        "CODEX_METADATA_CLAIMS_CHECKED",
    ]
    assert result["authority"] == {
        "execute": False,
        "merge": False,
        "deploy": False,
        "release": False,
        "publish": False,
        "billing": False,
    }
    assert all(len(item["sha256"]) == 64 for item in result["files"])


def test_unbound_success_and_self_attested_gate_fail_closed(tmp_path: Path):
    path = tmp_path / "claim.json"
    path.write_text(json.dumps({"status": "complete", "tests_passed": True, "agent": "coder"}), encoding="utf-8")

    result = audit_metadata(tmp_path, [path])
    codes = {item["code"] for item in result["findings"]}

    assert result["status"] == "REVIEW_REQUIRED"
    assert "E_METADATA_UNBOUND_TERMINAL" in codes
    assert "E_METADATA_SELF_ATTESTED_GATE" in codes
    assert "CODEX_METADATA_REVIEW_REQUIRED" in result["markers"]


def test_unclear_intent_is_not_an_acceptable_test_gate(tmp_path: Path):
    path = tmp_path / "claim.json"
    path.write_text(json.dumps({"tests_passed": True, "intent_status": "needs_clarification", "agent": "coder"}), encoding="utf-8")

    result = audit_metadata(tmp_path, [path])

    assert any(item["code"] == "E_METADATA_INTENT_UNCLEAR" for item in result["findings"])
    assert any(item["code"] == "E_METADATA_INTENT_UNBOUND" for item in result["findings"])


def test_command_only_terminal_claim_is_weak_evidence(tmp_path: Path):
    path = tmp_path / "claim.json"
    path.write_text(json.dumps({"status": "complete", "command": "pytest -q", "intent_id": "REQ-1"}), encoding="utf-8")

    result = audit_metadata(tmp_path, [path])

    assert any(item["code"] == "E_METADATA_WEAK_EVIDENCE" for item in result["findings"])


def test_green_gate_requires_negative_or_adversarial_proof(tmp_path: Path):
    path = tmp_path / "gate.json"
    path.write_text(
        json.dumps({
            "tests_passed": True,
            "receipt": {"sha256": "a" * 64},
            "independent_verifier": "reviewer",
            "intent_hash": "b" * 64,
        }),
        encoding="utf-8",
    )

    result = audit_metadata(tmp_path, [path])

    assert any(item["code"] == "E_METADATA_GATE_NO_NEGATIVE_PROOF" for item in result["findings"])


def test_contradictory_provider_state_is_not_collapsed_into_success(tmp_path: Path):
    path = tmp_path / "claim.json"
    path.write_text(
        json.dumps({
            "status": "published",
            "state": "pending",
            "provider": "JetBrains Marketplace",
            "command": "upload",
            "agent": "coder",
        }),
        encoding="utf-8",
    )

    result = audit_metadata(tmp_path, [path])
    codes = {item["code"] for item in result["findings"]}

    assert "E_METADATA_CONTRADICTORY_STATUS" in codes
    assert "E_METADATA_PROVIDER_UNBOUND" in codes


def test_malformed_jsonl_is_named_instead_of_skipped(tmp_path: Path):
    path = tmp_path / "history.jsonl"
    path.write_text(json.dumps(_bound()) + "\nnot-json\n", encoding="utf-8")

    result = audit_metadata(tmp_path, [path])

    assert result["status"] == "REVIEW_REQUIRED"
    assert any(item["code"] == "E_METADATA_PARSE_INVALID" and item["location"] == "line:2" for item in result["findings"])


def test_orphan_active_and_workspace_mismatch_are_visible(tmp_path: Path):
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps({"status": "active", "cwd": str(tmp_path.parent / "other-project")}),
        encoding="utf-8",
    )

    result = audit_metadata(tmp_path, [path])
    codes = {item["code"] for item in result["findings"]}

    assert "E_METADATA_ORPHAN_ACTIVE" in codes
    assert "E_METADATA_WORKSPACE_MISMATCH" in codes


def test_active_policy_constraints_are_not_misclassified_as_live_execution(tmp_path: Path):
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps({
            "active_policy": {
                "constraints": {"parser": {"status": "active", "prevented": 4}},
            },
            "version": 1,
        }),
        encoding="utf-8",
    )

    result = audit_metadata(tmp_path, [path])

    assert result["status"] == "VERIFIED"
    assert not any(item["code"] == "E_METADATA_ORPHAN_ACTIVE" for item in result["findings"])


def test_markdown_claims_without_receipts_are_review_required(tmp_path: Path):
    path = tmp_path / "progress.md"
    path.write_text("Status: published to PyPI\nstatus=active\nall_green=true\n", encoding="utf-8")

    result = audit_metadata(tmp_path, [path])
    codes = {item["code"] for item in result["findings"]}

    assert "E_METADATA_UNBOUND_TERMINAL" in codes
    assert "E_METADATA_PROVIDER_UNBOUND" in codes
    assert "E_METADATA_ORPHAN_ACTIVE" in codes
    assert "E_METADATA_SELF_ATTESTED_GATE" in codes


def test_cli_writes_readable_receipt_and_returns_one_for_review(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    path = tmp_path / "claim.json"
    path.write_text(json.dumps({"status": "success"}), encoding="utf-8")
    out = tmp_path / ".factory" / "ops" / "metadata-integrity.json"

    assert main(["ops", "metadata", "--root", str(tmp_path), "--path", "claim.json", "--out", str(out), "--json"]) == 1
    emitted = json.loads(capsys.readouterr().out)

    assert out.exists()
    written = json.loads(out.read_text(encoding="utf-8"))
    assert emitted["status"] == "REVIEW_REQUIRED"
    assert written["marker"] == "CODEX_METADATA_CLI_WRITTEN"
    assert written["schema"] == "factory.codex-metadata-integrity.v1"
    assert written["audit_sha256"] == emitted["audit_sha256"]


def test_path_escape_and_missing_inventory_are_rejected(tmp_path: Path):
    with pytest.raises(MetadataAuditError) as escaped:
        audit_metadata(tmp_path, [Path("..") / "outside.json"])
    assert escaped.value.code == "E_METADATA_PATH_ESCAPE"
    with pytest.raises(MetadataAuditError) as missing:
        audit_metadata(tmp_path, [Path("missing.json")])
    assert missing.value.code == "E_METADATA_INPUT_MISSING"
