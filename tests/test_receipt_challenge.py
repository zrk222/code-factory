from __future__ import annotations

import json
from pathlib import Path

from factoryline.cli import main
from factoryline.enterprise_receipts import canonical_json
from factoryline.receipt_challenge import MUTATION_GATE_SCHEMA, verify_receipt_mutations


EXPECTED_CODES = {
    "payload_byte_flip": "E_PAYLOAD_DIGEST_MISMATCH",
    "digest_rebound_without_signature": "E_SIGNATURE_INVALID",
    "identity_swap": "E_IDENTITY_MISMATCH",
    "backdated_revocation": "E_SIGNER_REVOKED",
}


def test_receipt_mutation_gate_rejects_every_declared_mutant(tmp_path: Path) -> None:
    result = verify_receipt_mutations(tmp_path)

    assert result["schema"] == MUTATION_GATE_SCHEMA
    assert result["passed"] is True
    assert result["marker"] == "RECEIPT_MUTATIONS_REJECTED"
    assert result["offline_marker"] == "RECEIPT_CHALLENGE_OFFLINE"
    assert result["control"]["verdict"] == "VERIFIED"
    assert result["attempted"] == result["rejected"] == 4
    assert {item["name"]: item["observed_code"] for item in result["mutations"]} == EXPECTED_CODES
    assert all(item["rejected"] for item in result["mutations"])
    assert not any(result["authority"].values())
    assert result["ephemeral_private_keys_preserved"] is False
    assert not list(tmp_path.rglob("*.pem"))

    receipt_path = Path(result["path"])
    stored = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt_path.read_bytes() == canonical_json(stored) + b"\n"


def test_verify_receipts_cli_emits_json_and_fails_when_a_mutant_survives(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    assert main(["verify-receipts", "--root", str(tmp_path), "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["marker"] == "RECEIPT_MUTATIONS_REJECTED"

    monkeypatch.setattr(
        "factoryline.receipt_challenge.verify_receipt_mutations",
        lambda root, out=None: {
            "schema": MUTATION_GATE_SCHEMA,
            "passed": False,
            "marker": "RECEIPT_MUTATION_SURVIVED",
            "attempted": 4,
            "rejected": 3,
            "path": str(tmp_path / "failed.json"),
        },
    )
    assert main(["verify-receipts", "--root", str(tmp_path), "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["marker"] == "RECEIPT_MUTATION_SURVIVED"


def test_unclassified_mutation_failure_cannot_be_reported_as_a_pass(
    tmp_path: Path, monkeypatch
) -> None:
    from factoryline import receipt_challenge

    original = receipt_challenge.verify_receipt_v2
    calls = 0

    def fail_after_control(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return original(*args, **kwargs)
        raise RuntimeError("unexpected verifier failure")

    monkeypatch.setattr(receipt_challenge, "verify_receipt_v2", fail_after_control)
    result = receipt_challenge.verify_receipt_mutations(tmp_path)

    assert result["passed"] is False
    assert result["marker"] == "RECEIPT_MUTATION_SURVIVED"
    assert result["rejected"] == 0
    assert all(item["observed_code"] == "UNCLASSIFIED:RuntimeError" for item in result["mutations"])
