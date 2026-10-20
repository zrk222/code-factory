from __future__ import annotations
import json
from pathlib import Path
from factoryline.cli import main
from factoryline.enterprise_receipts import canonical_json
from factoryline.receipt_challenge import MUTATION_GATE_SCHEMA, verify_receipt_mutations
from factoryline.receipt_index import build_receipt_index
import pytest
from factoryline.runtime_audit import runtime_audit_status
from factoryline.runtime_audit_common import canonical_bytes, sha256_bytes
from factoryline.runtime_audit_contract import LANES

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
    assert {
        item["name"]: item["observed_code"] for item in result["mutations"]
    } == EXPECTED_CODES
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
    assert all(
        item["observed_code"] == "UNCLASSIFIED:RuntimeError"
        for item in result["mutations"]
    )


# --- Merged from test_receipt_index.py; test definitions and fixtures retained ---


def test_receipt_index_is_content_addressed_and_plan_only(tmp_path: Path) -> None:
    receipt_dir = tmp_path / "receipts"
    receipt_dir.mkdir()
    (receipt_dir / "one.json").write_text('{"ok":true}\n', encoding="utf-8")
    (receipt_dir / "two.json").write_text('{"ok":true}\n', encoding="utf-8")
    result = build_receipt_index(tmp_path, hot_days=0, max_files=1)
    assert result["counts"]["files"] == 2
    assert result["counts"]["over_limit"] == 1
    assert result["counts"]["duplicate_groups"] == 1
    assert result["retention_plan"]["mutation"] is False


def test_receipt_index_cli_writes_local_index(tmp_path: Path, capsys) -> None:
    (tmp_path / "receipts").mkdir()
    (tmp_path / "receipts" / "one.json").write_text("{}", encoding="utf-8")
    assert main(["ops", "receipts", "--root", str(tmp_path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["schema"] == "factory.receipt-index.v1"
    assert (tmp_path / ".factory" / "ops" / "receipt-index.json").is_file()


def test_receipt_index_reports_scan_budget_and_keeps_hot_entries_first(
    tmp_path: Path,
) -> None:
    receipt_dir = tmp_path / "receipts"
    receipt_dir.mkdir()
    for index in range(3):
        (receipt_dir / f"{index}.json").write_text(str(index), encoding="utf-8")
    result = build_receipt_index(tmp_path, hot_days=999, max_files=1, max_scan_files=2)
    assert result["counts"]["scan_truncated"] is True
    assert result["entries"][0]["temperature"] == "hot"


def test_receipt_index_rejects_output_escape(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(ValueError, match="inside the workspace"):
        from factoryline.receipt_index import write_receipt_index

        write_receipt_index(tmp_path, tmp_path.parent / "outside.json")


# --- Merged from test_runtime_receipt_readiness.py; test definitions and fixtures retained ---


@pytest.mark.parametrize(
    "mutation",
    [
        "empty",
        "duplicate",
        "id",
        "state",
        "decision",
        "authority",
        "release",
        "malformed",
        "unknown",
    ],
)
def test_rehashed_false_readiness_is_rejected(tmp_path, mutation):
    receipt = {
        "schema": "factory.runtime-audit-receipt.v1",
        "decision": "READY_FOR_HUMAN_REVIEW",
        "authority": "none",
        "release_approval": False,
        "lanes": [{"id": kind, "lane": kind, "state": "PASS"} for kind in LANES],
    }
    if mutation == "empty":
        receipt["lanes"] = []
    elif mutation == "duplicate":
        receipt["lanes"][-1] = receipt["lanes"][0]
    elif mutation == "id":
        receipt["lanes"][0]["id"] = ""
    elif mutation == "state":
        receipt["lanes"][0]["state"] = "UNKNOWN"
    elif mutation == "decision":
        receipt["lanes"][0]["state"] = "FAIL"
    elif mutation == "authority":
        receipt["authority"] = "release"
    elif mutation == "release":
        receipt["release_approval"] = True
    elif mutation == "unknown":
        receipt["lanes"][0]["lane"] = "other"
    else:
        receipt["lanes"][0] = None
    receipt["receipt_sha256"] = sha256_bytes(canonical_bytes(receipt))
    path = tmp_path / ".factory/runtime-audits/run-test/runtime-audit-receipt.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(receipt))
    assert runtime_audit_status(tmp_path)["state"] == "INCOMPLETE"
