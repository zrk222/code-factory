from __future__ import annotations

import json

import pytest

from factoryline.proof_reuse import (
    ProofReuseError,
    challenge_proof_receipt,
    plan_proofs,
    proof_facts,
    proof_key,
    record_proof,
    verify_proof_receipt,
)
from factoryline.cli import main


def _workspace(tmp_path):
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir(parents=True)
    source.write_text("print('verified')\n", encoding="utf-8")
    output = tmp_path / "dist" / "result.json"
    output.parent.mkdir()
    output.write_text('{"passed":true}\n', encoding="utf-8")
    gate = {
        "name": "python-tests",
        "command": ["python", "-m", "pytest", "-q"],
        "inputs": ["src/app.py"],
        "outputs": ["dist/result.json"],
        "relevant_paths": ["src"],
        "safe_to_skip": True,
        "read_only": True,
        "toolchain": {"python": "3.11.9", "pytest": "9.0.2"},
        "environment": {"os": "windows", "arch": "x64"},
    }
    return source, output, gate


def _manifest(gate):
    return {"schema": "factory.proof-request.v1", "gates": [gate]}


@pytest.mark.parametrize("row", [None, "artifact", 42, [], True])
@pytest.mark.parametrize("field", ["inputs", "outputs"])
def test_malformed_artifact_rows_reject_without_crashing(tmp_path, row, field):
    from pathlib import Path
    _, _, gate = _workspace(tmp_path)
    saved = record_proof(tmp_path, gate, elapsed_ms=100)
    path = Path(saved["receipt"])
    payload = json.loads(path.read_text())
    payload[field] = [row]
    path.write_text(json.dumps(payload))
    result = verify_proof_receipt(tmp_path, path)
    assert result["valid"] is False
    assert any("artifact row must be an object" in error for error in result["errors"])


def test_proof_key_is_stable_and_changes_with_input(tmp_path):
    source, _, gate = _workspace(tmp_path)
    facts = proof_facts(tmp_path, gate)
    assert facts["command_sha256"] and "command" not in facts
    assert gate["command"] != facts.get("command")
    first = proof_key(tmp_path, gate)
    assert first == proof_key(tmp_path, gate)
    source.write_text("print('changed')\n", encoding="utf-8")
    assert proof_key(tmp_path, gate) != first


def test_exact_green_receipt_is_reused(tmp_path):
    _, _, gate = _workspace(tmp_path)
    receipt = record_proof(tmp_path, gate, elapsed_ms=60_000, tokens=1200)
    verification = verify_proof_receipt(tmp_path, receipt["receipt"])
    assert verification["valid"] is True
    plan = plan_proofs(tmp_path, _manifest(gate), changed_paths=["src/app.py"])
    assert plan["counts"] == {"RUN": 0, "REUSE": 1, "SKIP": 0, "BLOCK": 0}
    assert plan["items"][0]["disposition"] == "REUSE"
    assert "PROOF_RECEIPT_REUSED" in plan["items"][0]["markers"]


def test_mutated_input_forces_run_and_challenge_rejects_it(tmp_path):
    source, _, gate = _workspace(tmp_path)
    receipt = record_proof(tmp_path, gate, elapsed_ms=1000)
    challenge = challenge_proof_receipt(tmp_path, receipt["receipt"])
    assert challenge["passed"] is True
    assert challenge["disposition_after_mutation"] == "RUN"
    source.write_text("print('mutated')\n", encoding="utf-8")
    plan = plan_proofs(tmp_path, _manifest(gate), changed_paths=["src/app.py"])
    assert plan["items"][0]["disposition"] == "RUN"


def test_side_effect_gate_is_blocked_and_cannot_be_recorded(tmp_path):
    _, _, gate = _workspace(tmp_path)
    gate["read_only"] = False
    gate["name"] = "publish-release"
    plan = plan_proofs(tmp_path, _manifest(gate), changed_paths=["src/app.py"])
    assert plan["items"][0]["disposition"] == "BLOCK"
    assert "PROOF_SIDE_EFFECT_REUSE_REFUSED" in plan["items"][0]["markers"]
    with pytest.raises(ProofReuseError) as error:
        record_proof(tmp_path, gate, elapsed_ms=1)
    assert error.value.code == "PROOF_SIDE_EFFECT_REUSE_REFUSED"


def test_reviewed_unaffected_gate_skips_but_ambiguous_relevance_runs(tmp_path):
    _, _, gate = _workspace(tmp_path)
    skipped = plan_proofs(tmp_path, _manifest(gate), changed_paths=["docs/readme.md"])
    assert skipped["items"][0]["disposition"] == "SKIP"
    assert "PROOF_IRRELEVANT_CHANGE" in skipped["items"][0]["markers"]
    gate["safe_to_skip"] = False
    ambiguous = plan_proofs(tmp_path, _manifest(gate), changed_paths=["docs/readme.md"])
    assert ambiguous["items"][0]["disposition"] == "RUN"
    assert "PROOF_RELEVANCE_FAIL_CLOSED" in ambiguous["items"][0]["markers"]


def test_missing_or_escaping_input_blocks(tmp_path):
    _, _, gate = _workspace(tmp_path)
    gate["inputs"] = ["missing.py"]
    plan = plan_proofs(tmp_path, _manifest(gate))
    assert plan["items"][0]["disposition"] == "BLOCK"
    gate["inputs"] = ["../outside.py"]
    plan = plan_proofs(tmp_path, _manifest(gate))
    assert plan["items"][0]["disposition"] == "BLOCK"


def test_auto_savings_records_exact_pair_and_preserves_unknown_tokens(tmp_path):
    _, _, gate = _workspace(tmp_path)
    record_proof(tmp_path, gate, elapsed_ms=600_000)
    plan = plan_proofs(tmp_path, _manifest(gate), changed_paths=["src/app.py"], auto_savings=True)
    item = plan["items"][0]
    assert item["disposition"] == "REUSE"
    assert item["savings"]["time_saved_ms"] == 600_000 - item["routing_elapsed_ms"]
    assert item["savings"]["tokens_saved"] is None
    assert "PROOF_AUTO_SAVINGS_EXACT" in item["markers"]
    assert "PROOF_TOKEN_SAVINGS_UNKNOWN" in item["markers"]
    pairs = list((tmp_path / ".factory" / "savings").glob("*.json"))
    assert len(pairs) == 1
    assert json.loads(pairs[0].read_text(encoding="utf-8"))["schema"] == "factory.savings-pair.v1"


def test_compact_plan_omits_raw_commands_and_absolute_paths(tmp_path):
    _, _, gate = _workspace(tmp_path)
    plan = plan_proofs(tmp_path, _manifest(gate), changed_paths=["src/app.py"])
    persisted = json.loads((tmp_path / ".factory" / "proof-plans" / f"{plan['plan_sha256']}.json").read_text(encoding="utf-8"))
    encoded = json.dumps(persisted)
    assert "pytest" not in encoded
    assert str(tmp_path) not in encoded
    assert "print('verified')" not in encoded
    assert persisted["schema"] == "factory.proof-plan.v1"


def test_proofs_cli_record_plan_verify_and_challenge(tmp_path, capsys):
    _, _, gate = _workspace(tmp_path)
    manifest_path = tmp_path / "proofs.json"
    manifest_path.write_text(json.dumps(_manifest(gate)), encoding="utf-8")
    assert main([
        "proofs", "record", str(manifest_path), "--root", str(tmp_path),
        "--elapsed-ms", "5000", "--json",
    ]) == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["schema"] == "factory.proof-receipt.v1"
    assert main([
        "proofs", "plan", str(manifest_path), "--root", str(tmp_path),
        "--changed", "src/app.py", "--json",
    ]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["items"][0]["disposition"] == "REUSE"
    assert main(["proofs", "verify", receipt["receipt"], "--root", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert main(["proofs", "challenge", receipt["receipt"], "--root", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["marker"] == "PROOF_MUTATION_REJECTED"
