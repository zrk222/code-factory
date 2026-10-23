from __future__ import annotations
import json
import pytest
from factoryline.proof_reuse import (
    ProofReuseError,
    challenge_proof_receipt,
    evaluate_proofs,
    plan_proofs,
    proof_facts,
    proof_key,
    record_proof,
    verify_proof_receipt,
)
from factoryline.cli import main
from pathlib import Path
import hashlib
import subprocess
from factoryline.proof_worklog import (
    MARKER,
    create_proof_worklog,
    proof_worklog_projection,
    verify_proof_worklog,
)
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.oracle_firewall import capture_intent_handoff, seal_oracle_contract


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


def test_changed_output_declaration_does_not_reuse_receipt(tmp_path):
    _, _, gate = _workspace(tmp_path)
    record_proof(tmp_path, gate, elapsed_ms=1000)
    alternate = tmp_path / "dist" / "alternate.json"
    alternate.write_text('{"passed":true}\n', encoding="utf-8")
    changed = {**gate, "outputs": ["dist/alternate.json"]}

    plan = plan_proofs(tmp_path, _manifest(changed))

    assert plan["items"][0]["disposition"] == "RUN"
    assert plan["items"][0]["reason"] == "receipt verification failed"


def test_output_declaration_order_and_duplicates_do_not_change_reuse(tmp_path):
    _, _, gate = _workspace(tmp_path)
    record_proof(tmp_path, gate, elapsed_ms=1000)
    changed = {**gate, "outputs": ["dist/result.json", "./dist/result.json"]}

    plan = plan_proofs(tmp_path, _manifest(changed))

    assert plan["items"][0]["disposition"] == "REUSE"


@pytest.mark.parametrize("outputs", [None, []])
def test_incomplete_output_declaration_fails_closed(tmp_path, outputs):
    _, _, gate = _workspace(tmp_path)
    record_proof(tmp_path, gate, elapsed_ms=1000)
    changed = {**gate}
    if outputs is None:
        changed.pop("outputs")
    else:
        changed["outputs"] = outputs

    plan = plan_proofs(tmp_path, _manifest(changed))

    assert plan["items"][0]["disposition"] == "BLOCK"
    assert plan["items"][0]["reason"] == "PROOF_INPUT_INVALID"


def test_missing_requested_output_fails_closed(tmp_path):
    _, output, gate = _workspace(tmp_path)
    record_proof(tmp_path, gate, elapsed_ms=1000)
    output.unlink()

    plan = plan_proofs(tmp_path, _manifest(gate))

    assert plan["items"][0]["disposition"] == "RUN"
    assert plan["items"][0]["reason"] == "receipt verification failed"


def test_first_run_with_not_yet_created_output_routes_to_run(tmp_path):
    _, output, gate = _workspace(tmp_path)
    output.unlink()

    plan = plan_proofs(tmp_path, _manifest(gate))

    assert plan["items"][0]["disposition"] == "RUN"
    assert plan["items"][0]["reason"] == "no exact verified green receipt"


def test_malformed_output_declaration_fails_closed(tmp_path):
    _, _, gate = _workspace(tmp_path)
    record_proof(tmp_path, gate, elapsed_ms=1000)
    changed = {**gate, "outputs": [42]}

    plan = plan_proofs(tmp_path, _manifest(changed))

    assert plan["items"][0]["disposition"] == "BLOCK"
    assert plan["items"][0]["reason"] == "PROOF_INPUT_INVALID"


def test_symlinked_requested_output_fails_closed_when_supported(tmp_path):
    source, output, gate = _workspace(tmp_path)
    record_proof(tmp_path, gate, elapsed_ms=1000)
    linked_output = tmp_path / "dist" / "linked.json"
    try:
        linked_output.symlink_to(source)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlinks unavailable: {error}")
    changed = {**gate, "outputs": ["dist/linked.json"]}

    plan = plan_proofs(tmp_path, _manifest(changed))

    assert plan["items"][0]["disposition"] == "BLOCK"
    assert plan["items"][0]["reason"] == "PROOF_REUSE_BLOCKED"


def test_receipt_binds_regular_file_identity(tmp_path):
    _, _, gate = _workspace(tmp_path)
    receipt = record_proof(tmp_path, gate, elapsed_ms=1000)
    payload = json.loads(
        (tmp_path / ".factory" / "proofs" / f"{receipt['proof_key']}.json").read_text(
            encoding="utf-8"
        )
    )
    for field in ("inputs", "outputs"):
        assert payload[field][0]["identity"]["inode"] >= 0
        assert payload[field][0]["identity"]["size"] > 0


def test_replaced_file_blocks_receipt_reuse(tmp_path):
    source, _, gate = _workspace(tmp_path)
    receipt = record_proof(tmp_path, gate, elapsed_ms=1000)
    replacement = source.with_name("replacement.py")
    replacement.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    source.unlink()
    replacement.replace(source)
    verification = verify_proof_receipt(tmp_path, receipt["receipt"])
    assert verification["valid"] is False
    assert verification["marker"] == "PROOF_REUSE_BLOCKED"
    assert verification["blocked"] is True
    assert any("file identity changed" in error for error in verification["errors"])


def test_truncated_file_blocks_receipt_reuse(tmp_path):
    source, _, gate = _workspace(tmp_path)
    receipt = record_proof(tmp_path, gate, elapsed_ms=1000)
    source.write_bytes(b"x")
    verification = verify_proof_receipt(tmp_path, receipt["receipt"])
    assert verification["valid"] is False
    assert verification["marker"] == "PROOF_REUSE_BLOCKED"
    assert any("PROOF_REUSE_BLOCKED" in error for error in verification["errors"])


def test_symlinked_file_blocks_receipt_reuse_when_supported(tmp_path):
    source, output, gate = _workspace(tmp_path)
    receipt = record_proof(tmp_path, gate, elapsed_ms=1000)
    source.unlink()
    try:
        source.symlink_to(output)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlinks unavailable: {error}")
    verification = verify_proof_receipt(tmp_path, receipt["receipt"])
    assert verification["valid"] is False
    assert verification["marker"] == "PROOF_REUSE_BLOCKED"
    assert any("symlink" in error for error in verification["errors"])


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
    plan = plan_proofs(
        tmp_path, _manifest(gate), changed_paths=["src/app.py"], auto_savings=True
    )
    item = plan["items"][0]
    assert item["disposition"] == "REUSE"
    assert item["savings"]["time_saved_ms"] == 600_000 - item["routing_elapsed_ms"]
    assert item["savings"]["tokens_saved"] is None
    assert "PROOF_AUTO_SAVINGS_EXACT" in item["markers"]
    assert "PROOF_TOKEN_SAVINGS_UNKNOWN" in item["markers"]
    pairs = list((tmp_path / ".factory" / "savings").glob("*.json"))
    assert len(pairs) == 1
    assert (
        json.loads(pairs[0].read_text(encoding="utf-8"))["schema"]
        == "factory.savings-pair.v1"
    )


def test_compact_plan_omits_raw_commands_and_absolute_paths(tmp_path):
    _, _, gate = _workspace(tmp_path)
    plan = plan_proofs(tmp_path, _manifest(gate), changed_paths=["src/app.py"])
    persisted = json.loads(
        (
            tmp_path / ".factory" / "proof-plans" / f"{plan['plan_sha256']}.json"
        ).read_text(encoding="utf-8")
    )
    encoded = json.dumps(persisted)
    assert "pytest" not in encoded
    assert str(tmp_path) not in encoded
    assert "print('verified')" not in encoded
    assert persisted["schema"] == "factory.proof-plan.v1"


def test_evaluation_batches_shared_input_and_plan_wrapper_writes_once(
    tmp_path, monkeypatch
):
    _, _, first = _workspace(tmp_path)
    second = {**first, "name": "python-lint", "command": ["python", "-m", "ruff"]}
    stable_reads = 0
    writes = 0
    original_read = __import__(
        "factoryline.proof_reuse", fromlist=["_stable_file_read"]
    )._stable_file_read
    original_write = __import__(
        "factoryline.proof_reuse", fromlist=["_atomic_json"]
    )._atomic_json

    def count_read(*args, **kwargs):
        nonlocal stable_reads
        stable_reads += 1
        return original_read(*args, **kwargs)

    def count_write(*args, **kwargs):
        nonlocal writes
        writes += 1
        return original_write(*args, **kwargs)

    monkeypatch.setattr("factoryline.proof_reuse._stable_file_read", count_read)
    monkeypatch.setattr("factoryline.proof_reuse._atomic_json", count_write)
    request = {"schema": "factory.proof-request.v1", "gates": [first, second]}
    evaluated = evaluate_proofs(tmp_path, request)
    assert [item["disposition"] for item in evaluated["items"]] == ["RUN", "RUN"]
    assert stable_reads == 1
    assert writes == 0
    assert not (tmp_path / ".factory" / "proof-plans").exists()

    destination = tmp_path / "final-plan.json"
    persisted = plan_proofs(tmp_path, request, out=destination)
    assert persisted["plan"] == str(destination.resolve())
    assert destination.is_file()
    assert writes == 1


def test_proof_evaluation_phase_preserves_behavior_and_records_failures(tmp_path):
    from factoryline.ops_telemetry import _phase_telemetry

    _, _, gate = _workspace(tmp_path)
    record_proof(tmp_path, gate, elapsed_ms=1000)
    request = _manifest(gate)
    expected = evaluate_proofs(tmp_path, request)
    with _phase_telemetry(0) as telemetry:
        observed = evaluate_proofs(tmp_path, request)
    fields = ("gate", "proof_key", "receipt_sha256", "disposition", "reason", "markers")
    assert observed["counts"] == expected["counts"]
    assert [
        tuple(item.get(field) for field in fields) for item in observed["items"]
    ] == [tuple(item.get(field) for field in fields) for item in expected["items"]]
    phase = telemetry.snapshot()["phases"][0]
    assert phase["phase"] == "proof_evaluation"
    assert phase["completed"] == 1
    assert str(tmp_path) not in json.dumps(telemetry.snapshot())

    with _phase_telemetry(0) as telemetry:
        with pytest.raises(ProofReuseError) as error:
            evaluate_proofs(tmp_path, {"schema": "invalid", "gates": "bad"})
    assert error.value.code == "PROOF_MANIFEST_INVALID"
    assert telemetry.snapshot()["status"] == "incomplete"
    assert telemetry.snapshot()["phases"][0]["incomplete"] == 1


def test_shared_snapshot_does_not_bypass_per_receipt_freshness_check(
    tmp_path, monkeypatch
):
    source, _, first = _workspace(tmp_path)
    second = {**first, "name": "python-lint", "command": ["python", "-m", "ruff"]}
    record_proof(tmp_path, first, elapsed_ms=1000)
    record_proof(tmp_path, second, elapsed_ms=1000)
    module = __import__("factoryline.proof_reuse", fromlist=["_stable_file_read"])
    original_read = module._stable_file_read
    reads = 0

    def mutate_after_snapshot(path, *, label):
        nonlocal reads
        result = original_read(path, label=label)
        reads += 1
        if reads == 1:
            source.write_text(
                "print('changed after shared snapshot')\n", encoding="utf-8"
            )
        return result

    monkeypatch.setattr(module, "_stable_file_read", mutate_after_snapshot)
    result = evaluate_proofs(
        tmp_path, {"schema": "factory.proof-request.v1", "gates": [first, second]}
    )
    assert [item["disposition"] for item in result["items"]] == ["RUN", "RUN"]
    assert all(
        item["reason"] == "receipt verification failed" for item in result["items"]
    )


def test_malformed_gate_does_not_suppress_valid_sibling(tmp_path):
    _, _, valid = _workspace(tmp_path)
    invalid = {**valid, "name": 42}
    result = evaluate_proofs(
        tmp_path, {"schema": "factory.proof-request.v1", "gates": [invalid, valid]}
    )
    assert [item["disposition"] for item in result["items"]] == ["BLOCK", "RUN"]
    assert result["items"][0]["reason"] == "PROOF_GATE_INVALID"


def test_batch_route_exception_does_not_suppress_valid_reuse(tmp_path, monkeypatch):
    _, _, valid = _workspace(tmp_path)
    record_proof(tmp_path, valid, elapsed_ms=1000)
    broken = {**valid, "name": "broken"}
    module = __import__("factoryline.proof_reuse", fromlist=["_route_gate"])
    original_route = module._route_gate

    def fail_one(root, gate, changed, auto_savings, **kwargs):
        if gate.get("name") == "broken":
            raise RuntimeError("isolated evaluator failure")
        return original_route(root, gate, changed, auto_savings, **kwargs)

    monkeypatch.setattr(module, "_route_gate", fail_one)
    result = evaluate_proofs(
        tmp_path, {"schema": "factory.proof-request.v1", "gates": [broken, valid]}
    )
    assert [item["disposition"] for item in result["items"]] == ["RUN", "REUSE"]
    assert result["items"][0]["reason"] == "PROOF_EXECUTION_REQUIRED"


def test_shared_input_cache_is_limited_to_one_evaluation(tmp_path):
    source, _, gate = _workspace(tmp_path)
    request = {"schema": "factory.proof-request.v1", "gates": [gate, gate]}
    first = evaluate_proofs(tmp_path, request)
    source.write_text("print('next invocation')\n", encoding="utf-8")
    second = evaluate_proofs(tmp_path, request)
    assert first["items"][0]["proof_key"] != second["items"][0]["proof_key"]


def test_proofs_cli_record_plan_verify_and_challenge(tmp_path, capsys):
    _, _, gate = _workspace(tmp_path)
    manifest_path = tmp_path / "proofs.json"
    manifest_path.write_text(json.dumps(_manifest(gate)), encoding="utf-8")
    assert (
        main(
            [
                "proofs",
                "record",
                str(manifest_path),
                "--root",
                str(tmp_path),
                "--elapsed-ms",
                "5000",
                "--json",
            ]
        )
        == 0
    )
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["schema"] == "factory.proof-receipt.v1"
    assert (
        main(
            [
                "proofs",
                "plan",
                str(manifest_path),
                "--root",
                str(tmp_path),
                "--changed",
                "src/app.py",
                "--json",
            ]
        )
        == 0
    )
    plan = json.loads(capsys.readouterr().out)
    assert plan["items"][0]["disposition"] == "REUSE"
    assert (
        main(
            ["proofs", "verify", receipt["receipt"], "--root", str(tmp_path), "--json"]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert (
        main(
            [
                "proofs",
                "challenge",
                receipt["receipt"],
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["marker"] == "PROOF_MUTATION_REJECTED"


# --- Merged from test_proof_worklog.py; test definitions and fixtures retained ---


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _applied_repo(root: Path) -> str:
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Test")
    (root / "before.py").write_text("before = 1\n", encoding="utf-8")
    (root / "delete.py").write_text("delete = 1\n", encoding="utf-8")
    (root / "rename-old.py").write_text("rename = 1\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "baseline")
    return _git(root, "rev-parse", "HEAD")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_applied_change_projection_binds_current_candidate_and_declared_baseline(
    tmp_path,
):
    from factoryline.proof_worklog import applied_change_projection

    baseline = _applied_repo(tmp_path)
    (tmp_path / "before.py").write_text("after = 2\n", encoding="utf-8")
    (tmp_path / "literal[1].py").write_text("added = 1\n", encoding="utf-8")
    (tmp_path / "rename-old.py").rename(tmp_path / "rename-new.py")
    (tmp_path / "unrelated.txt").write_text("other\n", encoding="utf-8")
    (tmp_path / "delete.py").unlink()
    _git(
        tmp_path, "add", "before.py", "literal[1].py", "rename-old.py", "rename-new.py"
    )
    _git(tmp_path, "commit", "-qm", "candidate")
    manifest = [
        {"path": "before.py", "sha256": _sha(tmp_path / "before.py")},
        {"path": "literal[1].py", "sha256": _sha(tmp_path / "literal[1].py")},
        {"path": "rename-new.py", "sha256": _sha(tmp_path / "rename-new.py")},
    ]
    baseline_files = {
        "before.py": hashlib.sha256(b"before = 1\n").hexdigest(),
        "literal[1].py": None,
        "rename-old.py": hashlib.sha256(b"rename = 1\n").hexdigest(),
    }
    result = applied_change_projection(
        tmp_path,
        baseline,
        manifest,
        "Complete the checkout flow.",
        baseline_files=baseline_files,
    )

    assert result["state"] == "available"
    assert result["baseline_oid"] == baseline
    assert result["rationale"] == "Complete the checkout flow."
    changes = {row["path"]: row for row in result["changes"]}
    assert changes["before.py"]["disposition"] == "verified_candidate_bytes"
    assert changes["literal[1].py"]["kind"] == "added"
    assert changes["literal[1].py"]["disposition"] == "verified_candidate_bytes"
    assert changes["rename-new.py"]["kind"] == "renamed"
    assert changes["rename-new.py"]["old_path"] == "rename-old.py"
    assert changes["delete.py"]["disposition"] == "unverified"
    assert "unrelated.txt" in result["unrelated_dirty_paths"]


def test_applied_change_projection_keeps_same_file_dirty_and_unbound_delete_unverified(
    tmp_path,
):
    from factoryline.proof_worklog import applied_change_projection

    baseline = _applied_repo(tmp_path)
    (tmp_path / "before.py").write_text("staged = 1\n", encoding="utf-8")
    _git(tmp_path, "add", "before.py")
    (tmp_path / "before.py").write_text("tested = 2\n", encoding="utf-8")
    manifest = [{"path": "before.py", "sha256": _sha(tmp_path / "before.py")}]
    (tmp_path / "delete.py").unlink()
    result = applied_change_projection(
        tmp_path,
        baseline,
        manifest,
        "Do not infer authorship.",
        baseline_files={"before.py": hashlib.sha256(b"before = 1\n").hexdigest()},
    )
    changes = {row["path"]: row for row in result["changes"]}
    assert result["state"] == "available"
    assert changes["before.py"]["disposition"] == "unverified"
    assert changes["before.py"]["reason"] == "mixed_or_ambiguous_same_file_edits"
    assert changes["delete.py"]["disposition"] == "unverified"


def test_applied_change_projection_rejects_missing_baseline_symlink_and_exhaustion(
    tmp_path,
):
    from factoryline.proof_worklog import applied_change_projection

    assert (
        applied_change_projection(tmp_path, None, [], "private")["reason"]
        == "baseline_unbound"
    )
    baseline = _applied_repo(tmp_path)
    try:
        (tmp_path / "linked.py").symlink_to(tmp_path / "before.py")
    except OSError:
        pytest.skip("symlink creation is unavailable")
    symlink_result = applied_change_projection(
        tmp_path,
        baseline,
        [{"path": "linked.py", "sha256": _sha(tmp_path / "before.py")}],
        "private",
        baseline_files={"linked.py": None},
    )
    assert symlink_result["state"] == "unavailable"
    assert (
        applied_change_projection(
            tmp_path,
            baseline,
            [{"path": f"file-{index}.py", "sha256": "a" * 64} for index in range(1001)],
            "private",
        )["reason"]
        == "candidate_manifest_unavailable"
    )


def test_applied_change_projection_rejects_head_change_during_final_freshness(
    tmp_path, monkeypatch
):
    from factoryline import proof_worklog

    baseline = _applied_repo(tmp_path)
    (tmp_path / "before.py").write_text("candidate = 2\n", encoding="utf-8")
    _git(tmp_path, "add", "before.py")
    _git(tmp_path, "commit", "-qm", "candidate")
    manifest = [{"path": "before.py", "sha256": _sha(tmp_path / "before.py")}]
    original = proof_worklog._AppliedChangeGit.verify_current

    def change_head(git, snapshot):
        (tmp_path / "head-change.txt").write_text("changed\n", encoding="utf-8")
        _git(tmp_path, "add", "head-change.txt")
        _git(tmp_path, "commit", "-qm", "head changed during projection")
        return original(git, snapshot)

    monkeypatch.setattr(proof_worklog._AppliedChangeGit, "verify_current", change_head)
    result = proof_worklog.applied_change_projection(
        tmp_path,
        baseline,
        manifest,
        "private",
        baseline_files={"before.py": hashlib.sha256(b"before = 1\n").hexdigest()},
    )
    assert result["state"] == "unavailable"


def test_applied_change_projection_stops_at_retained_data_limit(tmp_path):
    from factoryline.proof_worklog import applied_change_projection

    baseline = _applied_repo(tmp_path)
    large = tmp_path / "large.bin"
    large.write_bytes(b"x" * (8 * 1024 * 1024 + 1))
    _git(tmp_path, "add", "large.bin")
    _git(tmp_path, "commit", "-qm", "large baseline")
    baseline = _git(tmp_path, "rev-parse", "HEAD")
    large.write_bytes(b"y" * (8 * 1024 * 1024 + 1))
    result = applied_change_projection(
        tmp_path,
        baseline,
        [{"path": "large.bin", "sha256": _sha(large)}],
        "large test",
        baseline_files={"large.bin": _sha(large)},
    )
    assert result["state"] == "unavailable"


def test_applied_change_projection_rejects_unsuccessful_cleanup_receipt(
    tmp_path, monkeypatch
):
    from factoryline import assembly_process
    from factoryline.proof_worklog import applied_change_projection

    baseline = _applied_repo(tmp_path)
    monkeypatch.setattr(
        assembly_process,
        "run_cli_detailed",
        lambda *args, **kwargs: {
            "ok": False,
            "reason": "timeout",
            "cleanup_confirmed": True,
            "streams_closed": True,
            "exit_code": 0,
            "stdout": b"",
            "stderr": b"",
        },
    )
    result = applied_change_projection(
        tmp_path,
        baseline,
        [{"path": "before.py", "sha256": _sha(tmp_path / "before.py")}],
        "must fail closed",
        baseline_files={"before.py": _sha(tmp_path / "before.py")},
    )
    assert result["state"] == "unavailable"


@pytest.mark.parametrize("late_change", ["index", "untracked"])
def test_applied_change_projection_rechecks_index_and_untracked_facts(
    tmp_path, monkeypatch, late_change
):
    from factoryline import proof_worklog

    baseline = _applied_repo(tmp_path)
    (tmp_path / "before.py").write_text("candidate = 2\n", encoding="utf-8")
    manifest = [{"path": "before.py", "sha256": _sha(tmp_path / "before.py")}]
    original = proof_worklog._AppliedChangeGit.verify_current

    def add_late_fact(git, snapshot):
        if late_change == "index":
            (tmp_path / "delete.py").write_text("index-only = 3\n", encoding="utf-8")
            _git(tmp_path, "add", "delete.py")
        else:
            (tmp_path / "late.txt").write_text("untracked\n", encoding="utf-8")
        return original(git, snapshot)

    monkeypatch.setattr(
        proof_worklog._AppliedChangeGit, "verify_current", add_late_fact
    )
    result = proof_worklog.applied_change_projection(
        tmp_path,
        baseline,
        manifest,
        "recheck all disposition inputs",
        baseline_files={"before.py": _sha(tmp_path / "before.py")},
    )
    assert result["state"] == "unavailable"


def test_applied_change_projection_rechecks_untracked_bytes_with_same_git_facts(
    tmp_path, monkeypatch
):
    from factoryline import proof_worklog

    baseline = _applied_repo(tmp_path)
    (tmp_path / "before.py").write_text("candidate = 2\n", encoding="utf-8")
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_text("initial\n", encoding="utf-8")
    manifest = [{"path": "before.py", "sha256": _sha(tmp_path / "before.py")}]
    original = proof_worklog._AppliedChangeGit.verify_current

    def change_untracked_bytes(git, snapshot):
        before = git.inventory(snapshot["baseline_oid"])[5]
        assert before == snapshot["facts"]
        unrelated.write_text(
            "different bytes, same untracked status\n", encoding="utf-8"
        )
        after = git.inventory(snapshot["baseline_oid"])[5]
        assert after == snapshot["facts"]
        return original(git, snapshot)

    monkeypatch.setattr(
        proof_worklog._AppliedChangeGit, "verify_current", change_untracked_bytes
    )
    result = proof_worklog.applied_change_projection(
        tmp_path,
        baseline,
        manifest,
        "byte facts must remain fresh",
        baseline_files={"before.py": hashlib.sha256(b"before = 1\n").hexdigest()},
    )
    assert result["state"] == "unavailable"


def test_applied_change_digest_honors_expired_deadline_for_empty_file(tmp_path):
    from factoryline import proof_worklog

    empty = tmp_path / "empty.bin"
    empty.touch()
    budget = {"deadline": proof_worklog.time.monotonic() - 1, "retained": 0}
    git = proof_worklog._AppliedChangeGit(tmp_path, budget)
    with pytest.raises(ValueError, match="resource_exhausted"):
        git.digest(empty)


def test_applied_change_missing_snapshot_file_checks_deadline_after_path_read(
    tmp_path, monkeypatch
):
    from factoryline import proof_worklog

    budget = {
        "deadline": proof_worklog.time.monotonic() + 30,
        "retained": 0,
    }
    git = proof_worklog._AppliedChangeGit(tmp_path, budget)
    resolve_path = proof_worklog._literal_workspace_file

    def expire_after_resolve(root, value, *, may_be_missing):
        target = resolve_path(root, value, may_be_missing=may_be_missing)
        budget["deadline"] = proof_worklog.time.monotonic() - 1
        return target

    monkeypatch.setattr(proof_worklog, "_literal_workspace_file", expire_after_resolve)
    with pytest.raises(ValueError, match="resource_exhausted"):
        git.file_fact("missing-after-snapshot.py")


def test_untracked_candidate_needs_explicit_planned_new_baseline_fact(tmp_path):
    from factoryline.proof_worklog import applied_change_projection

    baseline = _applied_repo(tmp_path)
    created = tmp_path / "planned.py"
    created.write_text("planned = True\n", encoding="utf-8")
    result = applied_change_projection(
        tmp_path,
        baseline,
        [{"path": "planned.py", "sha256": _sha(created)}],
        "must be explicitly declared planned-new",
        baseline_files={},
    )
    change = next(row for row in result["changes"] if row["path"] == "planned.py")
    assert result["state"] == "available"
    assert change["disposition"] == "unverified"


def test_candidate_binding_discovery_shares_deadline_and_caps_directory_scan(
    tmp_path,
):
    from factoryline import proof_worklog

    expired = {
        "deadline": proof_worklog.time.monotonic() - 1,
        "retained": 0,
    }
    context = proof_worklog.bound_candidate_context(
        tmp_path,
        tmp_path / "mission.json",
        {},
        "a" * 64,
        _budget=expired,
    )
    assert context[0] is None
    for index in range(101):
        (tmp_path / f"candidate-binding-{index:03}.json").write_text(
            "{}", encoding="utf-8"
        )
    bounded = proof_worklog.bound_candidate_context(
        tmp_path,
        tmp_path / "mission.json",
        {},
        "a" * 64,
    )
    assert bounded[0] is None


def test_applied_change_projection_fails_closed_for_missing_nonancestor_stale_and_non_git(
    tmp_path,
):
    from factoryline.proof_worklog import applied_change_projection

    outside = tmp_path / "outside"
    outside.mkdir()
    assert (
        applied_change_projection(outside, "a" * 40, [], "private")["reason"]
        == "candidate_manifest_unavailable"
    )
    assert (
        applied_change_projection(tmp_path / "not-git", "a" * 40, [], "private")[
            "state"
        ]
        == "unavailable"
    )
    baseline = _applied_repo(tmp_path)
    manifest = [{"path": "before.py", "sha256": _sha(tmp_path / "before.py")}]
    assert (
        applied_change_projection(tmp_path, baseline, manifest, "r", baseline_files={})[
            "state"
        ]
        == "available"
    )
    assert (
        applied_change_projection(tmp_path, "f" * 40, manifest, "r", baseline_files={})[
            "state"
        ]
        == "unavailable"
    )
    (tmp_path / "before.py").write_text("stale\n", encoding="utf-8")
    stale = applied_change_projection(
        tmp_path,
        baseline,
        manifest,
        "r",
        baseline_files={"before.py": hashlib.sha256(b"before = 1\n").hexdigest()},
    )
    assert stale["state"] == "unavailable"


def test_applied_change_projection_rejects_existing_nonancestor_baseline(tmp_path):
    from factoryline.proof_worklog import applied_change_projection

    baseline = _applied_repo(tmp_path)
    _git(tmp_path, "checkout", "--orphan", "unrelated-history")
    _git(tmp_path, "rm", "-q", "-rf", "--", "before.py", "delete.py", "rename-old.py")
    (tmp_path / "other.py").write_text("other = 1\n", encoding="utf-8")
    _git(tmp_path, "add", "other.py")
    _git(tmp_path, "commit", "-qm", "unrelated history")
    result = applied_change_projection(
        tmp_path,
        baseline,
        [{"path": "other.py", "sha256": _sha(tmp_path / "other.py")}],
        "unrelated baseline must not be accepted",
    )

    assert result["state"] == "unavailable"
    assert result["reason"] == "projection_unavailable_or_stale"


AGENT = {
    "schema": "factory.agent-identity.v1",
    "subject": "worklog-owner",
    "provider": "declared",
    "model": "declared-model",
}


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    return path


def _contract(root: Path) -> Path:
    intent = root / "briefs" / "intent.md"
    source = root / "src" / "checkout.py"
    intent.parent.mkdir(parents=True, exist_ok=True)
    source.parent.mkdir(parents=True, exist_ok=True)
    intent.write_text(
        "Checkout completes valid orders and never exposes private account data.\n",
        encoding="utf-8",
    )
    source.write_text(
        "def checkout(order):\n    return bool(order)\n", encoding="utf-8"
    )
    handoff = capture_intent_handoff(
        root,
        intent,
        AGENT,
        "worklog-intake",
        Path(".factory/oracles/handoffs/worklog-intake.json"),
    )
    payload = {
        "schema": "factory.oracle-contract-input.v1",
        "id": "worklog-checkout",
        "version": 1,
        "approved_by": "Release Owner",
        "approval_rationale": "Original intent reviewed.",
        "scope_paths": ["src"],
        "handoff": handoff["path"],
        "sources": [],
        "requirements": [
            {
                "id": "complete",
                "statement": "Valid checkout completes.",
                "origin": "human_confirmed",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
            }
        ],
        "forbidden_behaviors": [
            {
                "id": "private",
                "statement": "Private account data is never exposed.",
                "origin": "human_confirmed",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
            }
        ],
        "gates": [
            {
                "id": "quality",
                "statement": "Quality reaches approved threshold.",
                "origin": "trusted_source",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
                "comparison": "gte",
                "value": 95,
            }
        ],
        "exceptions": [
            {
                "id": "offline",
                "statement": "Offline evidence remains advisory until review.",
                "origin": "human_confirmed",
                "effect": "advisory",
                "source_id": "original-intent",
                "critical": False,
            }
        ],
        "negative_cases": [
            {
                "id": "bad-order",
                "statement": "Invalid order does not complete.",
                "origin": "human_confirmed",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
            }
        ],
        "invariants": [
            {
                "id": "scope",
                "statement": "Only sealed scope changes.",
                "origin": "trusted_source",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
            }
        ],
        "tests": [
            {
                "id": "checkout-test",
                "statement": "Rejected-order path is tested.",
                "origin": "human_confirmed",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
                "path": "tests/test_checkout.py",
            }
        ],
    }
    return (
        root
        / seal_oracle_contract(
            root,
            _write(root / "oracle-input.json", payload),
            Path(".factory/oracles/contracts/worklog-checkout.json"),
        )["path"]
    )


def test_worklog_is_bound_to_current_contract_and_never_claims_external_post(
    tmp_path: Path,
) -> None:
    contract = _contract(tmp_path)
    draft = create_proof_worklog(tmp_path, contract.relative_to(tmp_path))

    assert draft["marker"] == MARKER
    assert draft["review_required"] is True
    assert "has not been posted" in draft["markdown"]
    assert "Valid checkout completes." in draft["markdown"]
    assert "Private account data is never exposed." in draft["markdown"]
    assert all(value is False for value in draft["authority"].values())
    assert verify_proof_worklog(tmp_path, Path(draft["path"]))["ok"] is True
    projection = proof_worklog_projection(tmp_path)
    assert projection["draft_count"] == 1
    assert projection["invalid_count"] == 0
    snapshot = graph_ops_snapshot(tmp_path)
    assert snapshot["facts"]["proof_worklog_draft_count"] == 1
    assert any(node["kind"] == "proof_worklog" for node in snapshot["nodes"])


def test_worklog_fails_closed_when_contract_changes(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    draft = create_proof_worklog(tmp_path, contract.relative_to(tmp_path))
    value = json.loads(contract.read_text(encoding="utf-8"))
    value["contract_sha256"] = "0" * 64
    contract.write_text(json.dumps(value), encoding="utf-8")

    checked = verify_proof_worklog(tmp_path, Path(draft["path"]))
    assert checked["ok"] is False
    assert checked["reason"] == "oracle_binding_stale"
