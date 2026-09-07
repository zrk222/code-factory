import hashlib
import json
import sys

import pytest

from factoryline.senior_assurance import (
    REPAIR_SCHEMA,
    REUSE_REQUEST_SCHEMA,
    SeniorAssuranceError,
    compare_repair,
    explain_evidence_reuse,
    failure_brief,
    load_assurance_json,
    run_replay,
    validate_replay_manifest,
)


def _sha_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _tree_sha(path):
    rows = []
    for item in sorted(path.rglob("*")):
        if item.is_file():
            rows.append({"path": item.relative_to(path).as_posix(), "sha256": _sha_bytes(item.read_bytes()), "size": item.stat().st_size})
    return _sha_bytes(_canonical(rows))


def _digest_file(path) -> str:
    return _sha_bytes(path.read_bytes())


def _replay(root, name, exit_code, contract, *, script="import sys; print('receipt'); sys.exit(%d)" % 0):
    source = root / name
    source.mkdir()
    (source / "run.py").write_text(script, encoding="utf-8")
    policy = root / f"{name}-policy.json"
    dependencies = root / f"{name}-dependencies.lock"
    policy.write_text('{"policy":"approved"}', encoding="utf-8")
    dependencies.write_text("dependency==1", encoding="utf-8")
    return {
        "schema": "factory.replay-manifest.v1",
        "replay_id": f"{name}-replay",
        "source_root": name,
        "source_sha256": _tree_sha(source),
        "dependencies_sha256": {"path": dependencies.name, "sha256": _digest_file(dependencies)},
        "policy_sha256": {"path": policy.name, "sha256": _digest_file(policy)},
        "input_files": [],
        "argv": [sys.executable, "run.py"],
        "env": {"PYTHONIOENCODING": "utf-8"},
        "expected_exit": exit_code,
        "timeout_seconds": 10,
        "max_output_bytes": 4096,
        "contract_sha256": contract,
    }


def test_replay_runs_fresh_workspace_without_inheriting_secrets(tmp_path):
    contract = _sha_bytes(b"contract")
    manifest = _replay(tmp_path, "candidate", 1, contract, script="import sys; print('failure'); sys.exit(1)")
    receipt = run_replay(tmp_path, manifest, execute=True)
    assert receipt["state"] == "PASS"
    assert receipt["observed_exit"] == 1
    assert receipt["cleanup"] is True
    assert receipt["authority"] == "none"
    assert "SECRET" not in receipt["stdout_preview"]


def test_replay_validation_and_bounded_json_loader_are_exercised(tmp_path):
    contract = _sha_bytes(b"contract")
    manifest = _replay(tmp_path, "candidate", 0, contract)
    normalized = validate_replay_manifest(tmp_path, manifest)
    assert normalized["replay_id"] == "candidate-replay"
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(_canonical(manifest))
    assert load_assurance_json(manifest_path)["schema"] == "factory.replay-manifest.v1"


def test_replay_rejects_secret_environment_and_source_drift(tmp_path):
    contract = _sha_bytes(b"contract")
    manifest = _replay(tmp_path, "candidate", 0, contract)
    manifest["env"] = {"API_TOKEN": "do-not-accept"}
    with pytest.raises(SeniorAssuranceError) as error:
        run_replay(tmp_path, manifest)
    assert error.value.code == "E_REPLAY_SECRET"


def test_repair_comparison_requires_original_failure_and_negative_controls(tmp_path):
    contract = _sha_bytes(b"contract")
    manifest = {
        "schema": REPAIR_SCHEMA,
        "comparison_id": "repair-1",
        "contract_sha256": contract,
        "buggy": _replay(tmp_path, "buggy", 1, contract, script="import sys; sys.exit(1)"),
        "fixed": _replay(tmp_path, "fixed", 0, contract, script="import sys; sys.exit(0)"),
        "negative_controls": [_replay(tmp_path, "control", 1, contract, script="import sys; sys.exit(1)")],
    }
    receipt = compare_repair(tmp_path, manifest, execute=True)
    assert receipt["state"] == "PASS"
    assert receipt["regression_checks"] == {"original_fails": True, "repaired_passes": True, "negative_controls_fail": True}


def test_repair_blocks_unreviewed_expectation_change(tmp_path):
    contract = _sha_bytes(b"contract")
    manifest = {
        "schema": REPAIR_SCHEMA,
        "comparison_id": "repair-2",
        "contract_sha256": contract,
        "buggy": _replay(tmp_path, "buggy", 1, contract),
        "fixed": _replay(tmp_path, "fixed", 0, contract, script="import sys; sys.exit(0)"),
        "negative_controls": [_replay(tmp_path, "control", 1, contract)],
        "expectations_changed": True,
    }
    with pytest.raises(SeniorAssuranceError) as error:
        compare_repair(tmp_path, manifest)
    assert error.value.code == "E_EXPECTATION_REVIEW_REQUIRED"


def test_reuse_explains_exact_match_and_unknown_policy_dependency(tmp_path):
    policy = _sha_bytes(b"policy")
    dependencies = _sha_bytes(b"deps")
    receipt = {
        "schema": "factory.proof-receipt.v1",
        "status": "green",
        "read_only": True,
        "policy_sha256": policy,
        "dependencies_sha256": dependencies,
        "toolchain": {"python": "3.11"},
        "environment": {"os": "windows"},
        "inputs": [],
    }
    receipt_path = tmp_path / "proof.json"
    receipt_path.write_bytes(_canonical(receipt))
    request = {"schema": REUSE_REQUEST_SCHEMA, "request_id": "r1", "policy_sha256": policy, "dependencies_sha256": dependencies, "gates": [{"id": "lint", "read_only": True, "side_effects": False, "receipt_path": "proof.json", "receipt_sha256": _sha_bytes(receipt_path.read_bytes()), "toolchain": {"python": "3.11"}, "environment": {"os": "windows"}}]}
    exact = explain_evidence_reuse(tmp_path, request)
    assert exact["gates"][0]["decision"] == "REUSE"
    request["gates"][0].pop("toolchain")
    unknown = explain_evidence_reuse(tmp_path, request)
    assert unknown["gates"][0]["decision"] == "RUN"
    assert "toolchain" in unknown["gates"][0]["unknown_inputs"]


def test_failure_brief_links_finding_to_receipt_and_surfaces_uncertainty():
    brief = failure_brief({"schema": "factory.replay-receipt.v1", "state": "FAIL", "replay_id": "r1", "source_root": "src", "failure_reason": "EXIT_MISMATCH", "argv": [sys.executable, "run.py"], "receipt_sha256": _sha_bytes(b"receipt")}, receipt_path=".factory/senior/replay.json")
    assert brief["state"] == "ACTION_REQUIRED"
    assert brief["what_broke"][0]["evidence"] == _sha_bytes(b"receipt")
    assert brief["reproduce"]["argv"]
    assert brief["uncertainty"]
