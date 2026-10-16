import json
import hashlib
from pathlib import Path

import pytest

from factoryline.assembly import ModuleStatus
from factoryline.continuation import (
    ContinuationError,
    continue_assembly,
    resolve_feature,
    resolve_ssat,
)
from factoryline.run_metrics import public_metrics


def _release_contract_fixture(root, feature, required_stages, *, path=None):
    from factoryline.oracle_firewall import capture_intent_handoff, seal_oracle_contract
    from factoryline.release_contract import _sha

    agent = {
        "schema": "factory.agent-identity.v1",
        "subject": "release-owner",
        "provider": "local",
        "model": "test-reviewer",
    }
    brief = root / "brief.md"
    brief.write_text("Keep each required release gate traceable.", encoding="utf-8")
    handoff = capture_intent_handoff(
        root,
        brief,
        agent,
        "release",
        Path(f".factory/oracles/handoffs/{feature}.json"),
    )

    def rule(identifier, statement, **extra):
        return {
            "id": identifier,
            "statement": statement,
            "origin": "human_confirmed",
            "effect": "blocking",
            "source_id": "original-intent",
            "critical": True,
            **extra,
        }

    oracle_input = {
        "schema": "factory.oracle-contract-input.v1",
        "id": f"release-{feature}",
        "version": 1,
        "approved_by": "Release Owner",
        "approval_rationale": "A human reviewed the release boundary.",
        "scope_paths": ["."],
        "handoff": handoff["path"],
        "sources": [],
        "requirements": [rule("intent", "Preserve the approved intent.")],
        "forbidden_behaviors": [rule("weaken", "Do not weaken a required gate.")],
        "gates": [
            rule(
                "proof",
                "A proof receipt is required.",
                comparison="present",
                value=True,
            )
        ],
        "exceptions": [
            {
                "id": "note",
                "statement": "A future policy note remains advisory.",
                "origin": "human_confirmed",
                "effect": "advisory",
                "source_id": "original-intent",
                "critical": False,
            }
        ],
        "negative_cases": [rule("negative", "A missing receipt cannot pass.")],
        "invariants": [rule("bound", "Evidence stays bound to this feature.")],
        "tests": [
            rule(
                "test",
                "The required proof test must run.",
                path="tests/test_release.py",
            )
        ],
    }
    source = root / "oracle-input.json"
    source.write_text(json.dumps(oracle_input), encoding="utf-8")
    oracle_path = Path(
        seal_oracle_contract(
            root, source, Path(f".factory/oracles/contracts/{feature}.json")
        )["path"]
    )
    oracle = json.loads((root / oracle_path).read_text(encoding="utf-8"))
    core = {
        "schema": "factory.release-contract.v1",
        "feature": feature,
        "oracle_contract": oracle_path.as_posix(),
        "oracle_contract_sha256": oracle["contract_sha256"],
        "required_stages": required_stages,
        "approved_by": "Release Owner",
    }
    contract = {**core, "policy_digest": _sha(core)}
    destination = path or root / "custom" / f"{feature}.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(contract), encoding="utf-8")
    return destination, contract


def _pause_custom_contract(tmp_path, monkeypatch):
    from factoryline.assembly import assemble

    feature = "feature"
    contract_path, _ = _release_contract_fixture(tmp_path, feature, ["specline:strict"])
    modules = [
        ModuleStatus(name, name, True, "test")
        for name in ("specline", "forgeline", "hsf", "prestige")
    ]
    monkeypatch.setattr("factoryline.assembly.detect", lambda: modules)
    calls = []

    def run_cli(*args, **kwargs):
        calls.append(args)
        return True, ""

    monkeypatch.setattr("factoryline.assembly.run_cli", run_cli)
    (tmp_path / "specs").mkdir(exist_ok=True)
    report = assemble(
        tmp_path, feature, release_contract_path=Path("custom/feature.json")
    )
    assert report["paused_at"] == "author_spec"
    return contract_path, calls


def test_feature_inference_requires_exactly_one_candidate(tmp_path):
    with pytest.raises(ContinuationError) as error:
        resolve_feature(tmp_path, None)
    assert error.value.code == "FEATURE_SELECTION_REQUIRED"
    (tmp_path / "specs").mkdir(exist_ok=True)
    (tmp_path / "specs" / "only.md").write_text("# only", encoding="utf-8")
    assert resolve_feature(tmp_path, None) == ("only", True)
    (tmp_path / "specs" / "other.md").write_text("# other", encoding="utf-8")
    with pytest.raises(ContinuationError) as error:
        resolve_feature(tmp_path, None)
    assert error.value.candidates == ["only", "other"]


def test_ssat_resolution_prefers_specs_and_never_fuzzy_matches(tmp_path):
    (tmp_path / "specs").mkdir()
    expected = tmp_path / "specs" / "feature.ssat.yaml"
    expected.write_text("schema: x", encoding="utf-8")
    (tmp_path / "feature-old.ssat.yaml").write_text("schema: wrong", encoding="utf-8")
    assert resolve_ssat(tmp_path, "feature") == expected
    assert resolve_ssat(tmp_path, "missing") is None


def test_continue_writes_unknown_usage_receipt_and_safe_aggregate(
    tmp_path, monkeypatch
):
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "feature.md").write_text("# feature", encoding="utf-8")
    monkeypatch.setattr(
        "factoryline.continuation.assemble",
        lambda root, feature, dry_run=False: {
            "feature": feature,
            "root": str(root),
            "run_id": "run-1",
            "stages": [{"module": "specline", "stage": "strict", "status": "ok"}],
            "paused_at": "architecture_approval",
            "rollup": {},
            "dry_run": dry_run,
        },
    )
    result = continue_assembly(tmp_path, "feature")
    assert result["status"] == "waiting_for_human"
    assert result["next_action"]["command"] == "forge gate architected feature"
    receipt = json.loads(
        (tmp_path / ".factory" / "runs" / "run-1.json").read_text(encoding="utf-8")
    )
    assert receipt["usage"]["quality"] == "unknown"
    assert receipt["usage"]["tokens_in"] is None
    aggregate = public_metrics(tmp_path)
    assert aggregate["marker"] == "PUBLIC_METRICS_AGGREGATE_SAFE"
    assert aggregate["usage"]["quality"] == "unknown"
    assert aggregate["savings"]["tokens_saved"] is None
    encoded = json.dumps(aggregate)
    assert "feature" not in encoded
    assert str(tmp_path) not in encoded


def test_dry_run_does_not_write_receipt(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "factoryline.continuation.assemble",
        lambda root, feature, dry_run=False: {
            "feature": feature,
            "root": str(root),
            "run_id": "dry",
            "stages": [],
            "rollup": {},
            "dry_run": dry_run,
        },
    )
    result = continue_assembly(tmp_path, "feature", dry_run=True)
    assert result["status"] == "completed"
    assert not (tmp_path / ".factory" / "runs").exists()


def test_custom_release_contract_survives_pause_and_resume(
    tmp_path, monkeypatch, capsys
):
    from factoryline.cli import main

    feature = "feature"
    outside = tmp_path.parent / f"{tmp_path.name}-external"
    outside.mkdir()
    contract_path, contract = _release_contract_fixture(
        tmp_path,
        feature,
        ["specline:strict"],
        path=outside / "feature.json",
    )
    modules = [
        ModuleStatus(name, name, True, "test")
        for name in ("specline", "forgeline", "hsf", "prestige")
    ]
    monkeypatch.setattr("factoryline.assembly.detect", lambda: modules)
    monkeypatch.setattr(
        "factoryline.assembly.run_cli_detailed",
        lambda *args, **kwargs: {
            "ok": True,
            "stdout": b"",
            "stderr": b"",
            "exit_code": 0,
            "cleanup_confirmed": True,
            "streams_closed": True,
            "output": "",
        },
    )
    monkeypatch.setattr(
        "factoryline.assembly.run_cli", lambda *args, **kwargs: (True, "")
    )

    assert (
        main(
            [
                "assemble",
                feature,
                "--root",
                str(tmp_path),
                "--release-contract",
                str(contract_path),
            ]
        )
        == 0
    )
    assemble_report = json.loads(capsys.readouterr().out)
    assert assemble_report["paused_at"] == "author_spec"
    assert assemble_report["release_contract_path"] == str(contract_path)

    (tmp_path / "specs").mkdir(exist_ok=True)
    (tmp_path / "specs" / f"{feature}.md").write_text("# Feature", encoding="utf-8")
    monkeypatch.setattr(
        "factoryline.assembly.detect",
        lambda: [
            ModuleStatus(item.name, item.cli, item.name != "specline", item.role)
            for item in modules
        ],
    )
    assert main(["continue", feature, "--root", str(tmp_path), "--json"]) == 1
    continuation_report = json.loads(capsys.readouterr().out)
    assert continuation_report["halted_at"] == "specline:strict"
    checkpoints = list(
        (tmp_path / "receipts").glob(
            "factoryline-feature-continuation-release-checkpoint-*.json"
        )
    )
    assert len(checkpoints) == 2
    checkpoint = max(
        (json.loads(path.read_text(encoding="utf-8")) for path in checkpoints),
        key=lambda item: item["inputs"]["checkpoint"]["revision"],
    )
    assert checkpoint["inputs"]["checkpoint"]["state"] == "waiting_for_human"
    assert (
        checkpoint["inputs"]["checkpoint"]["policy_sha256"]
        == hashlib.sha256(contract_path.read_bytes()).hexdigest()
    )
    assert checkpoint["inputs"]["checkpoint"]["policy_path"] == {
        "kind": "absolute",
        "value": str(contract_path),
    }
    initial_receipt = next((tmp_path / "receipts").glob("specline-feature-new-*.json"))
    stage_receipt = json.loads(initial_receipt.read_text(encoding="utf-8"))
    assert (
        stage_receipt["inputs"]["release_contract_policy_digest"]
        == contract["policy_digest"]
    )
    assert str(contract_path) not in json.dumps(public_metrics(tmp_path))
    contract_path.unlink()
    outside.rmdir()


def test_resolve_continuation_release_contract_binds_policy_and_rejects_invalid(
    tmp_path,
):
    from factoryline.assembly import resolve_continuation_release_contract

    contract_path, contract = _release_contract_fixture(
        tmp_path, "feature", ["specline:strict"]
    )
    resolved_path, snapshot, digest = resolve_continuation_release_contract(
        tmp_path, "feature", Path("custom/feature.json")
    )
    assert resolved_path == contract_path
    assert snapshot["policy_digest"] == contract["policy_digest"]
    assert digest == hashlib.sha256(contract_path.read_bytes()).hexdigest()

    malformed_path = tmp_path / "custom" / "malformed.json"
    malformed_path.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError):
        resolve_continuation_release_contract(tmp_path, "other", malformed_path)


def test_assemble_cli_returns_report_and_structured_policy_error(tmp_path, monkeypatch):
    from factoryline.assembly import assemble_cli

    contract_path, _ = _release_contract_fixture(
        tmp_path, "feature", ["specline:strict"]
    )
    modules = [
        ModuleStatus(name, name, True, "test")
        for name in ("specline", "forgeline", "hsf", "prestige")
    ]
    monkeypatch.setattr("factoryline.assembly.detect", lambda: modules)
    report = assemble_cli(
        str(tmp_path),
        "feature",
        dry_run=True,
        release_contract_path=str(contract_path),
    )
    assert report["dry_run"] is True
    assert report["release_contract_path"] == str(contract_path)

    malformed = assemble_cli(
        tmp_path,
        "feature",
        dry_run=True,
        release_contract_path=tmp_path / "missing.json",
    )
    assert malformed["schema"] == "factory.release-contract.error.v1"
    assert malformed["code"] == "RELEASE_CONTRACT_INPUT_INVALID"


def test_continue_cli_normalizes_inputs_and_propagates_invalid_policy(
    tmp_path, monkeypatch
):
    from factoryline.continuation import continue_cli

    contract_path = tmp_path / "custom" / "policy.json"
    usage = {"tokens_in": 7}
    expected = {"status": "waiting_for_human"}
    observed = {}

    def capture(root, feature, **kwargs):
        observed.update(root=root, feature=feature, **kwargs)
        return expected

    monkeypatch.setattr("factoryline.continuation.continue_assembly", capture)
    result = continue_cli(str(tmp_path), "feature", True, usage, str(contract_path))
    assert result is expected
    assert observed == {
        "root": tmp_path,
        "feature": "feature",
        "dry_run": True,
        "usage": usage,
        "release_contract_path": contract_path,
    }

    monkeypatch.undo()
    malformed_path = tmp_path / "malformed.json"
    malformed_path.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError):
        continue_cli(tmp_path, "feature", True, None, malformed_path)


@pytest.mark.parametrize("change", ["missing", "stale"])
def test_resume_rejects_missing_or_changed_release_contract_before_stages(
    tmp_path, monkeypatch, change
):
    contract_path, calls = _pause_custom_contract(tmp_path, monkeypatch)
    if change == "missing":
        contract_path.unlink()
    else:
        contract_path.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="resume release contract"):
        continue_assembly(tmp_path, "feature")
    assert len(calls) == 1


def test_continue_rejects_rebound_contract_path_before_stages(
    tmp_path, monkeypatch, capsys
):
    from factoryline.cli import main

    contract_path, calls = _pause_custom_contract(tmp_path, monkeypatch)
    rebound_path = contract_path.with_name("rebound.json")
    rebound_path.write_bytes(contract_path.read_bytes())
    assert (
        main(
            [
                "continue",
                "feature",
                "--root",
                str(tmp_path),
                "--release-contract",
                str(contract_path),
                "--dry-run",
                "--json",
            ]
        )
        == 0
    )
    dry_run_report = json.loads(capsys.readouterr().out)
    assert dry_run_report["dry_run"] is True
    assert (
        main(
            [
                "continue",
                "feature",
                "--root",
                str(tmp_path),
                "--release-contract",
                str(rebound_path),
                "--json",
            ]
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().err)
    assert payload["code"] == "CONTINUATION_INPUT_INVALID"
    assert "differs from the paused run" in payload["message"]
    assert str(tmp_path) not in payload["message"]
    assert len(calls) == 1


def test_assemble_rejects_missing_custom_contract_before_stages(
    tmp_path, monkeypatch, capsys
):
    from factoryline.cli import main

    calls = []
    monkeypatch.setattr(
        "factoryline.assembly.detect",
        lambda: [ModuleStatus("specline", "specline", True, "test")],
    )
    monkeypatch.setattr(
        "factoryline.assembly.run_cli",
        lambda *args, **kwargs: calls.append(args) or (True, ""),
    )
    missing = tmp_path / "custom" / "missing.json"
    assert (
        main(
            [
                "assemble",
                "feature",
                "--root",
                str(tmp_path),
                "--release-contract",
                str(missing),
            ]
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().err)
    assert payload["code"] == "RELEASE_CONTRACT_INPUT_INVALID"
    assert str(tmp_path) not in payload["message"]
    assert calls == []


def test_checkpoint_inventory_ambiguity_blocks_before_stages(tmp_path, monkeypatch):
    contract_path, calls = _pause_custom_contract(tmp_path, monkeypatch)
    original = next(
        (tmp_path / "receipts").glob(
            "factoryline-feature-continuation-release-checkpoint-*.json"
        )
    )
    duplicate = original.with_name(original.stem + "-duplicate.json")
    duplicate.write_bytes(original.read_bytes())
    with pytest.raises(ValueError, match="ambiguous"):
        continue_assembly(tmp_path, "feature")
    assert len(calls) == 1


def test_changed_policy_before_lock_acquisition_is_revalidated(tmp_path, monkeypatch):
    import factoryline.assembly as assembly

    contract_path, calls = _pause_custom_contract(tmp_path, monkeypatch)
    real_open = assembly.os.open
    changed = False

    def change_policy_before_lock(path, flags, mode=0o600, *, dir_fd=None):
        nonlocal changed
        if not changed and Path(path).name.startswith("assembly-"):
            assert mode == 0o600
            contract_path.write_text("{}", encoding="utf-8")
            changed = True
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(assembly.os, "open", change_policy_before_lock)
    with pytest.raises(ValueError, match="resume release contract"):
        continue_assembly(tmp_path, "feature")
    assert changed
    assert len(calls) == 1


def test_huge_checkpoint_revision_fails_without_unbounded_allocation(
    tmp_path, monkeypatch
):
    contract_path, calls = _pause_custom_contract(tmp_path, monkeypatch)
    checkpoint_path = next(
        (tmp_path / "receipts").glob(
            "factoryline-feature-continuation-release-checkpoint-*.json"
        )
    )
    receipt = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    receipt["inputs"]["checkpoint"]["revision"] = 10**12
    checkpoint_path.write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(ValueError, match="history is incomplete"):
        continue_assembly(tmp_path, "feature")
    assert len(calls) == 1


def test_release_contract_dry_run_preserves_workspace_state(tmp_path, monkeypatch):
    from factoryline.assembly import assemble

    feature = "feature"
    contract_path, _ = _release_contract_fixture(tmp_path, feature, ["specline:strict"])
    before = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    monkeypatch.setattr(
        "factoryline.assembly.detect",
        lambda: [
            ModuleStatus(name, name, True, "test")
            for name in ("specline", "forgeline", "hsf", "prestige")
        ],
    )
    report = assemble(
        tmp_path, feature, dry_run=True, release_contract_path=contract_path
    )
    after = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    assert report["dry_run"] is True
    assert after == before
