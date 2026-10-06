from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.loop_passport import (
    build_loop_passport,
    default_manifest,
    evaluate_budget,
    init_loop,
    load_manifest,
    validate_manifest,
    verify_loop_passport,
)


def _manifest(tmp_path: Path) -> Path:
    return Path(init_loop(tmp_path, "dependency-audit", "platform-team")["path"])


def test_default_manifest_is_conservative_and_rejects_invalid_ids():
    manifest = default_manifest("dependency-audit", "platform-team")
    assert manifest["autonomy"] == "human_controlled"
    assert manifest["workspace"]["network"] == "deny"
    assert manifest["budgets"]["max_iterations"] == 1
    try:
        default_manifest("Dependency Audit", "platform-team")
    except ValueError as exc:
        assert "loop id" in str(exc)
    else:
        raise AssertionError("invalid loop id unexpectedly accepted")


def test_loop_passport_validates_and_binds_a_conservative_contract(tmp_path):
    manifest = _manifest(tmp_path)
    validation = validate_manifest(manifest)
    assert validation["valid"] is True
    passport = build_loop_passport(tmp_path, manifest)
    assert passport["verdict"] == "VERIFIED"
    assert (
        Path(passport["paths"]["mermaid"])
        .read_text(encoding="utf-8")
        .startswith("flowchart LR")
    )
    assert verify_loop_passport(Path(passport["paths"]["json"]))["valid"] is True


def test_loop_passport_requires_validator_triads_for_autonomy(tmp_path):
    manifest_path = _manifest(tmp_path)
    manifest = load_manifest(manifest_path)
    manifest["autonomy"] = "autonomous"
    manifest["workspace"]["mode"] = "ephemeral"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    validation = validate_manifest(manifest_path)
    assert validation["valid"] is False
    assert any("validators.pre" in error for error in validation["errors"])
    assert any("validators.post" in error for error in validation["errors"])
    assert any("validators.invariant" in error for error in validation["errors"])


def test_loop_passport_rejects_unapproved_destructive_capability_and_secret(tmp_path):
    manifest_path = _manifest(tmp_path)
    manifest = load_manifest(manifest_path)
    manifest["capabilities"]["actions"].append("deploy")
    manifest["approvals"]["required_for"].remove("deploy")
    manifest["capabilities"]["api_key"] = "sk-should-not-be-here"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    validation = validate_manifest(manifest_path)
    assert validation["valid"] is False
    assert any("destructive actions" in error for error in validation["errors"])
    assert any("secret-like fields" in error for error in validation["errors"])


def test_loop_budget_receipt_is_fail_closed_and_receipted(tmp_path):
    manifest = _manifest(tmp_path)
    within = tmp_path / "within.json"
    within.write_bytes(
        b"\xef\xbb\xbf"
        + json.dumps(
            {"iterations": 1, "wall_seconds": 10, "tokens": 0, "cost_usd": 0}
        ).encode("utf-8")
    )
    result = evaluate_budget(tmp_path, manifest, within)
    assert result["ok"] is True
    assert result["verdict"] == "WITHIN_BUDGET"
    assert Path(result["path"]).exists()

    exceeded = tmp_path / "exceeded.json"
    exceeded.write_text(
        json.dumps({"iterations": 2, "wall_seconds": 10, "tokens": 0, "cost_usd": 0}),
        encoding="utf-8",
    )
    result = evaluate_budget(tmp_path, manifest, exceeded)
    assert result["ok"] is False
    assert result["verdict"] == "BUDGET_EXCEEDED"
    assert result["exceeded"]["iterations"] == {"actual": 2.0, "limit": 1}


def test_loop_budget_receipt_is_incomplete_when_any_measurement_is_missing(tmp_path):
    manifest = _manifest(tmp_path)
    usage = tmp_path / "partial-usage.json"
    usage.write_text(
        json.dumps({"iterations": 1, "wall_seconds": 10, "tokens": 0}),
        encoding="utf-8",
    )

    result = evaluate_budget(tmp_path, manifest, usage)

    assert result["ok"] is False
    assert result["verdict"] == "INCOMPLETE"
    assert result["missing_measurements"] == ["cost_usd"]
    assert Path(result["path"]).exists()


def test_loop_budget_receipt_reports_invalid_manifest_without_a_traceback(tmp_path):
    manifest_path = _manifest(tmp_path)
    manifest = load_manifest(manifest_path)
    del manifest["budgets"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    usage = tmp_path / "usage.json"
    usage.write_text(
        json.dumps({"iterations": 0, "wall_seconds": 0, "tokens": 0, "cost_usd": 0}),
        encoding="utf-8",
    )
    result = evaluate_budget(tmp_path, manifest_path, usage)
    assert result["ok"] is False
    assert result["verdict"] == "MANIFEST_INVALID"
    assert result["limits"]["iterations"] is None


def test_loop_passport_verification_detects_manifest_tampering(tmp_path):
    manifest = _manifest(tmp_path)
    passport = build_loop_passport(tmp_path, manifest)
    manifest.write_text(manifest.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    result = verify_loop_passport(Path(passport["paths"]["json"]))
    assert result["valid"] is False
    assert "loop manifest hash mismatch" in result["errors"]


def test_loop_cli_outputs_json_and_returns_nonzero_for_budget_exceeded(
    tmp_path, capsys
):
    assert (
        main(
            [
                "loop",
                "init",
                "ci-audit",
                "--owner",
                "platform-team",
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    initialized = json.loads(capsys.readouterr().out)
    manifest = initialized["path"]
    assert main(["loop", "validate", manifest, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert main(["loop", "passport", manifest, "--root", str(tmp_path), "--json"]) == 0
    passport = json.loads(capsys.readouterr().out)
    assert main(["loop", "verify", passport["paths"]["json"], "--json"]) == 0
    capsys.readouterr()
    usage = tmp_path / "usage.json"
    usage.write_text(
        json.dumps({"iterations": 2, "wall_seconds": 1, "tokens": 0, "cost_usd": 0}),
        encoding="utf-8",
    )
    assert (
        main(
            ["loop", "budget", manifest, str(usage), "--root", str(tmp_path), "--json"]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["verdict"] == "BUDGET_EXCEEDED"


def _runtime_passport(tmp_path: Path) -> tuple[Path, Path]:
    manifest_path = _manifest(tmp_path)
    manifest = load_manifest(manifest_path)
    manifest["budgets"].update(
        {
            "max_iterations": 3,
            "max_wall_seconds": 120,
            "max_tokens": 10000,
            "max_cost_usd": 5,
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    passport = build_loop_passport(tmp_path, manifest_path)
    return manifest_path, Path(passport["paths"]["json"])


def test_runtime_session_replay_reuses_totals_and_changed_passport_conflicts(tmp_path):
    import secrets

    from factoryline.loop_passport import start_budget_session

    manifest_path, passport_path = _runtime_passport(tmp_path)
    run_id = secrets.token_hex(16)
    first = start_budget_session(tmp_path, passport_path, run_id)
    resumed = start_budget_session(tmp_path, passport_path, run_id)
    assert resumed["status"] == first["status"] == "ACTIVE"
    assert resumed["path"] == first["path"]
    assert resumed["usage"] == first["usage"]
    assert "RUNTIME_SESSION_REPLAY_SAFE" in resumed["markers"]

    manifest = load_manifest(manifest_path)
    manifest["budgets"]["max_tokens"] += 1
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    changed_passport = build_loop_passport(tmp_path, manifest_path)
    conflict = start_budget_session(
        tmp_path, Path(changed_passport["paths"]["json"]), run_id
    )
    assert conflict["status"] == "ACTION_CONFLICT"
    assert Path(first["path"]).read_bytes() == Path(resumed["path"]).read_bytes()


def test_runtime_reservation_is_idempotent_and_rejects_conflicting_replay(tmp_path):
    import secrets

    from factoryline.loop_passport import admit_budget_action, start_budget_session

    _, passport_path = _runtime_passport(tmp_path)
    run_id, action_id = secrets.token_hex(16), secrets.token_hex(16)
    start_budget_session(tmp_path, passport_path, run_id)
    estimate = {"iterations": 1, "wall_seconds": 10, "tokens": 100, "cost_usd": 0.1}
    admitted = admit_budget_action(tmp_path, passport_path, run_id, action_id, estimate)
    replay = admit_budget_action(tmp_path, passport_path, run_id, action_id, estimate)
    conflict = admit_budget_action(
        tmp_path,
        passport_path,
        run_id,
        action_id,
        {**estimate, "tokens": 101},
    )
    assert admitted["status"] == "ADMITTED"
    assert replay["action"] == admitted["action"]
    assert "RUNTIME_ACTION_IDEMPOTENT" in replay["markers"]
    assert conflict["status"] == "ACTION_CONFLICT"


def test_runtime_settlement_replay_reconciles_reservation_once(tmp_path):
    import secrets

    from factoryline.loop_passport import (
        admit_budget_action,
        budget_session_status,
        settle_budget_action,
        start_budget_session,
    )

    _, passport_path = _runtime_passport(tmp_path)
    run_id, action_id = secrets.token_hex(16), secrets.token_hex(16)
    start_budget_session(tmp_path, passport_path, run_id)
    estimate = {"iterations": 1, "wall_seconds": 10, "tokens": 100, "cost_usd": 0.1}
    admit_budget_action(tmp_path, passport_path, run_id, action_id, estimate)
    actual = {"iterations": 1, "wall_seconds": 12, "tokens": 110, "cost_usd": 0.11}
    settled = settle_budget_action(tmp_path, passport_path, run_id, action_id, actual)
    replay = settle_budget_action(tmp_path, passport_path, run_id, action_id, actual)
    conflict = settle_budget_action(
        tmp_path,
        passport_path,
        run_id,
        action_id,
        {**actual, "tokens": 111},
    )
    status = budget_session_status(tmp_path, passport_path, run_id)
    assert settled["status"] == "SETTLED"
    assert replay["action"] == settled["action"]
    assert "RUNTIME_SETTLEMENT_IDEMPOTENT" in replay["markers"]
    assert conflict["status"] == "ACTION_CONFLICT"
    assert status["usage"] == {
        "iterations": 1,
        "wall_seconds": 12,
        "tokens": 110,
        "cost_usd": "0.11",
    }


def test_runtime_pending_reservation_survives_restart_and_blocks_new_action(tmp_path):
    import secrets

    from factoryline.loop_passport import (
        admit_budget_action,
        start_budget_session,
    )

    _, passport_path = _runtime_passport(tmp_path)
    run_id, action_id = secrets.token_hex(16), secrets.token_hex(16)
    session = start_budget_session(tmp_path, passport_path, run_id)
    estimate = {"iterations": 1, "wall_seconds": 10, "tokens": 100, "cost_usd": 0.1}
    admit_budget_action(tmp_path, passport_path, run_id, action_id, estimate)

    # A fresh call reopens the durable ledger, like a new adapter process.
    resumed = start_budget_session(tmp_path, passport_path, run_id)
    blocked = admit_budget_action(
        tmp_path, passport_path, run_id, secrets.token_hex(16), estimate
    )
    assert resumed["path"] == session["path"]
    assert resumed["usage"] == {
        "iterations": 1,
        "wall_seconds": 10,
        "tokens": 100,
        "cost_usd": "0.1",
    }
    assert blocked["status"] == "ACTION_IN_PROGRESS"


def test_runtime_concurrent_admission_serializes_check_and_reserve(tmp_path):
    import secrets
    from concurrent.futures import ThreadPoolExecutor

    from factoryline.loop_passport import admit_budget_action, start_budget_session

    _, passport_path = _runtime_passport(tmp_path)
    run_id = secrets.token_hex(16)
    start_budget_session(tmp_path, passport_path, run_id)
    estimate = {"iterations": 1, "wall_seconds": 10, "tokens": 100, "cost_usd": 0.1}

    def reserve() -> dict:
        return admit_budget_action(
            tmp_path, passport_path, run_id, secrets.token_hex(16), estimate
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: reserve(), range(2)))
    statuses = sorted(result["status"] for result in results)
    assert statuses == ["ACTION_IN_PROGRESS", "ADMITTED"]


def test_runtime_rejects_invalid_identifiers_and_stores_only_digests(tmp_path):
    import secrets

    from factoryline.loop_passport import start_budget_session

    _, passport_path = _runtime_passport(tmp_path)
    invalid_id = "prompt text with spaces"
    rejected = start_budget_session(tmp_path, passport_path, invalid_id)
    assert rejected["status"] == "INCOMPLETE"
    assert "RUNTIME_OPERATION_FAIL_CLOSED" in rejected["markers"]
    assert "RUNTIME_SESSION_INCOMPLETE" not in rejected["markers"]
    run_id = secrets.token_hex(16)
    result = start_budget_session(tmp_path, passport_path, run_id)
    database = Path(result["path"]).read_bytes()
    assert run_id.encode("ascii") not in database


def test_runtime_missing_settlement_measurement_fails_closed(tmp_path):
    import secrets

    from factoryline.loop_passport import (
        admit_budget_action,
        settle_budget_action,
        start_budget_session,
    )

    _, passport_path = _runtime_passport(tmp_path)
    run_id, action_id = secrets.token_hex(16), secrets.token_hex(16)
    start_budget_session(tmp_path, passport_path, run_id)
    admit_budget_action(
        tmp_path,
        passport_path,
        run_id,
        action_id,
        {"iterations": 1, "wall_seconds": 10, "tokens": 100, "cost_usd": 0.1},
    )
    incomplete = settle_budget_action(
        tmp_path,
        passport_path,
        run_id,
        action_id,
        {"iterations": 1, "wall_seconds": 10, "tokens": 100},
    )
    assert incomplete["status"] == "INCOMPLETE"
    blocked = admit_budget_action(
        tmp_path,
        passport_path,
        run_id,
        secrets.token_hex(16),
        {"iterations": 1, "wall_seconds": 10, "tokens": 100, "cost_usd": 0.1},
    )
    assert blocked["status"] == "ACTION_IN_PROGRESS"


def test_runtime_overrun_is_recorded_and_closes_the_session(tmp_path):
    import secrets

    from factoryline.loop_passport import (
        admit_budget_action,
        settle_budget_action,
        start_budget_session,
    )

    _, passport_path = _runtime_passport(tmp_path)
    run_id, action_id = secrets.token_hex(16), secrets.token_hex(16)
    start_budget_session(tmp_path, passport_path, run_id)
    admit_budget_action(
        tmp_path,
        passport_path,
        run_id,
        action_id,
        {"iterations": 1, "wall_seconds": 10, "tokens": 100, "cost_usd": 0.1},
    )
    result = settle_budget_action(
        tmp_path,
        passport_path,
        run_id,
        action_id,
        {"iterations": 1, "wall_seconds": 11, "tokens": 101, "cost_usd": 6},
    )
    assert result["status"] == "BUDGET_EXCEEDED"
    assert "RUNTIME_OVERRUN_RECORDED" in result["markers"]
    assert result["usage"]["cost_usd"] == 6


def test_runtime_detects_manifest_change_before_admission(tmp_path):
    import secrets

    from factoryline.loop_passport import (
        admit_budget_action,
        load_manifest,
        start_budget_session,
    )

    manifest_path, passport_path = _runtime_passport(tmp_path)
    run_id = secrets.token_hex(16)
    start_budget_session(tmp_path, passport_path, run_id)
    manifest = load_manifest(manifest_path)
    manifest["budgets"]["max_tokens"] += 1
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = admit_budget_action(
        tmp_path,
        passport_path,
        run_id,
        secrets.token_hex(16),
        {"iterations": 1, "wall_seconds": 1, "tokens": 1, "cost_usd": 0},
    )
    assert result["status"] == "INCOMPLETE"
    assert "RUNTIME_SESSION_INCOMPLETE" in result["markers"]


def test_runtime_rejects_non_object_passport_without_traceback(tmp_path):
    from factoryline.loop_passport import start_budget_session, verify_loop_passport

    for payload in ("[", "[]", "null"):
        passport_path = tmp_path / "passport.json"
        passport_path.write_text(payload, encoding="utf-8")
        verification = verify_loop_passport(passport_path)
        result = start_budget_session(tmp_path, passport_path, "a" * 32)

        assert verification["valid"] is False
        assert result["status"] == "INCOMPLETE"
        assert "RUNTIME_SESSION_INCOMPLETE" in result["markers"]
        assert "passport" in result["error"].casefold()
        assert not (tmp_path / ".factory" / "loop-runs").exists()


def test_hsf_admission_advice_routes_extraction_failure_to_human_review(tmp_path):
    pytest.importorskip(
        "hsf",
        reason="HSF integration is exercised in the dedicated five-brick CI job",
    )
    from hsf.foundry.compiler import render_artifact
    from hsf.runtime import Orchestrator
    from hsf.runtime.extractor import FixtureExtractor
    from hsf.spec.loader import load_spec

    spec_path = (
        Path(__file__).parents[1] / "specs" / "loop-runtime-budget-admission.yaml"
    )
    spec, spec_sha = load_spec(spec_path)
    artifact = tmp_path / "admission_advice.py"
    artifact.write_text(render_artifact(spec, spec_sha, "template"), encoding="utf-8")
    status_contract = spec.outputs["AdmissionAdvice"]["status"]
    assert "HUMAN_REVIEW" in status_contract

    result = Orchestrator(artifact, FixtureExtractor({})).run(
        {"text": "No structured runtime evidence is available."}
    )

    assert result.status == "HUMAN_REVIEW"


def test_runtime_rejects_non_csprng_action_id_without_persisting_it(tmp_path):
    import secrets

    from factoryline.loop_passport import (
        admit_budget_action,
        start_budget_session,
    )

    _, passport_path = _runtime_passport(tmp_path)
    run_id = secrets.token_hex(16)
    start_budget_session(tmp_path, passport_path, run_id)
    result = admit_budget_action(
        tmp_path,
        passport_path,
        run_id,
        "prompttextwithoutspaces1234567",
        {"iterations": 1, "wall_seconds": 1, "tokens": 1, "cost_usd": 0},
    )
    assert result["status"] == "INCOMPLETE"
    assert not list(
        (tmp_path / ".factory" / "loop-runs").rglob("prompttextwithoutspaces1234567")
    )


def test_runtime_fixed_point_accounting_is_exact_at_fractional_budget_boundary(
    tmp_path,
):
    import secrets
    from decimal import Decimal

    from factoryline.loop_passport import (
        admit_budget_action,
        build_loop_passport,
        settle_budget_action,
        start_budget_session,
    )

    manifest_path, _ = _runtime_passport(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["budgets"]["max_cost_usd"] = 0.3
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    passport_path = Path(build_loop_passport(tmp_path, manifest_path)["paths"]["json"])
    run_id = secrets.token_hex(16)
    start_budget_session(tmp_path, passport_path, run_id)

    first_action = secrets.token_hex(16)
    first = {"iterations": 1, "wall_seconds": 1, "tokens": 1, "cost_usd": 0.1}
    assert (
        admit_budget_action(tmp_path, passport_path, run_id, first_action, first)[
            "status"
        ]
        == "ADMITTED"
    )
    assert (
        settle_budget_action(tmp_path, passport_path, run_id, first_action, first)[
            "status"
        ]
        == "SETTLED"
    )

    second_action = secrets.token_hex(16)
    second = {"iterations": 1, "wall_seconds": 1, "tokens": 1, "cost_usd": 0.2}
    assert (
        admit_budget_action(tmp_path, passport_path, run_id, second_action, second)[
            "status"
        ]
        == "ADMITTED"
    )
    settled = settle_budget_action(
        tmp_path,
        passport_path,
        run_id,
        second_action,
        {**second, "cost_usd": 0.200001},
    )
    assert settled["status"] == "BUDGET_EXCEEDED"
    assert settled["usage"]["cost_usd"] == "0.300001"

    rejected = admit_budget_action(
        tmp_path,
        passport_path,
        run_id,
        secrets.token_hex(16),
        {**first, "cost_usd": 0.0000001},
    )
    assert rejected["status"] == "INCOMPLETE"
    assert "at most 6 fractional digits" in rejected["error"]
    long_significand = Decimal("1." + ("0" * 80) + "1")
    rejected_long = admit_budget_action(
        tmp_path,
        passport_path,
        run_id,
        secrets.token_hex(16),
        {**first, "cost_usd": long_significand},
    )
    assert rejected_long["status"] == "INCOMPLETE"
    assert "at most 6 fractional digits" in rejected_long["error"]


def test_runtime_rejects_rehashed_passport_claims_not_bound_to_manifest(tmp_path):
    import hashlib

    from factoryline.loop_passport import _canonical, _runtime_payload

    _, passport_path = _runtime_passport(tmp_path)
    passport = json.loads(passport_path.read_text(encoding="utf-8"))
    passport["loop_id"] = "../../outside"
    passport["budgets"]["max_cost_usd"] = 10**12
    core = {
        key: value
        for key, value in passport.items()
        if key not in {"passport_sha256", "paths"}
    }
    passport["passport_sha256"] = hashlib.sha256(_canonical(core)).hexdigest()
    passport_path.write_text(json.dumps(passport), encoding="utf-8")

    verified = verify_loop_passport(passport_path)
    assert verified["valid"] is False
    assert any("loop_id" in error for error in verified["errors"])
    assert any("budgets" in error for error in verified["errors"])
    try:
        _runtime_payload(passport_path)
    except ValueError as error:
        assert "invalid" in str(error)
    else:
        raise AssertionError("forged passport claims must fail closed")


def test_runtime_rejects_manifest_change_between_verification_and_claim_binding(
    tmp_path, monkeypatch
):
    import factoryline.loop_passport as loop_passport

    manifest_path, passport_path = _runtime_passport(tmp_path)
    original_verify = loop_passport.verify_loop_passport

    def verify_then_replace(path):
        result = original_verify(path)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["budgets"]["max_tokens"] += 1
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return result

    monkeypatch.setattr(loop_passport, "verify_loop_passport", verify_then_replace)
    try:
        loop_passport._runtime_payload(passport_path)
    except ValueError as error:
        assert "changed after passport verification" in str(error)
    else:
        raise AssertionError("manifest replacement must invalidate the passport")


def test_runtime_ledger_rejects_symlink_escape_from_workspace_root(tmp_path):
    import secrets

    from factoryline.loop_passport import start_budget_session

    _, passport_path = _runtime_passport(tmp_path)
    factory_dir = tmp_path / ".factory"
    factory_dir.mkdir(exist_ok=True)
    outside = tmp_path / "outside-ledger"
    outside.mkdir()
    try:
        (factory_dir / "loop-runs").symlink_to(outside, target_is_directory=True)
    except OSError as error:
        import pytest

        pytest.skip(f"directory symlinks unavailable: {error}")

    result = start_budget_session(tmp_path, passport_path, secrets.token_hex(16))
    assert result["status"] == "INCOMPLETE"
    assert "uses a link" in result["error"]
    assert "RUNTIME_LEDGER_PATH_BLOCKED" in result["markers"]
    assert not list(outside.iterdir())


def test_runtime_ledger_rejects_database_file_symlink_alias(tmp_path):
    import secrets

    from factoryline.loop_passport import (
        _runtime_database_path,
        _runtime_id_digest,
        start_budget_session,
    )

    _, passport_path = _runtime_passport(tmp_path)
    first = start_budget_session(tmp_path, passport_path, secrets.token_hex(16))
    second_run_id = secrets.token_hex(16)
    passport = json.loads(passport_path.read_text(encoding="utf-8"))
    target = _runtime_database_path(
        tmp_path, passport["loop_id"], _runtime_id_digest(second_run_id, "run_id")
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        target.symlink_to(Path(first["path"]))
    except OSError as error:
        import pytest

        pytest.skip(f"file symlinks unavailable: {error}")

    result = start_budget_session(tmp_path, passport_path, second_run_id)
    assert result["status"] == "INCOMPLETE"
    assert "RUNTIME_LEDGER_PATH_BLOCKED" in result["markers"]
    assert "RUNTIME_SESSION_PASSPORT_BOUND" not in result["markers"]


def test_runtime_ledger_rejects_loop_directory_symlink_alias(tmp_path):
    import secrets

    from factoryline.loop_passport import start_budget_session

    _, passport_path = _runtime_passport(tmp_path)
    passport = json.loads(passport_path.read_text(encoding="utf-8"))
    ledger_root = tmp_path / ".factory" / "loop-runs"
    alias_target = ledger_root / "other-loop"
    alias_target.mkdir(parents=True)
    requested = ledger_root / passport["loop_id"]
    try:
        requested.symlink_to(alias_target, target_is_directory=True)
    except OSError as error:
        import pytest

        pytest.skip(f"directory symlinks unavailable: {error}")

    result = start_budget_session(tmp_path, passport_path, secrets.token_hex(16))
    assert result["status"] == "INCOMPLETE"
    assert "RUNTIME_LEDGER_PATH_BLOCKED" in result["markers"]
    assert not list(alias_target.iterdir())


def test_runtime_admission_replay_never_reauthorizes_settled_or_blocked_work(tmp_path):
    import secrets

    from factoryline.loop_passport import (
        admit_budget_action,
        settle_budget_action,
        start_budget_session,
    )

    manifest_path, passport_path = _runtime_passport(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["budgets"]["max_cost_usd"] = 1
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    from factoryline.loop_passport import build_loop_passport

    passport_path = Path(build_loop_passport(tmp_path, manifest_path)["paths"]["json"])
    run_id, action_id = secrets.token_hex(16), secrets.token_hex(16)
    estimate = {"iterations": 1, "wall_seconds": 1, "tokens": 1, "cost_usd": 0.1}
    start_budget_session(tmp_path, passport_path, run_id)
    assert (
        admit_budget_action(tmp_path, passport_path, run_id, action_id, estimate)[
            "status"
        ]
        == "ADMITTED"
    )
    settled = settle_budget_action(
        tmp_path,
        passport_path,
        run_id,
        action_id,
        {**estimate, "cost_usd": 0.2},
    )
    assert settled["status"] == "SETTLED"

    replay = admit_budget_action(tmp_path, passport_path, run_id, action_id, estimate)
    assert replay["status"] == "SETTLED"
    assert replay["action"]["status"] == "SETTLED"
    assert "RUNTIME_ACTION_RESERVED" not in replay["markers"]
    assert "RUNTIME_ACTION_ALREADY_SETTLED" in replay["markers"]

    # A later overrun closes the run; even a previously admitted action must
    # no longer return an authorizing ADMITTED receipt.
    second_action = secrets.token_hex(16)
    assert (
        admit_budget_action(tmp_path, passport_path, run_id, second_action, estimate)[
            "status"
        ]
        == "ADMITTED"
    )
    overrun = settle_budget_action(
        tmp_path,
        passport_path,
        run_id,
        second_action,
        {**estimate, "cost_usd": 1.1},
    )
    assert overrun["status"] == "BUDGET_EXCEEDED"
    blocked_replay = admit_budget_action(
        tmp_path, passport_path, run_id, action_id, estimate
    )
    assert blocked_replay["status"] == "BUDGET_EXCEEDED"
    assert "RUNTIME_ACTION_REPLAY_BLOCKED" in blocked_replay["markers"]
    assert "action" not in blocked_replay


def test_runtime_ledger_migrates_older_action_table(tmp_path):
    import sqlite3

    from factoryline.loop_passport import _runtime_connection

    database = tmp_path / "legacy.sqlite"
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TABLE action (action_digest TEXT PRIMARY KEY, request_sha256 TEXT NOT NULL, "
        "estimate_json TEXT NOT NULL, actual_json TEXT, settlement_sha256 TEXT, "
        "settlement_json TEXT, status TEXT NOT NULL, created_at TEXT NOT NULL, settled_at TEXT)"
    )
    connection.close()

    migrated = _runtime_connection(database)
    columns = {row[1] for row in migrated.execute("PRAGMA table_info(action)")}
    migrated.close()
    assert "admission_json" in columns
    assert "accounting_version" in columns


def _seed_admitted_runtime_action(tmp_path):
    import secrets
    import sqlite3

    from factoryline.loop_passport import admit_budget_action, start_budget_session

    _, passport_path = _runtime_passport(tmp_path)
    run_id, action_id = secrets.token_hex(16), secrets.token_hex(16)
    session = start_budget_session(tmp_path, passport_path, run_id)
    assert session["status"] == "ACTIVE"
    estimate = {"iterations": 1, "wall_seconds": 1, "tokens": 1, "cost_usd": 0.1}
    admission = admit_budget_action(
        tmp_path, passport_path, run_id, action_id, estimate
    )
    assert admission["status"] == "ADMITTED"
    return sqlite3, passport_path, run_id, action_id, Path(session["path"])


def test_runtime_corrupt_usage_row_returns_incomplete(tmp_path):
    from factoryline.loop_passport import budget_session_status

    sqlite3, passport_path, run_id, _, database = _seed_admitted_runtime_action(
        tmp_path
    )
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE action SET estimate_json = '{}' ")

    result = budget_session_status(tmp_path, passport_path, run_id)
    assert result["status"] == "INCOMPLETE"
    assert "RUNTIME_SESSION_INCOMPLETE" in result["markers"]


def test_runtime_missing_replay_receipt_returns_incomplete(tmp_path):
    from factoryline.loop_passport import admit_budget_action

    sqlite3, passport_path, run_id, action_id, database = _seed_admitted_runtime_action(
        tmp_path
    )
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE action SET admission_json = NULL")

    result = admit_budget_action(
        tmp_path,
        passport_path,
        run_id,
        action_id,
        {"iterations": 1, "wall_seconds": 1, "tokens": 1, "cost_usd": 0.1},
    )
    assert result["status"] == "INCOMPLETE"
    assert "RUNTIME_SESSION_INCOMPLETE" in result["markers"]


def test_runtime_settled_replay_rejects_receipt_that_claims_admitted(tmp_path):
    import json

    from factoryline.loop_passport import admit_budget_action, settle_budget_action

    sqlite3, passport_path, run_id, action_id, database = _seed_admitted_runtime_action(
        tmp_path
    )
    estimate = {"iterations": 1, "wall_seconds": 1, "tokens": 1, "cost_usd": 0.1}
    settled = settle_budget_action(tmp_path, passport_path, run_id, action_id, estimate)
    assert settled["status"] == "SETTLED"
    with sqlite3.connect(database) as connection:
        row = connection.execute("SELECT settlement_json FROM action").fetchone()
        receipt = json.loads(row[0])
        receipt["status"] = "ADMITTED"
        receipt["action"]["status"] = "ADMITTED"
        connection.execute(
            "UPDATE action SET settlement_json = ?",
            (json.dumps(receipt),),
        )

    result = admit_budget_action(tmp_path, passport_path, run_id, action_id, estimate)
    assert result["status"] == "INCOMPLETE"
    assert "RUNTIME_SESSION_INCOMPLETE" in result["markers"]
    assert "RUNTIME_ACTION_RESERVED" not in result["markers"]


def test_runtime_admission_replay_rejects_corrupt_request_digest(tmp_path):
    from factoryline.loop_passport import admit_budget_action

    sqlite3, passport_path, run_id, action_id, database = _seed_admitted_runtime_action(
        tmp_path
    )
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE action SET request_sha256 = ?", ("0" * 64,))

    result = admit_budget_action(
        tmp_path,
        passport_path,
        run_id,
        action_id,
        {"iterations": 1, "wall_seconds": 1, "tokens": 1, "cost_usd": 0.1},
    )
    assert result["status"] == "INCOMPLETE"
    assert "RUNTIME_SESSION_INCOMPLETE" in result["markers"]


def test_runtime_settlement_replay_rejects_corrupt_measurement_digest(tmp_path):
    from factoryline.loop_passport import settle_budget_action

    sqlite3, passport_path, run_id, action_id, database = _seed_admitted_runtime_action(
        tmp_path
    )
    actual = {"iterations": 1, "wall_seconds": 1, "tokens": 1, "cost_usd": 0.1}
    assert (
        settle_budget_action(tmp_path, passport_path, run_id, action_id, actual)[
            "status"
        ]
        == "SETTLED"
    )
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE action SET settlement_sha256 = ?", ("0" * 64,))

    result = settle_budget_action(tmp_path, passport_path, run_id, action_id, actual)
    assert result["status"] == "INCOMPLETE"
    assert "RUNTIME_SESSION_INCOMPLETE" in result["markers"]


def test_runtime_settlement_replay_requires_overrun_marker_for_overrun_status(
    tmp_path,
):
    import json

    from factoryline.loop_passport import admit_budget_action, settle_budget_action

    sqlite3, passport_path, run_id, action_id, database = _seed_admitted_runtime_action(
        tmp_path
    )
    estimate = {"iterations": 1, "wall_seconds": 1, "tokens": 1, "cost_usd": 0.1}
    settle_budget_action(tmp_path, passport_path, run_id, action_id, estimate)
    with sqlite3.connect(database) as connection:
        row = connection.execute("SELECT settlement_json FROM action").fetchone()
        receipt = json.loads(row[0])
        receipt["status"] = "BUDGET_EXCEEDED"
        connection.execute(
            "UPDATE action SET settlement_json = ?", (json.dumps(receipt),)
        )

    result = admit_budget_action(tmp_path, passport_path, run_id, action_id, estimate)
    assert result["status"] == "INCOMPLETE"
    assert "RUNTIME_SESSION_INCOMPLETE" in result["markers"]


def test_runtime_settlement_replay_rejects_spurious_overrun_marker(tmp_path):
    import json

    from factoryline.loop_passport import admit_budget_action, settle_budget_action

    sqlite3, passport_path, run_id, action_id, database = _seed_admitted_runtime_action(
        tmp_path
    )
    estimate = {"iterations": 1, "wall_seconds": 1, "tokens": 1, "cost_usd": 0.1}
    settle_budget_action(tmp_path, passport_path, run_id, action_id, estimate)
    with sqlite3.connect(database) as connection:
        row = connection.execute("SELECT settlement_json FROM action").fetchone()
        receipt = json.loads(row[0])
        receipt["markers"].append("RUNTIME_OVERRUN_RECORDED")
        connection.execute(
            "UPDATE action SET settlement_json = ?", (json.dumps(receipt),)
        )

    result = admit_budget_action(tmp_path, passport_path, run_id, action_id, estimate)
    assert result["status"] == "INCOMPLETE"
    assert "RUNTIME_SESSION_INCOMPLETE" in result["markers"]


def test_loop_runtime_cli_session_admit_settle_and_status(tmp_path, capsys):
    import argparse
    import secrets

    from factoryline.cli_runtime_proof import (
        add_loop_parser,
        add_loop_runtime_parser,
        run_loop_runtime,
    )

    manifest, passport = _runtime_passport(tmp_path)
    run_id, action_id = secrets.token_hex(16), secrets.token_hex(16)
    estimate_path = tmp_path / "estimate.json"
    actual_path = tmp_path / "actual.json"
    estimate = {"iterations": 1, "wall_seconds": 2, "tokens": 10, "cost_usd": 0.01}
    estimate_path.write_text(json.dumps(estimate), encoding="utf-8")
    actual = {"iterations": 1, "wall_seconds": 3, "tokens": 11, "cost_usd": 0.02}
    actual_path.write_text(json.dumps(actual), encoding="utf-8")

    assert (
        main(
            [
                "loop",
                "runtime",
                "session",
                str(passport),
                "--run-id",
                run_id,
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    session = json.loads(capsys.readouterr().out)
    assert session["status"] == "ACTIVE"

    assert (
        main(
            [
                "loop",
                "runtime",
                "admit",
                str(passport),
                "--values",
                str(estimate_path),
                "--run-id",
                run_id,
                "--action-id",
                action_id,
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "ADMITTED"

    assert (
        main(
            [
                "loop",
                "runtime",
                "settle",
                str(passport),
                "--values",
                str(actual_path),
                "--run-id",
                run_id,
                "--action-id",
                action_id,
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "SETTLED"

    assert (
        main(
            [
                "loop",
                "runtime",
                "status",
                str(passport),
                "--run-id",
                run_id,
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    status = json.loads(capsys.readouterr().out)
    assert status["usage"] == {
        "iterations": 1,
        "wall_seconds": 3,
        "tokens": 11,
        "cost_usd": "0.02",
    }
    assert status["pending_action"] is False
    assert manifest.exists()

    # Exercise both parser layers and the public runtime handler directly as
    # well as through main(), so each supported CLI entry point stays covered.
    root_parser = argparse.ArgumentParser()
    root_commands = root_parser.add_subparsers(dest="command", required=True)
    add_loop_parser(root_commands)
    parsed = root_parser.parse_args(
        [
            "loop",
            "runtime",
            "status",
            str(passport),
            "--run-id",
            run_id,
            "--root",
            str(tmp_path),
            "--json",
        ]
    )
    assert parsed.command == "loop"
    assert parsed.loop_cmd == "runtime"
    assert parsed.loop_runtime_cmd == "status"

    runtime_parser = argparse.ArgumentParser()
    add_loop_runtime_parser(runtime_parser)
    runtime_args = runtime_parser.parse_args(
        ["status", str(passport), "--run-id", run_id, "--root", str(tmp_path), "--json"]
    )
    assert run_loop_runtime(runtime_args) == 0
    direct_status = json.loads(capsys.readouterr().out)
    assert direct_status["usage"] == {
        "iterations": 1,
        "wall_seconds": 3,
        "tokens": 11,
        "cost_usd": "0.02",
    }
