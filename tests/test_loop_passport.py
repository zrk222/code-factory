from __future__ import annotations

import json
from pathlib import Path

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
    assert Path(passport["paths"]["mermaid"]).read_text(encoding="utf-8").startswith("flowchart LR")
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
    within.write_bytes(b"\xef\xbb\xbf" + json.dumps({"iterations": 1, "wall_seconds": 10, "tokens": 0, "cost_usd": 0}).encode("utf-8"))
    result = evaluate_budget(tmp_path, manifest, within)
    assert result["ok"] is True
    assert result["verdict"] == "WITHIN_BUDGET"
    assert Path(result["path"]).exists()

    exceeded = tmp_path / "exceeded.json"
    exceeded.write_text(json.dumps({"iterations": 2, "wall_seconds": 10, "tokens": 0, "cost_usd": 0}), encoding="utf-8")
    result = evaluate_budget(tmp_path, manifest, exceeded)
    assert result["ok"] is False
    assert result["verdict"] == "BUDGET_EXCEEDED"
    assert result["exceeded"]["iterations"] == {"actual": 2.0, "limit": 1}


def test_loop_budget_receipt_reports_invalid_manifest_without_a_traceback(tmp_path):
    manifest_path = _manifest(tmp_path)
    manifest = load_manifest(manifest_path)
    del manifest["budgets"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    usage = tmp_path / "usage.json"
    usage.write_text(json.dumps({"iterations": 0, "wall_seconds": 0, "tokens": 0, "cost_usd": 0}), encoding="utf-8")
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


def test_loop_cli_outputs_json_and_returns_nonzero_for_budget_exceeded(tmp_path, capsys):
    assert main(["loop", "init", "ci-audit", "--owner", "platform-team", "--root", str(tmp_path), "--json"]) == 0
    initialized = json.loads(capsys.readouterr().out)
    manifest = initialized["path"]
    assert main(["loop", "validate", manifest, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert main(["loop", "passport", manifest, "--root", str(tmp_path), "--json"]) == 0
    passport = json.loads(capsys.readouterr().out)
    assert main(["loop", "verify", passport["paths"]["json"], "--json"]) == 0
    capsys.readouterr()
    usage = tmp_path / "usage.json"
    usage.write_text(json.dumps({"iterations": 2, "wall_seconds": 1, "tokens": 0, "cost_usd": 0}), encoding="utf-8")
    assert main(["loop", "budget", manifest, str(usage), "--root", str(tmp_path), "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["verdict"] == "BUDGET_EXCEEDED"
