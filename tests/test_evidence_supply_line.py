from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys

import pytest

from factoryline.cli import main
from factoryline.gauntlet_draft import draft_gauntlet
from factoryline.loop_passport import build_loop_passport, init_loop
from factoryline.run_admission import prepare_admission
from factoryline.session_recorder import run_observed_session, verify_session_receipt


AGENT = {"schema": "factory.agent-identity.v1", "subject": "agent-alpha", "provider": "local", "model": "test"}


def _admission(root: Path, identifier: str = "observed-run") -> Path:
    manifest = Path(init_loop(root, "observed-loop", "platform-team")["path"])
    passport = Path(build_loop_passport(root, manifest)["paths"]["json"])
    request = root / "request.json"
    request.write_text(json.dumps({
        "schema": "factory.run-admission.request.v1",
        "id": identifier,
        "valid_until": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
        "trigger": {"type": "manual"},
        "actions": ["read_repository"],
        "paths": ["."],
        "budget": {"max_iterations": 1, "max_wall_seconds": 30, "max_tokens": 0, "max_cost_usd": 0},
        "approvals": [],
        "agent": AGENT,
    }), encoding="utf-8")
    return Path(prepare_admission(root, passport, request)["path"])


def _validators(root: Path, *, passing: bool = True) -> Path:
    path = root / "validators.json"
    code = "from pathlib import Path; assert Path('product.txt').read_text() == 'ready'" if passing else "raise AssertionError('wrong output')"
    path.write_text(json.dumps({
        "schema": "factory.session-recorder.validators.v1",
        "verifier_subject": "independent-verifier",
        "validators": [{"id": "product-proof", "argv": [sys.executable, "-c", code], "timeout_seconds": 10}],
    }), encoding="utf-8")
    return path


def test_observed_session_binds_pre_run_admission_delta_validators_and_license_event(tmp_path: Path) -> None:
    validators = _validators(tmp_path)
    admission = _admission(tmp_path)

    result = run_observed_session(
        tmp_path,
        admission,
        validators,
        [sys.executable, "-c", "from pathlib import Path; Path('product.txt').write_text('ready')"],
        "observed-run",
    )

    assert result["session"]["passed"] is True
    assert result["ledger"]["marker"] == "AGENT_LICENSE_EVENT_RECORDED"
    receipt = json.loads(Path(result["path"]).read_text(encoding="utf-8"))
    observed = json.loads((tmp_path / receipt["result"]["path"]).read_text(encoding="utf-8"))
    assert observed["admission"]["pre_run_verdict"] == "READY"
    assert observed["workspace_delta"] == [{"after_sha256": observed["workspace_delta"][0]["after_sha256"], "path": "product.txt", "status": "created"}]
    assert observed["scope_limits"][0] == "Observed execution is not sandboxed execution."
    assert "Path('product.txt')" not in json.dumps(observed)
    assert verify_session_receipt(tmp_path, Path(result["path"]))["ok"] is True


def test_observed_session_classifies_validator_failure_without_calling_it_hollow(tmp_path: Path) -> None:
    validators = _validators(tmp_path, passing=False)
    result = run_observed_session(
        tmp_path,
        _admission(tmp_path, "failed-run"),
        validators,
        [sys.executable, "-c", "from pathlib import Path; Path('product.txt').write_text('ready')"],
        "failed-run",
    )

    assert result["session"]["passed"] is False
    assert result["session"]["failure_classes"] == ["wrong_output"]
    assert result["ledger"]["incident_path"] is None


def test_gauntlet_draft_uses_structural_cli_evidence_and_withholds_route_execution(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname="demo"\nversion="1.0"\n[project.scripts]\ndemo="demo:main"\n', encoding="utf-8")
    (tmp_path / "api.py").write_text('from fastapi import FastAPI\napp=FastAPI()\n@app.get("/health")\ndef health(): return {"ok": True}\n', encoding="utf-8")

    result = draft_gauntlet(tmp_path, "demo-draft")
    source = json.loads(Path(result["source_path"]).read_text(encoding="utf-8"))

    assert result["draft"]["status"] == "DRAFT"
    assert result["draft"]["facts"]["runnable_manifest_count"] == 0
    assert source["promises"][0]["evidence"]["target"] == "demo:main"
    assert source["unresolved_http_routes"][0]["route"] == "/health"
    assert all(value is False for value in result["draft"]["authority"].values())


def test_cli_draft_and_wrap_are_exposed(tmp_path: Path, capsys) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname="demo"\nversion="1.0"\n[project.scripts]\ndemo="demo:main"\n', encoding="utf-8")
    assert main(["gauntlet", "draft", "--root", str(tmp_path), "--source-id", "demo-draft", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["draft"]["marker"] == "GAUNTLET_DRAFT_CREATED"

    validators = _validators(tmp_path)
    admission = _admission(tmp_path, "cli-wrap")
    code = main([
        "wrap", "--root", str(tmp_path), "--admission", str(admission), "--validators", str(validators),
        "--run-id", "cli-wrap", "--json", "--", sys.executable, "-c", "from pathlib import Path; Path('product.txt').write_text('ready')",
    ])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["session"]["passed"] is True


def test_claude_hook_plugin_hashes_input_without_retaining_it(tmp_path: Path) -> None:
    script = Path(__file__).parents[1] / "plugins" / "code-factory-session-recorder" / "scripts" / "record_hook.py"
    secret = "do-not-retain-this-command"
    env = {**os.environ, "CLAUDE_PROJECT_DIR": str(tmp_path)}
    completed = subprocess.run(
        [sys.executable, str(script), "pre-tool"], input=json.dumps({"session_id": "abc", "tool_name": "Bash", "tool_input": {"command": secret}}),
        text=True, capture_output=True, env=env, check=False,
    )
    assert completed.returncode == 0
    record = next((tmp_path / ".factory" / "session-recorder" / "claude-hooks").rglob("*.json"))
    text = record.read_text(encoding="utf-8")
    assert secret not in text
    assert json.loads(text)["tool_name"] == "Bash"


def test_observed_session_rejects_reused_or_mismatched_admission_before_execution(tmp_path: Path) -> None:
    validators = _validators(tmp_path)
    admission = _admission(tmp_path, "single-use-run")
    command = [sys.executable, "-c", "from pathlib import Path; Path('product.txt').write_text('ready')"]
    run_observed_session(tmp_path, admission, validators, command, "single-use-run")

    with pytest.raises(ValueError, match="already been consumed"):
        run_observed_session(
            tmp_path,
            admission,
            validators,
            [sys.executable, "-c", "from pathlib import Path; Path('should-not-exist.txt').write_text('bad')"],
            "single-use-run",
        )
    assert not (tmp_path / "should-not-exist.txt").exists()

    mismatch_root = tmp_path / "mismatch"
    mismatch_root.mkdir()
    other_validators = _validators(mismatch_root)
    other_admission = _admission(mismatch_root, "admitted-name")
    with pytest.raises(ValueError, match="exactly match"):
        run_observed_session(mismatch_root, other_admission, other_validators, command, "different-name")


def test_observed_session_detects_validator_manifest_tampering(tmp_path: Path) -> None:
    validators = _validators(tmp_path)
    admission = _admission(tmp_path, "manifest-drift")
    command = [
        sys.executable,
        "-c",
        "from pathlib import Path; Path('product.txt').write_text('ready'); Path('validators.json').write_text('{}')",
    ]

    result = run_observed_session(tmp_path, admission, validators, command, "manifest-drift")

    assert result["session"]["passed"] is False
    assert "hollow_validator" in result["session"]["failure_classes"]


def test_session_chain_uses_recorded_time_not_lexical_run_id(tmp_path: Path) -> None:
    recorder = tmp_path / ".factory" / "session-recorder"
    for run_id, recorded_at, digest in (
        ("z-old", "2026-01-01T00:00:00Z", "a" * 64),
        ("a-new", "2026-01-02T00:00:00Z", "b" * 64),
    ):
        path = recorder / run_id / "session.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"run_id": run_id, "recorded_at": recorded_at, "session_sha256": digest}), encoding="utf-8")

    from factoryline.session_recorder import _previous_session

    assert _previous_session(tmp_path) == "b" * 64
