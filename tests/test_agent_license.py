from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from factoryline.agent_license import (
    AgentLicenseError,
    derive_license,
    issue_license,
    record_governed_run,
    verify_license,
)
from factoryline.loop_passport import build_loop_passport, init_loop, load_manifest
from factoryline.run_admission import AdmissionError, prepare_admission


AGENT = {"schema": "factory.agent-identity.v1", "subject": "agent-alpha", "provider": "deepseek", "model": "reasoner"}


def _passport(root: Path, autonomy: str = "human_controlled") -> Path:
    manifest = Path(init_loop(root, "agent-license-loop", "platform-team")["path"])
    if autonomy != "human_controlled":
        payload = load_manifest(manifest)
        payload["autonomy"] = autonomy
        if autonomy == "supervised":
            payload["validators"] = {"pre": ["pre"], "post": ["post"], "invariant": []}
        if autonomy == "autonomous":
            payload["workspace"]["mode"] = "ephemeral"
            payload["validators"] = {"pre": ["pre"], "post": ["post"], "invariant": ["invariant"]}
        manifest.write_text(json.dumps(payload), encoding="utf-8")
    return Path(build_loop_passport(root, manifest)["paths"]["json"])


def _request(root: Path, identity: dict[str, str], identifier: str) -> Path:
    path = root / ".factory" / "requests" / f"{identifier}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "schema": "factory.run-admission.request.v1",
        "id": identifier,
        "valid_until": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
        "trigger": {"type": "manual"},
        "actions": ["read_repository"],
        "paths": ["."],
        "budget": {"max_iterations": 1, "max_wall_seconds": 900, "max_tokens": 0, "max_cost_usd": 0},
        "approvals": [],
        "agent": identity,
    }), encoding="utf-8")
    return path


def _record(root: Path, passport: Path, identity: dict[str, str], identifier: str, *, passed: bool = True, failures: list[str] | None = None, task_id: str | None = None) -> dict:
    request = _request(root, identity, identifier)
    admission = prepare_admission(root, passport, request)
    receipt_dir = root / ".factory" / "license-fixtures"
    receipt_dir.mkdir(parents=True, exist_ok=True)
    result = receipt_dir / f"{identifier}-result.json"
    verifier = receipt_dir / f"{identifier}-verifier.json"
    result.write_text(json.dumps({"marker": "WORKER_RESULT", "id": identifier}), encoding="utf-8")
    verifier.write_text(json.dumps({"marker": "INDEPENDENT_VERIFICATION", "id": identifier}), encoding="utf-8")
    event = receipt_dir / f"{identifier}-event.json"
    event.write_text(json.dumps({
        "schema": "factory.agent-run.v1", "id": identifier, "agent": identity, "task_id": task_id,
        "admission": admission["path"], "result_receipt": str(result.relative_to(root)),
        "verification": {"subject": "reviewer-beta", "receipt": str(verifier.relative_to(root))},
        "passed": passed, "failure_classes": failures or [],
    }), encoding="utf-8")
    return record_governed_run(root, event)


def test_clean_current_governed_runs_earn_scoped_autonomy_and_hash_verify(tmp_path: Path):
    passport = _passport(tmp_path)
    for index in range(20):
        _record(tmp_path, passport, AGENT, f"run-{index:02d}")

    derived = derive_license(tmp_path, AGENT)
    issued = issue_license(tmp_path, AGENT)

    assert derived["tier"] == "autonomous"
    assert derived["allowed_paths"] == ["."]
    assert derived["evidence"]["current_governed_event_count"] == 20
    assert verify_license(Path(issued["path"]))["ok"] is True
    assert derived["identity_provenance"] == "declared_in_admission_packet"


def test_severe_failure_writes_incident_and_demotes_immediately(tmp_path: Path):
    passport = _passport(tmp_path)
    for index in range(20):
        _record(tmp_path, passport, AGENT, f"run-{index:02d}")
    severe = _record(tmp_path, passport, AGENT, "run-99", passed=False, failures=["hollow_test"])

    derived = derive_license(tmp_path, AGENT)

    assert severe["incident_path"]
    assert Path(severe["incident_path"]).is_file()
    assert derived["tier"] == "human_controlled"
    assert derived["reason"] == "SEVERE_FAILURE_DEMOTION"


def test_record_requires_independent_verifier_without_writing_event(tmp_path: Path):
    passport = _passport(tmp_path)
    request = _request(tmp_path, AGENT, "run-one")
    admission = prepare_admission(tmp_path, passport, request)
    fixture = tmp_path / ".factory" / "fixture.json"
    fixture.write_text("{}", encoding="utf-8")
    event = tmp_path / ".factory" / "event.json"
    event.write_text(json.dumps({
        "schema": "factory.agent-run.v1", "id": "run-one", "agent": AGENT, "task_id": None,
        "admission": admission["path"], "result_receipt": ".factory/fixture.json",
        "verification": {"subject": "agent-alpha", "receipt": ".factory/fixture.json"},
        "passed": True, "failure_classes": [],
    }), encoding="utf-8")

    with pytest.raises(AgentLicenseError) as raised:
        record_governed_run(tmp_path, event)

    assert raised.value.code == "E_LICENSE_VERIFIER_NOT_INDEPENDENT"
    assert not list((tmp_path / ".factory" / "agent-licenses" / "events").glob("*.json")) if (tmp_path / ".factory" / "agent-licenses" / "events").exists() else True


def test_admission_caps_declared_agent_autonomy_by_license(tmp_path: Path):
    passport = _passport(tmp_path, "autonomous")
    with pytest.raises(AdmissionError) as raised:
        prepare_admission(tmp_path, passport, _request(tmp_path, AGENT, "autonomy-request"))

    assert raised.value.code == "E_LICENSE_EXCEEDED"
