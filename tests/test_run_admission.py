from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.loop_passport import build_loop_passport, init_loop
from factoryline.run_admission import (
    AdmissionError,
    prepare_admission,
    verify_admission,
)
from test_intake_admission import _intake


def _passport(tmp_path: Path) -> Path:
    manifest = Path(init_loop(tmp_path, "dependency-audit", "platform-team")["path"])
    return Path(build_loop_passport(tmp_path, manifest)["paths"]["json"])


def _request(tmp_path: Path, *, action: str = "read_repository") -> Path:
    path = tmp_path / "request.json"
    path.write_text(
        json.dumps(
            {
                "schema": "factory.run-admission.request.v1",
                "id": "dependency-audit-run-1",
                "valid_until": (
                    datetime.now(timezone.utc) + timedelta(minutes=30)
                ).isoformat(),
                "trigger": {"type": "manual"},
                "actions": [action],
                "paths": ["."],
                "budget": {
                    "max_iterations": 1,
                    "max_wall_seconds": 900,
                    "max_tokens": 0,
                    "max_cost_usd": 0,
                },
                "approvals": [],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_admission_seals_then_revalidates_without_external_authority(tmp_path: Path):
    packet = prepare_admission(tmp_path, _passport(tmp_path), _request(tmp_path))
    verified = verify_admission(tmp_path, Path(packet["path"]))

    assert packet["verdict"] == "SEALED"
    assert packet["markers"] == [
        "ADMISSION_PACKET_SEALED",
        "ADMISSION_EXTERNAL_EFFECTS_DENIED",
    ]
    assert verified["marker"] == "ADMISSION_READY"
    assert all(value is False for value in verified["authority"].values())


def test_admission_rejects_undeclared_action_without_writing_packet(tmp_path: Path):
    with pytest.raises(AdmissionError) as raised:
        prepare_admission(
            tmp_path, _passport(tmp_path), _request(tmp_path, action="publish")
        )

    assert raised.value.code == "ADMISSION_ACTION_UNDECLARED"
    assert not (tmp_path / ".factory" / "admissions").exists()


def test_admission_becomes_stale_when_workspace_changes(tmp_path: Path):
    source = tmp_path / "source.txt"
    source.write_text("before", encoding="utf-8")
    packet = prepare_admission(tmp_path, _passport(tmp_path), _request(tmp_path))
    source.write_text("after", encoding="utf-8")

    verified = verify_admission(tmp_path, Path(packet["path"]))

    assert verified["marker"] == "ADMISSION_STALE"
    assert verified["reason"] == "workspace_or_graph_changed"


def test_admission_rejects_expired_or_overlong_validity_before_writing_packet(
    tmp_path: Path,
):
    request = _request(tmp_path)
    payload = json.loads(request.read_text(encoding="utf-8"))
    payload["valid_until"] = (
        datetime.now(timezone.utc) - timedelta(seconds=1)
    ).isoformat()
    request.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(AdmissionError) as raised:
        prepare_admission(tmp_path, _passport(tmp_path), request)

    assert raised.value.code == "ADMISSION_EXPIRED"
    assert not (tmp_path / ".factory" / "admissions").exists()


def test_admission_blocks_a_tampered_packet_with_the_public_marker(tmp_path: Path):
    packet = prepare_admission(tmp_path, _passport(tmp_path), _request(tmp_path))
    path = Path(packet["path"])
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["request"]["actions"] = ["publish"]
    path.write_text(json.dumps(payload), encoding="utf-8")

    verified = verify_admission(tmp_path, path)

    assert verified["marker"] == "ADMISSION_PACKET_BLOCKED"
    assert verified["reason"] == "packet_sha256_mismatch"


def test_admission_cli_seals_then_reports_a_ready_packet(tmp_path: Path, capsys):
    passport, request = _passport(tmp_path), _request(tmp_path)
    code = main(
        [
            "admission",
            "prepare",
            str(passport),
            str(request),
            "--root",
            str(tmp_path),
            "--json",
        ]
    )
    sealed = json.loads(capsys.readouterr().out)
    verify_code = main(
        ["admission", "verify", sealed["path"], "--root", str(tmp_path), "--json"]
    )
    ready = json.loads(capsys.readouterr().out)

    assert code == 0
    assert sealed["markers"][0] == "ADMISSION_PACKET_SEALED"
    assert verify_code == 0
    assert ready["marker"] == "ADMISSION_READY"


def test_strict_admission_binds_authoritative_intake_parameters(tmp_path: Path):
    source = tmp_path / "source.txt"
    source.write_text("source", encoding="utf-8")
    intake_path, _ = _intake(tmp_path, scope=["source.txt"], mode="human_controlled")
    passport = _passport(tmp_path)
    request = _request(tmp_path)
    payload = json.loads(request.read_text(encoding="utf-8"))
    payload["paths"] = ["source.txt"]
    payload["budget"] = {
        "max_iterations": 1,
        "max_wall_seconds": 100,
        "max_tokens": 0,
        "max_cost_usd": 0,
    }
    intake = json.loads(intake_path.read_text(encoding="utf-8"))
    payload["intake_parameters"] = {
        "path": intake_path.relative_to(tmp_path).as_posix(),
        "parameter_sha256": intake["parameter_sha256"],
    }
    request.write_text(json.dumps(payload), encoding="utf-8")

    packet = prepare_admission(tmp_path, passport, request, require_intake=True)
    verified = verify_admission(tmp_path, Path(packet["path"]))
    assert packet["intake_parameters"]["parameter_sha256"] == intake["parameter_sha256"]
    assert verified["marker"] == "ADMISSION_READY"


def test_strict_admission_rejects_missing_intake_binding(tmp_path: Path):
    with pytest.raises(AdmissionError) as raised:
        prepare_admission(
            tmp_path, _passport(tmp_path), _request(tmp_path), require_intake=True
        )
    assert raised.value.code == "E_INTAKE_BINDING_REQUIRED"


def test_checkpoint_fix_is_bound_to_scope_patch_and_human_approval(tmp_path: Path):
    source = tmp_path / "source.txt"
    source.write_text("source", encoding="utf-8")
    patch = tmp_path / "checkpoint.patch"
    patch.write_text("diff --git a/source.txt b/source.txt\n", encoding="utf-8")
    intake_path, _ = _intake(tmp_path, scope=["source.txt"], mode="human_controlled")
    passport = _passport(tmp_path)
    request = _request(tmp_path)
    payload = json.loads(request.read_text(encoding="utf-8"))
    payload["actions"] = ["read_repository", "write_workspace"]
    payload["paths"] = ["source.txt"]
    payload["budget"] = {
        "max_iterations": 1,
        "max_wall_seconds": 100,
        "max_tokens": 0,
        "max_cost_usd": 0,
    }
    intake = json.loads(intake_path.read_text(encoding="utf-8"))
    payload["intake_parameters"] = {
        "path": intake_path.relative_to(tmp_path).as_posix(),
        "parameter_sha256": intake["parameter_sha256"],
    }
    payload["checkpoint_fix"] = {
        "checkpoint_id": "verify-1",
        "patch_path": "checkpoint.patch",
        "patch_sha256": __import__("hashlib").sha256(patch.read_bytes()).hexdigest(),
        "paths": ["source.txt"],
        "reason": "Repair the verified checkpoint defect before retrying the lane.",
        "approved_by": "Rick Katz",
        "approval_expires_at": payload["valid_until"],
    }
    request.write_text(json.dumps(payload), encoding="utf-8")

    packet = prepare_admission(tmp_path, passport, request, require_intake=True)
    verified = verify_admission(tmp_path, Path(packet["path"]))

    assert packet["request"]["checkpoint_fix"]["checkpoint_id"] == "verify-1"
    assert verified["checkpoint_fix"]["state"] == "BOUND_FOR_EXTERNAL_HARNESS"
