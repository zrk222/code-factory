from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import factoryline.release_candidate as candidate
from test_intake_admission import _intake


def test_candidate_tag_must_match_package_version(tmp_path, monkeypatch):
    monkeypatch.setattr(
        candidate, "source_snapshot", lambda root: {"version": "0.46.9"}
    )
    with pytest.raises(ValueError, match="source package version"):
        candidate.release_candidate_preflight(
            tmp_path, Path("contract.json"), candidate_tag="v0.46.8"
        )


def test_editor_candidate_tag_must_match_editor_version(tmp_path, monkeypatch):
    monkeypatch.setattr(
        candidate,
        "source_snapshot",
        lambda root: {
            "version": "0.47.0",
            "platform_versions": {"vscode": "1.1.0", "intellij": "1.1.0"},
        },
    )
    with pytest.raises(ValueError, match="channel source version"):
        candidate.release_candidate_preflight(
            tmp_path,
            Path("contract.json"),
            candidate_tag="vscode-v1.0.1",
            channel="vscode",
        )


@pytest.fixture(autouse=True)
def _eligible_release_cadence(monkeypatch) -> None:
    monkeypatch.setattr(
        candidate,
        "release_cadence_status",
        lambda _root: {
            "available": True,
            "admission": True,
            "state": "eligible",
            "release_train_status": "valid",
            "reason": "fixture cadence admitted",
        },
    )
    monkeypatch.setattr(
        candidate,
        "evaluate_architecture_health",
        lambda _root, *, strict=False: {
            "decision": "HEALTHY",
            "regressions": [],
            "baseline_debt": [],
        },
    )


def _source(root: Path, *, version: str = "0.46.3") -> None:
    (root / "factoryline").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        f'[project]\nversion = "{version}"\n', encoding="utf-8"
    )
    (root / "factoryline" / "__init__.py").write_text(
        f'__version__ = "{version}"\n', encoding="utf-8"
    )


def _contract(root: Path, *, version: str = "0.46.3", commit: str = "a" * 40) -> Path:
    path = root / "contract.json"
    path.write_text(
        json.dumps(
            {
                "schema": "factory.release-contract.v1",
                "feature": "release",
                "candidate": {"source_version": version, "source_commit": commit},
            }
        ),
        encoding="utf-8",
    )
    return path


def test_stale_python_artifact_is_rejected(monkeypatch, tmp_path: Path) -> None:
    _source(tmp_path)
    monkeypatch.setattr(candidate, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        candidate,
        "verify_release_contract",
        lambda *args: {"ok": True, "marker": "RELEASE_CONTRACT_VALID"},
    )
    artifact_dir = tmp_path / "candidate"
    artifact_dir.mkdir()
    (artifact_dir / "factoryline_code_factory-0.46.2-py3-none-any.whl").write_bytes(
        b"old"
    )

    result = candidate.release_candidate_preflight(
        tmp_path, _contract(tmp_path), [artifact_dir]
    )

    assert result["ok"] is False
    assert any(
        item["code"] == "E_RELEASE_ARTIFACT_VERSION_MISMATCH"
        for item in result["blockers"]
    )
    assert result["marker"] == "RELEASE_CANDIDATE_PREFLIGHT_BLOCKED"


def test_matching_artifact_and_source_binding_pass(monkeypatch, tmp_path: Path) -> None:
    _source(tmp_path)
    monkeypatch.setattr(candidate, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        candidate,
        "verify_release_contract",
        lambda *args: {"ok": True, "marker": "RELEASE_CONTRACT_VALID"},
    )
    artifact_dir = tmp_path / "candidate"
    artifact_dir.mkdir()
    (artifact_dir / "factoryline_code_factory-0.46.3-py3-none-any.whl").write_bytes(
        b"new"
    )

    result = candidate.release_candidate_preflight(
        tmp_path, _contract(tmp_path), [artifact_dir]
    )

    assert result["ok"] is True
    assert result["marker"] == "RELEASE_CANDIDATE_PREFLIGHT_PASS"
    assert result["facts"]["artifact_versions_match"] is True
    assert result["artifacts"]["artifacts"][0]["platform"] == "python"


def test_missing_artifact_inventory_fails_closed(monkeypatch, tmp_path: Path) -> None:
    _source(tmp_path)
    monkeypatch.setattr(candidate, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        candidate,
        "verify_release_contract",
        lambda *args: {"ok": True, "marker": "RELEASE_CONTRACT_VALID"},
    )

    result = candidate.release_candidate_preflight(
        tmp_path, _contract(tmp_path), [tmp_path / "empty"]
    )

    assert result["ok"] is False
    assert any(
        item["code"] == "E_RELEASE_ARTIFACT_MISSING" for item in result["blockers"]
    )


def test_source_commit_mismatch_blocks_before_candidate_pass(
    monkeypatch, tmp_path: Path
) -> None:
    _source(tmp_path)
    monkeypatch.setattr(candidate, "_git_head", lambda _root: "b" * 40)
    monkeypatch.setattr(
        candidate,
        "verify_release_contract",
        lambda *args: {"ok": True, "marker": "RELEASE_CONTRACT_VALID"},
    )
    artifact_dir = tmp_path / "candidate"
    artifact_dir.mkdir()
    (artifact_dir / "factoryline_code_factory-0.46.3-py3-none-any.whl").write_bytes(
        b"new"
    )

    result = candidate.release_candidate_preflight(
        tmp_path, _contract(tmp_path), [artifact_dir]
    )

    assert result["ok"] is False
    assert any(
        item["code"] == "RELEASE_CONTRACT_SOURCE_MISMATCH"
        for item in result["blockers"]
    )


def test_release_cadence_hold_blocks_candidate_preflight(
    monkeypatch, tmp_path: Path
) -> None:
    _source(tmp_path)
    monkeypatch.setattr(candidate, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        candidate,
        "verify_release_contract",
        lambda *args: {"ok": True, "marker": "RELEASE_CONTRACT_VALID"},
    )
    monkeypatch.setattr(
        candidate,
        "release_cadence_status",
        lambda _root: {
            "available": True,
            "admission": False,
            "state": "rate_limited",
            "release_train_status": "valid",
            "next_eligible_at": "2026-10-10T02:49:36Z",
            "reason": "4 tags are inside the rolling budget.",
        },
    )
    artifact_dir = tmp_path / "candidate"
    artifact_dir.mkdir()
    (artifact_dir / "factoryline_code_factory-0.46.3-py3-none-any.whl").write_bytes(
        b"new"
    )

    result = candidate.release_candidate_preflight(
        tmp_path, _contract(tmp_path), [artifact_dir]
    )

    assert result["ok"] is False
    assert result["facts"]["release_cadence_admissible"] is False
    assert any(
        item["code"] == "E_RELEASE_CADENCE_BLOCKED" for item in result["blockers"]
    )
    assert any(
        item["id"] == "RELEASE_CADENCE_ADMISSION" and not item["passed"]
        for item in result["checks"]
    )


def test_openvsx_cadence_exception_is_bound_to_v111_run_attempt(
    tmp_path: Path, monkeypatch
) -> None:
    issued = datetime.now(timezone.utc)
    path = tmp_path / "exception.json"
    path.write_text(
        json.dumps(
            {
                "schema": "factory.release-cadence-exception.v1",
                "channel": "vscode",
                "version": "1.1.1",
                "candidate_tag": "vscode-v1.1.1",
                "source_commit": "a" * 40,
                "requesting_actor": "zrk222",
                "reason": "Approved one-time Open VSX release exception.",
                "issued_at": issued.isoformat(),
                "expires_at": (issued + timedelta(minutes=30)).isoformat(),
                "workflow_run_id": "12345",
                "workflow_run_attempt": "2",
                "environment": "openvsx",
                "environment_authorized": True,
                "publish_enabled": True,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "12345")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    source = {
        "commit": "a" * 40,
        "platform_versions": {"vscode": "1.1.1"},
    }
    contract = {"approved_by": "zrk222"}

    result = candidate._cadence_exception_payload(
        tmp_path, path, source, "vscode", "vscode-v1.1.1", contract
    )

    assert result["workflow_run_attempt"] == "2"
    assert result["candidate_tag"] == "vscode-v1.1.1"


def test_openvsx_cadence_exception_rejects_other_candidate_or_run(
    tmp_path: Path, monkeypatch
) -> None:
    issued = datetime.now(timezone.utc)
    path = tmp_path / "exception.json"
    value = {
        "schema": "factory.release-cadence-exception.v1",
        "channel": "vscode",
        "version": "1.1.1",
        "candidate_tag": "vscode-v1.1.1",
        "source_commit": "a" * 40,
        "requesting_actor": "zrk222",
        "reason": "Approved one-time Open VSX release exception.",
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(minutes=30)).isoformat(),
        "workflow_run_id": "12345",
        "workflow_run_attempt": "2",
        "environment": "openvsx",
        "environment_authorized": True,
        "publish_enabled": True,
    }
    path.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "12345")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")

    with pytest.raises(
        ValueError, match="not bound to this GitHub Actions run attempt"
    ):
        candidate._cadence_exception_payload(
            tmp_path,
            path,
            {"commit": "a" * 40, "platform_versions": {"vscode": "1.1.1"}},
            "vscode",
            "vscode-v1.1.1",
            {"approved_by": "zrk222"},
        )

    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    with pytest.raises(ValueError, match="restricted to vscode-v1.1.1"):
        candidate._cadence_exception_payload(
            tmp_path,
            path,
            {"commit": "a" * 40, "platform_versions": {"vscode": "1.1.2"}},
            "vscode",
            "vscode-v1.1.2",
            {"approved_by": "zrk222"},
        )


def test_pypi_cadence_exception_is_bound_to_core_v0480_run_attempt(
    tmp_path: Path, monkeypatch
) -> None:
    issued = datetime.now(timezone.utc)
    path = tmp_path / "exception.json"
    path.write_text(
        json.dumps(
            {
                "schema": "factory.release-cadence-exception.v1",
                "channel": "core",
                "version": "0.48.0",
                "candidate_tag": "v0.48.0",
                "source_commit": "b" * 40,
                "requesting_actor": "zrk222",
                "reason": "Approved one-time PyPI release exception.",
                "issued_at": issued.isoformat(),
                "expires_at": (issued + timedelta(minutes=30)).isoformat(),
                "workflow_run_id": "12345",
                "workflow_run_attempt": "2",
                "environment": "pypi",
                "environment_authorized": True,
                "publish_enabled": True,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "12345")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    source = {"version": "0.48.0", "commit": "b" * 40}
    contract = {"approved_by": "zrk222"}

    result = candidate._cadence_exception_payload(
        tmp_path, path, source, "core", "v0.48.0", contract
    )

    assert result["channel"] == "core"
    assert result["version"] == "0.48.0"
    assert result["candidate_tag"] == "v0.48.0"
    assert result["workflow_run_id"] == "12345"
    assert result["workflow_run_attempt"] == "2"


def test_pypi_cadence_exception_rejects_other_core_version_tag_or_environment(
    tmp_path: Path, monkeypatch
) -> None:
    issued = datetime.now(timezone.utc)
    path = tmp_path / "exception.json"
    value = {
        "schema": "factory.release-cadence-exception.v1",
        "channel": "core",
        "version": "0.48.0",
        "candidate_tag": "v0.48.0",
        "source_commit": "b" * 40,
        "requesting_actor": "zrk222",
        "reason": "Approved one-time PyPI release exception.",
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(minutes=30)).isoformat(),
        "workflow_run_id": "12345",
        "workflow_run_attempt": "2",
        "environment": "pypi",
        "environment_authorized": True,
        "publish_enabled": True,
    }
    path.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "12345")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")

    with pytest.raises(ValueError, match="restricted to.*core v0.48.0"):
        candidate._cadence_exception_payload(
            tmp_path,
            path,
            {"version": "0.48.1", "commit": "b" * 40},
            "core",
            "v0.48.1",
            {"approved_by": "zrk222"},
        )

    with pytest.raises(
        ValueError, match="requires successful protected pypi authorization"
    ):
        value["environment"] = "openvsx"
        path.write_text(json.dumps(value), encoding="utf-8")
        candidate._cadence_exception_payload(
            tmp_path,
            path,
            {"version": "0.48.0", "commit": "b" * 40},
            "core",
            "v0.48.0",
            {"approved_by": "zrk222"},
        )


def test_architecture_health_debt_blocks_candidate_preflight(
    monkeypatch, tmp_path: Path
) -> None:
    _source(tmp_path)
    monkeypatch.setattr(candidate, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        candidate,
        "verify_release_contract",
        lambda *args: {"ok": True, "marker": "RELEASE_CONTRACT_VALID"},
    )
    monkeypatch.setattr(
        candidate,
        "evaluate_architecture_health",
        lambda _root, *, strict=False: {
            "decision": "BLOCKED",
            "regressions": [{"code": "E_ARCH_CLI_LINES_GROWTH"}],
            "baseline_debt": [],
        },
    )
    artifact_dir = tmp_path / "candidate"
    artifact_dir.mkdir()
    (artifact_dir / "factoryline_code_factory-0.46.3-py3-none-any.whl").write_bytes(
        b"new"
    )

    result = candidate.release_candidate_preflight(
        tmp_path, _contract(tmp_path), [artifact_dir]
    )

    assert result["ok"] is False
    assert result["facts"]["architecture_health_admissible"] is False
    assert any(
        item["code"] == "E_RELEASE_ARCHITECTURE_HEALTH_BLOCKED"
        for item in result["blockers"]
    )


def test_missing_architecture_policy_fails_candidate_preflight(
    monkeypatch, tmp_path: Path
) -> None:
    _source(tmp_path)
    monkeypatch.setattr(candidate, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        candidate,
        "verify_release_contract",
        lambda *args: {"ok": True, "marker": "RELEASE_CONTRACT_VALID"},
    )

    def _missing_policy(_root: Path, *, strict: bool = False) -> dict[str, object]:
        raise candidate.ArchitectureHealthError("architecture policy is missing")

    monkeypatch.setattr(candidate, "evaluate_architecture_health", _missing_policy)
    artifact_dir = tmp_path / "candidate"
    artifact_dir.mkdir()
    (artifact_dir / "factoryline_code_factory-0.46.3-py3-none-any.whl").write_bytes(
        b"new"
    )

    result = candidate.release_candidate_preflight(
        tmp_path, _contract(tmp_path), [artifact_dir]
    )

    assert result["ok"] is False
    assert result["architecture_health"]["regressions"][0]["code"] == (
        "E_ARCH_POLICY_UNAVAILABLE"
    )


def test_requested_active_metadata_is_part_of_candidate_decision(
    monkeypatch, tmp_path: Path
) -> None:
    _source(tmp_path)
    monkeypatch.setattr(candidate, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        candidate,
        "verify_release_contract",
        lambda *args: {"ok": True, "marker": "RELEASE_CONTRACT_VALID"},
    )
    artifact_dir = tmp_path / "candidate"
    artifact_dir.mkdir()
    (artifact_dir / "factoryline_code_factory-0.46.3-py3-none-any.whl").write_bytes(
        b"new"
    )
    progress = tmp_path / "Progress.md"
    progress.write_text(
        "[2026-09-06 10:00] event\n[2026-09-06 09:00] event\n", encoding="utf-8"
    )

    result = candidate.release_candidate_preflight(
        tmp_path, _contract(tmp_path), [artifact_dir], [progress]
    )

    assert result["ok"] is False
    assert result["facts"]["ledger_drift"] is True
    assert any(item["code"] == "E_METADATA_LEDGER_ORDER" for item in result["blockers"])


def test_release_preflight_can_require_authoritative_intake(
    monkeypatch, tmp_path: Path
) -> None:
    _source(tmp_path)
    monkeypatch.setattr(candidate, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        candidate,
        "verify_release_contract",
        lambda *args: {"ok": True, "marker": "RELEASE_CONTRACT_VALID"},
    )
    artifact_dir = tmp_path / "candidate"
    artifact_dir.mkdir()
    (artifact_dir / "factoryline_code_factory-0.46.3-py3-none-any.whl").write_bytes(
        b"new"
    )
    intake_path, _ = _intake(tmp_path)

    result = candidate.release_candidate_preflight(
        tmp_path,
        _contract(tmp_path),
        [artifact_dir],
        intake_parameters=intake_path,
        require_intake=True,
    )

    assert result["ok"] is True
    assert result["facts"]["intake_binding_verified"] is True
    assert result["intake_parameters"]["marker"] == "INTAKE_BINDING_VERIFIED"


def test_release_preflight_strict_mode_blocks_without_intake(
    monkeypatch, tmp_path: Path
) -> None:
    _source(tmp_path)
    monkeypatch.setattr(candidate, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        candidate,
        "verify_release_contract",
        lambda *args: {"ok": True, "marker": "RELEASE_CONTRACT_VALID"},
    )
    artifact_dir = tmp_path / "candidate"
    artifact_dir.mkdir()
    (artifact_dir / "factoryline_code_factory-0.46.3-py3-none-any.whl").write_bytes(
        b"new"
    )

    result = candidate.release_candidate_preflight(
        tmp_path, _contract(tmp_path), [artifact_dir], require_intake=True
    )

    assert result["ok"] is False
    assert any(
        item["code"] == "E_INTAKE_BINDING_REQUIRED" for item in result["blockers"]
    )
