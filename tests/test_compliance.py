from __future__ import annotations
import pytest
from factoryline.compliance import ComplianceError, build_oscal_assessment
from factoryline.privacy import (
    PrivacyError,
    bbs_status,
    issue_bbs_credential,
    merkle_disclosure,
    verify_merkle_disclosure,
    zkvm_pilot_status,
)
import json
import subprocess
from pathlib import Path
from factoryline.migration import (
    READINESS_CATEGORIES,
    MigrationError,
    assess_migration_readiness,
    build_repository_context,
    verify_migration_readiness,
    verify_repository_context,
)
from factoryline.agent_license import AUTONOMY_RANK
from factoryline.agent_proof_bridge import (
    _AUTONOMY,
    _CAPABILITIES,
    _ISOLATION,
    _NODE_KINDS,
    _PROVIDERS,
    _STATUS,
)
from factoryline.atomic_proof_adapter import _AUTONOMY as ATOMIC_AUTONOMY
from factoryline.atomic_proof_adapter import _CAPABILITIES as ATOMIC_CAPABILITIES
from factoryline.atomic_proof_adapter import _ISOLATION as ATOMIC_ISOLATION
from factoryline.atomic_proof_adapter import _STAGE_KINDS, _STAGE_STATUS
from factoryline.lifecycle_ledger import _EVENTS, _TRACE_STAGES
from factoryline.operations_control import _TIERS, _WORK_KINDS
from factoryline.oracle_firewall import AUTHORITY_ORIGINS, EFFECTS, ORIGINS
from factoryline.protocol_enums import (
    AgentCapability,
    AgentProvider,
    AgentRunStatus,
    AuthorityOrigin,
    AutonomyLevel,
    IsolationBoundary,
    LifecycleEvent,
    OperationsEvidenceTier,
    OperationsWorkKind,
    RepairConsequence,
    RepairSeverity,
    RuleEffect,
    SessionTraceStage,
    WorkflowNodeKind,
)
from factoryline.repair_loop import _CONSEQUENCES, _SEVERITIES
from factoryline.workspace_advisor import (
    WORKSPACE_ADVISOR_MARKER,
    WORKSPACE_ADVISOR_SCHEMA,
    WorkspaceAdvisorError,
    _path_classification,
    inspect_workspace,
    write_workspace_advisor_artifacts,
)
from factoryline.cli import main


@pytest.mark.parametrize("pack", ["nist-ssdf", "owasp-asvs", "soc2", "iso27001"])
def test_builtin_control_packs_emit_non_certifying_oscal_evidence(pack):
    result = build_oscal_assessment(pack, tenant_id="acme", evidence=[])
    assert result["schema"] == "factory.compliance.v1"
    assert (
        result["assessment-results"]["metadata"]["props"][-1]["value"]
        == "not-a-certification"
    )
    assert result["assessment_sha256"]


def test_customer_pack_accepts_reviewed_controls_and_maps_evidence():
    result = build_oscal_assessment(
        "customer",
        tenant_id="acme",
        custom_controls=[
            {"id": "ACME-1", "title": "Release approval", "evidence": ["approval"]}
        ],
        evidence=[{"control_ids": ["ACME-1"]}],
    )
    observation = result["assessment-results"]["results"][0]["observations"][0]
    assert observation["props"][0]["value"] == "satisfied"


def test_unknown_pack_is_rejected():
    with pytest.raises(ComplianceError) as error:
        build_oscal_assessment("unknown", tenant_id="acme", evidence=[])
    assert error.value.code == "E_CONTROL_PACK"


def test_merkle_disclosure_proves_one_leaf_without_disclosing_siblings():
    disclosure = merkle_disclosure(["a" * 64, "b" * 64, "c" * 64], "b" * 64)
    assert verify_merkle_disclosure(disclosure) is True
    assert "c" * 64 not in str(disclosure)
    disclosure["leaf"] = "d" * 64
    assert verify_merkle_disclosure(disclosure) is False


def test_merkle_rejects_unknown_leaf():
    with pytest.raises(PrivacyError) as error:
        merkle_disclosure(["a" * 64], "b" * 64)
    assert error.value.code == "E_LEAF_NOT_FOUND"


def test_optional_cryptographic_backends_fail_closed():
    assert bbs_status()["available"] is False
    assert zkvm_pilot_status()["available"] is False
    with pytest.raises(PrivacyError) as error:
        issue_bbs_credential()
    assert error.value.code == "E_BBS_UNAVAILABLE"


def _manifest(root: Path, *, complete: bool = True) -> Path:
    evidence = root / "proof.json"
    evidence.write_text('{"passed": true}\n', encoding="utf-8")
    categories = READINESS_CATEGORIES if complete else READINESS_CATEGORIES[:-1]
    payload = {
        "schema": "factory.migration.readiness-input.v1",
        "project": "legacy-modernization",
        "checks": [
            {
                "id": f"check-{category}",
                "category": category,
                "command": ["tool", "verify", category],
                "passed": True,
                "evidence": [str(evidence)],
                **(
                    {"reproducibility_runs": {"passed": 2, "total": 2}}
                    if category == "environment"
                    else {}
                ),
            }
            for category in categories
        ],
    }
    path = root / "readiness-input.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_migration_readiness_separates_registration_from_executable_proof(
    tmp_path: Path,
):
    partial = assess_migration_readiness(_manifest(tmp_path, complete=False), tmp_path)
    assert partial["ready"] is False
    assert partial["lane_registration_pct"] < 100
    assert partial["executable_proof_pct"] < 100
    full = assess_migration_readiness(_manifest(tmp_path), tmp_path, force=True)
    assert full["ready"] is True
    assert full["lane_registration_pct"] == 100
    assert full["executable_proof_pct"] == 100
    assert verify_migration_readiness(Path(full["path"]))["ready"] is True
    (tmp_path / "proof.json").write_text('{"passed": false}\n', encoding="utf-8")
    assert verify_migration_readiness(Path(full["path"]))["valid"] is False


def test_autowiki_and_lore_are_bound_to_tracked_facts(tmp_path: Path):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "tests@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "Tests"], check=True
    )
    (tmp_path / "adr").mkdir()
    (tmp_path / "adr" / "0001-choice.md").write_text(
        "# Keep migrations reversible\n", encoding="utf-8"
    )
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-m", "record reversible migration"],
        check=True,
        capture_output=True,
    )
    receipt = build_repository_context(tmp_path)
    assert receipt["tracked_files"] == 2
    assert verify_repository_context(Path(receipt["path"]))["valid"] is True
    lore = tmp_path / ".factory" / "context" / "LORE.md"
    assert "Keep migrations reversible" in lore.read_text(encoding="utf-8")
    lore.write_text("tampered\n", encoding="utf-8")
    assert verify_repository_context(Path(receipt["path"]))["valid"] is False


def test_readiness_rejects_invalid_argv_and_implicit_replacement(tmp_path: Path):
    manifest = _manifest(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["checks"][0]["command"] = "tool verify"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(MigrationError, match="argv command") as invalid:
        assess_migration_readiness(manifest, tmp_path)
    assert invalid.value.code == "MIGRATION_READINESS_INPUT"

    manifest = _manifest(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    environment = next(
        check for check in payload["checks"] if check["category"] == "environment"
    )
    environment["reproducibility_runs"] = {"passed": 1, "total": 1}
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    insufficient = assess_migration_readiness(manifest, tmp_path)
    assert insufficient["ready"] is False
    assert "environment" in insufficient["unverified_categories"]

    manifest = _manifest(tmp_path)
    assess_migration_readiness(manifest, tmp_path, force=True)
    with pytest.raises(MigrationError) as replay:
        assess_migration_readiness(manifest, tmp_path)
    assert replay.value.code == "MIGRATION_ARTIFACT_EXISTS"


def test_migration_verifiers_fail_closed_on_malformed_records(tmp_path: Path):
    readiness = assess_migration_readiness(_manifest(tmp_path), tmp_path)
    readiness_path = Path(readiness["path"])
    payload = json.loads(readiness_path.read_text(encoding="utf-8"))
    payload["evidence"] = [
        None,
        {"path": "", "sha256": "bad"},
        {"path": str(tmp_path / "proof.json"), "sha256": "bad"},
    ]
    readiness_path.write_text(json.dumps(payload), encoding="utf-8")
    result = verify_migration_readiness(readiness_path)
    assert result["valid"] is False
    assert any("must be an object" in error for error in result["errors"])
    assert any("path is invalid" in error for error in result["errors"])
    assert any("sha256 is invalid" in error for error in result["errors"])

    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", str(repository)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "tests@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "Tests"], check=True
    )
    (repository / "app.py").write_text("print('ok')\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-m", "initial"],
        check=True,
        capture_output=True,
    )
    context = build_repository_context(repository)
    context_path = Path(context["path"])
    context_payload = json.loads(context_path.read_text(encoding="utf-8"))
    context_payload["artifacts"] = "not-a-list"
    context_path.write_text(json.dumps(context_payload), encoding="utf-8")
    context_result = verify_repository_context(context_path)
    assert context_result["valid"] is False
    assert "context artifact records must be a list" in context_result["errors"]


def test_readiness_evidence_cannot_escape_the_repository(tmp_path: Path):
    manifest = _manifest(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    outside = tmp_path.parent / "outside-proof.json"
    outside.write_text("{}\n", encoding="utf-8")
    payload["checks"][0]["evidence"] = [str(outside)]
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(MigrationError) as rejected:
        assess_migration_readiness(manifest, tmp_path)
    assert rejected.value.code == "MIGRATION_EVIDENCE_OUTSIDE_ROOT"


"""Compatibility checks for shared Factoryline protocol enumerations."""


def test_shared_protocol_enums_preserve_existing_wire_values() -> None:
    """Keep persisted manifest strings stable while centralizing validators."""
    assert ORIGINS == AuthorityOrigin.values()
    assert EFFECTS == RuleEffect.values()
    assert AUTHORITY_ORIGINS == {"human_confirmed", "trusted_source"}
    assert AUTONOMY_RANK == {"human_controlled": 0, "supervised": 1, "autonomous": 2}
    assert _PROVIDERS == AgentProvider.values()
    assert _STATUS == AgentRunStatus.values() == _STAGE_STATUS
    assert _AUTONOMY == AutonomyLevel.values() == ATOMIC_AUTONOMY
    assert _ISOLATION == IsolationBoundary.values() == ATOMIC_ISOLATION
    assert _NODE_KINDS == WorkflowNodeKind.values() == _STAGE_KINDS
    assert _CAPABILITIES == AgentCapability.values() == ATOMIC_CAPABILITIES
    assert tuple(item.value for item in LifecycleEvent) == _EVENTS
    assert tuple(item.value for item in SessionTraceStage) == _TRACE_STAGES
    assert _TIERS == OperationsEvidenceTier.values()
    assert _WORK_KINDS == OperationsWorkKind.values()
    assert _SEVERITIES == RepairSeverity.values()
    assert _CONSEQUENCES == RepairConsequence.values()


def test_protocol_enum_members_are_json_strings() -> None:
    """Require string-compatible members for backwards-compatible JSON artifacts."""
    assert isinstance(AgentProvider.CODERABBIT, str)
    assert AgentProvider.CODERABBIT == "coderabbit"
    assert AutonomyLevel.SUPERVISED == "supervised"
    assert RepairConsequence.DATA_INTEGRITY == "data_integrity"


def _files(root: Path) -> dict[str, bytes]:
    return {
        item.relative_to(root).as_posix(): item.read_bytes()
        for item in root.rglob("*")
        if item.is_file()
    }


def test_workspace_advisor_is_bounded_read_only_and_reports_reviewable_facts(
    tmp_path: Path,
):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "bundle.js").write_bytes(b"x" * 12)
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "module.js").write_bytes(b"y" * 7)
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "ignored").write_bytes(b"z" * 99)
    before = _files(tmp_path)

    report = inspect_workspace(tmp_path, platform_name="Windows", environ={})

    assert report["schema"] == WORKSPACE_ADVISOR_SCHEMA
    assert report["marker"] == WORKSPACE_ADVISOR_MARKER
    assert {
        "WORKSPACE_ADVISOR_SCHEMA_BOUND",
        "WORKSPACE_ADVISOR_NO_WRITE_DEFAULT",
        "WORKSPACE_ADVISOR_ZERO_AUTHORITY",
    } <= set(report["markers"])
    assert report["scan"]["files_scanned"] == 3
    assert report["scan"]["bytes_scanned"] == 21
    assert report["scan"]["git_directory_skipped"] is True
    assert report["workspace"]["path_classification"] == "windows_local"
    assert report["workspace"]["ecosystems"] == ["node"]
    assert {item["path"] for item in report["managed_directory_summary"]} == {
        "build",
        "node_modules",
    }
    assert {item["id"] for item in report["recommendations"]} >= {
        "review_generated_directories",
        "review_dependency_directory_visibility",
    }
    assert set(report["authority"]) == {
        "execution",
        "ide_settings",
        "cache_mutation",
        "indexing_mutation",
        "remote_connection",
        "credential",
        "publication",
        "deployment",
    }
    assert all(value is False for value in report["authority"].values())
    assert _files(tmp_path) == before


def test_workspace_advisor_detects_remote_path_classes_without_connecting():
    assert (
        _path_classification(r"\\wsl$\Ubuntu\home\dev\app", "Windows", {}) == "wsl_unc"
    )
    assert _path_classification(r"\\server\share\app", "Windows", {}) == "windows_unc"
    assert (
        _path_classification("/home/dev/app", "Linux", {"WSL_DISTRO_NAME": "Ubuntu"})
        == "linux_wsl"
    )
    assert _path_classification("C:\\work\\app", "Windows", {}) == "windows_local"


def test_workspace_advisor_marks_a_bounded_scan_and_never_fabricates_a_performance_diagnosis(
    tmp_path: Path,
):
    for index in range(3):
        (tmp_path / f"source-{index}.py").write_text("pass\n", encoding="utf-8")

    report = inspect_workspace(tmp_path, max_files=2, platform_name="Linux", environ={})

    assert report["scan"]["files_scanned"] == 2
    assert report["scan"]["scan_limited"] is True
    assert any(
        item["id"] == "evaluate_shared_indexes" for item in report["recommendations"]
    )
    assert any("IDE freeze" in item for item in report["limitations"])

    exact_cap = inspect_workspace(
        tmp_path, max_files=3, platform_name="Linux", environ={}
    )
    assert exact_cap["scan"]["files_scanned"] == 3
    assert exact_cap["scan"]["scan_limited"] is True


def test_workspace_advisor_writes_explicit_local_artifacts_only(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='demo'\n", encoding="utf-8"
    )
    report = inspect_workspace(tmp_path, platform_name="Linux", environ={})

    paths = write_workspace_advisor_artifacts(
        report, tmp_path, tmp_path / ".factory" / "workspace-advice"
    )

    assert paths == {
        "json": ".factory/workspace-advice/workspace-advisor.json",
        "markdown": ".factory/workspace-advice/workspace-advisor.md",
        "mermaid": ".factory/workspace-advice/workspace-advisor.mmd",
    }
    assert "not an IDE performance diagnosis" in (
        tmp_path / paths["markdown"]
    ).read_text(encoding="utf-8")
    assert "flowchart LR" in (tmp_path / paths["mermaid"]).read_text(encoding="utf-8")
    with pytest.raises(WorkspaceAdvisorError, match="artifact directory"):
        write_workspace_advisor_artifacts(report, tmp_path, tmp_path.parent / "outside")


def test_workspace_advisor_refuses_invalid_roots_and_scan_limits(tmp_path: Path):
    with pytest.raises(WorkspaceAdvisorError, match="existing directory"):
        inspect_workspace(tmp_path / "missing")
    with pytest.raises(WorkspaceAdvisorError, match="max_files"):
        inspect_workspace(tmp_path, max_files=0)


def test_workspace_cli_returns_the_read_only_contract_without_artifacts(
    tmp_path: Path, capsys
):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    before = _files(tmp_path)

    assert main(["workspace", "inspect", "--root", str(tmp_path), "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["marker"] == WORKSPACE_ADVISOR_MARKER
    assert "WORKSPACE_ADVISOR_NO_WRITE_DEFAULT" in payload["markers"]
    assert payload["artifacts"] == {}
    assert _files(tmp_path) == before

    out_dir = tmp_path / ".factory" / "workspace-advice"
    assert (
        main(
            [
                "workspace",
                "inspect",
                "--root",
                str(tmp_path),
                "--out-dir",
                str(out_dir),
                "--json",
            ]
        )
        == 0
    )
    written = json.loads(capsys.readouterr().out)
    assert "WORKSPACE_ADVISOR_ARTIFACTS_EXPLICIT" in written["markers"]
    assert set(written["artifacts"]["paths"]) == {"json", "markdown", "mermaid"}
