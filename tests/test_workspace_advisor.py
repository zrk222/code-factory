from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.workspace_advisor import (
    WORKSPACE_ADVISOR_MARKER,
    WORKSPACE_ADVISOR_SCHEMA,
    WorkspaceAdvisorError,
    _path_classification,
    inspect_workspace,
    write_workspace_advisor_artifacts,
)
from factoryline.cli import main


def _files(root: Path) -> dict[str, bytes]:
    return {
        item.relative_to(root).as_posix(): item.read_bytes()
        for item in root.rglob("*") if item.is_file()
    }


def test_workspace_advisor_is_bounded_read_only_and_reports_reviewable_facts(tmp_path: Path):
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
    assert {"WORKSPACE_ADVISOR_SCHEMA_BOUND", "WORKSPACE_ADVISOR_NO_WRITE_DEFAULT", "WORKSPACE_ADVISOR_ZERO_AUTHORITY"} <= set(report["markers"])
    assert report["scan"]["files_scanned"] == 3
    assert report["scan"]["bytes_scanned"] == 21
    assert report["scan"]["git_directory_skipped"] is True
    assert report["workspace"]["path_classification"] == "windows_local"
    assert report["workspace"]["ecosystems"] == ["node"]
    assert {item["path"] for item in report["managed_directory_summary"]} == {"build", "node_modules"}
    assert {item["id"] for item in report["recommendations"]} >= {
        "review_generated_directories", "review_dependency_directory_visibility",
    }
    assert set(report["authority"]) == {
        "execution", "ide_settings", "cache_mutation", "indexing_mutation",
        "remote_connection", "credential", "publication", "deployment",
    }
    assert all(value is False for value in report["authority"].values())
    assert _files(tmp_path) == before


def test_workspace_advisor_detects_remote_path_classes_without_connecting():
    assert _path_classification(r"\\wsl$\Ubuntu\home\dev\app", "Windows", {}) == "wsl_unc"
    assert _path_classification(r"\\server\share\app", "Windows", {}) == "windows_unc"
    assert _path_classification("/home/dev/app", "Linux", {"WSL_DISTRO_NAME": "Ubuntu"}) == "linux_wsl"
    assert _path_classification("C:\\work\\app", "Windows", {}) == "windows_local"


def test_workspace_advisor_marks_a_bounded_scan_and_never_fabricates_a_performance_diagnosis(tmp_path: Path):
    for index in range(3):
        (tmp_path / f"source-{index}.py").write_text("pass\n", encoding="utf-8")

    report = inspect_workspace(tmp_path, max_files=2, platform_name="Linux", environ={})

    assert report["scan"]["files_scanned"] == 2
    assert report["scan"]["scan_limited"] is True
    assert any(item["id"] == "evaluate_shared_indexes" for item in report["recommendations"])
    assert any("IDE freeze" in item for item in report["limitations"])

    exact_cap = inspect_workspace(tmp_path, max_files=3, platform_name="Linux", environ={})
    assert exact_cap["scan"]["files_scanned"] == 3
    assert exact_cap["scan"]["scan_limited"] is True


def test_workspace_advisor_writes_explicit_local_artifacts_only(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    report = inspect_workspace(tmp_path, platform_name="Linux", environ={})

    paths = write_workspace_advisor_artifacts(report, tmp_path, tmp_path / ".factory" / "workspace-advice")

    assert paths == {
        "json": ".factory/workspace-advice/workspace-advisor.json",
        "markdown": ".factory/workspace-advice/workspace-advisor.md",
        "mermaid": ".factory/workspace-advice/workspace-advisor.mmd",
    }
    assert "not an IDE performance diagnosis" in (tmp_path / paths["markdown"]).read_text(encoding="utf-8")
    assert "flowchart LR" in (tmp_path / paths["mermaid"]).read_text(encoding="utf-8")
    with pytest.raises(WorkspaceAdvisorError, match="artifact directory"):
        write_workspace_advisor_artifacts(report, tmp_path, tmp_path.parent / "outside")


def test_workspace_advisor_refuses_invalid_roots_and_scan_limits(tmp_path: Path):
    with pytest.raises(WorkspaceAdvisorError, match="existing directory"):
        inspect_workspace(tmp_path / "missing")
    with pytest.raises(WorkspaceAdvisorError, match="max_files"):
        inspect_workspace(tmp_path, max_files=0)


def test_workspace_cli_returns_the_read_only_contract_without_artifacts(tmp_path: Path, capsys):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    before = _files(tmp_path)

    assert main(["workspace", "inspect", "--root", str(tmp_path), "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["marker"] == WORKSPACE_ADVISOR_MARKER
    assert "WORKSPACE_ADVISOR_NO_WRITE_DEFAULT" in payload["markers"]
    assert payload["artifacts"] == {}
    assert _files(tmp_path) == before

    out_dir = tmp_path / ".factory" / "workspace-advice"
    assert main(["workspace", "inspect", "--root", str(tmp_path), "--out-dir", str(out_dir), "--json"]) == 0
    written = json.loads(capsys.readouterr().out)
    assert "WORKSPACE_ADVISOR_ARTIFACTS_EXPLICIT" in written["markers"]
    assert set(written["artifacts"]["paths"]) == {"json", "markdown", "mermaid"}
