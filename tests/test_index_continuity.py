from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.index_continuity import (
    INDEX_CONTINUITY_BASELINE_SCHEMA,
    INDEX_CONTINUITY_MARKER,
    IndexContinuityError,
    capture_continuity_baseline,
    compare_continuity,
    write_continuity_baseline,
)


def _baseline(root: Path) -> Path:
    output = root / ".factory" / "index-continuity" / "baseline.json"
    write_continuity_baseline(capture_continuity_baseline(root), root, output)
    return output


def test_baseline_is_explicit_local_and_never_stores_source_contents(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"name":"demo-secret"}', encoding="utf-8")
    baseline = capture_continuity_baseline(tmp_path)
    output = tmp_path / ".factory" / "index-continuity" / "baseline.json"

    assert baseline["schema"] == INDEX_CONTINUITY_BASELINE_SCHEMA
    assert baseline["marker"] == INDEX_CONTINUITY_MARKER
    assert all(value is False for value in baseline["authority"].values())
    assert "demo-secret" not in json.dumps(baseline)
    assert write_continuity_baseline(baseline, tmp_path, output) == ".factory/index-continuity/baseline.json"
    with pytest.raises(IndexContinuityError, match="workspace root"):
        write_continuity_baseline(baseline, tmp_path, tmp_path.parent / "outside.json")


def test_identical_baseline_is_stable_and_does_not_fabricate_a_duration(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"name":"demo"}', encoding="utf-8")
    result = compare_continuity(tmp_path, _baseline(tmp_path))

    assert result["review_scope"] == "stable"
    assert result["changes"] == []
    assert "no reindexing duration" in json.dumps(result).lower()
    assert "INDEX_CONTINUITY_NO_IDE_MUTATION" in result["markers"]


def test_changed_manifest_requires_broad_reanalysis_with_exact_path(tmp_path: Path):
    manifest = tmp_path / "package.json"
    manifest.write_text('{"name":"demo","version":"1"}', encoding="utf-8")
    baseline = _baseline(tmp_path)
    manifest.write_text('{"name":"demo","version":"2"}', encoding="utf-8")

    result = compare_continuity(tmp_path, baseline)

    assert result["review_scope"] == "broad_reanalysis"
    file_change = next(item for item in result["changes"] if item["kind"] == "structural_files")
    assert file_change["files"] == [{"path": "package.json", "change": "changed"}]


def test_managed_directory_drift_is_targeted_not_a_corruption_claim(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    baseline = _baseline(tmp_path)
    generated = tmp_path / "build"
    generated.mkdir()
    (generated / "bundle.js").write_text("output", encoding="utf-8")

    result = compare_continuity(tmp_path, baseline)

    assert result["review_scope"] == "targeted_reanalysis"
    assert "corrupt" not in json.dumps(result).lower()


def test_tampered_or_invalid_baseline_fails_closed(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    baseline = _baseline(tmp_path)
    payload = json.loads(baseline.read_text(encoding="utf-8"))
    payload["source_roots"] = ["unexpected"]
    baseline.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(IndexContinuityError, match="digest"):
        compare_continuity(tmp_path, baseline)


def test_cli_end_to_end_baseline_then_compare(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    manifest = tmp_path / "Cargo.toml"
    manifest.write_text("[package]\nname='demo'\n", encoding="utf-8")
    baseline = tmp_path / ".factory" / "index-continuity" / "baseline.json"

    assert main(["workspace", "continuity", "baseline", "--root", str(tmp_path), "--out", str(baseline), "--json"]) == 0
    captured = json.loads(capsys.readouterr().out)
    assert captured["baseline_path"] == ".factory/index-continuity/baseline.json"
    manifest.write_text("[package]\nname='changed'\n", encoding="utf-8")
    assert main(["workspace", "continuity", "compare", "--root", str(tmp_path), "--baseline", str(baseline), "--json"]) == 0
    compared = json.loads(capsys.readouterr().out)
    assert compared["review_scope"] == "broad_reanalysis"
