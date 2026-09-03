from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.appforge_native_surface import verify_native_surface
from factoryline.appforge_surface_matrix import create_surface_matrix, surface_matrix_projection
from factoryline.cli import main
from factoryline.revenueforge import RevenueForgeError

from test_appforge_native_surface import _candidate, _contract, _evidence, _source


def test_surface_matrix_expands_the_exact_ready_native_surface_receipt(tmp_path: Path, capsys) -> None:
    candidate = _candidate(tmp_path)
    source = _source(tmp_path)
    contract = _contract(tmp_path, source)
    evidence = _evidence(tmp_path, contract)
    verify_native_surface(tmp_path, candidate, contract, evidence, Path(".factory/appforge/native-surface.json"))

    receipt = create_surface_matrix(tmp_path, candidate, Path(".factory/appforge/native-surface.json"), Path(".factory/appforge/surface-matrix.json"))

    assert receipt["marker"] == "APPFORGE_SURFACE_MATRIX_WRITTEN"
    assert {item["configuration"] for item in receipt["scenarios"]} >= {"Split View / compact width", "Dynamic Type accessibility size", "VoiceOver"}
    assert all(item["required_evidence"] == "supervised physical-device capture" for item in receipt["scenarios"])
    assert receipt["authority"]["device_access"] is False
    assert surface_matrix_projection(tmp_path)["current_count"] == 1
    assert main(["revenue", "appforge-surface-matrix", "--root", str(tmp_path), "--candidate", "candidate.json", "--native-surface", ".factory/appforge/native-surface.json", "--out", ".factory/appforge/cli-surface-matrix.json", "--json"]) == 0
    assert "APPFORGE_SURFACE_MATRIX_WRITTEN" in capsys.readouterr().out


def test_surface_matrix_rejects_unsealed_or_mismatched_native_surface(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    bad = tmp_path / "native.json"
    bad.write_text(json.dumps({"schema": "factory.appforge.native-surface-receipt.v1", "marker": "APPFORGE_NATIVE_SURFACE_READY", "candidate": {}}), encoding="utf-8")

    with pytest.raises(RevenueForgeError, match="hash-valid, ready"):
        create_surface_matrix(tmp_path, candidate, bad, Path(".factory/appforge/surface-matrix.json"))


def test_surface_matrix_projection_excludes_tampered_receipt(tmp_path: Path) -> None:
    directory = tmp_path / ".factory" / "appforge"
    directory.mkdir(parents=True)
    (directory / "surface-matrix.json").write_text(json.dumps({"schema": "factory.appforge.surface-matrix-receipt.v1", "receipt_sha256": "0" * 64}), encoding="utf-8")
    projection = surface_matrix_projection(tmp_path)
    assert projection["current_count"] == 0
    assert projection["invalid_count"] == 1
