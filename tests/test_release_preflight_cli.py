from __future__ import annotations

import json
from pathlib import Path

import factoryline.release_candidate as candidate
from factoryline.cli import main


def test_release_preflight_cli_writes_machine_receipt(monkeypatch, tmp_path: Path, capsys) -> None:
    source = tmp_path / "factoryline"
    source.mkdir()
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.46.3"\n', encoding="utf-8")
    (source / "__init__.py").write_text('__version__ = "0.46.3"\n', encoding="utf-8")
    monkeypatch.setattr(candidate, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(candidate, "verify_release_contract", lambda *args: {"ok": True, "marker": "RELEASE_CONTRACT_VALID"})
    contract = tmp_path / "contract.json"
    contract.write_text(json.dumps({"schema": "factory.release-contract.v1", "feature": "release", "candidate": {"source_version": "0.46.3", "source_commit": "a" * 40}}), encoding="utf-8")
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "factoryline_code_factory-0.46.3.tar.gz").write_bytes(b"candidate")
    out = tmp_path / ".factory" / "preflight.json"

    assert main(["release", "preflight", "--root", str(tmp_path), "--contract", str(contract), "--artifact-dir", str(artifacts), "--out", str(out), "--json"]) == 0
    emitted = json.loads(capsys.readouterr().out)
    written = json.loads(out.read_text(encoding="utf-8"))

    assert emitted["marker"] == "RELEASE_CANDIDATE_PREFLIGHT_WRITTEN"
    assert written["ok"] is True
    assert written["authority"]["publication"] is False
    assert len(written["receipt_sha256"]) == 64
