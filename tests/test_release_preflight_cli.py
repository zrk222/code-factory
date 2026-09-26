from __future__ import annotations

import json
from pathlib import Path

import factoryline.release_candidate as candidate
from factoryline.cli import main
from scripts.verify_release_preflight import main as verify_release_preflight_main
from scripts.verify_release_preflight import verify as verify_release_preflight


def test_release_preflight_cli_writes_machine_receipt(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    source = tmp_path / "factoryline"
    source.mkdir()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nversion = "0.46.3"\n', encoding="utf-8"
    )
    (source / "__init__.py").write_text('__version__ = "0.46.3"\n', encoding="utf-8")
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
    contract = tmp_path / "contract.json"
    contract.write_text(
        json.dumps(
            {
                "schema": "factory.release-contract.v1",
                "feature": "release",
                "candidate": {"source_version": "0.46.3", "source_commit": "a" * 40},
            }
        ),
        encoding="utf-8",
    )
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "factoryline_code_factory-0.46.3.tar.gz").write_bytes(b"candidate")
    out = tmp_path / ".factory" / "preflight.json"

    assert (
        main(
            [
                "release",
                "preflight",
                "--root",
                str(tmp_path),
                "--contract",
                str(contract),
                "--artifact-dir",
                str(artifacts),
                "--out",
                str(out),
                "--json",
            ]
        )
        == 0
    )
    emitted = json.loads(capsys.readouterr().out)
    written = json.loads(out.read_text(encoding="utf-8"))

    assert emitted["marker"] == "RELEASE_CANDIDATE_PREFLIGHT_WRITTEN"
    assert written["ok"] is True
    assert written["authority"]["publication"] is False
    assert len(written["receipt_sha256"]) == 64


def test_structured_ok_receipt_is_accepted(tmp_path):
    path = tmp_path / "release-preflight.json"
    path.write_text(
        json.dumps(
            {
                "ok": True,
                "schema": "factory.release-candidate-preflight.v1",
                "marker": "RELEASE_CANDIDATE_PREFLIGHT_WRITTEN",
            }
        ),
        encoding="utf-8",
    )
    assert verify_release_preflight(path)["ok"] is True
    assert verify_release_preflight_main([str(path)]) == 0


def test_failed_or_malformed_receipt_is_rejected(tmp_path):
    failed = tmp_path / "failed.json"
    failed.write_text(json.dumps({"ok": False}), encoding="utf-8")
    malformed = tmp_path / "malformed.json"
    malformed.write_text("[]", encoding="utf-8")
    assert verify_release_preflight_main([str(failed)]) == 1
    assert verify_release_preflight_main([str(malformed)]) == 1
