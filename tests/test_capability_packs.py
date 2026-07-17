from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from factoryline import capability_packs
from factoryline.capability_packs import (
    BUILTIN_ROOT,
    CapabilityPackError,
    builtin_packs,
    install_pack,
    target_inventory,
    validate_pack,
)
from factoryline.cli import main


EXPECTED_TARGETS = {"agent-ui", "mobile", "web", "worker"}


def test_builtin_target_packs_are_signed_and_mutation_tested():
    packs = builtin_packs()
    assert {item["target_kind"] for item in packs} == EXPECTED_TARGETS
    for item in packs:
        result = validate_pack(Path(item["path"]))
        assert result["valid"] is True
        assert result["signature"]["verified"] is True
        assert result["mutations"]["attempted"] == 5
        assert result["mutations"]["rejected"] == 5


def test_target_inventory_is_derived_from_packs():
    inventory = target_inventory()
    assert set(inventory) == EXPECTED_TARGETS
    assert inventory["agent-ui"]["pack_id"] == "target-agent-ui"
    assert inventory["worker"]["entrypoint"] == "python -m worker.main"


def test_builtin_discovery_ignores_python_cache_directories(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    root = tmp_path / "builtin_packs"
    shutil.copytree(BUILTIN_ROOT / "target-worker", root / "target-worker")
    (root / "__pycache__").mkdir()
    monkeypatch.setattr(capability_packs, "BUILTIN_ROOT", root)

    packs = builtin_packs()

    assert [item["id"] for item in packs] == ["target-worker"]


def test_tampered_pack_fails_closed(tmp_path: Path):
    source = BUILTIN_ROOT / "target-worker"
    tampered = tmp_path / "target-worker"
    shutil.copytree(source, tampered)
    manifest = json.loads((tampered / "pack.yaml").read_text(encoding="utf-8"))
    manifest["summary"] = "tampered"
    (tampered / "pack.yaml").write_text(json.dumps(manifest), encoding="utf-8")

    result = validate_pack(tampered)

    assert result["valid"] is False
    assert any("signed pack payload does not match current files" in item for item in result["errors"])
    assert result["failure"]["causal_code"] == "PACK_VALIDATION_FAILED"


def test_hollow_canary_manifest_is_rejected_before_install(tmp_path: Path):
    source = BUILTIN_ROOT / "target-web"
    broken = tmp_path / "target-web"
    shutil.copytree(source, broken)
    canaries = broken / "canaries" / "manifest.json"
    canaries.write_text('{"schema":"factory.pack.canaries.v1","canaries":[]}', encoding="utf-8")

    result = validate_pack(broken)

    assert result["valid"] is False
    assert "canary manifest must be non-empty" in result["errors"]


def test_install_is_verified_and_refuses_implicit_replacement(tmp_path: Path):
    source = BUILTIN_ROOT / "target-mobile"
    result = install_pack(source, tmp_path)
    installed = tmp_path / ".factory" / "packs" / "target-mobile"
    assert result["marker"] == "PACK_INSTALLED_VERIFIED"
    assert installed.is_dir()
    assert validate_pack(installed)["valid"] is True

    with pytest.raises(CapabilityPackError, match="PACK_EXISTS"):
        install_pack(source, tmp_path)


def test_install_rejects_pack_id_path_escape(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(capability_packs, "validate_pack", lambda *args, **kwargs: {
        "valid": True,
        "pack_id": "../escape",
        "version": "1.0.0",
        "signature": {"verified": True},
        "mutations": {"attempted": 5, "rejected": 5},
        "errors": [],
    })
    with pytest.raises(CapabilityPackError, match="PACK_PATH_INVALID"):
        install_pack(BUILTIN_ROOT / "target-worker", tmp_path)
    assert not (tmp_path / ".factory" / "escape").exists()


def test_force_install_restores_previous_pack_when_swap_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    source = BUILTIN_ROOT / "target-worker"
    install_pack(source, tmp_path)
    destination = tmp_path / ".factory" / "packs" / "target-worker"
    sentinel = destination / "local-sentinel.txt"
    sentinel.write_text("previous-install", encoding="utf-8")
    original_replace = capability_packs.os.replace
    calls = 0

    def fail_final_swap(src, dst):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated final swap failure")
        return original_replace(src, dst)

    monkeypatch.setattr(capability_packs.os, "replace", fail_final_swap)
    with pytest.raises(CapabilityPackError) as caught:
        install_pack(source, tmp_path, force=True)
    assert caught.value.code == "PACK_INSTALL_FAILED"
    assert "PACK_ROLLBACK_RESTORED" in caught.value.markers
    assert sentinel.read_text(encoding="utf-8") == "previous-install"


def test_cli_lists_verified_packs(capsys: pytest.CaptureFixture[str]):
    assert main(["pack", "list"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["packs"]) == 4
    assert all(item["valid"] and item["signature"]["verified"] for item in payload["packs"])
