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
    compose_packs,
    install_pack,
    target_inventory,
    validate_pack,
)
from factoryline.cli import main


EXPECTED_TARGETS = {"agent-ui", "api", "cli", "mcp", "mobile", "web", "worker"}
EXPECTED_KINDS = {"target", "surface", "language", "capability", "data", "ops"}


def test_builtin_target_packs_are_signed_and_mutation_tested():
    packs = builtin_packs()
    assert len(packs) == 29
    assert {item["kind"] for item in packs} == EXPECTED_KINDS
    assert {item["target_kind"] for item in packs if item["kind"] == "target"} == EXPECTED_TARGETS
    for item in packs:
        result = validate_pack(Path(item["path"]))
        assert result["valid"] is True
        assert result["signature"]["verified"] is True
        assert result["mutations"]["attempted"] == 10
        assert result["mutations"]["rejected"] == 10


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


def test_pack_signatures_are_portable_across_text_line_endings(tmp_path: Path):
    source = BUILTIN_ROOT / "target-worker"
    copied = tmp_path / "target-worker"
    shutil.copytree(source, copied)
    for path in copied.rglob("*"):
        if not path.is_file() or path.name == "pack.signature.json":
            continue
        data = path.read_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        path.write_bytes(text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n").encode("utf-8"))

    result = validate_pack(copied)

    assert result["valid"] is True
    assert result["signature"]["verified"] is True


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
    assert len(payload["packs"]) == 29
    assert all(item["valid"] and item["signature"]["verified"] for item in payload["packs"])


def test_pack_composition_is_hash_bound_and_has_no_execution_authority(tmp_path: Path):
    result = compose_packs([
        BUILTIN_ROOT / "target-web",
        BUILTIN_ROOT / "surface-nextjs",
        BUILTIN_ROOT / "language-typescript",
        BUILTIN_ROOT / "capability-auth",
    ], tmp_path, name="review-portal")

    assert result["marker"] == "PACK_COMPOSITION_VERIFIED"
    assert result["pack_count"] == 4
    assert result["target_kind"] == "web"
    assert result["authority"] == {"generate": False, "execute": False, "deploy": False, "publish": False}
    assert len(result["composition_sha256"]) == 64
    assert Path(result["path"]).is_file()
    assert {item["id"] for item in result["packs"]} == {
        "target-web", "surface-nextjs", "language-typescript", "capability-auth",
    }


def test_pack_composition_rejects_incompatible_target(tmp_path: Path):
    with pytest.raises(CapabilityPackError, match="PACK_COMPOSITION_INCOMPATIBLE"):
        compose_packs([
            BUILTIN_ROOT / "target-worker",
            BUILTIN_ROOT / "surface-expo",
        ], tmp_path)


def test_pack_composition_preserves_existing_file_when_atomic_swap_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
    composition_root = tmp_path / ".factory" / "pack-compositions"
    composition_root.mkdir(parents=True)
    destination = composition_root / "api-stack.json"
    destination.write_text('{"previous": true}\n', encoding="utf-8")

    def fail_swap(_source, _destination):
        raise OSError("simulated composition swap failure")

    monkeypatch.setattr(capability_packs.os, "replace", fail_swap)
    with pytest.raises(CapabilityPackError) as caught:
        compose_packs([
            BUILTIN_ROOT / "target-api",
            BUILTIN_ROOT / "language-python",
        ], tmp_path, name="api-stack", force=True)

    assert caught.value.code == "PACK_COMPOSITION_WRITE_FAILED"
    assert "PACK_COMPOSITION_ROLLBACK_PRESERVED" in caught.value.markers
    assert destination.read_text(encoding="utf-8") == '{"previous": true}\n'
    assert not list(composition_root.glob(".api-stack.json.*.tmp"))


def test_pack_compose_cli_writes_review_plan(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    assert main([
        "pack", "compose",
        str(BUILTIN_ROOT / "target-api"),
        str(BUILTIN_ROOT / "language-python"),
        str(BUILTIN_ROOT / "capability-auth"),
        "--root", str(tmp_path), "--name", "api-stack",
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["target_kind"] == "api"
    assert "PACK_COMPOSITION_NO_EXECUTION_AUTHORITY" in payload["markers"]
