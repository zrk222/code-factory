from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import json

import pytest

from factoryline.target_compiler import (
    TARGETS,
    TargetCompileError,
    create_target_from_prd,
    create_target_from_prompt,
)


@pytest.mark.parametrize("target", sorted(TARGETS))
def test_each_target_has_governance_proof_and_hashes(tmp_path: Path, target: str):
    output = tmp_path / target
    result = create_target_from_prompt(
        "Build a receipt review workspace with explicit approval boundaries.",
        target=target,
        out_dir=output,
        name=f"review-{target}",
        purpose="developer",
    )

    assert result["status"] == "compiled_blocked"
    assert result["target_kind"] == target
    assert "SOURCE_EXACTLY_ONE" in result["markers"]
    assert "COMPILE_RECEIPT_BOUND" in result["markers"]
    manifest = json.loads((output / "target_manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema"] == "factory.target.v1"
    assert manifest["promotion"]["state"] == "blocked"
    assert manifest["privacy"]["network_egress"] == "not_granted"
    assert {"deploy", "publish", "sign", "external_message"}.issubset(
        manifest["approvals"]["required_for"]
    )

    receipt = json.loads((output / ".factory" / "target-compile-receipt.json").read_text(encoding="utf-8"))
    assert receipt["schema"] == "factory.target_compile_receipt.v1"
    assert receipt["manifest_sha256"] == sha256((output / "target_manifest.json").read_bytes()).hexdigest()
    for relative, expected in receipt["files"].items():
        assert sha256((output / relative).read_bytes()).hexdigest() == expected

    assert (output / f"review-{target}.ssat.yaml").is_file()
    assert (output / "smoke" / f"review-{target}.json").is_file()
    assert (output / ".factory" / "target-architecture.mmd").is_file()
    assert 'pythonpath = ["."]' in (output / "pyproject.toml").read_text(encoding="utf-8")


def test_target_specific_runtime_shapes(tmp_path: Path):
    worker = tmp_path / "worker"
    create_target_from_prompt("Build a deterministic receipt worker.", target="worker", out_dir=worker, name="receipt-worker")
    assert "def run_task" in (worker / "worker" / "main.py").read_text(encoding="utf-8")

    mobile = tmp_path / "mobile"
    create_target_from_prompt("Build a mobile receipt inbox.", target="mobile", out_dir=mobile, name="receipt-mobile")
    package = json.loads((mobile / "mobile" / "package.json").read_text(encoding="utf-8"))
    assert package["dependencies"]["expo"] == "~57.0.0"
    assert package["dependencies"]["expo-status-bar"] == "~57.0.1"
    assert package["dependencies"]["react-native"] == "0.86.0"
    assert package["overrides"]["uuid"] == "11.1.1"
    assert package["devDependencies"]["expo-doctor"] == "1.20.1"
    assert package["devDependencies"]["typescript"] == "~6.0.3"
    app_config = json.loads((mobile / "mobile" / "app.json").read_text(encoding="utf-8"))
    assert "newArchEnabled" not in app_config["expo"]
    assert not (mobile / "mobile" / "android").exists()
    assert not (mobile / "mobile" / "ios").exists()

    operator = tmp_path / "operator"
    create_target_from_prompt("Build a supervised release operator.", target="agent-ui", out_dir=operator, name="release-operator")
    backend = (operator / "backend" / "main.py").read_text(encoding="utf-8")
    assert '"approval_required": True' in backend
    assert '"executed": False' in backend
    assert (operator / "frontend" / "app" / "layout.tsx").is_file()


def test_non_empty_output_is_unchanged(tmp_path: Path):
    output = tmp_path / "existing"
    output.mkdir()
    sentinel = output / "service.ts"
    sentinel.write_text("export const intact = true;\n", encoding="utf-8")

    with pytest.raises(TargetCompileError, match="OUTPUT_EXISTS"):
        create_target_from_prompt("Build a worker.", target="worker", out_dir=output)

    assert sentinel.read_text(encoding="utf-8") == "export const intact = true;\n"
    assert list(output.iterdir()) == [sentinel]


def test_prd_is_the_single_bound_source(tmp_path: Path):
    prd = tmp_path / "PRD.md"
    prd.write_text("# Audit Mobile\n\nBuild a governed audit inbox.\n", encoding="utf-8")
    output = tmp_path / "audit-mobile"
    create_target_from_prd(prd, target="mobile", out_dir=output, name="audit-mobile")

    manifest = json.loads((output / "target_manifest.json").read_text(encoding="utf-8"))
    assert manifest["intent"]["source_kind"] == "prd"
    assert manifest["intent"]["source_sha256"] == sha256(prd.read_bytes()).hexdigest()
