from __future__ import annotations
from hashlib import sha256
from pathlib import Path
import json
import pytest
from factoryline.target_compiler import (
    GENERATOR_ADAPTERS,
    TARGETS,
    TargetCompileError,
    create_target_from_prd,
    create_target_from_prompt,
)
from factoryline import target_compiler
from factoryline.cli import main
from factoryline.team_pilot import (
    TeamPilotError,
    evaluate_team_pilot_readiness,
    validate_team_pilot_manifest,
    validate_team_pilot_receipt,
    write_team_pilot_artifacts,
)


def test_windows_staging_promotion_retries_transient_access_denied(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    attempts = 0

    def deny_replace(*_args):
        raise PermissionError("Windows cannot replace a directory")

    def transient_rename(*_args):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            error = PermissionError("Windows file scan temporarily holds staging")
            error.winerror = 5
            raise error

    monkeypatch.setattr(target_compiler.os, "name", "nt")
    monkeypatch.setattr(target_compiler.os, "replace", deny_replace)
    monkeypatch.setattr(target_compiler.os, "rename", transient_rename)
    monkeypatch.setattr(target_compiler.time, "sleep", lambda _seconds: None)

    target_compiler._promote_staging(tmp_path / "staging", tmp_path / "target")

    assert attempts == 2


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
    assert "OUTPUT_MERMAID_MAP_WRITTEN" in result["markers"]
    assert "TARGET_DEPLOYMENT_PROFILE_BOUND" in result["markers"]
    assert "TARGET_PACK_GENERATOR_DISPATCHED" in result["markers"]
    assert TARGETS[target]["generator_adapter"] in GENERATOR_ADAPTERS
    manifest = json.loads((output / "target_manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema"] == "factory.target.v1"
    assert manifest["promotion"]["state"] == "blocked"
    assert manifest["privacy"]["network_egress"] == "not_granted"
    assert (
        manifest["deployment"]["selected_profile_id"]
        == TARGETS[target]["deployment_profiles"][0]["id"]
    )
    assert manifest["deployment"]["external_effects_authorized"] is False
    assert {"deploy", "publish", "sign", "external_message"}.issubset(
        manifest["approvals"]["required_for"]
    )

    receipt = json.loads(
        (output / ".factory" / "target-compile-receipt.json").read_text(
            encoding="utf-8"
        )
    )
    assert receipt["schema"] == "factory.target_compile_receipt.v1"
    assert (
        receipt["manifest_sha256"]
        == sha256((output / "target_manifest.json").read_bytes()).hexdigest()
    )
    for relative, expected in receipt["files"].items():
        assert sha256((output / relative).read_bytes()).hexdigest() == expected
    output_map = output / "docs" / "CODE_FACTORY_OUTPUT_MAP.md"
    map_text = output_map.read_text(encoding="utf-8")
    assert result["output_map"] == str(output_map)
    assert result["output_map_sha256"] == sha256(output_map.read_bytes()).hexdigest()
    assert receipt["output_map"] == {
        "path": "docs/CODE_FACTORY_OUTPUT_MAP.md",
        "sha256": result["output_map_sha256"],
    }
    assert "CODE_FACTORY_OUTPUT_MAP_V1" in map_text
    assert "flowchart TD" in map_text
    assert "Promotion: **compiled_blocked**" in map_text
    assert "## Optional sharing" in map_text
    share_section = map_text.split("## Optional sharing", maxsplit=1)[1]
    assert (
        "[Built with Code Factory](https://github.com/zrk222/code-factory)"
        in share_section
    )
    assert "does not post it, edit other files, or send output data" in share_section
    assert str(output) not in share_section
    assert "approval-tracker" not in share_section
    mapped = {
        line[3:-1]
        for line in map_text.splitlines()
        if line.startswith("- `") and line.endswith("`")
    }
    assert mapped == set(result["files"])
    assert ".factory/target-compile-receipt.json" in mapped

    assert (output / f"review-{target}.ssat.yaml").is_file()
    assert (output / "smoke" / f"review-{target}.json").is_file()
    assert (output / ".factory" / "target-architecture.mmd").is_file()
    assert 'pythonpath = ["."]' in (output / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    workflow = (output / "docs" / "TARGET_WORKFLOW.md").read_text(encoding="utf-8")
    assert manifest["deployment"]["profile"]["verify"] in workflow
    assert manifest["deployment"]["profile"]["approval"] in workflow


def test_selected_external_deployment_profile_is_bound_but_not_authorized(
    tmp_path: Path,
):
    output = tmp_path / "web-external"
    result = create_target_from_prompt(
        "Build a review dashboard.",
        target="web",
        out_dir=output,
        name="review-dashboard",
        deployment_profile="split-hosting",
    )

    assert result["deployment"]["selected_profile_id"] == "split-hosting"
    assert result["deployment"]["external_effects_authorized"] is False
    assert "two external deploys" in result["deployment"]["profile"]["approval"]


def test_unknown_deployment_profile_fails_before_writing(tmp_path: Path):
    output = tmp_path / "invalid-route"
    with pytest.raises(TargetCompileError, match="DEPLOYMENT_PROFILE_UNSUPPORTED"):
        create_target_from_prompt(
            "Build a worker.",
            target="worker",
            out_dir=output,
            deployment_profile="mystery-cloud",
        )
    assert not output.exists()


def test_missing_pack_generator_fails_closed_before_promotion(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setitem(TARGETS["worker"], "generator_adapter", "missing-adapter")
    output = tmp_path / "missing-generator"

    with pytest.raises(TargetCompileError, match="PACK_GENERATOR_UNSUPPORTED"):
        create_target_from_prompt("Build a worker.", target="worker", out_dir=output)

    assert not output.exists()


def test_target_specific_runtime_shapes(tmp_path: Path):
    cli = tmp_path / "cli"
    create_target_from_prompt(
        "Build a receipt CLI.", target="cli", out_dir=cli, name="receipt-cli"
    )
    assert "def render" in (cli / "cli_app" / "main.py").read_text(encoding="utf-8")

    api = tmp_path / "api"
    create_target_from_prompt(
        "Build a receipt API.", target="api", out_dir=api, name="receipt-api"
    )
    api_source = (api / "backend" / "main.py").read_text(encoding="utf-8")
    assert '@app.post("/v1/echo")' in api_source
    assert "class EchoRequest" in api_source

    mcp = tmp_path / "mcp"
    create_target_from_prompt(
        "Build a receipt MCP server.", target="mcp", out_dir=mcp, name="receipt-mcp"
    )
    mcp_source = (mcp / "mcp_server" / "main.py").read_text(encoding="utf-8")
    assert 'method == "tools/list"' in mcp_source
    assert 'method == "tools/call"' in mcp_source

    worker = tmp_path / "worker"
    create_target_from_prompt(
        "Build a deterministic receipt worker.",
        target="worker",
        out_dir=worker,
        name="receipt-worker",
    )
    assert "def run_task" in (worker / "worker" / "main.py").read_text(encoding="utf-8")

    mobile = tmp_path / "mobile"
    create_target_from_prompt(
        "Build a mobile receipt inbox.",
        target="mobile",
        out_dir=mobile,
        name="receipt-mobile",
    )
    package = json.loads(
        (mobile / "mobile" / "package.json").read_text(encoding="utf-8")
    )
    assert package["dependencies"]["expo"] == "~57.0.0"
    assert package["dependencies"]["expo-status-bar"] == "~57.0.1"
    assert package["dependencies"]["react-native"] == "0.86.0"
    assert package["overrides"]["uuid"] == "11.1.1"
    assert package["devDependencies"]["expo-doctor"] == "1.20.1"
    assert package["devDependencies"]["typescript"] == "~6.0.3"
    app_config = json.loads(
        (mobile / "mobile" / "app.json").read_text(encoding="utf-8")
    )
    assert "newArchEnabled" not in app_config["expo"]
    assert not (mobile / "mobile" / "android").exists()
    assert not (mobile / "mobile" / "ios").exists()

    operator = tmp_path / "operator"
    create_target_from_prompt(
        "Build a supervised release operator.",
        target="agent-ui",
        out_dir=operator,
        name="release-operator",
    )
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
    prd.write_text(
        "# Audit Mobile\n\nBuild a governed audit inbox.\n", encoding="utf-8"
    )
    output = tmp_path / "audit-mobile"
    create_target_from_prd(prd, target="mobile", out_dir=output, name="audit-mobile")

    manifest = json.loads((output / "target_manifest.json").read_text(encoding="utf-8"))
    assert manifest["intent"]["source_kind"] == "prd"
    assert manifest["intent"]["source_sha256"] == sha256(prd.read_bytes()).hexdigest()


REQUIRED_KINDS = [
    "commercial_terms_review",
    "data_retention_decision",
    "deployment_security_review",
    "design_partner_selection",
    "support_and_incident_owner",
]


def _sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _packaging(root: Path, *, team_purchasable: bool = False) -> None:
    docs = root / "docs"
    docs.mkdir(parents=True)
    payload = {
        "schema": "factory.commercial-packaging.v1",
        "governance": {
            "classification": "human_controlled",
            "automation_may_activate": False,
        },
        "current_verdict": "COMMERCIALIZATION_STAGED_NOT_SELLABLE",
        "tiers": {
            "team_proof_hub": {
                "availability": "design_partner_only",
                "purchasable": team_purchasable,
            }
        },
    }
    (docs / "COMMERCIAL_PACKAGING.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )


def _manifest(root: Path, **overrides: object) -> Path:
    _packaging(root)
    evidence: list[dict[str, str]] = []
    for kind in REQUIRED_KINDS:
        path = root / f"{kind}.json"
        path.write_text(json.dumps({"kind": kind, "reviewed": True}), encoding="utf-8")
        evidence.append({"kind": kind, "path": path.name, "sha256": _sha(path)})
    payload: dict[str, object] = {
        "schema": "factory.team-pilot-launch.v1",
        "pilot_id": "team-alpha",
        "owner": "pilot-owner",
        "partner_count": 3,
        "governance": "human_controlled",
        "delivery_mode": "customer_managed_reference",
        "evidence": evidence,
    }
    payload.update(overrides)
    path = root / "team-pilot.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_team_pilot_readiness_binds_all_required_evidence_and_writes_public_receipt(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)

    validated = validate_team_pilot_manifest(tmp_path, manifest)
    receipt = evaluate_team_pilot_readiness(tmp_path, manifest)

    assert [entry["kind"] for entry in validated["evidence"]] == REQUIRED_KINDS
    assert receipt["schema"] == "factory.team-pilot-readiness.v1"
    assert receipt["marker"] == "TEAM_PILOT_READY_FOR_OWNER_REVIEW"
    assert receipt["verdict"] == "READY_FOR_OWNER_REVIEW"
    assert receipt["commercial_boundary"]["purchasable"] is False
    assert receipt["authority"]["payment"] is False
    assert receipt["authority"]["marketplace_activation"] is False
    assert "does not accept a customer" in receipt["receipt_markdown"]
    assert validate_team_pilot_receipt(receipt) is receipt

    artifacts = write_team_pilot_artifacts(receipt, tmp_path / "packet")
    assert artifacts["marker"] == "TEAM_PILOT_ARTIFACTS_WRITTEN"
    assert set(artifacts["paths"]) == {"json", "markdown", "mermaid"}
    written = json.loads(Path(artifacts["paths"]["json"]).read_text(encoding="utf-8"))
    assert written["receipt_sha256"] == receipt["receipt_sha256"]


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"partner_count": 4}, "E_TEAM_PILOT_PARTNER_CAP"),
        ({"partner_count": True}, "E_TEAM_PILOT_PARTNER_CAP"),
        ({"governance": "supervised"}, "E_TEAM_PILOT_GOVERNANCE"),
        ({"delivery_mode": "factory_managed"}, "E_TEAM_PILOT_DELIVERY_MODE"),
        ({"evidence": []}, "E_TEAM_PILOT_EVIDENCE_KIND"),
    ],
)
def test_team_pilot_manifest_fails_closed_on_scope_and_governance_errors(
    tmp_path: Path,
    overrides: dict[str, object],
    code: str,
) -> None:
    manifest = _manifest(tmp_path, **overrides)

    with pytest.raises(TeamPilotError) as exc:
        evaluate_team_pilot_readiness(tmp_path, manifest)

    assert exc.value.code == code


def test_team_pilot_rejects_digest_drift_and_workspace_escape_before_owner_review(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    first = tmp_path / payload["evidence"][0]["path"]
    first.write_text("changed after review", encoding="utf-8")

    with pytest.raises(TeamPilotError) as exc:
        evaluate_team_pilot_readiness(tmp_path, manifest)
    assert exc.value.code == "E_TEAM_PILOT_EVIDENCE_DIGEST"

    manifest = _manifest(tmp_path / "escaped")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["evidence"][0]["path"] = "../outside.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(TeamPilotError) as exc:
        evaluate_team_pilot_readiness(manifest.parent, manifest)
    assert exc.value.code == "E_TEAM_PILOT_EVIDENCE_PATH"


def test_team_pilot_rejects_commercial_boundary_drift_and_tampered_receipts(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    packaging_path = tmp_path / "docs" / "COMMERCIAL_PACKAGING.json"
    packaging = json.loads(packaging_path.read_text(encoding="utf-8"))
    packaging["tiers"]["team_proof_hub"]["purchasable"] = True
    packaging_path.write_text(json.dumps(packaging), encoding="utf-8")

    with pytest.raises(TeamPilotError) as exc:
        evaluate_team_pilot_readiness(tmp_path, manifest)
    assert exc.value.code == "E_TEAM_PILOT_COMMERCIAL_BOUNDARY"

    manifest = _manifest(tmp_path / "tampered")
    receipt = evaluate_team_pilot_readiness(manifest.parent, manifest)
    receipt["authority"]["payment"] = True
    with pytest.raises(TeamPilotError) as exc:
        validate_team_pilot_receipt(receipt)
    assert exc.value.code == "E_TEAM_PILOT_RECEIPT_INVALID"


def test_team_pilot_cli_is_json_safe_and_receipt_verifiable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = _manifest(tmp_path)

    code = main(
        [
            "team-pilot",
            "readiness",
            "--root",
            str(tmp_path),
            "--manifest",
            manifest.name,
            "--out-dir",
            str(tmp_path / "packet"),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    receipt_path = Path(output["artifacts"]["paths"]["json"])
    assert code == 0
    assert output["receipt"]["marker"] == "TEAM_PILOT_READY_FOR_OWNER_REVIEW"

    code = main(["team-pilot", "verify", str(receipt_path), "--json"])
    verified = json.loads(capsys.readouterr().out)
    assert code == 0
    assert verified["receipt"]["verdict"] == "READY_FOR_OWNER_REVIEW"
