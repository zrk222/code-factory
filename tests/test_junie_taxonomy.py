from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.junie_taxonomy import (
    JunieTaxonomyError,
    PACK_CONFIRMATION,
    install_junie_factoryline_pack,
    junie_taxonomy,
    validate_junie_contribution,
)
from factoryline.mcp import _tool_definitions


def test_taxonomy_is_complete_progressive_and_has_no_external_effect_authority(tmp_path: Path) -> None:
    taxonomy = junie_taxonomy(tmp_path)
    declared = [tool for stage in taxonomy["stages"] for tool in stage["tools"]]
    inventory = [tool["name"] for tool in _tool_definitions()]

    assert taxonomy["schema"] == "factory.junie-taxonomy.v1"
    assert taxonomy["marker"] == "JUNIE_FACTORYLINE_TAXONOMY_READY"
    assert set(declared) == set(inventory)
    assert len(declared) == len(set(declared))
    assert taxonomy["tool_count"] == len(inventory)
    assert [stage["id"] for stage in taxonomy["stages"]] == [
        "orient", "intent", "review", "audit", "agent_handoff", "enterprise", "product",
    ]
    assert [stage["default"] for stage in taxonomy["stages"]] == [True, True, True, True, True, False, False]
    assert all(value is False for value in taxonomy["authority"].values())
    assert "does not install, enable, start, observe, or control Junie" in taxonomy["claim_boundary"]
    protocol = taxonomy["contribution_protocol"]
    assert protocol["marker"] == "JUNIE_FACTORYLINE_CONTRIBUTION_PROTOCOL_READY"
    assert protocol["taxonomy_sha256"] == taxonomy["taxonomy_sha256"]
    assert "cannot authenticate Junie" in protocol["claim_boundary"]


def test_contribution_gives_visible_bounded_credit_and_hashes_only_cited_local_files(tmp_path: Path) -> None:
    evidence = tmp_path / "receipts/evidence.json"
    changed = tmp_path / "src/example.py"
    evidence.parent.mkdir(parents=True)
    changed.parent.mkdir(parents=True)
    evidence.write_text('{"passed": true}\n', encoding="utf-8")
    changed.write_text("print('reviewed')\n", encoding="utf-8")
    taxonomy = junie_taxonomy(tmp_path)

    contribution = validate_junie_contribution(tmp_path, {
        "taxonomy_sha256": taxonomy["taxonomy_sha256"],
        "tools_called": ["factory.junie_taxonomy", "factory.graph_ops"],
        "evidence_paths": ["receipts/evidence.json"],
        "changed_paths": ["src/example.py"],
        "change_rationales": {"src/example.py": "Connect this changed implementation path to the reviewable proof route."},
        "contribution": "Mapped the proposed change to local proof evidence for review.",
        "unknowns": ["A human reviewer must still decide whether the evidence is sufficient."],
    })

    assert contribution["marker"] == "JUNIE_FACTORYLINE_CONTRIBUTION_DECLARED"
    assert contribution["declaration_state"] == "declared_with_local_evidence"
    assert contribution["credit_line"].startswith("FactoryLine contribution declared:")
    assert contribution["evidence"][0]["path"] == "receipts/evidence.json"
    assert contribution["change_cards"][0]["path"] == "src/example.py"
    assert contribution["change_cards"][0]["rationale"].startswith("Connect this changed")
    assert contribution["review_lens"]["sequence"] == "source → obligation → forbidden behavior → gate → test → evidence → decision"
    assert "cannot authenticate Junie" in contribution["claim_boundary"]
    assert all(value is False for value in contribution["authority"].values())

    with pytest.raises(JunieTaxonomyError) as mismatch:
        validate_junie_contribution(tmp_path, {
            "taxonomy_sha256": "0" * 64,
            "tools_called": ["factory.junie_taxonomy"],
            "evidence_paths": [],
            "changed_paths": [],
            "change_rationales": {},
            "contribution": "Mapped the change to local review facts.",
            "unknowns": [],
        })
    assert mismatch.value.marker == "JUNIE_CONTRIBUTION_TAXONOMY_MISMATCH"


def test_project_pack_requires_confirmation_is_idempotent_and_preserves_owned_files(tmp_path: Path) -> None:
    with pytest.raises(JunieTaxonomyError, match="confirmation") as confirmation:
        install_junie_factoryline_pack(tmp_path, "yes")
    assert confirmation.value.marker == "JUNIE_PACK_CONFIRMATION_REQUIRED"

    installed = install_junie_factoryline_pack(tmp_path, PACK_CONFIRMATION)
    repeated = install_junie_factoryline_pack(tmp_path, PACK_CONFIRMATION)
    guidance = (tmp_path / ".junie/AGENTS.md").read_text(encoding="utf-8")
    config = json.loads((tmp_path / ".junie/mcp/mcp.json").read_text(encoding="utf-8"))
    assert installed["marker"] == "JUNIE_FACTORYLINE_PACK_INSTALLED"
    assert installed["state"] == "installed"
    assert repeated["state"] == "already_current"
    assert config["mcpServers"]["code-factory"]["command"] == "factory"
    assert "factory.junie_taxonomy" in guidance
    assert "factory.junie_contribution" in guidance
    assert "Do not create or alter those facts" in guidance
    assert all(value is False for value in installed["authority"].values())

    (tmp_path / ".junie/AGENTS.md").write_text("team-owned guidance\n", encoding="utf-8")
    with pytest.raises(JunieTaxonomyError, match="no overwrite") as guidance_conflict:
        install_junie_factoryline_pack(tmp_path, PACK_CONFIRMATION)
    assert guidance_conflict.value.marker == "JUNIE_PACK_CONFLICT"
    assert (tmp_path / ".junie/AGENTS.md").read_text(encoding="utf-8") == "team-owned guidance\n"


def test_project_pack_rejects_conflicting_mcp_before_creating_guidance(tmp_path: Path) -> None:
    target = tmp_path / ".junie/mcp/mcp.json"
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps({"mcpServers": {"code-factory": {"command": "other", "args": []}}}), encoding="utf-8")

    with pytest.raises(JunieTaxonomyError, match="no overwrite"):
        install_junie_factoryline_pack(tmp_path, PACK_CONFIRMATION)
    assert not (tmp_path / ".junie/AGENTS.md").exists()


def test_cli_exposes_taxonomy_and_only_installs_after_the_exact_phrase(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["junie", "taxonomy", "--root", str(tmp_path), "--json"]) == 0
    taxonomy = json.loads(capsys.readouterr().out)
    assert taxonomy["marker"] == "JUNIE_FACTORYLINE_TAXONOMY_READY"

    assert main(["junie", "install", "--root", str(tmp_path), "--confirmation", PACK_CONFIRMATION, "--json"]) == 0
    installed = json.loads(capsys.readouterr().out)
    assert installed["targets"]["guidance"]["path"] == ".junie/AGENTS.md"
    assert installed["targets"]["mcp"]["path"] == ".junie/mcp/mcp.json"

    evidence = tmp_path / "receipt.json"
    evidence.write_text("{}\n", encoding="utf-8")
    declaration = tmp_path / "contribution.json"
    declaration.write_text(json.dumps({
        "taxonomy_sha256": taxonomy["taxonomy_sha256"],
        "tools_called": ["factory.junie_taxonomy"],
        "evidence_paths": ["receipt.json"],
        "changed_paths": [],
        "change_rationales": {},
        "contribution": "Made the FactoryLine route and a local receipt inspectable.",
        "unknowns": [],
    }), encoding="utf-8")
    assert main(["junie", "contribution", "--root", str(tmp_path), "--declaration", "contribution.json", "--json"]) == 0
    contribution = json.loads(capsys.readouterr().out)
    assert contribution["marker"] == "JUNIE_FACTORYLINE_CONTRIBUTION_DECLARED"

    outside = tmp_path.parent / "outside-contribution.json"
    outside.write_text("{}", encoding="utf-8")
    assert main(["junie", "contribution", "--root", str(tmp_path), "--declaration", str(outside), "--json"]) == 2
    assert "JUNIE_CONTRIBUTION_PATH_REJECTED" in capsys.readouterr().err
