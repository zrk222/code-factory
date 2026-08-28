from __future__ import annotations

import json
from pathlib import Path

from factoryline import __version__


ROOT = Path(__file__).parents[1]
PLUGIN = ROOT / "plugins" / "code-factory-langgraph"


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_cross_tool_plugin_manifests_are_aligned_and_version_bound() -> None:
    codex = _json(PLUGIN / ".codex-plugin" / "plugin.json")
    claude = _json(PLUGIN / ".claude-plugin" / "plugin.json")

    assert codex == claude
    assert codex["name"] == "code-factory-langgraph"
    assert codex["version"] == __version__
    assert "resume-parity" in str(codex["description"])


def test_local_mcp_configuration_starts_only_the_read_only_factory_server() -> None:
    payload = _json(PLUGIN / ".mcp.json")
    servers = payload["mcpServers"]
    assert isinstance(servers, dict)
    server = servers["code-factory-langgraph"]
    assert server == {"command": "factory", "args": ["mcp", "serve", "--root", "."]}


def test_plugin_skill_and_workflow_keep_execution_and_release_authority_human_controlled() -> None:
    skill = (PLUGIN / "skills" / "langgraph-proof" / "SKILL.md").read_text(encoding="utf-8")
    workflow = (PLUGIN / "assets" / "github-actions" / "langgraph-proof.yml").read_text(encoding="utf-8")

    assert "factory langgraph replay-verify" in skill
    assert "factory.langgraph_assurance" in skill
    assert "factoryline-code-factory-v044" in skill
    assert "cannot invoke a graph" in skill
    assert "Do not authorize or execute repairs" in skill
    assert "pull_request_target" not in workflow
    assert "contents: read" in workflow
    assert f"zrk222/code-factory@v{__version__}" in workflow
    assert "write" not in workflow


def test_marketplace_entry_and_docs_expose_all_supported_coding_agent_installs() -> None:
    marketplace = _json(ROOT / ".claude-plugin" / "marketplace.json")
    plugins = marketplace["plugins"]
    assert isinstance(plugins, list)
    assert plugins[0] == {
        "name": "code-factory-langgraph",
        "source": "./plugins/code-factory-langgraph",
        "description": "Proof-aware LangGraph guidance and read-only resume-parity receipts before review.",
        "author": {"name": "Richard Katz", "email": "rkatz22@gmail.com"},
    }
    assert plugins[1]["name"] == "code-factory-session-recorder"
    assert plugins[1]["source"] == "./plugins/code-factory-session-recorder"

    docs = (ROOT / "docs" / "LANGCHAIN_MARKETPLACE.md").read_text(encoding="utf-8")
    assert "codex plugin add code-factory-langgraph@code-factory" in docs
    assert "/plugin install code-factory-langgraph@code-factory" in docs
    assert "dcode plugin install code-factory-langgraph@code-factory" in docs
    assert "factoryline-code-factory>=0.44.0" in docs
    assert "accepts only official\nLangChain skills and MCPs" in docs
    assert "does not imply LangChain endorsement" in docs
    assert "while that review is pending" not in docs
    assert "separate upstream-review process" not in docs


def test_plugin_smoke_tracks_the_package_version_instead_of_a_stale_literal() -> None:
    smoke = _json(ROOT / "smoke" / "langgraph-marketplace-plugin.json")
    checks = smoke["checks"]
    assert isinstance(checks, list)
    command = checks[0]["run"]
    assert isinstance(command, str)
    assert "from factoryline import __version__" in command
    assert "codex['version'] == __version__" in command
    assert "0.39.0" not in command


def test_refresh_smoke_reuses_the_version_bound_plugin_contract() -> None:
    smoke = _json(ROOT / "smoke" / "langgraph-marketplace-plugin-v044-refresh.json")
    checks = smoke["checks"]
    assert isinstance(checks, list)
    command = checks[0]["run"]
    assert isinstance(command, str)
    assert "langgraph-marketplace-plugin.json" in command
