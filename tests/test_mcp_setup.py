from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.mcp_setup import McpSetupError, install_project_mcp_config, mcp_connection_config


def test_mcp_setup_renders_copy_only_configs_for_supported_clients(tmp_path: Path):
    generic = mcp_connection_config(tmp_path)
    cursor = mcp_connection_config(tmp_path, "cursor")
    opencode = mcp_connection_config(tmp_path, "opencode")
    codex = mcp_connection_config(tmp_path, "codex")
    junie = mcp_connection_config(tmp_path, "junie")
    copilot = mcp_connection_config(tmp_path, "copilot")

    for payload in (generic, cursor, opencode, codex, junie, copilot):
        assert payload["schema"] == "factory.mcp.setup.v1"
        assert payload["marker"] == "FACTORY_MCP_CONFIG_READY"
        assert payload["markers"] == [
            "FACTORY_MCP_CONFIG_READY",
            "MCP_CLIENT_RENDERED",
            "MCP_COMMAND_BOUND",
            "MCP_COPY_ONLY",
            "MCP_CLIENT_CONFIG_COPYABLE",
        ]
        assert payload["transport"] == "stdio"
        assert payload["writes"] is False
        assert all(value is False for value in payload["authority"].values())
        assert payload["connection"] == {
            "command": "factory",
            "args": ["mcp", "serve", "--root", str(tmp_path.resolve())],
        }

    assert generic["target"] == "any stdio MCP client"
    assert cursor["target"] == ".cursor/mcp.json"
    assert opencode["config"]["mcp"]["code-factory"]["enabled"] is True
    assert codex["command_line"] == f"codex mcp add code-factory -- factory mcp serve --root {tmp_path.resolve()}"
    assert junie["target"] == ".junie/mcp/mcp.json"
    assert copilot["target"] == ".github/agents/factoryline-proof.agent.md"
    assert "mcp-servers:" in copilot["agent_profile"]
    assert "code-factory/factory.agent_proof_mission" in copilot["agent_profile"]


def test_junie_project_install_is_confirmed_idempotent_and_never_overwrites_a_conflict(tmp_path: Path):
    with pytest.raises(McpSetupError, match="confirmation"):
        install_project_mcp_config(tmp_path, "junie", "yes")
    installed = install_project_mcp_config(tmp_path, "junie", "INSTALL Junie MCP")
    repeated = install_project_mcp_config(tmp_path, "junie", "INSTALL Junie MCP")
    config = json.loads((tmp_path / ".junie/mcp/mcp.json").read_text(encoding="utf-8"))
    assert installed["state"] == "installed"
    assert repeated["state"] == "already_current"
    assert config["mcpServers"]["code-factory"]["command"] == "factory"
    assert all(value is False for value in installed["authority"].values())

    config["mcpServers"]["code-factory"]["command"] = "other"
    (tmp_path / ".junie/mcp/mcp.json").write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(McpSetupError, match="no overwrite"):
        install_project_mcp_config(tmp_path, "junie", "INSTALL Junie MCP")


def test_copilot_project_install_is_confirmed_idempotent_and_never_overwrites_a_conflict(tmp_path: Path):
    with pytest.raises(McpSetupError, match="confirmation"):
        install_project_mcp_config(tmp_path, "copilot", "yes")
    installed = install_project_mcp_config(tmp_path, "copilot", "INSTALL Copilot MCP")
    repeated = install_project_mcp_config(tmp_path, "copilot", "INSTALL Copilot MCP")
    profile = (tmp_path / ".github/agents/factoryline-proof.agent.md").read_text(encoding="utf-8")
    assert installed["marker"] == "FACTORY_COPILOT_MCP_INSTALLED"
    assert installed["state"] == "installed"
    assert repeated["state"] == "already_current"
    assert "target: github-copilot" in profile
    assert "command: factory" in profile
    assert "approval" in profile
    assert all(value is False for value in installed["authority"].values())

    (tmp_path / ".github/agents/factoryline-proof.agent.md").write_text("owner content\n", encoding="utf-8")
    with pytest.raises(McpSetupError, match="no overwrite"):
        install_project_mcp_config(tmp_path, "copilot", "INSTALL Copilot MCP")


def test_mcp_setup_rejects_unknown_clients_and_missing_roots(tmp_path: Path):
    with pytest.raises(McpSetupError, match="client must be one of") as client_error:
        mcp_connection_config(tmp_path, "unsafe-hosted")
    assert client_error.value.marker == "MCP_CLIENT_REJECTED"
    with pytest.raises(McpSetupError, match="existing directory") as root_error:
        mcp_connection_config(tmp_path / "missing")
    assert root_error.value.marker == "MCP_ROOT_REJECTED"


def test_mcp_config_cli_prints_a_copy_only_codex_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    assert main(["mcp", "config", "--client", "codex", "--root", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "Factory MCP config (codex)" in output
    assert f"codex mcp add code-factory -- factory mcp serve --root {tmp_path.resolve()}" in output
    assert "read-only local context" in output


def test_mcp_install_cli_writes_only_the_confirmed_junie_project_entry(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    assert main(["mcp", "install", "--client", "junie", "--root", str(tmp_path), "--confirmation", "INSTALL Junie MCP", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["marker"] == "FACTORY_JUNIE_MCP_INSTALLED"
    assert result["target"] == ".junie/mcp/mcp.json"


def test_mcp_install_cli_writes_only_the_confirmed_copilot_agent(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    assert main(["mcp", "install", "--client", "copilot", "--root", str(tmp_path), "--confirmation", "INSTALL Copilot MCP", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["marker"] == "FACTORY_COPILOT_MCP_INSTALLED"
    assert result["target"] == ".github/agents/factoryline-proof.agent.md"
