from __future__ import annotations

from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.mcp_setup import McpSetupError, mcp_connection_config


def test_mcp_setup_renders_copy_only_configs_for_supported_clients(tmp_path: Path):
    generic = mcp_connection_config(tmp_path)
    cursor = mcp_connection_config(tmp_path, "cursor")
    opencode = mcp_connection_config(tmp_path, "opencode")
    codex = mcp_connection_config(tmp_path, "codex")

    for payload in (generic, cursor, opencode, codex):
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
