"""Deterministic, copy-only configuration for the local Code Factory MCP server."""
from __future__ import annotations

from pathlib import Path


MCP_SETUP_SCHEMA = "factory.mcp.setup.v1"
MCP_SETUP_MARKER = "FACTORY_MCP_CONFIG_READY"
MCP_SETUP_MARKERS = (
    MCP_SETUP_MARKER,
    "MCP_CLIENT_RENDERED",
    "MCP_COMMAND_BOUND",
    "MCP_COPY_ONLY",
    "MCP_CLIENT_CONFIG_COPYABLE",
)
_CLIENTS = ("generic", "cursor", "opencode", "codex")


class McpSetupError(ValueError):
    """Raised when a local MCP connection snippet cannot be rendered safely."""

    def __init__(self, message: str, marker: str = "MCP_SETUP_INPUT_REJECTED"):
        super().__init__(message)
        self.marker = marker


def _workspace(root: Path | str) -> Path:
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise McpSetupError("workspace root must be an existing directory", "MCP_ROOT_REJECTED")
    return workspace


def _command(root: Path) -> list[str]:
    return ["factory", "mcp", "serve", "--root", str(root)]


def _json_config(root: Path) -> dict[str, object]:
    return {"mcpServers": {"code-factory": {"command": "factory", "args": _command(root)[1:]}}}


def _opencode_config(root: Path) -> dict[str, object]:
    return {
        "$schema": "https://opencode.ai/config.json",
        "mcp": {
            "code-factory": {
                "type": "local",
                "command": _command(root),
                "enabled": True,
                "timeout": 5000,
            }
        },
    }


def mcp_connection_config(root: Path | str, client: str = "generic") -> dict[str, object]:
    """Return one copy-only MCP configuration without touching a client or workspace."""
    workspace = _workspace(root)
    normalized = client.strip().lower().replace("-", "_") if isinstance(client, str) else ""
    if normalized not in _CLIENTS:
        raise McpSetupError(f"client must be one of: {', '.join(_CLIENTS)}", "MCP_CLIENT_REJECTED")

    command = _command(workspace)
    payload: dict[str, object] = {
        "schema": MCP_SETUP_SCHEMA,
        "marker": MCP_SETUP_MARKER,
        "markers": list(MCP_SETUP_MARKERS),
        "client": normalized,
        "workspace_root": str(workspace),
        "transport": "stdio",
        "connection": {"command": command[0], "args": command[1:]},
        "authority": {
            "execution": False,
            "approval": False,
            "publication": False,
            "deployment": False,
            "signing": False,
            "messaging": False,
            "credential": False,
            "connector": False,
        },
        "writes": False,
        "next_action": "Copy the rendered configuration into the named client, then approve its local MCP server under that client's own controls.",
    }
    if normalized in {"generic", "cursor"}:
        payload["config"] = _json_config(workspace)
        payload["target"] = "any stdio MCP client" if normalized == "generic" else ".cursor/mcp.json"
    elif normalized == "opencode":
        payload["config"] = _opencode_config(workspace)
        payload["target"] = "opencode.json or .opencode/opencode.json"
    else:
        payload["command_line"] = "codex mcp add code-factory -- " + " ".join(command)
        payload["target"] = "Codex global MCP configuration"
    return payload
