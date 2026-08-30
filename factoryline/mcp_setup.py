"""Deterministic local MCP configuration with explicit project-write consent."""
from __future__ import annotations

from hashlib import sha256
import json
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
_CLIENTS = ("generic", "cursor", "opencode", "codex", "junie", "copilot")


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


def _copilot_agent(root: Path) -> str:
    args = json.dumps(_command(root)[1:], ensure_ascii=False)
    return f'''---
name: FactoryLine Proof
description: Implement one sealed mission, then return evidence for independent FactoryLine review.
target: github-copilot
tools: ["read", "edit", "search", "code-factory/*"]
mcp-servers:
  code-factory:
    type: local
    command: factory
    args: {args}
    tools: ["*"]
---

Preserve the FactoryLine proof contract. Ask `code-factory/factory.agent_proof_mission`
for the sealed scope before editing. Do not expand scope or weaken a failing test merely
to get green. Return exact changed paths, tests, analyzer SARIF path and provider, failures,
and unknowns. Never claim approval, merge, deployment, or production readiness; FactoryLine
and the human reviewer make that decision from independently supplied evidence.
'''


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
    if normalized in {"generic", "cursor", "junie"}:
        payload["config"] = _json_config(workspace)
        payload["target"] = "any stdio MCP client" if normalized == "generic" else ".cursor/mcp.json" if normalized == "cursor" else ".junie/mcp/mcp.json"
    elif normalized == "opencode":
        payload["config"] = _opencode_config(workspace)
        payload["target"] = "opencode.json or .opencode/opencode.json"
    elif normalized == "codex":
        payload["command_line"] = "codex mcp add code-factory -- " + " ".join(command)
        payload["target"] = "Codex global MCP configuration"
    else:
        payload["agent_profile"] = _copilot_agent(workspace)
        payload["target"] = ".github/agents/factoryline-proof.agent.md"
    return payload


def install_project_mcp_config(root: Path | str, client: str, confirmation: str) -> dict[str, object]:
    """Merge one secret-free project MCP entry after exact human confirmation."""
    workspace = _workspace(root)
    normalized = client.strip().lower() if isinstance(client, str) else ""
    if normalized not in {"junie", "copilot"}:
        raise McpSetupError("project installation supports only Junie or Copilot", "MCP_CLIENT_REJECTED")
    expected_confirmation = f"INSTALL {normalized.title()} MCP"
    if confirmation != expected_confirmation:
        raise McpSetupError(f"confirmation must equal {expected_confirmation}", "MCP_SETUP_CONFIRMATION_REQUIRED")
    if normalized == "copilot":
        target = workspace / ".github/agents/factoryline-proof.agent.md"
        encoded = _copilot_agent(workspace).encode("utf-8")
        if target.exists() and target.read_bytes() != encoded:
            raise McpSetupError("existing FactoryLine Copilot agent differs; no overwrite was performed", "MCP_SETUP_CONFLICT")
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(f".{target.name}.tmp")
            temporary.write_bytes(encoded)
            temporary.replace(target)
            state = "installed"
        else:
            state = "already_current"
        return {
            "schema": "factory.mcp.install.v1", "marker": "FACTORY_COPILOT_MCP_INSTALLED", "state": state,
            "client": "copilot", "target": target.relative_to(workspace).as_posix(), "file_sha256": sha256(encoded).hexdigest(),
            "connection": {"command": "factory", "args": _command(workspace)[1:]},
            "authority": {"agent_start": False, "credential": False, "network": False, "approval": False},
            "next_action": "Open Copilot Chat in JetBrains, choose Configure Agents, select the workspace FactoryLine Proof agent, and review its MCP tools before use.",
        }
    target = workspace / ".junie/mcp/mcp.json"
    expected = _json_config(workspace)["mcpServers"]["code-factory"]
    current: dict[str, object] = {}
    if target.exists():
        try:
            loaded = json.loads(target.read_text(encoding="utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise McpSetupError("existing Junie MCP config is not valid UTF-8 JSON", "MCP_SETUP_CONFLICT") from exc
        if not isinstance(loaded, dict) or set(loaded) - {"mcpServers"} or not isinstance(loaded.get("mcpServers", {}), dict):
            raise McpSetupError("existing Junie MCP config has an unsupported shape; copy the rendered entry manually", "MCP_SETUP_CONFLICT")
        current = loaded
    servers = dict(current.get("mcpServers", {}))
    existing = servers.get("code-factory")
    if existing is not None and existing != expected:
        raise McpSetupError("existing code-factory MCP entry differs; no overwrite was performed", "MCP_SETUP_CONFLICT")
    servers["code-factory"] = expected
    result = {"mcpServers": servers}
    encoded = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    if not target.exists() or target.read_bytes() != encoded:
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.tmp")
        temporary.write_bytes(encoded)
        temporary.replace(target)
        state = "installed"
    else:
        state = "already_current"
    return {
        "schema": "factory.mcp.install.v1", "marker": "FACTORY_JUNIE_MCP_INSTALLED", "state": state,
        "client": "junie", "target": target.relative_to(workspace).as_posix(), "file_sha256": sha256(encoded).hexdigest(),
        "connection": {"command": "factory", "args": _command(workspace)[1:]},
        "authority": {"agent_start": False, "credential": False, "network": False, "approval": False},
        "next_action": "Enable custom MCP servers in JetBrains AI Assistant, confirm code-factory is active, then ask Junie for factory.agent_proof_mission.",
    }
