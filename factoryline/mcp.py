"""Local stdio-only MCP adapter over deterministic Graph Ops facts."""
from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any, TextIO

from . import __version__
from .graph_ops import graph_ops_impact, graph_ops_snapshot


MCP_PROTOCOL_VERSION = "2025-03-26"
MCP_STATUS_SCHEMA = "factory.mcp.status.v1"
MCP_SERVER_NAME = "code-factory"
_AUTHORITY = {
    "execution": False,
    "approval": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


class McpError(ValueError):
    """A stable error raised for an invalid local MCP request."""

    def __init__(self, message: str, marker: str = "MCP_INVALID_PARAMS_REJECTED"):
        super().__init__(message)
        self.marker = marker


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _workspace_root(root: Path | str) -> Path:
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise McpError("workspace root must be an existing directory")
    return workspace


def _tool_definitions() -> list[dict[str, object]]:
    no_args = {"type": "object", "properties": {}, "additionalProperties": False}
    return [
        {
            "name": "factory.status",
            "description": "Read the local Code Factory MCP boundary and authority status.",
            "inputSchema": no_args,
        },
        {
            "name": "factory.graph_ops",
            "description": "Read the deterministic local Graph Ops snapshot without executing work.",
            "inputSchema": no_args,
        },
        {
            "name": "factory.graph_impact",
            "description": "Map explicit root-relative changed paths to bound proof impact without executing work.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "changed_paths": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 50,
                        "items": {"type": "string", "minLength": 1, "maxLength": 512},
                    },
                },
                "required": ["changed_paths"],
                "additionalProperties": False,
            },
        },
        {
            "name": "factory.next_action",
            "description": "Read the one fact-derived Graph Ops recommendation without executing it.",
            "inputSchema": no_args,
        },
    ]


def mcp_status(root: Path | str) -> dict[str, object]:
    """Return the explicit boundary for the local MCP adapter."""
    workspace = _workspace_root(root)
    return {
        "schema": MCP_STATUS_SCHEMA,
        "marker": "FACTORY_MCP_LOCAL_READ_ONLY",
        "markers": ["FACTORY_MCP_LOCAL_READ_ONLY", "MCP_STDLIB_ONLY"],
        "transport": "stdio",
        "workspace_root": str(workspace),
        "server": {"name": MCP_SERVER_NAME, "version": __version__, "protocol_version": MCP_PROTOCOL_VERSION},
        "authority": dict(_AUTHORITY),
        "tools": [tool["name"] for tool in _tool_definitions()],
        "resources": ["factory://status", "factory://graph"],
    }


def _error(request_id: object, code: int, message: str, marker: str) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message, "data": {"marker": marker}},
    }


def _result(request_id: object, result: dict[str, object]) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _content(payload: object) -> dict[str, object]:
    return {"content": [{"type": "text", "text": _canonical(payload)}]}


def _changed_paths(arguments: object) -> list[str]:
    if not isinstance(arguments, dict) or set(arguments) != {"changed_paths"}:
        raise McpError("factory.graph_impact requires only changed_paths")
    value = arguments["changed_paths"]
    if not isinstance(value, list) or not 1 <= len(value) <= 50:
        raise McpError("changed_paths must contain 1 to 50 paths")
    paths: list[str] = []
    for entry in value:
        if not isinstance(entry, str) or not 1 <= len(entry) <= 512:
            raise McpError("each changed path must contain 1 to 512 characters")
        candidate = Path(entry)
        if candidate.is_absolute() or ".." in candidate.parts or entry.strip() != entry:
            raise McpError("each changed path must be root-relative without parent traversal")
        paths.append(candidate.as_posix())
    return paths


def _tool_call(root: Path, params: object) -> dict[str, object]:
    if not isinstance(params, dict) or set(params) - {"name", "arguments"}:
        raise McpError("tools/call requires name and optional arguments")
    name = params.get("name")
    arguments = params.get("arguments", {})
    if not isinstance(name, str):
        raise McpError("tools/call name must be a string")
    if name == "factory.status":
        if arguments != {}:
            raise McpError("factory.status accepts no arguments")
        return _content(mcp_status(root))
    if name == "factory.graph_ops":
        if arguments != {}:
            raise McpError("factory.graph_ops accepts no arguments")
        return _content({"marker": "MCP_GRAPH_OPS_PARITY", "graph": graph_ops_snapshot(root)})
    if name == "factory.graph_impact":
        return _content({
            "marker": "MCP_GRAPH_IMPACT_PARITY",
            "impact": graph_ops_impact(root, _changed_paths(arguments)),
        })
    if name == "factory.next_action":
        if arguments != {}:
            raise McpError("factory.next_action accepts no arguments")
        graph = graph_ops_snapshot(root)
        return _content({
            "marker": "MCP_GRAPH_OPS_PARITY",
            "graph_sha256": graph["graph_sha256"],
            "recommendation": graph["recommendation"],
            "authority": graph["authority"],
        })
    raise McpError("unknown MCP tool")


def _resource_read(root: Path, params: object) -> dict[str, object]:
    if not isinstance(params, dict) or set(params) != {"uri"} or not isinstance(params.get("uri"), str):
        raise McpError("resources/read requires only a URI")
    uri = params["uri"]
    if uri == "factory://status":
        payload = mcp_status(root)
    elif uri == "factory://graph":
        payload = graph_ops_snapshot(root)
    else:
        raise McpError("unknown MCP resource")
    return {
        "marker": "MCP_RESOURCES_PARITY",
        "contents": [{"uri": uri, "mimeType": "application/json", "text": _canonical(payload)}],
    }


def _require_no_params(params: object, method: str) -> None:
    if params != {}:
        raise McpError(f"{method} accepts no params")


def _initialize(_root: Path, params: object) -> dict[str, object]:
    if not isinstance(params, dict):
        raise McpError("initialize params must be an object")
    return {
        "marker": "MCP_INITIALIZED",
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "serverInfo": {"name": MCP_SERVER_NAME, "version": __version__},
        "capabilities": {"tools": {}, "resources": {}},
    }


def _tools_list(_root: Path, params: object) -> dict[str, object]:
    _require_no_params(params, "tools/list")
    return {"marker": "FACTORY_MCP_TOOL_INVENTORY", "tools": _tool_definitions()}


def _tools_call(root: Path, params: object) -> dict[str, object]:
    return _tool_call(root, params)


def _resources_list(_root: Path, params: object) -> dict[str, object]:
    _require_no_params(params, "resources/list")
    return {
        "marker": "MCP_RESOURCES_PARITY",
        "resources": [
            {"uri": "factory://status", "name": "Factory MCP status", "mimeType": "application/json"},
            {"uri": "factory://graph", "name": "Factory Graph Ops", "mimeType": "application/json"},
        ],
    }


def _resources_read(root: Path, params: object) -> dict[str, object]:
    return _resource_read(root, params)


def _method_result(root: Path, method: str, params: object) -> dict[str, object]:
    handlers = {
        "initialize": _initialize,
        "tools/list": _tools_list,
        "tools/call": _tools_call,
        "resources/list": _resources_list,
        "resources/read": _resources_read,
    }
    handler = handlers.get(method)
    if handler is None:
        raise LookupError(method)
    return handler(root, params)


def _request_context(request: object) -> tuple[object, bool, str, object] | None:
    if not isinstance(request, dict):
        return None
    if request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
        return None
    return request.get("id"), "id" not in request, request["method"], request.get("params", {})


def _error_or_notification(is_notification: bool, request_id: object, code: int,
                           message: str, marker: str) -> dict[str, object] | None:
    if is_notification:
        return None
    return _error(request_id, code, message, marker)


def _result_or_notification(is_notification: bool, request_id: object,
                            result: dict[str, object]) -> dict[str, object] | None:
    if is_notification:
        return None
    return _result(request_id, result)


def dispatch(request: object, root: Path | str) -> dict[str, object] | None:
    """Dispatch one MCP JSON-RPC object without mutating the workspace."""
    context = _request_context(request)
    if context is None:
        request_id = request.get("id") if isinstance(request, dict) else None
        return _error(request_id, -32602, "invalid JSON-RPC request", "MCP_INVALID_PARAMS_REJECTED")
    request_id, is_notification, method, params = context
    if method == "notifications/initialized":
        return None
    try:
        response = _method_result(_workspace_root(root), method, params)
    except LookupError:
        return _error_or_notification(is_notification, request_id, -32601, "method not found", "MCP_UNKNOWN_METHOD_REJECTED")
    except McpError as exc:
        return _error_or_notification(is_notification, request_id, -32602, str(exc), exc.marker)
    return _result_or_notification(is_notification, request_id, response)


def serve_stdio(root: Path | str, *, input_stream: TextIO | None = None, output_stream: TextIO | None = None) -> int:
    """Serve newline-delimited JSON-RPC requests over stdio and return 0 at EOF."""
    _workspace_root(root)
    input_stream = input_stream or sys.stdin
    output_stream = output_stream or sys.stdout
    for raw in input_stream:
        try:
            request = json.loads(raw)
        except json.JSONDecodeError:
            response = _error(None, -32602, "invalid JSON-RPC request", "MCP_INVALID_PARAMS_REJECTED")
        else:
            response = dispatch(request, root)
        if response is not None:
            output_stream.write(_canonical(response) + "\n")
            output_stream.flush()
    return 0
