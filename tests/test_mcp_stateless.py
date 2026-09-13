from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.mcp import McpError, dispatch_stateless


def _files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _request_digest(request: object) -> str:
    canonical = json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode("utf-8")).hexdigest()


def test_one_shot_request_is_hash_bound_and_does_not_mutate_workspace(tmp_path: Path):
    request = {"jsonrpc": "2.0", "id": "r1", "method": "tools/list", "params": {}}
    before = _files(tmp_path)

    first = dispatch_stateless(request, tmp_path)
    second = dispatch_stateless(request, tmp_path)

    assert first == second
    assert first["schema"] == "factory.mcp.stateless-response.v1"
    assert first["marker"] == "MCP_STATELESS_RESPONSE"
    assert first["request_sha256"] == _request_digest(request)
    assert first["state"] == "stateless"
    assert first["server_state"] == "none"
    assert first["response"]["result"]["marker"] == "FACTORY_MCP_TOOL_INVENTORY"
    assert all(value is False for value in first["authority"].values())
    assert _files(tmp_path) == before


@pytest.mark.parametrize(
    "payload",
    [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "sessionId": "abc"},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "state": {"cursor": "x"}},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "cursor": "x"},
    ],
)
def test_stateful_extensions_are_rejected(tmp_path: Path, payload: dict[str, object]):
    with pytest.raises(McpError) as error:
        dispatch_stateless(payload, tmp_path)
    assert error.value.marker == "MCP_STATELESS_STATE_REJECTED"


def test_oversized_request_is_rejected_before_dispatch(tmp_path: Path):
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {"padding": "x" * 70_000},
    }
    with pytest.raises(McpError) as error:
        dispatch_stateless(request, tmp_path)
    assert error.value.marker == "MCP_STATELESS_REQUEST_TOO_LARGE"


def test_non_object_request_and_non_string_keys_are_rejected(tmp_path: Path):
    with pytest.raises(McpError) as not_object:
        dispatch_stateless(["not", "an", "object"], tmp_path)
    assert not_object.value.marker == "MCP_STATELESS_REQUEST_INVALID"
    with pytest.raises(McpError) as non_string:
        dispatch_stateless({1: "non-string key"}, tmp_path)
    assert non_string.value.marker == "MCP_STATELESS_REQUEST_INVALID"


def test_notification_returns_null_response_inside_stateless_envelope(tmp_path: Path):
    payload = dispatch_stateless(
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        tmp_path,
    )
    assert payload["response"] is None
    assert payload["state"] == "stateless"


def test_cli_request_reads_relative_json_without_writing(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    request = {"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}}
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(request), encoding="utf-8")
    before = _files(tmp_path)

    assert main(["mcp", "request", "request.json", "--root", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["marker"] == "MCP_STATELESS_RESPONSE"
    assert payload["request_sha256"] == _request_digest(request)
    assert payload["server_state"] == "none"
    assert _files(tmp_path) == before


@pytest.mark.parametrize("request_path", ["..\\request.json", "C:\\outside\\request.json"])
def test_cli_rejects_parent_or_absolute_request_paths(
    tmp_path: Path, request_path: str, capsys: pytest.CaptureFixture[str]
):
    assert main(["mcp", "request", request_path, "--root", str(tmp_path), "--json"]) == 2
    assert "MCP_STATELESS_REQUEST_PATH_REJECTED" in capsys.readouterr().err
