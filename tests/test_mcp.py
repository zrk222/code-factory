from __future__ import annotations

from io import StringIO
import json
from pathlib import Path

from factoryline.graph_ops import graph_ops_impact, graph_ops_snapshot
from factoryline.langgraph_assurance import LangGraphTransitionRecorder
from factoryline.mcp import MCP_PROTOCOL_VERSION, dispatch, mcp_status, serve_stdio


def _content(response: dict[str, object]) -> dict[str, object]:
    result = response["result"]
    assert isinstance(result, dict)
    content = result["content"]
    assert isinstance(content, list)
    return json.loads(content[0]["text"])


def _files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def test_mcp_status_declares_a_stdio_only_zero_authority_boundary(tmp_path: Path):
    status = mcp_status(tmp_path)

    assert status["schema"] == "factory.mcp.status.v1"
    assert status["marker"] == "FACTORY_MCP_LOCAL_READ_ONLY"
    assert status["markers"] == ["FACTORY_MCP_LOCAL_READ_ONLY", "MCP_STDLIB_ONLY"]
    assert status["transport"] == "stdio"
    assert status["workspace_root"] == str(tmp_path.resolve())
    assert status["tools"] == [
        "factory.status",
        "factory.graph_ops",
        "factory.graph_impact",
        "factory.developer_memory",
        "factory.langgraph_assurance",
        "factory.next_action",
        "factory.list_receipts",
        "factory.get_receipt",
        "factory.verifier_status",
        "factory.proof_reuse",
        "factory.proof_delta_status",
        "factory.cdte_status",
        "factory.prd_grill_status",
        "factory.intake_status",
        "factory.gauntlet_status",
        "factory.agent_license_status",
        "factory.combine_status",
        "factory.workspace_advisor",
    ]
    assert status["resources"] == ["factory://status", "factory://graph"]
    assert all(value is False for value in status["authority"].values())


def test_mcp_protocol_parity_is_read_only(tmp_path: Path):
    before = _files(tmp_path)
    initialized = dispatch({
        "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": MCP_PROTOCOL_VERSION},
    }, tmp_path)
    assert initialized == {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "marker": "MCP_INITIALIZED",
            "protocolVersion": MCP_PROTOCOL_VERSION,
                "serverInfo": {"name": "code-factory", "version": "0.40.2"},
            "capabilities": {"tools": {}, "resources": {}},
        },
    }

    inventory = dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, tmp_path)
    assert inventory["result"]["marker"] == "FACTORY_MCP_TOOL_INVENTORY"
    assert [tool["name"] for tool in inventory["result"]["tools"]] == mcp_status(tmp_path)["tools"]
    assert all(tool["annotations"] == {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    } for tool in inventory["result"]["tools"])

    graph = _content(dispatch({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "factory.graph_ops"},
    }, tmp_path))
    assert graph == {"marker": "MCP_GRAPH_OPS_PARITY", "graph": graph_ops_snapshot(tmp_path)}

    summary = _content(dispatch({
        "jsonrpc": "2.0", "id": 30, "method": "tools/call",
        "params": {"name": "factory.graph_ops", "arguments": {"format": "summary"}},
    }, tmp_path))
    assert summary["marker"] == "MCP_GRAPH_OPS_PARITY"
    assert summary["summary"]["graph_sha256"] == graph_ops_snapshot(tmp_path)["graph_sha256"]

    impact = _content(dispatch({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "factory.graph_impact", "arguments": {"changed_paths": ["input.txt"]}},
    }, tmp_path))
    assert impact == {
        "marker": "MCP_GRAPH_IMPACT_PARITY",
        "impact": graph_ops_impact(tmp_path, ["input.txt"]),
    }

    memory = _content(dispatch({
        "jsonrpc": "2.0", "id": 41, "method": "tools/call",
        "params": {"name": "factory.developer_memory", "arguments": {"changed_paths": ["input.txt"]}},
    }, tmp_path))
    assert memory["marker"] == "MCP_DEVELOPER_MEMORY_READ_ONLY"
    assert memory["brief"]["schema"] == "factory.developer-memory-brief.v1"
    assert memory["brief"]["authority"]["external_effects"] is False

    next_action = _content(dispatch({
        "jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "factory.next_action"},
    }, tmp_path))
    snapshot = graph_ops_snapshot(tmp_path)
    assert next_action == {
        "marker": "MCP_GRAPH_OPS_PARITY",
        "graph_sha256": snapshot["graph_sha256"],
        "recommendation": snapshot["recommendation"],
        "authority": snapshot["authority"],
    }

    resources = dispatch({"jsonrpc": "2.0", "id": 6, "method": "resources/list"}, tmp_path)
    assert resources["result"]["marker"] == "MCP_RESOURCES_PARITY"
    assert [item["uri"] for item in resources["result"]["resources"]] == mcp_status(tmp_path)["resources"]
    resource = dispatch({
        "jsonrpc": "2.0", "id": 7, "method": "resources/read", "params": {"uri": "factory://graph"},
    }, tmp_path)
    assert resource["result"]["marker"] == "MCP_RESOURCES_PARITY"
    assert json.loads(resource["result"]["contents"][0]["text"]) == graph_ops_snapshot(tmp_path)
    assert _files(tmp_path) == before


def test_mcp_langgraph_assurance_reads_existing_receipts_without_execution(tmp_path: Path):
    def record(run_id: str, outcome: str) -> Path:
        recorder = LangGraphTransitionRecorder("agent-graph", run_id)
        recorder.record_transition(
            "route", superstep=1, checkpoint_id="cp-1", before_state={"request": "secret"},
            after_state={"request": "secret", "outcome": outcome},
            decision={"route": outcome, "reason": "private reason"},
        )
        recorder.seal(tmp_path, f".factory/langgraph/{run_id}.json")
        return tmp_path / ".factory" / "langgraph" / f"{run_id}.json"

    reference = record("reference", "allow")
    resumed = record("resumed", "deny")
    before = _files(tmp_path)
    result = _content(dispatch({
        "jsonrpc": "2.0", "id": 88, "method": "tools/call", "params": {
            "name": "factory.langgraph_assurance",
            "arguments": {
                "reference": reference.relative_to(tmp_path).as_posix(),
                "resumed": resumed.relative_to(tmp_path).as_posix(),
            },
        },
    }, tmp_path))

    assert result["marker"] == "LANGGRAPH_MCP_READ_ONLY"
    assert result["assurance"]["verdict"] == "REVIEW_REQUIRED"
    assert all(value is False for value in result["assurance"]["authority"].values())
    assert '"secret"' not in json.dumps(result)
    assert _files(tmp_path) == before


def test_mcp_read_only_receipt_and_gate_status_tools(tmp_path: Path):
    receipt = tmp_path / "receipts" / "build.json"
    receipt.parent.mkdir()
    receipt.write_text(json.dumps({"schema": "factory.receipt.v1", "feature": "checkout", "created_at": "2026-08-08T00:00:00Z"}), encoding="utf-8")
    session = tmp_path / ".factory" / "verifier-sessions" / "checkout.session.json"
    session.parent.mkdir(parents=True)
    session.write_text(json.dumps({
        "schema": "factory.verifier-session.v1", "mission_id": "checkout", "session_sha256": "a" * 64,
        "budgets": {"max_attempts": 5, "max_wall_seconds": 3600, "max_tokens": 100000, "max_cost_usd": 25.0},
    }), encoding="utf-8")
    prd = tmp_path / "PRD.md"
    prd.write_text("# Checkout", encoding="utf-8")
    before = _files(tmp_path)

    listed = _content(dispatch({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "factory.list_receipts", "arguments": {"feature": "checkout"}},
    }, tmp_path))
    assert listed["marker"] == "MCP_RECEIPTS_UNASSESSED"
    assert listed["entries"][0]["assessment"] == "unassessed"

    loaded = _content(dispatch({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "factory.get_receipt", "arguments": {"path": "receipts/build.json"}},
    }, tmp_path))
    assert loaded["receipt"]["feature"] == "checkout"
    assert loaded["metadata"]["verification"] == "not_run"

    verifier = _content(dispatch({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "factory.verifier_status", "arguments": {"mission": "checkout"}},
    }, tmp_path))
    assert verifier["worker"]["result"] == "not_supplied"
    assert verifier["budget"]["remaining"] == "unobserved"

    reuse = _content(dispatch({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "factory.proof_reuse", "arguments": {"gate": "python-tests"}},
    }, tmp_path))
    assert reuse["disposition"] == "BLOCK"

    cdte = _content(dispatch({
        "jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "factory.cdte_status"},
    }, tmp_path))
    assert cdte["marker"] == "MCP_CDTE_SCAN_REQUIRED"

    advisor = _content(dispatch({
        "jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "factory.workspace_advisor"},
    }, tmp_path))
    assert advisor["marker"] == "MCP_WORKSPACE_ADVISOR_READ_ONLY"
    assert advisor["report"]["marker"] == "WORKSPACE_ADVISOR_LOCAL_READ_ONLY"
    assert advisor["scope"].startswith("In-memory local")
    assert _files(tmp_path) == before

    grill = _content(dispatch({
        "jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "factory.prd_grill_status", "arguments": {"prd_path": "PRD.md"}},
    }, tmp_path))
    assert grill["marker"] == "MCP_PRD_GRILL_REQUIRED"
    assert _files(tmp_path) == before

    intake = _content(dispatch({
        "jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "factory.intake_status", "arguments": {"prd_path": "PRD.md"}},
    }, tmp_path))
    assert intake["marker"] == "MCP_INTAKE_READ_ONLY"
    assert intake["status"]["marker"] == "INTAKE_CONFIRMATION_REQUIRED"
    assert _files(tmp_path) == before

    gauntlet = _content(dispatch({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "factory.gauntlet_status", "arguments": {}},
    }, tmp_path))
    assert gauntlet["marker"] == "MCP_GAUNTLET_READ_ONLY"
    assert gauntlet["status"]["entries"] == []

    licenses = _content(dispatch({
        "jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "factory.agent_license_status", "arguments": {}},
    }, tmp_path))
    assert licenses["marker"] == "MCP_AGENT_LICENSE_READ_ONLY"
    assert licenses["status"]["licenses"] == []

    combine = _content(dispatch({
        "jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "factory.combine_status", "arguments": {}},
    }, tmp_path))
    assert combine["marker"] == "MCP_COMBINE_READ_ONLY"
    assert combine["status"]["scoreboards"] == []
    assert _files(tmp_path) == before


def test_mcp_rejects_malformed_and_unsafe_requests_without_writing(tmp_path: Path):
    before = _files(tmp_path)
    requests = [
        {"id": 1, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "unknown"}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "factory.graph_impact", "arguments": {"changed_paths": ["../outside.txt"]},
        }},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "factory.graph_impact", "arguments": {"changed_paths": [str(tmp_path / "outside.txt")]},
        }},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
            "name": "factory.get_receipt", "arguments": {"path": "../outside.json"},
        }},
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {
            "name": "factory.prd_grill_status", "arguments": {"prd_path": "../outside.md"},
        }},
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {
            "name": "factory.intake_status", "arguments": {"prd_path": "../outside.md"},
        }},
    ]
    for request in requests:
        response = dispatch(request, tmp_path)
        assert response["error"]["code"] == -32602
        assert response["error"]["data"]["marker"] == "MCP_INVALID_PARAMS_REJECTED"

    unknown_method = dispatch({"jsonrpc": "2.0", "id": 7, "method": "factory/nope"}, tmp_path)
    assert unknown_method["error"]["code"] == -32601
    assert unknown_method["error"]["data"]["marker"] == "MCP_UNKNOWN_METHOD_REJECTED"
    missing_root = dispatch({"jsonrpc": "2.0", "id": 8, "method": "tools/list"}, tmp_path / "missing")
    assert missing_root["error"]["code"] == -32602
    assert missing_root["error"]["data"]["marker"] == "MCP_INVALID_PARAMS_REJECTED"
    assert _files(tmp_path) == before


def test_mcp_stdio_emits_only_newline_delimited_json_rpc(tmp_path: Path):
    incoming = StringIO(
        '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n'
        'this is not json\n'
        '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
    )
    outgoing = StringIO()

    assert serve_stdio(tmp_path, input_stream=incoming, output_stream=outgoing) == 0
    lines = outgoing.getvalue().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["result"]["marker"] == "FACTORY_MCP_TOOL_INVENTORY"
    assert json.loads(lines[1])["error"]["data"]["marker"] == "MCP_INVALID_PARAMS_REJECTED"
