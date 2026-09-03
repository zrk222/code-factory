from __future__ import annotations

from io import StringIO
import hashlib
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
        "factory.journey_status",
        "factory.graph_impact",
        "factory.developer_memory",
        "factory.intent_ledger",
        "factory.judgment_status",
        "factory.judgment_safety_case",
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
        "factory.revenue_status",
        "factory.revenue_memory",
        "factory.appforge_status",
        "factory.oracle_firewall_status",
        "factory.semantic_authority_status",
        "factory.enterprise_enforcement_status",
        "factory.atomic_status",
        "factory.operations_control_status",
        "factory.lifecycle_status",
        "factory.repair_loop_status",
        "factory.mission_control_status",
        "factory.agent_bridge_status",
        "factory.agent_handoff_brief",
        "factory.proof_worklog_status",
        "factory.codex_metadata_audit",
        "factory.appforge_oracle_status",
        "factory.appforge_device_reality_status",
        "factory.appforge_release_rehearsal_status",
        "factory.appforge_native_surface_status",
        "factory.appforge_surface_matrix_status",
        "factory.appforge_storefront_story_status",
        "factory.appforge_fastlane_capture_status",
        "factory.appforge_submission_integrity_status",
        "factory.proof_continuity_status",
        "factory.saas_status",
        "factory.agent_proof_mission",
        "factory.jetbrains_handshake",
        "factory.jetbrains_handshake_status",
    ]
    assert status["resources"] == ["factory://status", "factory://graph"]
    assert all(value is False for value in status["authority"].values())


def test_mcp_protocol_parity_is_read_only(tmp_path: Path):
    initialized = dispatch({
        "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": MCP_PROTOCOL_VERSION},
    }, tmp_path)
    assert initialized == {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "marker": "MCP_INITIALIZED",
            "protocolVersion": MCP_PROTOCOL_VERSION,
                "serverInfo": {"name": "code-factory", "version": "0.46.1"},
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

    metadata = tmp_path / "run.json"
    metadata.write_text(json.dumps({"status": "complete", "intent_id": "mission-1"}), encoding="utf-8")
    before = _files(tmp_path)
    audit = _content(dispatch({
        "jsonrpc": "2.0", "id": 31, "method": "tools/call",
        "params": {"name": "factory.codex_metadata_audit", "arguments": {"paths": ["run.json"]}},
    }, tmp_path))
    assert audit["marker"] == "MCP_CODEX_METADATA_AUDIT_READ_ONLY"
    assert audit["audit"]["status"] == "REVIEW_REQUIRED"
    assert audit["scope"].startswith("Read-only local metadata integrity")

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

    intent_ledger = _content(dispatch({
        "jsonrpc": "2.0", "id": 42, "method": "tools/call",
        "params": {"name": "factory.intent_ledger", "arguments": {
            "change_list": "Billing cancellation", "changed_paths": ["input.txt"],
        }},
    }, tmp_path))
    assert intent_ledger["marker"] == "MCP_INTENT_LEDGER_READ_ONLY"
    assert intent_ledger["ledger"]["state"] == "uncontracted"
    assert all(value is False for value in intent_ledger["ledger"]["authority"].values())

    judgment = _content(dispatch({
        "jsonrpc": "2.0", "id": 43, "method": "tools/call", "params": {"name": "factory.judgment_status"},
    }, tmp_path))
    assert judgment["marker"] == "MCP_JUDGMENT_STATUS_READ_ONLY"
    assert judgment["status"]["state"] == "empty"

    safety_case = _content(dispatch({
        "jsonrpc": "2.0", "id": 44, "method": "tools/call", "params": {"name": "factory.judgment_safety_case", "arguments": {"changed_paths": ["input.txt"]}},
    }, tmp_path))
    assert safety_case["marker"] == "MCP_JUDGMENT_SAFETY_CASE_READ_ONLY"
    assert safety_case["safety_case"]["route"] == "GREEN"
    assert all(value is False for value in safety_case["safety_case"]["authority"].values())

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


def test_mcp_revenue_appforge_saas_and_memory_tools_are_read_only(tmp_path: Path):
    before = _files(tmp_path)
    revenue = _content(dispatch({
        "jsonrpc": "2.0", "id": 80, "method": "tools/call",
        "params": {"name": "factory.revenue_status"},
    }, tmp_path))
    assert revenue["marker"] == "MCP_REVENUEFORGE_READ_ONLY"
    assert revenue["status"]["marker"] == "GRAPH_OPS_REVENUEFORGE_READ_ONLY"

    memory = _content(dispatch({
        "jsonrpc": "2.0", "id": 81, "method": "tools/call",
        "params": {"name": "factory.revenue_memory", "arguments": {"app_id": "example.app", "journey": "purchase"}},
    }, tmp_path))
    assert memory["marker"] == "MCP_REVENUEFORGE_MEMORY_READ_ONLY"
    assert memory["status"]["status"] == "empty"

    appforge = _content(dispatch({
        "jsonrpc": "2.0", "id": 82, "method": "tools/call",
        "params": {"name": "factory.appforge_status"},
    }, tmp_path))
    assert appforge["marker"] == "MCP_APPFORGE_READ_ONLY"
    assert appforge["status"]["marker"] == "APPFORGE_DESIGN_READ_ONLY"
    assert all(value is False for value in appforge["status"]["authority"].values())
    oracle = _content(dispatch({
        "jsonrpc": "2.0", "id": 821, "method": "tools/call",
        "params": {"name": "factory.oracle_firewall_status"},
    }, tmp_path))
    assert oracle["marker"] == "MCP_ORACLE_FIREWALL_READ_ONLY"
    assert oracle["status"]["marker"] == "ORACLE_FIREWALL_READ_ONLY"
    semantic = _content(dispatch({
        "jsonrpc": "2.0", "id": 8210, "method": "tools/call",
        "params": {"name": "factory.semantic_authority_status"},
    }, tmp_path))
    assert semantic["marker"] == "MCP_SEMANTIC_AUTHORITY_READ_ONLY"
    assert semantic["status"]["marker"] == "SEMANTIC_AUTHORITY_READ_ONLY"
    assert all(value is False for value in semantic["status"]["authority"].values())
    enterprise = _content(dispatch({
        "jsonrpc": "2.0", "id": 82101, "method": "tools/call",
        "params": {"name": "factory.enterprise_enforcement_status"},
    }, tmp_path))
    assert enterprise["marker"] == "MCP_ENTERPRISE_ENFORCEMENT_READ_ONLY"
    assert enterprise["status"]["marker"] == "ENTERPRISE_ENFORCEMENT_READ_ONLY"
    assert all(value is False for value in enterprise["status"]["authority"].values())
    assert enterprise["status"]["runner_admission"]["marker"] == "RUNNER_ADMISSION_READ_ONLY"
    assert all(value is False for value in enterprise["status"]["runner_admission"]["authority"].values())
    atomic = _content(dispatch({
        "jsonrpc": "2.0", "id": 8211, "method": "tools/call",
        "params": {"name": "factory.atomic_status"},
    }, tmp_path))
    assert atomic["marker"] == "ATOMIC_MCP_READ_ONLY"
    assert atomic["status"]["marker"] == "ATOMIC_MCP_READ_ONLY"
    assert all(value is False for value in atomic["status"]["authority"].values())
    appforge_oracle = _content(dispatch({
        "jsonrpc": "2.0", "id": 822, "method": "tools/call",
        "params": {"name": "factory.appforge_oracle_status"},
    }, tmp_path))
    assert appforge_oracle["marker"] == "MCP_APPFORGE_ORACLE_READ_ONLY"
    assert appforge_oracle["status"]["marker"] == "APPFORGE_ORACLE_AUTHORITY_READ_ONLY"
    device_reality = _content(dispatch({
        "jsonrpc": "2.0", "id": 8221, "method": "tools/call",
        "params": {"name": "factory.appforge_device_reality_status"},
    }, tmp_path))
    assert device_reality["marker"] == "MCP_APPFORGE_DEVICE_REALITY_READ_ONLY"
    assert device_reality["status"]["marker"] == "APPFORGE_DEVICE_REALITY_READ_ONLY"
    rehearsal = _content(dispatch({
        "jsonrpc": "2.0", "id": 8222, "method": "tools/call",
        "params": {"name": "factory.appforge_release_rehearsal_status"},
    }, tmp_path))
    assert rehearsal["marker"] == "MCP_APPFORGE_RELEASE_REHEARSAL_READ_ONLY"
    assert rehearsal["status"]["marker"] == "APPFORGE_RELEASE_REHEARSAL_READ_ONLY"
    native_surface = _content(dispatch({
        "jsonrpc": "2.0", "id": 8223, "method": "tools/call",
        "params": {"name": "factory.appforge_native_surface_status"},
    }, tmp_path))
    assert native_surface["marker"] == "MCP_APPFORGE_NATIVE_SURFACE_READ_ONLY"
    assert native_surface["status"]["marker"] == "APPFORGE_NATIVE_SURFACE_READ_ONLY"
    surface_matrix = _content(dispatch({
        "jsonrpc": "2.0", "id": 8224, "method": "tools/call",
        "params": {"name": "factory.appforge_surface_matrix_status"},
    }, tmp_path))
    assert surface_matrix["marker"] == "MCP_APPFORGE_SURFACE_MATRIX_READ_ONLY"
    assert surface_matrix["status"]["marker"] == "APPFORGE_SURFACE_MATRIX_READ_ONLY"
    storefront_story = _content(dispatch({
        "jsonrpc": "2.0", "id": 8225, "method": "tools/call",
        "params": {"name": "factory.appforge_storefront_story_status"},
    }, tmp_path))
    assert storefront_story["marker"] == "MCP_APPFORGE_STOREFRONT_STORY_READ_ONLY"
    assert storefront_story["status"]["marker"] == "APPFORGE_STOREFRONT_STORY_READ_ONLY"
    fastlane_capture = _content(dispatch({
        "jsonrpc": "2.0", "id": 8226, "method": "tools/call",
        "params": {"name": "factory.appforge_fastlane_capture_status"},
    }, tmp_path))
    assert fastlane_capture["marker"] == "MCP_APPFORGE_FASTLANE_CAPTURE_READ_ONLY"
    assert fastlane_capture["status"]["marker"] == "APPFORGE_FASTLANE_CAPTURE_READ_ONLY"
    assert all(value is False for value in fastlane_capture["status"]["authority"].values())
    saas = _content(dispatch({
        "jsonrpc": "2.0", "id": 83, "method": "tools/call",
        "params": {"name": "factory.saas_status"},
    }, tmp_path))
    assert saas["marker"] == "MCP_SAAS_PROOF_READ_ONLY"
    assert saas["status"]["marker"] == "SAAS_PROOF_READ_ONLY"
    assert all(value is False for value in saas["status"]["authority"].values())
    assert _files(tmp_path) == before


def test_mcp_judgment_safety_case_accepts_only_a_hash_bound_declared_change_profile(tmp_path: Path):
    core = {
        "schema": "factory.judgment.change-profile.v1",
        "changed": [{"path": "src/service.py", "change_kinds": ["public-api"]}],
    }
    profile = {
        **core,
        "profile_sha256": hashlib.sha256(
            json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        ).hexdigest(),
    }
    (tmp_path / "change-profile.json").write_text(json.dumps(profile), encoding="utf-8")
    before = _files(tmp_path)

    result = _content(dispatch({
        "jsonrpc": "2.0", "id": 45, "method": "tools/call", "params": {
            "name": "factory.judgment_safety_case",
            "arguments": {"changed_paths": ["src/service.py"], "change_profile": "change-profile.json"},
        },
    }, tmp_path))

    safety_case = result["safety_case"]
    assert result["marker"] == "MCP_JUDGMENT_SAFETY_CASE_READ_ONLY"
    assert safety_case["route"] == "GREEN"
    assert safety_case["profile"]["state"] == "valid"
    assert safety_case["facts"]["source_semantics_inferred"] is False
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
