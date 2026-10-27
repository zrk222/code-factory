from __future__ import annotations
from factoryline import __version__
from io import StringIO
import hashlib
import json
from pathlib import Path
from factoryline.graph_ops import graph_ops_impact, graph_ops_snapshot
from factoryline.langgraph_assurance import LangGraphTransitionRecorder
from factoryline.mcp import MCP_PROTOCOL_VERSION, dispatch, mcp_status, serve_stdio
import pytest
import factoryline.mcp as mcp
from factoryline.mcp_mrt import (
    McpMrtError,
    release_gate_completed,
    release_gate_input_required,
)
from factoryline.cli import main
from factoryline.mcp_setup import (
    McpSetupError,
    install_project_mcp_config,
    mcp_connection_config,
)


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


def test_mcp_status_declares_default_stdio_and_zero_authority_boundary(tmp_path: Path):
    status = mcp_status(tmp_path)

    assert status["schema"] == "factory.mcp.status.v1"
    assert status["marker"] == "FACTORY_MCP_LOCAL_READ_ONLY"
    assert status["markers"] == ["FACTORY_MCP_LOCAL_READ_ONLY", "MCP_STDLIB_ONLY"]
    assert status["transport"] == "stdio"
    assert status["available_transports"] == [
        "stdio",
        "stateless-streamable-http-local-only",
    ]
    assert status["server"]["streamable_http_protocol_version"] == "2026-07-28"
    assert status["workspace_root"] == str(tmp_path.resolve())
    assert status["tools"] == [
        "factory.status",
        "factory.first_lap_status",
        "factory.agui_review_events",
        "factory.graph_ops",
        "factory.journey_status",
        "factory.evaluate_trace",
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
        "factory.ide_playbook",
        "factory.revenue_status",
        "factory.revenue_memory",
        "factory.appforge_status",
        "factory.project_scope_review",
        "factory.oracle_firewall_status",
        "factory.semantic_authority_status",
        "factory.enterprise_enforcement_status",
        "factory.atomic_status",
        "factory.operations_control_status",
        "factory.agentic_control_status",
        "factory.model_route_audit",
        "factory.task_board_status",
        "factory.task_handoff_status",
        "factory.candidate_alignment_status",
        "factory.task_evidence_status",
        "factory.senior_control_status",
        "factory.blueprint_status",
        "factory.update_status",
        "factory.lifecycle_status",
        "factory.repair_loop_status",
        "factory.mission_control_status",
        "factory.context_efficiency_status",
        "factory.intake_parameters_status",
        "factory.deep_audit_status",
        "factory.runtime_audit_status",
        "factory.search_audit_rules",
        "factory.agent_bridge_status",
        "factory.agent_handoff_brief",
        "factory.proof_worklog_status",
        "factory.codex_metadata_audit",
        "factory.appforge_oracle_status",
        "factory.appforge_device_reality_status",
        "factory.appforge_release_rehearsal_status",
        "factory.appforge_native_surface_status",
        "factory.appforge_surface_matrix_status",
        "factory.appforge_mobile_evidence_status",
        "factory.release_readiness",
        "factory.release_decision",
        "factory.appforge_storefront_story_status",
        "factory.appforge_fastlane_capture_status",
        "factory.appforge_submission_integrity_status",
        "factory.proof_continuity_status",
        "factory.saas_status",
        "factory.github_overview",
        "factory.audit_taxonomy",
        "factory.audit_agent_context",
        "factory.junie_taxonomy",
        "factory.junie_contribution",
        "factory.junie_review",
        "factory.runtime_coverage_status",
        "factory.agent_proof_mission",
        "factory.jetbrains_handshake",
        "factory.jetbrains_handshake_status",
    ]
    assert status["resources"] == ["factory://status", "factory://graph"]
    assert all(value is False for value in status["authority"].values())


def test_mcp_protocol_parity_is_read_only(tmp_path: Path, monkeypatch):
    initialized = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": MCP_PROTOCOL_VERSION},
        },
        tmp_path,
    )
    assert initialized == {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "marker": "MCP_INITIALIZED",
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "serverInfo": {"name": "code-factory", "version": __version__},
            "capabilities": {"tools": {}, "resources": {}},
        },
    }

    inventory = dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, tmp_path)
    assert inventory["result"]["marker"] == "FACTORY_MCP_TOOL_INVENTORY"
    assert [tool["name"] for tool in inventory["result"]["tools"]] == mcp_status(
        tmp_path
    )["tools"]
    for tool in inventory["result"]["tools"]:
        annotations = tool["annotations"]
        assert annotations["readOnlyHint"] is True
        assert annotations["destructiveHint"] is False
        assert annotations["idempotentHint"] is True
        assert annotations["openWorldHint"] is (
            tool["name"] == "factory.github_overview"
        )

    junie = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 29,
                "method": "tools/call",
                "params": {"name": "factory.junie_taxonomy"},
            },
            tmp_path,
        )
    )
    assert junie["marker"] == "MCP_JUNIE_TAXONOMY_READ_ONLY"
    assert junie["taxonomy"]["tool_count"] == len(mcp_status(tmp_path)["tools"])
    assert all(value is False for value in junie["taxonomy"]["authority"].values())

    shared_taxonomy = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 2900,
                "method": "tools/call",
                "params": {"name": "factory.audit_taxonomy"},
            },
            tmp_path,
        )
    )
    assert shared_taxonomy["marker"] == "MCP_AUDIT_TAXONOMY_READ_ONLY"
    registry = shared_taxonomy["taxonomy"]
    assert registry["schema"] == "factory.audit-domain-taxonomy.v1"
    assert (
        registry["agent_usage_contract"]["primary_mcp_tool"] == "factory.audit_taxonomy"
    )
    assert (
        registry["agent_usage_contract"]["cli_fallback"]
        == "factory audit taxonomy --json"
    )
    harness = registry["agent_usage_contract"]["native_harness"]
    assert set(harness["capabilities"]) == {
        "context_shards",
        "runtime_audit",
        "repair_branches",
        "incident_triage",
        "activation_experiment",
        "durable_incident_driver",
    }
    assert "unauthenticated" in harness["capabilities"]["context_shards"]["boundary"]
    assert (
        "legacy plans remain serial"
        in harness["capabilities"]["runtime_audit"]["boundary"]
    )
    assert (
        "unknown outcomes never relaunch"
        in harness["capabilities"]["durable_incident_driver"]["boundary"]
    )
    assert any(
        route["route"] == "factory.github_overview"
        for route in registry["agent_usage_contract"]["agent_routes"]
    )
    assert (
        registry["agent_usage_contract"]["connected_repository_context"]["mcp_tool"]
        == "factory.github_overview"
    )
    assert (
        "Before scoping"
        in registry["agent_usage_contract"]["connected_repository_context"]["use_when"]
    )
    assert (
        "account-wide open pull requests and issues"
        in registry["agent_usage_contract"]["connected_repository_context"]["scope"]
    )
    assert {
        route["capability"]
        for route in registry["agent_usage_contract"]["agent_routes"]
    } == {"mcp", "local_cli", "platform_adapter"}
    assert (
        "candidate.candidate_sha256"
        in registry["agent_usage_contract"]["required_report_fields"]
    )
    assert (
        "specialist_role"
        in registry["agent_usage_contract"]["required_agent_action_fields"]
    )
    assert registry["taxonomy_sha256"]
    assert {
        domain_id
        for role in registry["specialist_roles"]
        for domain_id in role["measurement_ids"]
    } == {row["measurement_id"] for row in registry["domains"]}
    assert any(
        row["measurement_id"] == "agent_workflow_effectiveness"
        for row in registry["domains"]
    )
    assert junie["taxonomy"]["audit_taxonomy"] == registry

    agent_context = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 2903,
                "method": "tools/call",
                "params": {
                    "name": "factory.audit_agent_context",
                    "arguments": {"specialist_role": "specialty_ai_security_reviewer"},
                },
            },
            tmp_path,
        )
    )
    assert agent_context["marker"] == "MCP_AUDIT_AGENT_CONTEXT_READ_ONLY"
    assert agent_context["context"]["taxonomy_sha256"] == registry["taxonomy_sha256"]
    assert (
        agent_context["context"]["role_resolution_state"]
        == "RESOLVED_FROM_CANONICAL_REGISTRY"
    )
    assert "not an authentication claim" in agent_context["context"]["identity_scope"]
    assert all(
        value is False for value in agent_context["context"]["authority"].values()
    )
    assert all(
        row["specialist_role"] == "specialty_ai_security_reviewer"
        for row in agent_context["context"]["domains"]
    )

    from factoryline import github_account_overview

    monkeypatch.setattr(
        github_account_overview,
        "build_github_account_overview",
        lambda root, *, limit: {
            "schema": "factory.github-account-overview.v1",
            "state": "COMPLETE",
            "limit": limit,
            "repository": {"hostname": "github.com", "owner": "owner", "name": "repo"},
            "sections": {},
            "authority": {"merge": False},
        },
    )
    github = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 2904,
                "method": "tools/call",
                "params": {
                    "name": "factory.github_overview",
                    "arguments": {"limit": 12},
                },
            },
            tmp_path,
        )
    )
    assert github["marker"] == "MCP_GITHUB_OVERVIEW_READ_ONLY"
    assert github["overview"]["limit"] == 12
    assert "current workspace origin" in github["scope"].lower()
    assert "pull requests/issues visible" in github["scope"]
    invalid_github = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 2905,
            "method": "tools/call",
            "params": {"name": "factory.github_overview", "arguments": {"limit": 0}},
        },
        tmp_path,
    )
    assert invalid_github["error"]["data"]["marker"] == "MCP_INVALID_PARAMS_REJECTED"

    coverage = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 2901,
                "method": "tools/call",
                "params": {"name": "factory.runtime_coverage_status"},
            },
            tmp_path,
        )
    )
    assert coverage["marker"] == "MCP_RUNTIME_COVERAGE_STATUS_READ_ONLY"
    assert coverage["summary"]["state"] == "NOT_RUN"
    assert "files" not in coverage["summary"]
    assert "do not establish assertion strength" in coverage["scope"]
    invalid_coverage = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 2902,
            "method": "tools/call",
            "params": {
                "name": "factory.runtime_coverage_status",
                "arguments": {"module": "../outside.py"},
            },
        },
        tmp_path,
    )
    assert (
        invalid_coverage["error"]["data"]["marker"]
        == "RUNTIME_COVERAGE_MODULE_REJECTED"
    )

    agentic = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 290,
                "method": "tools/call",
                "params": {"name": "factory.agentic_control_status"},
            },
            tmp_path,
        )
    )
    assert agentic["marker"] == "AGENTIC_CONTROL_MCP_READ_ONLY"
    assert agentic["status"]["features"]["capability_registry"]["status"] == "available"
    assert (
        agentic["status"]["features"]["durable_task_cards"]["schema"]
        == "factory.task-card.v1"
    )
    assert all(value is False for value in agentic["status"]["authority"].values())

    board = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 2910,
                "method": "tools/call",
                "params": {"name": "factory.task_board_status", "arguments": {}},
            },
            tmp_path,
        )
    )
    assert board["marker"] == "TASK_BOARD_MCP_READ_ONLY"
    assert board["status"]["task_count"] == 0
    assert board["status"]["dispatcher"] == {
        "poll_interval_seconds": 60,
        "started": False,
    }

    handoff = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 2911,
            "method": "tools/call",
            "params": {"name": "factory.task_handoff_status", "arguments": {}},
        },
        tmp_path,
    )
    assert handoff["error"]["data"]["marker"] == "TASK_HANDOFF_INPUT_REFUSED"

    candidate = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 2912,
            "method": "tools/call",
            "params": {"name": "factory.candidate_alignment_status", "arguments": {}},
        },
        tmp_path,
    )
    assert candidate["error"]["data"]["marker"] == "CANDIDATE_INPUT_REFUSED"

    evidence = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 2913,
            "method": "tools/call",
            "params": {"name": "factory.task_evidence_status", "arguments": {}},
        },
        tmp_path,
    )
    assert evidence["error"]["data"]["marker"] == "TASK_EVIDENCE_INPUT_REFUSED"

    senior = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 2914,
                "method": "tools/call",
                "params": {"name": "factory.senior_control_status", "arguments": {}},
            },
            tmp_path,
        )
    )
    assert senior["marker"] == "SENIOR_CONTROL_MCP_READ_ONLY"
    assert senior["status"]["readiness"] == "AWAITING_BUNDLE"

    blueprint = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 292,
                "method": "tools/call",
                "params": {"name": "factory.blueprint_status"},
            },
            tmp_path,
        )
    )
    assert blueprint["marker"] == "BLUEPRINT_MCP_READ_ONLY"
    assert blueprint["status"]["schema"] == "factory.ai-native-blueprint.v1"

    update = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 293,
            "method": "tools/call",
            "params": {
                "name": "factory.update_status",
                "arguments": {"manifest_path": "missing-update-manifest.json"},
            },
        },
        tmp_path,
    )
    assert update["error"]["data"]["marker"] == "UPDATE_CHECK_REFUSED"

    evidence_path = tmp_path / "junie-evidence.json"
    evidence_path.write_text('{"local": true}\n', encoding="utf-8")
    contribution = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 291,
                "method": "tools/call",
                "params": {
                    "name": "factory.junie_contribution",
                    "arguments": {
                        "taxonomy_sha256": junie["taxonomy"]["taxonomy_sha256"],
                        "tools_called": ["factory.junie_taxonomy", "factory.graph_ops"],
                        "evidence_paths": ["junie-evidence.json"],
                        "changed_paths": [],
                        "change_rationales": {},
                        "contribution": "Mapped the change review to local FactoryLine evidence.",
                        "unknowns": [
                            "A human reviewer still decides whether the change is acceptable."
                        ],
                    },
                },
            },
            tmp_path,
        )
    )
    assert contribution["marker"] == "MCP_JUNIE_CONTRIBUTION_READ_ONLY"
    assert (
        contribution["contribution"]["marker"]
        == "JUNIE_FACTORYLINE_CONTRIBUTION_DECLARED"
    )
    assert contribution["contribution"]["credit_line"].startswith(
        "FactoryLine contribution declared:"
    )
    assert "cannot authenticate Junie" in contribution["contribution"]["claim_boundary"]

    graph = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "factory.graph_ops"},
            },
            tmp_path,
        )
    )
    assert graph == {
        "marker": "MCP_GRAPH_OPS_PARITY",
        "graph": graph_ops_snapshot(tmp_path),
    }

    summary = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 30,
                "method": "tools/call",
                "params": {
                    "name": "factory.graph_ops",
                    "arguments": {"format": "summary"},
                },
            },
            tmp_path,
        )
    )
    assert summary["marker"] == "MCP_GRAPH_OPS_PARITY"
    assert (
        summary["summary"]["graph_sha256"]
        == graph_ops_snapshot(tmp_path)["graph_sha256"]
    )

    metadata = tmp_path / "run.json"
    metadata.write_text(
        json.dumps({"status": "complete", "intent_id": "mission-1"}), encoding="utf-8"
    )
    before = _files(tmp_path)
    audit = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 31,
                "method": "tools/call",
                "params": {
                    "name": "factory.codex_metadata_audit",
                    "arguments": {"paths": ["run.json"]},
                },
            },
            tmp_path,
        )
    )
    assert audit["marker"] == "MCP_CODEX_METADATA_AUDIT_READ_ONLY"
    assert audit["audit"]["status"] == "REVIEW_REQUIRED"
    assert audit["scope"].startswith("Read-only local metadata integrity")

    impact = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "factory.graph_impact",
                    "arguments": {"changed_paths": ["input.txt"]},
                },
            },
            tmp_path,
        )
    )
    assert impact == {
        "marker": "MCP_GRAPH_IMPACT_PARITY",
        "impact": graph_ops_impact(tmp_path, ["input.txt"]),
    }

    memory = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 41,
                "method": "tools/call",
                "params": {
                    "name": "factory.developer_memory",
                    "arguments": {"changed_paths": ["input.txt"]},
                },
            },
            tmp_path,
        )
    )
    assert memory["marker"] == "MCP_DEVELOPER_MEMORY_READ_ONLY"
    assert memory["brief"]["schema"] == "factory.developer-memory-brief.v1"
    assert memory["brief"]["authority"]["external_effects"] is False

    intent_ledger = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/call",
                "params": {
                    "name": "factory.intent_ledger",
                    "arguments": {
                        "change_list": "Billing cancellation",
                        "changed_paths": ["input.txt"],
                    },
                },
            },
            tmp_path,
        )
    )
    assert intent_ledger["marker"] == "MCP_INTENT_LEDGER_READ_ONLY"
    assert intent_ledger["ledger"]["state"] == "uncontracted"
    assert all(
        value is False for value in intent_ledger["ledger"]["authority"].values()
    )

    judgment = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 43,
                "method": "tools/call",
                "params": {"name": "factory.judgment_status"},
            },
            tmp_path,
        )
    )
    assert judgment["marker"] == "MCP_JUDGMENT_STATUS_READ_ONLY"
    assert judgment["status"]["state"] == "empty"

    safety_case = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 44,
                "method": "tools/call",
                "params": {
                    "name": "factory.judgment_safety_case",
                    "arguments": {"changed_paths": ["input.txt"]},
                },
            },
            tmp_path,
        )
    )
    assert safety_case["marker"] == "MCP_JUDGMENT_SAFETY_CASE_READ_ONLY"
    assert safety_case["safety_case"]["route"] == "GREEN"
    assert all(
        value is False for value in safety_case["safety_case"]["authority"].values()
    )

    next_action = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "factory.next_action"},
            },
            tmp_path,
        )
    )
    snapshot = graph_ops_snapshot(tmp_path)
    assert next_action == {
        "marker": "MCP_GRAPH_OPS_PARITY",
        "graph_sha256": snapshot["graph_sha256"],
        "recommendation": snapshot["recommendation"],
        "daily_action": snapshot["mission_control"]["daily_action"],
        "authority": snapshot["authority"],
    }
    assert next_action["daily_action"]["execution"] == "NOT_RUN"
    assert next_action["daily_action"]["audit_state"] == "NOT_REQUESTED"
    assert not any(next_action["daily_action"]["authority"].values())

    resources = dispatch(
        {"jsonrpc": "2.0", "id": 6, "method": "resources/list"}, tmp_path
    )
    assert resources["result"]["marker"] == "MCP_RESOURCES_PARITY"
    assert [item["uri"] for item in resources["result"]["resources"]] == mcp_status(
        tmp_path
    )["resources"]
    resource = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "resources/read",
            "params": {"uri": "factory://graph"},
        },
        tmp_path,
    )
    assert resource["result"]["marker"] == "MCP_RESOURCES_PARITY"
    assert json.loads(resource["result"]["contents"][0]["text"]) == graph_ops_snapshot(
        tmp_path
    )
    assert _files(tmp_path) == before


def test_mcp_project_scope_review_routes_matching_prd_scopes_read_only(tmp_path: Path):
    appforge_prd = tmp_path / "specs" / "mobile-app-prd.md"
    saas_spec = tmp_path / "specs" / "saas-spec.md"
    appforge_prd.parent.mkdir()
    appforge_prd.write_text(
        "# iOS mobile app requirements\nThe app uses SwiftUI and TestFlight.",
        encoding="utf-8",
    )
    saas_spec.write_text(
        "# SaaS specification\nOAuth/OIDC login, subscriptions, billing and entitlements.",
        encoding="utf-8",
    )
    result = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 41,
                "method": "tools/call",
                "params": {
                    "name": "factory.project_scope_review",
                    "arguments": {
                        "source_paths": [
                            "specs/mobile-app-prd.md",
                            "specs/saas-spec.md",
                        ]
                    },
                },
            },
            tmp_path,
        )
    )
    assert result["schema"] == "factory.project-scope-review.v1"
    assert result["marker"] == "MCP_PROJECT_SCOPE_REVIEW_READ_ONLY"
    assert result["state"] == "routed"
    assert result["sources"] == ["specs/mobile-app-prd.md", "specs/saas-spec.md"]
    assert result["routes"]["appforge"]["implementation"] == "factory.appforge_status"
    assert (
        result["routes"]["appforge"]["status"]["marker"] == "APPFORGE_DESIGN_READ_ONLY"
    )
    assert result["routes"]["saasforge"]["implementation"] == (
        "factory.saas_status (provider-neutral saas_proof)"
    )
    assert result["routes"]["saasforge"]["status"]["marker"] == "SAAS_PROOF_READ_ONLY"
    assert all(value is False for value in result["authority"].values())


def test_mcp_project_scope_review_does_not_route_unmatched_specs(tmp_path: Path):
    source = tmp_path / "specs" / "generic.md"
    source.parent.mkdir()
    source.write_text(
        "# Static documentation\nNo app, billing, or identity requirements.",
        encoding="utf-8",
    )
    result = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/call",
                "params": {
                    "name": "factory.project_scope_review",
                    "arguments": {"source_paths": ["specs/generic.md"]},
                },
            },
            tmp_path,
        )
    )
    assert result["state"] == "no_matching_scope"
    assert result["routes"] == {}


def test_mcp_project_scope_review_rejects_paths_outside_workspace(tmp_path: Path):
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 43,
            "method": "tools/call",
            "params": {
                "name": "factory.project_scope_review",
                "arguments": {"source_paths": ["../outside.md"]},
            },
        },
        tmp_path,
    )
    assert response["error"]["data"]["marker"] == "MCP_INVALID_PARAMS_REJECTED"


def test_mcp_first_lap_status_is_integrity_checked_and_read_only(tmp_path: Path):
    from factoryline.first_lap import initialize_first_lap

    initialize_first_lap(
        tmp_path,
        mission="Ship the approved outcome",
        journeys=["User can complete the flow"],
        holdouts=["Invalid input is rejected"],
    )
    before = _files(tmp_path)
    status = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 901,
                "method": "tools/call",
                "params": {"name": "factory.first_lap_status"},
            },
            tmp_path,
        )
    )
    assert status["marker"] == "MCP_FIRST_LAP_STATUS_READ_ONLY"
    assert status["status"]["marker"] == "FIRST_LAP_INITIALIZED"
    assert status["status"]["state"] == "INITIALIZED"
    assert status["status"]["journey_count"] == 1
    assert all(item["state"] == "VERIFIED" for item in status["status"]["artifacts"])
    assert all(value is False for value in status["status"]["authority"].values())
    events = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 902,
                "method": "tools/call",
                "params": {"name": "factory.agui_review_events"},
            },
            tmp_path,
        )
    )
    assert events["marker"] == "MCP_AGUI_REVIEW_EVENTS_READ_ONLY"
    assert [event["type"] for event in events["events"]] == [
        "RUN_STARTED",
        "STATE_SNAPSHOT",
        "REVIEW_CARD",
        "RUN_FINISHED",
    ]
    assert all(
        event["payload"].get("authority", {}).get("release") is False
        for event in events["events"]
        if isinstance(event.get("payload"), dict) and "authority" in event["payload"]
    )
    assert _files(tmp_path) == before


def test_mcp_revenue_appforge_saas_and_memory_tools_are_read_only(tmp_path: Path):
    before = _files(tmp_path)
    revenue = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 80,
                "method": "tools/call",
                "params": {"name": "factory.revenue_status"},
            },
            tmp_path,
        )
    )
    assert revenue["marker"] == "MCP_REVENUEFORGE_READ_ONLY"
    assert revenue["status"]["marker"] == "GRAPH_OPS_REVENUEFORGE_READ_ONLY"

    memory = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 81,
                "method": "tools/call",
                "params": {
                    "name": "factory.revenue_memory",
                    "arguments": {"app_id": "example.app", "journey": "purchase"},
                },
            },
            tmp_path,
        )
    )
    assert memory["marker"] == "MCP_REVENUEFORGE_MEMORY_READ_ONLY"
    assert memory["status"]["status"] == "empty"

    appforge = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 82,
                "method": "tools/call",
                "params": {"name": "factory.appforge_status"},
            },
            tmp_path,
        )
    )
    assert appforge["marker"] == "MCP_APPFORGE_READ_ONLY"
    assert appforge["status"]["marker"] == "APPFORGE_DESIGN_READ_ONLY"
    assert all(value is False for value in appforge["status"]["authority"].values())
    oracle = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 821,
                "method": "tools/call",
                "params": {"name": "factory.oracle_firewall_status"},
            },
            tmp_path,
        )
    )
    assert oracle["marker"] == "MCP_ORACLE_FIREWALL_READ_ONLY"
    assert oracle["status"]["marker"] == "ORACLE_FIREWALL_READ_ONLY"
    semantic = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 8210,
                "method": "tools/call",
                "params": {"name": "factory.semantic_authority_status"},
            },
            tmp_path,
        )
    )
    assert semantic["marker"] == "MCP_SEMANTIC_AUTHORITY_READ_ONLY"
    assert semantic["status"]["marker"] == "SEMANTIC_AUTHORITY_READ_ONLY"
    assert all(value is False for value in semantic["status"]["authority"].values())
    enterprise = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 82101,
                "method": "tools/call",
                "params": {"name": "factory.enterprise_enforcement_status"},
            },
            tmp_path,
        )
    )
    assert enterprise["marker"] == "MCP_ENTERPRISE_ENFORCEMENT_READ_ONLY"
    assert enterprise["status"]["marker"] == "ENTERPRISE_ENFORCEMENT_READ_ONLY"
    assert all(value is False for value in enterprise["status"]["authority"].values())
    assert (
        enterprise["status"]["runner_admission"]["marker"]
        == "RUNNER_ADMISSION_READ_ONLY"
    )
    assert all(
        value is False
        for value in enterprise["status"]["runner_admission"]["authority"].values()
    )
    atomic = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 8211,
                "method": "tools/call",
                "params": {"name": "factory.atomic_status"},
            },
            tmp_path,
        )
    )
    assert atomic["marker"] == "ATOMIC_MCP_READ_ONLY"
    assert atomic["status"]["marker"] == "ATOMIC_MCP_READ_ONLY"
    assert all(value is False for value in atomic["status"]["authority"].values())
    appforge_oracle = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 822,
                "method": "tools/call",
                "params": {"name": "factory.appforge_oracle_status"},
            },
            tmp_path,
        )
    )
    assert appforge_oracle["marker"] == "MCP_APPFORGE_ORACLE_READ_ONLY"
    assert appforge_oracle["status"]["marker"] == "APPFORGE_ORACLE_AUTHORITY_READ_ONLY"
    device_reality = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 8221,
                "method": "tools/call",
                "params": {"name": "factory.appforge_device_reality_status"},
            },
            tmp_path,
        )
    )
    assert device_reality["marker"] == "MCP_APPFORGE_DEVICE_REALITY_READ_ONLY"
    assert device_reality["status"]["marker"] == "APPFORGE_DEVICE_REALITY_READ_ONLY"
    rehearsal = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 8222,
                "method": "tools/call",
                "params": {"name": "factory.appforge_release_rehearsal_status"},
            },
            tmp_path,
        )
    )
    assert rehearsal["marker"] == "MCP_APPFORGE_RELEASE_REHEARSAL_READ_ONLY"
    assert rehearsal["status"]["marker"] == "APPFORGE_RELEASE_REHEARSAL_READ_ONLY"
    native_surface = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 8223,
                "method": "tools/call",
                "params": {"name": "factory.appforge_native_surface_status"},
            },
            tmp_path,
        )
    )
    assert native_surface["marker"] == "MCP_APPFORGE_NATIVE_SURFACE_READ_ONLY"
    assert native_surface["status"]["marker"] == "APPFORGE_NATIVE_SURFACE_READ_ONLY"
    surface_matrix = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 8224,
                "method": "tools/call",
                "params": {"name": "factory.appforge_surface_matrix_status"},
            },
            tmp_path,
        )
    )
    assert surface_matrix["marker"] == "MCP_APPFORGE_SURFACE_MATRIX_READ_ONLY"

    mobile_evidence = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 82241,
                "method": "tools/call",
                "params": {"name": "factory.appforge_mobile_evidence_status"},
            },
            tmp_path,
        )
    )
    assert mobile_evidence["marker"] == "MCP_APPFORGE_MOBILE_EVIDENCE_READ_ONLY"
    assert mobile_evidence["status"]["marker"] == "APPFORGE_MOBILE_EVIDENCE_READ_ONLY"
    assert surface_matrix["status"]["marker"] == "APPFORGE_SURFACE_MATRIX_READ_ONLY"
    storefront_story = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 8225,
                "method": "tools/call",
                "params": {"name": "factory.appforge_storefront_story_status"},
            },
            tmp_path,
        )
    )
    assert storefront_story["marker"] == "MCP_APPFORGE_STOREFRONT_STORY_READ_ONLY"
    assert storefront_story["status"]["marker"] == "APPFORGE_STOREFRONT_STORY_READ_ONLY"
    fastlane_capture = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 8226,
                "method": "tools/call",
                "params": {"name": "factory.appforge_fastlane_capture_status"},
            },
            tmp_path,
        )
    )
    assert fastlane_capture["marker"] == "MCP_APPFORGE_FASTLANE_CAPTURE_READ_ONLY"
    assert fastlane_capture["status"]["marker"] == "APPFORGE_FASTLANE_CAPTURE_READ_ONLY"
    assert all(
        value is False for value in fastlane_capture["status"]["authority"].values()
    )
    saas = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 83,
                "method": "tools/call",
                "params": {"name": "factory.saas_status"},
            },
            tmp_path,
        )
    )
    assert saas["marker"] == "MCP_SAAS_PROOF_READ_ONLY"
    assert saas["status"]["marker"] == "SAAS_PROOF_READ_ONLY"
    assert all(value is False for value in saas["status"]["authority"].values())
    assert _files(tmp_path) == before


def test_mcp_judgment_safety_case_accepts_only_a_hash_bound_declared_change_profile(
    tmp_path: Path,
):
    core = {
        "schema": "factory.judgment.change-profile.v1",
        "changed": [{"path": "src/service.py", "change_kinds": ["public-api"]}],
    }
    profile = {
        **core,
        "profile_sha256": hashlib.sha256(
            json.dumps(
                core, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
        ).hexdigest(),
    }
    (tmp_path / "change-profile.json").write_text(json.dumps(profile), encoding="utf-8")
    before = _files(tmp_path)

    result = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 45,
                "method": "tools/call",
                "params": {
                    "name": "factory.judgment_safety_case",
                    "arguments": {
                        "changed_paths": ["src/service.py"],
                        "change_profile": "change-profile.json",
                    },
                },
            },
            tmp_path,
        )
    )

    safety_case = result["safety_case"]
    assert result["marker"] == "MCP_JUDGMENT_SAFETY_CASE_READ_ONLY"
    assert safety_case["route"] == "GREEN"
    assert safety_case["profile"]["state"] == "valid"
    assert safety_case["facts"]["source_semantics_inferred"] is False
    assert _files(tmp_path) == before


def test_mcp_langgraph_assurance_reads_existing_receipts_without_execution(
    tmp_path: Path,
):
    def record(run_id: str, outcome: str) -> Path:
        recorder = LangGraphTransitionRecorder("agent-graph", run_id)
        recorder.record_transition(
            "route",
            superstep=1,
            checkpoint_id="cp-1",
            before_state={"request": "secret"},
            after_state={"request": "secret", "outcome": outcome},
            decision={"route": outcome, "reason": "private reason"},
        )
        recorder.seal(tmp_path, f".factory/langgraph/{run_id}.json")
        return tmp_path / ".factory" / "langgraph" / f"{run_id}.json"

    reference = record("reference", "allow")
    resumed = record("resumed", "deny")
    before = _files(tmp_path)
    result = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 88,
                "method": "tools/call",
                "params": {
                    "name": "factory.langgraph_assurance",
                    "arguments": {
                        "reference": reference.relative_to(tmp_path).as_posix(),
                        "resumed": resumed.relative_to(tmp_path).as_posix(),
                    },
                },
            },
            tmp_path,
        )
    )

    assert result["marker"] == "LANGGRAPH_MCP_READ_ONLY"
    assert result["assurance"]["verdict"] == "REVIEW_REQUIRED"
    assert all(value is False for value in result["assurance"]["authority"].values())
    assert '"secret"' not in json.dumps(result)
    assert _files(tmp_path) == before


def test_mcp_read_only_receipt_and_gate_status_tools(tmp_path: Path):
    receipt = tmp_path / "receipts" / "build.json"
    receipt.parent.mkdir()
    receipt.write_text(
        json.dumps(
            {
                "schema": "factory.receipt.v1",
                "feature": "checkout",
                "created_at": "2026-08-08T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    session = tmp_path / ".factory" / "verifier-sessions" / "checkout.session.json"
    session.parent.mkdir(parents=True)
    session.write_text(
        json.dumps(
            {
                "schema": "factory.verifier-session.v1",
                "mission_id": "checkout",
                "session_sha256": "a" * 64,
                "budgets": {
                    "max_attempts": 5,
                    "max_wall_seconds": 3600,
                    "max_tokens": 100000,
                    "max_cost_usd": 25.0,
                },
            }
        ),
        encoding="utf-8",
    )
    prd = tmp_path / "PRD.md"
    prd.write_text("# Checkout", encoding="utf-8")
    before = _files(tmp_path)

    listed = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "factory.list_receipts",
                    "arguments": {"feature": "checkout"},
                },
            },
            tmp_path,
        )
    )
    assert listed["marker"] == "MCP_RECEIPTS_UNASSESSED"
    assert listed["entries"][0]["assessment"] == "unassessed"

    loaded = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "factory.get_receipt",
                    "arguments": {"path": "receipts/build.json"},
                },
            },
            tmp_path,
        )
    )
    assert loaded["receipt"]["feature"] == "checkout"
    assert loaded["metadata"]["verification"] == "not_run"

    verifier = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "factory.verifier_status",
                    "arguments": {"mission": "checkout"},
                },
            },
            tmp_path,
        )
    )
    assert verifier["worker"]["result"] == "not_supplied"
    assert verifier["budget"]["remaining"] == "unobserved"

    reuse = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "factory.proof_reuse",
                    "arguments": {"gate": "python-tests"},
                },
            },
            tmp_path,
        )
    )
    assert reuse["disposition"] == "BLOCK"

    cdte = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "factory.cdte_status"},
            },
            tmp_path,
        )
    )
    assert cdte["marker"] == "MCP_CDTE_SCAN_REQUIRED"

    advisor = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "factory.workspace_advisor"},
            },
            tmp_path,
        )
    )
    assert advisor["marker"] == "MCP_WORKSPACE_ADVISOR_READ_ONLY"
    assert advisor["report"]["marker"] == "WORKSPACE_ADVISOR_LOCAL_READ_ONLY"
    assert advisor["scope"].startswith("In-memory local")
    assert _files(tmp_path) == before

    grill = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "factory.prd_grill_status",
                    "arguments": {"prd_path": "PRD.md"},
                },
            },
            tmp_path,
        )
    )
    assert grill["marker"] == "MCP_PRD_GRILL_REQUIRED"
    assert _files(tmp_path) == before

    intake = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "factory.intake_status",
                    "arguments": {"prd_path": "PRD.md"},
                },
            },
            tmp_path,
        )
    )
    assert intake["marker"] == "MCP_INTAKE_READ_ONLY"
    assert intake["status"]["marker"] == "INTAKE_CONFIRMATION_REQUIRED"
    assert _files(tmp_path) == before

    gauntlet = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "factory.gauntlet_status", "arguments": {}},
            },
            tmp_path,
        )
    )
    assert gauntlet["marker"] == "MCP_GAUNTLET_READ_ONLY"
    assert gauntlet["status"]["entries"] == []

    licenses = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {"name": "factory.agent_license_status", "arguments": {}},
            },
            tmp_path,
        )
    )
    assert licenses["marker"] == "MCP_AGENT_LICENSE_READ_ONLY"
    assert licenses["status"]["licenses"] == []

    combine = _content(
        dispatch(
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": "factory.combine_status", "arguments": {}},
            },
            tmp_path,
        )
    )
    assert combine["marker"] == "MCP_COMBINE_READ_ONLY"
    assert combine["status"]["scoreboards"] == []
    assert _files(tmp_path) == before


def test_mcp_rejects_malformed_and_unsafe_requests_without_writing(tmp_path: Path):
    before = _files(tmp_path)
    requests = [
        {"id": 1, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "unknown"},
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "factory.graph_impact",
                "arguments": {"changed_paths": ["../outside.txt"]},
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "factory.graph_impact",
                "arguments": {"changed_paths": [str(tmp_path / "outside.txt")]},
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "factory.get_receipt",
                "arguments": {"path": "../outside.json"},
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "factory.prd_grill_status",
                "arguments": {"prd_path": "../outside.md"},
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "factory.intake_status",
                "arguments": {"prd_path": "../outside.md"},
            },
        },
    ]
    for request in requests:
        response = dispatch(request, tmp_path)
        assert response["error"]["code"] == -32602
        assert response["error"]["data"]["marker"] == "MCP_INVALID_PARAMS_REJECTED"

    unknown_method = dispatch(
        {"jsonrpc": "2.0", "id": 7, "method": "factory/nope"}, tmp_path
    )
    assert unknown_method["error"]["code"] == -32601
    assert unknown_method["error"]["data"]["marker"] == "MCP_UNKNOWN_METHOD_REJECTED"
    missing_root = dispatch(
        {"jsonrpc": "2.0", "id": 8, "method": "tools/list"}, tmp_path / "missing"
    )
    assert missing_root["error"]["code"] == -32602
    assert missing_root["error"]["data"]["marker"] == "MCP_INVALID_PARAMS_REJECTED"
    assert _files(tmp_path) == before


def test_mcp_stdio_emits_only_newline_delimited_json_rpc(tmp_path: Path):
    incoming = StringIO(
        '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n'
        "this is not json\n"
        '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
    )
    outgoing = StringIO()

    assert serve_stdio(tmp_path, input_stream=incoming, output_stream=outgoing) == 0
    lines = outgoing.getvalue().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["result"]["marker"] == "FACTORY_MCP_TOOL_INVENTORY"
    assert (
        json.loads(lines[1])["error"]["data"]["marker"] == "MCP_INVALID_PARAMS_REJECTED"
    )


@pytest.mark.parametrize("method", ["tools/list", "resources/list"])
@pytest.mark.parametrize(
    "params",
    [
        None,
        {},
        {"cursor": None},
        {"_meta": {}},
        {"_meta": None},
        {"cursor": None, "_meta": {"progressToken": "probe"}},
    ],
)
def test_mcp_empty_list_params_and_request_metadata_allow_discovery(
    tmp_path, method, params
):
    request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    baseline = dispatch({**request, "params": {}}, tmp_path)
    assert dispatch(request, tmp_path) == baseline


@pytest.mark.parametrize("method", ["tools/list", "resources/list"])
@pytest.mark.parametrize(
    "params",
    [
        {"cursor": "unknown"},
        {"root": "/other"},
        {"_meta": []},
        {"_meta": "invalid"},
        {"cursor": False},
        [],
    ],
)
def test_mcp_request_metadata_preserves_rejection_of_state_and_unknown_params(
    tmp_path, method, params
):
    result = dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, tmp_path
    )
    assert result["error"]["code"] == -32602
    assert result["error"]["data"]["marker"] == "MCP_INVALID_PARAMS_REJECTED"


@pytest.mark.parametrize(
    "method, params",
    [
        ("tools/call", {"name": "factory.status", "arguments": {}}),
        ("resources/read", {"uri": "factory://status"}),
    ],
)
def test_mcp_request_metadata_is_transport_only_and_cannot_retarget_workspace(
    tmp_path, method, params
):
    request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    baseline = dispatch(request, tmp_path)
    actual = dispatch(
        {
            **request,
            "params": {
                **params,
                "_meta": {"progressToken": "probe", "root": "/other", "approval": True},
            },
        },
        tmp_path,
    )
    assert actual == baseline
    payload = (
        _content(actual)
        if method == "tools/call"
        else json.loads(actual["result"]["contents"][0]["text"])
    )
    assert payload["workspace_root"] == str(tmp_path.resolve())
    assert not any(payload["authority"].values())


def test_mcp_protocol_metadata_stdio_initialize_discover_and_read_status(tmp_path):
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "Codex-compatible-probe", "version": "1"},
                "_meta": {},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {"cursor": None, "_meta": {"progressToken": "probe"}},
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "factory.status",
                "arguments": {},
                "_meta": {"progressToken": "probe"},
            },
        },
    ]
    before = _files(tmp_path)
    incoming = StringIO("\n".join(json.dumps(row) for row in requests) + "\n")
    outgoing = StringIO()
    assert serve_stdio(tmp_path, input_stream=incoming, output_stream=outgoing) == 0
    replies = [json.loads(line) for line in outgoing.getvalue().splitlines()]
    assert len(replies) == 3
    assert all("error" not in reply for reply in replies)
    assert "factory.status" in {row["name"] for row in replies[1]["result"]["tools"]}
    assert _content(replies[2])["workspace_root"] == str(tmp_path.resolve())
    assert _files(tmp_path) == before


def test_mcp_request_metadata_cannot_relax_tool_arguments(tmp_path):
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "factory.status",
                "arguments": {"root": "/other"},
                "_meta": {},
            },
        },
        tmp_path,
    )
    assert response["error"]["code"] == -32602


def test_mcp_protocol_metadata_stateless_keeps_original_request_binding(tmp_path):
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {"_meta": {"progressToken": "probe"}},
    }
    response = mcp.dispatch_stateless(request, tmp_path)
    assert response["response"] == dispatch({**request, "params": {}}, tmp_path)
    assert (
        response["request_sha256"]
        == hashlib.sha256(mcp._canonical(request).encode()).hexdigest()
    )
    assert not any(response["authority"].values())


def test_mcp_protocol_metadata_real_stdio_process(tmp_path):
    import subprocess
    import sys

    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "probe", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {"cursor": None, "_meta": {"progressToken": "probe"}},
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "factory.status",
                "arguments": {},
                "_meta": {"root": "/other"},
            },
        },
    ]
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "factoryline.cli",
            "mcp",
            "serve",
            "--root",
            str(tmp_path),
        ],
        cwd=Path(mcp.__file__).resolve().parent.parent,
        input="\n".join(json.dumps(row) for row in requests) + "\n",
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0 and not result.stderr
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    assert [row["id"] for row in replies] == [1, 2, 3]
    assert all("error" not in row for row in replies)
    assert len(replies[1]["result"]["tools"]) == len(mcp._tool_definitions())
    status = _content(replies[2])
    assert status["workspace_root"] == str(tmp_path.resolve())
    assert not any(status["authority"].values())
    files = _files(tmp_path)
    assert len(files) == 1
    name, data = next(iter(files.items()))
    assert name.startswith(".factory/ops/lifecycle/") and name.endswith(".json")
    assert json.loads(data)["command_family"] == "mcp"


def test_release_gate_input_required_is_deterministic_and_authority_free() -> None:
    card = {
        "feature": "payments",
        "state": "LOCAL_EVIDENCE_BLOCKED",
        "classification": "local_evidence_failure",
        "blockers": [
            {
                "source": "strict_release_verification",
                "code": "RELEASE_CONTRACT_MISSING",
                "detail": "contract absent",
            }
        ],
        "next_action": {"action": "create_or_restore_release_contract"},
    }
    first = release_gate_input_required(card)
    second = release_gate_input_required(card)
    assert first == second
    assert first["type"] == "input_required"
    assert first["toolCallId"].startswith("release-gate:")
    assert first["context"]["proofCardHash"].startswith("sha256:")
    assert first["context"]["hasUnresolvedProofDebt"] is True
    assert first["context"]["proofDebt"] == ["RELEASE_CONTRACT_MISSING"]
    assert first["inputSchema"]["required"] == ["decision", "reviewerIdentity"]
    assert all(value is False for value in first["authority"].values())
    assert "does not" in first["claim_boundary"]


def test_release_gate_input_required_preserves_empty_proof_debt() -> None:
    card = {
        "feature": "payments",
        "state": "EXTERNAL_GATES_UNOBSERVED",
        "next_action": {"action": "review_external_publish_gates"},
    }
    result = release_gate_input_required(card)
    assert result["context"]["hasUnresolvedProofDebt"] is False
    assert result["context"]["proofDebt"] == []
    assert result["context"]["nextFactDerivedAction"] == "review_external_publish_gates"


def test_release_gate_input_required_projects_explicit_failed_lane() -> None:
    card = {
        "feature": "payments",
        "state": "LOCAL_EVIDENCE_BLOCKED",
        "blockers": [
            {
                "lane": "authorization_tenant_isolation",
                "rejectionCondition": "CF-RULE-AUTH-04",
                "evidenceDigest": "sha256:evidence_456",
                "riskSeverity": "HIGH",
                "code": "AUTH_TENANT_SCOPE",
            }
        ],
    }
    result = release_gate_input_required(card)
    assert "1 failed audit lane(s)" in result["prompt"]
    assert result["context"]["failedLanes"] == [
        {
            "lane": "authorization_tenant_isolation",
            "rejectionCondition": "CF-RULE-AUTH-04",
            "evidenceDigest": "sha256:evidence_456",
            "riskSeverity": "HIGH",
        }
    ]


def test_release_gate_completed_is_deterministic_and_authority_free() -> None:
    card = {"feature": "payments", "state": "EXTERNAL_GATES_UNOBSERVED"}
    challenge = release_gate_input_required(card)
    human_input = {
        "decision": "APPROVE_RELEASE",
        "reviewerIdentity": "dev-lead@company.com",
        "reviewerNotes": "Local evidence reviewed.",
    }
    first = release_gate_completed(
        card,
        human_input,
        tool_call_id=challenge["toolCallId"],
        proof_card_hash=challenge["context"]["proofCardHash"],
    )
    second = release_gate_completed(
        card,
        human_input,
        tool_call_id=challenge["toolCallId"],
        proof_card_hash=challenge["context"]["proofCardHash"],
    )
    assert first == second
    assert first["type"] == "completed"
    assert first["status"] == "RELEASE_APPROVED"
    assert first["receiptHash"].startswith("sha256:")
    assert "permanently sealed by dev-lead@company.com" in first["summary"]
    assert all(value is False for value in first["authority"].values())
    assert "does not approve" in first["claim_boundary"]


def test_release_gate_completed_requires_proof_debt_acknowledgement() -> None:
    card = {
        "feature": "payments",
        "state": "LOCAL_EVIDENCE_BLOCKED",
        "blockers": [{"code": "RELEASE_CONTRACT_MISSING"}],
    }
    challenge = release_gate_input_required(card)
    with pytest.raises(McpMrtError, match="acknowledgement") as exc_info:
        release_gate_completed(
            card,
            {"decision": "APPROVE_RELEASE", "reviewerIdentity": "lead"},
            tool_call_id=challenge["toolCallId"],
            proof_card_hash=challenge["context"]["proofCardHash"],
        )
    assert exc_info.value.marker == "MCP2_RELEASE_DEBT_UNACKNOWLEDGED"
    result = release_gate_completed(
        card,
        {
            "decision": "APPROVE_RELEASE",
            "reviewerIdentity": "lead",
            "acknowledgedProofDebt": ["RELEASE_CONTRACT_MISSING"],
        },
        tool_call_id=challenge["toolCallId"],
        proof_card_hash=challenge["context"]["proofCardHash"],
    )
    assert result["status"] == "RELEASE_APPROVED"


def test_release_gate_completed_rejects_invalid_input_and_binding_mismatch() -> None:
    card = {"feature": "payments", "state": "EXTERNAL_GATES_UNOBSERVED"}
    with pytest.raises(McpMrtError, match="decision"):
        release_gate_completed(
            card, {"decision": "INVALID", "reviewerIdentity": "lead"}
        )
    with pytest.raises(McpMrtError) as exc_info:
        release_gate_completed(
            card,
            {"decision": "REJECT_RELEASE", "reviewerIdentity": "lead"},
            tool_call_id="release-gate:wrong",
            proof_card_hash=release_gate_input_required(card)["context"][
                "proofCardHash"
            ],
        )
    assert exc_info.value.marker == "MCP2_RELEASE_GATE_BINDING_MISMATCH"


def test_release_gate_completed_requires_both_stateless_bindings() -> None:
    card = {"feature": "payments", "state": "EXTERNAL_GATES_UNOBSERVED"}
    challenge = release_gate_input_required(card)
    with pytest.raises(McpMrtError) as exc_info:
        release_gate_completed(
            card,
            {"decision": "REJECT_RELEASE", "reviewerIdentity": "lead"},
            tool_call_id=challenge["toolCallId"],
        )
    assert exc_info.value.marker == "MCP2_RELEASE_GATE_BINDING_MISMATCH"


def test_factory_release_decision_bridges_both_stateless_mrt_legs(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    card = {"feature": "payments", "state": "EXTERNAL_GATES_UNOBSERVED"}
    monkeypatch.setattr(mcp, "release_decision_card", lambda _root, _feature: card)
    challenge = mcp._release_decision_status(tmp_path, {"feature": "payments"})
    challenge_payload = challenge["mcp2"]
    completed = mcp._release_decision_status(
        tmp_path,
        {
            "feature": "payments",
            "tool_call_id": challenge_payload["toolCallId"],
            "proof_card_hash": challenge_payload["context"]["proofCardHash"],
            "human_input": {"decision": "REJECT_RELEASE", "reviewerIdentity": "lead"},
        },
    )
    assert challenge["marker"] == "MCP_RELEASE_DECISION_READ_ONLY"
    assert completed["marker"] == "MCP_RELEASE_DECISION_COMPLETED"
    assert completed["mcp2"]["status"] == "RELEASE_REJECTED"


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
    assert (
        codex["command_line"]
        == f"codex mcp add code-factory -- factory mcp serve --root {tmp_path.resolve()}"
    )
    assert junie["target"] == ".junie/mcp/mcp.json"
    assert copilot["target"] == ".github/agents/factoryline-proof.agent.md"
    assert "mcp-servers:" in copilot["agent_profile"]
    assert "code-factory/factory.agent_proof_mission" in copilot["agent_profile"]


def test_junie_project_install_is_confirmed_idempotent_and_never_overwrites_a_conflict(
    tmp_path: Path,
):
    with pytest.raises(McpSetupError, match="confirmation"):
        install_project_mcp_config(tmp_path, "junie", "yes")
    installed = install_project_mcp_config(tmp_path, "junie", "INSTALL Junie MCP")
    repeated = install_project_mcp_config(tmp_path, "junie", "INSTALL Junie MCP")
    config = json.loads((tmp_path / ".junie/mcp/mcp.json").read_text(encoding="utf-8"))
    assert installed["state"] == "installed"
    assert repeated["state"] == "already_current"
    assert config["mcpServers"]["code-factory"]["command"] == "factory"
    assert "factory.junie_taxonomy" in installed["next_action"]
    assert all(value is False for value in installed["authority"].values())

    config["mcpServers"]["code-factory"]["command"] = "other"
    (tmp_path / ".junie/mcp/mcp.json").write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(McpSetupError, match="no overwrite"):
        install_project_mcp_config(tmp_path, "junie", "INSTALL Junie MCP")


def test_copilot_project_install_is_confirmed_idempotent_and_never_overwrites_a_conflict(
    tmp_path: Path,
):
    with pytest.raises(McpSetupError, match="confirmation"):
        install_project_mcp_config(tmp_path, "copilot", "yes")
    installed = install_project_mcp_config(tmp_path, "copilot", "INSTALL Copilot MCP")
    repeated = install_project_mcp_config(tmp_path, "copilot", "INSTALL Copilot MCP")
    profile = (tmp_path / ".github/agents/factoryline-proof.agent.md").read_text(
        encoding="utf-8"
    )
    assert installed["marker"] == "FACTORY_COPILOT_MCP_INSTALLED"
    assert installed["state"] == "installed"
    assert repeated["state"] == "already_current"
    assert "target: github-copilot" in profile
    assert "command: factory" in profile
    assert "approval" in profile
    assert all(value is False for value in installed["authority"].values())

    (tmp_path / ".github/agents/factoryline-proof.agent.md").write_text(
        "owner content\n", encoding="utf-8"
    )
    with pytest.raises(McpSetupError, match="no overwrite"):
        install_project_mcp_config(tmp_path, "copilot", "INSTALL Copilot MCP")


def test_mcp_setup_rejects_unknown_clients_and_missing_roots(tmp_path: Path):
    with pytest.raises(McpSetupError, match="client must be one of") as client_error:
        mcp_connection_config(tmp_path, "unsafe-hosted")
    assert client_error.value.marker == "MCP_CLIENT_REJECTED"
    with pytest.raises(McpSetupError, match="existing directory") as root_error:
        mcp_connection_config(tmp_path / "missing")
    assert root_error.value.marker == "MCP_ROOT_REJECTED"


def test_mcp_config_cli_prints_a_copy_only_codex_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    assert main(["mcp", "config", "--client", "codex", "--root", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "Factory MCP config (codex)" in output
    assert (
        f"codex mcp add code-factory -- factory mcp serve --root {tmp_path.resolve()}"
        in output
    )
    assert "read-only local context" in output


def test_mcp_install_cli_writes_only_the_confirmed_junie_project_entry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    assert (
        main(
            [
                "mcp",
                "install",
                "--client",
                "junie",
                "--root",
                str(tmp_path),
                "--confirmation",
                "INSTALL Junie MCP",
                "--json",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["marker"] == "FACTORY_JUNIE_MCP_INSTALLED"
    assert result["target"] == ".junie/mcp/mcp.json"


def test_mcp_install_cli_writes_only_the_confirmed_copilot_agent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    assert (
        main(
            [
                "mcp",
                "install",
                "--client",
                "copilot",
                "--root",
                str(tmp_path),
                "--confirmation",
                "INSTALL Copilot MCP",
                "--json",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["marker"] == "FACTORY_COPILOT_MCP_INSTALLED"
    assert result["target"] == ".github/agents/factoryline-proof.agent.md"
