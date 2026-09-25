from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

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


def test_plugin_skill_and_workflow_keep_execution_and_release_authority_human_controlled() -> (
    None
):
    skill = (PLUGIN / "skills" / "langgraph-proof" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    workflow = (PLUGIN / "assets" / "github-actions" / "langgraph-proof.yml").read_text(
        encoding="utf-8"
    )

    assert "factory langgraph replay-verify" in skill
    assert "factory.langgraph_assurance" in skill
    assert "cannot invoke a graph" in skill
    assert "Do not authorize or execute repairs" in skill
    assert "pull_request_target" not in workflow
    assert "contents: read" in workflow
    assert "zrk222/code-factory@v0.45.0" in workflow
    assert "write" not in workflow


def test_marketplace_entry_and_docs_expose_all_supported_coding_agent_installs() -> (
    None
):
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
    assert plugins[2] == {
        "name": "code-factory-build-audit",
        "source": "./plugins/muse-code-factory-audit",
        "description": "Native Muse Code build audits with PRD/spec-driven AppForge and SaaS proof routing.",
        "author": {"name": "Richard Katz", "email": "rkatz22@gmail.com"},
    }

    docs = (ROOT / "docs" / "LANGCHAIN_MARKETPLACE.md").read_text(encoding="utf-8")
    assert "codex plugin add code-factory-langgraph@code-factory" in docs
    assert "/plugin install code-factory-langgraph@code-factory" in docs
    assert "dcode plugin install code-factory-langgraph@code-factory" in docs
    assert "factoryline-code-factory>=0.44.0" in docs


def test_muse_native_plugin_declares_marketplace_hooks_and_safe_routing() -> None:
    package = ROOT / "plugins" / "muse-code-factory-audit"
    manifest = _json(package / ".muse-plugin" / "plugin.json")
    capabilities = manifest["capabilities"]

    assert manifest["name"] == "code-factory-build-audit"
    assert manifest["compat"] == {"source": "native", "manifestDir": ".muse-plugin"}
    assert {hook["event"] for hook in capabilities["hooks"]} == {
        "PostToolUse",
        "PostToolUseFailure",
        "Stop",
    }
    hook_paths = [hook["command"][1] for hook in capabilities["hooks"]]
    assert len(hook_paths) == len(set(hook_paths))
    assert all((package / path).is_file() for path in hook_paths)
    skill = (package / "skills" / "cf-fl-build-audit" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    assert "Python ASTs only" in skill
    assert "provider-neutral `saas_proof`" in skill
    assert "ForgeLine `qa --repo-wide` is an inventory check" in skill
    hook_source = (package / "hooks" / "audit.mjs").read_text(encoding="utf-8")
    assert "bounded to 80 changed Markdown paths" in hook_source
    assert "Python AST only" in hook_source
    assert '"Code Factory: <result>" and "ForgeLine: <result>"' in hook_source


def test_expertise_muse_plugin_manifest_and_catalog_cover_three_workflows() -> None:
    package = ROOT / "plugins" / "muse-expertise-agent-workflows"
    manifest = _json(package / ".muse-plugin" / "plugin.json")
    marketplace = _json(ROOT / ".claude-plugin" / "marketplace.json")
    assert manifest["name"] == "expertise-agent-workflows"
    assert len(manifest["capabilities"]["skills"]) == 1
    skill = manifest["capabilities"]["skills"][0]
    assert skill["id"] == "expertise-agent-workflows"
    assert (package / skill["path"]).is_file()
    catalog = next(item for item in marketplace["plugins"] if item["name"] == manifest["name"])
    assert catalog["source"] == "./plugins/muse-expertise-agent-workflows"


def test_expertise_mcp_server_lists_and_routes_each_workflow() -> None:
    package = ROOT / "plugins" / "muse-expertise-agent-workflows"
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "expertise_earnie_vendor_value_review", "arguments": {"request": "Review this renewal"}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "expertise_cluso_account_impact_review", "arguments": {"request": "Summarize this account"}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "expertise_surely_portfolio_watch", "arguments": {"request": "Review these sites"}}},
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "expertise_surely_portfolio_watch", "arguments": {"request": "  "}}},
    ]
    process = subprocess.run(
        ["node", "mcp/server.mjs"], cwd=package,
        input="\n".join(json.dumps(message) for message in messages) + "\n",
        text=True, capture_output=True, check=True, timeout=10,
        env={**os.environ, "NO_COLOR": "1"},
    )
    replies = [json.loads(line) for line in process.stdout.splitlines()]
    assert [reply["id"] for reply in replies] == [1, 2, 3, 4, 5, 6]
    tools = replies[1]["result"]["tools"]
    assert {tool["name"] for tool in tools} == {
        "expertise_earnie_vendor_value_review",
        "expertise_cluso_account_impact_review",
        "expertise_surely_portfolio_watch",
    }
    for reply in replies[2:5]:
        packet = reply["result"]["structuredContent"]
        assert packet["status"] == "prepared_for_muse_review"
        assert packet["skillId"] == "expertise-agent-workflows"
        assert packet["execution"].startswith("Muse agent performs")
    assert replies[5]["result"]["isError"] is True
    assert replies[5]["result"]["content"][0]["text"] == "invalid_workflow_request"
    assert process.stderr == ""


def test_muse_build_hook_runs_both_audits_and_routes_changed_prd_specs(tmp_path: Path) -> None:
    package = ROOT / "plugins" / "muse-code-factory-audit"
    project = tmp_path / "project"
    (project / ".git").mkdir(parents=True)
    (project / ".factory").mkdir()
    (project / ".factory" / "review-audits.json").write_text("{}", encoding="utf-8")
    (project / "specs").mkdir()
    (project / "specs" / "mobile-prd.md").write_text(
        "# iOS mobile app\nSwiftUI and TestFlight requirements.", encoding="utf-8"
    )
    (project / "specs" / "saas-spec.md").write_text(
        "# SaaS spec\nOAuth/OIDC and subscriptions with entitlements.", encoding="utf-8"
    )
    runner = r"""
import { pathToFileURL } from 'node:url';
const { buildAudit } = await import(pathToFileURL(process.env.AUDIT_HOOK_MODULE));
const calls = [];
const output = [];
const runGit = (_root, args) => {
  if (args[0] === 'symbolic-ref') return ['refs/remotes/origin/main'];
  if (args[0] === 'rev-parse') return ['origin/main'];
  if (args[0] === 'diff' && args[1] === '--name-only') return ['specs/mobile-prd.md', 'specs/saas-spec.md'];
  return [];
};
const runRtk = (args) => {
  calls.push(args);
  if (args[1] === 'audit' && args[2] === 'all') return { exitCode: 0, stdout: JSON.stringify({state:'no_structural_findings'}), stderr: '' };
  if (args[1] === 'audit' && args[2] === 'security') return { exitCode: 0, stdout: JSON.stringify({state:'CLEAN', files_scanned:2}), stderr: '' };
  if (args[0] === 'forge') return { exitCode: 0, stdout: JSON.stringify({grade:'F', passed:false}), stderr: '' };
  if (args[2] === 'appforge-status') return { exitCode: 0, stdout: JSON.stringify({marker:'APP_REVIEW_GATE_READ_ONLY', current_count:0, invalid_count:0}), stderr: '' };
  if (args[1] === 'saas' && args[2] === 'status') return { exitCode: 0, stdout: JSON.stringify({marker:'SAAS_PROOF_READ_ONLY'}), stderr: '' };
  throw new Error(`unexpected command: ${args.join(' ')}`);
};
const event = {
  hook_event_name:'PostToolUse', session_id:'session-test', turn_id:'turn-test',
  cwd:process.env.TEST_PROJECT, tool_input:{command:'npm run build'},
};
const result = buildAudit(event, {runGit, runRtk, emit:(value)=>output.push(value)});
process.stdout.write(JSON.stringify({calls, output, summary:result.summary}));
"""
    runner_path = tmp_path / "audit-hook-runner.mjs"
    runner_path.write_text(runner, encoding="utf-8")
    environment = {
        **os.environ,
        "AUDIT_HOOK_MODULE": str(package / "hooks" / "audit.mjs"),
        "MUSE_PLUGIN_DATA_DIR": str(tmp_path / "plugin-data"),
        "TEST_PROJECT": str(project),
    }
    process = subprocess.run(
        ["node", str(runner_path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
        timeout=10,
        env=environment,
    )
    assert process.stdout, (
        f"Node hook harness produced no output (exit={process.returncode}, "
        f"stderr={process.stderr!r})"
    )
    result = json.loads(process.stdout)
    summary = result["summary"]
    assert "Code Factory patterns/guard-paths: no_structural_findings" in summary
    assert "ForgeLine repo-wide QA: grade=F, passed=false, scope=inventory-only" in summary
    assert "AppForge (PRD/spec scope: ios, mobile app, swiftui, testflight)" in summary
    assert "SaaSForge scope via Code Factory saas_proof" in summary
    assert '"Code Factory: <result>" and "ForgeLine: <result>"' in summary
    command_vectors = [call[:3] for call in result["calls"]]
    assert ["factory", "audit", "all"] in command_vectors
    assert ["factory", "audit", "security"] in command_vectors
    assert ["forge", "qa", "--repo-wide"] in command_vectors
    assert ["factory", "revenue", "appforge-status"] in command_vectors
    assert ["factory", "saas", "status"] in command_vectors
