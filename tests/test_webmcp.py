import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from factoryline.webmcp import WEBMCP_TOOLS, webmcp_manifest


ROOT = Path(__file__).resolve().parents[1]


def test_webmcp_manifest_is_deterministic_read_only_and_progressive() -> None:
    first = webmcp_manifest()
    second = webmcp_manifest()
    assert first == second
    assert first["marker"] == "FACTORY_WEBMCP_PROGRESSIVE_READ_ONLY"
    assert first["spec_status"] == "draft-community-group-report"
    assert [item["name"] for item in first["tools"]] == [
        item["name"] for item in WEBMCP_TOOLS
    ]
    assert "factory.first_lap_status" in [item["name"] for item in first["tools"]]
    assert "factory.agui_review_events" in [item["name"] for item in first["tools"]]
    assert "factory.deep_audit_status" in [item["name"] for item in first["tools"]]
    assert "factory.runtime_audit_status" in [item["name"] for item in first["tools"]]
    assert "factory.saas_status" in [item["name"] for item in first["tools"]]
    assert "factory.oracle_firewall_status" in [item["name"] for item in first["tools"]]
    assert "factory.atomic_status" in [item["name"] for item in first["tools"]]
    assert "factory.context_efficiency_status" in [
        item["name"] for item in first["tools"]
    ]
    assert "factory.appforge_oracle_status" in [item["name"] for item in first["tools"]]
    assert "factory.appforge_device_reality_status" in [
        item["name"] for item in first["tools"]
    ]
    assert "factory.appforge_release_rehearsal_status" in [
        item["name"] for item in first["tools"]
    ]
    assert "factory.appforge_native_surface_status" in [
        item["name"] for item in first["tools"]
    ]
    assert "factory.appforge_surface_matrix_status" in [
        item["name"] for item in first["tools"]
    ]
    assert "factory.appforge_mobile_evidence_status" in [
        item["name"] for item in first["tools"]
    ]
    assert "factory.appforge_storefront_story_status" in [
        item["name"] for item in first["tools"]
    ]
    assert "factory.jetbrains_handshake_status" in [
        item["name"] for item in first["tools"]
    ]
    assert all(
        item["inputSchema"]["additionalProperties"] is False for item in first["tools"]
    )
    assert all(
        item["annotations"] == {"readOnlyHint": True, "untrustedContentHint": True}
        for item in first["tools"]
    )
    assert all(value is False for value in first["authority"].values())


def test_audit_webmcp_registration_and_projection_in_node_vm() -> None:
    node = shutil.which("node")
    assert node, "Node.js is required to verify the actual browser registration code"
    html = (ROOT / "factoryline" / "graph_ops.html").read_text(encoding="utf-8")
    assert "const setText=(id,text)=>{byId(id).textContent=String(text);};" in html
    names_start = html.index("    const WEBMCP_TOOL_NAMES=")
    names_end = html.index("\n", names_start)
    names = html[names_start:names_end]
    start = html.index("    const webmcpUnavailable=")
    end = html.index("    async function registerMobileEvidenceWebMcp()", start)
    source = html[start:end]
    render_start = html.index("    function renderControlPlane(payload){")
    render_end = html.index("    function renderAgenticControl(payload){", render_start)
    source += html[render_start:render_end]
    script = f"""
const assert = require('assert');
const vm = require('vm');
const registered = [];
const messages = [];
const ui = {{}};
const document = {{modelContext: {{registerTool: async (tool) => registered.push(tool)}}}};
const setText = (id, value) => {{ui[id] = value; messages.push(value)}};
const context = {{assert, registered, messages, document, setText, ui, byId: () => null, latestGraphOpsPayload: null}};
const checks = {json.dumps(names)} + '\\n' + {json.dumps(source)} + '\\n' + `(async () => {{
  await registerFactoryWebMcp();
  assert.strictEqual(JSON.stringify(registered.map((tool) => tool.name)), JSON.stringify(WEBMCP_TOOL_NAMES));
  assert.strictEqual(registered.length, WEBMCP_TOOL_NAMES.length);
  const deepTool = registered.find((tool) => tool.name === 'factory.deep_audit_status');
  const runtimeTool = registered.find((tool) => tool.name === 'factory.runtime_audit_status');
  assert(deepTool && runtimeTool);
  for (const tool of registered) {{
    assert.strictEqual(tool.annotations.readOnlyHint, true);
    assert.strictEqual(tool.annotations.untrustedContentHint, true);
    assert.strictEqual(tool.inputSchema.additionalProperties, false);
  }}
  const unavailable = await deepTool.execute({{}});
  assert.strictEqual(unavailable.marker, 'FACTORY_WEBMCP_DATA_UNAVAILABLE');
  for (const invalid of [null, [], 'malformed', 1]) {{
    latestGraphOpsPayload = {{deep_audit: invalid, mission_control: {{evidence: {{runtime_assurance: invalid}}}}}};
    assert.strictEqual((await deepTool.execute({{}})).marker, 'FACTORY_WEBMCP_DATA_UNAVAILABLE');
    assert.strictEqual((await runtimeTool.execute({{}})).marker, 'FACTORY_WEBMCP_DATA_UNAVAILABLE');
  }}
  latestGraphOpsPayload = {{
    deep_audit: {{state: 'READY_FOR_HUMAN_REVIEW', chains: [{{finding_id: 'private-finding', source: 'C:/private/source.py',
      receipt_path: 'C:/private/receipt.json', repair_command: 'private repair'}}], receipt_sha256: 'a'.repeat(64), authority: 'none'}},
    mission_control: {{evidence: {{runtime_assurance: {{schema: 'factory.runtime-audit-status.v1',
      state: 'READY_FOR_HUMAN_REVIEW', lanes: Array.from({{length: 6}}, () => ({{lane_id: 'private-lane', state: 'PASS', repair_command: 'private repair'}})),
      receipt_sha256: 'c'.repeat(64), candidate_sha256: 'd'.repeat(64), authority: 'none'}}}}}}
  }};
  const deep = await deepTool.execute({{}});
  const runtime = await runtimeTool.execute({{}});
  assert.strictEqual(deep.state, 'READY_FOR_HUMAN_REVIEW');
  assert.strictEqual(deep.finding_count, null);
  assert.strictEqual(deep.chain_count, 1);
  assert.strictEqual(deep.candidate_sha256, null);
  assert.strictEqual(runtime.state, 'READY_FOR_HUMAN_REVIEW');
  assert.strictEqual(runtime.finding_count, null);
  assert.strictEqual(runtime.lane_count, 6);
  assert.strictEqual(runtime.receipt_sha256, 'c'.repeat(64));
  assert.strictEqual(runtime.candidate_sha256, 'd'.repeat(64));
  for (const result of [deep, runtime]) {{
    assert.strictEqual(JSON.stringify(Object.keys(result).sort()),
      JSON.stringify(['authority','candidate_sha256','chain_count','claim_boundary','finding_count','lane_count','marker','receipt_sha256','state','tool'].sort()));
    assert(Object.values(result.authority).every((value) => value === false));
    assert(!JSON.stringify(result).includes('private'));
    assert(!JSON.stringify(result).includes('repair'));
    assert(!JSON.stringify(result).includes('source.py'));
  }}
  assert.strictEqual(deep.receipt_sha256, 'a'.repeat(64));
  latestGraphOpsPayload = {{
    deep_audit: {{state: 'EXECUTE', finding_count: -1, chains: [{{}}], receipt_sha256: 'A'.repeat(64), candidate_sha256: 'b'.repeat(63)}},
    mission_control: {{evidence: {{runtime_assurance: {{state: 'PASS', finding_count: Number.POSITIVE_INFINITY,
      lanes: [{{}}], receipt_sha256: 'g'.repeat(64), candidate_sha256: null}}}}}}
  }};
  const invalidDeep = await deepTool.execute({{}});
  const invalidRuntime = await runtimeTool.execute({{}});
  assert.strictEqual(invalidDeep.state, 'UNKNOWN');
  assert.strictEqual(invalidDeep.finding_count, null);
  assert.strictEqual(invalidDeep.receipt_sha256, null);
  assert.strictEqual(invalidDeep.candidate_sha256, null);
  assert.strictEqual(invalidRuntime.state, 'UNKNOWN');
  assert.strictEqual(invalidRuntime.finding_count, null);
  assert.strictEqual(invalidRuntime.receipt_sha256, null);
  assert.strictEqual(invalidRuntime.candidate_sha256, null);
  const label = 'Review <script>' + 'x'.repeat(300);
  latestGraphOpsPayload = {{graph_sha256: 'e'.repeat(64), recommendation: 'legacy', mission_control: {{state: 'review_required',
    human_control_plane: {{next_action: 'old human action'}}, daily_action: {{schema: 'factory.daily-action.v1', evidence_state: 'review_required',
      audit_state: 'PLAN_ONLY', execution: 'NOT_RUN', proof_counts: {{RUN: 1, REUSE: 2, SKIP: 3, BLOCK: 0}},
      primary_action: {{id: 'private-id', label, command: 'C:/private/secret'}}, private_status: 'private'}}}}}};
  renderControlPlane(latestGraphOpsPayload);
  const next = boundedNextAction();
  assert.strictEqual(ui['control-plane-next'], label.slice(0, 256));
  assert.strictEqual(next.recommendation, ui['control-plane-next']);
  assert.deepStrictEqual(Object.keys(next.daily_action).sort(), ['audit_state','evidence_state','execution','primary_action','proof_counts'].sort());
  assert.deepStrictEqual(next.daily_action.proof_counts, {{RUN: 1, REUSE: 2, SKIP: 3, BLOCK: 0}});
  assert(!JSON.stringify(next).includes('private') && !JSON.stringify(next).includes('command'));
  assert(Object.values(next.authority).every((value) => value === false));
  const daily = latestGraphOpsPayload.mission_control.daily_action;
  for (const proof_counts of [null, [], {{RUN: Infinity, REUSE: 0, SKIP: 0, BLOCK: 0}}]) {{ daily.proof_counts = proof_counts; assert.strictEqual(boundedDailyAction(latestGraphOpsPayload), null); }}
  daily.proof_counts = {{RUN: 1, REUSE: 2, SKIP: 3, BLOCK: 0}}; daily.evidence_state = 'PRIVATE';
  assert.strictEqual(boundedDailyAction(latestGraphOpsPayload), null);
  latestGraphOpsPayload = {{mission_control: {{human_control_plane: {{next_action: 'old human action'}}, daily_action: {{primary_action: {{label: 'ignored'}}}}}}, recommendation: 'legacy'}};
  renderControlPlane(latestGraphOpsPayload);
  assert.strictEqual(ui['control-plane-next'], 'old human action');
  assert.strictEqual(boundedNextAction().recommendation, 'legacy');
  globalThis.testOutcome = {{registered: registered.length, projections: 2, unavailable: 8, all_authority_false: true}};
}})()`;
(async () => {{ await vm.runInNewContext(checks, context, {{timeout: 5000}}); console.log(JSON.stringify(context.testOutcome)); }})()
  .catch((error) => {{ console.error(error); process.exitCode = 1; }});
"""
    artifact_dir = ROOT / ".factory" / "mcp-refresh"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".cjs", encoding="utf-8", dir=artifact_dir, delete=False
    ) as node_script:
        node_script.write(script)
        script_path = Path(node_script.name)
    try:
        result = subprocess.run(
            [node, str(script_path)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
    finally:
        script_path.unlink(missing_ok=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "registered": 16,
        "projections": 2,
        "unavailable": 8,
        "all_authority_false": True,
    }
