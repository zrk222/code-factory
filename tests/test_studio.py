from __future__ import annotations

import hashlib
import json
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from pathlib import Path

import pytest

from factoryline.meter import MeterLog, StageTiming
from factoryline.app_builder import (
    _studio_execute_plan,
    serve_studio_preview_asset,
    studio_journey_plan,
    studio_journey_status,
)
from factoryline.studio import (
    MAX_BODY_BYTES,
    StudioRequestError,
    continue_from_studio,
    create_from_studio,
    create_product_mission_from_studio,
    create_server,
    decide_product_mission_from_studio,
    developer_memory_snapshot,
    make_handler,
    savings_from_studio,
    serve_studio,
    studio_dashboard,
    studio_status,
)


def _studio_bound_candidate(tmp_path: Path):
    from test_product_missions import _approved_binding_inputs
    from factoryline.product_missions import bind_mission_candidate

    mission, decision, candidate, declaration = _approved_binding_inputs(tmp_path)
    declaration["paths"] = ["README.md"]
    binding = bind_mission_candidate(
        Path(mission["path"]),
        Path(decision["path"]),
        tmp_path,
        owner="release-owner",
        declaration=declaration,
    )
    return candidate, declaration, binding


def test_journey_status_and_plan_require_current_binding_and_exact_command(
    tmp_path: Path,
):
    candidate, declaration, binding = _studio_bound_candidate(tmp_path)
    payload = {"binding_path": binding["path"], "owner": "release-owner"}
    status = studio_journey_status(tmp_path, payload)
    assert status["complete_application"] is False
    assert all(
        status["stages"][name]["state"] == "missing_evidence"
        for name in ("build", "preview", "verification", "repair")
    )
    assert status["commands"] == [declaration["commands"][0]["argv"]]
    with pytest.raises(ValueError, match="command_index"):
        studio_journey_plan(
            tmp_path,
            {**payload, "stage": "build", "image": "python@sha256:" + "a" * 64},
        )
    plan = studio_journey_plan(
        tmp_path,
        {
            **payload,
            "stage": "build",
            "command_index": 0,
            "image": "python@sha256:" + "a" * 64,
        },
    )
    assert plan["argv"] == status["commands"][0]
    assert plan["candidate_sha256"] == status["candidate_sha256"]
    (candidate / "README.md").write_text("changed", encoding="utf-8")
    with pytest.raises(Exception, match="MISSION_CANDIDATE_INVALID"):
        studio_journey_status(tmp_path, payload)


def test_journey_preview_is_candidate_declared_regular_file_only(tmp_path: Path):
    _candidate, declaration, binding = _studio_bound_candidate(tmp_path)
    result = serve_studio_preview_asset(
        tmp_path, Path(binding["path"]), "release-owner", "README.md"
    )
    assert result["content"].replace("\r\n", "\n") == "candidate base\n"
    assert result["sandbox"] == "allow-scripts"
    assert result["parent_origin_access"] is False
    with pytest.raises(ValueError, match="not declared"):
        serve_studio_preview_asset(
            tmp_path, Path(binding["path"]), "release-owner", "../outside"
        )


def test_journey_execution_requires_exact_confirmation_and_cleans_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from factoryline import app_builder

    _candidate, _declaration, binding = _studio_bound_candidate(tmp_path)
    plan = studio_journey_plan(
        tmp_path,
        {
            "binding_path": binding["path"],
            "owner": "release-owner",
            "stage": "build",
            "command_index": 0,
            "image": "python@sha256:" + "a" * 64,
        },
    )
    base = {
        "plan_path": plan["path"],
        "plan_sha256": plan["plan_sha256"],
        "owner": "release-owner",
    }
    with pytest.raises(ValueError, match="confirmation"):
        _studio_execute_plan(tmp_path, {**base, "confirmed": False})
    calls = []

    def runner(cli, args, cwd, **kwargs):
        calls.append((cli, args, kwargs))
        if args[0] == "inspect":
            return {
                "ok": False,
                "exit_code": 1,
                "cleanup_confirmed": True,
                "stdout": b"",
                "stderr": b"no such container",
            }
        return {
            "ok": True,
            "exit_code": 0,
            "cleanup_confirmed": True,
            "streams_closed": True,
            "stdout": b"ok",
            "stderr": b"",
        }

    monkeypatch.setattr(app_builder, "run_cli_detailed", runner)
    receipt = _studio_execute_plan(tmp_path, {**base, "confirmed": True})
    assert receipt["ok"] is True
    assert receipt["cleanup_confirmed"] is True
    docker = calls[0][1]
    for flag in (
        "--network=none",
        "--read-only",
        "--memory=512m",
        "--pids-limit=64",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
    ):
        assert flag in docker
    assert "--rm" not in docker
    assert calls[1][1][:2] == ["rm", "--force"]
    assert calls[2][1][:2] == ["inspect", "--type"]


def test_journey_rejects_tampered_plan_and_root_relative_binding(tmp_path: Path):
    _candidate, _declaration, binding = _studio_bound_candidate(tmp_path)
    relative_binding = Path(binding["path"]).relative_to(tmp_path)
    status = studio_journey_status(
        tmp_path, {"binding_path": str(relative_binding), "owner": "release-owner"}
    )
    plan = studio_journey_plan(
        tmp_path,
        {
            "binding_path": binding["path"],
            "owner": "release-owner",
            "stage": "build",
            "command_index": 0,
            "image": "python@sha256:" + "a" * 64,
        },
    )
    raw = json.loads(Path(plan["path"]).read_text(encoding="utf-8"))
    raw["receipt"]["image"] = "evil:latest"
    Path(plan["path"]).write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="integrity"):
        _studio_execute_plan(
            tmp_path,
            {
                "plan_path": plan["path"],
                "plan_sha256": plan["plan_sha256"],
                "confirmed": True,
                "owner": "release-owner",
            },
        )
    assert status["complete_application"] is False


def test_journey_preview_enforces_csp_in_html_and_rejects_binary(tmp_path: Path):
    from test_product_missions import _approved_binding_inputs
    from factoryline.product_missions import bind_mission_candidate

    mission, decision, candidate, declaration = _approved_binding_inputs(tmp_path)
    (candidate / "index.html").write_text(
        "<!doctype html><html><head><title>Test</title></head><body>ok</body></html>",
        encoding="utf-8",
    )
    import subprocess

    subprocess.run(["git", "-C", str(candidate), "add", "index.html"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(candidate),
            "-c",
            "user.name=Test Owner",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "preview asset",
        ],
        check=True,
    )
    declaration["base_commit"] = subprocess.run(
        ["git", "-C", str(candidate), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    declaration["paths"] = ["index.html"]
    binding = bind_mission_candidate(
        Path(mission["path"]),
        Path(decision["path"]),
        tmp_path,
        owner="release-owner",
        declaration=declaration,
    )
    result = serve_studio_preview_asset(
        tmp_path, Path(binding["path"]), "release-owner", "index.html"
    )
    assert "Content-Security-Policy" in result["content"]
    assert "connect-src 'none'" in result["content"]
    assert "<title>Test</title>" in result["content"]
    (candidate / "index.html").write_bytes(b"\x00\xff")
    with pytest.raises(Exception, match="MISSION_CANDIDATE_INVALID"):
        serve_studio_preview_asset(
            tmp_path, Path(binding["path"]), "release-owner", "index.html"
        )


def test_studio_dual_track_defaults_to_instant_mvp_and_keeps_pro_controls_visible():
    from factoryline.studio import _studio_html

    page = _studio_html("session-token")

    assert "FACTORY_DUAL_TRACK_START" in page
    assert "Instant MVP" in page
    assert "Professional workflow" in page
    assert "GRAPH_OPS_UNIFIED_READ_ONLY" in page
    assert "else setMode('starter')" in page
    assert "Build my MVP" in page
    assert "Prior measured runs" in page
    assert "Request safe stop" in page
    assert "Memory Spine: next safe proof" in page
    assert "Refresh stats and proof brief" in page
    assert "Refresh team attribution" in page
    assert "renderStudioMemory(payload.developer_memory)" in page
    assert "fetch('/api/developer-memory'" in page
    assert "profile.approval}`])));rows('authority-list'" in page
    assert "innerHTML" not in page


def test_studio_assembly_uses_shared_continuation_and_preserves_authority(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        "factoryline.studio.continue_assembly",
        lambda root, feature: {
            "status": "waiting_for_human",
            "feature": feature,
            "next_action": {"label": "Review"},
        },
    )
    result = continue_from_studio(tmp_path, {"action": "continue", "feature": "sample"})
    assert result["studio_marker"] == "STUDIO_ASSEMBLY_CONTAINED"
    assert result["status"] == "waiting_for_human"
    status = studio_status(tmp_path, 0)
    assert status["authority"]["can_continue_assembly_to_human_boundary"] is True
    assert status["authority"]["can_publish"] is False


def test_studio_savings_records_exact_pair_and_rejects_path_escape(tmp_path):
    result = savings_from_studio(
        tmp_path,
        {
            "action": "savings-record",
            "pair_id": "studio-pair",
            "baseline_elapsed_ms": 1000,
            "factory_elapsed_ms": 600,
            "baseline_tokens": 100,
            "factory_tokens": 70,
        },
    )
    assert result["studio_marker"] == "SAVINGS_STUDIO_CONTAINED"
    assert result["savings"]["time_saved_ms"] == 400
    assert studio_dashboard(tmp_path)["savings"]["tokens"]["saved_total"] == 30
    with pytest.raises(StudioRequestError, match="PATH_REJECTED"):
        savings_from_studio(
            tmp_path,
            {
                "action": "savings-record",
                "pair_id": "escape",
                "baseline_elapsed_ms": 1,
                "factory_elapsed_ms": 1,
                "equivalent_outcome": True,
                "evidence": "../private.txt",
            },
        )


def test_studio_status_is_exact_and_loopback_only(tmp_path: Path):
    status = studio_status(tmp_path, 4321)
    assert status["marker"] == "STUDIO_STATUS_EXACT"
    assert status["listener"] == {
        "host": "127.0.0.1",
        "port": 4321,
        "production": False,
    }
    assert status["limits"]["overwrite"] is False
    assert status["authority"]["can_deploy"] is False
    assert status["authority"]["can_inject_credentials"] is False

    server, _token = create_server(tmp_path)
    try:
        assert server.server_address[0] == "127.0.0.1"
    finally:
        server.server_close()


def test_dashboard_preserves_unknowns_and_exposes_control_state(tmp_path: Path):
    dashboard = studio_dashboard(tmp_path)
    assert dashboard["schema"] == "factory.studio.dashboard.v1"
    assert dashboard["meter"]["summary"]["stages_measured"] == 0
    assert dashboard["meter"]["activity"]["stage_success_rate"] is None
    assert dashboard["approvals"]["awaiting_owner"] == 0
    assert len(dashboard["packs"]) == 29
    assert all(
        pack["signature_verified"] and pack["mutations_rejected"] == 10
        for pack in dashboard["packs"]
    )
    assert all(pack["deployment_profiles"] for pack in dashboard["packs"])
    assert dashboard["authority"]["can_deploy"] is False
    assert dashboard["developer_memory"]["marker"] == "DEVELOPER_MEMORY_STUDIO_CACHED"
    assert (
        dashboard["developer_memory"]["brief"]["schema"]
        == "factory.developer-memory-brief.v1"
    )
    assert "STUDIO_DEVELOPER_MEMORY_VISIBLE" in dashboard["markers"]
    repeated = developer_memory_snapshot(tmp_path)
    assert repeated["cache"]["state"] == "reused"
    assert repeated["cache"]["refresh_interval_ms"] == 5000


def test_studio_audit_http_flow_is_token_bound_and_prepares_selected_proposal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from factoryline import studio
    from test_repair_sandbox import _selected_origin

    run_id, finding_id, _origin = _selected_origin(tmp_path, monkeypatch)
    projection = {
        "state": "INCOMPLETE",
        "run_id": run_id,
        "state_content_sha256": "d" * 64,
        "candidate_sha256": "c" * 64,
        "observed_state": "RUNNING",
        "repair_tasks": [
            {
                "finding_id": finding_id,
                "rule_id": "sample-rule",
                "severity": "high",
                "path": "src/value.py",
                "line": 1,
                "remediation": "Inspect this selected finding.",
            }
        ],
        "truncated": False,
    }
    monkeypatch.setattr(
        studio, "deep_scan_projection", lambda _root: (projection, None)
    )
    monkeypatch.setattr(
        studio,
        "pause_deep_run",
        lambda _root, value: {"run_id": value, "state": "PAUSE_REQUESTED"},
    )
    server, token = create_server(tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    conn = HTTPConnection("127.0.0.1", server.server_port, timeout=3)

    def call(method, path, body=None, *, authenticated=True):
        headers = {}
        if authenticated:
            headers["X-Factory-Studio-Token"] = token
        if body is not None:
            headers["Content-Type"] = "application/json"
        conn.request(
            method, path, json.dumps(body) if body is not None else None, headers
        )
        response = conn.getresponse()
        data = response.read()
        try:
            body = json.loads(data) if data else None
        except json.JSONDecodeError:
            body = data.decode("utf-8")
        return response.status, body

    try:
        assert call("GET", "/api/studio-audit", authenticated=False)[0] == 403
        assert call("GET", "/api/studio-audit") == (200, projection)
        assert call("GET", "/studio_audit.js")[0] == 200
        status, active = call(
            "POST",
            "/api/studio-audit/prepare",
            {
                "run_id": run_id,
                "expected_state_content_sha256": "d" * 64,
                "finding_ids": [finding_id],
            },
        )
        assert status == 409 and active["code"] == "AUDIT_ACTIVE"
        status, pause = call(
            "POST",
            "/api/studio-audit/pause",
            {"run_id": run_id, "expected_state_content_sha256": "d" * 64},
        )
        assert status == 201 and pause["state"] == "PAUSE_REQUESTED"
        projection["observed_state"] = "INCOMPLETE"
        assert (
            call(
                "POST",
                "/api/studio-audit/prepare",
                {
                    "run_id": run_id,
                    "expected_state_content_sha256": "e" * 64,
                    "finding_ids": [finding_id],
                },
            )[0]
            == 409
        )
        status, malformed = call(
            "POST",
            "/api/studio-audit/prepare",
            {
                "run_id": run_id,
                "expected_state_content_sha256": "d" * 64,
                "finding_ids": [finding_id],
                "out_dir": "../outside",
            },
        )
        assert status == 400 and malformed["code"] == "AUDIT_REQUEST_INVALID"
        status, invalid = call(
            "POST",
            "/api/studio-audit/prepare",
            {
                "run_id": run_id,
                "expected_state_content_sha256": "d" * 64,
                "finding_ids": ["f" * 64],
            },
        )
        assert status == 409 and invalid["code"] == "REPAIR_SCOPE_REJECTED"
        status, proposal = call(
            "POST",
            "/api/studio-audit/prepare",
            {
                "run_id": run_id,
                "expected_state_content_sha256": "d" * 64,
                "finding_ids": [finding_id],
            },
        )
        assert status == 201, proposal
        assert proposal["finding_ids"] == [finding_id]
        assert set(proposal["paths"].values()) == {
            f".factory/repair-scopes/{proposal['scope_id']}.json",
            f".factory/repair-scopes/{proposal['scope_id']}.md",
            f".factory/repair-scopes/{proposal['scope_id']}.mmd",
        }
        saved = json.loads((tmp_path / proposal["paths"]["json"]).read_text())
        assert saved["finding_ids"] == [finding_id]
        assert saved["authority"]["patch_apply"] is False
    finally:
        conn.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_request_studio_audit_pause_preserves_bound_state(tmp_path, monkeypatch):
    from factoryline import studio

    projection = {
        "run_id": "a" * 32,
        "state_content_sha256": "b" * 64,
        "observed_state": "RUNNING",
    }
    monkeypatch.setattr(studio, "deep_scan_projection", lambda root: (projection, None))
    calls = []

    def pause(root, run_id):
        calls.append((root, run_id))
        return {"run_id": run_id, "state": "PAUSE_REQUESTED"}

    monkeypatch.setattr(studio, "pause_deep_run", pause)
    payload = {
        "run_id": projection["run_id"],
        "expected_state_content_sha256": projection["state_content_sha256"],
    }
    assert studio.request_studio_audit_pause(tmp_path, payload) == {
        "run_id": projection["run_id"],
        "state": "PAUSE_REQUESTED",
    }
    assert calls == [(tmp_path, projection["run_id"])]
    for changed in ({**payload, "run_id": "c" * 32}, {**payload, "extra": True}):
        with pytest.raises(StudioRequestError):
            studio.request_studio_audit_pause(tmp_path, changed)
    projection["observed_state"] = "PAUSE_REQUESTED"
    with pytest.raises(StudioRequestError, match="AUDIT_NOT_RUNNING"):
        studio.request_studio_audit_pause(tmp_path, payload)
    assert calls == [(tmp_path, projection["run_id"])]


def test_studio_audit_refresh_preserves_selection_and_focus(tmp_path: Path):
    import shutil
    import subprocess

    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for the Studio JavaScript execution profile")
    script = tmp_path / "audit-refresh.cjs"
    script.write_text(
        r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.checked = false; }
  set textContent(value) { this.text = value; this.children = []; }
  setAttribute() {}
  append(...items) { this.children.push(...items); }
  appendChild(item) { this.append(item); }
  prepend(item) { this.children.unshift(item); }
  replaceChildren(...items) { this.children = items; }
  addEventListener() {}
  querySelectorAll() {
    return this.children.flatMap(item => [
      ...(item.tag === 'input' && item.checked ? [item] : []),
      ...item.querySelectorAll()
    ]);
  }
  querySelector() { return this.querySelectorAll()[0]; }
}
const grid = new Element('grid');
const document = { querySelector: () => grid, createElement: tag => new Element(tag) };
let refresh, fail = false;
let projection = {run_id: 'run-1', state_content_sha256: 'hash-1', state: 'INCOMPLETE',
  observed_state: 'INCOMPLETE', repair_tasks: [{finding_id: 'finding-1',
    rule_id: 'rule', path: 'src/a.py', severity: 'HIGH', remediation: 'Review'}]};
const context = {document, token: 'local-test', window: {setInterval: fn => {refresh = fn;}},
  fetch: async () => {if (fail) throw new Error('offline');
    return {ok: true, json: async () => structuredClone(projection)};}};
const inputs = element => element.children.flatMap(child =>
  [...(child.tag === 'input' ? [child] : []), ...inputs(child)]);
const settle = () => new Promise(resolve => setImmediate(resolve));
(async () => {
  vm.runInNewContext(fs.readFileSync(process.argv[2], 'utf8'), context);
  await settle();
  const box = inputs(grid)[0];
  assert.ok(box);
  box.checked = true;
  document.activeElement = box;
  await refresh();
  assert.equal(inputs(grid)[0], box, 'unchanged projection must retain DOM identity');
  assert.equal(box.checked, true, 'selection must survive the polling interval');
  assert.equal(document.activeElement, box, 'polling must not replace focused input');
  projection.state_content_sha256 = 'hash-2';
  await refresh();
  assert.notEqual(inputs(grid)[0], box, 'changed evidence must invalidate selection');
  assert.equal(inputs(grid)[0].checked, false);
  fail = true;
  await refresh();
  fail = false;
  await refresh();
  assert.equal(inputs(grid).length, 1, 'same projection must render after recovery');
})().catch(error => {console.error(error); process.exitCode = 1;});
""",
        encoding="utf-8",
    )
    asset = Path(__file__).parents[1] / "factoryline" / "studio_audit.js"
    subprocess.run([node, str(script), str(asset)], check=True, timeout=10)


def test_studio_audit_active_pause_state_and_package_asset_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from factoryline import studio

    running = {
        "state": "INCOMPLETE",
        "run_id": "a" * 32,
        "state_content_sha256": "b" * 64,
        "observed_state": "RUNNING",
        "repair_tasks": [{"finding_id": "c" * 64}],
    }
    monkeypatch.setattr(studio, "deep_scan_projection", lambda _root: (running, None))
    with pytest.raises(StudioRequestError, match="AUDIT_ACTIVE"):
        studio.prepare_studio_repair_scope(
            tmp_path,
            {
                "run_id": running["run_id"],
                "expected_state_content_sha256": running["state_content_sha256"],
                "finding_ids": ["c" * 64],
            },
        )
    package_data = Path("pyproject.toml").read_text(encoding="utf-8")
    manifest = Path("MANIFEST.in").read_text(encoding="utf-8")
    asset = Path(studio.__file__).with_name("studio_audit.js")
    assert asset.is_file() and asset.stat().st_size <= 6500
    assert (
        "studio_audit.js" in package_data and "factoryline/studio_audit.js" in manifest
    )


def test_context_value_reports_unknowns_without_promising_target(tmp_path):
    value = studio_dashboard(tmp_path)["context_engine"]
    assert value["schema"] == "factory.studio.context-value.v1"
    assert value["target_latency_reduction"] == 0.5
    assert value["observed_latency_reduction"] is None
    assert value["observed_cost_delta"] is None
    assert "target, not an observed result" in value["claim_boundary"]
    assert value["next_action"]


def test_context_value_projects_only_finite_aggregate_fields(tmp_path, monkeypatch):
    from factoryline.studio import _context_engine_value, _studio_html

    monkeypatch.setattr(
        "factoryline.context_efficiency.context_efficiency_status",
        lambda root: {
            "state": "READY",
            "packet_count": 2,
            "cache_hits": 3,
            "paired_sample_count": 4,
            "observed_latency_reduction": 0.25,
            "observed_cost_delta": -0.03,
            "observed_token_delta": float("nan"),
            "estimated_tokens": True,
            "packets": [{"excerpt": "private body"}],
        },
    )
    value = _context_engine_value(tmp_path)
    assert value["observed_latency_reduction"] == 0.25
    assert value["observed_cost_delta"] == -0.03
    assert value["observed_token_delta"] is None
    assert value["estimated_tokens"] is None
    assert "private body" not in json.dumps(value)
    page = _studio_html("local-token")
    assert "Context engine: measured user value" in page
    assert 'aria-live="polite"' in page
    assert "renderContextValue(payload.context_engine)" in page
    assert "Previous metrics have been cleared" in page


def test_dashboard_lists_prior_measured_runs_without_inferring_success(tmp_path: Path):
    ledger = MeterLog(tmp_path)
    ledger.record(
        StageTiming(
            module="spec",
            stage="validate",
            wall_ms=125,
            model_calls=0,
            tokens_in=0,
            tokens_out=0,
            ok=True,
            feature="approval-tracker",
            run_id="run-earlier",
            recorded_at="2026-08-18T10:00:00+00:00",
        )
    )
    ledger.record(
        StageTiming(
            module="verify",
            stage="tests",
            wall_ms=250,
            model_calls=1,
            tokens_in=40,
            tokens_out=20,
            ok=False,
            feature="approval-tracker",
            run_id="run-latest",
            recorded_at="2026-08-18T11:00:00+00:00",
        )
    )

    runs = studio_dashboard(tmp_path)["recent_runs"]

    assert [item["run_id"] for item in runs] == ["run-latest", "run-earlier"]
    assert runs[0]["outcome"] == "failed_stage_observed"
    assert runs[0]["tokens"] == 60
    assert runs[0]["cost_usd"] is None


def test_studio_contains_output_and_forbids_promotion(tmp_path: Path):
    result = create_from_studio(
        tmp_path,
        {
            "action": "create",
            "target": "worker",
            "prompt": "Build a deterministic inbox worker.",
            "name": "inbox-worker",
            "deployment_profile": "container-host",
        },
    )
    assert result["studio_marker"] == "STUDIO_CONTAINED"
    assert Path(result["out_dir"]).parent == tmp_path.resolve()
    assert result["deployment"]["selected_profile_id"] == "container-host"
    assert result["deployment"]["external_effects_authorized"] is False

    with pytest.raises(StudioRequestError, match="PATH_REJECTED"):
        create_from_studio(
            tmp_path,
            {
                "action": "create",
                "target": "worker",
                "prompt": "Build another worker.",
                "name": "../escaped",
            },
        )
    with pytest.raises(StudioRequestError, match="ACTION_FORBIDDEN"):
        create_from_studio(tmp_path, {"action": "publish"})
    assert not (tmp_path.parent / "escaped").exists()


def test_studio_compiles_a_contained_supervised_product_mission(tmp_path: Path):
    from test_product_missions import PRD

    result = create_product_mission_from_studio(
        tmp_path,
        {
            "action": "product-mission",
            "prompt": PRD,
            "name": "signal-desk",
            "executor": "codex",
            "owner": "product-owner",
            "resolution_mode": "auto_resolve_safe",
        },
    )
    assert result["studio_marker"] == "STUDIO_PRODUCT_MISSION_CONTAINED"
    assert result["mission"]["approval_state"] == "required_before_execution"
    assert result["mission"]["authority"]["merge"] is False
    assert result["approval"]["state"] == "ready_for_human_decision"
    assert result["approval"]["authority_after_approval"]["deploy"] is False
    assert result["resolution"]["mode"] == "auto_resolve_safe"
    assert Path(result["mission"]["path"]).is_relative_to(tmp_path)

    decision = decide_product_mission_from_studio(
        tmp_path,
        {
            "action": "mission-decision",
            "mission": result["mission"]["path"],
            "owner": "product-owner",
            "decision": "approved_execution",
            "rationale": "The bounded mission and budget are ready.",
        },
    )
    assert decision["execution_authorized"] is True
    assert decision["authority"]["merge"] is False

    dashboard = studio_dashboard(tmp_path)
    assert dashboard["products"][0]["journeys"]
    assert dashboard["slice_queue"][0]["priority"] >= 0
    assert ".factory/worktrees/" in dashboard["missions"][0]["worktree"].replace(
        "\\", "/"
    )
    assert dashboard["missions"][0]["branch"].startswith("codex/")
    assert dashboard["proof_timeline"][0]["requirement_id"]
    assert dashboard["receipt_comparison"]["status"] == "insufficient_runs"


def test_approved_studio_mission_returns_exact_bound_agent_handoff(tmp_path: Path):
    from test_product_missions import PRD

    planned = create_product_mission_from_studio(
        tmp_path,
        {
            "action": "product-mission",
            "prompt": PRD,
            "name": "handoff-proof",
            "executor": "codex",
            "owner": "owner",
        },
    )
    mission_path = Path(planned["mission"]["path"])
    source = json.loads(mission_path.read_bytes())
    decision = decide_product_mission_from_studio(
        tmp_path,
        {
            "action": "mission-decision",
            "mission": str(mission_path),
            "owner": "owner",
            "decision": "approved_execution",
            "rationale": "Implement this bounded slice.",
        },
    )
    handoff = decision["agent_handoff"]
    assert (
        handoff["candidate_binding"]["bind_command"] == "factory mission bind-candidate"
    )
    assert (
        handoff["candidate_binding"]["verify_command"]
        == "factory mission verify-candidate"
    )
    assert handoff["candidate_binding"]["operator_input_required"] is False
    assert handoff["candidate_binding"]["execution_authorized"] is False
    assert handoff["task_packet"] == source["task_packet"]
    assert handoff["mission"] == decision["mission"]
    assert handoff["decision"]["sha256"] == decision["decision_sha256"]
    assert handoff["executor"] == "codex"
    assert handoff["dispatched"] is False
    assert handoff["state"] == "approved_needs_candidate_binding"
    assert (
        handoff["candidate_binding"]["repair_command"]
        == "factory mission execute-repair"
    )
    assert "Separate exact" in handoff["candidate_binding"]["repair_prerequisite"]
    guidance = handoff["acceptance_guidance"]
    assert len(guidance["starter_scenarios"]) == 5
    assert "reload" in guidance["starter_scenarios"][2].lower()
    assert "account or workspace" in guidance["custom_scenarios"]
    assert any("disposable test data" in step for step in guidance["protocol"])
    assert any("exact candidate" in step for step in guidance["protocol"])
    assert any("Invalidate prior results" in step for step in guidance["protocol"])
    assert handoff["verify_argv"] == [
        "factory",
        "mission",
        "verify",
        str(mission_path),
        "--json",
    ]
    assert "exact permitted paths" in handoff["instructions"][1]
    persisted = json.loads(Path(decision["path"]).read_bytes())
    assert "agent_handoff" not in persisted


def test_studio_handoff_requires_approval_and_exact_mission_bytes():
    from factoryline.studio import _mission_agent_handoff

    assert (
        _mission_agent_handoff(Path("mission.json"), b"", {"decision": "deferred"})
        is None
    )
    assert (
        _mission_agent_handoff(Path("mission.json"), b"", {"decision": "rejected"})
        is None
    )
    with pytest.raises(StudioRequestError, match="MISSION_INPUT_DRIFT"):
        _mission_agent_handoff(
            Path("mission.json"),
            b"changed",
            {
                "decision": "approved_execution",
                "mission": {"file_sha256": "0" * 64},
            },
        )


def test_studio_handoff_ui_is_explicit_readonly_and_never_dispatches():
    from factoryline.studio import _studio_html

    page = _studio_html("token")
    assert "renderAgentHandoff(payload.agent_handoff)" in page
    assert "Nothing has been dispatched" in page
    assert "input.readOnly=true" in page
    assert "input.value=JSON.stringify(handoff,null,2)" in page
    assert "input.onclick=()=>input.select()" in page
    assert "Beginner acceptance checks:" in page
    assert "Build success is not proof that your app works." in page
    assert "Approve this exact" in page
    assert "guidedButton('Run'" not in page


def test_guided_resume_renders_restored_agent_handoff():
    from factoryline.studio import _studio_html

    page = _studio_html("token")
    render_guided = page.split("function renderGuided(payload)", 1)[1].split(
        "async function confirmGuided", 1
    )[0]
    assert "renderAgentHandoff(payload.agent_handoff)" in render_guided


def test_studio_mission_decision_uses_inline_required_rationale():
    from factoryline.studio import _studio_html

    page = _studio_html("token")
    decision_function = page.split("async function decideMission(decision)", 1)[
        1
    ].split("function renderAgentHandoff", 1)[0]
    assert "window.prompt(" not in decision_function
    assert "rationaleLabel.htmlFor='mission-rationale'" in page
    assert "rationaleInput.maxLength=4000" in page
    assert "Explain this decision before continuing" in page
    assert "rationaleInput.oninput=()=>rationaleInput.setCustomValidity('')" in page


def test_studio_decision_serializes_requests_and_ignores_stale_responses():
    from factoryline.studio import _studio_html

    page = _studio_html("token")
    action = page.split("async function decideMission(decision)", 1)[1].split(
        "function renderAgentHandoff", 1
    )[0]
    assert "if(missionDecisionBusy||!currentMission||!rationaleInput)return" in action
    assert "generation!==guidedGeneration||currentMission!==mission" in action
    assert "finally{missionDecisionBusy=false" in action
    assert "DECISION_STATUS_UNKNOWN" in action
    assert "may have been recorded" in action


def test_dashboard_mission_decisions_use_an_in_page_rationale_form():
    from factoryline.studio import _studio_html

    page = _studio_html("token")
    interaction = page.split("function dashboardDecisionReasons", 1)[1].split(
        "async function decideMission(decision)", 1
    )[0]
    assert all(call not in interaction for call in ("window.prompt(", "window.alert("))
    open_action = page.split("function decideDashboardMission", 1)[1].split(
        "function cancelDashboardMissionDecision", 1
    )[0]
    assert "fetch(" not in open_action
    assert "Choose a starting point" in interaction
    assert "Write a custom reason" in interaction
    assert "Confirm decision" in interaction
    assert "Cancel" in interaction
    assert "I reviewed the bounded scope and budget" in interaction
    assert "I need more information before deciding." in interaction
    assert "The scope or risk is not acceptable as written." in interaction


def test_dashboard_decision_draft_survives_polling_and_errors():
    from factoryline.studio import _studio_html

    page = _studio_html("token")
    approval_rows = page.split("function approvalRows(missions,refreshId)", 1)[1].split(
        "function dashboardDecisionReasons", 1
    )[0]
    submit = page.split("async function submitDashboardMissionDecision()", 1)[1].split(
        "async function decideMission(decision)", 1
    )[0]
    assert (
        "dashboardDecisionDraft&&host.querySelector('.dashboard-decision-form')"
        in approval_rows
    )
    assert "if(dashboardDecisionBusy||!draft||draft.uncertain)return" in submit
    assert "dashboardDecisionBusy=true" in submit
    assert "fetch('/api/mission-decision'" in submit
    assert "X-Factory-Studio-Token" in submit
    assert "showDashboardDecisionError" in submit
    assert "catch(error)" in submit
    assert "dashboardDecisionDraft=null;await refreshDashboard()" in submit


def test_dashboard_decision_uncertainty_requires_refresh_before_retry():
    from factoryline.studio import _studio_html

    page = _studio_html("token")
    uncertain = page.split("function markDashboardDecisionUncertain", 1)[1].split(
        "let missionDecisionBusy", 1
    )[0]
    approval_rows = page.split("function approvalRows(missions,refreshId)", 1)[1].split(
        "function dashboardDecisionReasons", 1
    )[0]
    cancel = page.split("function cancelDashboardMissionDecision()", 1)[1].split(
        "function showDashboardDecisionError", 1
    )[0]
    assert "response.status>=500" in uncertain
    assert "dashboardDecisionDraft.uncertain=true" in uncertain
    assert "uncertainAfter=dashboardRefreshSequence" in uncertain
    assert (
        "Refresh the dashboard and inspect the saved decision before retrying."
        in uncertain
    )
    assert "if(!current)return" in approval_rows
    assert "current.decision!=='awaiting_owner'" in approval_rows
    assert "refreshId<=dashboardDecisionDraft.uncertainAfter" in approval_rows
    assert "approvalRows(dashboardMissionSnapshot);refreshDashboard()" in cancel


def test_studio_gap_feedback_is_actionable_and_never_auto_invents_product_facts(
    tmp_path: Path,
):
    result = create_product_mission_from_studio(
        tmp_path,
        {
            "action": "product-mission",
            "prompt": "# Idea\n\nA useful dashboard.",
            "name": "idea",
            "resolution_mode": "auto_resolve_safe",
        },
    )
    assert result["status"] == "needs_input"
    assert result["resolution"]["status"] == "human_input_required"
    assert result["resolution"]["auto_resolved"] == []
    assert all(
        item["next_action"] and item["approval_required"]
        for item in result["resolution"]["items"]
    )
    assert "cannot be invented" in result["resolution"]["why_auto_stopped"]


def test_studio_guided_prd_requires_bound_confirmation_before_mission_compile(
    tmp_path: Path,
):
    from test_product_missions import PRD
    from factoryline.studio import product_grill_from_studio

    draft = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-start",
            "prompt": PRD,
            "name": "guided-demo",
            "mode": "quick",
        },
    )
    assert draft["status"] == "ready_for_confirmation"
    assert draft["confirmation_required"] is True
    with pytest.raises(StudioRequestError, match="CONFIRMATION_REQUIRED"):
        product_grill_from_studio(
            tmp_path,
            {
                "action": "product-grill-confirm",
                "session_path": draft["session"]["path"],
                "session_sha256": draft["session"]["session_sha256"],
                "confirmed": False,
            },
        )
    confirmed = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-confirm",
            "session_path": draft["session"]["path"],
            "session_sha256": draft["session"]["session_sha256"],
            "confirmed": True,
        },
    )
    compiled = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-guided-compile",
            "confirmation_path": confirmed["confirmation"]["path"],
            "confirmation_sha256": confirmed["confirmation"]["sha256"],
            "owner": "product-owner",
            "executor": "manual",
            "resolution_mode": "human_approval",
        },
    )
    assert compiled["studio_marker"] == "STUDIO_PRODUCT_MISSION_CONTAINED"
    assert compiled["guided_source_sha256"] == draft["source_sha256"]
    assert compiled["mission"]["approval_state"] == "required_before_execution"
    with pytest.raises(StudioRequestError, match="CONFIRMATION_BINDING_INVALID"):
        product_grill_from_studio(
            tmp_path,
            {
                "action": "product-guided-compile",
                "confirmation_path": confirmed["confirmation"]["path"],
                "confirmation_sha256": "0" * 64,
                "owner": "product-owner",
                "executor": "manual",
                "resolution_mode": "human_approval",
            },
        )
    session_document = json.loads(
        (tmp_path / Path(draft["session"]["path"])).read_text(encoding="utf-8")
    )
    (tmp_path / Path(session_document["source_path"])).write_text(
        PRD + "\nChanged after confirmation.\n", encoding="utf-8"
    )
    with pytest.raises(StudioRequestError, match="SOURCE_BINDING_INVALID"):
        product_grill_from_studio(
            tmp_path,
            {
                "action": "product-guided-compile",
                "confirmation_path": confirmed["confirmation"]["path"],
                "confirmation_sha256": confirmed["confirmation"]["sha256"],
            },
        )


def test_guided_resume_restores_verified_approval_and_handoff(tmp_path: Path):
    from test_product_missions import PRD
    from factoryline.studio import product_grill_from_studio

    draft = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-start",
            "prompt": PRD,
            "name": "resume-ok",
            "mode": "quick",
        },
    )
    confirmed = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-confirm",
            "session_path": draft["session"]["path"],
            "session_sha256": draft["session"]["session_sha256"],
            "confirmed": True,
        },
    )
    mission = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-guided-compile",
            "confirmation_path": confirmed["confirmation"]["path"],
            "confirmation_sha256": confirmed["confirmation"]["sha256"],
            "owner": "resume-owner",
            "executor": "manual",
        },
    )
    decide_product_mission_from_studio(
        tmp_path,
        {
            "action": "mission-decision",
            "mission": mission["mission"]["path"],
            "owner": "resume-owner",
            "decision": "approved_execution",
            "rationale": "Resume this approved bounded mission.",
        },
    )
    resumed = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-resume",
            "session_path": draft["session"]["path"],
            "session_sha256": draft["session"]["session_sha256"],
        },
    )
    assert resumed["agent_handoff"]["mission"]["path"] == mission["mission"]["path"]
    assert resumed["agent_handoff"]["state"] == "approved_needs_candidate_binding"
    assert resumed["agent_handoff"]["dispatched"] is False


def test_guided_resume_ignores_approved_mission_from_other_project(tmp_path: Path):
    from test_product_missions import PRD
    from factoryline.studio import product_grill_from_studio

    current = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-start",
            "prompt": PRD,
            "name": "current-project",
            "mode": "quick",
        },
    )
    other = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-start",
            "prompt": PRD,
            "name": "other-project",
            "mode": "quick",
        },
    )
    assert other["source_sha256"] == current["source_sha256"]
    confirmed = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-confirm",
            "session_path": other["session"]["path"],
            "session_sha256": other["session"]["session_sha256"],
            "confirmed": True,
        },
    )
    mission = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-guided-compile",
            "confirmation_path": confirmed["confirmation"]["path"],
            "confirmation_sha256": confirmed["confirmation"]["sha256"],
            "owner": "other-owner",
            "executor": "manual",
        },
    )
    decide_product_mission_from_studio(
        tmp_path,
        {
            "action": "mission-decision",
            "mission": mission["mission"]["path"],
            "owner": "other-owner",
            "decision": "approved_execution",
            "rationale": "Approve only the other project's bounded mission.",
        },
    )
    resumed = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-resume",
            "session_path": current["session"]["path"],
            "session_sha256": current["session"]["session_sha256"],
        },
    )
    assert "agent_handoff" not in resumed


@pytest.mark.parametrize(
    "sabotage",
    ["decision_tamper", "mission_stale", "wrong_owner", "graph_source_stale"],
)
def test_guided_resume_never_restores_unverified_approval(
    tmp_path: Path, sabotage: str
):
    from test_product_missions import PRD
    from factoryline.studio import product_grill_from_studio

    draft = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-start",
            "prompt": PRD,
            "name": f"resume-{sabotage}",
            "mode": "quick",
        },
    )
    confirmed = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-confirm",
            "session_path": draft["session"]["path"],
            "session_sha256": draft["session"]["session_sha256"],
            "confirmed": True,
        },
    )
    mission = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-guided-compile",
            "confirmation_path": confirmed["confirmation"]["path"],
            "confirmation_sha256": confirmed["confirmation"]["sha256"],
            "owner": "resume-owner",
            "executor": "manual",
        },
    )
    decision = decide_product_mission_from_studio(
        tmp_path,
        {
            "action": "mission-decision",
            "mission": mission["mission"]["path"],
            "owner": "resume-owner",
            "decision": "approved_execution",
            "rationale": "Resume this approved bounded mission.",
        },
    )
    if sabotage == "decision_tamper":
        receipt_path = Path(decision["path"])
        receipt = json.loads(receipt_path.read_bytes())
        receipt["rationale"] = "Tampered without updating the decision hash."
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    elif sabotage == "wrong_owner":
        receipt_path = Path(decision["path"])
        receipt = json.loads(receipt_path.read_bytes())
        receipt["owner"] = "other-owner"
        core = {
            key: value
            for key, value in receipt.items()
            if key not in {"decision_sha256", "generated_at"}
        }
        receipt["decision_sha256"] = hashlib.sha256(
            json.dumps(
                core, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    elif sabotage == "mission_stale":
        mission_path = Path(mission["mission"]["path"])
        mission_path.write_bytes(mission_path.read_bytes() + b" ")
    else:
        graph_path = Path(mission["mission"]["inputs"]["graph_path"])
        source_path = graph_path.parent / "source.md"
        source_path.write_bytes(source_path.read_bytes() + b" tampered")
    resumed = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-resume",
            "session_path": draft["session"]["path"],
            "session_sha256": draft["session"]["session_sha256"],
        },
    )
    assert "agent_handoff" not in resumed


def test_studio_guided_prd_answers_are_explicit_bounded_and_linked(tmp_path: Path):
    from factoryline.studio import product_grill_from_studio

    draft = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-start",
            "prompt": "# Idea\n\nA useful dashboard.",
            "name": "answered-demo",
            "mode": "quick",
        },
    )
    assert draft["status"] == "needs_answers"
    question_id = draft["questions"][0]["id"]
    request = {
        "action": "product-grill-answer",
        "session_path": draft["session"]["path"],
        "session_sha256": draft["session"]["session_sha256"],
        "answers": [
            {
                "question_id": question_id,
                "answer": "The operator must be able to review a prioritized dashboard.",
            }
        ],
    }
    answered = product_grill_from_studio(tmp_path, request)
    assert answered["session"]["session_sha256"] != draft["session"]["session_sha256"]
    assert answered["session"]["path"] != draft["session"]["path"]
    assert question_id not in {item["id"] for item in answered["questions"]}
    session_path = tmp_path / Path(answered["session"]["path"])
    session = json.loads(session_path.read_text(encoding="utf-8"))
    answered_source = tmp_path / Path(session["source_path"])
    assert "## Requirements" in answered_source.read_text(encoding="utf-8")
    assert session["previous"]["path"] == draft["session"]["path"]
    assert session["answers"] == [
        {
            "question_id": question_id,
            "answer": "The operator must be able to review a prioritized dashboard.",
        }
    ]
    with pytest.raises(StudioRequestError, match="QUESTION_ID_INVALID"):
        product_grill_from_studio(
            tmp_path,
            {
                **request,
                "answers": [{"question_id": "Q-NOT-DECLARED", "answer": "invented"}],
            },
        )
    with pytest.raises(StudioRequestError, match="QUESTION_ID_INVALID"):
        product_grill_from_studio(
            tmp_path,
            {
                **request,
                "answers": [
                    {"question_id": question_id, "answer": "one"},
                    {"question_id": question_id, "answer": "two"},
                ],
            },
        )
    with pytest.raises(StudioRequestError, match="ANSWER_INVALID"):
        product_grill_from_studio(
            tmp_path,
            {
                **request,
                "answers": [{"question_id": question_id, "answer": "\ud800"}],
            },
        )


def test_studio_guided_receipts_reject_hash_consistent_bad_shape_and_source_binding(
    tmp_path: Path,
):
    import hashlib

    from test_product_missions import PRD
    from factoryline.studio import product_grill_from_studio

    draft = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-start",
            "prompt": PRD,
            "name": "receipt-shape",
            "mode": "quick",
        },
    )
    session_file = tmp_path / Path(draft["session"]["path"])
    session = json.loads(session_file.read_text(encoding="utf-8"))
    session.pop("project")
    core = {key: value for key, value in session.items() if key != "session_sha256"}
    session["session_sha256"] = hashlib.sha256(
        json.dumps(
            core, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    session_file.write_text(json.dumps(session), encoding="utf-8")
    with pytest.raises(StudioRequestError, match="ARTIFACT_INVALID"):
        product_grill_from_studio(
            tmp_path,
            {
                "action": "product-grill-confirm",
                "session_path": draft["session"]["path"],
                "session_sha256": session["session_sha256"],
                "confirmed": True,
            },
        )

    typed = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-start",
            "prompt": PRD,
            "name": "receipt-type",
            "mode": "quick",
        },
    )
    typed_file = tmp_path / Path(typed["session"]["path"])
    typed_session = json.loads(typed_file.read_text(encoding="utf-8"))
    typed_session["mode"] = []
    typed_core = {
        key: value for key, value in typed_session.items() if key != "session_sha256"
    }
    typed_session["session_sha256"] = hashlib.sha256(
        json.dumps(
            typed_core, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    typed_file.write_text(json.dumps(typed_session), encoding="utf-8")
    with pytest.raises(StudioRequestError, match="SESSION_INVALID"):
        product_grill_from_studio(
            tmp_path,
            {
                "action": "product-grill-confirm",
                "session_path": typed["session"]["path"],
                "session_sha256": typed_session["session_sha256"],
                "confirmed": True,
            },
        )

    bound = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-start",
            "prompt": PRD,
            "name": "receipt-source",
            "mode": "quick",
        },
    )
    bound_file = tmp_path / Path(bound["session"]["path"])
    bound_session = json.loads(bound_file.read_text(encoding="utf-8"))
    changed_source = (
        tmp_path / ".factory" / "studio-guided" / "receipt-source" / "changed.md"
    )
    changed_source.write_text(PRD + "\nAdditional text.", encoding="utf-8")
    changed_bytes = changed_source.read_bytes()
    bound_session["source_path"] = changed_source.relative_to(tmp_path).as_posix()
    bound_session["source_sha256"] = hashlib.sha256(changed_bytes).hexdigest()
    bound_core = {
        key: value for key, value in bound_session.items() if key != "session_sha256"
    }
    bound_session["session_sha256"] = hashlib.sha256(
        json.dumps(
            bound_core, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    bound_file.write_text(json.dumps(bound_session), encoding="utf-8")
    with pytest.raises(StudioRequestError, match="RECEIPT_INVALID"):
        product_grill_from_studio(
            tmp_path,
            {
                "action": "product-grill-confirm",
                "session_path": bound["session"]["path"],
                "session_sha256": bound_session["session_sha256"],
                "confirmed": True,
            },
        )


def test_studio_guided_malformed_grill_and_surrogate_session_fail_closed(
    tmp_path: Path,
):
    from test_product_missions import PRD
    from factoryline.studio import (
        _guided_canonical,
        _guided_digest,
        product_grill_from_studio,
    )

    draft = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-start",
            "prompt": PRD,
            "name": "malformed-grill",
            "mode": "quick",
        },
    )
    session_path = tmp_path / Path(draft["session"]["path"])
    session = json.loads(session_path.read_text(encoding="utf-8"))
    grill_path = tmp_path / Path(session["grill_path"])
    grill = json.loads(grill_path.read_text(encoding="utf-8"))
    grill["source"] = []
    grill_core = {
        key: value
        for key, value in grill.items()
        if key not in {"grill_sha256", "generated_at"}
    }
    grill["grill_sha256"] = _guided_digest(_guided_canonical(grill_core))
    grill_bytes = json.dumps(grill, sort_keys=True).encode("utf-8") + b"\n"
    grill_path.write_bytes(grill_bytes)
    session["grill_sha256"] = _guided_digest(grill_bytes)
    session_core = {
        key: value for key, value in session.items() if key != "session_sha256"
    }
    session["session_sha256"] = _guided_digest(_guided_canonical(session_core))
    session_path.write_text(json.dumps(session), encoding="utf-8")
    with pytest.raises(StudioRequestError, match="RECEIPT_INVALID"):
        product_grill_from_studio(
            tmp_path,
            {
                "action": "product-grill-confirm",
                "session_path": draft["session"]["path"],
                "session_sha256": session["session_sha256"],
                "confirmed": True,
            },
        )

    unicode_draft = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-start",
            "prompt": PRD,
            "name": "surrogate-session",
            "mode": "quick",
        },
    )
    unicode_file = tmp_path / Path(unicode_draft["session"]["path"])
    raw_session = json.loads(unicode_file.read_text(encoding="utf-8"))
    raw_session["project"] = "\ud800"
    unicode_file.write_text(json.dumps(raw_session), encoding="utf-8")
    with pytest.raises(StudioRequestError, match="ARTIFACT_INVALID"):
        product_grill_from_studio(
            tmp_path,
            {
                "action": "product-grill-confirm",
                "session_path": unicode_draft["session"]["path"],
                "session_sha256": unicode_draft["session"]["session_sha256"],
                "confirmed": True,
            },
        )


def test_studio_guided_acceptance_answer_reaches_confirmed_compile(tmp_path: Path):
    from test_product_missions import PRD
    from factoryline.studio import product_grill_from_studio

    prompt = PRD.split("\n## Acceptance\n", 1)[0]
    draft = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-start",
            "prompt": prompt,
            "name": "acceptance-answer",
            "mode": "quick",
        },
    )
    assert [item["id"] for item in draft["questions"]] == ["Q-ACCEPTANCE"]
    scenario = """Scenario: Review a signal
  Given an authenticated operator has prioritized signals
  When the operator opens the dashboard
  Then the highest-priority signal and its reason are visible"""
    answered = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-answer",
            "session_path": draft["session"]["path"],
            "session_sha256": draft["session"]["session_sha256"],
            "answers": [{"question_id": "Q-ACCEPTANCE", "answer": scenario}],
        },
    )
    assert answered["status"] == "ready_for_confirmation"
    answered_session = json.loads(
        (tmp_path / Path(answered["session"]["path"])).read_text(encoding="utf-8")
    )
    saved_prd = (tmp_path / Path(answered_session["source_path"])).read_text(
        encoding="utf-8"
    )
    assert "Scenario: Review a signal" in saved_prd
    assert "- Scenario: Review a signal" not in saved_prd
    confirmed = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-confirm",
            "session_path": answered["session"]["path"],
            "session_sha256": answered["session"]["session_sha256"],
            "confirmed": True,
        },
    )
    compiled = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-guided-compile",
            "confirmation_path": confirmed["confirmation"]["path"],
            "confirmation_sha256": confirmed["confirmation"]["sha256"],
        },
    )
    assert compiled["studio_marker"] == "STUDIO_PRODUCT_MISSION_CONTAINED"


def test_studio_guided_quick_mode_escalates_remaining_deep_gaps(tmp_path: Path):
    from test_product_missions import PRD
    from factoryline.studio import product_grill_from_studio

    prefix, remainder = PRD.split("\n## Experience states\n", 1)
    acceptance = "\n## Acceptance\n" + remainder.split("\n## Acceptance\n", 1)[1]
    prompt = prefix + acceptance
    quick = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-start",
            "prompt": prompt,
            "name": "quick-escalation",
            "mode": "quick",
        },
    )
    assert quick["status"] == "deep_review_required"
    assert quick["next_action"] == "start_deep_review"
    with pytest.raises(StudioRequestError, match="PRD_UNRESOLVED"):
        product_grill_from_studio(
            tmp_path,
            {
                "action": "product-grill-confirm",
                "session_path": quick["session"]["path"],
                "session_sha256": quick["session"]["session_sha256"],
                "confirmed": True,
            },
        )
    deep = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-start",
            "prompt": prompt,
            "name": "quick-escalation-deep",
            "mode": "deep",
        },
    )
    assert deep["questions"]


def test_legacy_product_endpoint_labels_direct_compile_compatibility(tmp_path: Path):
    from test_product_missions import PRD

    result = create_product_mission_from_studio(
        tmp_path,
        {"action": "product-mission", "prompt": PRD, "name": "legacy-demo"},
    )
    assert result["compatibility_path"] == "legacy-product-mission-v1"


def test_http_guided_prd_route_is_token_bound(tmp_path: Path):
    server, token = create_server(tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request(
            "POST",
            "/api/product-grill",
            body=json.dumps(
                {
                    "action": "product-grill-start",
                    "prompt": "# Product\n\nA dashboard for private team notes.",
                    "name": "http-guided",
                    "mode": "quick",
                }
            ),
            headers={"Content-Type": "application/json"},
        )
        denied = connection.getresponse()
        denied.read()
        assert denied.status == 403
        connection.close()
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request(
            "POST",
            "/api/product-grill",
            body=json.dumps(
                {
                    "action": "product-grill-start",
                    "prompt": "# Product\n\nA dashboard for private team notes.",
                    "name": "http-guided",
                    "mode": "quick",
                }
            ),
            headers={
                "Content-Type": "application/json",
                "X-Factory-Studio-Token": token,
            },
        )
        response = connection.getresponse()
        result = json.loads(response.read())
        assert response.status == 201
        assert result["schema"] == "factory.studio.guided-prd.v1"
        assert result["confirmation_required"] is True
        assert (
            hashlib.sha256(result["source_text"].encode("utf-8")).hexdigest()
            == result["source_sha256"]
        )
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_studio_guided_ui_consumes_questions_confirmation_compile_and_source_safely():
    from factoryline.studio import _studio_html

    page = _studio_html("session-token")
    assert "fetch('/api/product-grill'" in page
    assert "action:'product-grill-start'" in page
    assert "/api/product/product-mission" not in page
    assert "renderGuided" in page
    assert "sendGuided" in page
    assert "confirmGuided" in page
    assert "compileGuided" in page
    assert "payload.questions" in page
    assert "product-grill-confirm" in page
    assert "product-guided-compile" in page
    assert "payload.source_text" in page
    assert "textContent" in page
    assert "innerHTML" not in page


def test_guided_ui_offers_multiple_choice_and_editable_custom_answers_without_saving():
    from factoryline.studio import _studio_html

    page = _studio_html("session-token")
    assert "guidedAnswerOptions(question)" in page
    assert "Custom answer" in page
    assert "choice.onchange" in page
    assert "input.value=guidedAnswerOptions(question)[Number(choice.value)]" in page
    assert "input.addEventListener('input'" in page
    assert "action:'product-grill-answer'" in page
    assert "guidedButton('Save my answers'" in page
    assert "guidedButton('Confirm this PRD'" in page
    assert "choice.onchange" in page
    change_handler = page.split("choice.onchange=", 1)[1].split(";field.append", 1)[0]
    assert "sendGuided" not in change_handler
    assert "confirmGuided" not in change_handler


def test_guided_ui_question_stepper_keeps_answers_local_until_validated_save():
    from factoryline.studio import _studio_html

    page = _studio_html("session-token")
    assert "guidedStepper(answers,save)" in page
    assert "Question " in page and " of " in page
    assert "Back" in page
    assert "Next" in page
    assert "field.hidden" in page
    assert "validateGuidedAnswer(answers[active].input)" in page
    assert "input.value.trim()" in page
    assert "guidedButton('Save my answers'" in page

    stepper = page.split("function guidedStepper(answers,save)", 1)[1].split(
        "function sendGuided", 1
    )[0]
    assert "guidedButton('Back',()=>show(active-1))" in stepper
    assert (
        "guidedButton('Next question',()=>{if(validateGuidedAnswer(answers[active].input))show(active+1);})"
        in stepper
    )
    assert "sendGuided" not in stepper


def test_http_guided_answer_returns_explicit_answer_source(tmp_path: Path):
    server, token = create_server(tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        headers = {
            "Content-Type": "application/json",
            "X-Factory-Studio-Token": token,
        }
        prompt = "# Product\n\nA dashboard for private team notes."
        connection.request(
            "POST",
            "/api/product-grill",
            body=json.dumps(
                {
                    "action": "product-grill-start",
                    "prompt": prompt,
                    "name": "answer-source",
                    "mode": "quick",
                }
            ),
            headers=headers,
        )
        start = json.loads(connection.getresponse().read())
        question = start["questions"][0]
        answer_text = "Keep notes private and searchable by their owners."
        connection.request(
            "POST",
            "/api/product-grill",
            body=json.dumps(
                {
                    "action": "product-grill-answer",
                    "session_path": start["session"]["path"],
                    "session_sha256": start["session"]["session_sha256"],
                    "answers": [{"question_id": question["id"], "answer": answer_text}],
                }
            ),
            headers=headers,
        )
        answer = json.loads(connection.getresponse().read())
        assert answer_text in answer["source_text"]
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_http_surface_requires_session_token_and_enforces_body_limit(tmp_path: Path):
    # Real requests exercise _StudioHandler.do_GET, do_POST, and log_message.
    server, token = create_server(tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request("GET", "/api/status")
        response = connection.getresponse()
        assert response.status == 200
        status = json.loads(response.read())
        assert status["listener"]["port"] == server.server_port

        connection.request("GET", "/api/dashboard")
        response = connection.getresponse()
        assert response.status == 403
        assert int(response.getheader("Content-Length")) > 0
        response.read()

        connection.request(
            "GET", "/api/dashboard", headers={"X-Factory-Studio-Token": token}
        )
        response = connection.getresponse()
        assert response.status == 200
        dashboard = json.loads(response.read())
        assert dashboard["schema"] == "factory.studio.dashboard.v1"
        assert dashboard["live_activity"]["status"] == "idle"

        connection.request("GET", "/api/savings")
        response = connection.getresponse()
        assert response.status == 403
        response.read()

        connection.request("GET", "/api/developer-memory")
        response = connection.getresponse()
        assert response.status == 403
        response.read()

        connection.request(
            "GET", "/api/developer-memory", headers={"X-Factory-Studio-Token": token}
        )
        response = connection.getresponse()
        assert response.status == 200
        developer_memory = json.loads(response.read())
        assert developer_memory["marker"] == "DEVELOPER_MEMORY_STUDIO_CACHED"
        assert developer_memory["brief"]["authority"]["external_effects"] is False

        connection.request("GET", "/api/graph-ops")
        response = connection.getresponse()
        assert response.status == 403
        response.read()

        connection.request("GET", "/graph-ops")
        response = connection.getresponse()
        assert response.status == 200
        page = response.read().decode("utf-8")
        assert "GRAPH_OPS_VISUAL_ACCESSIBLE" in page
        assert "session-token" not in page

        connection.request(
            "GET", "/api/graph-ops", headers={"X-Factory-Studio-Token": token}
        )
        response = connection.getresponse()
        assert response.status == 200
        graph_ops = json.loads(response.read())
        assert graph_ops["schema"] == "factory.graph-ops.v1"
        assert graph_ops["authority"]["publication"] is False
        assert graph_ops["live_telemetry"]["activity"]["status"] == "idle"
        assert graph_ops["live_telemetry"]["refresh_interval_ms"] == 1000
        assert graph_ops["live_telemetry"]["recent_runs"] == []

        savings_body = json.dumps(
            {
                "action": "savings-record",
                "pair_id": "http-pair",
                "baseline_elapsed_ms": 500,
                "factory_elapsed_ms": 300,
                "baseline_tokens": 50,
                "factory_tokens": 40,
            }
        )
        connection.request(
            "POST",
            "/api/savings",
            body=savings_body,
            headers={
                "Content-Type": "application/json",
                "X-Factory-Studio-Token": token,
            },
        )
        response = connection.getresponse()
        assert response.status == 201
        assert json.loads(response.read())["savings"]["time_saved_ms"] == 200

        connection.request(
            "GET", "/api/savings", headers={"X-Factory-Studio-Token": token}
        )
        response = connection.getresponse()
        assert response.status == 200
        savings = json.loads(response.read())
        assert savings["tokens"]["saved_total"] == 10

        connection.request("GET", "/favicon.ico")
        response = connection.getresponse()
        assert response.status == 204
        assert response.getheader("Content-Length") == "0"
        assert response.read() == b""

        connection.close()
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        body = json.dumps(
            {
                "action": "create",
                "target": "worker",
                "prompt": "Build a worker.",
                "name": "http-worker",
            }
        )
        connection.request(
            "POST",
            "/api/create",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        assert response.status == 403
        assert response.getheader("Connection") == "close"
        token_failure = json.loads(response.read())
        assert token_failure["failure"]["point_of_failure"]
        assert token_failure["failure"]["next_action"]

        connection.close()
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request(
            "POST",
            "/api/create",
            body=None,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(MAX_BODY_BYTES + 1),
                "X-Factory-Studio-Token": token,
            },
        )
        assert connection.getresponse().status == 413
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_studio_route_contract_golden_preserves_public_and_token_bound_surfaces(
    tmp_path: Path,
):
    """Keep the externally visible Studio route, token, and error contract stable."""
    from test_runtime_audit import _fixture, _write_report

    _write_report(tmp_path, _fixture(tmp_path))
    server, token = create_server(tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def get(
        path: str, headers: dict[str, str] | None = None
    ) -> tuple[int, str, str | None]:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request("GET", path, headers=headers or {})
        response = connection.getresponse()
        body = response.read().decode("utf-8")
        content_type = response.getheader("Content-Type")
        connection.close()
        return response.status, body, content_type

    def post(
        path: str, body: dict[str, object], headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, object], str | None]:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request(
            "POST",
            path,
            body=json.dumps(body),
            headers={"Content-Type": "application/json", **(headers or {})},
        )
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection_header = response.getheader("Connection")
        connection.close()
        return response.status, payload, connection_header

    try:
        for path, status, marker in [
            ("/", 200, "FACTORY_DUAL_TRACK_START"),
            ("/?screen=overview", 200, "FACTORY_DUAL_TRACK_START"),
            ("/graph-ops", 200, "GRAPH_OPS_VISUAL_ACCESSIBLE"),
            ("/favicon.ico", 204, ""),
            ("/favicon.ico?cache=1", 404, "NOT_FOUND"),
            ("/unknown", 404, "NOT_FOUND"),
        ]:
            actual_status, body, _content_type = get(path)
            assert (actual_status, marker in body) == (status, True)

        protected_schemas = {
            "/api/dashboard": "factory.studio.dashboard.v1",
            "/api/savings": "factory.savings-report.public.v1",
            "/api/developer-memory": "factory.studio.developer-memory.v1",
            "/api/graph-ops": "factory.graph-ops.v1",
            "/api/coverage-report": "factory.runtime-coverage.v1",
        }
        for path, schema in protected_schemas.items():
            rejected_status, rejected_body, _content_type = get(path)
            assert (rejected_status, json.loads(rejected_body)["code"]) == (
                403,
                "TOKEN_REQUIRED",
            )
            accepted_status, accepted_body, _content_type = get(
                path, {"X-Factory-Studio-Token": token}
            )
            assert (accepted_status, json.loads(accepted_body)["schema"]) == (
                200,
                schema,
            )
        coverage_status, coverage_body, _coverage_type = get(
            "/api/coverage-report", {"X-Factory-Studio-Token": token}
        )
        coverage = json.loads(coverage_body)
        assert (coverage_status, coverage["state"], coverage["file_count"]) == (
            200,
            "OBSERVED",
            1,
        )
        assert coverage["files"][0]["path"] == "factoryline/demo.py"

        unknown_status, unknown_body, unknown_connection = post(
            "/api/unknown", {}, {"X-Factory-Studio-Token": token}
        )
        assert (unknown_status, unknown_body["code"], unknown_connection) == (
            404,
            "NOT_FOUND",
            "close",
        )
        stopped_status, stopped_body, _stopped_connection = post(
            "/api/activity/stop",
            {"action": "request-stop"},
            {"X-Factory-Studio-Token": token},
        )
        assert (stopped_status, stopped_body["code"]) == (409, "NO_ACTIVE_ASSEMBLY")
        action_status, action_body, _action_connection = post(
            "/api/activity/stop", {}, {"X-Factory-Studio-Token": token}
        )
        assert (action_status, action_body["code"]) == (400, "ACTION_UNSUPPORTED")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_unauthorized_partial_body_has_bounded_drain_deadline(tmp_path: Path):
    server, _token = create_server(tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = socket.create_connection(("127.0.0.1", server.server_port), timeout=2)
    client.settimeout(2)
    started = time.monotonic()
    try:
        client.sendall(
            b"POST /api/create HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 10\r\n"
            b"X-Factory-Studio-Token: wrong-token\r\n\r\n{}"
        )
        response = client.recv(4096)
        assert b" 403 " in response
        assert time.monotonic() - started < 1.5
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_http_graph_ops_authorization_requires_token_and_consumes_one_reality_check(
    tmp_path: Path,
):
    from test_reality_check import _write

    from factoryline.graph_ops import graph_ops_snapshot
    from factoryline.reality_check import (
        run_reality_check,
        write_reality_check_artifacts,
    )

    receipt = run_reality_check(tmp_path, _write(tmp_path))
    write_reality_check_artifacts(receipt, tmp_path / ".factory" / "reality")
    node_id = next(
        node["id"]
        for node in graph_ops_snapshot(tmp_path)["nodes"]
        if node["kind"] == "reality_check"
    )
    server, token = create_server(tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    now = datetime.now(timezone.utc)
    authorization = {
        "action": "reality_check_execution",
        "id": "http-reality",
        "node_id": node_id,
        "approved_by": "reviewer",
        "rationale": "Run the exact declared behavior once.",
        "expires_at": (now + timedelta(hours=1))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "confirmation": "AUTHORIZE http-reality",
    }

    def post(path: str, payload: dict, session_token: str) -> tuple[int, dict]:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request(
            "POST",
            path,
            body=json.dumps(payload),
            headers={
                "Content-Type": "application/json",
                "X-Factory-Studio-Token": session_token,
            },
        )
        response = connection.getresponse()
        parsed = json.loads(response.read())
        connection.close()
        return response.status, parsed

    try:
        status, rejected = post(
            "/api/graph-ops-authorize", authorization, "wrong-token"
        )
        assert status == 403
        assert rejected["code"] == "TOKEN_REQUIRED"

        status, approved = post("/api/graph-ops-authorize", authorization, token)
        assert status == 201
        assert approved["marker"] == "GRAPH_OPS_HUMAN_AUTHORIZATION_RECORDED"

        status, executed = post(
            "/api/graph-ops-run", {"authorization": approved["path"]}, token
        )
        assert status == 201
        assert executed["marker"] == "GRAPH_OPS_AUTHORIZED_REALITY_CHECK_EXECUTED"
        assert executed["receipt"]["marker"] == "REALITY_CHECK_VERIFIED"

        status, replayed = post(
            "/api/graph-ops-run", {"authorization": approved["path"]}, token
        )
        assert status == 409
        assert replayed["code"] == "GRAPH_AUTHORIZATION_NOT_EXECUTABLE"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_http_mission_decision_rejects_wrong_token_escape_and_replay(tmp_path: Path):
    from test_product_missions import PRD

    mission = create_product_mission_from_studio(
        tmp_path,
        {
            "action": "product-mission",
            "prompt": PRD,
            "name": "decision-api",
            "executor": "codex",
            "owner": "product-owner",
        },
    )
    decision = {
        "action": "mission-decision",
        "mission": mission["mission"]["path"],
        "owner": "product-owner",
        "decision": "approved_execution",
        "rationale": "The bounded mission and budget are ready.",
    }
    server, token = create_server(tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def post(payload: dict, session_token: str) -> tuple[int, dict]:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        body = json.dumps(payload)
        connection.request(
            "POST",
            "/api/mission-decision",
            body=body,
            headers={
                "Content-Type": "application/json",
                "X-Factory-Studio-Token": session_token,
            },
        )
        response = connection.getresponse()
        parsed = json.loads(response.read())
        connection.close()
        return response.status, parsed

    try:
        status, rejected = post(decision, "wrong-token")
        assert status == 403
        assert rejected["code"] == "TOKEN_REQUIRED"

        escaped = {**decision, "mission": str(tmp_path.parent / "foreign-mission.json")}
        status, rejected = post(escaped, token)
        assert status == 403
        assert rejected["code"] == "PATH_REJECTED"

        status, accepted = post(decision, token)
        assert status == 201
        receipt_path = Path(accepted["path"])
        original = receipt_path.read_bytes()

        status, rejected = post(decision, token)
        assert status == 400
        assert rejected["code"] == "ARTIFACT_EXISTS"
        assert receipt_path.read_bytes() == original
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_handler_binding_and_serve_lifecycle(tmp_path: Path, monkeypatch, capsys):
    handler = make_handler(tmp_path, "session-token")
    assert handler.studio_root == tmp_path
    assert handler.studio_token == "session-token"

    events: list[str] = []

    class FakeServer:
        server_port = 43117

        def serve_forever(self, poll_interval: float) -> None:
            events.append(f"serve:{poll_interval}")

        def server_close(self) -> None:
            events.append("closed")

    monkeypatch.setattr(
        "factoryline.studio.create_server", lambda root, port: (FakeServer(), "token")
    )
    serve_studio(tmp_path, open_browser=False, on_started=events.append)

    assert "http://127.0.0.1:43117/" in events
    assert events[-1] == "closed"
    assert "Factory Studio: http://127.0.0.1:43117/" in capsys.readouterr().out


def test_guided_ui_explains_required_actor_and_experience_answer_formats():
    from factoryline.studio import _studio_html

    page = _studio_html("local-contract")
    assert "Use Role: responsibility" in page
    assert "question.id.startsWith('Q-UX-')" in page
    assert "question.id.slice(5).toLowerCase()" in page
    assert "guidedAnswerFormat(question)" in page


def test_guided_resume_restores_saved_frontier_and_rejects_changed_source(
    tmp_path: Path,
):
    from factoryline.studio import product_grill_from_studio

    started = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-start",
            "prompt": "Build a private dashboard.",
            "name": "resume-proof",
            "mode": "deep",
        },
    )
    saved = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-answer",
            "session_path": started["session"]["path"],
            "session_sha256": started["session"]["session_sha256"],
            "answers": [
                {
                    "question_id": "Q-ACTORS",
                    "answer": "Operator: reviews private records.",
                }
            ],
        },
    )
    request = {
        "action": "product-grill-resume",
        "session_path": saved["session"]["path"],
        "session_sha256": saved["session"]["session_sha256"],
    }
    resumed = product_grill_from_studio(tmp_path, request)
    assert resumed["project"] == "resume-proof"
    assert resumed["session"] == saved["session"]
    assert resumed["source_text"] == saved["source_text"]
    assert resumed["questions"] == saved["questions"]
    assert "Q-ACTORS" not in [q["id"] for q in resumed["questions"]]
    assert resumed["confirmation_required"] is True
    assert resumed["implementation_authorized"] is False
    session = json.loads(
        (tmp_path / saved["session"]["path"]).read_text(encoding="utf-8")
    )
    (tmp_path / session["source_path"]).write_text("changed", encoding="utf-8")
    with pytest.raises(StudioRequestError, match="SOURCE_BINDING_INVALID"):
        product_grill_from_studio(tmp_path, request)


def test_guided_resume_rejects_extra_fields_and_escape(tmp_path: Path):
    from factoryline.studio import product_grill_from_studio

    with pytest.raises(StudioRequestError, match="REQUEST_INVALID"):
        product_grill_from_studio(
            tmp_path,
            {
                "action": "product-grill-resume",
                "session_path": "x",
                "session_sha256": "0" * 64,
                "confirmed": True,
            },
        )
    with pytest.raises(StudioRequestError, match="PATH_REJECTED"):
        product_grill_from_studio(
            tmp_path,
            {
                "action": "product-grill-resume",
                "session_path": "../foreign.json",
                "session_sha256": "0" * 64,
            },
        )


def test_guided_resume_ui_stores_only_locator_and_requires_explicit_resume():
    from factoryline.studio import _studio_html

    html = _studio_html("local-contract")
    bookmark = html.split("function saveGuidedBookmark(payload)", 1)[1].split(
        "async function resumeGuided", 1
    )[0]
    assert "project:payload.project,session:payload.session" in bookmark
    assert "source_text" not in bookmark
    assert "token" not in bookmark
    assert "sessionStorage" in bookmark
    assert "Resume saved interview" in html
    assert "Unsaved answers are not restored" in html
    assert "action:'product-grill-resume'" in html
    assert "document.getElementById('prompt').value=payload.source_text" in html


def test_guided_resume_reads_verified_snapshot_without_regrilling(
    tmp_path: Path, monkeypatch
):
    from factoryline.studio import product_grill_from_studio

    saved = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-start",
            "prompt": "Build a private dashboard.",
            "name": "resume-snapshot",
            "mode": "deep",
        },
    )
    before = {
        p.relative_to(tmp_path).as_posix(): p.read_bytes()
        for p in tmp_path.rglob("*")
        if p.is_file()
    }

    def forbidden(*args, **kwargs):
        raise AssertionError("Resume must not regenerate immutable Grill evidence")

    monkeypatch.setattr("factoryline.studio.grill_prd", forbidden)
    resumed = product_grill_from_studio(
        tmp_path,
        {
            "action": "product-grill-resume",
            "session_path": saved["session"]["path"],
            "session_sha256": saved["session"]["session_sha256"],
        },
    )
    after = {
        p.relative_to(tmp_path).as_posix(): p.read_bytes()
        for p in tmp_path.rglob("*")
        if p.is_file()
    }
    assert resumed == saved
    assert after == before


def test_guided_product_advanced_controls_are_optional_and_collapsed():
    from html.parser import HTMLParser
    from factoryline.studio import _studio_html

    class Controls(HTMLParser):
        def __init__(self):
            super().__init__()
            self.advanced = False
            self.collapsed = False
            self.inside = []
            self.outside = []

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == "details" and attrs.get("id") == "mission-advanced":
                self.advanced = True
                self.collapsed = "open" not in attrs
            if tag in {"input", "select", "textarea"}:
                (self.inside if self.advanced else self.outside).append(attrs.get("id"))

        def handle_endtag(self, tag):
            if tag == "details":
                self.advanced = False

    html = _studio_html("simple-ux-contract")
    controls = Controls()
    controls.feed(html)
    assert controls.collapsed
    assert controls.inside == ["executor", "owner", "resolution-mode"]
    assert {"name", "prompt"}.issubset(controls.outside)
    assert "Advanced options" in html
    assert "The defaults are ready to use." in html


@pytest.mark.parametrize("failure", ["timeout", "cleanup", "drift"])
def test_journey_execution_retains_failures_without_success(
    tmp_path, monkeypatch, failure
):
    from factoryline import app_builder

    candidate, _, binding = _studio_bound_candidate(tmp_path)
    payload = {"binding_path": binding["path"], "owner": "release-owner"}
    plan = studio_journey_plan(
        tmp_path,
        {
            **payload,
            "stage": "verify",
            "command_index": 0,
            "image": "python@sha256:" + "a" * 64,
        },
    )

    def runner(cli, args, cwd, **kwargs):
        if args[0] == "inspect":
            return {
                "ok": False,
                "exit_code": 1,
                "stderr": b"daemon unavailable"
                if failure == "cleanup"
                else b"no such container",
            }
        if args[0] == "run" and failure == "drift":
            (candidate / "README.md").write_text("changed", encoding="utf-8")
        return {
            "ok": failure != "timeout",
            "exit_code": 0,
            "reason": "timeout" if failure == "timeout" else None,
            "cleanup_confirmed": True,
            "streams_closed": True,
            "stdout": b"bounded log",
            "stderr": b"",
        }

    monkeypatch.setattr(app_builder, "run_cli_detailed", runner)
    result = _studio_execute_plan(
        tmp_path,
        {
            **payload,
            "plan_path": plan["path"],
            "plan_sha256": plan["plan_sha256"],
            "confirmed": True,
        },
    )
    assert result["ok"] is False
    retained = json.loads(Path(result["path"]).read_text(encoding="utf-8"))
    assert retained["receipt"]["ok"] is False
    assert retained["receipt"]["telemetry"]["status"] == "ERROR"
    if failure == "cleanup":
        assert result["container_removed"] is False
    if failure == "drift":
        assert result["candidate_unchanged"] is False
    if failure == "timeout":
        assert result["timed_out"] is True


def test_journey_status_ignores_malformed_and_other_binding_receipts(tmp_path):
    from factoryline import app_builder

    _, _, binding = _studio_bound_candidate(tmp_path)
    payload = {"binding_path": binding["path"], "owner": "release-owner"}
    status = studio_journey_status(tmp_path, payload)
    app_builder._studio_write(
        tmp_path,
        "attempt",
        {
            "stage": "build",
            "ok": True,
            "candidate_sha256": status["candidate_sha256"],
            "binding_sha256": "f" * 64,
        },
    )
    evidence = tmp_path / ".factory" / "studio-journey"
    (evidence / "attempt-malformed.json").write_text("{}", encoding="utf-8")
    status = studio_journey_status(tmp_path, payload)
    assert status["stages"]["build"] == {"state": "missing_evidence", "attempts": []}


@pytest.mark.parametrize("status, expected", [("VERIFIED", True), ("FAILED", False)])
def test_journey_repair_requires_existing_approval_and_preserves_result(
    tmp_path, monkeypatch, status, expected
):
    from factoryline import app_builder

    _, _, binding = _studio_bound_candidate(tmp_path)
    observed = []

    def repair(binding_path, approval_path, root, *, owner):
        observed.append((binding_path, approval_path, owner))
        return {"status": status, "attempt_id": "bound-attempt"}

    monkeypatch.setattr(app_builder, "execute_mission_repair", repair)
    approval = tmp_path / "existing-exact-approval.json"
    approval.write_text("{}", encoding="utf-8")
    payload = {
        "action": "repair",
        "binding_path": binding["path"],
        "owner": "release-owner",
        "approval_path": approval.name,
    }
    result = app_builder.studio_journey(tmp_path, payload)
    assert observed == [(Path(binding["path"]), approval, "release-owner")]
    assert result["ok"] is expected
    assert result["repair_result"]["status"] == status
    assert Path(result["path"]).is_file()


def test_journey_wrapper_handles_repair_sandbox_errors_as_validation(
    tmp_path, monkeypatch
):
    from factoryline import app_builder
    from factoryline.repair_sandbox import RepairSandboxError
    from factoryline.studio import journey_from_studio

    def rejected(root, payload):
        raise RepairSandboxError("REPAIR_APPROVAL_INVALID", "private approval detail")

    monkeypatch.setattr(app_builder, "studio_journey", rejected)
    with pytest.raises(StudioRequestError) as caught:
        journey_from_studio(
            tmp_path,
            {
                "action": "repair",
                "binding_path": "bound.json",
                "owner": "owner",
                "approval_path": "approval.json",
            },
        )
    assert caught.value.code == "JOURNEY_ACTION_REJECTED"
    assert "private approval detail" not in str(caught.value)
