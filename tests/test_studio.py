from __future__ import annotations

from http.client import HTTPConnection
from pathlib import Path
from datetime import datetime, timedelta, timezone
import json
import threading

import pytest

from factoryline.studio import (
    MAX_BODY_BYTES,
    StudioRequestError,
    developer_memory_snapshot,
    create_from_studio,
    create_product_mission_from_studio,
    decide_product_mission_from_studio,
    create_server,
    make_handler,
    serve_studio,
    studio_dashboard,
    continue_from_studio,
    savings_from_studio,
    studio_status,
)
from factoryline.meter import MeterLog, StageTiming


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


def test_studio_assembly_uses_shared_continuation_and_preserves_authority(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "factoryline.studio.continue_assembly",
        lambda root, feature: {"status": "waiting_for_human", "feature": feature, "next_action": {"label": "Review"}},
    )
    result = continue_from_studio(tmp_path, {"action": "continue", "feature": "sample"})
    assert result["studio_marker"] == "STUDIO_ASSEMBLY_CONTAINED"
    assert result["status"] == "waiting_for_human"
    status = studio_status(tmp_path, 0)
    assert status["authority"]["can_continue_assembly_to_human_boundary"] is True
    assert status["authority"]["can_publish"] is False


def test_studio_savings_records_exact_pair_and_rejects_path_escape(tmp_path):
    result = savings_from_studio(tmp_path, {
        "action": "savings-record", "pair_id": "studio-pair",
        "baseline_elapsed_ms": 1000, "factory_elapsed_ms": 600,
        "baseline_tokens": 100, "factory_tokens": 70,
    })
    assert result["studio_marker"] == "SAVINGS_STUDIO_CONTAINED"
    assert result["savings"]["time_saved_ms"] == 400
    assert studio_dashboard(tmp_path)["savings"]["tokens"]["saved_total"] == 30
    with pytest.raises(StudioRequestError, match="PATH_REJECTED"):
        savings_from_studio(tmp_path, {
            "action": "savings-record", "pair_id": "escape",
            "baseline_elapsed_ms": 1, "factory_elapsed_ms": 1,
            "equivalent_outcome": True, "evidence": "../private.txt",
        })


def test_studio_status_is_exact_and_loopback_only(tmp_path: Path):
    status = studio_status(tmp_path, 4321)
    assert status["marker"] == "STUDIO_STATUS_EXACT"
    assert status["listener"] == {"host": "127.0.0.1", "port": 4321, "production": False}
    assert status["limits"]["overwrite"] is False
    assert status["authority"]["can_deploy"] is False
    assert status["authority"]["can_inject_credentials"] is False


def test_dashboard_preserves_unknowns_and_exposes_control_state(tmp_path: Path):
    dashboard = studio_dashboard(tmp_path)
    assert dashboard["schema"] == "factory.studio.dashboard.v1"
    assert dashboard["meter"]["summary"]["stages_measured"] == 0
    assert dashboard["meter"]["activity"]["stage_success_rate"] is None
    assert dashboard["approvals"]["awaiting_owner"] == 0
    assert len(dashboard["packs"]) == 29
    assert all(pack["signature_verified"] and pack["mutations_rejected"] == 10 for pack in dashboard["packs"])
    assert all(pack["deployment_profiles"] for pack in dashboard["packs"])
    assert dashboard["authority"]["can_deploy"] is False
    assert dashboard["developer_memory"]["marker"] == "DEVELOPER_MEMORY_STUDIO_CACHED"
    assert dashboard["developer_memory"]["brief"]["schema"] == "factory.developer-memory-brief.v1"
    assert "STUDIO_DEVELOPER_MEMORY_VISIBLE" in dashboard["markers"]
    repeated = developer_memory_snapshot(tmp_path)
    assert repeated["cache"]["state"] == "reused"
    assert repeated["cache"]["refresh_interval_ms"] == 5000


def test_dashboard_lists_prior_measured_runs_without_inferring_success(tmp_path: Path):
    ledger = MeterLog(tmp_path)
    ledger.record(StageTiming(
        module="spec", stage="validate", wall_ms=125, model_calls=0,
        tokens_in=0, tokens_out=0, ok=True, feature="approval-tracker",
        run_id="run-earlier", recorded_at="2026-08-18T10:00:00+00:00",
    ))
    ledger.record(StageTiming(
        module="verify", stage="tests", wall_ms=250, model_calls=1,
        tokens_in=40, tokens_out=20, ok=False, feature="approval-tracker",
        run_id="run-latest", recorded_at="2026-08-18T11:00:00+00:00",
    ))

    runs = studio_dashboard(tmp_path)["recent_runs"]

    assert [item["run_id"] for item in runs] == ["run-latest", "run-earlier"]
    assert runs[0]["outcome"] == "failed_stage_observed"
    assert runs[0]["tokens"] == 60
    assert runs[0]["cost_usd"] is None


def test_studio_contains_output_and_forbids_promotion(tmp_path: Path):
    result = create_from_studio(tmp_path, {
        "action": "create",
        "target": "worker",
        "prompt": "Build a deterministic inbox worker.",
        "name": "inbox-worker",
        "deployment_profile": "container-host",
    })
    assert result["studio_marker"] == "STUDIO_CONTAINED"
    assert Path(result["out_dir"]).parent == tmp_path.resolve()
    assert result["deployment"]["selected_profile_id"] == "container-host"
    assert result["deployment"]["external_effects_authorized"] is False

    with pytest.raises(StudioRequestError, match="PATH_REJECTED"):
        create_from_studio(tmp_path, {
            "action": "create",
            "target": "worker",
            "prompt": "Build another worker.",
            "name": "../escaped",
        })
    with pytest.raises(StudioRequestError, match="ACTION_FORBIDDEN"):
        create_from_studio(tmp_path, {"action": "publish"})
    assert not (tmp_path.parent / "escaped").exists()


def test_studio_compiles_a_contained_supervised_product_mission(tmp_path: Path):
    from test_product_missions import PRD

    result = create_product_mission_from_studio(tmp_path, {
        "action": "product-mission", "prompt": PRD, "name": "signal-desk", "executor": "codex",
        "owner": "product-owner", "resolution_mode": "auto_resolve_safe",
    })
    assert result["studio_marker"] == "STUDIO_PRODUCT_MISSION_CONTAINED"
    assert result["mission"]["approval_state"] == "required_before_execution"
    assert result["mission"]["authority"]["merge"] is False
    assert result["approval"]["state"] == "ready_for_human_decision"
    assert result["approval"]["authority_after_approval"]["deploy"] is False
    assert result["resolution"]["mode"] == "auto_resolve_safe"
    assert Path(result["mission"]["path"]).is_relative_to(tmp_path)

    decision = decide_product_mission_from_studio(tmp_path, {
        "action": "mission-decision", "mission": result["mission"]["path"],
        "owner": "product-owner", "decision": "approved_execution",
        "rationale": "The bounded mission and budget are ready.",
    })
    assert decision["execution_authorized"] is True
    assert decision["authority"]["merge"] is False

    dashboard = studio_dashboard(tmp_path)
    assert dashboard["products"][0]["journeys"]
    assert dashboard["slice_queue"][0]["priority"] >= 0
    assert ".factory/worktrees/" in dashboard["missions"][0]["worktree"].replace("\\", "/")
    assert dashboard["missions"][0]["branch"].startswith("codex/")
    assert dashboard["proof_timeline"][0]["requirement_id"]
    assert dashboard["receipt_comparison"]["status"] == "insufficient_runs"


def test_studio_gap_feedback_is_actionable_and_never_auto_invents_product_facts(tmp_path: Path):
    result = create_product_mission_from_studio(tmp_path, {
        "action": "product-mission", "prompt": "# Idea\n\nA useful dashboard.",
        "name": "idea", "resolution_mode": "auto_resolve_safe",
    })
    assert result["status"] == "needs_input"
    assert result["resolution"]["status"] == "human_input_required"
    assert result["resolution"]["auto_resolved"] == []
    assert all(item["next_action"] and item["approval_required"] for item in result["resolution"]["items"])
    assert "cannot be invented" in result["resolution"]["why_auto_stopped"]


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

        connection.request("GET", "/api/dashboard", headers={"X-Factory-Studio-Token": token})
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

        connection.request("GET", "/api/developer-memory", headers={"X-Factory-Studio-Token": token})
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

        connection.request("GET", "/api/graph-ops", headers={"X-Factory-Studio-Token": token})
        response = connection.getresponse()
        assert response.status == 200
        graph_ops = json.loads(response.read())
        assert graph_ops["schema"] == "factory.graph-ops.v1"
        assert graph_ops["authority"]["publication"] is False
        assert graph_ops["live_telemetry"]["activity"]["status"] == "idle"
        assert graph_ops["live_telemetry"]["refresh_interval_ms"] == 1000
        assert graph_ops["live_telemetry"]["recent_runs"] == []

        savings_body = json.dumps({
            "action": "savings-record", "pair_id": "http-pair",
            "baseline_elapsed_ms": 500, "factory_elapsed_ms": 300,
            "baseline_tokens": 50, "factory_tokens": 40,
        })
        connection.request(
            "POST", "/api/savings", body=savings_body,
            headers={"Content-Type": "application/json", "X-Factory-Studio-Token": token},
        )
        response = connection.getresponse()
        assert response.status == 201
        assert json.loads(response.read())["savings"]["time_saved_ms"] == 200

        connection.request("GET", "/api/savings", headers={"X-Factory-Studio-Token": token})
        response = connection.getresponse()
        assert response.status == 200
        savings = json.loads(response.read())
        assert savings["tokens"]["saved_total"] == 10

        connection.request("GET", "/favicon.ico")
        response = connection.getresponse()
        assert response.status == 204
        assert response.getheader("Content-Length") == "0"
        assert response.read() == b""

        body = json.dumps({"action": "create", "target": "worker", "prompt": "Build a worker.", "name": "http-worker"})
        connection.request("POST", "/api/create", body=body, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        assert response.status == 403
        assert response.getheader("Connection") == "close"
        token_failure = json.loads(response.read())
        assert token_failure["failure"]["point_of_failure"]
        assert token_failure["failure"]["next_action"]

        connection.request(
            "POST",
            "/api/create",
            body=b"{}",
            headers={"Content-Type": "application/json", "Content-Length": str(MAX_BODY_BYTES + 1), "X-Factory-Studio-Token": token},
        )
        assert connection.getresponse().status == 413
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_http_graph_ops_authorization_requires_token_and_consumes_one_reality_check(tmp_path: Path):
    from test_reality_check import _write
    from factoryline.graph_ops import graph_ops_snapshot
    from factoryline.reality_check import run_reality_check, write_reality_check_artifacts

    receipt = run_reality_check(tmp_path, _write(tmp_path))
    write_reality_check_artifacts(receipt, tmp_path / ".factory" / "reality")
    node_id = next(node["id"] for node in graph_ops_snapshot(tmp_path)["nodes"] if node["kind"] == "reality_check")
    server, token = create_server(tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    now = datetime.now(timezone.utc)
    authorization = {
        "action": "reality_check_execution", "id": "http-reality", "node_id": node_id,
        "approved_by": "reviewer", "rationale": "Run the exact declared behavior once.",
        "expires_at": (now + timedelta(hours=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "confirmation": "AUTHORIZE http-reality",
    }

    def post(path: str, payload: dict, session_token: str) -> tuple[int, dict]:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request("POST", path, body=json.dumps(payload), headers={
            "Content-Type": "application/json", "X-Factory-Studio-Token": session_token,
        })
        response = connection.getresponse()
        parsed = json.loads(response.read())
        connection.close()
        return response.status, parsed

    try:
        status, rejected = post("/api/graph-ops-authorize", authorization, "wrong-token")
        assert status == 403
        assert rejected["code"] == "TOKEN_REQUIRED"

        status, approved = post("/api/graph-ops-authorize", authorization, token)
        assert status == 201
        assert approved["marker"] == "GRAPH_OPS_HUMAN_AUTHORIZATION_RECORDED"

        status, executed = post("/api/graph-ops-run", {"authorization": approved["path"]}, token)
        assert status == 201
        assert executed["marker"] == "GRAPH_OPS_AUTHORIZED_REALITY_CHECK_EXECUTED"
        assert executed["receipt"]["marker"] == "REALITY_CHECK_VERIFIED"

        status, replayed = post("/api/graph-ops-run", {"authorization": approved["path"]}, token)
        assert status == 409
        assert replayed["code"] == "GRAPH_AUTHORIZATION_NOT_EXECUTABLE"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_http_mission_decision_rejects_wrong_token_escape_and_replay(tmp_path: Path):
    from test_product_missions import PRD

    mission = create_product_mission_from_studio(tmp_path, {
        "action": "product-mission", "prompt": PRD, "name": "decision-api",
        "executor": "codex", "owner": "product-owner",
    })
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
        connection.request("POST", "/api/mission-decision", body=body, headers={
            "Content-Type": "application/json",
            "X-Factory-Studio-Token": session_token,
        })
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

    monkeypatch.setattr("factoryline.studio.create_server", lambda root, port: (FakeServer(), "token"))
    serve_studio(tmp_path, open_browser=False, on_started=events.append)

    assert "http://127.0.0.1:43117/" in events
    assert events[-1] == "closed"
    assert "Factory Studio: http://127.0.0.1:43117/" in capsys.readouterr().out
