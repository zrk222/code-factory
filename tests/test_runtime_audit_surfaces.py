from pathlib import Path

from factoryline.ide_playbook import ide_playbook
from factoryline.mcp import dispatch
from factoryline.mission_control_status import mission_control_status


def test_runtime_assurance_is_visible_to_agents_humans_and_mcp(tmp_path: Path):
    playbook = ide_playbook()
    pack = next(item for item in playbook["capability_packs"] if item["id"] == "runtime_assurance")
    assert pack["next"] == "factory.runtime_audit_status"
    mission = mission_control_status(tmp_path)
    assert mission["evidence"]["runtime_assurance"]["state"] == "NOT_RUN"
    inventory = dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, tmp_path)
    assert "factory.runtime_audit_status" in [item["name"] for item in inventory["result"]["tools"]]
    call = dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "factory.runtime_audit_status"}}, tmp_path)
    assert call["result"]["content"][0]["text"].find("RUNTIME_AUDIT_MCP_READ_ONLY") >= 0


def test_graph_ops_ui_shows_six_lanes_and_actionable_output():
    html = Path("factoryline/graph_ops.html").read_text(encoding="utf-8")
    assert "RUNTIME_ASSURANCE_SIX_LANES" in html
    for label in ("Stateful workflows", "Tenant isolation", "Failure recovery", "Consumer compatibility", "Migration integrity", "Performance + memory"):
        assert label in html
    assert "Next repair:" in html
