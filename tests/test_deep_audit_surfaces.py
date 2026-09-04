import json
from pathlib import Path

import pytest

from test_deep_audit import inputs
from factoryline.cli import main
from factoryline.deep_audit import execute_deep_audit
from factoryline.mcp import _deep_audit_status, McpError, dispatch
from factoryline.mission_control_status import mission_control_status
from factoryline.ide_playbook import ide_playbook


@pytest.mark.parametrize("clean", [False, True])
def test_cli_evaluates_signed_inputs_and_status(tmp_path, capsys, clean):
    args, _, _, _ = inputs(tmp_path, clean=clean)
    argv = ["deep-audit", "evaluate", "--plan", str(args[0]), "--trust-root", str(args[1]),
            "--trust-root-sha256", args[2], "--root", str(tmp_path)]
    assert main(argv) == (0 if clean else 1)
    output = json.loads(capsys.readouterr().out)
    assert output["authority"] == "none"
    assert main(["deep-audit", "status", "--root", str(tmp_path)]) == (0 if clean else 1)
    assert json.loads(capsys.readouterr().out)["state"] == output["receipt"]["decision"]


def test_no_evidence_is_not_a_green_cli(tmp_path, capsys):
    assert main(["deep-audit", "status", "--root", str(tmp_path)]) == 1
    assert json.loads(capsys.readouterr().out)["state"] == "NOT_RUN"


@pytest.mark.parametrize("clean", [False, True])
def test_mission_and_mcp_preserve_review_boundary(tmp_path, clean):
    args, _, _, _ = inputs(tmp_path, clean=clean)
    execute_deep_audit(*args)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    mcp = _deep_audit_status(tmp_path, {})
    mission = mission_control_status(tmp_path)
    assert mission["evidence"]["deep_audit"] == mcp["status"]
    assert mission["state"] == ("review_required" if clean else "blocked")
    assert not any(mission["authority"].values())
    assert before == {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    with pytest.raises(McpError):
        _deep_audit_status(tmp_path, {"approve": True})


def test_tampering_blocks_mission(tmp_path):
    args, _, _, _ = inputs(tmp_path, clean=True)
    result = execute_deep_audit(*args)
    Path(result["receipt_path"]).write_text("{}")
    assert mission_control_status(tmp_path)["blockers"]["deep_audit_blocked"] == 1


def test_playbook_discovers_read_only_tool():
    assert "factory.deep_audit_status" in json.dumps(ide_playbook())


def test_mcp_dispatch_routes_to_read_only_status(tmp_path):
    response = dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "factory.deep_audit_status", "arguments": {}}}, tmp_path)
    body = json.loads(response["result"]["content"][0]["text"])
    assert body["marker"] == "DEEP_AUDIT_MCP_READ_ONLY"
    assert body["status"]["state"] == "NOT_RUN"
    assert not list(tmp_path.iterdir())
