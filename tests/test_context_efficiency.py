import json

import pytest

from factoryline.context_efficiency import (
    ContextEfficiencyError,
    REQUEST_SCHEMA,
    build_context_packet,
    context_efficiency_status,
    verify_context_packet,
)
from factoryline.cli import main
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.mission_control_status import mission_control_status


def _request(paths=("README.md",), **overrides):
    value = {
        "schema": REQUEST_SCHEMA,
        "mission_id": "speed-slice",
        "contract_digest": "a" * 64,
        "changed_paths": list(paths),
        "sources": [
            {"path": path, "role": "intent", "priority": 100 - index}
            for index, path in enumerate(paths)
        ],
        "max_tokens": 256,
        "per_file_tokens": 64,
    }
    value.update(overrides)
    return value


def test_packet_is_bounded_and_verifiable(tmp_path):
    (tmp_path / "README.md").write_text(
        "intent\n" + ("detail " * 1000), encoding="utf-8"
    )
    packet = build_context_packet(tmp_path, _request())
    assert packet["budget"]["decision"] == "TRUNCATED"
    assert (
        packet["budget"]["token_quality"]
        == "estimated_from_utf8_bytes_not_provider_usage"
    )
    assert packet["budget"]["selected_bytes"] <= packet["budget"]["max_bytes"]
    result = verify_context_packet(tmp_path, tmp_path / packet["cache"]["path"])
    assert result["valid"] is True


def test_secret_file_is_digest_only(tmp_path):
    (tmp_path / "api-token.txt").write_text("not for context", encoding="utf-8")
    packet = build_context_packet(tmp_path, _request(paths=("api-token.txt",)))
    assert packet["sources"][0]["inclusion"] == "digest_only"
    assert "excerpt" not in packet["sources"][0]


def test_secret_material_in_request_is_rejected(tmp_path):
    (tmp_path / "README.md").write_text("safe", encoding="utf-8")
    with pytest.raises(ContextEfficiencyError, match="E_SECRET_MATERIAL"):
        build_context_packet(tmp_path, _request(token="do-not-accept"))


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_tokens", 255),
        ("max_tokens", 12001),
        ("per_file_tokens", 31),
        ("per_file_tokens", 2001),
    ],
)
def test_budget_bounds_are_fail_closed(tmp_path, field, value):
    (tmp_path / "README.md").write_text("safe", encoding="utf-8")
    with pytest.raises(ContextEfficiencyError, match="E_FIELD"):
        build_context_packet(tmp_path, _request(**{field: value}))


def test_traversal_and_symlink_are_rejected(tmp_path):
    (tmp_path / "README.md").write_text("safe", encoding="utf-8")
    with pytest.raises(ContextEfficiencyError, match="E_PATH_BOUNDARY"):
        build_context_packet(tmp_path, _request(paths=("../README.md",)))
    link = tmp_path / "link.md"
    try:
        link.symlink_to(tmp_path / "README.md")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(ContextEfficiencyError, match="E_PATH_LINK"):
        build_context_packet(tmp_path, _request(paths=("link.md",)))


def test_second_build_reuses_exact_cache(tmp_path):
    (tmp_path / "README.md").write_text("stable", encoding="utf-8")
    first = build_context_packet(tmp_path, _request())
    second = build_context_packet(tmp_path, _request())
    assert first["cache"]["key"] == second["cache"]["key"]
    assert first["packet_sha256"] != second["packet_sha256"]
    assert second["cache"]["hit"] is True
    assert context_efficiency_status(tmp_path)["cache_hits"] == 1


def test_source_drift_blocks_verification(tmp_path):
    (tmp_path / "README.md").write_text("before", encoding="utf-8")
    packet = build_context_packet(tmp_path, _request())
    (tmp_path / "README.md").write_text("after", encoding="utf-8")
    result = verify_context_packet(tmp_path, tmp_path / packet["cache"]["path"])
    assert result["state"] == "BLOCKED"
    assert result["code"] == "E_SOURCE_DRIFT"


def test_status_missing_ready_and_invalid(tmp_path):
    assert context_efficiency_status(tmp_path)["state"] == "MISSING"
    (tmp_path / "README.md").write_text("safe", encoding="utf-8")
    build_context_packet(tmp_path, _request())
    assert context_efficiency_status(tmp_path)["state"] == "READY"
    broken = tmp_path / ".factory" / "context-efficiency" / "broken.json"
    broken.write_text("{}", encoding="utf-8")
    status = context_efficiency_status(tmp_path)
    assert status["state"] == "BLOCKED"
    assert status["invalid_count"] == 1


def test_cli_pack_verify_and_status_are_read_only(tmp_path, capsys):
    (tmp_path / "README.md").write_text("safe", encoding="utf-8")
    manifest = tmp_path / "request.json"
    manifest.write_text(json.dumps(_request()), encoding="utf-8")
    assert (
        main(
            [
                "efficiency",
                "pack",
                "--manifest",
                str(manifest),
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    packet = json.loads(capsys.readouterr().out)
    packet_path = tmp_path / packet["cache"]["path"]
    assert (
        main(
            [
                "efficiency",
                "verify",
                str(packet_path),
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert main(["efficiency", "status", "--root", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "READY"


def test_mission_and_graph_surface_invalid_cache_as_review_only(tmp_path):
    directory = tmp_path / ".factory" / "context-efficiency"
    directory.mkdir(parents=True)
    (directory / "broken.json").write_text("{}", encoding="utf-8")
    mission = mission_control_status(tmp_path)
    assert mission["blockers"]["context_efficiency_blocked"] == 1
    assert (
        mission["human_control_plane"]["next_action"]
        == "repair_context_efficiency_packet"
    )
    assert all(value is False for value in mission["authority"].values())
    snapshot = graph_ops_snapshot(tmp_path)
    assert snapshot["facts"]["context_efficiency_blocked"] == 1
    assert snapshot["recommendation"]["action"] == "repair_context_efficiency_packet"
    assert "GRAPH_OPS_CONTEXT_EFFICIENCY_REVIEW_REQUIRED" in snapshot["markers"]
