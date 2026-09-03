"""Behavioral checks for request-local assembly observation sharing, not gate caching."""
import importlib
import json
from collections import Counter

import pytest

from factoryline import graph_ops
from factoryline.cli import main

control = importlib.import_module("factoryline.mission_control_status")
READERS = ("oracle_firewall_projection", "operations_control_projection",
           "lifecycle_projection", "repair_loop_projection")
HELPERS = ("_append_oracle_firewall", "_append_operations_controls",
           "_append_lifecycle_events", "_append_repair_loops")


def _count_reads(monkeypatch):
    counts = Counter()
    for name in READERS:
        original = getattr(control, name)
        def counted(root, name=name, original=original):
            counts[name] += 1
            return original(root)
        monkeypatch.setattr(control, name, counted)
        monkeypatch.setattr(graph_ops, name, counted)
    return counts


def test_graph_reads_shared_stores_once_and_preserves_legacy_output(tmp_path, monkeypatch):
    counts = _count_reads(monkeypatch)
    optimized = graph_ops.graph_ops_snapshot(tmp_path)
    assert dict(counts) == {name: 1 for name in READERS}
    counts.clear()
    for name in HELPERS:
        original = getattr(graph_ops, name)
        def legacy(state, root, projection=None, original=original):
            return original(state, root)
        monkeypatch.setattr(graph_ops, name, legacy)
    legacy = graph_ops.graph_ops_snapshot(tmp_path)
    assert dict(counts) == {name: 2 for name in READERS}
    assert optimized == legacy


def test_next_graph_request_reads_fresh_invalid_evidence(tmp_path, monkeypatch):
    counts = _count_reads(monkeypatch)
    first = graph_ops.graph_ops_snapshot(tmp_path)
    directory = tmp_path / ".factory" / "operations-control"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "broken.json").write_text("not json", encoding="utf-8")
    second = graph_ops.graph_ops_snapshot(tmp_path)
    assert dict(counts) == {name: 2 for name in READERS}
    assert second["mission_control"]["blockers"]["operations_invalid"] > first["mission_control"]["blockers"]["operations_invalid"]
    assert second["mission_control"]["state"] == "blocked"
    assert not any(second["mission_control"]["authority"].values())


@pytest.mark.parametrize("helper", HELPERS)
def test_explicit_empty_observation_does_not_trigger_a_second_read(tmp_path, monkeypatch, helper):
    def forbidden(root):
        raise AssertionError("read was duplicated")
    for name in READERS:
        monkeypatch.setattr(graph_ops, name, forbidden)
    getattr(graph_ops, helper)({"nodes": {}, "edges": [], "edge_keys": set()}, tmp_path, {})


def test_profile_has_stable_fingerprints_and_no_raw_evidence(tmp_path, monkeypatch):
    ticks = iter(range(1000))
    monkeypatch.setattr(control.time, "perf_counter_ns", lambda: next(ticks))
    first = control.mission_control_profile(tmp_path)
    ticks = iter(range(0, 10000, 10))
    second = control.mission_control_profile(tmp_path)
    assert first["evidence_sha256"] == second["evidence_sha256"]
    assert first["reader_elapsed_ns"] == 5
    assert second["reader_elapsed_ns"] == 50
    assert len(first["spans"]) == 5
    assert all(set(span) == {"name", "elapsed_ns", "output_sha256"} for span in first["spans"])
    assert all(len(span["output_sha256"]) == 64 for span in first["spans"])
    assert "evidence" not in first
    assert not any(first["authority"].values())


def test_profile_fingerprint_changes_with_evidence(tmp_path, monkeypatch):
    before = control.mission_control_profile(tmp_path)
    monkeypatch.setattr(control, "operations_control_projection", lambda root: {"invalid_count": 7})
    after = control.mission_control_profile(tmp_path)
    assert before["evidence_sha256"] != after["evidence_sha256"]


def test_profile_does_not_export_private_values(tmp_path, monkeypatch):
    monkeypatch.setattr(control, "operations_control_projection", lambda root: {"private": "never-display-this-value"})
    assert "never-display-this-value" not in json.dumps(control.mission_control_profile(tmp_path))


def test_reader_failure_does_not_return_a_success_profile(tmp_path, monkeypatch):
    def failed(root):
        raise OSError("cannot read evidence")
    monkeypatch.setattr(control, "operations_control_projection", failed)
    with pytest.raises(OSError):
        control.mission_control_profile(tmp_path)


def test_profile_cli(tmp_path, capsys):
    assert main(["mission-control", "profile", "--root", str(tmp_path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["schema"] == "factory.mission-control-profile.v1"
    assert len(result["spans"]) == 5
