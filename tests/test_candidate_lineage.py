from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from factoryline.candidate_lineage import CandidateLineageError, verify_candidate_lineage
from factoryline.cli import main
from factoryline.deep_audit import execute_deep_audit
from factoryline.graph_forensics import seal_graph_lineage

from test_deep_audit import inputs
from test_oracle_firewall import _contract


def _steps() -> list[dict]:
    return [
        {
            "sequence": 1,
            "superstep": 1,
            "node_id": "verify",
            "checkpoint_id": "cp-1",
            "reads": [],
            "writes": [],
            "evidence": [{"path": "evidence/verify.json", "sha256": "a" * 64}],
            "side_effects": [],
            "decision": {"route": "next", "reason": "candidate evidence checked"},
        }
    ]


def _manifest(root: Path, oracle: Path, candidate: str, deep: Path, graph: Path) -> Path:
    rows = []
    for identifier, kind, path in (("deep", "deep_audit", deep), ("graph", "graph_lineage", graph)):
        rows.append({"id": identifier, "kind": kind, "path": path.relative_to(root).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    path = root / "continuity.json"
    path.write_text(
        json.dumps(
            {
                "schema": "factory.candidate-lineage-input.v1",
                "id": "candidate-review",
                "candidate_sha256": candidate,
                "oracle_contract": {"path": oracle.relative_to(root).as_posix(), "contract_sha256": json.loads(oracle.read_text())["contract_sha256"]},
                "evidence": rows,
                "authority": "none",
            }
        ),
        encoding="utf-8",
    )
    return path


def _fixture(root: Path) -> tuple[Path, Path, Path, Path, str]:
    oracle = _contract(root)
    args, *_ = inputs(root, clean=True)
    audit = execute_deep_audit(*args)
    deep = Path(audit["receipt_path"])
    candidate = audit["receipt"]["candidate_sha256"]
    steps = root / "steps.json"
    steps.write_text(json.dumps(_steps()), encoding="utf-8")
    graph = root / "graph.json"
    seal_graph_lineage("run-1", "review", steps, graph, candidate_sha256=candidate)
    return oracle, deep, graph, _manifest(root, oracle, candidate, deep, graph), candidate


def test_candidate_lineage_verifies_one_current_candidate(tmp_path: Path):
    _, _, _, manifest, candidate = _fixture(tmp_path)
    result = verify_candidate_lineage(tmp_path, manifest)
    assert result["marker"] == "CANDIDATE_LINEAGE_VERIFIED"
    assert result["candidate_sha256"] == candidate
    assert result["evidence_kinds"] == ["deep_audit", "graph_lineage"]
    assert result["release_approval"] is False
    assert all(value is False for value in result["authority"].values())


def test_cli_surfaces_continuity_receipt_without_authority(tmp_path: Path, capsys):
    _, _, _, manifest, _ = _fixture(tmp_path)
    assert main(["graph", "lineage-continuity", str(manifest), "--root", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["marker"] == "CANDIDATE_LINEAGE_VERIFIED"
    assert payload["release_approval"] is False


def test_legacy_graph_is_readable_but_not_strictly_candidate_bound(tmp_path: Path):
    oracle, deep, _, _, candidate = _fixture(tmp_path)
    steps = tmp_path / "legacy-steps.json"
    steps.write_text(json.dumps(_steps()), encoding="utf-8")
    legacy = tmp_path / "legacy.json"
    seal_graph_lineage("run-legacy", "review", steps, legacy)
    manifest = _manifest(tmp_path, oracle, candidate, deep, legacy)
    with pytest.raises(CandidateLineageError) as raised:
        verify_candidate_lineage(tmp_path, manifest)
    assert raised.value.code == "E_CANDIDATE_LINEAGE_GRAPH"


def test_mixed_candidate_graph_fails_closed(tmp_path: Path):
    oracle, deep, _, _, candidate = _fixture(tmp_path)
    steps = tmp_path / "other-steps.json"
    steps.write_text(json.dumps(_steps()), encoding="utf-8")
    graph = tmp_path / "other.json"
    seal_graph_lineage("run-other", "review", steps, graph, candidate_sha256="b" * 64)
    manifest = _manifest(tmp_path, oracle, candidate, deep, graph)
    with pytest.raises(CandidateLineageError) as raised:
        verify_candidate_lineage(tmp_path, manifest)
    assert raised.value.code == "E_CANDIDATE_LINEAGE_GRAPH"


def test_stale_evidence_digest_and_incomplete_kinds_fail_closed(tmp_path: Path):
    oracle, deep, graph, manifest, _ = _fixture(tmp_path)
    payload = json.loads(manifest.read_text())
    payload["evidence"][0]["sha256"] = "c" * 64
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CandidateLineageError) as raised:
        verify_candidate_lineage(tmp_path, manifest)
    assert raised.value.code == "E_CANDIDATE_LINEAGE_EVIDENCE"

    payload["evidence"] = [payload["evidence"][1]]
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CandidateLineageError) as raised:
        verify_candidate_lineage(tmp_path, manifest)
    assert raised.value.code == "E_CANDIDATE_LINEAGE_EVIDENCE"


def test_oracle_authority_and_workspace_paths_fail_closed(tmp_path: Path):
    oracle, deep, graph, manifest, candidate = _fixture(tmp_path)
    payload = json.loads(manifest.read_text())
    payload["authority"] = {"publish": True}
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CandidateLineageError) as raised:
        verify_candidate_lineage(tmp_path, manifest)
    assert raised.value.code == "E_CANDIDATE_LINEAGE_AUTHORITY"

    payload["authority"] = "none"
    payload["oracle_contract"]["path"] = "../outside.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CandidateLineageError) as raised:
        verify_candidate_lineage(tmp_path, manifest)
    assert raised.value.code == "E_CANDIDATE_LINEAGE_PATH"

    link = tmp_path / "oracle-link.json"
    try:
        link.symlink_to(oracle)
    except OSError:
        pytest.skip("symlink creation is unavailable on this Windows host")
    payload["oracle_contract"]["path"] = link.name
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CandidateLineageError) as raised:
        verify_candidate_lineage(tmp_path, manifest)
    assert raised.value.code == "E_CANDIDATE_LINEAGE_PATH"
