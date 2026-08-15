from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from factoryline.change_review import review_change
from factoryline.cli import main
from factoryline.github_assurance_dossier import (
    GITHUB_ASSURANCE_EXCEPTION_SCHEMA,
    GITHUB_POLICY_SNAPSHOT_SCHEMA,
    GitHubAssuranceDossierError,
    build_assurance_dossier,
    policy_snapshot_sha256,
    write_assurance_dossier_artifacts,
)
from factoryline.github_proof_review import render_github_proof_review
from factoryline.graph_ops import graph_ops_snapshot


HEAD = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
NOW = datetime(2026, 8, 15, tzinfo=timezone.utc)


def _snapshot(*, checks: list[str] | None = None, signed: bool = True) -> dict:
    return {
        "schema": GITHUB_POLICY_SNAPSHOT_SCHEMA, "captured_at": "2026-08-15T10:00:00+00:00",
        "scope": {"owner": "factoryline", "repository": "demo"},
        "capture": {"source": "github_api_export", "captured_by": "release.engineer", "source_reference": "rulesets-export-001"},
        "rulesets": [{"id": "main-protection", "name": "Main protection", "enforcement": "active", "required_checks": checks if checks is not None else ["factory-proof", "tests"], "required_workflows": ["verify"], "require_signed_commits": signed, "allow_force_pushes": False, "bypass_actors": []}],
    }


def _proof(root: Path) -> dict:
    return render_github_proof_review(review_change(root, changed=["factoryline/tool.py"]), HEAD)


def _exception(snapshot: dict, finding_ids: list[str], *, head: str = HEAD) -> dict:
    return {"schema": GITHUB_ASSURANCE_EXCEPTION_SCHEMA, "id": "temporary-controls-exception", "approval": {"state": "approved", "approved_by": "security.owner"}, "expires_at": "2026-08-20T10:00:00+00:00", "policy_sha256": policy_snapshot_sha256(snapshot), "head_sha": head, "finding_ids": finding_ids}


def test_assurance_dossier_is_deterministic_and_writes_only_to_explicit_directory(tmp_path: Path) -> None:
    proof = _proof(tmp_path)
    dossier = build_assurance_dossier(proof, _snapshot(), _snapshot(), now=NOW)

    assert dossier["status"] == "policy_aligned"
    assert dossier["drift"] == {"baseline_supplied": True, "findings": [], "unresolved_high_count": 0}
    assert dossier["authority"]["merge"] is False
    assert "does not fetch or prove the live GitHub configuration" in dossier["dossier_markdown"]
    artifacts = write_assurance_dossier_artifacts(dossier, tmp_path / ".factory" / "github-assurance")
    assert set(artifacts["paths"]) == {"json", "markdown", "mermaid"}
    assert all(Path(path).is_file() for path in artifacts["paths"].values())


def test_assurance_dossier_reports_deterministic_high_drift_and_named_exception(tmp_path: Path) -> None:
    current = _snapshot(checks=["tests"], signed=False)
    unapproved = build_assurance_dossier(_proof(tmp_path), current, _snapshot(), now=NOW)
    ids = [item["id"] for item in unapproved["drift"]["findings"]]
    assert unapproved["status"] == "review_required"
    assert ids == ["ruleset:main-protection:check:factory-proof", "ruleset:main-protection:signed_commits"]

    accepted = build_assurance_dossier(_proof(tmp_path), current, _snapshot(), [_exception(current, ids)], now=NOW)
    assert accepted["status"] == "exception_accepted"
    assert accepted["drift"]["unresolved_high_count"] == 0


def test_assurance_dossier_rejects_expired_or_wrongly_bound_exception_before_write(tmp_path: Path) -> None:
    current = _snapshot(checks=["tests"])
    exception = _exception(current, ["ruleset:main-protection:check:factory-proof"], head="0" * 40)
    with pytest.raises(GitHubAssuranceDossierError) as exc:
        build_assurance_dossier(_proof(tmp_path), current, _snapshot(), [exception], now=NOW)
    assert exc.value.code == "GITHUB_ASSURANCE_EXCEPTION_INVALID"


def test_assurance_dossier_cli_writes_receipt_then_returns_blocking_status(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    review_path, current_path, baseline_path = tmp_path / "review.json", tmp_path / "current.json", tmp_path / "baseline.json"
    review_path.write_text(json.dumps(_proof(tmp_path)), encoding="utf-8")
    current_path.write_text(json.dumps(_snapshot(checks=["tests"])), encoding="utf-8")
    baseline_path.write_text(json.dumps(_snapshot()), encoding="utf-8")
    out_dir = tmp_path / ".factory" / "github-assurance"

    assert main(["github", "assurance-dossier", "--proof-review", str(review_path), "--policy-snapshot", str(current_path), "--baseline-policy-snapshot", str(baseline_path), "--out-dir", str(out_dir), "--require-aligned", "--json"]) == 3
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "review_required"
    assert Path(result["artifacts"]["paths"]["json"]).is_file()


def test_graph_ops_projects_valid_assurance_dossier_and_recommends_human_drift_resolution(tmp_path: Path) -> None:
    dossier = build_assurance_dossier(_proof(tmp_path), _snapshot(checks=["tests"]), _snapshot(), now=NOW)
    write_assurance_dossier_artifacts(dossier, tmp_path / ".factory" / "github-assurance")

    graph = graph_ops_snapshot(tmp_path)
    assert graph["facts"]["assurance_dossier_count"] == 1
    assert graph["facts"]["assurance_unresolved_high_count"] == 1
    assert graph["recommendation"]["action"] == "resolve_policy_drift"
    assert "GRAPH_OPS_GITHUB_ASSURANCE_PROJECTED" in graph["markers"]
    assert any(node["kind"] == "policy_drift" for node in graph["nodes"])
