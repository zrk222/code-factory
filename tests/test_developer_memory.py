from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess

import pytest

from factoryline.change_review import ChangeReviewError
from factoryline.cli import main
from factoryline.continuity import ContinuityPrincipal, ContinuityStore
from factoryline.developer_memory import MAX_ACTIONS, developer_memory_brief
from factoryline.proof_reuse import record_proof


def _files(root: Path) -> dict[str, bytes]:
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def _stale_proof_workspace(root: Path) -> None:
    (root / "input.txt").write_text("before", encoding="utf-8")
    (root / "output.txt").write_text("green", encoding="utf-8")
    record_proof(root, {
        "name": "unit", "command": ["python", "-m", "pytest"], "read_only": True,
        "inputs": ["input.txt"], "outputs": ["output.txt"],
    }, elapsed_ms=50)
    (root / "input.txt").write_text("after", encoding="utf-8")


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(["git", *arguments], cwd=root, check=True, capture_output=True, text=True)


def _continuity_record() -> dict[str, object]:
    return {
        "schema": "factory.continuity.record.v1",
        "tenant_id": "tenant-a",
        "record_type": "lesson",
        "memory_ref": "memory://private/strategy-42",
        "purpose": {"id": "delivery-review", "version": "1"},
        "scope": {"repository_ref": "repo:sha256:private"},
        "evidence_refs": ["receipt:sha256:proof-001"],
        "summary": "private continuity summary",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=3)).isoformat(),
    }


def _principal(subject: str, roles: tuple[str, ...]) -> ContinuityPrincipal:
    return ContinuityPrincipal(subject, "tenant-a", roles, ("delivery-review@1",))


def test_developer_memory_brief_makes_stale_proof_visual_action_without_writing(tmp_path: Path) -> None:
    _stale_proof_workspace(tmp_path)
    before = _files(tmp_path)

    brief = developer_memory_brief(tmp_path, changed=["input.txt"])

    assert brief["schema"] == "factory.developer-memory-brief.v1"
    assert "DEVELOPER_MEMORY_BRIEF_V1" in brief["markers"]
    assert "DEVELOPER_MEMORY_CHANGE_REVIEW_EXACT" in brief["markers"]
    assert "DEVELOPER_MEMORY_STALE_PROOF_ACTIONS" in brief["markers"]
    assert "DEVELOPER_MEMORY_VISUAL_EXPLAINED" in brief["markers"]
    assert brief["actions"][0]["kind"] == "rerun_stale_proof"
    assert brief["actions"][0]["evidence"]["proof_id"]
    assert brief["actions"][0]["evidence"]["review_sha256"] == brief["change_review"]["review_sha256"]
    assert brief["presentation"]["action_fields"] == ["what_changed", "why_it_matters", "do_this_next", "evidence"]
    assert brief["authority"]["external_effects"] is False
    assert all(value is False for value in brief["authority"].values())
    assert _files(tmp_path) == before
    assert developer_memory_brief(tmp_path, changed=["input.txt"])["brief_sha256"] == brief["brief_sha256"]


def test_developer_memory_brief_withholds_continuity_bodies(tmp_path: Path) -> None:
    store = ContinuityStore(tmp_path / ".factory" / "continuity.sqlite3")
    store.record(_principal("worker", ("writer",)), _continuity_record(), idempotency_key="memory", record_id="private-record")
    store.promote(_principal("reviewer", ("promoter",)), "tenant-a", "private-record", reason="independent review")

    brief = developer_memory_brief(tmp_path, changed=["app/service.py"])
    rendered = json.dumps(brief, sort_keys=True)

    assert "DEVELOPER_MEMORY_REDACTED_CONTINUITY" in brief["markers"]
    assert brief["continuity"]["record_ids"] == ["private-record"]
    assert "memory://private/strategy-42" not in rendered
    assert "private continuity summary" not in rendered
    assert brief["actions"][0]["kind"] == "bind_changed_path_to_proof"


def test_developer_memory_attributes_observed_local_git_contributors_without_claiming_seats(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.name", "Ada Lovelace")
    _git(tmp_path, "config", "user.email", "ada@example.test")
    (tmp_path / "app.py").write_text("first\n", encoding="utf-8")
    _git(tmp_path, "add", "app.py")
    _git(tmp_path, "commit", "-m", "Ada adds app")
    _git(tmp_path, "config", "user.name", "Grace Hopper")
    _git(tmp_path, "config", "user.email", "grace@example.test")
    (tmp_path / "app.py").write_text("second\n", encoding="utf-8")
    _git(tmp_path, "add", "app.py")
    _git(tmp_path, "commit", "-m", "Grace updates app")

    brief = developer_memory_brief(tmp_path, changed=["app.py"])

    assert "DEVELOPER_MEMORY_TEAM_ATTRIBUTION_LOCAL_GIT" in brief["markers"]
    assert brief["team"]["source"] == {
        "kind": "local_git_history",
        "directory_connected": False,
        "roster_completeness": "observed_contributors_only",
        "scope": "all local Git refs",
    }
    names = {seat["display_name"] for seat in brief["team"]["seats"]}
    assert names == {"Ada Lovelace", "Grace Hopper"}
    assert all("email" not in seat for seat in brief["team"]["seats"])
    assert brief["actions"][0]["contributor_seat_ids"]
    assert "billing" not in json.dumps(brief["team"]["source"]).lower()
    assert "not a verified identity-provider or billing-seat roster" in brief["team"]["scope_limits"][0]


def test_developer_memory_reports_unavailable_change_set_without_inference(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(*_args, **_kwargs):
        raise ChangeReviewError("DIFF_BASE_UNAVAILABLE", "base unavailable")

    monkeypatch.setattr("factoryline.developer_memory.review_change", unavailable)

    brief = developer_memory_brief(tmp_path)

    assert "DEVELOPER_MEMORY_UNAVAILABLE_EXPLICIT" in brief["markers"]
    assert brief["actions"] == [brief["actions"][0]]
    assert brief["actions"][0]["kind"] == "change_review_unavailable"
    assert brief["actions"][0]["evidence"]["failure_code"] == "DIFF_BASE_UNAVAILABLE"
    assert brief["change_review"]["changed_paths"] == []
    assert "productivity" in brief["scope_limits"][0]


def test_developer_memory_caps_action_cards_before_lower_priority_advice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = [f"src/path-{index}.py" for index in range(MAX_ACTIONS + 4)]
    review = {
        "base": "main", "input_source": "explicit", "changed_paths": paths,
        "review_sha256": "a" * 64,
        "impact": {"unmatched_changed_paths": paths, "rerun_proofs": []},
        "coverage": {"ok": True, "uncovered": []},
        "risk": {"rerun_stages": []},
        "unproven_claims": [],
    }
    monkeypatch.setattr("factoryline.developer_memory.review_change", lambda *_args, **_kwargs: review)

    brief = developer_memory_brief(tmp_path, changed=paths)

    assert len(brief["actions"]) == MAX_ACTIONS
    assert all(action["kind"] == "bind_changed_path_to_proof" for action in brief["actions"])
    assert brief["next_action"]["id"] == "scope-gap:src/path-0.py"


def test_developer_memory_cli_is_machine_readable_and_read_only(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _stale_proof_workspace(tmp_path)
    before = _files(tmp_path)

    assert main(["memory", "brief", "--root", str(tmp_path), "--changed", "input.txt", "--json"]) == 0

    brief = json.loads(capsys.readouterr().out)
    assert brief["schema"] == "factory.developer-memory-brief.v1"
    assert brief["next_action"]["action"] == "rerun_stale_proof"
    assert _files(tmp_path) == before
