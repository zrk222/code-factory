from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.github_plan_proof_review import (
    GitHubPlanProofReviewError,
    compile_github_plan_proof_review,
    render_github_plan_proof_review,
    write_github_plan_proof_review_artifacts,
)
from factoryline.plan_proof_review import (
    PlanProofReviewError,
    review_plan_proof,
    validate_agent_plan,
    write_plan_proof_review_artifacts,
)


HEAD_SHA = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"


def _plan(root: Path, *, deep: bool = False) -> Path:
    item = {
        "id": "auth-flow" if deep else "service-flow",
        "paths": ["src/auth.py" if deep else "src/service.py"],
        "test_paths": ["tests/test_auth.py" if deep else "tests/test_service.py"],
        "review_tier": "deep" if deep else "standard",
    }
    if deep:
        item["review_owner"] = "security-owner"
    plan = {
        "schema": "factory.agent_plan.v1",
        "provider": "generic",
        "plan_id": "AAP-42",
        "approval": {"state": "approved", "approved_by": "Engineering Lead"},
        "items": [item],
    }
    path = root / "agent-plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    return path


def _files(root: Path) -> dict[str, bytes]:
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def test_plan_review_prioritizes_unplanned_paths_and_opens_deterministic_proof_debt(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    before = _files(tmp_path)

    review = review_plan_proof(tmp_path, plan, changed=["src/service.py", "src/secret.py"])

    assert review["schema"] == "factory.plan_proof_review.v1"
    assert {
        "PLAN_TO_PROOF_UNPLANNED_PATH_PRIORITY",
        "PLAN_TO_PROOF_DECLARED_TEST_EXACT",
        "PLAN_TO_PROOF_DEEP_REVIEW_ROUTED",
        "PLAN_TO_PROOF_INVALID_REJECTED",
    }.issubset(review["markers"])
    assert review["findings"][0]["kind"] == "unplanned_changed_path"
    assert review["next_action"]["action"] == "reconcile_unplanned_change"
    assert review["alignment"]["unplanned_changed_paths"] == ["src/secret.py"]
    assert review["proof_debt"]["schema"] == "factory.proof_debt.v1"
    assert review["proof_debt"]["state"] == "open"
    assert review["proof_debt"]["items"][0]["kind"] == "unplanned_changed_path"
    assert "agent plan as complete" not in review["review_markdown"].lower()
    assert _files(tmp_path) == before


def test_plan_review_requires_declared_test_change_without_claiming_execution(tmp_path: Path) -> None:
    plan = _plan(tmp_path)

    review = review_plan_proof(tmp_path, plan, changed=["src/service.py"])

    finding = next(item for item in review["findings"] if item["kind"] == "declared_test_path_missing")
    assert finding["facts"]["test_paths"] == ["tests/test_service.py"]
    assert review["next_action"]["action"] == "provide_declared_test_change"
    assert "test executed" not in review["review_markdown"].lower()
    assert "not evidence" in review["scope_limits"][1].lower()


def test_deep_plan_review_routes_to_named_human_without_claiming_completed_review(tmp_path: Path) -> None:
    plan = _plan(tmp_path, deep=True)

    review = review_plan_proof(tmp_path, plan, changed=["src/auth.py", "tests/test_auth.py"])

    finding = next(item for item in review["findings"] if item["kind"] == "named_human_review_required")
    assert finding["facts"]["review_owner"] == "security-owner"
    assert review["next_action"]["action"] == "route_to_named_reviewer"
    assert "completed human review" not in review["review_markdown"].lower()


@pytest.mark.parametrize("mutator", [
    lambda payload: payload.__setitem__("extra", True),
    lambda payload: payload["approval"].__setitem__("state", "draft"),
    lambda payload: payload["items"].append(dict(payload["items"][0])),
    lambda payload: payload["items"][0].__setitem__("paths", ["../escape.py"]),
])
def test_plan_validation_rejects_malformed_or_unapproved_inputs_before_artifacts(tmp_path: Path, mutator) -> None:
    plan_path = _plan(tmp_path)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    mutator(payload)
    malformed = tmp_path / "malformed.json"
    malformed.write_text(json.dumps(payload), encoding="utf-8")
    out_dir = tmp_path / "out"

    with pytest.raises(PlanProofReviewError) as exc:
        review_plan_proof(tmp_path, malformed, changed=["src/service.py"])

    assert exc.value.code == "PLAN_TO_PROOF_PLAN_INVALID"
    assert not out_dir.exists()


def test_plan_review_writes_only_explicit_artifacts_and_rejects_tampered_payload(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    plan = _plan(workspace)
    review = review_plan_proof(workspace, plan, changed=["src/service.py", "tests/test_service.py"])
    before = _files(workspace)
    artifacts = write_plan_proof_review_artifacts(review, tmp_path / "packet")

    assert artifacts["marker"] == "PLAN_TO_PROOF_ARTIFACTS_WRITTEN"
    assert set(artifacts["paths"]) == {"json", "markdown", "mermaid"}
    assert all(Path(path).is_file() for path in artifacts["paths"].values())
    assert _files(workspace) == before
    review["next_action"]["action"] = "tampered"
    with pytest.raises(PlanProofReviewError) as exc:
        write_plan_proof_review_artifacts(review, tmp_path / "tampered")
    assert exc.value.code == "PLAN_TO_PROOF_REVIEW_INVALID"


def test_github_plan_review_is_sha_bound_neutral_and_uses_existing_stable_marker(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    review = review_plan_proof(tmp_path, plan, changed=["src/service.py", "tests/test_service.py"])
    payload = render_github_plan_proof_review(review, HEAD_SHA)

    assert payload["schema"] == "factory.github_plan_proof_review.v1"
    assert payload["head_sha"] == HEAD_SHA
    assert {
        "GITHUB_PLAN_PROOF_REVIEW_CHECK_ADVISORY",
        "GITHUB_PLAN_PROOF_REVIEW_WORKFLOW_SCOPED",
    }.issubset(payload["markers"])
    assert payload["check"]["name"] == "FactoryLine / Proof Review"
    assert payload["check"]["conclusion"] == "neutral"
    assert "<!-- factoryline-proof-review -->" in payload["github_comment"]
    assert "CodeRabbit" not in payload["github_comment"]
    assert payload["proof_debt"] == review["proof_debt"]
    assert render_github_plan_proof_review(review, HEAD_SHA)["payload_sha256"] == payload["payload_sha256"]
    with pytest.raises(GitHubPlanProofReviewError):
        render_github_plan_proof_review(review, "ABC")


def test_github_plan_review_artifacts_and_cli_are_local_only(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    plan = _plan(tmp_path)
    payload = compile_github_plan_proof_review(tmp_path, plan, changed=["src/service.py", "tests/test_service.py"], head_sha=HEAD_SHA)
    artifacts = write_github_plan_proof_review_artifacts(payload, tmp_path / "github-packet")

    assert artifacts["marker"] == "GITHUB_PLAN_PROOF_REVIEW_ARTIFACTS_WRITTEN"
    payload["github_comment"] = "tampered"
    with pytest.raises(GitHubPlanProofReviewError):
        write_github_plan_proof_review_artifacts(payload, tmp_path / "tampered-github-packet")
    assert main([
        "plan", "verify", "--root", str(tmp_path), "--plan", str(plan), "--changed", "src/service.py",
        "--json",
    ]) == 0
    cli = json.loads(capsys.readouterr().out)
    assert cli["schema"] == "factory.plan_proof_review.v1"
    assert main([
        "github", "plan-proof-review", "--root", str(tmp_path), "--plan", str(plan),
        "--changed", "src/service.py", "--head-sha", HEAD_SHA, "--json",
    ]) == 0
    github = json.loads(capsys.readouterr().out)
    assert github["schema"] == "factory.github_plan_proof_review.v1"
    assert github["check"]["conclusion"] == "neutral"


def test_agent_plan_canonicalization_preserves_required_human_approval() -> None:
    plan = {
        "schema": "factory.agent_plan.v1", "provider": "blitzy", "plan_id": "AAP-9",
        "approval": {"state": "approved", "approved_by": "Ari"},
        "items": [{"id": "one", "paths": ["src/a.py"], "test_paths": [], "review_tier": "light"}],
    }
    normalized = validate_agent_plan(plan)

    assert normalized == plan | {"items": [plan["items"][0] | {"review_owner": None}]}
