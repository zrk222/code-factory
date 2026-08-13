from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.change_review import review_change
from factoryline.cli import main
from factoryline.github_proof_review import (
    GitHubProofReviewError,
    compile_github_proof_review,
    render_github_proof_review,
    write_github_proof_review_artifacts,
)
from factoryline.proof_reuse import record_proof


HEAD_SHA = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"


def _stale_proof_workspace(root: Path) -> None:
    (root / "input.txt").write_text("before", encoding="utf-8")
    (root / "output.txt").write_text("green", encoding="utf-8")
    record_proof(root, {
        "name": "unit", "command": ["python", "-m", "pytest"], "read_only": True,
        "inputs": ["input.txt"], "outputs": ["output.txt"],
    }, elapsed_ms=50)
    (root / "input.txt").write_text("after", encoding="utf-8")


def _files(root: Path) -> dict[str, bytes]:
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def test_github_proof_review_preserves_exact_facts_without_writing_workspace(tmp_path: Path) -> None:
    _stale_proof_workspace(tmp_path)
    review = review_change(tmp_path, changed=["input.txt", "docs/guide.md", "factoryline/tool.py", "scripts/release.py"])
    before = _files(tmp_path)

    payload = render_github_proof_review(review, HEAD_SHA)

    assert payload["schema"] == "factory.github_proof_review.v1"
    assert "GITHUB_PROOF_REVIEW_V1" in payload["markers"]
    assert payload["head_sha"] == HEAD_SHA
    assert payload["review_sha256"] == review["review_sha256"]
    assert payload["changed_paths"] == review["changed_paths"]
    assert payload["findings"] == review["findings"]
    assert payload["next_action"] == review["next_action"]
    assert payload["unproven_claims"] == review["unproven_claims"]
    assert [cohort["id"] for cohort in payload["path_cohorts"]] == ["docs", "implementation", "other"]
    assert {path for cohort in payload["path_cohorts"] for path in cohort["paths"]} == set(review["changed_paths"])
    assert payload["check"]["name"] == "FactoryLine / Proof Review"
    assert payload["check"]["conclusion"] == "neutral"
    assert payload["authority"] == {
        "execution": False, "approval": False, "publication": False, "deployment": False,
        "signing": False, "messaging": False, "credential": False, "connector": False,
        "source_write": False, "test_execution": False, "repair": False,
    }
    assert "<!-- factoryline-proof-review -->" in payload["github_comment"]
    assert HEAD_SHA in payload["github_comment"]
    assert review["mermaid"] in payload["github_comment"]
    assert _files(tmp_path) == before
    assert render_github_proof_review(review, HEAD_SHA)["payload_sha256"] == payload["payload_sha256"]


def test_compile_github_proof_review_uses_explicit_paths_without_git_or_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_if_git_is_collected(*_args, **_kwargs):
        raise AssertionError("explicit paths must not invoke Git collection")

    monkeypatch.setattr("factoryline.change_review.git_changed_paths", fail_if_git_is_collected)

    payload = compile_github_proof_review(tmp_path, base="origin/main", changed=["src/only.py"], head_sha=HEAD_SHA)

    assert payload["head_sha"] == HEAD_SHA
    assert payload["changed_paths"] == ["src/only.py"]
    assert payload["next_action"]["action"] == "bind_changed_path_to_proof"


def test_github_proof_review_rejects_tampered_source_before_writing_artifacts(tmp_path: Path) -> None:
    review = review_change(tmp_path, changed=["app/service.py"])
    review["findings"][0]["message"] = "tampered"
    out_dir = tmp_path.parent / "github-proof-review-artifacts"

    with pytest.raises(GitHubProofReviewError) as exc:
        render_github_proof_review(review, HEAD_SHA)

    assert exc.value.code == "GITHUB_PROOF_REVIEW_INPUT_INVALID"
    assert not out_dir.exists()


def test_github_proof_review_writes_only_explicit_json_and_markdown_artifacts(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    out_dir = tmp_path / "payload"
    workspace.mkdir()
    review = review_change(workspace, changed=["specs/feature.md", "tests/test_feature.py"])
    payload = render_github_proof_review(review, HEAD_SHA)
    before = _files(workspace)

    artifacts = write_github_proof_review_artifacts(payload, out_dir)

    assert artifacts["marker"] == "GITHUB_PROOF_REVIEW_ARTIFACTS_WRITTEN"
    assert set(artifacts["paths"]) == {"json", "markdown"}
    assert all(Path(path).is_file() for path in artifacts["paths"].values())
    assert all(len(digest) == 64 for digest in artifacts["sha256"].values())
    assert _files(workspace) == before
    packet = json.loads(Path(artifacts["paths"]["json"]).read_text(encoding="utf-8"))
    assert packet["payload_sha256"] == payload["payload_sha256"]
    assert Path(artifacts["paths"]["markdown"]).read_text(encoding="utf-8") == payload["github_comment"]


def test_github_proof_review_rejects_forged_source_shapes_and_tampered_delivery_before_write(tmp_path: Path) -> None:
    source = review_change(tmp_path, changed=["src/only.py"])
    source["changed_paths"] = [42]
    with pytest.raises(GitHubProofReviewError) as source_error:
        render_github_proof_review(source, HEAD_SHA)
    assert source_error.value.code == "GITHUB_PROOF_REVIEW_INPUT_INVALID"

    payload = render_github_proof_review(review_change(tmp_path, changed=["src/only.py"]), HEAD_SHA)
    payload["github_comment"] = "tampered"
    out_dir = tmp_path / "forged-artifact"
    with pytest.raises(GitHubProofReviewError) as delivery_error:
        write_github_proof_review_artifacts(payload, out_dir)
    assert delivery_error.value.code == "GITHUB_PROOF_REVIEW_INPUT_INVALID"
    assert not out_dir.exists()


def test_github_proof_review_cli_is_machine_readable_and_local_only(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out_dir = tmp_path.parent / "packet"

    assert main([
        "github", "proof-review", "--root", str(tmp_path), "--changed", "src/only.py",
        "--head-sha", HEAD_SHA, "--out-dir", str(out_dir), "--json",
    ]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["head_sha"] == HEAD_SHA
    assert "GITHUB_PROOF_REVIEW_LOCAL_ONLY" in payload["markers"]
    assert payload["artifacts"]["marker"] == "GITHUB_PROOF_REVIEW_ARTIFACTS_WRITTEN"
    assert Path(payload["artifacts"]["paths"]["json"]).is_file()


def test_github_proof_review_cli_rejects_noncanonical_head_sha(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([
        "github", "proof-review", "--root", str(tmp_path), "--changed", "src/only.py",
        "--head-sha", "ABC", "--json",
    ]) == 2

    error = json.loads(capsys.readouterr().err)
    assert error["schema"] == "factory.github_proof_review.error.v1"
    assert error["code"] == "GITHUB_PROOF_REVIEW_HEAD_SHA_INVALID"


def test_opt_in_workflow_is_advisory_scoped_and_never_uses_a_privileged_pr_trigger() -> None:
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "factory-pr-proof-review.yml").read_text(encoding="utf-8")

    assert "pull_request:" in workflow
    assert "pull_request_target" not in workflow
    assert "contents: read" in workflow
    assert "pull-requests: write" in workflow
    assert "checks: write" in workflow
    assert "contents: write" not in workflow
    assert "github.rest.issues.updateComment" in workflow
    assert "github.rest.issues.createComment" in workflow
    assert "github.rest.checks.create" in workflow
    assert "<!-- factoryline-proof-review -->" in workflow
    assert "approve" not in workflow.lower()
    assert "merge" not in workflow.lower()


def test_coderabbit_positioning_is_complementary_and_never_claims_vendor_access() -> None:
    root = Path(__file__).parents[1]
    guide = (root / "docs" / "GITHUB_PROOF_REVIEW.md").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")
    discovery = (root / "docs" / "GITHUB_DISCOVERY.md").read_text(encoding="utf-8")

    assert "CodeRabbit and Code Factory are complementary, not interchangeable" in guide
    assert "does **not** call a CodeRabbit API" in guide.replace("\n", " ")
    assert "not trying to replace the AI reviewer" in discovery
    assert "Use Code Factory with CodeRabbit or another AI reviewer" in readme
    assert "does not replace human review" in readme.replace("\n", " ")
