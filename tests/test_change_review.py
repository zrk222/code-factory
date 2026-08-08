from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from factoryline.change_review import ChangeReviewError, review_change, write_review_artifacts
from factoryline.proof import git_changed_paths
from factoryline.cli import main
from factoryline.proof_reuse import record_proof


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


def test_change_review_preserves_exact_facts_without_default_writes(tmp_path: Path) -> None:
    _stale_proof_workspace(tmp_path)
    before = _files(tmp_path)

    review = review_change(tmp_path, changed=["input.txt"])

    assert review["schema"] == "factory.change_review.v1"
    assert review["input_source"] == "explicit"
    assert review["changed_paths"] == ["input.txt"]
    assert "DIFF_TO_PROOF_REVIEW_V1" in review["markers"]
    assert review["impact"]["rerun_proofs"]
    assert review["findings"][0]["kind"] == "stale_proof"
    assert review["next_action"]["action"] == "rerun_stale_proof"
    assert review["authority"] == {
        "execution": False, "approval": False, "publication": False, "deployment": False,
        "signing": False, "messaging": False, "credential": False, "connector": False,
    }
    assert "No command was executed." in review["review_markdown"]
    assert review["mermaid"].startswith("flowchart LR")
    assert _files(tmp_path) == before
    assert review_change(tmp_path, changed=["input.txt"])["review_sha256"] == review["review_sha256"]


def test_change_review_prioritizes_unmatched_paths_before_other_gaps(tmp_path: Path) -> None:
    review = review_change(tmp_path, changed=["app/service.py"])

    assert review["impact"]["unmatched_changed_paths"] == ["app/service.py"]
    assert review["findings"][0]["kind"] == "unmatched_changed_path"
    assert review["next_action"] == {
        "action": "bind_changed_path_to_proof",
        "reason": "This changed path has no explicit Graph Ops proof-input edge.",
        "path": "app/service.py",
    }
    assert "DIFF_TO_PROOF_UNMATCHED_PRIORITY" in review["markers"]
    assert "Unmatched: app/service.py" in review["mermaid"]


def test_change_review_writes_only_explicit_local_artifacts(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    out_dir = tmp_path / "review-artifacts"
    workspace.mkdir()
    _stale_proof_workspace(workspace)
    before = _files(workspace)
    review = review_change(workspace, changed=["input.txt"])

    artifacts = write_review_artifacts(review, out_dir)

    assert artifacts["marker"] == "DIFF_TO_PROOF_ARTIFACTS_WRITTEN"
    assert all(Path(path).is_file() for path in artifacts["paths"].values())
    assert all(len(digest) == 64 for digest in artifacts["sha256"].values())
    assert _files(workspace) == before
    packet = json.loads(Path(artifacts["paths"]["json"]).read_text(encoding="utf-8"))
    assert packet["review_sha256"] == review["review_sha256"]
    assert "review_markdown" not in packet


@pytest.mark.parametrize("changed", [["../secret.txt"], ["C:/secret.txt"], [""], [f"path-{index}.py" for index in range(51)]])
def test_change_review_rejects_unsafe_or_oversized_paths(tmp_path: Path, changed: list[str]) -> None:
    with pytest.raises(ChangeReviewError) as exc:
        review_change(tmp_path, changed=changed)
    assert exc.value.code in {"CHANGED_PATH_INVALID", "CHANGED_PATH_LIMIT"}
    assert not list(tmp_path.rglob("change-review-*"))


def test_change_review_cli_writes_opt_in_packet_and_keeps_machine_readability(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _stale_proof_workspace(tmp_path)
    out_dir = tmp_path.parent / "packet"

    assert main(["change", "review", "--root", str(tmp_path), "--changed", "input.txt", "--out-dir", str(out_dir), "--json"]) == 0

    review = json.loads(capsys.readouterr().out)
    assert review["artifacts"]["marker"] == "DIFF_TO_PROOF_ARTIFACTS_WRITTEN"
    assert Path(review["artifacts"]["paths"]["mermaid"]).is_file()


def test_change_review_cli_marks_rejected_paths_machine_readably(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["change", "review", "--root", str(tmp_path), "--changed", "../secret.txt", "--json"]) == 2

    error = json.loads(capsys.readouterr().err)
    assert error == {
        "schema": "factory.change_review.error.v1",
        "marker": "DIFF_TO_PROOF_PATH_REJECTED",
        "code": "CHANGED_PATH_INVALID",
        "message": "changed paths must be non-empty workspace-relative paths without parent traversal",
    }


def test_change_review_uses_git_paths_only_when_no_explicit_paths_are_supplied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("factoryline.change_review.git_changed_paths", lambda root, base: ["from-git.py"])

    review = review_change(tmp_path, base="origin/main")

    assert review["input_source"] == "git"
    assert review["base"] == "origin/main"
    assert review["changed_paths"] == ["from-git.py"]


def test_git_changed_paths_includes_branch_index_worktree_and_untracked_paths(tmp_path: Path) -> None:
    def git(*arguments: str) -> None:
        subprocess.run(["git", *arguments], cwd=tmp_path, check=True, capture_output=True, text=True)

    git("init")
    git("config", "user.email", "factoryline@example.test")
    git("config", "user.name", "FactoryLine Test")
    for path in ("tracked-staged.py", "tracked-unstaged.py"):
        (tmp_path / path).write_text("before\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-m", "base")

    (tmp_path / "branch.py").write_text("branch\n", encoding="utf-8")
    git("add", "branch.py")
    git("commit", "-m", "branch")
    (tmp_path / "tracked-staged.py").write_text("after\n", encoding="utf-8")
    git("add", "tracked-staged.py")
    (tmp_path / "tracked-unstaged.py").write_text("after\n", encoding="utf-8")
    (tmp_path / "untracked.py").write_text("new\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("ignored.py\n", encoding="utf-8")
    (tmp_path / "ignored.py").write_text("ignored\n", encoding="utf-8")

    assert git_changed_paths(tmp_path, "HEAD~1") == [
        ".gitignore",
        "branch.py",
        "tracked-staged.py",
        "tracked-unstaged.py",
        "untracked.py",
    ]


def test_change_review_explicit_paths_bypass_git_collection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("explicit paths must not invoke Git collection")

    monkeypatch.setattr("factoryline.change_review.git_changed_paths", fail_if_called)

    review = review_change(tmp_path, changed=["src/only.py"])

    assert review["input_source"] == "explicit"
    assert review["changed_paths"] == ["src/only.py"]
