from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from factoryline.change_review import (
    ChangeReviewError,
    MAX_CHANGED_PATHS,
    RepositoryScopeError,
    _resolve_changed_paths,
    _matches_scope_segment,
    check_repository_scope,
    review_change,
    write_review_artifacts,
)
from factoryline.proof import git_changed_paths
from factoryline.cli import main
from factoryline.proof_reuse import record_proof


@pytest.mark.parametrize(
    "path",
    [
        "AgentOvenServer.ts",
        "agentovenserver.ts",
        "AGENTOVENserver.ts",
        "AgentCloudBackend.kt",
        "agentcloudbackend.kt",
        "ConfidentialProductServer.ts",
        "confidentialproductserver.ts",
        "CONFIDENTIALPRODUCTserver.ts",
        "ExternalProductBackend.kt",
        "externalproductbackend.kt",
    ],
)
def test_scope_guard_blocks_compound_product_filenames(path: str) -> None:
    blocked = {
        "agent-oven",
        "agentoven",
        "agent-cloud",
        "agentcloud",
        "confidential-product",
        "confidentialproduct",
        "external-product",
        "externalproduct",
    }

    assert _matches_scope_segment(path, blocked) in blocked


def test_scope_guard_reserves_the_products_root_without_blocking_generic_docs() -> None:
    blocked = {"products", "confidential-product", "confidentialproduct"}

    assert _matches_scope_segment("products/new-product/main.ts", blocked) == "products"
    assert _matches_scope_segment("docs/products.md", blocked) is None


def test_current_scope_policy_keeps_external_product_names_reserved() -> None:
    policy = json.loads(
        (Path(__file__).parents[1] / ".factory/repository-scope.json").read_text(
            encoding="utf-8"
        )
    )
    blocked = set(policy["blocked_path_segments"])
    for path in (
        "src/AgentOvenServer.ts",
        "src/AgentCloudBackend.kt",
        "examples/factory-memory-core/client.py",
        "examples/factory-trust-core/client.py",
    ):
        assert _matches_scope_segment(path, blocked) in blocked


def _stale_proof_workspace(root: Path) -> None:
    (root / "input.txt").write_text("before", encoding="utf-8")
    (root / "output.txt").write_text("green", encoding="utf-8")
    record_proof(
        root,
        {
            "name": "unit",
            "command": ["python", "-m", "pytest"],
            "read_only": True,
            "inputs": ["input.txt"],
            "outputs": ["output.txt"],
        },
        elapsed_ms=50,
    )
    (root / "input.txt").write_text("after", encoding="utf-8")


def _files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def test_change_review_preserves_exact_facts_without_default_writes(
    tmp_path: Path,
) -> None:
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
        "execution": False,
        "approval": False,
        "publication": False,
        "deployment": False,
        "signing": False,
        "messaging": False,
        "credential": False,
        "connector": False,
    }
    assert "No command was executed." in review["review_markdown"]
    assert review["mermaid"].startswith("flowchart LR")
    assert _files(tmp_path) == before
    assert (
        review_change(tmp_path, changed=["input.txt"])["review_sha256"]
        == review["review_sha256"]
    )


def test_change_review_prioritizes_unmatched_paths_before_other_gaps(
    tmp_path: Path,
) -> None:
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


def test_change_review_preserves_hidden_workspace_paths_in_all_evidence(
    tmp_path: Path,
) -> None:
    path = ".github/workflows/proof-review.yml"

    review = review_change(tmp_path, changed=[path])

    assert review["changed_paths"] == [path]
    assert review["impact"]["changed_paths"] == [path]
    assert review["impact"]["unmatched_changed_paths"] == [path]
    assert review["findings"][0]["facts"]["path"] == path
    assert f"`{path}`" in review["unproven_claims"][0]
    assert f"Unmatched: {path}" in review["mermaid"]


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


@pytest.mark.parametrize(
    "changed",
    [
        ["../secret.txt"],
        ["C:/secret.txt"],
        [""],
        [f"path-{index}.py" for index in range(MAX_CHANGED_PATHS + 1)],
    ],
)
def test_change_review_rejects_unsafe_or_oversized_paths(
    tmp_path: Path, changed: list[str]
) -> None:
    with pytest.raises(ChangeReviewError) as exc:
        review_change(tmp_path, changed=changed)
    assert exc.value.code in {"CHANGED_PATH_INVALID", "CHANGED_PATH_LIMIT"}
    assert not list(tmp_path.rglob("change-review-*"))


def test_change_review_accepts_repository_wide_cleanup_path_count(
    tmp_path: Path,
) -> None:
    changed = [f"products/retired-product/path-{index}.txt" for index in range(322)]
    source, paths = _resolve_changed_paths(tmp_path, "base", changed)
    assert source == "explicit"
    assert paths == sorted(changed)


def test_change_review_cli_writes_opt_in_packet_and_keeps_machine_readability(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _stale_proof_workspace(tmp_path)
    out_dir = tmp_path.parent / "packet"

    assert (
        main(
            [
                "change",
                "review",
                "--root",
                str(tmp_path),
                "--changed",
                "input.txt",
                "--out-dir",
                str(out_dir),
                "--json",
            ]
        )
        == 0
    )

    review = json.loads(capsys.readouterr().out)
    assert review["artifacts"]["marker"] == "DIFF_TO_PROOF_ARTIFACTS_WRITTEN"
    assert Path(review["artifacts"]["paths"]["mermaid"]).is_file()


def test_change_review_cli_marks_rejected_paths_machine_readably(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "change",
                "review",
                "--root",
                str(tmp_path),
                "--changed",
                "../secret.txt",
                "--json",
            ]
        )
        == 2
    )

    error = json.loads(capsys.readouterr().err)
    assert error == {
        "schema": "factory.change_review.error.v1",
        "marker": "DIFF_TO_PROOF_PATH_REJECTED",
        "code": "CHANGED_PATH_INVALID",
        "message": "changed paths must be non-empty workspace-relative paths without parent traversal",
    }


def test_change_review_uses_git_paths_only_when_no_explicit_paths_are_supplied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "factoryline.change_review.git_changed_paths",
        lambda root, base: ["from-git.py"],
    )

    review = review_change(tmp_path, base="origin/main")

    assert review["input_source"] == "git"
    assert review["base"] == "origin/main"
    assert review["changed_paths"] == ["from-git.py"]


def test_git_changed_paths_includes_branch_index_worktree_and_untracked_paths(
    tmp_path: Path,
) -> None:
    def git(*arguments: str) -> None:
        subprocess.run(
            ["git", *arguments],
            cwd=tmp_path,
            check=True,
            capture_output=True,
            text=True,
        )

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


def test_change_review_explicit_paths_bypass_git_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("explicit paths must not invoke Git collection")

    monkeypatch.setattr("factoryline.change_review.git_changed_paths", fail_if_called)

    review = review_change(tmp_path, changed=["src/only.py"])

    assert review["input_source"] == "explicit"
    assert review["changed_paths"] == ["src/only.py"]


SCOPE_POLICY = {
    "schema": "factory.repository_scope.v1",
    "allowed_top_level_directories": [
        ".factory",
        "adr",
        "docs",
        "evidence",
        "examples",
        "factoryline",
        "src",
    ],
    "blocked_path_segments": [
        "products",
        "agent-cloud",
        "agentcloud",
        "agent-oven",
        "agentoven",
        "factory-memory-core",
        "factory-trust-core",
        "external-product",
        "externalproduct",
        "confidential-product",
        "confidentialproduct",
        "external-data-core",
        "external-policy-core",
    ],
}


def _scope_git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def _scope_commit(root: Path, message: str) -> None:
    _scope_git(root, "add", "--all")
    _scope_git(root, "commit", "-m", message)


def _scope_repository(root: Path) -> None:
    _scope_git(root, "init")
    _scope_git(root, "config", "user.email", "factoryline@example.test")
    _scope_git(root, "config", "user.name", "FactoryLine Test")
    (root / ".factory").mkdir()
    (root / ".factory/repository-scope.json").write_text(
        json.dumps(SCOPE_POLICY), encoding="utf-8"
    )
    (root / ".factory/repository-scope-decisions.json").write_text(
        json.dumps({"schema": "factory.repository_scope_decision.v1", "decisions": []}),
        encoding="utf-8",
    )
    (root / "confidential-product").mkdir()
    (root / "confidential-product/old.ts").write_text("old product\n", encoding="utf-8")
    (root / "factoryline").mkdir()
    (root / "factoryline/module.py").write_text("before\n", encoding="utf-8")
    _scope_commit(root, "base")


def test_scope_guard_blocks_reserved_names_and_preserves_historical_receipts(
    tmp_path: Path,
) -> None:
    (tmp_path / ".factory").mkdir()
    (tmp_path / ".factory/repository-scope.json").write_text(
        json.dumps(SCOPE_POLICY), encoding="utf-8"
    )

    review = check_repository_scope(
        tmp_path,
        changed_paths=[
            "src/ExternalProductBackend.kt",
            "src/ConfidentialProductServer.ts",
            "products/private_product/src/server.ts",
            "products/new-saas-app/src/main.ts",
            "examples/external-policy-core-client/index.ts",
            "adr/external-product-budget-enforcement-v1.md",
            "docs/ConfidentialProduct-readiness.md",
            "evidence/self-audit/obsolete-cross-scope-audit.json",
            "factoryline/graph_ops.py",
        ],
    )

    assert review["state"] == "blocked"
    assert review["marker"] == "REPOSITORY_SCOPE_BLOCKED"
    assert review["blocked_paths"] == [
        {
            "path": "adr/external-product-budget-enforcement-v1.md",
            "matched_segment": "external-product",
        },
        {
            "path": "docs/ConfidentialProduct-readiness.md",
            "matched_segment": "confidential-product",
        },
        {
            "path": "examples/external-policy-core-client/index.ts",
            "matched_segment": "external-policy-core",
        },
        {
            "path": "products/new-saas-app/src/main.ts",
            "matched_segment": "products",
        },
        {
            "path": "products/private_product/src/server.ts",
            "matched_segment": "products",
        },
        {
            "path": "src/ConfidentialProductServer.ts",
            "matched_segment": "confidential-product",
        },
        {
            "path": "src/ExternalProductBackend.kt",
            "matched_segment": "external-product",
        },
    ]
    assert review["next_action"]["action"] == "remove_or_rehome_unrelated_product_files"


def test_scope_guard_reads_trusted_base_policy_and_allows_cleanup_deletions(
    tmp_path: Path,
) -> None:
    _scope_repository(tmp_path)
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (tmp_path / "confidential-product/old.ts").unlink()
    (tmp_path / "factoryline/module.py").write_text("after\n", encoding="utf-8")
    (tmp_path / "products/external-product/src").mkdir(parents=True)
    (tmp_path / "products/external-product/src/server.ts").write_text(
        "separate product\n", encoding="utf-8"
    )
    (tmp_path / ".factory/repository-scope.json").write_text(
        json.dumps({**SCOPE_POLICY, "blocked_path_segments": []}), encoding="utf-8"
    )
    _scope_commit(tmp_path, "change scope")

    review = check_repository_scope(tmp_path, base=base, policy_ref=base)

    assert review["state"] == "blocked"
    assert review["policy_ref"] == base
    assert review["changed_paths"] == [
        ".factory/repository-scope.json",
        "factoryline/module.py",
        "products/external-product/src/server.ts",
    ]
    assert any(
        item["path"] == "products/external-product/src/server.ts"
        for item in review["blocked_paths"]
    )


def test_scope_guard_runs_trusted_base_code_against_a_fetched_candidate_ref(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _scope_repository(tmp_path)
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (tmp_path / "products/external-product/src").mkdir(parents=True)
    (tmp_path / "products/external-product/src/server.ts").write_text(
        "unrelated product\n", encoding="utf-8"
    )
    _scope_commit(tmp_path, "candidate adds unrelated product")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    _scope_git(tmp_path, "checkout", "--detach", base)

    result = main(
        [
            "change",
            "scope-check",
            "--root",
            str(tmp_path),
            "--base",
            base,
            "--head",
            head,
            "--policy-ref",
            base,
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert result == 2
    assert payload["marker"] == "REPOSITORY_SCOPE_BLOCKED"
    assert payload["head"] == head
    assert payload["policy_ref"] == base
    assert payload["blocked_paths"] == [
        {
            "path": "products/external-product/src/server.ts",
            "matched_segment": "products",
        }
    ]


def test_scope_guard_allows_removal_without_hiding_other_changes(
    tmp_path: Path,
) -> None:
    _scope_repository(tmp_path)
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (tmp_path / "confidential-product/old.ts").unlink()
    (tmp_path / "factoryline/module.py").write_text("after\n", encoding="utf-8")
    _scope_commit(tmp_path, "remove unrelated file")

    review = check_repository_scope(tmp_path, base=base, policy_ref=base)

    assert review["state"] == "clear"
    assert review["changed_paths"] == ["factoryline/module.py"]


def test_scope_guard_blocks_renaming_reserved_path_to_neutral_name(
    tmp_path: Path,
) -> None:
    _scope_repository(tmp_path)
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    destination = tmp_path / "factoryline/product_data.ts"
    (tmp_path / "confidential-product/old.ts").replace(destination)
    _scope_commit(tmp_path, "rename reserved file to a neutral name")

    review = check_repository_scope(tmp_path, base=base, policy_ref=base)

    assert review["state"] == "blocked"
    assert review["blocked_paths"] == [
        {
            "path": "confidential-product/old.ts",
            "matched_segment": "confidential-product",
        }
    ]


def test_scope_guard_blocks_copying_reserved_path_to_neutral_name(
    tmp_path: Path,
) -> None:
    _scope_repository(tmp_path)
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (tmp_path / "factoryline/copied_product.ts").write_text(
        (tmp_path / "confidential-product/old.ts").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    _scope_commit(tmp_path, "copy reserved product file to a neutral name")

    review = check_repository_scope(tmp_path, base=base, policy_ref=base)

    assert review["state"] == "blocked"
    assert review["changed_paths"] == [
        "confidential-product/old.ts",
        "factoryline/copied_product.ts",
    ]
    assert review["blocked_paths"] == [
        {
            "path": "confidential-product/old.ts",
            "matched_segment": "confidential-product",
        }
    ]


def test_scope_guard_blocks_unexpected_top_level_directory_even_when_name_is_neutral(
    tmp_path: Path,
) -> None:
    (tmp_path / ".factory").mkdir()
    (tmp_path / ".factory/repository-scope.json").write_text(
        json.dumps(SCOPE_POLICY), encoding="utf-8"
    )
    review = check_repository_scope(
        tmp_path, changed_paths=["fresh-neutral-area/src/module.py"]
    )
    assert review["state"] == "blocked"
    assert review["blocked_paths"] == [
        {
            "path": "fresh-neutral-area/src/module.py",
            "matched_segment": "unapproved-top-level:fresh-neutral-area",
        }
    ]


def test_scope_policy_addition_requires_candidate_evidence_record_and_never_bypasses_base(
    tmp_path: Path,
) -> None:
    _scope_repository(tmp_path)
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    candidate_policy = {
        **SCOPE_POLICY,
        "allowed_top_level_directories": [
            *SCOPE_POLICY["allowed_top_level_directories"],
            "new-area",
        ],
    }
    (tmp_path / ".factory/repository-scope.json").write_text(
        json.dumps(candidate_policy), encoding="utf-8"
    )
    (tmp_path / "new-area").mkdir()
    (tmp_path / "new-area/module.py").write_text("new content\n", encoding="utf-8")
    _scope_commit(tmp_path, "add directory policy without decision")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    with pytest.raises(RepositoryScopeError) as exc:
        check_repository_scope(tmp_path, base=base, head=head, policy_ref=base)
    assert exc.value.code == "SCOPE_DECISION_MISSING"

    record = {
        "schema": "factory.repository_scope_decision.v1",
        "decisions": [
            {
                "top_level_directory": "new-area",
                "rationale": "The repository owns this new subsystem.",
                "evidence": ["adr/0001-new-area.md"],
            }
        ],
    }
    (tmp_path / ".factory/repository-scope-decisions.json").write_text(
        json.dumps(record), encoding="utf-8"
    )
    _scope_commit(tmp_path, "record evidence decision")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    review = check_repository_scope(tmp_path, base=base, head=head, policy_ref=base)
    assert review["scope_decisions"] == "evidence_recorded_pending_trusted_merge"
    assert review["state"] == "blocked"
    assert review["blocked_paths"] == [
        {
            "path": "new-area/module.py",
            "matched_segment": "unapproved-top-level:new-area",
        }
    ]


@pytest.mark.parametrize("path", ["../secret.py", "C:/secret.py", "", "/secret.py"])
def test_scope_guard_rejects_unsafe_paths(tmp_path: Path, path: str) -> None:
    (tmp_path / ".factory").mkdir()
    (tmp_path / ".factory/repository-scope.json").write_text(
        json.dumps(SCOPE_POLICY), encoding="utf-8"
    )

    with pytest.raises(RepositoryScopeError) as exc:
        check_repository_scope(tmp_path, changed_paths=[path])

    assert exc.value.code == "SCOPE_PATH_INVALID"


def test_scope_guard_cli_returns_blocking_machine_readable_result(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / ".factory").mkdir()
    (tmp_path / ".factory/repository-scope.json").write_text(
        json.dumps(SCOPE_POLICY), encoding="utf-8"
    )

    result = main(
        [
            "change",
            "scope-check",
            "--root",
            str(tmp_path),
            "--changed",
            "products/external-product/app.ts",
            "--json",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert result == 2
    assert output["marker"] == "REPOSITORY_SCOPE_BLOCKED"
    assert output["blocked_paths"][0]["path"] == "products/external-product/app.ts"


def test_standard_change_review_applies_configured_product_boundary(
    tmp_path: Path,
) -> None:
    (tmp_path / ".factory").mkdir()
    (tmp_path / ".factory/repository-scope.json").write_text(
        json.dumps(SCOPE_POLICY), encoding="utf-8"
    )

    review = review_change(
        tmp_path,
        changed=["factoryline/graph_ops.py", "products/external-product/api.ts"],
    )

    assert review["repository_scope"]["state"] == "blocked"
    assert review["findings"][0]["kind"] == "repository_scope_violation"
    assert review["next_action"] == {
        "action": "remove_or_rehome_unrelated_product_files",
        "reason": "Changed paths cross a reserved repository product boundary.",
        "paths": ["products/external-product/api.ts"],
    }
    assert any(
        "products/external-product/api.ts" in claim
        for claim in review["unproven_claims"]
    )


def test_scope_guard_rejects_an_untrusted_policy_revision(tmp_path: Path) -> None:
    with pytest.raises(RepositoryScopeError) as exc:
        check_repository_scope(tmp_path, changed_paths=[], policy_ref="not-a-ref")

    assert exc.value.code == "SCOPE_POLICY_UNAVAILABLE"


def test_scope_guard_upgrades_only_trusted_legacy_base(tmp_path: Path) -> None:
    (tmp_path / ".factory").mkdir()
    (tmp_path / "factoryline").mkdir()
    (tmp_path / "factoryline/main.py").write_text("VALUE = 1\n")
    legacy = {
        "schema": "factory.repository_scope.v1",
        "blocked_path_segments": ["products"],
    }
    (tmp_path / ".factory/repository-scope.json").write_text(json.dumps(legacy))
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    _scope_git(tmp_path, "config", "user.name", "FactoryLine Test")
    _scope_git(tmp_path, "config", "user.email", "factoryline@example.test")
    _scope_commit(tmp_path, "legacy trusted base")
    review = check_repository_scope(
        tmp_path,
        changed_paths=["factoryline/main.py", "new-saas/main.py"],
        policy_ref="HEAD",
    )
    assert review["blocked_paths"] == [
        {"path": "new-saas/main.py", "matched_segment": "unapproved-top-level:new-saas"}
    ]
    with pytest.raises(RepositoryScopeError, match="policy must contain"):
        check_repository_scope(tmp_path, changed_paths=["factoryline/main.py"])
