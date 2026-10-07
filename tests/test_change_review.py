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
from factoryline.coverage import requirement_coverage
from factoryline.proof import git_changed_paths
from factoryline.cli import main
from factoryline.proof_reuse import record_proof
import hashlib
import runpy
from factoryline.cdte import SCAN_SCHEMA, load_scans
from factoryline.habituation import load_resamples
from factoryline.cli_foundations import cli_command, emit_version
from factoryline.codex_metadata import write_metadata_audit
from factoryline.combine import combine_projection
from factoryline.control_api import ControlPlaneAPI, create_app
from factoryline.full_stack_ux_harness import (
    FullStackUXHarnessError,
    quality_harness_template,
    write_quality_harness_template,
)
from factoryline.mcp_mrt import evaluate_release_gate
from factoryline.migration import RepositoryHistoryError, git_lines
from factoryline.output_map import OUTPUT_MAP_MARKER, write_output_map
from factoryline.proof import execute_replay, load_trace
from factoryline.signed_receipts import SignedReceiptError, ci_receipt_main
from factoryline.deep_audit import cancel_deep_run, deep_run_status, scan_deep_audit
from factoryline.runtime_audit_common import RuntimeAuditError
from factoryline.studio import (
    StudioRequestError,
    authorize_graph_ops_from_studio,
    run_graph_ops_reality_check_from_studio,
)


@pytest.mark.parametrize(
    "path",
    [
        "ConfidentialProductServer.ts",
        "confidentialproductserver.ts",
        "CONFIDENTIALPRODUCTserver.ts",
        "ExternalProductBackend.kt",
        "externalproductbackend.kt",
    ],
)
def test_scope_guard_blocks_compound_product_filenames(path: str) -> None:
    blocked = {
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
        "products/new-service/main.ts",
        "src/ConfidentialProductServer.ts",
        "examples/external-memory-core/client.py",
        "examples/external-trust-core/client.py",
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


def test_requirement_coverage_is_not_applicable_to_plain_repositories(
    tmp_path: Path,
) -> None:
    coverage = requirement_coverage(tmp_path)

    assert coverage["ok"] is True
    assert coverage["applicable"] is False
    assert coverage["status"] == "not_applicable"
    assert coverage["uncovered"] == []
    assert coverage["attribution"]["rate"] is None


def test_app_starter_requirement_coverage_still_fails_closed_without_manifest(
    tmp_path: Path,
) -> None:
    (tmp_path / "app_blueprint.json").write_text("{}", encoding="utf-8")

    coverage = requirement_coverage(tmp_path)

    assert coverage["ok"] is False
    assert coverage["applicable"] is True
    assert coverage["status"] == "incomplete"
    assert coverage["uncovered"] == ["coverage:manifest"]


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
        "external-product",
        "externalproduct",
        "confidential-product",
        "confidentialproduct",
        "external-memory-core",
        "external-trust-core",
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


# Consolidated tests from tests/test_attribution_98.py
"""Behavior assertions for previously unattributed local workflow functions."""


def test_load_scans_keeps_only_valid_schema_receipts(tmp_path: Path) -> None:
    directory = tmp_path / ".factory" / "cdte"
    directory.mkdir(parents=True)
    valid = {"schema": SCAN_SCHEMA, "scan_id": "scan-1", "conflicts": []}
    (directory / "00-valid.json").write_text(json.dumps(valid), encoding="utf-8")
    (directory / "01-foreign.json").write_text(
        json.dumps({"schema": "other.v1"}), encoding="utf-8"
    )
    (directory / "02-broken.json").write_text("{", encoding="utf-8")

    assert load_scans(tmp_path) == [valid]


def test_load_resamples_skips_corrupt_and_foreign_records(tmp_path: Path) -> None:
    directory = tmp_path / ".factory" / "habituation"
    directory.mkdir(parents=True)
    valid = {"schema": "factory.habituation.resample.v1", "review_id": "r-1"}
    (directory / "resample.01.json").write_text(json.dumps(valid), encoding="utf-8")
    (directory / "resample.02.json").write_text(
        json.dumps({"schema": "other.v1"}), encoding="utf-8"
    )
    (directory / "resample.03.json").write_text("not-json", encoding="utf-8")

    assert load_resamples(tmp_path) == [valid]


def test_emit_version_formats_json_and_human_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from factoryline import provenance as provenance_module

    payload = {"version": "0.47.0", "source_commit": "abc123"}
    monkeypatch.setattr(provenance_module, "provenance", lambda: payload)

    assert emit_version(as_json=True) == 0
    assert json.loads(capsys.readouterr().out) == payload
    assert emit_version(as_json=False) == 0
    assert capsys.readouterr().out.strip() == "factory 0.47.0"


def test_cli_command_prefers_launcher_directory(tmp_path: Path, monkeypatch) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    launcher = scripts / "factory-launcher.py"
    launcher.write_text("", encoding="utf-8")
    executable = scripts / "factory.exe"
    executable.write_text("", encoding="utf-8")
    monkeypatch.setattr("factoryline.cli_foundations.sys.argv", [str(launcher)])

    assert cli_command("factory") == str(executable)


def test_write_metadata_audit_persists_marked_receipt(tmp_path: Path) -> None:
    source = tmp_path / "candidate.json"
    source.write_text(json.dumps({"status": "draft"}), encoding="utf-8")

    result = write_metadata_audit(tmp_path, [source], Path("audit.json"))

    persisted = json.loads((tmp_path / "audit.json").read_text(encoding="utf-8"))
    assert result["marker"] == "CODEX_METADATA_CLI_WRITTEN"
    assert result["markers"][-1] == "CODEX_METADATA_CLI_WRITTEN"
    assert persisted == result
    assert not (tmp_path / "audit.json.tmp").exists()


def test_combine_projection_reports_empty_read_only_state(tmp_path: Path) -> None:
    result = combine_projection(tmp_path)

    assert result["marker"] == "COMBINE_STATUS_READ_ONLY"
    assert result["available"] is False
    assert result["scoreboards"] == []
    assert all(value is False for value in result["authority"].values())


def test_create_app_exposes_health_and_requires_verified_identity(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path / "control.sqlite3")
    assert isinstance(app, ControlPlaneAPI)

    def call(path: str) -> tuple[str, dict]:
        captured: dict[str, str] = {}

        def start_response(status: str, headers: list[tuple[str, str]]) -> None:
            captured["status"] = status

        body = b"".join(
            app(
                {
                    "REQUEST_METHOD": "GET",
                    "PATH_INFO": path,
                    "CONTENT_LENGTH": "0",
                    "wsgi.input": __import__("io").BytesIO(b""),
                },
                start_response,
            )
        )
        return captured["status"], json.loads(body)

    status, health = call("/healthz")
    assert status == "200 OK" and health["ok"] is True
    status, error = call("/v1/evidence")
    assert status == "400 Bad Request"
    assert error["error"]["code"] == "E_IDENTITY_REQUIRED"


def test_write_quality_harness_template_containment_and_no_overwrite(
    tmp_path: Path,
) -> None:
    result = write_quality_harness_template(
        tmp_path, Path("quality.json"), ui_in_scope=False
    )
    saved = json.loads((tmp_path / "quality.json").read_text(encoding="utf-8"))
    assert saved["checks"] == quality_harness_template(ui_in_scope=False)["checks"]
    assert result["path"] == str((tmp_path / "quality.json").resolve())

    with pytest.raises(FullStackUXHarnessError) as exists_error:
        write_quality_harness_template(
            tmp_path, Path("quality.json"), ui_in_scope=False
        )
    assert exists_error.value.code == "E_UX_MANIFEST_EXISTS"
    with pytest.raises(FullStackUXHarnessError) as path_error:
        write_quality_harness_template(
            tmp_path, Path("../outside.json"), ui_in_scope=False
        )
    assert path_error.value.code == "E_UX_MANIFEST_PATH"


def test_evaluate_release_gate_requests_input_without_approving() -> None:
    card = {
        "feature": "payments",
        "state": "BLOCKED",
        "blockers": [{"code": "MISSING_EVIDENCE"}],
    }

    first = evaluate_release_gate(card)
    second = evaluate_release_gate(card)

    assert first["type"] == "input_required"
    assert first["toolCallId"] == second["toolCallId"]
    assert first["context"]["proofDebt"] == ["MISSING_EVIDENCE"]
    assert all(value is False for value in first["authority"].values())


def test_git_lines_is_read_only_allowlisted_and_returns_root(tmp_path: Path) -> None:
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)

    observed_root = git_lines(tmp_path, "rev-parse", "--show-toplevel")
    assert len(observed_root) == 1
    assert Path(observed_root[0]).resolve() == tmp_path.resolve()
    with pytest.raises(RepositoryHistoryError, match="read-only allowlist"):
        git_lines(tmp_path, "status", "--short")


def test_write_output_map_binds_digest_and_lists_expected_paths(tmp_path: Path) -> None:
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text("value = 1\n", encoding="utf-8")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()

    result = write_output_map(
        tmp_path,
        name="sample",
        source_sha256=source_hash,
        status="blocked",
        expected_paths=["src/app.py"],
    )
    rendered = (tmp_path / result["path"]).read_text(encoding="utf-8")

    assert result["marker"] == OUTPUT_MAP_MARKER
    assert (
        result["sha256"]
        == hashlib.sha256((tmp_path / result["path"]).read_bytes()).hexdigest()
    )
    assert result["file_count"] >= 2
    assert "src/app.py" in rendered
    assert "output inventory, not a completion certificate" in rendered


def test_load_trace_reads_exact_json_object_and_rejects_malformed_json(
    tmp_path: Path,
) -> None:
    trace = {"feature": "payments", "nodes": [{"stage": "tests"}]}
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(trace), encoding="utf-8")
    assert load_trace(path) == trace

    path.write_text("{", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        load_trace(path)


def test_execute_replay_stops_after_failed_command(tmp_path: Path) -> None:
    (tmp_path / "input.json").write_text('{"ok": true}', encoding="utf-8")
    result = execute_replay(
        {
            "feature": "json-replay",
            "trace_sha256": "a" * 64,
            "commands": [
                {"command": "python -m json.tool input.json"},
                {"command": "python -m json.tool missing.json"},
                {"command": "python -m json.tool input.json"},
            ],
        },
        root=tmp_path,
    )

    assert result["executed"] is True
    assert result["ok"] is False
    assert [row["status"] for row in result["results"]] == ["ok", "failed"]
    assert '"ok": true' in result["results"][0]["log_tail"]


def test_ci_receipt_main_rejects_missing_or_unknown_route() -> None:
    with pytest.raises(SignedReceiptError) as exc:
        ci_receipt_main([])
    assert exc.value.code == "E_CI_RECEIPT"


def test_authorize_graph_ops_from_studio_rejects_incomplete_payload(
    tmp_path: Path,
) -> None:
    with pytest.raises(StudioRequestError) as exc:
        authorize_graph_ops_from_studio(tmp_path, {})
    assert exc.value.code == "GRAPH_AUTHORIZATION_INVALID"
    assert exc.value.status == 400


def test_run_graph_ops_reality_check_from_studio_rejects_extra_fields(
    tmp_path: Path,
) -> None:
    with pytest.raises(StudioRequestError) as exc:
        run_graph_ops_reality_check_from_studio(
            tmp_path, {"authorization": "missing.json", "unexpected": True}
        )
    assert exc.value.code == "GRAPH_AUTHORIZATION_INVALID"
    assert exc.value.status == 400


def test_prooflab_run_module_executes_and_surfaces_module_failure(
    tmp_path: Path,
) -> None:
    source = Path(__file__).parents[1] / "scripts" / "prooflab_e2e.py"
    run_module = runpy.run_path(str(source))["run_module"]
    (tmp_path / "input.json").write_text('{"ok": true}', encoding="utf-8")

    assert run_module("json.tool", ["input.json"], tmp_path) is None
    with pytest.raises(RuntimeError, match="failed"):
        run_module("json.tool", ["missing.json"], tmp_path)


def test_release_train_write_complete_emits_every_declared_stage(
    tmp_path: Path,
) -> None:
    source = Path(__file__).parents[1] / "scripts" / "release_train_e2e.py"
    module = runpy.run_path(str(source))

    module["write_complete"](tmp_path, {"source_sha256": "a" * 64})

    receipts = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in (tmp_path / "receipts").glob("*.json")
    ]
    observed_stages = {(row["module"], row["stage"]) for row in receipts}
    expected_stages = {tuple(item.split(":", maxsplit=1)) for item in module["STAGES"]}
    assert observed_stages == expected_stages
    assert all(row["feature"] == "release-train" and row["ok"] for row in receipts)


def test_cancel_deep_run_does_not_rewrite_a_terminal_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_deep_audit_contract import execution_fixture

    root, manifest, pin, authorization, trust, plan, _, _ = execution_fixture(tmp_path)

    def unavailable() -> None:
        raise RuntimeAuditError("E_DOCKER_UNAVAILABLE", "fixture unavailable")

    monkeypatch.setattr("factoryline.deep_audit._docker_base", unavailable)
    run = scan_deep_audit(
        root,
        manifest,
        pin,
        authorization=authorization,
        trust_root=trust,
        trust_root_sha256=plan["trust_root_sha256"],
        emit=lambda _event: None,
    )
    run_id = run["run_id"]

    cancellation = cancel_deep_run(root, run_id)

    assert run["state"] == "INCOMPLETE"
    assert deep_run_status(root, run_id)["observed_state"] == "INCOMPLETE"
    assert cancellation == {
        "run_id": run_id,
        "state": "ALREADY_STOPPED",
        "authority": "none",
    }


@pytest.mark.parametrize("commit", [None, "a" * 40, "quote'\nvalue"])
def test_write_provenance_round_trips_source_identity(tmp_path, monkeypatch, commit):
    import runpy
    import setuptools
    import ast

    monkeypatch.setattr(setuptools, "setup", lambda **kwargs: None)
    setup_module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "setup.py"))
    destination = tmp_path / "provenance.py"
    setup_module["write_provenance"](destination, commit)
    tree = ast.parse(destination.read_text())
    assert ast.literal_eval(tree.body[-1].value) == commit


def test_make_release_tree_stamps_distribution_not_checkout(tmp_path, monkeypatch):
    import runpy
    import setuptools
    from setuptools import Distribution
    from setuptools.command.sdist import sdist as base_sdist

    monkeypatch.setattr(setuptools, "setup", lambda **kwargs: None)
    setup_module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "setup.py"))

    def prepare(self, base_dir, files):
        (Path(base_dir) / "factoryline").mkdir()

    monkeypatch.setattr(base_sdist, "make_release_tree", prepare)
    command = setup_module["sdist"](Distribution())
    destination = tmp_path / "distribution"
    destination.mkdir()
    command.make_release_tree(str(destination), [])
    provenance = destination / "factoryline" / "_build_provenance.py"
    assert provenance.is_file() and "SOURCE_COMMIT = " in provenance.read_text()


def test_run_evidence_missing_manifest_is_structured_failure(tmp_path, capsys):
    from types import SimpleNamespace
    from factoryline.cli_quality import run_evidence

    args = SimpleNamespace(
        root=str(tmp_path), manifest="absent.json", execute=False, json=True
    )
    assert run_evidence(args) == 2
    error = json.loads(capsys.readouterr().err)
    assert error["marker"] == "CAPABILITY_EVIDENCE_BLOCKED"
    assert error["code"].startswith("E_")


def test_run_quality_creates_unverified_template(tmp_path, capsys):
    from types import SimpleNamespace
    from factoryline.cli_quality import run_quality

    args = SimpleNamespace(
        root=str(tmp_path),
        quality_cmd="template",
        out="quality.json",
        ui=False,
        json=True,
    )
    assert run_quality(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert (tmp_path / "quality.json").is_file()
    assert result.get("marker") or result.get("schema")
    manifest = json.loads((tmp_path / "quality.json").read_text())
    assert manifest["schema"].startswith("factory.")


def test_run_workflow_family_normalizes_os_failure(tmp_path, monkeypatch, capsys):
    from types import SimpleNamespace
    import factoryline.cli_domain as module

    def unavailable(args):
        raise OSError("fixture unavailable")

    monkeypatch.setattr(module, "_workflow_result", unavailable)
    assert module.run_workflow_family(SimpleNamespace(root=str(tmp_path))) == 1
    result = json.loads(capsys.readouterr().err)
    assert result["code"] == "E_INPUT"


def test_seal_combine_scoreboard_rejects_invalid_candidate_before_key_access(
    tmp_path, monkeypatch
):
    import factoryline.combine as module

    monkeypatch.setattr(module, "verify_combine_scoreboard", lambda path: {"ok": False})
    with pytest.raises(module.CombineError, match="scoreboard must verify") as failure:
        module.seal_combine_scoreboard(
            tmp_path / "scoreboard.json",
            private_key_path=tmp_path / "missing.key",
            keyid="fixture",
            identity="fixture",
            issuer="fixture",
            tenant_id="t",
            out=tmp_path / "sealed.json",
        )
    assert failure.value.code == "COMBINE_SIGNING_FAILED"
    assert not (tmp_path / "sealed.json").exists()


def test_adapter_main_missing_profile_returns_code_without_exception_text(
    monkeypatch, capsys
):
    import factoryline.deep_audit_io as module

    real_path = Path

    def absent(path):
        if str(path).startswith("/opt/factory/"):
            raise OSError("secret-fixture")
        return real_path(path)

    monkeypatch.setattr(module, "Path", absent)
    assert module.adapter_main(["runtime", "--mode", "coverage"]) == 2
    captured = capsys.readouterr()
    assert captured.err.strip() == "E_ADAPTER_INPUT" and captured.out == ""


def test_native_fuzz_main_rejects_unbound_harness_before_instrumentation(
    tmp_path, monkeypatch
):
    import sys
    from types import SimpleNamespace
    import factoryline.deep_audit_io as module

    contract = tmp_path / "contract.json"
    contract.write_text(json.dumps({"inventory": {"files": []}}))
    real_path = Path

    def paths(value):
        return contract if str(value) == "/factory-contract.json" else real_path(value)

    monkeypatch.setattr(module, "Path", paths)
    monkeypatch.setitem(sys.modules, "atheris", SimpleNamespace())
    with pytest.raises(KeyError):
        module.native_fuzz_main(["/src/unknown.py", str(tmp_path / "out.json")])
    assert not (tmp_path / "out.json").exists()


def test_write_release_candidate_preflight_binds_atomic_output(tmp_path, monkeypatch):
    import factoryline.release_candidate as module

    monkeypatch.setattr(
        module,
        "release_candidate_preflight",
        lambda *args, **kwargs: {"state": "BLOCKED", "reasons": ["fixture"]},
    )
    result = module.write_release_candidate_preflight(
        tmp_path, Path("contract.json"), [], Path("receipt.json")
    )
    stored = json.loads((tmp_path / "receipt.json").read_text())
    assert stored == result and stored["state"] == "BLOCKED"
    assert stored["marker"] == "RELEASE_CANDIDATE_PREFLIGHT_WRITTEN"
    assert len(stored["receipt_sha256"]) == 64
    assert not (tmp_path / "receipt.json.tmp").exists()
    with pytest.raises(ValueError, match="inside the workspace"):
        module.write_release_candidate_preflight(
            tmp_path, Path("contract.json"), [], tmp_path.parent / "escape.json"
        )


def test_compare_deep_audit_repairs_forwards_exact_bound_inputs(tmp_path, monkeypatch):
    from factoryline.repair_loop import compare_deep_audit_repairs
    import factoryline.deep_audit_loop as module

    calls = []

    def compare(root, before, after, **kwargs):
        calls.append((root, before, after, kwargs))
        return {"state": "INCOMPLETE", "authority": "none"}

    monkeypatch.setattr(module, "compare_deep_audits", compare)
    result = compare_deep_audit_repairs(
        tmp_path, "before.json", "after.json", require_attestation=True
    )
    assert result == {"state": "INCOMPLETE", "authority": "none"}
    assert calls == [
        (tmp_path, "before.json", "after.json", {"require_attestation": True})
    ]


def test_guarded_lane_evaluator_sanitizes_unknown_failure_codes():
    from factoryline.runtime_audit_common import guarded_lane_evaluator

    @guarded_lane_evaluator("runtime")
    def evaluate():
        raise ValueError("secret-fixture")

    result = evaluate()
    assert result["state"] == "INCOMPLETE"
    assert result["details"]["error_code"] == "E_ARTIFACT_INVALID"
    assert "secret-fixture" not in json.dumps(result)
