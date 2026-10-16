from __future__ import annotations

import json
from pathlib import Path
import hashlib
import subprocess

import pytest

from factoryline.proof_worklog import (
    MARKER,
    create_proof_worklog,
    proof_worklog_projection,
    verify_proof_worklog,
)
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.oracle_firewall import capture_intent_handoff, seal_oracle_contract


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _applied_repo(root: Path) -> str:
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Test")
    (root / "before.py").write_text("before = 1\n", encoding="utf-8")
    (root / "delete.py").write_text("delete = 1\n", encoding="utf-8")
    (root / "rename-old.py").write_text("rename = 1\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "baseline")
    return _git(root, "rev-parse", "HEAD")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_applied_change_projection_binds_current_candidate_and_declared_baseline(
    tmp_path,
):
    from factoryline.proof_worklog import applied_change_projection

    baseline = _applied_repo(tmp_path)
    (tmp_path / "before.py").write_text("after = 2\n", encoding="utf-8")
    (tmp_path / "literal[1].py").write_text("added = 1\n", encoding="utf-8")
    (tmp_path / "rename-old.py").rename(tmp_path / "rename-new.py")
    (tmp_path / "unrelated.txt").write_text("other\n", encoding="utf-8")
    (tmp_path / "delete.py").unlink()
    _git(
        tmp_path, "add", "before.py", "literal[1].py", "rename-old.py", "rename-new.py"
    )
    _git(tmp_path, "commit", "-qm", "candidate")
    manifest = [
        {"path": "before.py", "sha256": _sha(tmp_path / "before.py")},
        {"path": "literal[1].py", "sha256": _sha(tmp_path / "literal[1].py")},
        {"path": "rename-new.py", "sha256": _sha(tmp_path / "rename-new.py")},
    ]
    baseline_files = {
        "before.py": hashlib.sha256(b"before = 1\n").hexdigest(),
        "literal[1].py": None,
        "rename-old.py": hashlib.sha256(b"rename = 1\n").hexdigest(),
    }
    result = applied_change_projection(
        tmp_path,
        baseline,
        manifest,
        "Complete the checkout flow.",
        baseline_files=baseline_files,
    )

    assert result["state"] == "available"
    assert result["baseline_oid"] == baseline
    assert result["rationale"] == "Complete the checkout flow."
    changes = {row["path"]: row for row in result["changes"]}
    assert changes["before.py"]["disposition"] == "verified_candidate_bytes"
    assert changes["literal[1].py"]["kind"] == "added"
    assert changes["literal[1].py"]["disposition"] == "verified_candidate_bytes"
    assert changes["rename-new.py"]["kind"] == "renamed"
    assert changes["rename-new.py"]["old_path"] == "rename-old.py"
    assert changes["delete.py"]["disposition"] == "unverified"
    assert "unrelated.txt" in result["unrelated_dirty_paths"]


def test_applied_change_projection_keeps_same_file_dirty_and_unbound_delete_unverified(
    tmp_path,
):
    from factoryline.proof_worklog import applied_change_projection

    baseline = _applied_repo(tmp_path)
    (tmp_path / "before.py").write_text("staged = 1\n", encoding="utf-8")
    _git(tmp_path, "add", "before.py")
    (tmp_path / "before.py").write_text("tested = 2\n", encoding="utf-8")
    manifest = [{"path": "before.py", "sha256": _sha(tmp_path / "before.py")}]
    (tmp_path / "delete.py").unlink()
    result = applied_change_projection(
        tmp_path,
        baseline,
        manifest,
        "Do not infer authorship.",
        baseline_files={"before.py": hashlib.sha256(b"before = 1\n").hexdigest()},
    )
    changes = {row["path"]: row for row in result["changes"]}
    assert result["state"] == "available"
    assert changes["before.py"]["disposition"] == "unverified"
    assert changes["before.py"]["reason"] == "mixed_or_ambiguous_same_file_edits"
    assert changes["delete.py"]["disposition"] == "unverified"


def test_applied_change_projection_rejects_missing_baseline_symlink_and_exhaustion(
    tmp_path,
):
    from factoryline.proof_worklog import applied_change_projection

    assert (
        applied_change_projection(tmp_path, None, [], "private")["reason"]
        == "baseline_unbound"
    )
    baseline = _applied_repo(tmp_path)
    try:
        (tmp_path / "linked.py").symlink_to(tmp_path / "before.py")
    except OSError:
        pytest.skip("symlink creation is unavailable")
    symlink_result = applied_change_projection(
        tmp_path,
        baseline,
        [{"path": "linked.py", "sha256": _sha(tmp_path / "before.py")}],
        "private",
        baseline_files={"linked.py": None},
    )
    assert symlink_result["state"] == "unavailable"
    assert (
        applied_change_projection(
            tmp_path,
            baseline,
            [{"path": f"file-{index}.py", "sha256": "a" * 64} for index in range(1001)],
            "private",
        )["reason"]
        == "candidate_manifest_unavailable"
    )


def test_applied_change_projection_rejects_head_change_during_final_freshness(
    tmp_path, monkeypatch
):
    from factoryline import proof_worklog

    baseline = _applied_repo(tmp_path)
    (tmp_path / "before.py").write_text("candidate = 2\n", encoding="utf-8")
    _git(tmp_path, "add", "before.py")
    _git(tmp_path, "commit", "-qm", "candidate")
    manifest = [{"path": "before.py", "sha256": _sha(tmp_path / "before.py")}]
    original = proof_worklog._AppliedChangeGit.verify_current

    def change_head(git, snapshot):
        (tmp_path / "head-change.txt").write_text("changed\n", encoding="utf-8")
        _git(tmp_path, "add", "head-change.txt")
        _git(tmp_path, "commit", "-qm", "head changed during projection")
        return original(git, snapshot)

    monkeypatch.setattr(proof_worklog._AppliedChangeGit, "verify_current", change_head)
    result = proof_worklog.applied_change_projection(
        tmp_path,
        baseline,
        manifest,
        "private",
        baseline_files={"before.py": hashlib.sha256(b"before = 1\n").hexdigest()},
    )
    assert result["state"] == "unavailable"


def test_applied_change_projection_stops_at_retained_data_limit(tmp_path):
    from factoryline.proof_worklog import applied_change_projection

    baseline = _applied_repo(tmp_path)
    large = tmp_path / "large.bin"
    large.write_bytes(b"x" * (8 * 1024 * 1024 + 1))
    _git(tmp_path, "add", "large.bin")
    _git(tmp_path, "commit", "-qm", "large baseline")
    baseline = _git(tmp_path, "rev-parse", "HEAD")
    large.write_bytes(b"y" * (8 * 1024 * 1024 + 1))
    result = applied_change_projection(
        tmp_path,
        baseline,
        [{"path": "large.bin", "sha256": _sha(large)}],
        "large test",
        baseline_files={"large.bin": _sha(large)},
    )
    assert result["state"] == "unavailable"


def test_applied_change_projection_rejects_unsuccessful_cleanup_receipt(
    tmp_path, monkeypatch
):
    from factoryline import assembly_process
    from factoryline.proof_worklog import applied_change_projection

    baseline = _applied_repo(tmp_path)
    monkeypatch.setattr(
        assembly_process,
        "run_cli_detailed",
        lambda *args, **kwargs: {
            "ok": False,
            "reason": "timeout",
            "cleanup_confirmed": True,
            "streams_closed": True,
            "exit_code": 0,
            "stdout": b"",
            "stderr": b"",
        },
    )
    result = applied_change_projection(
        tmp_path,
        baseline,
        [{"path": "before.py", "sha256": _sha(tmp_path / "before.py")}],
        "must fail closed",
        baseline_files={"before.py": _sha(tmp_path / "before.py")},
    )
    assert result["state"] == "unavailable"


@pytest.mark.parametrize("late_change", ["index", "untracked"])
def test_applied_change_projection_rechecks_index_and_untracked_facts(
    tmp_path, monkeypatch, late_change
):
    from factoryline import proof_worklog

    baseline = _applied_repo(tmp_path)
    (tmp_path / "before.py").write_text("candidate = 2\n", encoding="utf-8")
    manifest = [{"path": "before.py", "sha256": _sha(tmp_path / "before.py")}]
    original = proof_worklog._AppliedChangeGit.verify_current

    def add_late_fact(git, snapshot):
        if late_change == "index":
            (tmp_path / "delete.py").write_text("index-only = 3\n", encoding="utf-8")
            _git(tmp_path, "add", "delete.py")
        else:
            (tmp_path / "late.txt").write_text("untracked\n", encoding="utf-8")
        return original(git, snapshot)

    monkeypatch.setattr(
        proof_worklog._AppliedChangeGit, "verify_current", add_late_fact
    )
    result = proof_worklog.applied_change_projection(
        tmp_path,
        baseline,
        manifest,
        "recheck all disposition inputs",
        baseline_files={"before.py": _sha(tmp_path / "before.py")},
    )
    assert result["state"] == "unavailable"


def test_applied_change_projection_rechecks_untracked_bytes_with_same_git_facts(
    tmp_path, monkeypatch
):
    from factoryline import proof_worklog

    baseline = _applied_repo(tmp_path)
    (tmp_path / "before.py").write_text("candidate = 2\n", encoding="utf-8")
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_text("initial\n", encoding="utf-8")
    manifest = [{"path": "before.py", "sha256": _sha(tmp_path / "before.py")}]
    original = proof_worklog._AppliedChangeGit.verify_current

    def change_untracked_bytes(git, snapshot):
        before = git.inventory(snapshot["baseline_oid"])[5]
        assert before == snapshot["facts"]
        unrelated.write_text(
            "different bytes, same untracked status\n", encoding="utf-8"
        )
        after = git.inventory(snapshot["baseline_oid"])[5]
        assert after == snapshot["facts"]
        return original(git, snapshot)

    monkeypatch.setattr(
        proof_worklog._AppliedChangeGit, "verify_current", change_untracked_bytes
    )
    result = proof_worklog.applied_change_projection(
        tmp_path,
        baseline,
        manifest,
        "byte facts must remain fresh",
        baseline_files={"before.py": hashlib.sha256(b"before = 1\n").hexdigest()},
    )
    assert result["state"] == "unavailable"


def test_applied_change_digest_honors_expired_deadline_for_empty_file(tmp_path):
    from factoryline import proof_worklog

    empty = tmp_path / "empty.bin"
    empty.touch()
    budget = {"deadline": proof_worklog.time.monotonic() - 1, "retained": 0}
    git = proof_worklog._AppliedChangeGit(tmp_path, budget)
    with pytest.raises(ValueError, match="resource_exhausted"):
        git.digest(empty)


def test_applied_change_missing_snapshot_file_checks_deadline_after_path_read(
    tmp_path, monkeypatch
):
    from factoryline import proof_worklog

    budget = {
        "deadline": proof_worklog.time.monotonic() + 30,
        "retained": 0,
    }
    git = proof_worklog._AppliedChangeGit(tmp_path, budget)
    resolve_path = proof_worklog._literal_workspace_file

    def expire_after_resolve(root, value, *, may_be_missing):
        target = resolve_path(root, value, may_be_missing=may_be_missing)
        budget["deadline"] = proof_worklog.time.monotonic() - 1
        return target

    monkeypatch.setattr(proof_worklog, "_literal_workspace_file", expire_after_resolve)
    with pytest.raises(ValueError, match="resource_exhausted"):
        git.file_fact("missing-after-snapshot.py")


def test_untracked_candidate_needs_explicit_planned_new_baseline_fact(tmp_path):
    from factoryline.proof_worklog import applied_change_projection

    baseline = _applied_repo(tmp_path)
    created = tmp_path / "planned.py"
    created.write_text("planned = True\n", encoding="utf-8")
    result = applied_change_projection(
        tmp_path,
        baseline,
        [{"path": "planned.py", "sha256": _sha(created)}],
        "must be explicitly declared planned-new",
        baseline_files={},
    )
    change = next(row for row in result["changes"] if row["path"] == "planned.py")
    assert result["state"] == "available"
    assert change["disposition"] == "unverified"


def test_candidate_binding_discovery_shares_deadline_and_caps_directory_scan(
    tmp_path,
):
    from factoryline import proof_worklog

    expired = {
        "deadline": proof_worklog.time.monotonic() - 1,
        "retained": 0,
    }
    context = proof_worklog.bound_candidate_context(
        tmp_path,
        tmp_path / "mission.json",
        {},
        "a" * 64,
        _budget=expired,
    )
    assert context[0] is None
    for index in range(101):
        (tmp_path / f"candidate-binding-{index:03}.json").write_text(
            "{}", encoding="utf-8"
        )
    bounded = proof_worklog.bound_candidate_context(
        tmp_path,
        tmp_path / "mission.json",
        {},
        "a" * 64,
    )
    assert bounded[0] is None


def test_applied_change_projection_fails_closed_for_missing_nonancestor_stale_and_non_git(
    tmp_path,
):
    from factoryline.proof_worklog import applied_change_projection

    outside = tmp_path / "outside"
    outside.mkdir()
    assert (
        applied_change_projection(outside, "a" * 40, [], "private")["reason"]
        == "candidate_manifest_unavailable"
    )
    assert (
        applied_change_projection(tmp_path / "not-git", "a" * 40, [], "private")[
            "state"
        ]
        == "unavailable"
    )
    baseline = _applied_repo(tmp_path)
    manifest = [{"path": "before.py", "sha256": _sha(tmp_path / "before.py")}]
    assert (
        applied_change_projection(tmp_path, baseline, manifest, "r", baseline_files={})[
            "state"
        ]
        == "available"
    )
    assert (
        applied_change_projection(tmp_path, "f" * 40, manifest, "r", baseline_files={})[
            "state"
        ]
        == "unavailable"
    )
    (tmp_path / "before.py").write_text("stale\n", encoding="utf-8")
    stale = applied_change_projection(
        tmp_path,
        baseline,
        manifest,
        "r",
        baseline_files={"before.py": hashlib.sha256(b"before = 1\n").hexdigest()},
    )
    assert stale["state"] == "unavailable"


def test_applied_change_projection_rejects_existing_nonancestor_baseline(tmp_path):
    from factoryline.proof_worklog import applied_change_projection

    baseline = _applied_repo(tmp_path)
    _git(tmp_path, "checkout", "--orphan", "unrelated-history")
    _git(tmp_path, "rm", "-q", "-rf", "--", "before.py", "delete.py", "rename-old.py")
    (tmp_path / "other.py").write_text("other = 1\n", encoding="utf-8")
    _git(tmp_path, "add", "other.py")
    _git(tmp_path, "commit", "-qm", "unrelated history")
    result = applied_change_projection(
        tmp_path,
        baseline,
        [{"path": "other.py", "sha256": _sha(tmp_path / "other.py")}],
        "unrelated baseline must not be accepted",
    )

    assert result["state"] == "unavailable"
    assert result["reason"] == "projection_unavailable_or_stale"


AGENT = {
    "schema": "factory.agent-identity.v1",
    "subject": "worklog-owner",
    "provider": "declared",
    "model": "declared-model",
}


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    return path


def _contract(root: Path) -> Path:
    intent = root / "briefs" / "intent.md"
    source = root / "src" / "checkout.py"
    intent.parent.mkdir(parents=True, exist_ok=True)
    source.parent.mkdir(parents=True, exist_ok=True)
    intent.write_text(
        "Checkout completes valid orders and never exposes private account data.\n",
        encoding="utf-8",
    )
    source.write_text(
        "def checkout(order):\n    return bool(order)\n", encoding="utf-8"
    )
    handoff = capture_intent_handoff(
        root,
        intent,
        AGENT,
        "worklog-intake",
        Path(".factory/oracles/handoffs/worklog-intake.json"),
    )
    payload = {
        "schema": "factory.oracle-contract-input.v1",
        "id": "worklog-checkout",
        "version": 1,
        "approved_by": "Release Owner",
        "approval_rationale": "Original intent reviewed.",
        "scope_paths": ["src"],
        "handoff": handoff["path"],
        "sources": [],
        "requirements": [
            {
                "id": "complete",
                "statement": "Valid checkout completes.",
                "origin": "human_confirmed",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
            }
        ],
        "forbidden_behaviors": [
            {
                "id": "private",
                "statement": "Private account data is never exposed.",
                "origin": "human_confirmed",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
            }
        ],
        "gates": [
            {
                "id": "quality",
                "statement": "Quality reaches approved threshold.",
                "origin": "trusted_source",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
                "comparison": "gte",
                "value": 95,
            }
        ],
        "exceptions": [
            {
                "id": "offline",
                "statement": "Offline evidence remains advisory until review.",
                "origin": "human_confirmed",
                "effect": "advisory",
                "source_id": "original-intent",
                "critical": False,
            }
        ],
        "negative_cases": [
            {
                "id": "bad-order",
                "statement": "Invalid order does not complete.",
                "origin": "human_confirmed",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
            }
        ],
        "invariants": [
            {
                "id": "scope",
                "statement": "Only sealed scope changes.",
                "origin": "trusted_source",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
            }
        ],
        "tests": [
            {
                "id": "checkout-test",
                "statement": "Rejected-order path is tested.",
                "origin": "human_confirmed",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
                "path": "tests/test_checkout.py",
            }
        ],
    }
    return (
        root
        / seal_oracle_contract(
            root,
            _write(root / "oracle-input.json", payload),
            Path(".factory/oracles/contracts/worklog-checkout.json"),
        )["path"]
    )


def test_worklog_is_bound_to_current_contract_and_never_claims_external_post(
    tmp_path: Path,
) -> None:
    contract = _contract(tmp_path)
    draft = create_proof_worklog(tmp_path, contract.relative_to(tmp_path))

    assert draft["marker"] == MARKER
    assert draft["review_required"] is True
    assert "has not been posted" in draft["markdown"]
    assert "Valid checkout completes." in draft["markdown"]
    assert "Private account data is never exposed." in draft["markdown"]
    assert all(value is False for value in draft["authority"].values())
    assert verify_proof_worklog(tmp_path, Path(draft["path"]))["ok"] is True
    projection = proof_worklog_projection(tmp_path)
    assert projection["draft_count"] == 1
    assert projection["invalid_count"] == 0
    snapshot = graph_ops_snapshot(tmp_path)
    assert snapshot["facts"]["proof_worklog_draft_count"] == 1
    assert any(node["kind"] == "proof_worklog" for node in snapshot["nodes"])


def test_worklog_fails_closed_when_contract_changes(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    draft = create_proof_worklog(tmp_path, contract.relative_to(tmp_path))
    value = json.loads(contract.read_text(encoding="utf-8"))
    value["contract_sha256"] = "0" * 64
    contract.write_text(json.dumps(value), encoding="utf-8")

    checked = verify_proof_worklog(tmp_path, Path(draft["path"]))
    assert checked["ok"] is False
    assert checked["reason"] == "oracle_binding_stale"
