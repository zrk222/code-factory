from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from datetime import datetime, timedelta, timezone

import pytest
import factoryline.repair_sandbox as repair_sandbox

from factoryline.cli import main
from factoryline.repair_sandbox import (
    RepairSandboxError,
    create_repair_scope,
    inspect_repair_candidate,
    verify_repair_scope,
    write_repair_candidate_artifacts,
    write_repair_scope_artifacts,
    create_sandbox_execution_receipt,
    verify_sandbox_execution_receipt,
    create_repair_approval,
    execute_approved_repair,
    request_repair_stop,
    revoke_repair_approval,
)


def _files(root: Path) -> dict[str, bytes]:
    return {
        item.relative_to(root).as_posix(): item.read_bytes()
        for item in root.rglob("*")
        if item.is_file()
    }


def _patch(root: Path, name: str, body: str) -> Path:
    path = root / name
    path.write_text(body, encoding="utf-8")
    return path


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def _git_repair_case(root: Path) -> tuple[Path, Path]:
    (root / "src").mkdir(parents=True)
    (root / "src" / "value.py").write_text("VALUE = 0\n", encoding="utf-8")
    (root / ".gitignore").write_text(".factory/\n", encoding="utf-8")
    _git(root, "init", "--quiet")
    _git(root, "config", "user.name", "Repair Test")
    _git(root, "config", "user.email", "repair-test@example.invalid")
    _git(root, "add", ".gitignore", "src/value.py")
    _git(root, "commit", "--quiet", "-m", "baseline")
    scope = create_repair_scope(root, "Repair value", ["src/value.py"])
    out_dir = root / ".factory" / "scopes"
    scope_artifacts = write_repair_scope_artifacts(scope, root, out_dir)
    scope_path = Path(scope_artifacts["paths"]["json"])
    patch_path = root / ".factory" / "candidate.diff"
    patch_path.parent.mkdir(parents=True, exist_ok=True)
    patch_path.write_text(
        "diff --git a/src/value.py b/src/value.py\n"
        "--- a/src/value.py\n"
        "+++ b/src/value.py\n"
        "@@ -1 +1 @@\n"
        "-VALUE = 0\n"
        "+VALUE = 1\n",
        encoding="utf-8",
    )
    return scope_path, patch_path


def _repair_checks() -> list[dict[str, object]]:
    return [
        {
            "id": "value-repaired",
            "kind": "positive",
            "argv": [
                "python",
                "-c",
                "from pathlib import Path; assert 'VALUE = 1' in Path('src/value.py').read_text(), 'repair not applied'",
            ],
            "failure": {"exit_code": 1, "signature": "repair not applied"},
        },
        {
            "id": "old-value-removed",
            "kind": "negative",
            "argv": [
                "python",
                "-c",
                "from pathlib import Path; assert 'VALUE = 0' in Path('src/value.py').read_text(), 'negative control expected baseline value'",
            ],
            "failure": {
                "exit_code": 1,
                "signature": "negative control expected baseline value",
            },
        },
    ]


def _approval(root: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    scope_path, patch_path = _git_repair_case(root)
    digest = "b" * 64
    engine = {
        "context": "desktop-linux",
        "endpoint": "npipe:////./pipe/dockerDesktopLinuxEngine",
        "engine_id": "test-engine",
        "docker_root": "/var/lib/docker",
    }
    monkeypatch.setattr(
        "factoryline.repair_sandbox._docker_identity",
        lambda _root, _context=None: engine,
    )
    monkeypatch.setattr(
        "factoryline.repair_sandbox._image_ref",
        lambda _root, _image, _digest, _context=None: f"test-runtime@sha256:{digest}",
    )
    _mock_docker_tool_lookup(monkeypatch)
    return create_repair_approval(
        root,
        scope_path,
        patch_path,
        approved_by="maintainer",
        confirmation="APPROVE REPAIR "
        + inspect_repair_candidate(root, scope_path, patch_path)["candidate_sha256"],
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        container_image="test-runtime",
        container_digest=digest,
        checks=_repair_checks(),
    )


def _mock_docker_tool_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    original = repair_sandbox._tool_path
    monkeypatch.setattr(
        repair_sandbox,
        "_tool_path",
        lambda name: "docker-test-executable" if name == "docker" else original(name),
    )


def _assert_scope_contract(scope: dict[str, object], measured_bytes: bytes) -> None:
    assert scope["schema"] == "factory.repair_scope.v1"
    assert scope["change_list"] == "Checkout hardening"
    assert scope["scope_id"] == f"repair-scope-{scope['scope_sha256'][:12]}"
    assert scope["paths"] == [
        {
            "path": "src/service.py",
            "exists": True,
            "size_bytes": len(measured_bytes),
            "sha256": scope["paths"][0]["sha256"],
        }
    ]
    assert scope["context_budget"] == {
        "limit_bytes": 262144,
        "measured_bytes": len(measured_bytes),
        "file_count": 1,
        "missing_paths": 0,
        "decision": "within_budget",
        "scope_limits": "Measured bytes only; this is not a token, provider-credit, latency, or quality estimate.",
    }
    assert scope["review"]["changed_paths"] == ["src/service.py"]
    assert scope["candidate"]["state"] == "not_started"
    assert scope["authority"]["patch_apply"] is False
    assert [item["id"] for item in scope["verification"]["required_checks"]][-2:] == [
        "independent_verifier",
        "human_apply",
    ]


def test_repair_scope_is_explicit_deterministic_and_does_not_write_by_default(
    tmp_path: Path,
) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "service.py").write_text("before\n", encoding="utf-8")
    before = _files(tmp_path)
    scope = create_repair_scope(tmp_path, "Checkout hardening", ["src/service.py"])
    measured_bytes = (tmp_path / "src" / "service.py").read_bytes()
    _assert_scope_contract(scope, measured_bytes)
    assert _files(tmp_path) == before
    assert (
        create_repair_scope(tmp_path, "Checkout hardening", ["src/service.py"])[
            "scope_sha256"
        ]
        == scope["scope_sha256"]
    )


def test_repair_scope_artifacts_are_explicit_local_and_hash_bound(
    tmp_path: Path,
) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "service.py").write_text("before\n", encoding="utf-8")
    scope = create_repair_scope(tmp_path, "Checkout", ["src/service.py"])

    artifacts = write_repair_scope_artifacts(
        scope, tmp_path, tmp_path / ".factory" / "repair-sandboxes"
    )

    assert artifacts["marker"] == "REPAIR_SCOPE_ARTIFACTS_WRITTEN"
    assert all(Path(path).is_file() for path in artifacts["paths"].values())
    payload = json.loads(Path(artifacts["paths"]["json"]).read_text(encoding="utf-8"))
    assert payload["scope_sha256"] == scope["scope_sha256"]
    assert "scope_markdown" not in payload
    assert "Human diff review and apply" in Path(
        artifacts["paths"]["mermaid"]
    ).read_text(encoding="utf-8")


def test_verify_repair_scope_requires_a_current_canonical_scope(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "service.py").write_text("before\n", encoding="utf-8")
    scope = create_repair_scope(tmp_path, "Checkout", ["src/service.py"])

    assert verify_repair_scope(scope, tmp_path)["scope_id"] == scope["scope_id"]
    scope["paths"][0]["sha256"] = "0" * 64

    with pytest.raises(RepairSandboxError) as caught:
        verify_repair_scope(scope, tmp_path)

    assert caught.value.code == "REPAIR_SCOPE_TAMPERED"


def test_candidate_patch_is_scoped_and_never_applied(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    source = tmp_path / "src" / "service.py"
    source.write_text("before\n", encoding="utf-8")
    scope = create_repair_scope(tmp_path, "Checkout", ["src/service.py"])
    scope_artifacts = write_repair_scope_artifacts(
        scope, tmp_path, tmp_path / ".factory" / "repair-sandboxes"
    )
    patch = _patch(
        tmp_path,
        "candidate.patch",
        """diff --git a/src/service.py b/src/service.py
index 1111111..2222222 100644
--- a/src/service.py
+++ b/src/service.py
@@ -1 +1 @@
-before
+after
""",
    )

    candidate = inspect_repair_candidate(
        tmp_path, Path(scope_artifacts["paths"]["json"]), patch
    )

    assert candidate["schema"] == "factory.repair_candidate.v1"
    assert candidate["touched_paths"] == ["src/service.py"]
    assert candidate["patch"]["path"] == "candidate.patch"
    assert candidate["apply"]["state"] == "human_confirmation_required"
    assert candidate["authority"]["source_modify"] is False
    assert source.read_text(encoding="utf-8") == "before\n"
    artifacts = write_repair_candidate_artifacts(
        candidate, tmp_path, tmp_path / ".factory" / "repair-sandboxes"
    )
    assert Path(artifacts["paths"]["json"]).is_file()


def test_scope_reports_measured_context_and_recommends_split_without_estimating_tokens(
    tmp_path: Path,
) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "service.py").write_text("x" * 11, encoding="utf-8")

    scope = create_repair_scope(
        tmp_path, "Checkout", ["src/service.py"], context_budget_bytes=10
    )

    assert scope["context_budget"]["measured_bytes"] == 11
    assert scope["context_budget"]["decision"] == "split_recommended"
    assert "token" not in json.dumps(scope["context_budget"]).lower().replace(
        "not a token", ""
    )


def test_candidate_rejects_outside_scope_before_any_apply(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "service.py").write_text("before\n", encoding="utf-8")
    scope = create_repair_scope(tmp_path, "Checkout", ["src/service.py"])
    artifacts = write_repair_scope_artifacts(
        scope, tmp_path, tmp_path / ".factory" / "repair-sandboxes"
    )
    patch = _patch(
        tmp_path,
        "candidate.patch",
        """diff --git a/.github/workflows/publish.yml b/.github/workflows/publish.yml
index 1111111..2222222 100644
--- a/.github/workflows/publish.yml
+++ b/.github/workflows/publish.yml
@@ -1 +1 @@
-before
+after
""",
    )

    with pytest.raises(RepairSandboxError) as caught:
        inspect_repair_candidate(tmp_path, Path(artifacts["paths"]["json"]), patch)

    assert caught.value.code == "REPAIR_CANDIDATE_OUT_OF_SCOPE"
    assert (tmp_path / "src" / "service.py").read_text(encoding="utf-8") == "before\n"


@pytest.mark.parametrize(
    "patch_body",
    [
        "diff --git a/src/service.py b/src/service.py\nGIT binary patch\n",
        'diff --git "a/src/service.py" "b/src/service.py"\n',
        "diff --combined src/service.py\n",
    ],
)
def test_candidate_rejects_unsupported_patch_forms(
    tmp_path: Path, patch_body: str
) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "service.py").write_text("before\n", encoding="utf-8")
    scope = create_repair_scope(tmp_path, "Checkout", ["src/service.py"])
    artifacts = write_repair_scope_artifacts(
        scope, tmp_path, tmp_path / ".factory" / "repair-sandboxes"
    )
    patch = _patch(tmp_path, "candidate.patch", patch_body)

    with pytest.raises(RepairSandboxError) as caught:
        inspect_repair_candidate(tmp_path, Path(artifacts["paths"]["json"]), patch)

    assert caught.value.code == "REPAIR_PATCH_UNSUPPORTED"


def test_candidate_rejects_scope_drift(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    source = tmp_path / "src" / "service.py"
    source.write_text("before\n", encoding="utf-8")
    scope = create_repair_scope(tmp_path, "Checkout", ["src/service.py"])
    artifacts = write_repair_scope_artifacts(
        scope, tmp_path, tmp_path / ".factory" / "repair-sandboxes"
    )
    source.write_text("drifted\n", encoding="utf-8")
    patch = _patch(
        tmp_path, "candidate.patch", "diff --git a/src/service.py b/src/service.py\n"
    )

    with pytest.raises(RepairSandboxError) as caught:
        inspect_repair_candidate(tmp_path, Path(artifacts["paths"]["json"]), patch)

    assert caught.value.code == "REPAIR_SCOPE_DRIFT"


def test_repair_cli_outputs_machine_readable_scope_and_candidate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "service.py").write_text("before\n", encoding="utf-8")
    out_dir = tmp_path / ".factory" / "repair-sandboxes"

    assert (
        main(
            [
                "repair",
                "scope",
                "--root",
                str(tmp_path),
                "--change-list",
                "Checkout",
                "--changed",
                "src/service.py",
                "--out-dir",
                str(out_dir),
                "--json",
            ]
        )
        == 0
    )
    scope = json.loads(capsys.readouterr().out)
    patch = _patch(
        tmp_path, "candidate.patch", "diff --git a/src/service.py b/src/service.py\n"
    )
    assert (
        main(
            [
                "repair",
                "candidate",
                "--root",
                str(tmp_path),
                "--scope",
                scope["artifacts"]["paths"]["json"],
                "--patch",
                str(patch),
                "--out-dir",
                str(out_dir),
                "--json",
            ]
        )
        == 0
    )
    candidate = json.loads(capsys.readouterr().out)

    assert scope["artifacts"]["marker"] == "REPAIR_SCOPE_ARTIFACTS_WRITTEN"
    assert candidate["artifacts"]["marker"] == "REPAIR_CANDIDATE_ARTIFACTS_WRITTEN"
    assert candidate["scope_sha256"] == scope["scope_sha256"]


def test_repair_cli_marks_outside_candidate_path_machine_readably(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "service.py").write_text("before\n", encoding="utf-8")
    scope = create_repair_scope(tmp_path, "Checkout", ["src/service.py"])
    artifacts = write_repair_scope_artifacts(
        scope, tmp_path, tmp_path / ".factory" / "repair-sandboxes"
    )
    patch = _patch(
        tmp_path, "candidate.patch", "diff --git a/outside.py b/outside.py\n"
    )

    assert (
        main(
            [
                "repair",
                "candidate",
                "--root",
                str(tmp_path),
                "--scope",
                artifacts["paths"]["json"],
                "--patch",
                str(patch),
                "--json",
            ]
        )
        == 2
    )
    failure = json.loads(capsys.readouterr().err)

    assert failure["schema"] == "factory.repair_candidate.error.v1"
    assert failure["marker"] == "REPAIR_SANDBOX_PATH_REJECTED"
    assert failure["code"] == "REPAIR_CANDIDATE_OUT_OF_SCOPE"


def test_external_sandbox_observation_is_explicit_and_fail_closed() -> None:
    digest = "a" * 64
    receipt = create_sandbox_execution_receipt(
        digest,
        runner_id="docker-runner",
        isolation_level="CONTAINER_BOUNDARY",
        runtime_digest=digest,
        toolchain_digest=digest,
        network_policy="restricted",
        input_digests=[digest],
        output_digests=[digest],
        teardown_status="complete",
        executed=True,
        observed_at="2026-09-21T00:00:00Z",
    )
    assert verify_sandbox_execution_receipt(receipt)["status"] == "OBSERVED"
    unenforced = create_sandbox_execution_receipt(
        digest,
        runner_id="local",
        isolation_level="UNENFORCED",
        runtime_digest=digest,
        toolchain_digest=digest,
        network_policy="unknown",
        input_digests=[],
        output_digests=[],
        teardown_status="unknown",
        executed=True,
    )
    assert verify_sandbox_execution_receipt(unenforced)["status"] == "UNENFORCED"
    tampered = dict(receipt)
    tampered["status"] = "OBSERVED"
    tampered["isolation_level"] = "UNENFORCED"
    with pytest.raises(RepairSandboxError, match="digest"):
        verify_sandbox_execution_receipt(tampered)


def test_repair_approval_requires_exact_human_confirmation_and_bound_controls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scope_path, patch_path = _git_repair_case(tmp_path)
    monkeypatch.setattr(
        "factoryline.repair_sandbox._image_ref",
        lambda _root, image, digest, _context=None: f"{image}@sha256:{digest}",
    )
    monkeypatch.setattr(
        "factoryline.repair_sandbox._docker_identity",
        lambda _root, _context=None: {
            "context": "desktop-linux",
            "endpoint": "npipe:////./pipe/dockerDesktopLinuxEngine",
            "engine_id": "test-engine",
            "docker_root": "/var/lib/docker",
        },
    )
    _mock_docker_tool_lookup(monkeypatch)
    kwargs = {
        "approved_by": "maintainer",
        "confirmation": "APPROVE REPAIR wrong-candidate",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat(),
        "container_image": "runtime",
        "container_digest": "c" * 64,
        "checks": _repair_checks(),
    }
    with pytest.raises(RepairSandboxError, match="exact candidate"):
        create_repair_approval(tmp_path, scope_path, patch_path, **kwargs)
    kwargs["confirmation"] = (
        "APPROVE REPAIR "
        + inspect_repair_candidate(tmp_path, scope_path, patch_path)["candidate_sha256"]
    )
    approval = create_repair_approval(tmp_path, scope_path, patch_path, **kwargs)
    saved = json.loads((tmp_path / approval["path"]).read_text(encoding="utf-8"))
    assert approval["state"] == "APPROVED_NOT_EXECUTED"
    assert saved["base_commit"] == _git(tmp_path, "rev-parse", "HEAD")
    assert saved["scope_sha256"] == json.loads(scope_path.read_text())["scope_sha256"]
    assert (
        saved["patch_sha256"]
        == inspect_repair_candidate(tmp_path, scope_path, patch_path)["patch"]["sha256"]
    )
    assert len(saved["tool_contract_sha256"]) == 64


def test_repair_approval_rejects_missing_controls_and_unpinned_images(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scope_path, patch_path = _git_repair_case(tmp_path)
    monkeypatch.setattr(
        "factoryline.repair_sandbox._docker_identity",
        lambda _root, _context=None: {
            "context": "desktop-linux",
            "endpoint": "npipe:////./pipe/dockerDesktopLinuxEngine",
            "engine_id": "test-engine",
            "docker_root": "/var/lib/docker",
        },
    )
    with pytest.raises(RepairSandboxError, match="SHA-256 digest"):
        create_repair_approval(
            tmp_path,
            scope_path,
            patch_path,
            approved_by="maintainer",
            confirmation="APPROVE REPAIR placeholder",
            expires_at=(datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            container_image="runtime",
            container_digest="tag-only",
            checks=[],
        )


def test_repair_approval_fails_closed_when_docker_executable_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scope_path, patch_path = _git_repair_case(tmp_path)
    monkeypatch.setattr(
        repair_sandbox,
        "_docker_identity",
        lambda _root, _context=None: {
            "context": "desktop-linux",
            "endpoint": "npipe:////./pipe/dockerDesktopLinuxEngine",
            "engine_id": "test-engine",
            "docker_root": "/var/lib/docker",
        },
    )
    monkeypatch.setattr(
        repair_sandbox,
        "_image_ref",
        lambda _root, _image, digest, _context=None: f"runtime@sha256:{digest}",
    )
    original_which = repair_sandbox.shutil.which
    monkeypatch.setattr(
        repair_sandbox.shutil,
        "which",
        lambda name: None if name == "docker" else original_which(name),
    )
    with pytest.raises(RepairSandboxError) as caught:
        create_repair_approval(
            tmp_path,
            scope_path,
            patch_path,
            approved_by="maintainer",
            confirmation=(
                "APPROVE REPAIR "
                + inspect_repair_candidate(tmp_path, scope_path, patch_path)[
                    "candidate_sha256"
                ]
            ),
            expires_at=(datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            container_image="runtime",
            container_digest="f" * 64,
            checks=_repair_checks(),
        )
    assert caught.value.code == "REPAIR_TOOL_UNAVAILABLE"
    assert not list((tmp_path / ".factory" / "repair-approvals").glob("*.json"))


def test_repair_approval_rejects_protected_test_edits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_guard.py").write_text("assert True\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text(".factory/\n", encoding="utf-8")
    _git(tmp_path, "init", "--quiet")
    _git(tmp_path, "config", "user.name", "Repair Test")
    _git(tmp_path, "config", "user.email", "repair-test@example.invalid")
    _git(tmp_path, "add", ".gitignore", "tests/test_guard.py")
    _git(tmp_path, "commit", "--quiet", "-m", "baseline")
    scope = create_repair_scope(tmp_path, "Test attack", ["tests/test_guard.py"])
    scope_path = Path(
        write_repair_scope_artifacts(scope, tmp_path, tmp_path / ".factory")["paths"][
            "json"
        ]
    )
    patch_path = _patch(
        tmp_path,
        ".factory/test.patch",
        "diff --git a/tests/test_guard.py b/tests/test_guard.py\n"
        "--- a/tests/test_guard.py\n+++ b/tests/test_guard.py\n@@ -1 +1 @@\n"
        "-assert True\n+assert False\n",
    )
    monkeypatch.setattr(
        "factoryline.repair_sandbox._image_ref",
        lambda *_args: "runtime@sha256:" + "d" * 64,
    )
    monkeypatch.setattr(
        "factoryline.repair_sandbox._docker_identity",
        lambda _root, _context=None: {
            "context": "desktop-linux",
            "endpoint": "npipe:////./pipe/dockerDesktopLinuxEngine",
            "engine_id": "test-engine",
            "docker_root": "/var/lib/docker",
        },
    )
    _mock_docker_tool_lookup(monkeypatch)
    with pytest.raises(RepairSandboxError, match="protected paths"):
        create_repair_approval(
            tmp_path,
            scope_path,
            patch_path,
            approved_by="maintainer",
            confirmation="APPROVE REPAIR any",
            expires_at=(datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat(),
            container_image="runtime",
            container_digest="d" * 64,
            checks=_repair_checks(),
        )


def test_repair_approval_revocation_and_stale_candidate_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    approval = _approval(tmp_path, monkeypatch)
    revoked = revoke_repair_approval(
        tmp_path,
        approval["approval_sha256"],
        revoked_by="maintainer",
        reason="stop before execution",
    )
    assert revoked["state"] == "REVOKED"
    with pytest.raises(RepairSandboxError, match="expired, revoked"):
        execute_approved_repair(tmp_path, tmp_path / approval["path"])

    other = tmp_path / "second"
    other.mkdir()
    approval2 = _approval(other, monkeypatch)
    (other / ".factory" / "candidate.diff").write_text("tampered\n", encoding="utf-8")
    result = execute_approved_repair(other, other / approval2["path"])
    assert result["status"] == "FAILED"
    assert result["error"]["code"] in {
        "REPAIR_CANDIDATE_STALE",
        "REPAIR_SCOPE_DRIFT",
    }, result
    saved_state = json.loads(
        (other / result["attempt_path"]).read_text(encoding="utf-8")
    )
    assert saved_state["status"] == "FAILED"
    assert saved_state["error"]["code"] == result["error"]["code"]
    assert result["primary_checkout_unchanged"] is True
    with pytest.raises(RepairSandboxError, match="already been consumed"):
        execute_approved_repair(other, other / approval2["path"])


def test_repair_execution_runs_only_in_digest_pinned_docker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = os.environ.get("FACTORY_REPAIR_TEST_IMAGE")
    digest = os.environ.get("FACTORY_REPAIR_TEST_DIGEST")
    if not image or not digest:
        pytest.skip(
            "set FACTORY_REPAIR_TEST_IMAGE and FACTORY_REPAIR_TEST_DIGEST for the Docker operator test"
        )
    scope_path, patch_path = _git_repair_case(tmp_path)
    candidate = inspect_repair_candidate(tmp_path, scope_path, patch_path)
    approval = create_repair_approval(
        tmp_path,
        scope_path,
        patch_path,
        approved_by="Docker integration test",
        confirmation="APPROVE REPAIR " + candidate["candidate_sha256"],
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        container_image=image,
        container_digest=digest,
        checks=_repair_checks(),
    )
    result = execute_approved_repair(tmp_path, tmp_path / approval["path"])
    assert result["status"] == "VERIFIED", result
    assert result["schema"] == "factory.repair_attempt.v1"
    assert result["cleanup_confirmed"] is True
    assert result["primary_checkout_unchanged"] is True
    assert [item["stage"] for item in result["checks"]] == [
        "baseline",
        "repaired",
        "repaired",
    ]


def test_repair_stop_requires_running_attempt(tmp_path: Path) -> None:
    with pytest.raises(RepairSandboxError, match="active attempt"):
        request_repair_stop(
            tmp_path,
            "e" * 64,
            requested_by="maintainer",
            reason="stop",
        )


def test_repair_git_worktree_disables_configured_checkout_hook(tmp_path: Path) -> None:
    _git_repair_case(tmp_path)
    hooks = tmp_path / "host-hooks"
    hooks.mkdir()
    marker = tmp_path / "hook-ran"
    hook = hooks / "post-checkout"
    hook.write_text(
        f"#!/bin/sh\nprintf ran > '{marker.as_posix()}'\n", encoding="utf-8"
    )
    os.chmod(hook, 0o700)
    if os.name != "nt":
        assert hook.stat().st_mode & 0o100
        subprocess.run(["sh", str(hook)], cwd=tmp_path, check=True)
        assert marker.is_file()
        marker.unlink()
    _git(tmp_path, "config", "core.hooksPath", str(hooks))
    target = tmp_path / ".factory" / "hook-checkout"
    result = repair_sandbox._git(
        tmp_path, ["worktree", "add", "--detach", str(target), "HEAD"]
    )
    assert result["ok"]
    assert not marker.exists()
    assert repair_sandbox._git(
        tmp_path, ["worktree", "remove", "--force", str(target)]
    )["ok"]


def test_repair_rejects_workspace_paths_that_can_inject_docker_mount_options(
    tmp_path: Path,
) -> None:
    unsafe = tmp_path / "comma,path"
    unsafe.mkdir()
    with pytest.raises(RepairSandboxError, match="Docker mount"):
        repair_sandbox._mount_safe_workspace(unsafe)


def test_repair_cli_approval_checks_are_bounded_and_execution_failure_exits_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    scope_path, patch_path = _git_repair_case(tmp_path)
    checks_path = _patch(tmp_path, ".factory/checks.json", json.dumps(_repair_checks()))
    monkeypatch.setattr(
        "factoryline.repair_sandbox.create_repair_approval",
        lambda *_args, checks, **_kwargs: {
            "status": "APPROVED_NOT_EXECUTED",
            "checks": checks,
        },
    )
    result = main(
        [
            "repair",
            "approve",
            "--root",
            str(tmp_path),
            "--scope",
            str(scope_path),
            "--patch",
            str(patch_path),
            "--approved-by",
            "operator",
            "--confirmation",
            "APPROVE REPAIR candidate",
            "--expires-at",
            "2030-01-01T00:00:00+00:00",
            "--container-image",
            "runtime",
            "--container-digest",
            "e" * 64,
            "--checks",
            str(checks_path),
            "--json",
        ]
    )
    assert result == 0
    assert json.loads(capsys.readouterr().out)["checks"] == _repair_checks()

    escaping = main(
        [
            "repair",
            "approve",
            "--root",
            str(tmp_path),
            "--scope",
            str(scope_path),
            "--patch",
            str(patch_path),
            "--approved-by",
            "operator",
            "--confirmation",
            "APPROVE REPAIR candidate",
            "--expires-at",
            "2030-01-01T00:00:00+00:00",
            "--container-image",
            "runtime",
            "--container-digest",
            "e" * 64,
            "--checks",
            "../outside.json",
            "--json",
        ]
    )
    assert escaping == 2
    assert "REPAIR_CHECKS_INPUT_INVALID" in capsys.readouterr().err


def test_repair_cli_run_nonverified_attempt_exits_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "factoryline.repair_sandbox.execute_approved_repair",
        lambda *_args: {"status": "FAILED"},
    )
    assert (
        main(
            [
                "repair",
                "run",
                "--root",
                str(tmp_path),
                "--approval",
                ".factory/approval.json",
                "--json",
            ]
        )
        == 2
    )


@pytest.mark.parametrize("as_json", [True, False])
def test_repair_cli_errors_do_not_disclose_absolute_host_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    as_json: bool,
) -> None:
    windows_path = r"C:\Users\private\workspace\secret.py"
    posix_path = "/home/private/workspace/secret.py"

    def fail(*_args):
        raise RepairSandboxError(
            "REPAIR_TEST_FAILURE", f"failed in {windows_path} and {posix_path}"
        )

    monkeypatch.setattr("factoryline.repair_sandbox.execute_approved_repair", fail)
    argv = [
        "repair",
        "run",
        "--root",
        str(tmp_path),
        "--approval",
        ".factory/approval.json",
    ]
    if as_json:
        argv.append("--json")
    assert main(argv) == 2
    output = capsys.readouterr().err
    assert windows_path not in output
    assert posix_path not in output
    if as_json:
        assert json.loads(output)["code"] == "REPAIR_TEST_FAILURE"
