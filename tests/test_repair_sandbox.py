from __future__ import annotations

import hashlib
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
    execute_workflow_approved_repair,
    repair_dispatch_evidence,
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


def test_inventory_excludes_only_untracked_generated_factory_state(
    tmp_path: Path,
) -> None:
    from factoryline.deep_audit_io import inventory_candidate

    scope_path, patch_path = _git_repair_case(tmp_path)
    approval_path = tmp_path / ".factory" / "repair-approvals" / "approval.json"
    approval_path.parent.mkdir(parents=True)
    approval_path.write_text("{}\n", encoding="utf-8")
    attempt_path = tmp_path / ".factory" / "repair-attempts" / "attempt" / "state.json"
    attempt_path.parent.mkdir(parents=True)
    attempt_path.write_text("{}\n", encoding="utf-8")
    ignored_build = tmp_path / "build" / "cache.bin"
    ignored_build.parent.mkdir(parents=True)
    ignored_build.write_bytes(b"generated build input")
    with (tmp_path / ".gitignore").open("a", encoding="utf-8") as stream:
        stream.write("build/\n")
    _git(tmp_path, "add", ".gitignore")
    _git(tmp_path, "commit", "--quiet", "-m", "ignore build output")

    inventory = inventory_candidate(tmp_path)
    codes_and_paths = {(gap["code"], gap["path"]) for gap in inventory["gaps"]}
    assert not any(
        code == "IGNORED_INPUT_SCOPE" and path.startswith(".factory/")
        for code, path in codes_and_paths
    )
    assert ("IGNORED_INPUT_SCOPE", "build/cache.bin") in codes_and_paths
    assert scope_path.relative_to(tmp_path).as_posix() not in {
        item["path"] for item in inventory["files"]
    }
    assert patch_path.relative_to(tmp_path).as_posix() not in {
        item["path"] for item in inventory["files"]
    }

    collision = tmp_path / ".factory" / "scopes" / "collision.py"
    collision.write_text("VALUE = 1\n", encoding="utf-8")
    _git(tmp_path, "add", "-f", collision.relative_to(tmp_path).as_posix())
    _git(tmp_path, "commit", "--quiet", "-m", "track generated-path collision")
    tracked_collision = inventory_candidate(tmp_path)
    assert any(
        gap["code"] == "E_RESERVED_SOURCE"
        and gap["path"] == ".factory/scopes/collision.py"
        for gap in tracked_collision["gaps"]
    )


def test_deep_lane_normalization_failure_keeps_native_execution_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from factoryline import deep_audit, deep_audit_sarif
    from factoryline.deep_audit_io import digest
    from factoryline.runtime_audit_common import RuntimeAuditError

    raw = b'{"deliberately":"not normalized"}'
    facts = {
        "exit_code": 0,
        "cancelled": False,
        "timed_out": False,
        "output_limit_exceeded": False,
        "cleanup_confirmed": True,
        "stdout_bytes": len(raw),
        "stderr_bytes": 0,
    }
    lane = {
        "id": "native-test",
        "engine": "test-engine",
        "image": "test-worker@sha256:" + "a" * 64,
        "ruleset_sha256": "b" * 64,
        "timeout_seconds": 30,
    }
    state = {"run_id": "a" * 32, "manifest_sha256": "c" * 64}
    inventory = {"candidate_sha256": "d" * 64}

    def run_command(_argv, _cwd, _timeout, _scratch, *, stdout_path, cancelled):
        stdout_path.write_bytes(raw)
        assert not cancelled.is_set()
        return facts

    def reject_bundle(*_args, **_kwargs):
        raise RuntimeAuditError("E_RULE_ACCOUNTING", "details must not escape")

    monkeypatch.setattr(deep_audit, "_docker_base", lambda: "docker")
    monkeypatch.setattr(deep_audit, "_docker_preflight", lambda *_args: None)
    monkeypatch.setattr(deep_audit, "_container_argv", lambda *_args: ["docker", "run"])
    monkeypatch.setattr(deep_audit, "_container_cleanup", lambda *_args: True)
    monkeypatch.setattr(deep_audit, "_monitor_lane", lambda *_args: None)
    monkeypatch.setattr(
        "factoryline.runtime_audit_process.run_bounded_command", run_command
    )
    monkeypatch.setattr(deep_audit_sarif, "normalize_execution_bundle", reject_bundle)

    result = deep_audit._execute_lane(
        tmp_path,
        tmp_path / "run",
        state,
        tmp_path,
        lane,
        inventory,
        {"obligations": []},
        None,
    )

    native = result["native_execution"]
    assert result["state"] == "INCOMPLETE"
    assert result["gaps"] == ["E_RULE_ACCOUNTING"]
    assert native["completion"] == "COMMAND_COMPLETED_NORMALIZATION_FAILED"
    assert native["diagnostic_code"] == "E_RULE_ACCOUNTING"
    assert native["command_sha256"] == digest(["docker", "run"])
    assert native["image_sha256"] == digest(lane["image"])
    assert native["source_candidate_sha256"] == inventory["candidate_sha256"]
    assert native["manifest_sha256"] == state["manifest_sha256"]
    assert native["config_sha256"] == lane["ruleset_sha256"]
    assert native["output_sha256"] == hashlib.sha256(raw).hexdigest()
    assert native["cleanup_confirmed"] is True
    assert result["execution"] is facts
    assert "details must not escape" not in json.dumps(result)


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


def _workflow_repair_case(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    decision: str = "approved",
    mutate_evidence: bool = False,
):
    from factoryline.control_plane import EvidenceStore, Principal

    approval = _approval(root, monkeypatch)
    approval_path = root / approval["path"]
    requester = Principal("repair-operator", "tenant-a", ("operator",))
    approver = Principal("reviewer", "tenant-a", ("approver",))
    binding = repair_dispatch_evidence(
        root,
        approval_path,
        tenant_id="tenant-a",
        requester=requester.subject,
    )
    if mutate_evidence:
        binding["patch_sha256"] = "0" * 64
    store = EvidenceStore(root / ".factory" / "workflow-approvals.sqlite3")
    evidence = store.put(
        requester,
        {
            "schema": "factory.workflow-approval.v1",
            "tenant_id": "tenant-a",
            "expires_at": (
                datetime.now(timezone.utc) + timedelta(minutes=2)
            ).isoformat(),
            "phase_evidence": binding,
        },
    )
    request = store.request_approval(
        requester, "tenant-a", evidence["evidence_id"], "Authorize exact repair"
    )
    if decision != "pending":
        store.decide_approval(
            approver,
            "tenant-a",
            request["approval_id"],
            decision,
            "Independent review",
        )
    identities = {requester.subject: requester, approver.subject: approver}

    def resolve(subject, tenant):
        identity = identities.get(subject)
        return (
            identity if identity is not None and identity.tenant_id == tenant else None
        )

    return approval, approval_path, requester, request, store, identities, resolve


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


def test_workflow_approved_repair_dispatch_binds_exact_receipt_and_current_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    approval, approval_path, requester, request, store, _, resolve = (
        _workflow_repair_case(tmp_path, monkeypatch)
    )
    calls = []

    def execute(
        root,
        path,
        *,
        expected_approval_sha256,
        expected_approval_file_sha256,
    ):
        calls.append(
            (root, path, expected_approval_sha256, expected_approval_file_sha256)
        )
        return {
            "status": "VERIFYING",
            "approval_sha256": expected_approval_sha256,
            "event_sequence": 1,
            "event_sha256": "e" * 64,
        }

    def journal(root, expected_approval_sha256):
        return {
            "state": {
                "approval_sha256": expected_approval_sha256,
                "status": "VERIFYING",
                "event_sequence": 1,
                "origin_audit": None,
                "candidate_before_sha256": None,
            },
            "event_sha256": "e" * 64,
        }

    monkeypatch.setattr(repair_sandbox, "execute_approved_repair", execute)
    monkeypatch.setattr(repair_sandbox, "verify_repair_attempt_journal", journal)
    result = execute_workflow_approved_repair(
        tmp_path,
        approval_path,
        principal=requester,
        tenant_id="tenant-a",
        workflow_approval_id=request["approval_id"],
        evidence_store=store,
        resolve_principal=resolve,
    )

    assert result["approval_sha256"] == Path(approval["path"]).stem
    assert len(calls) == 1
    assert calls[0][2] == result["approval_sha256"]
    assert calls[0][3] == hashlib.sha256(approval_path.read_bytes()).hexdigest()
    binding = store.get(requester, "tenant-a", request["evidence_id"])["payload"][
        "phase_evidence"
    ]
    assert binding["repair_approval_sha256"] == result["approval_sha256"]
    assert binding["tool_contract_sha256"]
    assert binding["candidate_sha256"]
    assert "approved_by" not in binding


@pytest.mark.parametrize("decision", ["pending", "rejected"])
def test_workflow_approved_repair_dispatch_rejects_nonapproved_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, decision: str
) -> None:
    from factoryline.control_plane import ControlPlaneError

    _, approval_path, requester, request, store, _, resolve = _workflow_repair_case(
        tmp_path, monkeypatch, decision=decision
    )
    with pytest.raises(ControlPlaneError) as error:
        execute_workflow_approved_repair(
            tmp_path,
            approval_path,
            principal=requester,
            tenant_id="tenant-a",
            workflow_approval_id=request["approval_id"],
            evidence_store=store,
            resolve_principal=resolve,
        )
    assert error.value.code == "E_APPROVAL_REQUIRED"
    assert not (tmp_path / ".factory" / "repair-attempts").exists()


def test_workflow_approved_repair_dispatch_rechecks_approver_role(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from factoryline.control_plane import ControlPlaneError, Principal

    _, approval_path, requester, request, store, identities, resolve = (
        _workflow_repair_case(tmp_path, monkeypatch)
    )
    identities["reviewer"] = Principal("reviewer", "tenant-a", ("viewer",))
    with pytest.raises(ControlPlaneError) as error:
        execute_workflow_approved_repair(
            tmp_path,
            approval_path,
            principal=requester,
            tenant_id="tenant-a",
            workflow_approval_id=request["approval_id"],
            evidence_store=store,
            resolve_principal=resolve,
        )
    assert error.value.code == "E_ACTION_DENIED"
    assert not (tmp_path / ".factory" / "repair-attempts").exists()


def test_workflow_approved_repair_dispatch_rejects_wrong_tenant_and_drifted_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from factoryline.control_plane import ControlPlaneError, Principal

    _, approval_path, requester, request, store, identities, resolve = (
        _workflow_repair_case(tmp_path, monkeypatch)
    )
    other_tenant = Principal("repair-operator", "tenant-b", ("operator",))
    identities[requester.subject] = other_tenant
    with pytest.raises(ControlPlaneError) as tenant_error:
        execute_workflow_approved_repair(
            tmp_path,
            approval_path,
            principal=other_tenant,
            tenant_id="tenant-b",
            workflow_approval_id=request["approval_id"],
            evidence_store=store,
            resolve_principal=resolve,
        )
    assert tenant_error.value.code == "E_NOT_FOUND"

    second = tmp_path / "second"
    second.mkdir()
    (
        _,
        second_path,
        second_requester,
        second_request,
        second_store,
        _,
        second_resolve,
    ) = _workflow_repair_case(second, monkeypatch, mutate_evidence=True)
    with pytest.raises(ControlPlaneError) as drift_error:
        execute_workflow_approved_repair(
            second,
            second_path,
            principal=second_requester,
            tenant_id="tenant-a",
            workflow_approval_id=second_request["approval_id"],
            evidence_store=second_store,
            resolve_principal=second_resolve,
        )
    assert drift_error.value.code == "E_APPROVAL_EVIDENCE"
    assert not (second / ".factory" / "repair-attempts").exists()


def test_workflow_approved_repair_file_swap_fails_before_attempt_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    approval, approval_path, requester, request, store, _, resolve = (
        _workflow_repair_case(tmp_path, monkeypatch)
    )
    original = store.workflow_approval_verifier

    def swap_after_verification(*args, **kwargs):
        verifier = original(*args, **kwargs)

        def verify(expected):
            result = verifier(expected)
            approval_path.write_bytes(approval_path.read_bytes() + b" \n")
            return result

        return verify

    monkeypatch.setattr(store, "workflow_approval_verifier", swap_after_verification)
    with pytest.raises(RepairSandboxError) as error:
        execute_workflow_approved_repair(
            tmp_path,
            approval_path,
            principal=requester,
            tenant_id="tenant-a",
            workflow_approval_id=request["approval_id"],
            evidence_store=store,
            resolve_principal=resolve,
        )
    assert error.value.code == "REPAIR_APPROVAL_CHANGED"
    assert not (
        tmp_path / ".factory" / "repair-attempts" / Path(approval["path"]).stem
    ).exists()


def test_workflow_approved_repair_re_resolves_requester_role_before_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from factoryline.control_plane import ControlPlaneError, Principal

    _, approval_path, requester, request, store, identities, resolve = (
        _workflow_repair_case(tmp_path, monkeypatch)
    )
    identities[requester.subject] = Principal(
        requester.subject, "tenant-a", ("viewer",)
    )
    with pytest.raises(ControlPlaneError) as error:
        execute_workflow_approved_repair(
            tmp_path,
            approval_path,
            principal=requester,
            tenant_id="tenant-a",
            workflow_approval_id=request["approval_id"],
            evidence_store=store,
            resolve_principal=resolve,
        )
    assert error.value.code == "E_ACTION_DENIED"
    assert not (tmp_path / ".factory" / "repair-attempts").exists()


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
    source_candidate = "a" * 64
    source_run = {
        "observed_state": "INCOMPLETE",
        "candidate_sha256": source_candidate,
        "manifest_sha256": "b" * 64,
        "event_sha256": "c" * 64,
        "sequence": 3,
    }
    monkeypatch.setattr(
        "factoryline.deep_audit.deep_run_status", lambda _root, _run_id: source_run
    )
    monkeypatch.setattr(
        "factoryline.deep_audit_io.inventory_candidate",
        lambda _root: {"candidate_sha256": source_candidate, "gaps": []},
    )
    kwargs["audit_run_id"] = "d" * 32
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
    assert (
        saved["confirmation_sha256"]
        == hashlib.sha256(kwargs["confirmation"].encode("utf-8")).hexdigest()
    )
    assert saved["origin_audit"] == {
        "run_id": "d" * 32,
        "candidate_sha256": source_candidate,
        "manifest_sha256": "b" * 64,
        "event_sha256": "c" * 64,
        "sequence": 3,
    }
    assert repair_sandbox._verify_approval(saved) == approval["approval_sha256"]


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


def test_host_bound_stale_repair_rejects_before_attempt_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    approval = _approval(tmp_path, monkeypatch)
    approval_path = tmp_path / approval["path"]
    raw_sha = hashlib.sha256(approval_path.read_bytes()).hexdigest()
    (tmp_path / ".factory" / "candidate.diff").write_text(
        "tampered\n", encoding="utf-8"
    )
    with pytest.raises(RepairSandboxError) as error:
        execute_approved_repair(
            tmp_path,
            approval_path,
            expected_approval_sha256=approval["approval_sha256"],
            expected_approval_file_sha256=raw_sha,
        )
    assert error.value.code == "REPAIR_CANDIDATE_STALE"
    assert not (tmp_path / ".factory" / "repair-attempts").exists()


def test_repair_attempt_journal_detects_reorder_and_missing_events(
    tmp_path: Path,
) -> None:
    approval_sha = "a" * 64
    directory = tmp_path / ".factory" / "repair-attempts" / approval_sha
    repair_sandbox._begin_attempt(directory, approval_sha)
    state = repair_sandbox._read_attempt_state(directory)
    state["phase"] = "BASELINE"
    repair_sandbox._persist_attempt(directory, state)
    observed = repair_sandbox.verify_repair_attempt_journal(tmp_path, approval_sha)
    assert observed["state"]["event_sequence"] == 2
    assert observed["event_sha256"] == observed["state"]["event_sha256"]

    first = directory / "event-00001.json"
    saved = first.read_text(encoding="utf-8")
    tampered = json.loads(saved)
    tampered["sequence"] = 2
    first.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(RepairSandboxError, match="event chain"):
        repair_sandbox.verify_repair_attempt_journal(tmp_path, approval_sha)

    first.write_text(saved, encoding="utf-8")
    (directory / "event-00002.json").unlink()
    with pytest.raises((RepairSandboxError, FileNotFoundError)):
        repair_sandbox.verify_repair_attempt_journal(tmp_path, approval_sha)


def _recovery_attempt_case(root, monkeypatch, *, terminal=True):
    approval = _approval(root, monkeypatch)
    approval_path = root / approval["path"]
    binding = repair_dispatch_evidence(
        root, approval_path, tenant_id="tenant-a", requester="repair-operator"
    )
    attempt = root / ".factory" / "repair-attempts" / approval["approval_sha256"]
    state = repair_sandbox._begin_attempt(attempt, approval["approval_sha256"])
    approved = json.loads(approval_path.read_text(encoding="utf-8"))
    patch = (root / approved["patch_path"]).read_bytes()
    (attempt / "candidate.patch").write_bytes(patch)
    if terminal:
        _record_recovery_checks(attempt, state, approved["tool_contract"]["checks"])
        state.update(
            status="VERIFIED",
            phase="VERIFIED",
            cleanup_confirmed=True,
            primary_checkout_unchanged=True,
        )
        repair_sandbox._persist_attempt(attempt, state)
    return approval_path, binding, attempt, state


def _record_recovery_checks(attempt, state, checks):
    for stage in ("baseline", "repaired"):
        state["phase"] = "BASELINE" if stage == "baseline" else "REPAIRED_CHECKS"
        repair_sandbox._persist_attempt(attempt, state)
        for check in checks:
            failing = stage == "baseline" or check["kind"] == "negative"
            output = check["failure"]["signature"].encode() if failing else b"passed"
            outcome = {
                "result": {
                    "stdout": output,
                    "stderr": b"",
                    "exit_code": check["failure"]["exit_code"] if failing else 0,
                    "cleanup_confirmed": True,
                    "reason": None,
                },
                "container_cleanup_confirmed": True,
            }
            assert repair_sandbox._record_check(
                attempt, state, check, stage, outcome, True
            )


def test_host_recovery_verifies_real_repair_approval_and_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from factoryline.hosted_api import _recovery_attempt_evidence

    approval_path, binding, _attempt, state = _recovery_attempt_case(
        tmp_path, monkeypatch
    )
    attempt_sha, facts = _recovery_attempt_evidence(tmp_path, approval_path, binding)
    assert attempt_sha == state["event_sha256"]
    assert facts["approval_sha256"] == binding["repair_approval_sha256"]
    assert facts["approval_file_sha256"] == binding["repair_approval_file_sha256"]
    assert facts["event_sequence"] == state["event_sequence"]


def test_host_recovery_rejects_running_and_semantically_tampered_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from factoryline.hosted_api import _recovery_attempt_evidence
    from factoryline.pr_assurance import PRAssuranceError

    approval_path, binding, _attempt, _state = _recovery_attempt_case(
        tmp_path, monkeypatch, terminal=False
    )
    with pytest.raises(PRAssuranceError) as running:
        _recovery_attempt_evidence(tmp_path, approval_path, binding)
    assert running.value.code == "E_REPAIR_RECOVERY_INCOMPLETE"

    other = tmp_path / "other"
    other.mkdir()
    approval_path, binding, attempt, state = _recovery_attempt_case(other, monkeypatch)
    state["checks"][0]["exit_code"] = 0
    repair_sandbox._persist_attempt(attempt, state)
    with pytest.raises(PRAssuranceError) as tampered:
        _recovery_attempt_evidence(other, approval_path, binding)
    assert tampered.value.code == "E_REPAIR_CHECK_EVIDENCE"


def test_repair_check_receipt_states_expected_result(tmp_path: Path) -> None:
    approval_sha = "b" * 64
    directory = tmp_path / ".factory" / "repair-attempts" / approval_sha
    state = repair_sandbox._begin_attempt(directory, approval_sha)
    check = _repair_checks()[0]
    outcome = {
        "result": {
            "stdout": b"passed",
            "stderr": b"",
            "exit_code": 0,
            "cleanup_confirmed": True,
            "reason": None,
        },
        "container_cleanup_confirmed": True,
    }
    assert repair_sandbox._record_check(
        directory, state, check, "repaired", outcome, True
    )
    assert state["checks"][-1]["result"] == "PASS"
    outcome["result"]["exit_code"] = 1
    assert not repair_sandbox._record_check(
        directory, state, check, "repaired", outcome, True
    )
    assert state["checks"][-1]["result"] == "FAIL"


def _write_lineage_run(
    root: Path,
    run_id: str,
    parent_run: str | None = None,
    request_path: str | None = None,
) -> None:
    from factoryline.deep_audit import _event
    from factoryline.deep_audit_io import digest, run_directory, write_run_json
    from factoryline.runtime_audit_common import sha256_bytes

    candidate = "c" * 64
    manifest_sha = "d" * 64
    plan = {
        "schema": "factory.deep-execution.v1",
        "candidate_sha256": candidate,
        "lanes": [
            {"id": "static-python", "coverage": "coverage.json", "rule_ids": ["R1"]}
        ],
    }
    directory = run_directory(root, run_id, create=True)
    request_reference = None
    if request_path is not None:
        raw_request = (root / request_path).read_bytes()
        request_reference = {
            "path": request_path,
            "sha256": sha256_bytes(raw_request),
            "bytes": len(raw_request),
        }
    write_run_json(directory, "manifest.json", plan)
    write_run_json(
        directory, "inventory.json", {"candidate_sha256": candidate, "files": []}
    )
    coverage = {"schema": "factory.deep-coverage.v1", "complete": False}
    write_run_json(
        directory,
        "bundle-static-python.json",
        {"artifacts": {"coverage.json": coverage}},
    )
    state = {
        "schema": "factory.deep-run.v1",
        "run_id": run_id,
        "state": "RUNNING",
        "candidate_sha256": candidate,
        "manifest_sha256": manifest_sha,
        "manifest_content_sha256": digest(plan),
        "authorization_sha256": "e" * 64,
        "request_path": request_reference["path"] if request_reference else None,
        "request_sha256": request_reference["sha256"] if request_reference else None,
        "request_bytes": request_reference["bytes"] if request_reference else None,
        "parent_run": parent_run,
        "lanes": [
            {
                "lane_id": "static-python",
                "state": "INCOMPLETE",
                "gaps": ["RULE_ACCOUNTING_MISSING"],
                "findings": [],
                "report_sha256": "f" * 64,
                "coverage_sha256": digest(coverage),
                "challenge_sha256": "0" * 64,
                "rule_accounting_sha256": None,
            }
        ],
        "gaps": [],
        "analysis_complete": False,
        "authority": "none",
        "release_approval": False,
    }
    _event(
        directory,
        state,
        "run_started",
        {"candidate_sha256": candidate, "request": request_reference},
    )
    state["state"] = "PAUSED"
    _event(directory, state, "run_paused", {"analysis_complete": False})
    write_run_json(directory, "state.json", state)


def test_deep_lineage_marks_missing_rules_and_rejects_resume_reorder(
    tmp_path: Path,
) -> None:
    from factoryline.deep_audit import (
        build_deep_audit_lineage,
        verify_deep_audit_lineage,
        write_deep_audit_lineage,
    )

    first, resumed = "1" * 32, "2" * 32
    _write_lineage_run(tmp_path, first)
    _write_lineage_run(tmp_path, resumed, first)
    ordered = build_deep_audit_lineage(tmp_path, [first, resumed])
    assert "RULE_ACCOUNTING_MISSING:static-python" in ordered["gaps"]
    assert ordered["state"] == "INCOMPLETE"
    assert verify_deep_audit_lineage(ordered)["valid"]
    assert ordered["authority"] == {
        "execution": False,
        "approval": False,
        "merge": False,
        "deployment": False,
        "signing": False,
    }
    assert ordered["authentication"] == "UNSIGNED_INTEGRITY_ONLY"
    assert "stdout" not in json.dumps(ordered)
    assert any(event["kind"] == "run_paused" for event in ordered["runs"][0]["events"])
    written = write_deep_audit_lineage(tmp_path, [first, resumed])
    assert (tmp_path / written["receipt_path"]).is_file()
    tampered = dict(ordered)
    tampered["chain"] = list(ordered["chain"])
    tampered["chain"][0] = {**tampered["chain"][0], "reference_sha256": "0" * 64}
    assert not verify_deep_audit_lineage(tampered)["valid"]

    reversed_lineage = build_deep_audit_lineage(tmp_path, [resumed, first])
    assert "RESUME_PARENT_NOT_IN_ORDERED_LINEAGE" in reversed_lineage["gaps"]


def test_lineage_complete_state_rejects_empty_or_unbound_rule_matrices(
    tmp_path: Path,
) -> None:
    from factoryline.deep_audit import (
        _lineage_chain,
        _lineage_lane_complete,
        _lineage_references,
        build_deep_audit_lineage,
        verify_deep_audit_lineage,
    )
    from factoryline.deep_audit_io import digest

    run_id = "3" * 32
    rerun_id = "4" * 32
    _write_lineage_run(tmp_path, run_id, request_path=None)
    _write_lineage_run(tmp_path, rerun_id, parent_run=run_id, request_path=None)
    receipt = build_deep_audit_lineage(tmp_path, [run_id, rerun_id])
    families = [
        ("codeql", "static"),
        ("syft", "dependencies"),
        ("osv", "dependencies"),
        ("gitleaks", "secrets"),
        ("trivy", "configuration"),
        ("runtime", "runtime"),
        ("atheris", "fuzz"),
    ]

    def complete_lane(engine: str, family: str) -> dict:
        source = {
            "path": "src.py",
            "source_sha256": "a" * 64,
            "disposition": "executed",
            "evidence_sha256": "b" * 64,
        }
        accounting = {
            "schema": "factory.deep-rule-accounting.v1",
            "ruleset_sha256": "c" * 64,
            "invocation_sha256": "d" * 64,
            "native_report_sha256": "e" * 64,
            "rules": [{"rule_id": "R1", "sources": [source]}],
        }
        accounting["accounting_sha256"] = digest(accounting)
        return {
            "lane_id": engine,
            "engine": engine,
            "family": family,
            "state": "OBSERVED",
            "rule_accounting_sha256": accounting["accounting_sha256"],
            "expected_rule_ids": ["R1"],
            "source_paths": ["src.py"],
            "rule_accounting": accounting,
        }

    def reseal(candidate: dict) -> dict:
        candidate["gaps"] = []
        candidate["state"] = "LINEAGE_BOUND_UNAUTHENTICATED"
        for run in candidate["runs"]:
            run["request_state"] = "BOUND"
            run["analysis_complete"] = True
            if not run["lanes"] or run["lanes"][0].get("engine") is None:
                run["lanes"] = [complete_lane(*item) for item in families]
        candidate["repair"] = {
            "approval_sha256": "f" * 64,
            "attempt_status": "VERIFIED",
            "cleanup_confirmed": True,
            "primary_checkout_unchanged": True,
            "candidate_after_sha256": "1" * 64,
            "rerun_candidate_sha256": "1" * 64,
            "events": [],
        }
        candidate["chain"], candidate["chain_head"] = _lineage_chain(
            _lineage_references(candidate["runs"], candidate["repair"])
        )
        candidate["lineage_sha256"] = digest(
            {key: value for key, value in candidate.items() if key != "lineage_sha256"}
        )
        return candidate

    valid_claim = reseal(receipt)
    assert all(
        _lineage_lane_complete(lane) for lane in valid_claim["runs"][0]["lanes"]
    ), [
        lane
        for lane in valid_claim["runs"][0]["lanes"]
        if not _lineage_lane_complete(lane)
    ]
    assert verify_deep_audit_lineage(valid_claim)["valid"], verify_deep_audit_lineage(
        valid_claim
    )

    mutations = []
    missing_family = json.loads(json.dumps(valid_claim))
    missing_family["runs"][0]["lanes"].pop()
    mutations.append(missing_family)
    empty_rules = json.loads(json.dumps(valid_claim))
    empty_rules["runs"][0]["lanes"][0]["rule_accounting"]["rules"] = []
    mutations.append(empty_rules)
    empty_sources = json.loads(json.dumps(valid_claim))
    empty_sources["runs"][0]["lanes"][0]["rule_accounting"]["rules"][0]["sources"] = []
    mutations.append(empty_sources)
    wrong_ledger_hash = json.loads(json.dumps(valid_claim))
    wrong_ledger_hash["runs"][0]["lanes"][0]["rule_accounting_sha256"] = "0" * 64
    mutations.append(wrong_ledger_hash)
    malformed_rule = json.loads(json.dumps(valid_claim))
    malformed_rule["runs"][0]["lanes"][0]["rule_accounting"]["rules"][0]["rule_id"] = []
    mutations.append(malformed_rule)
    for index, changed in enumerate(mutations):
        reseal(changed)
        assert not verify_deep_audit_lineage(changed)["valid"], index


def test_deep_lineage_binds_exact_request_file_and_detects_drift(
    tmp_path: Path,
) -> None:
    from factoryline.deep_audit import build_deep_audit_lineage

    request = tmp_path / ".factory" / "deep-runs" / "requests" / "operator-request.txt"
    request.parent.mkdir(parents=True)
    request.write_text(
        "Run a native audit on the explicitly selected operator test repository.",
        encoding="utf-8",
    )
    run_id = "a" * 32
    relative = request.relative_to(tmp_path).as_posix()
    _write_lineage_run(tmp_path, run_id, request_path=relative)
    lineage = build_deep_audit_lineage(tmp_path, [run_id])
    assert lineage["runs"][0]["request_state"] == "BOUND"
    assert lineage["runs"][0]["request_path"] == relative
    assert "REQUEST_ARTIFACT_MISMATCH" not in lineage["gaps"]

    request.write_text("changed after the run", encoding="utf-8")
    stale = build_deep_audit_lineage(tmp_path, [run_id])
    assert "REQUEST_ARTIFACT_MISMATCH" in stale["gaps"]


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
            "--checks-sha256",
            hashlib.sha256(checks_path.read_bytes()).hexdigest(),
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


def test_repair_checks_bind_exact_reviewed_bytes(tmp_path: Path) -> None:
    from factoryline.cli_ide import _load_repair_checks

    path = _patch(tmp_path, "checks.json", json.dumps(_repair_checks()))
    reviewed_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    assert _load_repair_checks(
        tmp_path, "checks.json", repair_sandbox, reviewed_sha
    ) == (_repair_checks())
    path.write_text("[]", encoding="utf-8")
    for invalid_sha in (reviewed_sha, "", "not-a-hash", "A" * 64):
        with pytest.raises(RepairSandboxError, match="bounded workspace-contained"):
            _load_repair_checks(tmp_path, "checks.json", repair_sandbox, invalid_sha)
    assert _load_repair_checks(tmp_path, "checks.json", repair_sandbox) == []


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
