from __future__ import annotations

import base64
from contextlib import contextmanager
from io import BytesIO
import json
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from factoryline.control_plane import ControlPlaneError, Principal
from factoryline.hosted_api import (
    HostedPRAssuranceAPI,
    HostedConfig,
    HostedPRAssuranceService,
    _trusted_repair_path,
    _verify_recovery_check_logs,
    _require_terminal_recovery_state,
    create_hosted_app,
)
from factoryline.hosted_control import (
    CONTROL_SCHEMA_SQL,
    EnvSecretResolver,
    PostgresControlStore,
    TenantIdentityConfig,
    TenantIdentityVerifier,
    initialize_control_schema,
    issue_installation_state,
)
from factoryline.hosted_identity import HttpxTransport
from factoryline.pr_assurance import PRAssuranceError


def test_console_is_responsive_read_only_and_handles_all_runtime_states():
    source = (
        Path(__file__).resolve().parents[1] / "factoryline" / "hosted_console.html"
    ).read_text(encoding="utf-8")
    lowered = source.lower()
    assert '<meta name="viewport"' in source
    assert "@media (max-width: 560px)" in source
    assert 'id="empty"' in source
    assert 'id="loading"' in source
    assert 'id="error"' in source
    assert 'id="overview"' in source
    assert "CONTROL_CONSOLE_READ_ONLY" in source
    assert "method:" not in source
    assert all(
        term not in source
        for term in ["localStorage", "sessionStorage", "document.cookie"]
    )
    assert all(
        term not in lowered
        for term in ['type="file"', "deploy button", "release button"]
    )


def test_console_uses_text_content_for_remote_values_and_clears_token_input():
    source = (
        Path(__file__).resolve().parents[1] / "factoryline" / "hosted_console.html"
    ).read_text(encoding="utf-8")
    assert ".innerHTML" not in source
    assert 'document.getElementById("token").value = ""' in source
    assert "encodeURIComponent(tenant)" in source
    assert "Authorization: `Bearer ${token}`" in source
    assert "fetch(`/v1/admin/tenants/${encodeURIComponent(tenant)}/overview`" in source


def test_console_asset_is_declared_as_package_data():
    project = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    assert '"hosted_console.html"' in project


class Response:
    def __init__(self, value):
        self.status_code = 200
        self.value = value

    def json(self):
        return self.value


class Transport:
    def __init__(self, value):
        self.value = value

    def request(self, method, url, *, headers=None, json=None):
        assert method == "GET" and url == "https://id.acme.test/jwks"
        return Response(self.value)


class IdentityStore:
    def identity_config(self, tenant_id):
        assert tenant_id == "acme"
        return TenantIdentityConfig(
            "acme", "https://id.acme.test", "code-factory", "https://id.acme.test/jwks"
        )

    def role_map(self, tenant_id):
        assert tenant_id == "acme"
        return {"release": "approver"}


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _identity():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "key-1",
                "use": "sig",
                "alg": "RS256",
                "n": _b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
                "e": _b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
            }
        ]
    }
    return private, jwks


def _token(private, *, tenant_id="acme"):
    header = _b64(b'{"alg":"RS256","kid":"key-1"}')
    payload = _b64(
        json.dumps(
            {
                "iss": "https://id.acme.test",
                "aud": "code-factory",
                "sub": "reviewer",
                "tenant_id": tenant_id,
                "groups": ["release"],
                "jti": "control-jti",
                "nbf": 1_799_999_900,
                "exp": 1_900_000_300,
            },
            separators=(",", ":"),
        ).encode()
    )
    signature = private.sign(
        f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256()
    )
    return f"{header}.{payload}.{_b64(signature)}"


def test_control_schema_forces_rls_and_stores_references_and_state_digests_only():
    assert CONTROL_SCHEMA_SQL.count("FORCE ROW LEVEL SECURITY") == 8
    assert CONTROL_SCHEMA_SQL.count("current_setting('factory.tenant_id', true)") == 16
    assert "factory_hosted_repairs" in CONTROL_SCHEMA_SQL
    assert "PRIMARY KEY (tenant_id, repair_id)" in CONTROL_SCHEMA_SQL
    assert (
        "status IN ('registered','executing','completed','failed')"
        in CONTROL_SCHEMA_SQL
    )
    assert "ON CONFLICT (tenant_id,repair_id) DO NOTHING" not in CONTROL_SCHEMA_SQL
    assert "state_sha256 TEXT PRIMARY KEY" in CONTROL_SCHEMA_SQL
    assert "secret_ref TEXT NOT NULL" in CONTROL_SCHEMA_SQL
    lowered = CONTROL_SCHEMA_SQL.lower()
    assert (
        "secret_value" not in lowered
        and "bearer_token" not in lowered
        and "private_key" not in lowered
    )

    class Initializable:
        initialized = False

        def initialize(self):
            self.initialized = True

    wrapped = Initializable()
    initialize_control_schema(wrapped)
    assert wrapped.initialized is True


class _HostedRepairRouteService:
    def __init__(self):
        self.calls = []

    def execute_registered_repair(self, token, tenant, repair_id, body):
        self.calls.append((token, tenant, repair_id, body))
        return {
            "schema": "factory.hosted.repair.v1",
            "repair_id": repair_id,
            "status": "completed",
        }

    def reconcile_registered_repair(self, token, tenant, repair_id, body):
        self.calls.append((token, tenant, repair_id, body, "reconcile"))
        return {
            "schema": "factory.hosted.repair-recovery.v1",
            "repair_id": repair_id,
            "status": "failed",
            "recovery_status": "interrupted",
            "reason_code": "REPAIR_ATTEMPT_MISSING",
            "attempt_sha256": None,
            "evidence_sha256": "a" * 64,
            "recovery_sha256": "b" * 64,
        }

    def _emit(self, *_args, **_kwargs):
        return None


def _hosted_repair_call(app, *, path, body=b"{}", authorization="Bearer token"):
    status = []
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": BytesIO(body),
        "HTTP_AUTHORIZATION": authorization,
    }
    response = b"".join(app(environ, lambda value, _headers: status.append(value)))
    return status[0], json.loads(response)


def test_hosted_repair_route_uses_bearer_and_strict_empty_body():
    service = _HostedRepairRouteService()
    app = HostedPRAssuranceAPI(service)
    status, payload = _hosted_repair_call(
        app, path="/v1/tenants/acme/repairs/opaqueRepairId_123456/execute"
    )
    assert status == "200 OK"
    assert payload["status"] == "completed"
    assert service.calls == [("token", "acme", "opaqueRepairId_123456", {})]


def test_hosted_repair_route_rejects_extra_fields_and_missing_bearer():
    service = _HostedRepairRouteService()
    app = HostedPRAssuranceAPI(service)
    status, payload = _hosted_repair_call(
        app,
        path="/v1/tenants/acme/repairs/opaqueRepairId_123456/execute",
        body=b'{"workspace":"C:/private"}',
    )
    assert status == "400 Bad Request"
    assert payload["error"]["code"] == "E_REPAIR_BODY"
    assert not service.calls
    status, payload = _hosted_repair_call(
        app,
        path="/v1/tenants/acme/repairs/opaqueRepairId_123456/execute",
        authorization="",
    )
    assert status == "401 Unauthorized"
    assert payload["error"]["code"] == "E_AUTH_REQUIRED"


def test_hosted_repair_reconcile_route_uses_bearer_and_empty_body():
    service = _HostedRepairRouteService()
    app = HostedPRAssuranceAPI(service)
    status, payload = _hosted_repair_call(
        app,
        path="/v1/tenants/acme/repairs/opaqueRepairId_123456/reconcile",
        body=b"{}",
    )
    assert status == "200 OK"
    assert payload["recovery_status"] == "interrupted"
    assert service.calls == [
        ("token", "acme", "opaqueRepairId_123456", {}, "reconcile")
    ]


def test_hosted_repair_reconcile_rejects_nonempty_body():
    service = _HostedRepairRouteService()
    status, payload = _hosted_repair_call(
        HostedPRAssuranceAPI(service),
        path="/v1/tenants/acme/repairs/opaqueRepairId_123456/reconcile",
        body=b'{"retry":true}',
    )
    assert status == "400 Bad Request"
    assert payload["error"]["code"] == "E_REPAIR_BODY"
    assert service.calls == []


def _recovery_registry(binding, *, busy=False):
    class Registry:
        def __init__(self):
            self.target = {
                "workspace_path": "workspace",
                "approval_path": "approval.json",
                "workflow_approval_id": "workflow_12345678",
                "requester": "repair-operator",
                "binding": binding,
                "binding_sha256": "a" * 64,
                "status": "executing",
                "recovery": None,
            }
            self.audits = 0

        @contextmanager
        def hosted_repair_session_lock(self, *_args):
            if busy:
                raise PRAssuranceError("E_REPAIR_BUSY", "dispatch is active")
            yield

        def get_hosted_repair(self, _tenant, _repair_id):
            return self.target

        def workflow_approval_verifier(self, *_args, **_kwargs):
            def verify(expected):
                assert expected == binding
                return expected

            return verify

        def reconcile_hosted_repair(self, _tenant, repair_id, *, actor, recovery):
            assert actor == "tenant-admin"
            if self.target["recovery"] is not None:
                assert self.target["recovery"] == recovery
                return recovery
            self.target["status"] = recovery["status"]
            self.target["recovery"] = recovery
            self.audits += 1
            return recovery

    return Registry()


def test_registered_repair_recovery_reconciles_verified_journal_without_executor(
    tmp_path: Path, monkeypatch
):
    import factoryline.hosted_api as api

    binding = {
        "schema": "factory.repair.dispatch.v1",
        "repair_approval_sha256": "a" * 64,
    }
    root = tmp_path / "repair-root"
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    approval = workspace / "approval.json"
    approval.write_text("{}", encoding="utf-8")
    admin = Principal("tenant-admin", "acme", ("admin",))
    operator = Principal("repair-operator", "acme", ("operator",))
    registry = _recovery_registry(binding)
    service = object.__new__(HostedPRAssuranceService)
    service.control = registry
    service.repair_root = root
    service.current_principal_resolver = lambda subject, tenant: {
        admin.subject: admin,
        operator.subject: operator,
    }.get(subject)
    service.authenticate = lambda _token: (admin, {"sub": admin.subject}, None)
    monkeypatch.setattr(api, "_repair_dispatch_binding_or_error", lambda *_a: binding)
    monkeypatch.setattr(
        "factoryline.repair_sandbox.execute_workflow_approved_repair",
        lambda *_a, **_kw: pytest.fail("recovery must never execute the repair"),
    )
    monkeypatch.setattr(
        api,
        "_recovery_attempt_evidence",
        lambda *_a: ("c" * 64, {"journal_sha256": "c" * 64}),
    )
    first = service.reconcile_registered_repair(
        "admin-token", "acme", "opaqueRepairId_123456", {}
    )
    second = service.reconcile_registered_repair(
        "admin-token", "acme", "opaqueRepairId_123456", {}
    )
    assert first == second
    assert first["status"] == "completed"
    assert registry.audits == 1
    assert registry.target["status"] == "completed"


@pytest.mark.parametrize(
    "failure",
    [
        PRAssuranceError("E_REPAIR_PATCH_DRIFT", "patch changed"),
        PRAssuranceError("E_REPAIR_RECOVERY_INCOMPLETE", "attempt is running"),
        FileNotFoundError("missing attempt"),
        RuntimeError("unknown evidence failure"),
    ],
)
def test_registered_repair_recovery_refuses_unverified_evidence_without_mutation(
    tmp_path: Path, monkeypatch, failure
):
    import factoryline.hosted_api as api

    binding = {
        "schema": "factory.repair.dispatch.v1",
        "repair_approval_sha256": "a" * 64,
    }
    root = tmp_path / "repair-root"
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "approval.json").write_text("{}", encoding="utf-8")
    admin = Principal("tenant-admin", "acme", ("admin",))
    operator = Principal("repair-operator", "acme", ("operator",))
    registry = _recovery_registry(binding)
    service = object.__new__(HostedPRAssuranceService)
    service.control = registry
    service.repair_root = root
    service.current_principal_resolver = lambda subject, tenant: {
        admin.subject: admin,
        operator.subject: operator,
    }.get(subject)
    service.authenticate = lambda _token: (admin, {"sub": admin.subject}, None)
    monkeypatch.setattr(api, "_repair_dispatch_binding_or_error", lambda *_a: binding)

    def invalid_evidence(*_args):
        raise failure

    monkeypatch.setattr(api, "_recovery_attempt_evidence", invalid_evidence)
    with pytest.raises(PRAssuranceError) as refused:
        service.reconcile_registered_repair(
            "admin-token", "acme", "opaqueRepairId_123456", {}
        )
    assert refused.value.code == "E_REPAIR_RECOVERY_PENDING"
    assert "E_REPAIR_RECOVERY_PENDING" == refused.value.code
    assert (
        "E_REPAIR_PATCH_DRIFT" in refused.value.message
        or "E_REPAIR_RECOVERY_INCOMPLETE" in refused.value.message
        or "E_REPAIR_RECOVERY_INVALID" in refused.value.message
    )
    assert len(refused.value.message.rsplit(" ", 1)[-1]) == 65
    assert registry.target["status"] == "executing"
    assert registry.target["recovery"] is None
    assert registry.audits == 0


def test_recovery_check_log_tampering_is_rejected(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    log = workspace / ".factory" / "repair-attempts" / ("a" * 64)
    log.mkdir(parents=True)
    path = log / "repaired-check.log"
    path.write_bytes(b"original")
    row = {
        "stage": "repaired",
        "check_id": "check",
        "result": "PASS",
        "expected": "success",
        "exit_code": 0,
        "log": "repaired-check.log",
        "log_sha256": __import__("hashlib").sha256(b"original").hexdigest(),
        "process_cleanup_confirmed": True,
        "container_cleanup_confirmed": True,
        "worktree_unchanged": True,
    }
    expected = {
        ("repaired", "check"): {
            "log": "repaired-check.log",
            "expected": "success",
            "exit_code": 0,
            "signature": None,
        }
    }
    assert _verify_recovery_check_logs(workspace, "a" * 64, expected, [row])
    row["container_cleanup_confirmed"] = False
    with pytest.raises(PRAssuranceError) as unclean:
        _verify_recovery_check_logs(workspace, "a" * 64, expected, [row])
    assert unclean.value.code == "E_REPAIR_CHECK_EVIDENCE"
    row["container_cleanup_confirmed"] = True
    path.write_bytes(b"changed")
    with pytest.raises(PRAssuranceError) as error:
        _verify_recovery_check_logs(workspace, "a" * 64, expected, [row])
    assert error.value.code == "E_REPAIR_CHECK_EVIDENCE"


def test_recovery_requires_terminal_attempt_and_confirmed_cleanup():
    state = {
        "approval_sha256": "a" * 64,
        "status": "VERIFIED",
        "phase": "VERIFIED",
        "origin_audit": None,
        "candidate_before_sha256": None,
        "cleanup_confirmed": True,
        "primary_checkout_unchanged": True,
    }
    assert _require_terminal_recovery_state(state, "a" * 64, None) is None
    state["candidate_after_sha256"] = "b" * 64
    with pytest.raises(PRAssuranceError) as unexpected_candidate:
        _require_terminal_recovery_state(state, "a" * 64, None)
    assert unexpected_candidate.value.code == "E_REPAIR_RECOVERY_INCOMPLETE"
    state.pop("candidate_after_sha256")
    state["phase"] = "PATCH_APPLY"
    with pytest.raises(PRAssuranceError) as incomplete:
        _require_terminal_recovery_state(state, "a" * 64, None)
    assert incomplete.value.code == "E_REPAIR_RECOVERY_INCOMPLETE"


def test_recovery_cleanup_normalizes_windows_worktree_paths():
    from factoryline.hosted_api import (
        _normalize_worktree_path,
        _registered_worktree_paths,
    )

    paths = _registered_worktree_paths(
        "worktree C:\\repo\\.factory\\repair\\execution\n"
        "worktree C:\\repo\\.factory\\repair\\temporary\\..\\execution\n"
    )
    assert "c:/repo/.factory/repair/execution" in paths
    assert len(paths) == 1
    assert _normalize_worktree_path("\\\\server\\share\\repair") == (
        "//server/share/repair"
    )


def test_recovery_cleanup_resolves_native_worktree_paths():
    from factoryline.hosted_api import _normalize_worktree_path

    assert _normalize_worktree_path("/tmp/repo/repair/../execution") == (
        _normalize_worktree_path("/tmp/repo/execution")
    )


def test_registered_repair_recovery_refuses_while_dispatch_lock_is_held(
    tmp_path: Path,
):
    binding = {
        "schema": "factory.repair.dispatch.v1",
        "repair_approval_sha256": "a" * 64,
    }
    admin = Principal("tenant-admin", "acme", ("admin",))
    registry = _recovery_registry(binding, busy=True)
    service = object.__new__(HostedPRAssuranceService)
    service.control = registry
    service.repair_root = tmp_path
    service.current_principal_resolver = lambda subject, tenant: admin
    service.authenticate = lambda _token: (admin, {"sub": admin.subject}, None)
    with pytest.raises(PRAssuranceError) as busy:
        service.reconcile_registered_repair(
            "admin-token", "acme", "opaqueRepairId_123456", {}
        )
    assert busy.value.code == "E_REPAIR_BUSY"
    assert registry.audits == 0


def test_trusted_repair_path_rejects_escape_and_symlink(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "workspace"
    target.mkdir()
    with pytest.raises(PRAssuranceError):
        _trusted_repair_path(root, "../outside", directory=True)
    link = root / "linked"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    with pytest.raises(PRAssuranceError):
        _trusted_repair_path(root, "linked", directory=True)


def test_trusted_repair_path_rejects_windows_reparse_attribute(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    directory = root / "workspace"
    directory.mkdir()
    original_lstat = Path.lstat

    def reparse_lstat(path):
        if path == directory:
            return SimpleNamespace(
                st_mode=directory.stat().st_mode, st_file_attributes=0x400
            )
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", reparse_lstat)
    with pytest.raises(PRAssuranceError) as error:
        _trusted_repair_path(root, "workspace", directory=True)
    assert error.value.code == "E_REPAIR_PATH"


def test_service_fails_closed_without_current_identity_resolver():
    service = object.__new__(HostedPRAssuranceService)
    service.control = object()
    service.repair_root = Path(".")
    service.current_principal_resolver = None
    with pytest.raises(PRAssuranceError) as error:
        service.execute_registered_repair("token", "acme", "repair1234567890", {})
    assert error.value.code == "E_REPAIR_UNAVAILABLE"


def test_registered_dispatch_rechecks_binding_and_scrubs_executor_paths(
    tmp_path: Path, monkeypatch
):
    import factoryline.repair_sandbox as repair

    root = tmp_path / "repair-root"
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "approval.json").write_text("{}", encoding="utf-8")
    principal = Principal("requester", "acme", ("operator",))
    binding = {"schema": "factory.repair.dispatch.v1", "candidate_sha256": "a" * 64}

    class Registry:
        def __init__(self, registered_binding):
            self.target = {
                "workspace_path": "workspace",
                "approval_path": "approval.json",
                "workflow_approval_id": "workflow_12345678",
                "requester": "requester",
                "binding": registered_binding,
            }
            self.claimed = False
            self.finished = []

        def get_hosted_repair(self, _tenant, _repair_id):
            return self.target

        @contextmanager
        def hosted_repair_session_lock(self, *_args):
            yield

        def claim_hosted_repair(self, *_args):
            self.claimed = True

        def finish_hosted_repair(self, *_args, **kwargs):
            self.finished.append(kwargs)

    registry = Registry(binding)
    service = object.__new__(HostedPRAssuranceService)
    service.control = registry
    service.repair_root = root
    service.current_principal_resolver = lambda subject, tenant: Principal(
        subject, tenant, ("operator",)
    )
    service.authenticate = lambda _token: (principal, {"sub": "requester"}, None)
    service._emit = lambda *_args, **_kwargs: None
    monkeypatch.setattr(repair, "repair_dispatch_evidence", lambda *_a, **_kw: binding)
    monkeypatch.setattr(
        repair,
        "execute_workflow_approved_repair",
        lambda *_a, **_kw: {
            "status": "VERIFIED",
            "attempt_path": "C:/private/attempt.json",
            "origin_audit": {"private_path": "C:/private/source"},
        },
    )
    result = service.execute_registered_repair(
        "verified-token", "acme", "opaqueRepairId_123456", {}
    )
    assert result == {
        "schema": "factory.hosted.repair.v1",
        "repair_id": "opaqueRepairId_123456",
        "status": "completed",
    }
    assert registry.claimed is True
    assert registry.finished == [{"succeeded": True, "actor": "requester"}]

    registry = Registry({**binding, "candidate_sha256": "b" * 64})
    service.control = registry
    with pytest.raises(PRAssuranceError) as changed:
        service.execute_registered_repair(
            "verified-token", "acme", "opaqueRepairId_123456", {}
        )
    assert changed.value.code == "E_REPAIR_CHANGED"
    assert registry.claimed is False


def test_hosted_repair_preflight_error_is_redacted_before_claim(tmp_path, monkeypatch):
    import factoryline.repair_sandbox as repair

    from factoryline.repair_sandbox import RepairSandboxError

    root = tmp_path / "repair-root"
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "approval.json").write_text("{}", encoding="utf-8")
    principal = Principal("requester", "acme", ("operator",))
    binding = {"schema": "factory.repair.dispatch.v1", "candidate_sha256": "a" * 64}

    class Registry:
        claimed = False

        def get_hosted_repair(self, _tenant, _repair_id):
            return {
                "workspace_path": "workspace",
                "approval_path": "approval.json",
                "workflow_approval_id": "workflow_12345678",
                "requester": "requester",
                "binding": binding,
            }

        @contextmanager
        def hosted_repair_session_lock(self, *_args):
            yield

        def claim_hosted_repair(self, *_args):
            self.claimed = True

    registry = Registry()
    service = object.__new__(HostedPRAssuranceService)
    service.control = registry
    service.repair_root = root
    service.current_principal_resolver = lambda subject, tenant: Principal(
        subject, tenant, ("operator",)
    )
    service.authenticate = lambda _token: (principal, {"sub": "requester"}, None)
    service._emit = lambda *_args, **_kwargs: None

    def malformed_approval(*_args, **_kwargs):
        raise RepairSandboxError(
            "REPAIR_APPROVAL_INVALID", "invalid approval at C:/private/approval.json"
        )

    monkeypatch.setattr(repair, "repair_dispatch_evidence", malformed_approval)
    status, payload = _hosted_repair_call(
        HostedPRAssuranceAPI(service),
        path="/v1/tenants/acme/repairs/opaqueRepairId_123456/execute",
    )
    assert status == "400 Bad Request"
    assert payload["error"] == {
        "code": "REPAIR_APPROVAL_INVALID",
        "message": "repair dispatch was rejected",
    }
    assert "C:/private" not in json.dumps(payload)
    assert registry.claimed is False


def test_repair_provisioning_binds_existing_workflow_requester_not_admin(
    tmp_path: Path, monkeypatch
):
    import factoryline.repair_sandbox as repair

    admin = Principal("tenant-admin", "acme", ("admin",))
    operator = Principal("repair-operator", "acme", ("operator",))
    root = tmp_path / "repairs"
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "approval.json").write_text("{}", encoding="utf-8")

    class Registry:
        registration = None

        def get_approval(self, _principal, _tenant, _approval_id):
            return {"requester": operator.subject}

        def register_hosted_repair(self, **values):
            self.registration = values
            return {"repair_id": values["repair_id"]}

    registry = Registry()
    service = object.__new__(HostedPRAssuranceService)
    service.control = registry
    service.repair_root = root
    service.current_principal_resolver = lambda subject, tenant: {
        admin.subject: admin,
        operator.subject: operator,
    }.get(subject)
    service.authenticate = lambda _token: (admin, {"sub": admin.subject}, None)
    monkeypatch.setattr(
        repair,
        "repair_dispatch_evidence",
        lambda *_args, **kwargs: {"requester": kwargs["requester"]},
    )
    service.provision_repair_target(
        "admin-token",
        "acme",
        repair_id="opaqueRepairId_123456",
        workspace_relative="workspace",
        approval_relative="approval.json",
        workflow_approval_id="workflow_12345678",
    )
    assert registry.registration["requester"] == operator.subject
    assert registry.registration["registered_by"] == admin.subject
    assert registry.registration["binding"] == {"requester": operator.subject}


def test_repair_provisioning_redacts_preflight_error_before_registration(
    tmp_path: Path, monkeypatch
):
    import factoryline.repair_sandbox as repair

    from factoryline.repair_sandbox import RepairSandboxError

    admin = Principal("tenant-admin", "acme", ("admin",))
    operator = Principal("repair-operator", "acme", ("operator",))
    root = tmp_path / "repairs"
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "approval.json").write_text("{}", encoding="utf-8")

    class Registry:
        registration = None

        def get_approval(self, _principal, _tenant, _approval_id):
            return {"requester": operator.subject}

        def register_hosted_repair(self, **values):
            self.registration = values

    registry = Registry()
    service = object.__new__(HostedPRAssuranceService)
    service.control = registry
    service.repair_root = root
    service.current_principal_resolver = lambda subject, tenant: {
        admin.subject: admin,
        operator.subject: operator,
    }.get(subject)
    service.authenticate = lambda _token: (admin, {"sub": admin.subject}, None)

    def invalid_approval(*_args, **_kwargs):
        raise RepairSandboxError(
            "REPAIR_APPROVAL_INVALID", "C:/private/approval-secret.json"
        )

    monkeypatch.setattr(repair, "repair_dispatch_evidence", invalid_approval)
    with pytest.raises(PRAssuranceError) as error:
        service.provision_repair_target(
            "admin-token",
            "acme",
            repair_id="opaqueRepairId_123456",
            workspace_relative="workspace",
            approval_relative="approval.json",
            workflow_approval_id="workflow_12345678",
        )
    assert error.value.code == "REPAIR_APPROVAL_INVALID"
    assert str(error.value) == "repair preflight validation failed"
    assert "C:/private" not in str(error.value)
    assert registry.registration is None


def test_postgres_workflow_verifier_preserves_requester_and_current_approver_checks(
    monkeypatch,
):
    store = object.__new__(PostgresControlStore)
    requester = Principal("requester", "acme", ("operator",))
    approval = {
        "approval_id": "approval-1",
        "tenant_id": "acme",
        "evidence_id": "evidence-1",
        "requester": requester.subject,
        "reason": "dispatch repair",
        "status": "approved",
        "requested_at": "2026-10-11T12:00:00+00:00",
        "decided_at": "2026-10-11T12:01:00+00:00",
        "approver": "approver",
        "decision_reason": "reviewed",
    }
    monkeypatch.setattr(store, "get_approval", lambda *args, **kwargs: approval)
    consumed = []
    monkeypatch.setattr(
        store,
        "_consume_workflow_approval",
        lambda principal, tenant, record, expected: consumed.append(
            (principal, tenant, record, expected)
        )
        or dict(expected),
    )

    def resolver(subject, tenant):
        roles = ("operator",) if subject == requester.subject else ("approver",)
        return Principal(subject, tenant, roles)

    verifier = store.workflow_approval_verifier(
        requester,
        "acme",
        "approval-1",
        resolve_principal=resolver,
        require_requester=True,
    )
    expected = {"candidate_sha256": "a" * 64}
    assert verifier(expected) == expected
    assert consumed == [(requester, "acme", approval, expected)]

    def stale_requester(subject, tenant):
        roles = () if subject == requester.subject else ("approver",)
        return Principal(subject, tenant, roles)

    revoked = store.workflow_approval_verifier(
        requester, "acme", "approval-1", resolve_principal=stale_requester
    )
    with pytest.raises(ControlPlaneError) as caller_role_error:
        revoked(expected)
    assert caller_role_error.value.code == "E_ACTION_DENIED"

    def moved_requester(subject, _tenant):
        return Principal(subject, "other-tenant", ("operator",))

    moved = store.workflow_approval_verifier(
        requester, "acme", "approval-1", resolve_principal=moved_requester
    )
    with pytest.raises(ControlPlaneError) as tenant_error:
        moved(expected)
    assert tenant_error.value.code == "E_TENANT_BOUNDARY"

    def stale_role(subject, tenant):
        return Principal(subject, tenant, ("viewer",))

    denied = store.workflow_approval_verifier(
        requester, "acme", "approval-1", resolve_principal=stale_role
    )
    with pytest.raises(ControlPlaneError) as role_error:
        denied(expected)
    assert role_error.value.code == "E_ACTION_DENIED"

    other = Principal("other-requester", "acme", ("operator",))
    wrong_requester = store.workflow_approval_verifier(
        other,
        "acme",
        "approval-1",
        resolve_principal=resolver,
        require_requester=True,
    )
    with pytest.raises(ControlPlaneError) as requester_error:
        wrong_requester(expected)
    assert requester_error.value.code == "E_APPROVAL_REQUESTER"


def test_env_secret_resolver_accepts_only_scoped_references_and_never_returns_reference_text():
    resolver = EnvSecretResolver({"FACTORY_ACME_WEBHOOK": "0123456789abcdef"})
    assert resolver.resolve("env://FACTORY_ACME_WEBHOOK") == b"0123456789abcdef"
    for value in ["plain-text", "env://lower", "vault://secret", "env://MISSING"]:
        with pytest.raises(PRAssuranceError):
            resolver.resolve(value)


def test_dynamic_tenant_identity_uses_hint_only_for_lookup_then_verifies_every_claim(
    monkeypatch,
):
    private, jwks = _identity()
    verifier = TenantIdentityVerifier(IdentityStore(), Transport(jwks))
    monkeypatch.setattr("factoryline.pr_assurance.time.time", lambda: 1_800_000_000)
    principal, claims = verifier.verify(_token(private))
    assert principal == Principal("reviewer", "acme", ("approver",))
    assert claims["marker"] == "TENANT_IDENTITY_VERIFIED"
    with pytest.raises(PRAssuranceError) as malformed_hint:
        verifier.verify(_token(private, tenant_id="../other"))
    assert malformed_hint.value.code == "E_TENANT_INVALID"


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "2001:db8::1",
        "224.0.0.1",
    ],
)
def test_jwks_transport_rejects_literal_non_public_destinations(address):
    transport = object.__new__(HttpxTransport)
    transport._client = object()
    with pytest.raises(PRAssuranceError) as rejected:
        transport.request(
            "GET",
            f"https://[{address}]/jwks"
            if ":" in address
            else f"https://{address}/jwks",
        )
    assert rejected.value.code == "E_HTTP_DESTINATION"


def test_jwks_transport_requires_allowlisted_hostname_and_rejects_private_dns(
    monkeypatch,
):
    transport = object.__new__(HttpxTransport)
    transport._client = object()
    monkeypatch.delenv("FACTORY_HOSTED_JWKS_ALLOWED_HOSTS", raising=False)
    with pytest.raises(PRAssuranceError, match="allowlist"):
        transport.request("GET", "https://id.acme.test/jwks")

    monkeypatch.setenv("FACTORY_HOSTED_JWKS_ALLOWED_HOSTS", "id.acme.test")
    monkeypatch.setattr(
        "factoryline.hosted_identity.socket.getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.4", 443))
        ],
    )
    with pytest.raises(PRAssuranceError, match="non-public"):
        transport.request("GET", "https://id.acme.test/jwks")


def test_jwks_transport_pins_the_validated_address_and_preserves_tls_identity(
    monkeypatch,
):
    httpx = pytest.importorskip("httpx")
    events = []

    def handle_request(request):
        parts = request.url
        events.append(
            (
                "request",
                parts.host,
                request.headers["Host"],
                request.extensions.get("sni_hostname"),
                parts.path,
            )
        )
        return httpx.Response(200, json={"ok": True})

    transport = object.__new__(HttpxTransport)
    transport._client = httpx.Client(
        transport=httpx.MockTransport(handle_request),
        follow_redirects=False,
        trust_env=False,
    )
    monkeypatch.setenv("FACTORY_HOSTED_JWKS_ALLOWED_HOSTS", "id.acme.test")
    monkeypatch.setattr(
        "factoryline.hosted_identity.socket.getaddrinfo",
        lambda host, port, **kwargs: events.append(("resolve", host, port))
        or [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("8.8.8.8", 443),
            )
        ],
    )
    assert transport.request("GET", "https://id.acme.test/jwks").status_code == 200
    assert events == [
        ("resolve", "id.acme.test", 443),
        ("request", "8.8.8.8", "id.acme.test", "id.acme.test", "/jwks"),
    ]


def test_jwks_public_ip_literal_is_allowed():
    transport = object.__new__(HttpxTransport)
    transport._client = type(
        "Client",
        (),
        {
            "build_request": lambda self, *args, **kwargs: type(
                "Request", (), {"extensions": {}}
            )(),
            "send": lambda self, request: "ok",
        },
    )()
    assert transport.request("GET", "https://8.8.8.8/jwks") == "ok"


def test_jwks_transport_allows_and_pins_the_github_app_api_host(monkeypatch):
    class Request:
        extensions = {}

    class Client:
        def build_request(self, method, url, **kwargs):
            self.url = url
            self.headers = kwargs["headers"]
            return Request()

        def send(self, request):
            return self.url

    transport = object.__new__(HttpxTransport)
    transport._client = Client()
    monkeypatch.delenv("FACTORY_HOSTED_JWKS_ALLOWED_HOSTS", raising=False)
    monkeypatch.setattr(
        "factoryline.hosted_identity.socket.getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("140.82.112.5", 443))
        ],
    )

    assert (
        transport.request("GET", "https://api.github.com/app")
        == "https://140.82.112.5/app"
    )
    assert transport._client.headers["Host"] == "api.github.com"


class FakeAssuranceStore:
    def ping(self):
        return True


class FakeControl:
    def __init__(self):
        self.calls = []
        self.states = set()

    def create_tenant(self, principal, tenant_id, display_name):
        self.calls.append(("tenant", principal, tenant_id, display_name))
        return {
            "markers": ["TENANT_CREATED", "ADMIN_ACTION_AUDITED"],
            "tenant_id": tenant_id,
        }

    def configure_identity(self, principal, tenant_id, **values):
        if principal.tenant_id != "*" and principal.tenant_id != tenant_id:
            raise PRAssuranceError("E_TENANT_BOUNDARY", "cross tenant")
        self.calls.append(("identity", tenant_id, values))
        return {"marker": "OIDC_CONFIG_VERIFIED", "tenant_id": tenant_id}

    def replace_roles(self, principal, tenant_id, mappings):
        self.calls.append(("roles", tenant_id, mappings))
        return {"marker": "ROLE_MAPPING_BOUND", "tenant_id": tenant_id}

    def set_secret_reference(self, principal, tenant_id, purpose, reference):
        self.calls.append(("secret", tenant_id, purpose, reference))
        return {
            "marker": "SECRET_REFERENCE_BOUND",
            "tenant_id": tenant_id,
            "purpose": purpose,
        }

    def issue_state(self, principal, tenant_id):
        self.states.add("one-time-state-value-that-is-long-enough")
        return {
            "marker": "INSTALLATION_STATE_ISSUED",
            "tenant_id": tenant_id,
            "state": "one-time-state-value-that-is-long-enough",
        }

    def bind_installation(self, state, installation_id):
        if state not in self.states:
            raise PRAssuranceError("E_INSTALLATION_STATE", "state replay")
        self.states.remove(state)
        return {
            "marker": "INSTALLATION_BOUND",
            "tenant_id": "acme",
            "installation_id": installation_id,
        }

    def overview(self, principal, tenant_id):
        if principal.tenant_id != "*" and principal.tenant_id != tenant_id:
            raise PRAssuranceError("E_TENANT_BOUNDARY", "cross tenant")
        return {
            "markers": ["CONTROL_OVERVIEW_REDACTED"],
            "tenant": {
                "tenant_id": tenant_id,
                "display_name": "Acme",
                "status": "active",
            },
            "identity_configured": True,
            "role_counts": {"admin": 1},
            "installation_ids": [42],
            "secret_purposes": ["github_webhook"],
            "outbox_counts": {},
            "approval_counts": {},
            "audit": {"valid": True, "events": []},
        }


def _api_call(app, method, path, *, value=None, token="token"):
    captured = {}
    body = b"" if value is None else json.dumps(value).encode()
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": BytesIO(body),
        "HTTP_AUTHORIZATION": "Bearer " + token,
    }
    response = b"".join(
        app(
            environ,
            lambda status, headers: captured.update(status=status, headers=headers),
        )
    )
    return captured["status"], json.loads(response)


def _service(control, events):
    return HostedPRAssuranceService(
        store=FakeAssuranceStore(),
        jwks=object(),
        publisher=object(),
        config=HostedConfig(
            "https://bootstrap.test", "factory", {"platform": "platform_admin"}, {}, {}
        ),
        control=control,
        event_sink=events.append,
    )


def test_control_routes_are_authenticated_tenant_bound_replay_safe_and_secret_free(
    monkeypatch,
):
    events = []
    control = FakeControl()
    service = _service(control, events)
    platform = Principal("root", "*", ("platform_admin",))
    monkeypatch.setattr(
        service,
        "authenticate",
        lambda _token: (platform, {"iss": "x", "jti": "j"}, None),
    )
    app = create_hosted_app(service)
    assert (
        _api_call(
            app,
            "POST",
            "/v1/admin/tenants",
            value={"tenant_id": "acme", "display_name": "Acme"},
        )[0]
        == "201 Created"
    )
    assert (
        _api_call(
            app,
            "PUT",
            "/v1/admin/tenants/acme/identity",
            value={
                "issuer": "https://id.acme.test",
                "audience": "factory",
                "jwks_url": "https://id.acme.test/jwks",
            },
        )[1]["marker"]
        == "OIDC_CONFIG_VERIFIED"
    )
    assert (
        _api_call(
            app,
            "PUT",
            "/v1/admin/tenants/acme/roles",
            value={"mappings": {"ops": "admin"}},
        )[1]["marker"]
        == "ROLE_MAPPING_BOUND"
    )
    assert (
        _api_call(
            app,
            "PUT",
            "/v1/admin/tenants/acme/secrets/github_webhook",
            value={"reference": "env://FACTORY_ACME_WEBHOOK"},
        )[1]["marker"]
        == "SECRET_REFERENCE_BOUND"
    )
    _status, issued = _api_call(
        app, "POST", "/v1/admin/tenants/acme/installation-state", value={}
    )
    assert (
        service.issue_installation_state("token", "acme")["marker"]
        == "INSTALLATION_STATE_ISSUED"
    )
    assert (
        issue_installation_state(control, platform, "acme")["marker"]
        == "INSTALLATION_STATE_ISSUED"
    )
    callback = {"state": issued["state"], "installation_id": 42}
    assert (
        _api_call(app, "POST", "/v1/github/installations/callback", value=callback)[0]
        == "201 Created"
    )
    replay_status, replay = _api_call(
        app, "POST", "/v1/github/installations/callback", value=callback
    )
    assert (
        replay_status == "409 Conflict"
        and replay["error"]["code"] == "E_INSTALLATION_STATE"
    )
    overview_status, overview = _api_call(app, "GET", "/v1/admin/tenants/acme/overview")
    assert overview_status == "200 OK" and overview["markers"] == [
        "CONTROL_OVERVIEW_REDACTED"
    ]
    serialized = json.dumps(overview).lower()
    assert all(
        term not in serialized
        for term in ["env://", "token", "private_key", "secret_ref"]
    )
    service._emit(
        "admin.test",
        tenant_id="acme",
        state="plaintext",
        reference="env://HIDDEN",
        token="hidden",
    )
    assert events[-1] == {
        "schema": "factory.hosted.operation.v1",
        "operation": "admin.test",
        "tenant_id": "acme",
    }

    tenant_admin = Principal("admin", "acme", ("admin",))
    monkeypatch.setattr(
        service,
        "authenticate",
        lambda _token: (tenant_admin, {"iss": "x", "jti": "j2"}, None),
    )
    denied_status, denied = _api_call(
        app,
        "PUT",
        "/v1/admin/tenants/other/identity",
        value={
            "issuer": "https://id.other.test",
            "audience": "factory",
            "jwks_url": "https://id.other.test/jwks",
        },
    )
    assert (
        denied_status == "403 Forbidden"
        and denied["error"]["code"] == "E_TENANT_BOUNDARY"
    )


def test_secret_reference_lookup_routes_globally_then_reads_inside_tenant_rls():
    class Cursor:
        def __init__(self, row):
            self.row = row

        def execute(self, _sql, _params):
            return None

        def fetchone(self):
            return self.row

    rows = iter([("acme",), ("env://FACTORY_ACME_WEBHOOK",)])
    store = object.__new__(PostgresControlStore)

    @contextmanager
    def transaction(_tenant_id=None):
        yield object(), Cursor(next(rows))

    store._transaction = transaction
    assert store.secret_reference_for_installation(42, "github_webhook") == (
        "acme",
        "env://FACTORY_ACME_WEBHOOK",
    )


def test_control_console_route_sets_no_store_and_security_headers(monkeypatch):
    console = Path("factoryline/hosted_console.html").read_text(encoding="utf-8")
    service = _service(FakeControl(), [])
    service.console_html = console
    captured = {}
    response = b"".join(
        create_hosted_app(service)(
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/console",
                "CONTENT_LENGTH": "0",
                "wsgi.input": BytesIO(),
            },
            lambda status, headers: captured.update(
                status=status, headers=dict(headers)
            ),
        )
    )
    assert captured["status"] == "200 OK"
    assert captured["headers"]["Cache-Control"] == "no-store"
    assert "Content-Security-Policy" in captured["headers"]
    assert b"CONTROL_CONSOLE_READ_ONLY" in response


def test_bootstrap_fallback_accepts_only_platform_admin_with_star_tenant(monkeypatch):
    class MissingTenantIdentity:
        def verify(self, _token):
            raise PRAssuranceError("E_TENANT_INVALID", "bootstrap hint")

    service = _service(FakeControl(), [])
    service.tenant_identity = MissingTenantIdentity()
    monkeypatch.setattr(
        "factoryline.hosted_api.get_jwks", lambda _cache: {"keys": [{}]}
    )
    monkeypatch.setattr(
        "factoryline.hosted_api.verify_oidc_token",
        lambda *args, **kwargs: {
            "signature_verified": True,
            "iss": "https://bootstrap.test",
            "aud": "factory",
            "sub": "root",
            "tenant_id": "acme",
            "groups": ["platform"],
            "jti": "bootstrap",
            "exp": 1_900_000_000,
        },
    )
    monkeypatch.setattr(
        "factoryline.hosted_api.principal_from_verified_oidc",
        lambda *args, **kwargs: Principal("root", "acme", ("platform_admin",)),
    )
    with pytest.raises(PRAssuranceError) as denied:
        service.authenticate("bootstrap-token")
    assert denied.value.code == "E_TENANT_BOUNDARY"
    monkeypatch.setattr(
        "factoryline.hosted_api.principal_from_verified_oidc",
        lambda *args, **kwargs: Principal("root", "*", ("platform_admin",)),
    )
    principal, _claims, marker = service.authenticate("bootstrap-token")
    assert principal.tenant_id == "*" and marker is None
