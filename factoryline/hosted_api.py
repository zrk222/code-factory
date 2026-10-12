"""Authenticated WSGI and worker adapter for hosted PR assurance."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from importlib import resources
import json
import ntpath
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Callable, Mapping
from urllib.parse import unquote, urlsplit

from .hosted_github import GitHubAppPublisher
from .hosted_control import (
    EnvSecretResolver,
    PostgresControlStore,
    TenantIdentityVerifier,
)
from .hosted_identity import HttpxTransport, JwksCache, get_jwks
from .hosted_storage import PostgresAssuranceStore
from .control_plane import ControlPlaneError, Principal, canonical_json
from .integrations import principal_from_verified_oidc
from .pr_assurance import (
    MAX_WEBHOOK_BYTES,
    PRAssuranceError,
    verify_github_webhook,
    verify_oidc_token,
)


DECISION_BODY_MAX = 65_536


def _configured_maps(
    env: Mapping[str, str],
) -> tuple[dict[int, bytes], dict[int, str], dict[str, str]]:
    try:
        raw_secrets = json.loads(env.get("FACTORY_WEBHOOK_SECRETS_JSON", "{}"))
        raw_tenants = json.loads(env.get("FACTORY_INSTALLATION_TENANTS_JSON", "{}"))
        raw_roles = json.loads(
            env.get("FACTORY_ROLE_MAP_JSON", '{"release-approvers":"approver"}')
        )
        secrets = {
            int(key): str(value).encode("utf-8") for key, value in raw_secrets.items()
        }
        tenants = {int(key): str(value) for key, value in raw_tenants.items()}
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PRAssuranceError(
            "E_HOSTED_CONFIG", "hosted installation configuration is invalid"
        ) from exc
    if not isinstance(raw_roles, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in raw_roles.items()
    ):
        raise PRAssuranceError("E_HOSTED_CONFIG", "role map must be a string mapping")
    return secrets, tenants, raw_roles


def _identity_config(env: Mapping[str, str]) -> tuple[str, str]:
    try:
        return env["FACTORY_OIDC_ISSUER"], env["FACTORY_OIDC_AUDIENCE"]
    except KeyError as exc:
        raise PRAssuranceError(
            "E_HOSTED_CONFIG", "hosted identity configuration is invalid"
        ) from exc


def _validate_installation_maps(
    secrets: dict[int, bytes], tenants: dict[int, str]
) -> None:
    if any(key <= 0 or len(value) < 16 for key, value in secrets.items()):
        raise PRAssuranceError(
            "E_HOSTED_CONFIG",
            "each installation requires a secret of at least 16 bytes",
        )
    if secrets.keys() != tenants.keys() or any(
        not tenant.strip() for tenant in tenants.values()
    ):
        raise PRAssuranceError(
            "E_HOSTED_CONFIG", "installation tenant and secret keys must match"
        )


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _finish(start_response: Callable, status: str, value: Any) -> list[bytes]:
    body = _json_bytes(value)
    start_response(
        status,
        [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
    )
    return [body]


def _finish_html(start_response: Callable, value: str) -> list[bytes]:
    body = value.encode("utf-8")
    start_response(
        "200 OK",
        [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            (
                "Content-Security-Policy",
                "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:",
            ),
            ("Referrer-Policy", "no-referrer"),
            ("X-Content-Type-Options", "nosniff"),
        ],
    )
    return [body]


def _read_body(environ: Mapping[str, Any], maximum: int) -> bytes:
    try:
        length = int(environ.get("CONTENT_LENGTH") or "0")
    except ValueError as exc:
        raise PRAssuranceError(
            "E_HTTP_BODY", "Content-Length must be an integer"
        ) from exc
    if length < 1 or length > maximum:
        raise PRAssuranceError(
            "E_HTTP_BODY", f"request body must contain 1-{maximum} bytes"
        )
    value = environ.get("wsgi.input")
    if value is None:
        raise PRAssuranceError("E_HTTP_BODY", "request body stream is required")
    body = value.read(length)
    if len(body) != length:
        raise PRAssuranceError(
            "E_HTTP_BODY", "request body ended before Content-Length"
        )
    return body


def _json_body(environ: Mapping[str, Any]) -> dict[str, Any]:
    try:
        value = json.loads(_read_body(environ, DECISION_BODY_MAX))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PRAssuranceError(
            "E_HTTP_JSON", "request body must be UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        raise PRAssuranceError("E_HTTP_JSON", "request JSON must be an object")
    return value


def _installation_id(body: bytes) -> int:
    try:
        value = json.loads(body)
        installation_id = (
            (value.get("installation") or {}).get("id")
            if isinstance(value, dict)
            else None
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PRAssuranceError(
            "E_WEBHOOK_PAYLOAD", "webhook routing body is invalid JSON"
        ) from exc
    if (
        not isinstance(installation_id, int)
        or isinstance(installation_id, bool)
        or installation_id <= 0
    ):
        raise PRAssuranceError(
            "E_WEBHOOK_PAYLOAD", "installation.id is required for secure routing"
        )
    return installation_id


def _bearer(environ: Mapping[str, Any]) -> str:
    authorization = str(environ.get("HTTP_AUTHORIZATION", ""))
    if not authorization.startswith("Bearer ") or len(authorization) <= 7:
        raise PRAssuranceError(
            "E_AUTH_REQUIRED", "decision route requires a Bearer token"
        )
    return authorization[7:]


def _trusted_repair_path(root: Path, relative: str, *, directory: bool) -> Path:
    """Resolve a server-provisioned relative path without links or escapes."""
    parsed = _repair_relative_path(relative)
    base = _trusted_repair_root(root)
    resolved = _trusted_repair_child(base, parsed.parts)
    _check_repair_path_type(resolved, directory)
    return resolved


def _repair_relative_path(relative: str) -> PurePosixPath:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise PRAssuranceError("E_REPAIR_PATH", "registered repair path is invalid")
    parsed = PurePosixPath(relative)
    if parsed.is_absolute() or any(part in {"", ".", ".."} for part in parsed.parts):
        raise PRAssuranceError("E_REPAIR_PATH", "registered repair path is invalid")
    return parsed


def _trusted_repair_root(root: Path) -> Path:
    root = Path(root).absolute()
    root_parts = [*reversed(root.parents), root]
    for item in root_parts:
        if _repair_path_is_reparse(item):
            raise PRAssuranceError("E_REPAIR_PATH", "linked repair roots are refused")

    return root.resolve(strict=True)


def _trusted_repair_child(base: Path, parts: tuple[str, ...]) -> Path:
    current = base
    for part in parts:
        current = current / part
        if _repair_path_is_reparse(current):
            raise PRAssuranceError("E_REPAIR_PATH", "linked repair paths are refused")
    resolved = current.resolve(strict=True)
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise PRAssuranceError("E_REPAIR_PATH", "repair path escapes its root") from exc

    return resolved


def _check_repair_path_type(resolved: Path, directory: bool) -> None:
    if directory and not resolved.is_dir():
        raise PRAssuranceError("E_REPAIR_PATH", "registered repair path has wrong type")
    if not directory and not resolved.is_file():
        raise PRAssuranceError("E_REPAIR_PATH", "registered repair path has wrong type")


def _repair_path_is_reparse(path: Path) -> bool:
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & flag)


def _repair_dispatch_binding_or_error(workspace, approval, tenant_id, requester):
    from .repair_sandbox import RepairSandboxError, repair_dispatch_evidence

    try:
        return repair_dispatch_evidence(
            workspace, approval, tenant_id=tenant_id, requester=requester
        )
    except RepairSandboxError as exc:
        code = (
            exc.code
            if isinstance(exc.code, str)
            and re.fullmatch(r"REPAIR_[A-Z0-9_]{1,80}", exc.code)
            else "E_REPAIR_INVALID"
        )
        raise PRAssuranceError(code, "repair preflight validation failed") from None


def _current_repair_principal(principal, tenant_id, resolver, require_admin):
    if principal.tenant_id != tenant_id:
        if require_admin:
            raise PRAssuranceError("E_ACTION_DENIED", "current tenant admin required")
        raise PRAssuranceError("E_TENANT_BOUNDARY", "tenant identity differs")
    current = resolver(principal.subject, tenant_id)
    if (
        not isinstance(current, Principal)
        or current.subject != principal.subject
        or current.tenant_id != tenant_id
    ):
        if require_admin:
            raise PRAssuranceError("E_ACTION_DENIED", "current tenant admin required")
        raise PRAssuranceError("E_IDENTITY_REQUIRED", "current identity is unavailable")
    if require_admin and "admin" not in current.roles:
        raise PRAssuranceError("E_ACTION_DENIED", "current tenant admin required")
    return current


def _recovery_result(repair_id, status, recovery_status, reason, attempt_sha, facts):
    body = {
        "schema": "factory.hosted.repair-recovery.v1",
        "repair_id": repair_id,
        "status": status,
        "recovery_status": recovery_status,
        "reason_code": reason,
        "attempt_sha256": attempt_sha,
        "evidence_sha256": hashlib.sha256(canonical_json(facts)).hexdigest(),
    }
    body["recovery_sha256"] = hashlib.sha256(canonical_json(body)).hexdigest()
    return body


def _recovery_attempt_evidence(workspace, approval_path, binding):
    from .repair_sandbox import (
        _load_host_repair_approval,
        _attempt_directory,
        verify_repair_attempt_journal,
    )

    loaded = _load_host_repair_approval(workspace, approval_path)
    approval, approval_sha, file_sha, origin = (
        loaded[2],
        loaded[3],
        loaded[4],
        loaded[6],
    )
    if (
        approval_sha != binding["repair_approval_sha256"]
        or file_sha != binding["repair_approval_file_sha256"]
        or approval["patch_sha256"] != binding["patch_sha256"]
        or origin != binding.get("origin_audit")
    ):
        raise PRAssuranceError("E_REPAIR_CHANGED", "registered repair changed")
    journal = verify_repair_attempt_journal(workspace, approval_sha)
    state = journal["state"]
    _require_terminal_recovery_state(state, approval_sha, origin)
    attempt_dir = _attempt_directory(workspace, approval_sha)
    log_hashes = _verify_recovery_attempt_artifacts(
        workspace, attempt_dir, approval, approval_sha, state
    )
    _require_recovery_cleanup(workspace, attempt_dir, approval)
    facts = {
        "approval_sha256": approval_sha,
        "approval_file_sha256": file_sha,
        "patch_sha256": binding["patch_sha256"],
        "journal_sha256": journal["event_sha256"],
        "event_sequence": state["event_sequence"],
        "candidate_after_sha256": state.get("candidate_after_sha256"),
        "log_sha256s": log_hashes,
    }
    return journal["event_sha256"], facts


def _require_terminal_recovery_state(state, approval_sha, origin):
    expected_before = origin["candidate_sha256"] if origin else None
    expected_after = origin is not None
    if not _recovery_state_binding_valid(
        state, approval_sha, origin, expected_before
    ) or not _recovery_state_candidate_valid(state, expected_after):
        raise PRAssuranceError(
            "E_REPAIR_RECOVERY_INCOMPLETE", "attempt evidence is not terminal"
        )


def _recovery_state_binding_valid(state, approval_sha, origin, expected_before):
    return (
        state.get("approval_sha256") == approval_sha
        and state.get("origin_audit") == origin
        and state.get("candidate_before_sha256") == expected_before
        and state.get("cleanup_confirmed") is True
        and state.get("primary_checkout_unchanged") is True
    )


def _recovery_state_candidate_valid(state, expected_after):
    return (
        state.get("status") == "VERIFIED"
        and state.get("phase") == "VERIFIED"
        and (
            _is_digest(state.get("candidate_after_sha256"))
            if expected_after
            else state.get("candidate_after_sha256") is None
        )
    )


def _verify_recovery_attempt_artifacts(
    workspace, attempt, approval, approval_sha, state
):
    from .deep_audit_io import local_file

    patch_rel = f".factory/repair-attempts/{approval_sha}/candidate.patch"
    patch = local_file(workspace, patch_rel).read_bytes()
    if hashlib.sha256(patch).hexdigest() != approval["patch_sha256"]:
        raise PRAssuranceError("E_REPAIR_PATCH_DRIFT", "attempt patch changed")
    expected = {
        (stage, check["id"]): _expected_recovery_check(stage, check)
        for stage in ("baseline", "repaired")
        for check in approval["tool_contract"]["checks"]
    }
    rows = state.get("checks")
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise PRAssuranceError(
            "E_REPAIR_CHECK_EVIDENCE", "attempt checks are incomplete"
        )
    return _verify_recovery_check_logs(workspace, approval_sha, expected, rows)


def _expected_recovery_check(stage, check):
    failing = stage == "baseline" or check["kind"] == "negative"
    return {
        "log": f"{stage}-{check['id']}.log",
        "expected": "failure" if failing else "success",
        "exit_code": check["failure"]["exit_code"] if failing else 0,
        "signature": check["failure"]["signature"] if failing else None,
    }


def _verify_recovery_check_logs(workspace, approval_sha, expected, rows):
    observed, log_hashes, total = set(), [], 0
    for row in rows:
        key, name, actual, size = _recovery_check_log(
            workspace, approval_sha, expected, row
        )
        if key in observed:
            raise PRAssuranceError(
                "E_REPAIR_CHECK_EVIDENCE", "attempt checks are duplicated"
            )
        total += size
        if size > 2_000_000 or total > 32_000_000:
            raise PRAssuranceError(
                "E_REPAIR_CHECK_EVIDENCE", "attempt check logs exceed limits"
            )
        observed.add(key)
        log_hashes.append(actual)
    if observed != set(expected):
        raise PRAssuranceError(
            "E_REPAIR_CHECK_EVIDENCE", "attempt checks are incomplete"
        )
    return sorted(log_hashes)


def _recovery_check_log(workspace, approval_sha, expected, row):
    from .deep_audit_io import local_file

    if not isinstance(row, dict):
        raise PRAssuranceError("E_REPAIR_CHECK_EVIDENCE", "attempt check is invalid")
    key = (row.get("stage"), row.get("check_id"))
    if key not in expected or not _recovery_check_record_matches(row, expected[key]):
        raise PRAssuranceError("E_REPAIR_CHECK_EVIDENCE", "attempt check is invalid")
    name = expected[key]["log"]
    path = local_file(workspace, f".factory/repair-attempts/{approval_sha}/{name}")
    size = path.stat().st_size
    if size > 2_000_000:
        raise PRAssuranceError(
            "E_REPAIR_CHECK_EVIDENCE", "attempt check log exceeds limit"
        )
    raw = path.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != row["log_sha256"] or not _expected_check_signature(raw, expected[key]):
        raise PRAssuranceError("E_REPAIR_CHECK_EVIDENCE", "attempt check log changed")
    return key, name, actual, size


def _recovery_check_record_matches(row, expected):
    return (
        row.get("result") == "PASS"
        and row.get("expected") == expected["expected"]
        and row.get("exit_code") == expected["exit_code"]
        and row.get("log") == expected["log"]
        and _is_digest(row.get("log_sha256"))
        and row.get("process_cleanup_confirmed") is True
        and row.get("container_cleanup_confirmed") is True
        and row.get("worktree_unchanged") is True
    )


def _expected_check_signature(raw, expected):
    signature = expected["signature"]
    return signature is None or signature.encode("utf-8") in raw


def _require_recovery_cleanup(workspace, attempt, approval):
    from .repair_sandbox import _clean_base, _git

    execution = attempt / "execution"
    if _recovery_path_present(execution):
        raise PRAssuranceError("E_REPAIR_CLEANUP", "attempt worktree remains")
    worktrees = _git(workspace, ["worktree", "list", "--porcelain"])
    path_text = _normalize_worktree_path(str(execution))
    output = bytes(worktrees.get("stdout", b"")).decode("utf-8", errors="replace")
    registered_paths = _registered_worktree_paths(output)
    if not worktrees.get("ok") or path_text in registered_paths:
        raise PRAssuranceError(
            "E_REPAIR_CLEANUP", "attempt worktree is still registered"
        )
    _clean_base(workspace, approval["base_commit"])


def _registered_worktree_paths(output):
    paths = set()
    for line in output.splitlines():
        if line.startswith("worktree "):
            paths.add(_normalize_worktree_path(line[9:]))
    return paths


def _normalize_worktree_path(value):
    text = value.replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", text) or text.startswith("//"):
        return ntpath.normpath(text).replace("\\", "/").casefold()
    return str(Path(text).resolve()).replace("\\", "/").casefold()


def _recovery_path_present(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _is_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _safe_recovery_code(exc):
    code = getattr(exc, "code", "")
    return (
        code
        if isinstance(code, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{1,79}", code)
        else "E_REPAIR_RECOVERY_INVALID"
    )


@dataclass(frozen=True)
class HostedConfig:
    """Secret-bearing hosted configuration loaded by the deployment boundary."""

    issuer: str
    audience: str
    role_map: dict[str, str]
    webhook_secrets: dict[int, bytes]
    installation_tenants: dict[int, str]

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "HostedConfig":
        """Load required hosted identity and webhook configuration or fail closed."""
        env = dict(os.environ if environ is None else environ)
        issuer, audience = _identity_config(env)
        secrets, tenants, raw_roles = _configured_maps(env)
        _validate_installation_maps(secrets, tenants)
        return cls(
            issuer=issuer,
            audience=audience,
            role_map=raw_roles,
            webhook_secrets=secrets,
            installation_tenants=tenants,
        )


class HostedPRAssuranceService:
    """Compose PostgreSQL, OIDC, webhook, outbox, and publisher authority safely."""

    def __init__(
        self,
        *,
        store: PostgresAssuranceStore,
        jwks: JwksCache,
        publisher: GitHubAppPublisher,
        config: HostedConfig,
        event_sink: Callable[[dict[str, Any]], None] | None = None,
        control: PostgresControlStore | None = None,
        tenant_identity: TenantIdentityVerifier | None = None,
        secret_resolver: EnvSecretResolver | None = None,
        console_html: str = "",
        current_principal_resolver: Callable[[str, str], Principal] | None = None,
        repair_root: Path | None = None,
    ):
        self.store = store
        self.jwks = jwks
        self.publisher = publisher
        self.config = config
        self.event_sink = event_sink or (lambda _event: None)
        self.control = control
        self.tenant_identity = tenant_identity
        self.secret_resolver = secret_resolver
        self.console_html = console_html
        self.current_principal_resolver = current_principal_resolver
        self.repair_root = Path(repair_root).absolute() if repair_root else None

    def _repair_context(self, token: str, tenant_id: str, *, require_admin=False):
        resolver = self.current_principal_resolver
        if self.control is None or self.repair_root is None or not callable(resolver):
            raise PRAssuranceError(
                "E_REPAIR_UNAVAILABLE", "repair dispatch is disabled"
            )
        principal, _claims, _marker = self.authenticate(token)
        current = _current_repair_principal(
            principal, tenant_id, resolver, require_admin
        )
        return principal, current, resolver

    def provision_repair_target(
        self,
        token: str,
        tenant_id: str,
        *,
        repair_id: str,
        workspace_relative: str,
        approval_relative: str,
        workflow_approval_id: str,
    ) -> dict[str, Any]:
        """Provision from a verified tenant admin; this method has no HTTP route."""
        _principal, current, resolver = self._repair_context(
            token, tenant_id, require_admin=True
        )
        return self._provision_repair_target(
            current,
            resolver,
            tenant_id,
            repair_id,
            workspace_relative,
            approval_relative,
            workflow_approval_id,
        )

    def _provision_repair_target(
        self,
        current,
        resolver,
        tenant_id,
        repair_id,
        workspace_relative,
        approval_relative,
        workflow_approval_id,
    ):
        workspace = _trusted_repair_path(
            self.repair_root, workspace_relative, directory=True
        )
        approval = _trusted_repair_path(workspace, approval_relative, directory=False)
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,96}", repair_id) or not re.fullmatch(
            r"[A-Za-z0-9_-]{8,128}", workflow_approval_id
        ):
            raise PRAssuranceError("E_REPAIR_ID", "repair registration id is invalid")
        workflow_approval = self.control.get_approval(
            current, tenant_id, workflow_approval_id
        )
        requester = str(workflow_approval.get("requester", ""))
        current_requester = resolver(requester, tenant_id)
        if (
            not isinstance(current_requester, Principal)
            or current_requester.subject != requester
            or current_requester.tenant_id != tenant_id
        ):
            raise PRAssuranceError(
                "E_IDENTITY_REQUIRED",
                "current repair requester identity is unavailable",
            )
        from .control_plane import authorize

        authorize(current_requester, "repair.execute", tenant_id)
        binding = _repair_dispatch_binding_or_error(
            workspace, approval, tenant_id, requester
        )
        return self.control.register_hosted_repair(
            tenant_id=tenant_id,
            repair_id=repair_id,
            workspace_path=workspace.relative_to(self.repair_root).as_posix(),
            approval_path=approval.relative_to(workspace).as_posix(),
            workflow_approval_id=workflow_approval_id,
            requester=requester,
            binding=binding,
            registered_by=current.subject,
        )

    def execute_registered_repair(
        self, token: str, tenant_id: str, repair_id: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        """Dispatch one tenant-registered target after verified bearer authentication."""
        if body != {}:
            raise PRAssuranceError("E_REPAIR_BODY", "request body must be empty")
        principal, current, resolver = self._repair_context(token, tenant_id)
        try:
            return self._dispatch_registered_repair(
                principal, current, resolver, tenant_id, repair_id
            )
        except (ControlPlaneError, OSError) as exc:
            raise PRAssuranceError(
                getattr(exc, "code", "E_REPAIR_DISPATCH"),
                "repair dispatch was rejected",
            ) from None

    def _dispatch_registered_repair(
        self, principal, current, resolver, tenant_id, repair_id
    ):
        with self.control.hosted_repair_session_lock(tenant_id, repair_id):
            return self._dispatch_registered_repair_locked(
                principal, current, resolver, tenant_id, repair_id
            )

    def _dispatch_registered_repair_locked(
        self, principal, current, resolver, tenant_id, repair_id
    ):
        target, workspace, approval = self._registered_repair_inputs(
            current, tenant_id, repair_id
        )
        self.control.claim_hosted_repair(tenant_id, repair_id, current.subject)
        from .repair_sandbox import execute_workflow_approved_repair

        try:
            result = execute_workflow_approved_repair(
                workspace,
                approval,
                principal=principal,
                tenant_id=tenant_id,
                workflow_approval_id=target["workflow_approval_id"],
                evidence_store=self.control,
                resolve_principal=resolver,
            )
        except Exception:
            self.control.finish_hosted_repair(
                tenant_id, repair_id, succeeded=False, actor=current.subject
            )
            raise PRAssuranceError(
                "E_REPAIR_DISPATCH", "repair dispatch failed"
            ) from None
        if result.get("status") != "VERIFIED":
            self.control.finish_hosted_repair(
                tenant_id, repair_id, succeeded=False, actor=current.subject
            )
            raise PRAssuranceError("E_REPAIR_DISPATCH", "repair did not complete")
        self.control.finish_hosted_repair(
            tenant_id, repair_id, succeeded=True, actor=current.subject
        )
        self._emit("repair.dispatched", tenant_id=tenant_id, status="completed")
        return {
            "schema": "factory.hosted.repair.v1",
            "repair_id": repair_id,
            "status": "completed",
        }

    def _registered_repair_inputs(self, current, tenant_id, repair_id):
        from .control_plane import authorize

        authorize(current, "repair.execute", tenant_id)
        target = self.control.get_hosted_repair(tenant_id, repair_id)
        if target["requester"] != current.subject:
            raise PRAssuranceError("E_ACTION_DENIED", "repair requester differs")
        workspace = _trusted_repair_path(
            self.repair_root, target["workspace_path"], directory=True
        )
        approval = _trusted_repair_path(
            workspace, target["approval_path"], directory=False
        )
        binding = _repair_dispatch_binding_or_error(
            workspace, approval, tenant_id, current.subject
        )
        if binding != target["binding"]:
            raise PRAssuranceError("E_REPAIR_CHANGED", "registered repair changed")
        return target, workspace, approval

    def reconcile_registered_repair(
        self, token: str, tenant_id: str, repair_id: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        """Inspect an interrupted dispatch as a current tenant admin; never rerun it."""
        if body != {}:
            raise PRAssuranceError("E_REPAIR_BODY", "request body must be empty")
        _principal, current, resolver = self._repair_context(
            token, tenant_id, require_admin=True
        )
        from .control_plane import authorize

        authorize(current, "repair.execute", tenant_id)
        with self.control.hosted_repair_session_lock(tenant_id, repair_id):
            return self._reconcile_registered_repair_locked(
                current, resolver, tenant_id, repair_id
            )

    def _reconcile_registered_repair_locked(
        self, current, resolver, tenant_id, repair_id
    ):
        target = self.control.get_hosted_repair(tenant_id, repair_id)
        previous = target.get("recovery")
        if previous is not None:
            if previous.get("repair_id") != repair_id:
                raise PRAssuranceError(
                    "E_REPAIR_REGISTRY", "repair recovery record is invalid"
                )
            return previous
        if target["status"] != "executing":
            raise PRAssuranceError(
                "E_REPAIR_RECOVERY_STATE", "repair is not awaiting recovery"
            )
        try:
            outcome = self._inspect_repair_recovery(
                target, resolver, tenant_id, repair_id
            )
        except Exception as exc:
            if getattr(exc, "code", "").startswith("E_DATABASE"):
                raise
            reason = _safe_recovery_code(exc)
            refusal_sha = hashlib.sha256(
                canonical_json(
                    {
                        "binding_sha256": hashlib.sha256(
                            canonical_json(target["binding"])
                        ).hexdigest(),
                        "reason_code": reason,
                        "status": "executing",
                    }
                )
            ).hexdigest()
            raise PRAssuranceError(
                "E_REPAIR_RECOVERY_PENDING",
                f"executor stop is unverified; repair remains executing; "
                f"evidence review required ({reason}, {refusal_sha})",
            )
        return self.control.reconcile_hosted_repair(
            tenant_id, repair_id, actor=current.subject, recovery=outcome
        )

    def _inspect_repair_recovery(self, target, resolver, tenant_id, repair_id):
        workspace = _trusted_repair_path(
            self.repair_root, target["workspace_path"], directory=True
        )
        approval = _trusted_repair_path(
            workspace, target["approval_path"], directory=False
        )
        binding = _repair_dispatch_binding_or_error(
            workspace, approval, tenant_id, target["requester"]
        )
        if binding != target["binding"]:
            raise PRAssuranceError("E_REPAIR_CHANGED", "registered repair changed")
        self._verify_recovery_approval(target, resolver, tenant_id, binding)
        attempt_sha, facts = _recovery_attempt_evidence(workspace, approval, binding)
        return _recovery_result(
            repair_id,
            "completed",
            "reconciled_completed",
            "REPAIR_RECOVERED_VERIFIED",
            attempt_sha,
            facts,
        )

    def _verify_recovery_approval(self, target, resolver, tenant_id, binding):
        requester = resolver(target["requester"], tenant_id)
        if (
            not isinstance(requester, Principal)
            or requester.subject != target["requester"]
            or requester.tenant_id != tenant_id
        ):
            raise ControlPlaneError(
                "E_IDENTITY_REQUIRED", "current repair requester identity differs"
            )
        from .control_plane import authorize

        authorize(requester, "repair.execute", tenant_id)
        verifier = self.control.workflow_approval_verifier(
            requester,
            tenant_id,
            target["workflow_approval_id"],
            resolve_principal=resolver,
            require_requester=True,
        )
        verifier(binding)

    def _emit(self, operation: str, **fields: Any) -> None:
        allowed = {
            key: value
            for key, value in fields.items()
            if key
            in {
                "tenant_id",
                "installation_id",
                "repository",
                "approval_id",
                "outbox_id",
                "status",
                "error_code",
            }
        }
        self.event_sink(
            {"schema": "factory.hosted.operation.v1", "operation": operation, **allowed}
        )

    def health(self) -> dict[str, Any]:
        """Return a process-liveness response without probing dependencies."""
        return {"schema": "factory.hosted.health.v1", "ok": True}

    def ready(self) -> dict[str, Any]:
        """Return ready only when PostgreSQL and a usable JWKS are available."""
        if not self.store.ping():
            raise PRAssuranceError(
                "E_DATABASE_UNAVAILABLE", "PostgreSQL readiness failed"
            )
        get_jwks(self.jwks)
        return {
            "schema": "factory.hosted.readiness.v1",
            "ready": True,
            "marker": "JWKS_ROTATION_PINNED",
        }

    def ingest(self, body: bytes, headers: Mapping[str, str]) -> dict[str, Any]:
        """Route by installation, verify HMAC, and commit one tenant PR request."""
        installation_id = _installation_id(body)
        tenant_id = self.store.tenant_for_installation(installation_id)
        dynamic = False
        secret = None
        if self.control is not None and self.secret_resolver is not None:
            try:
                configured_tenant, reference = (
                    self.control.secret_reference_for_installation(
                        installation_id, "github_webhook"
                    )
                )
                if configured_tenant != tenant_id:
                    raise PRAssuranceError(
                        "E_TENANT_BOUNDARY",
                        "installation secret tenant differs from route",
                    )
                secret = self.secret_resolver.resolve(reference)
                dynamic = True
            except PRAssuranceError as exc:
                if installation_id not in self.config.webhook_secrets:
                    raise exc
        secret = secret or self.config.webhook_secrets.get(installation_id)
        if secret is None:
            raise PRAssuranceError(
                "E_SECRET_UNAVAILABLE", "installation webhook secret is unavailable"
            )
        event = verify_github_webhook(body, headers, secret)
        result = self.store.ingest(tenant_id, event)
        result["markers"].append("HOSTED_AUTH_BOUNDARY")
        if dynamic:
            result["markers"].append("DYNAMIC_WEBHOOK_SECRET_BOUND")
        self._emit(
            "webhook.accepted",
            tenant_id=tenant_id,
            installation_id=installation_id,
            repository=event.repository,
            approval_id=result["approval_id"],
            status="pending",
        )
        return result

    def decide(
        self, approval_id: str, token: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        """Verify OIDC identity and atomically queue one terminal GitHub Check."""
        principal, claims, identity_marker = self.authenticate(token)
        result = self.store.decide(
            principal,
            approval_id,
            issuer=claims["iss"],
            jti=claims["jti"],
            decision=str(body.get("decision", "")),
            reason=str(body.get("reason", "")),
        )
        result["markers"].extend(["JWKS_ROTATION_PINNED", "HOSTED_AUTH_BOUNDARY"])
        if identity_marker:
            result["markers"].append(identity_marker)
        self._emit(
            "approval.decided",
            tenant_id=principal.tenant_id,
            approval_id=approval_id,
            outbox_id=result["outbox_id"],
            status=result["status"],
        )
        return result

    def authenticate(self, token: str) -> tuple[Any, dict[str, Any], str | None]:
        """Verify a dynamic tenant or bootstrap OIDC token and return its principal."""
        bootstrap_only = False
        if self.tenant_identity is not None:
            try:
                principal, claims = self.tenant_identity.verify(token)
                return principal, claims, "TENANT_IDENTITY_VERIFIED"
            except PRAssuranceError as exc:
                if exc.code != "E_TENANT_INVALID":
                    raise
                bootstrap_only = True
        jwks = get_jwks(self.jwks)
        claims = verify_oidc_token(
            token, jwks, self.config.issuer, self.config.audience
        )
        principal = principal_from_verified_oidc(
            claims, expected_issuer=self.config.issuer, role_map=self.config.role_map
        )
        if bootstrap_only and not (
            principal.tenant_id == "*" and "platform_admin" in principal.roles
        ):
            raise PRAssuranceError(
                "E_TENANT_BOUNDARY",
                "bootstrap identity requires platform_admin tenant authority",
            )
        return principal, claims, None

    def create_tenant(self, token: str, body: dict[str, Any]) -> dict[str, Any]:
        """Create one tenant through verified bootstrap authority or refuse the request."""
        if self.control is None:
            raise PRAssuranceError(
                "E_CONTROL_UNAVAILABLE", "hosted control plane is unavailable"
            )
        principal, _claims, _marker = self.authenticate(token)
        return self.control.create_tenant(
            principal, str(body.get("tenant_id", "")), str(body.get("display_name", ""))
        )

    def configure_identity(
        self, token: str, tenant_id: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        """Store one tenant's public OIDC verification configuration or refuse it."""
        if self.control is None:
            raise PRAssuranceError(
                "E_CONTROL_UNAVAILABLE", "hosted control plane is unavailable"
            )
        principal, _claims, _marker = self.authenticate(token)
        return self.control.configure_identity(
            principal,
            tenant_id,
            issuer=str(body.get("issuer", "")),
            audience=str(body.get("audience", "")),
            jwks_url=str(body.get("jwks_url", "")),
        )

    def replace_roles(
        self, token: str, tenant_id: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        """Replace one tenant role map through verified administrative authority."""
        if self.control is None:
            raise PRAssuranceError(
                "E_CONTROL_UNAVAILABLE", "hosted control plane is unavailable"
            )
        principal, _claims, _marker = self.authenticate(token)
        mappings = body.get("mappings")
        if not isinstance(mappings, dict):
            raise PRAssuranceError("E_ROLE_MAPPING", "mappings must be a JSON object")
        return self.control.replace_roles(principal, tenant_id, mappings)

    def set_secret_reference(
        self, token: str, tenant_id: str, purpose: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        """Store a secret-manager reference through verified administrative authority."""
        if self.control is None:
            raise PRAssuranceError(
                "E_CONTROL_UNAVAILABLE", "hosted control plane is unavailable"
            )
        principal, _claims, _marker = self.authenticate(token)
        return self.control.set_secret_reference(
            principal, tenant_id, purpose, str(body.get("reference", ""))
        )

    def issue_installation_state(self, token: str, tenant_id: str) -> dict[str, Any]:
        """Issue one tenant-bound GitHub installation state or refuse the request."""
        if self.control is None:
            raise PRAssuranceError(
                "E_CONTROL_UNAVAILABLE", "hosted control plane is unavailable"
            )
        principal, _claims, _marker = self.authenticate(token)
        return self.control.issue_state(principal, tenant_id)

    def bind_installation(self, body: dict[str, Any]) -> dict[str, Any]:
        """Consume one installation callback state or reject replay and reassignment."""
        if self.control is None:
            raise PRAssuranceError(
                "E_CONTROL_UNAVAILABLE", "hosted control plane is unavailable"
            )
        installation_id = body.get("installation_id")
        if not isinstance(installation_id, int) or isinstance(installation_id, bool):
            raise PRAssuranceError(
                "E_INSTALLATION_STATE", "positive installation_id is required"
            )
        return self.control.bind_installation(
            str(body.get("state", "")), installation_id
        )

    def overview(self, token: str, tenant_id: str) -> dict[str, Any]:
        """Return one redacted tenant overview through verified read authority."""
        if self.control is None:
            raise PRAssuranceError(
                "E_CONTROL_UNAVAILABLE", "hosted control plane is unavailable"
            )
        principal, _claims, _marker = self.authenticate(token)
        return self.control.overview(principal, tenant_id)

    def dispatch(self, tenant_id: str, *, limit: int = 20) -> list[dict[str, Any]]:
        """Dispatch one bounded tenant outbox batch and retain classified failures."""
        results: list[dict[str, Any]] = []
        for record in self.store.claim_outbox(tenant_id, limit=limit):
            try:
                check_id = self.publisher.publish(
                    record.installation_id, record.repository, record.request
                )
                outcome = self.store.mark_published(record, check_id)
                self._emit(
                    "check.published",
                    tenant_id=tenant_id,
                    outbox_id=record.outbox_id,
                    status="published",
                )
            except PRAssuranceError as exc:
                outcome = self.store.mark_failed(record, exc.code)
                self._emit(
                    "check.failed",
                    tenant_id=tenant_id,
                    outbox_id=record.outbox_id,
                    status=outcome["marker"],
                    error_code=exc.code,
                )
            results.append(outcome)
        return results


class HostedPRAssuranceAPI:
    """WSGI surface exposing assurance and supervised hosted control routes."""

    def __init__(self, service: HostedPRAssuranceService):
        self.service = service

    def _dispatch_request(
        self,
        method: str,
        path: list[str],
        environ: dict[str, Any],
        start_response: Callable,
    ) -> list[bytes]:
        for handler in (
            self._read_route,
            self._delivery_route,
            self._tenant_admin_route,
        ):
            response = handler(method, path, environ, start_response)
            if response is not None:
                return response
        raise PRAssuranceError("E_NOT_FOUND", "hosted route not found")

    def _read_route(
        self,
        method: str,
        path: list[str],
        _environ: dict[str, Any],
        start_response: Callable,
    ) -> list[bytes] | None:
        if method == "GET" and path == ["healthz"]:
            return _finish(start_response, "200 OK", self.service.health())
        if method == "GET" and path == ["readyz"]:
            return _finish(start_response, "200 OK", self.service.ready())
        if method == "GET" and path == ["console"]:
            if not self.service.console_html:
                raise PRAssuranceError("E_NOT_FOUND", "operator console is unavailable")
            return _finish_html(start_response, self.service.console_html)
        return None

    def _delivery_route(
        self,
        method: str,
        path: list[str],
        environ: dict[str, Any],
        start_response: Callable,
    ) -> list[bytes] | None:
        for handler in (
            self._webhook_route,
            self._approval_route,
            self._repair_execute_route,
            self._repair_reconcile_route,
            self._installation_callback_route,
            self._tenant_create_route,
        ):
            response = handler(method, path, environ, start_response)
            if response is not None:
                return response
        return None

    def _repair_execute_route(
        self,
        method: str,
        path: list[str],
        environ: dict[str, Any],
        start_response: Callable,
    ) -> list[bytes] | None:
        if (
            method != "POST"
            or len(path) != 6
            or path[:2] != ["v1", "tenants"]
            or path[3] != "repairs"
            or path[5] != "execute"
        ):
            return None
        body = _json_body(environ)
        if body != {}:
            raise PRAssuranceError("E_REPAIR_BODY", "request body must be empty")
        return _finish(
            start_response,
            "200 OK",
            self.service.execute_registered_repair(
                _bearer(environ), path[2], path[4], body
            ),
        )

    def _repair_reconcile_route(
        self,
        method: str,
        path: list[str],
        environ: dict[str, Any],
        start_response: Callable,
    ) -> list[bytes] | None:
        if (
            method != "POST"
            or len(path) != 6
            or path[:2] != ["v1", "tenants"]
            or path[3] != "repairs"
            or path[5] != "reconcile"
        ):
            return None
        body = _json_body(environ)
        if body != {}:
            raise PRAssuranceError("E_REPAIR_BODY", "request body must be empty")
        return _finish(
            start_response,
            "200 OK",
            self.service.reconcile_registered_repair(
                _bearer(environ), path[2], path[4], body
            ),
        )

    def _webhook_route(
        self,
        method: str,
        path: list[str],
        environ: dict[str, Any],
        start_response: Callable,
    ) -> list[bytes] | None:
        if method != "POST" or path != ["v1", "github", "webhooks"]:
            return None
        body = _read_body(environ, MAX_WEBHOOK_BYTES)
        headers = {
            "X-Hub-Signature-256": str(environ.get("HTTP_X_HUB_SIGNATURE_256", "")),
            "X-GitHub-Event": str(environ.get("HTTP_X_GITHUB_EVENT", "")),
            "X-GitHub-Delivery": str(environ.get("HTTP_X_GITHUB_DELIVERY", "")),
        }
        return _finish(
            start_response, "202 Accepted", self.service.ingest(body, headers)
        )

    def _approval_route(
        self,
        method: str,
        path: list[str],
        environ: dict[str, Any],
        start_response: Callable,
    ) -> list[bytes] | None:
        if (
            method != "POST"
            or len(path) != 4
            or path[:2] != ["v1", "approvals"]
            or path[3] != "decision"
        ):
            return None
        return _finish(
            start_response,
            "202 Accepted",
            self.service.decide(path[2], _bearer(environ), _json_body(environ)),
        )

    def _installation_callback_route(
        self,
        method: str,
        path: list[str],
        environ: dict[str, Any],
        start_response: Callable,
    ) -> list[bytes] | None:
        if method != "POST" or path != [
            "v1",
            "github",
            "installations",
            "callback",
        ]:
            return None
        return _finish(
            start_response,
            "201 Created",
            self.service.bind_installation(_json_body(environ)),
        )

    def _tenant_create_route(
        self,
        method: str,
        path: list[str],
        environ: dict[str, Any],
        start_response: Callable,
    ) -> list[bytes] | None:
        if method != "POST" or path != ["v1", "admin", "tenants"]:
            return None
        return _finish(
            start_response,
            "201 Created",
            self.service.create_tenant(_bearer(environ), _json_body(environ)),
        )

    def _tenant_admin_route(
        self,
        method: str,
        path: list[str],
        environ: dict[str, Any],
        start_response: Callable,
    ) -> list[bytes] | None:
        if len(path) < 4 or path[:3] != ["v1", "admin", "tenants"]:
            return None
        tenant_id = path[3]
        for handler in (
            self._tenant_identity_route,
            self._tenant_roles_route,
            self._tenant_secret_route,
            self._tenant_installation_state_route,
            self._tenant_overview_route,
        ):
            response = handler(method, path, environ, start_response, tenant_id)
            if response is not None:
                return response
        return None

    def _tenant_identity_route(
        self,
        method: str,
        path: list[str],
        environ: dict[str, Any],
        start_response: Callable,
        tenant_id: str,
    ) -> list[bytes] | None:
        if method != "PUT" or len(path) != 5 or path[4] != "identity":
            return None
        return _finish(
            start_response,
            "200 OK",
            self.service.configure_identity(
                _bearer(environ), tenant_id, _json_body(environ)
            ),
        )

    def _tenant_roles_route(
        self,
        method: str,
        path: list[str],
        environ: dict[str, Any],
        start_response: Callable,
        tenant_id: str,
    ) -> list[bytes] | None:
        if method != "PUT" or len(path) != 5 or path[4] != "roles":
            return None
        return _finish(
            start_response,
            "200 OK",
            self.service.replace_roles(
                _bearer(environ), tenant_id, _json_body(environ)
            ),
        )

    def _tenant_secret_route(
        self,
        method: str,
        path: list[str],
        environ: dict[str, Any],
        start_response: Callable,
        tenant_id: str,
    ) -> list[bytes] | None:
        if method != "PUT" or len(path) != 6 or path[4] != "secrets":
            return None
        return _finish(
            start_response,
            "200 OK",
            self.service.set_secret_reference(
                _bearer(environ), tenant_id, path[5], _json_body(environ)
            ),
        )

    def _tenant_installation_state_route(
        self,
        method: str,
        path: list[str],
        environ: dict[str, Any],
        start_response: Callable,
        tenant_id: str,
    ) -> list[bytes] | None:
        if method != "POST" or len(path) != 5 or path[4] != "installation-state":
            return None
        return _finish(
            start_response,
            "201 Created",
            self.service.issue_installation_state(_bearer(environ), tenant_id),
        )

    def _tenant_overview_route(
        self,
        method: str,
        path: list[str],
        environ: dict[str, Any],
        start_response: Callable,
        tenant_id: str,
    ) -> list[bytes] | None:
        if method != "GET" or len(path) != 5 or path[4] != "overview":
            return None
        return _finish(
            start_response,
            "200 OK",
            self.service.overview(_bearer(environ), tenant_id),
        )

    def __call__(
        self, environ: dict[str, Any], start_response: Callable
    ) -> list[bytes]:
        method = str(environ.get("REQUEST_METHOD", "GET")).upper()
        path = [
            unquote(part)
            for part in urlsplit(str(environ.get("PATH_INFO", "/"))).path.split("/")
            if part
        ]
        try:
            return self._dispatch_request(method, path, environ, start_response)
        except PRAssuranceError as exc:
            return self._error_response(exc, start_response)

    def _error_response(
        self, exc: PRAssuranceError, start_response: Callable
    ) -> list[bytes]:
        status = _status_for(exc.code)
        self.service._emit(
            "request.rejected", error_code=exc.code, status=status.split()[0]
        )
        return _finish(
            start_response,
            status,
            {
                "schema": "factory.hosted.result.v1",
                "verdict": "ERROR",
                "error": {"code": exc.code, "message": exc.message},
            },
        )


def _status_for(code: str) -> str:
    if code in {"E_NOT_FOUND", "E_REPAIR_NOT_FOUND"}:
        return "404 Not Found"
    if code in {"E_AUTH_REQUIRED", "E_OIDC_SIGNATURE", "E_OIDC_EXPIRED"}:
        return "401 Unauthorized"
    if code in {"E_ACTION_DENIED", "E_TENANT_BOUNDARY", "E_SELF_APPROVAL"}:
        return "403 Forbidden"
    if code in {
        "E_WEBHOOK_REPLAY",
        "E_ALREADY_DECIDED",
        "E_OIDC_REPLAY",
        "E_REPAIR_EXISTS",
        "E_REPAIR_REPLAY",
        "E_REPAIR_CHANGED",
        "E_REPAIR_BUSY",
        "E_REPAIR_RECOVERY_STATE",
        "E_REPAIR_RECOVERY_CONFLICT",
        "E_REPAIR_RECOVERY_PENDING",
    }:
        return "409 Conflict"
    if code in {"E_INSTALLATION_STATE", "E_INSTALLATION_TENANT", "E_TENANT_CONFLICT"}:
        return "409 Conflict"
    if code.startswith("E_DATABASE") or code.startswith("E_JWKS"):
        return "503 Service Unavailable"
    if code in {"E_CONTROL_UNAVAILABLE", "E_REPAIR_UNAVAILABLE"}:
        return "503 Service Unavailable"
    return "400 Bad Request"


def create_hosted_app(service: HostedPRAssuranceService) -> HostedPRAssuranceAPI:
    """Create the authenticated WSGI surface without caller-controlled tenants."""
    return HostedPRAssuranceAPI(service)


def create_hosted_app_from_env(
    environ: Mapping[str, str] | None = None,
) -> HostedPRAssuranceAPI:
    """Construct the production adapter from secret-bearing environment configuration."""
    env = dict(os.environ if environ is None else environ)
    required = (
        "FACTORY_DATABASE_URL",
        "FACTORY_JWKS_URL",
        "FACTORY_GITHUB_APP_ID",
        "FACTORY_GITHUB_PRIVATE_KEY",
    )
    if any(not env.get(name) for name in required):
        raise PRAssuranceError(
            "E_HOSTED_CONFIG",
            "database, JWKS, and GitHub App configuration are required",
        )
    config = HostedConfig.from_env(env)
    transport = HttpxTransport()
    store = PostgresAssuranceStore(env["FACTORY_DATABASE_URL"])
    store.initialize()
    control = PostgresControlStore(store)
    control.initialize()
    for installation_id, tenant_id in config.installation_tenants.items():
        store.register_installation(tenant_id, installation_id)
    service = HostedPRAssuranceService(
        store=store,
        jwks=JwksCache(env["FACTORY_JWKS_URL"], transport),
        publisher=GitHubAppPublisher(
            app_id=int(env["FACTORY_GITHUB_APP_ID"]),
            private_key_pem=env["FACTORY_GITHUB_PRIVATE_KEY"].replace("\\n", "\n"),
            transport=transport,
        ),
        config=config,
        control=control,
        tenant_identity=TenantIdentityVerifier(control, transport),
        secret_resolver=EnvSecretResolver(env),
        console_html=resources.files("factoryline")
        .joinpath("hosted_console.html")
        .read_text(encoding="utf-8"),
    )
    return create_hosted_app(service)
