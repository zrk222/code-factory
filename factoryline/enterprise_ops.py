"""Enterprise operations primitives for the local Code Factory golden path.

The module deliberately composes the existing proof and control-plane ideas into
one small, portable operations surface.  It provides a tenant-bound evidence
workspace, an auditable identity lifecycle, an explicit proof-runner policy,
required-check evaluation, outcome telemetry, SLA readiness, and a compact
status read model.  The Docker runner is the only backend labelled isolated;
the process backend is always labelled as a process boundary.

No function in this module grants merge, deployment, billing, hosted identity,
or contractual SLA authority.  Those boundaries are returned in every
operator-facing receipt so a local success cannot be mistaken for a managed
enterprise service.
"""
from __future__ import annotations

from base64 import b64decode
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import time
from typing import Any, Iterable

from .e2e_proof import _run_command


OPS_SCHEMA = "factory.enterprise-ops.v1"
EVIDENCE_SCHEMA = "factory.enterprise-ops.evidence.v1"
IDENTITY_SCHEMA = "factory.enterprise-ops.identity.v1"
RUNNER_SCHEMA = "factory.enterprise-ops.runner.v1"
CHECK_SCHEMA = "factory.enterprise-ops.required-checks.v1"
OUTCOME_SCHEMA = "factory.enterprise-ops.outcome.v1"
SLA_SCHEMA = "factory.enterprise-ops.sla-readiness.v1"
OTEL_SCHEMA = "factory.enterprise-ops.otel.v1"
OPS_DIR = ".factory/ops"
TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
SUBJECT_RE = re.compile(r"^[A-Za-z0-9._:@/+-]{1,160}$")
ROLE_SET = frozenset({"viewer", "operator", "reviewer", "service_owner", "admin"})
STATUS_SET = frozenset({"active", "suspended", "revoked"})
KNOWN_SLA_GATES = (
    "support_owner",
    "escalation_channel",
    "production_telemetry",
    "dependency_mapping",
    "restore_drill",
    "legal_security_terms",
    "signed_acceptance",
)
SAFE_RESULT_SET = frozenset({"success", "failure", "deployed", "rolled_back", "incident", "aborted"})


class EnterpriseOpsError(ValueError):
    """Stable fail-closed error for the enterprise operations surface."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise EnterpriseOpsError("E_OPS_NON_CANONICAL", f"value is not canonical JSON: {exc}") from exc


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _require(value: Any, name: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EnterpriseOpsError("E_OPS_REQUIRED", f"{name} is required")
    normalized = value.strip()
    if pattern is not None and not pattern.fullmatch(normalized):
        raise EnterpriseOpsError("E_OPS_INVALID", f"{name} has an unsupported format")
    return normalized


def _tenant(value: Any) -> str:
    return _require(value, "tenant_id", TENANT_RE)


def _subject(value: Any) -> str:
    return _require(value, "subject", SUBJECT_RE)


def _ops_root(root: Path) -> Path:
    return Path(root).resolve()


def _ops_dir(root: Path, *, create: bool = True) -> Path:
    directory = _ops_root(root) / OPS_DIR
    if create:
        directory.mkdir(parents=True, exist_ok=True)
    return directory


def _config_path(root: Path) -> Path:
    return _ops_dir(root) / "config.json"


def _identity_path(root: Path) -> Path:
    return _ops_dir(root) / "identities.json"


def _db_path(root: Path) -> Path:
    return _ops_dir(root) / "evidence.db"


def _outcomes_path(root: Path) -> Path:
    return _ops_dir(root) / "outcomes.jsonl"


def _atomic_json(path: Path, payload: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return path


def _load_json(path: Path, *, code: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnterpriseOpsError(code, f"unable to read {path.name}: {exc}") from exc


def _connect(root: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(_db_path(root))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _ensure_initialized(root: Path) -> dict[str, Any]:
    config_path = _config_path(root)
    identity_path = _identity_path(root)
    if not config_path.exists() or not identity_path.exists() or not _db_path(root).exists():
        raise EnterpriseOpsError("E_OPS_NOT_INITIALIZED", "run factory ops init before using the operations workspace")
    config = _load_json(config_path, code="E_OPS_CONFIG_INVALID")
    if not isinstance(config, dict) or config.get("schema") != OPS_SCHEMA:
        raise EnterpriseOpsError("E_OPS_CONFIG_INVALID", "operations config has an unsupported schema")
    _tenant(config.get("tenant_id"))
    return config


def _initialize_db(root: Path) -> None:
    with _connect(root) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                verdict TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                inserted_by TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS evidence_tenant_created
              ON evidence(tenant_id, created_at, evidence_id);
            CREATE TABLE IF NOT EXISTS audit_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS audit_tenant_sequence
              ON audit_events(tenant_id, sequence);
            """
        )


def _identities(root: Path) -> list[dict[str, Any]]:
    value = _load_json(_identity_path(root), code="E_IDENTITY_REGISTRY_INVALID")
    if not isinstance(value, dict) or value.get("schema") != IDENTITY_SCHEMA or not isinstance(value.get("identities"), list):
        raise EnterpriseOpsError("E_IDENTITY_REGISTRY_INVALID", "identity registry has an unsupported schema")
    return value["identities"]


def _identity(root: Path, tenant_id: str, subject: str) -> dict[str, Any]:
    matches = [item for item in _identities(root) if item.get("tenant_id") == tenant_id and item.get("subject") == subject]
    if not matches:
        raise EnterpriseOpsError("E_IDENTITY_UNKNOWN", "identity is not provisioned in this tenant")
    item = matches[0]
    if item.get("status") != "active":
        raise EnterpriseOpsError("E_IDENTITY_INACTIVE", "identity is suspended or revoked")
    return item


def _authorize(root: Path, tenant_id: str, subject: str, roles: Iterable[str]) -> dict[str, Any]:
    identity = _identity(root, tenant_id, subject)
    allowed = set(roles)
    if not allowed.intersection({str(identity.get("role")), *identity.get("roles", [])}):
        raise EnterpriseOpsError("E_ACTION_DENIED", "identity role does not authorize this operation")
    return identity


def _audit(root: Path, tenant_id: str, action: str, actor: str, resource_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    created_at = _now()
    payload_json = _canonical(payload).decode("utf-8")
    with _connect(root) as db:
        previous = db.execute(
            "SELECT event_hash FROM audit_events WHERE tenant_id = ? ORDER BY sequence DESC LIMIT 1", (tenant_id,)
        ).fetchone()
        previous_hash = str(previous["event_hash"]) if previous else ""
        db.execute(
            "INSERT INTO audit_events (tenant_id,action,actor,resource_id,payload_json,previous_hash,event_hash,created_at) VALUES (?,?,?,?,?,?,?,?)",
            (tenant_id, action, actor, resource_id, payload_json, previous_hash, "pending", created_at),
        )
        sequence = int(db.execute("SELECT last_insert_rowid()").fetchone()[0])
        event = {
            "schema": "factory.enterprise-ops.audit.v1",
            "sequence": sequence,
            "tenant_id": tenant_id,
            "action": action,
            "actor": actor,
            "resource_id": resource_id,
            "payload": payload,
            "previous_hash": previous_hash,
            "created_at": created_at,
        }
        event_hash = _sha(event)
        db.execute("UPDATE audit_events SET event_hash = ? WHERE sequence = ?", (event_hash, sequence))
    return {"sequence": sequence, "event_hash": event_hash}


def initialize_workspace(root: Path, tenant_id: str, owner: str, *, retention_days: int = 90, force: bool = False) -> dict[str, Any]:
    """Create the portable operations workspace and its initial active owner."""
    root = _ops_root(root)
    tenant_id, owner = _tenant(tenant_id), _subject(owner)
    if not isinstance(retention_days, int) or isinstance(retention_days, bool) or not 1 <= retention_days <= 3650:
        raise EnterpriseOpsError("E_RETENTION_INVALID", "retention_days must be between 1 and 3650")
    config_path = _config_path(root)
    if config_path.exists() and not force:
        raise EnterpriseOpsError("E_OPS_ALREADY_INITIALIZED", "operations workspace already exists; use --force only to replace it")
    _ops_dir(root)
    config = {
        "schema": OPS_SCHEMA,
        "marker": "OPS_WORKSPACE_INITIALIZED",
        "tenant_id": tenant_id,
        "retention_days": retention_days,
        "created_at": _now(),
        "golden_path": ["admit", "verify", "review", "approve", "release"],
        "authority": {"merge": False, "deploy": False, "billing": False, "sso_enrollment": False, "sla_activation": False},
    }
    _atomic_json(config_path, config)
    _atomic_json(_identity_path(root), {
        "schema": IDENTITY_SCHEMA,
        "marker": "IDENTITY_REGISTRY_INITIALIZED",
        "tenant_id": tenant_id,
        "identities": [{"subject": owner, "tenant_id": tenant_id, "role": "admin", "roles": ["admin"], "status": "active", "created_at": _now(), "updated_at": _now()}],
    })
    _initialize_db(root)
    _audit(root, tenant_id, "workspace.init", owner, tenant_id, {"retention_days": retention_days})
    return workspace_status(root)


def provision_identity(root: Path, tenant_id: str, subject: str, role: str, *, actor: str, status: str = "active") -> dict[str, Any]:
    """Provision, suspend, or revoke one local identity with an audit event."""
    config = _ensure_initialized(root)
    tenant_id, subject = _tenant(tenant_id), _subject(subject)
    if config["tenant_id"] != tenant_id:
        raise EnterpriseOpsError("E_TENANT_BOUNDARY", "identity tenant differs from the initialized operations tenant")
    role = _require(role, "role").lower()
    status = _require(status, "status").lower()
    if role not in ROLE_SET:
        raise EnterpriseOpsError("E_ROLE_INVALID", f"role must be one of {sorted(ROLE_SET)}")
    if status not in STATUS_SET:
        raise EnterpriseOpsError("E_IDENTITY_STATUS_INVALID", f"status must be one of {sorted(STATUS_SET)}")
    _authorize(root, tenant_id, _subject(actor), {"admin"})
    registry = _load_json(_identity_path(root), code="E_IDENTITY_REGISTRY_INVALID")
    rows = registry["identities"]
    now = _now()
    existing = next((item for item in rows if item.get("tenant_id") == tenant_id and item.get("subject") == subject), None)
    if existing:
        existing.update({"role": role, "roles": [role], "status": status, "updated_at": now})
        action = "identity.update"
    else:
        existing = {"subject": subject, "tenant_id": tenant_id, "role": role, "roles": [role], "status": status, "created_at": now, "updated_at": now}
        rows.append(existing)
        action = "identity.provision"
    _atomic_json(_identity_path(root), registry)
    audit = _audit(root, tenant_id, action, _subject(actor), subject, {"role": role, "status": status})
    return {"schema": IDENTITY_SCHEMA, "marker": "IDENTITY_LIFECYCLE_RECORDED", "eops_marker": "EOPS_IDENTITY_READY", "identity": existing, "audit": audit}


def put_evidence(root: Path, tenant_id: str, subject: str, payload: dict[str, Any], *, evidence_id: str | None = None) -> dict[str, Any]:
    """Store immutable tenant evidence only for an active operator or admin."""
    config = _ensure_initialized(root)
    tenant_id, subject = _tenant(tenant_id), _subject(subject)
    if config["tenant_id"] != tenant_id:
        raise EnterpriseOpsError("E_TENANT_BOUNDARY", "evidence tenant differs from the initialized operations tenant")
    _authorize(root, tenant_id, subject, {"operator", "admin", "reviewer"})
    if not isinstance(payload, dict) or payload.get("tenant_id") != tenant_id:
        raise EnterpriseOpsError("E_EVIDENCE_TENANT", "evidence payload must be an object bound to the selected tenant")
    supplied_id = evidence_id or "ev-" + _sha(payload)[:32]
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", supplied_id):
        raise EnterpriseOpsError("E_EVIDENCE_ID_INVALID", "evidence_id has an unsupported format")
    digest = _sha(payload)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=int(config["retention_days"]))
    with _connect(root) as db:
        existing = db.execute("SELECT * FROM evidence WHERE evidence_id = ?", (supplied_id,)).fetchone()
        if existing:
            if existing["tenant_id"] != tenant_id or existing["payload_sha256"] != digest:
                raise EnterpriseOpsError("E_EVIDENCE_IMMUTABLE", "evidence id is already bound to different content")
            return {"schema": EVIDENCE_SCHEMA, "marker": "EVIDENCE_REUSED", "eops_marker": "EOPS_EVIDENCE_READY", "evidence_id": supplied_id, "payload_sha256": digest, "tenant_id": tenant_id}
        db.execute(
            "INSERT INTO evidence (evidence_id,tenant_id,payload_json,payload_sha256,verdict,created_at,expires_at,inserted_by) VALUES (?,?,?,?,?,?,?,?)",
            (supplied_id, tenant_id, _canonical(payload).decode("utf-8"), digest, str(payload.get("verdict", "UNKNOWN")), now.isoformat(), expires.isoformat(), subject),
        )
    audit = _audit(root, tenant_id, "evidence.write", subject, supplied_id, {"payload_sha256": digest, "verdict": str(payload.get("verdict", "UNKNOWN"))})
    return {"schema": EVIDENCE_SCHEMA, "marker": "EVIDENCE_RECORDED", "eops_marker": "EOPS_EVIDENCE_READY", "evidence_id": supplied_id, "payload_sha256": digest, "tenant_id": tenant_id, "expires_at": expires.isoformat(), "audit": audit}


def _verify_evidence_rows(rows: Iterable[sqlite3.Row]) -> list[str]:
    errors: list[str] = []
    for row in rows:
        try:
            expected = _sha(json.loads(row["payload_json"]))
        except (json.JSONDecodeError, TypeError, ValueError):
            expected = ""
        if expected != row["payload_sha256"]:
            errors.append(f"evidence {row['evidence_id']}: payload hash mismatch")
    return errors


def _verify_audit_rows(rows: Iterable[sqlite3.Row]) -> list[str]:
    errors: list[str] = []
    previous = ""
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
        except json.JSONDecodeError:
            errors.append(f"audit {row['sequence']}: invalid payload JSON")
            previous = row["event_hash"]
            continue
        event = {"schema": "factory.enterprise-ops.audit.v1", "sequence": row["sequence"], "tenant_id": row["tenant_id"], "action": row["action"], "actor": row["actor"], "resource_id": row["resource_id"], "payload": payload, "previous_hash": row["previous_hash"], "created_at": row["created_at"]}
        if row["previous_hash"] != previous:
            errors.append(f"audit {row['sequence']}: previous hash mismatch")
        if _sha(event) != row["event_hash"]:
            errors.append(f"audit {row['sequence']}: event hash mismatch")
        previous = row["event_hash"]
    return errors


def verify_workspace(root: Path, tenant_id: str | None = None) -> dict[str, Any]:
    """Verify evidence digests and the tenant audit hash chain."""
    config = _ensure_initialized(root)
    tenant_id = _tenant(tenant_id or config["tenant_id"])
    if tenant_id != config["tenant_id"]:
        raise EnterpriseOpsError("E_TENANT_BOUNDARY", "workspace verification cannot cross the initialized tenant")
    with _connect(root) as db:
        evidence_rows = db.execute("SELECT * FROM evidence WHERE tenant_id = ? ORDER BY created_at,evidence_id", (tenant_id,)).fetchall()
        audit_rows = db.execute("SELECT * FROM audit_events WHERE tenant_id = ? ORDER BY sequence", (tenant_id,)).fetchall()
    errors = _verify_evidence_rows(evidence_rows) + _verify_audit_rows(audit_rows)
    return {"schema": OPS_SCHEMA, "marker": "OPS_WORKSPACE_VERIFIED" if not errors else "OPS_WORKSPACE_TAMPERED", "eops_marker": "EOPS_EVIDENCE_READY" if not errors else "EOPS_FAIL_CLOSED", "tenant_id": tenant_id, "evidence": len(evidence_rows), "audit_events": len(audit_rows), "valid": not errors, "errors": errors}


def export_evidence(root: Path, out: Path) -> dict[str, Any]:
    """Export aggregate-safe evidence metadata and verification state."""
    verification = verify_workspace(root)
    config = _ensure_initialized(root)
    with _connect(root) as db:
        rows = db.execute("SELECT evidence_id,payload_sha256,verdict,created_at,expires_at,inserted_by FROM evidence WHERE tenant_id = ? ORDER BY created_at,evidence_id", (config["tenant_id"],)).fetchall()
    payload = {"schema": "factory.enterprise-ops.export.v1", "marker": "OPS_EXPORT_WRITTEN", "tenant_id": config["tenant_id"], "verification": verification, "records": [{"evidence_id": row["evidence_id"], "payload_sha256": row["payload_sha256"], "verdict": row["verdict"], "created_at": row["created_at"], "expires_at": row["expires_at"], "inserted_by": hashlib.sha256(str(row["inserted_by"]).encode()).hexdigest()[:16]} for row in rows], "disclosure": "metadata-only; payloads, prompts, source paths, and credentials omitted"}
    path = _atomic_json(Path(out).resolve(), payload)
    return {**payload, "path": str(path)}


def _validate_command(command: Any) -> list[str]:
    if not isinstance(command, list) or not command or not all(isinstance(part, str) and part for part in command):
        raise EnterpriseOpsError("E_RUNNER_COMMAND_INVALID", "command must be a non-empty argv list; shell strings are rejected")
    if any(part in {"&&", ";", "|", ">", "<", "`"} for part in command):
        raise EnterpriseOpsError("E_RUNNER_COMMAND_INVALID", "shell operators are not allowed in proof argv")
    return command


def _validate_runner_limits(backend: str, timeout_seconds: int, output_limit: int) -> None:
    if backend not in {"docker", "process"}:
        raise EnterpriseOpsError("E_RUNNER_BACKEND_INVALID", "backend must be docker or process")
    if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 3600:
        raise EnterpriseOpsError("E_RUNNER_TIMEOUT_INVALID", "timeout_seconds must be between 1 and 3600")
    if not isinstance(output_limit, int) or isinstance(output_limit, bool) or not 1024 <= output_limit <= 4 * 1024 * 1024:
        raise EnterpriseOpsError("E_RUNNER_OUTPUT_INVALID", "output_limit must be between 1024 and 4194304")


def _runner_argv(workspace: Path, command: list[str], backend: str, timeout_seconds: int, image: str, allow_process_boundary: bool) -> tuple[list[str], dict[str, Any]]:
    if backend == "docker":
        if shutil.which("docker") is None:
            raise EnterpriseOpsError("E_RUNNER_BACKEND_UNAVAILABLE", "Docker is not installed or not on PATH; process fallback is never implicit")
        if not re.fullmatch(r"[A-Za-z0-9._/@:-]{1,200}", image):
            raise EnterpriseOpsError("E_RUNNER_IMAGE_INVALID", "Docker image has an unsupported format")
        argv = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cpus", "1", "--memory", "512m", "--pids-limit", "256", "-v", f"{workspace.as_posix()}:/workspace:ro", "-w", "/workspace", image, *command]
        posture = {"backend": "docker", "isolation": "container", "network": "none", "filesystem": "read-only", "resource_limits": {"cpus": 1, "memory_mb": 512, "pids": 256}}
        return argv, posture
    if not allow_process_boundary:
        raise EnterpriseOpsError("E_RUNNER_ISOLATION_REQUIRED", "process execution requires --allow-process-boundary and is never labelled isolated")
    return command, {"backend": "process", "isolation": "not-isolated", "network": "not-enforced", "filesystem": "workspace-process", "resource_limits": {"timeout_seconds": timeout_seconds}}


def _execute_runner(argv: list[str], workspace: Path, timeout_seconds: int) -> tuple[int | None, str, str, bool]:
    result, captures = _run_command(argv, cwd=workspace, timeout_seconds=timeout_seconds)
    if result["status"] == "spawn_error":
        error = b64decode(captures["stderr"]).decode("utf-8", errors="replace")
        raise EnterpriseOpsError("E_RUNNER_EXECUTION", f"proof command could not start: {error}")
    stdout = b64decode(captures["stdout"]).decode("utf-8", errors="replace")
    stderr = b64decode(captures["stderr"]).decode("utf-8", errors="replace")
    return result["exit_code"], stdout, stderr, result["status"] == "timed_out"


def run_proof(root: Path, command: list[str], *, backend: str = "docker", timeout_seconds: int = 120, output_limit: int = 65536, image: str = "python:3.12-slim", allow_process_boundary: bool = False) -> dict[str, Any]:
    """Run one bounded proof command with explicit isolation posture."""
    config = _ensure_initialized(root)
    workspace = _ops_root(root)
    command = _validate_command(command)
    _validate_runner_limits(backend, timeout_seconds, output_limit)
    argv, posture = _runner_argv(workspace, command, backend, timeout_seconds, image, allow_process_boundary)
    started = time.perf_counter()
    exit_code, stdout, stderr, timed_out = _execute_runner(argv, workspace, timeout_seconds)
    combined = stdout + ("\n" if stdout and stderr else "") + stderr
    result = {"schema": RUNNER_SCHEMA, "marker": "RUNNER_ISOLATION_ENFORCED" if posture["isolation"] == "container" else "RUNNER_NOT_ISOLATED", "eops_marker": "EOPS_RUNNER_READY", "tenant_id": config["tenant_id"], "command": command, "posture": posture, "status": "timeout" if timed_out else "passed" if exit_code == 0 else "failed", "exit_code": exit_code, "elapsed_ms": round((time.perf_counter() - started) * 1000), "output": combined[:output_limit], "output_truncated": len(combined) > output_limit, "authority": {"source_write": False, "merge": False, "deploy": False, "secrets": False}}
    result["receipt_sha256"] = _sha({key: value for key, value in result.items() if key != "receipt_sha256"})
    return result


def _normalize_changed_paths(workspace: Path, changed_paths: Iterable[str]) -> list[str]:
    normalized: list[str] = []
    for path in sorted({_require(path, "changed_path") for path in changed_paths}):
        candidate = (workspace / path).resolve()
        try:
            normalized.append(candidate.relative_to(workspace).as_posix())
        except ValueError as exc:
            raise EnterpriseOpsError("E_PATH_ESCAPE", "changed path must stay inside the workspace") from exc
    return normalized


def _read_proof_receipts(workspace: Path, proof_receipts: Iterable[str]) -> list[dict[str, Any]]:
    receipts: list[dict[str, Any]] = []
    for item in proof_receipts:
        path = Path(item) if Path(item).is_absolute() else workspace / item
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EnterpriseOpsError("E_PROOF_RECEIPT_INVALID", f"proof receipt cannot be read: {exc}") from exc
        if isinstance(value, dict) and (value.get("verified") is True or value.get("status") in {"verified", "passed"}):
            receipts.append(value)
    return receipts


def _receipt_paths(receipts: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    indexed: dict[str, list[dict[str, Any]]] = {}
    for receipt in receipts:
        for path in receipt.get("changed_paths", []):
            indexed.setdefault(str(path), []).append(receipt)
    return indexed


def evaluate_required_checks(root: Path, changed_paths: Iterable[str], *, proof_receipts: Iterable[str] = ()) -> dict[str, Any]:
    """Evaluate proof freshness for a diff without granting merge authority."""
    config = _ensure_initialized(root)
    workspace = _ops_root(root)
    normalized = _normalize_changed_paths(workspace, changed_paths)
    receipts = _read_proof_receipts(workspace, proof_receipts)
    indexed = _receipt_paths(receipts)
    missing = [path for path in normalized if path not in indexed]
    stale = []
    for path in normalized:
        changed = workspace / path
        if changed.exists() and any(item.get("created_at") and _parse_timestamp(item["created_at"]) < changed.stat().st_mtime for item in indexed.get(path, [])):
            stale.append(path)
    decision = "READY_FOR_HUMAN_REVIEW" if not missing and not stale else "REVIEW_REQUIRED"
    return {"schema": CHECK_SCHEMA, "marker": "REQUIRED_CHECKS_READY" if decision == "READY_FOR_HUMAN_REVIEW" else "REQUIRED_CHECKS_REVIEW_REQUIRED", "eops_marker": "EOPS_CHECK_READY", "tenant_id": config["tenant_id"], "changed_paths": normalized, "proof_receipts": len(receipts), "missing": sorted(set(missing)), "stale": sorted(set(stale)), "decision": decision, "authority": {"merge": False, "deploy": False, "release": False}}


def _parse_timestamp(value: str) -> float:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return 0.0


def _outcome_rows(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    path = _outcomes_path(root)
    if not path.exists():
        return [], []
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    previous = ""
    for index, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            errors.append(f"line {index}: invalid JSON")
            continue
        supplied = value.get("event_sha256")
        core = {key: item for key, item in value.items() if key != "event_sha256"}
        if supplied != _sha(core):
            errors.append(f"line {index}: event hash mismatch")
        if value.get("previous_sha256", "") != previous:
            errors.append(f"line {index}: previous hash mismatch")
        previous = str(supplied or "")
        rows.append(value)
    return rows, errors


def record_outcome(root: Path, tenant_id: str, subject: str, *, service: str, environment: str, result: str, duration_ms: int, deployed: bool = False, incident: bool = False, rollback: bool = False) -> dict[str, Any]:
    """Append one allowlisted outcome event to the hash-linked operations ledger."""
    config = _ensure_initialized(root)
    tenant_id, subject = _tenant(tenant_id), _subject(subject)
    if tenant_id != config["tenant_id"]:
        raise EnterpriseOpsError("E_TENANT_BOUNDARY", "outcome tenant differs from the initialized operations tenant")
    _authorize(root, tenant_id, subject, {"operator", "admin", "service_owner"})
    service, environment, result = _require(service, "service"), _require(environment, "environment"), _require(result, "result").lower()
    if result not in SAFE_RESULT_SET:
        raise EnterpriseOpsError("E_OUTCOME_RESULT_INVALID", f"result must be one of {sorted(SAFE_RESULT_SET)}")
    if not isinstance(duration_ms, int) or isinstance(duration_ms, bool) or duration_ms < 0:
        raise EnterpriseOpsError("E_OUTCOME_DURATION_INVALID", "duration_ms must be a non-negative integer")
    rows, errors = _outcome_rows(root)
    if errors:
        raise EnterpriseOpsError("E_OUTCOME_LEDGER_TAMPERED", "; ".join(errors))
    event = {"schema": OUTCOME_SCHEMA, "marker": "OUTCOME_RECORDED", "eops_marker": "EOPS_OUTCOME_READY", "tenant_id": tenant_id, "actor": subject, "service": service, "environment": environment, "result": result, "duration_ms": duration_ms, "deployed": bool(deployed), "incident": bool(incident), "rollback": bool(rollback), "created_at": _now(), "previous_sha256": rows[-1]["event_sha256"] if rows else ""}
    event["event_sha256"] = _sha(event)
    path = _outcomes_path(root)
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return event


def outcome_summary(root: Path) -> dict[str, Any]:
    """Return aggregate outcome counts and integrity status."""
    rows, errors = _outcome_rows(root)
    deployments = sum(bool(item.get("deployed")) for item in rows)
    incidents = sum(bool(item.get("incident")) for item in rows)
    rollbacks = sum(bool(item.get("rollback")) for item in rows)
    return {"schema": OUTCOME_SCHEMA, "marker": "OUTCOME_SUMMARY_RECONCILED" if not errors else "OUTCOME_SUMMARY_TAMPERED", "events": len(rows), "deployments": deployments, "incidents": incidents, "rollbacks": rollbacks, "failed": sum(item.get("result") == "failure" for item in rows), "change_failure_rate": (incidents + rollbacks) / deployments if deployments else None, "integrity": {"valid": not errors, "errors": errors}, "claim_boundary": "aggregate observations only; not a DORA benchmark or causal productivity claim"}


def export_otel(root: Path, out: Path) -> dict[str, Any]:
    """Export allowlisted outcome events in a small OTLP-shaped JSON envelope."""
    rows, errors = _outcome_rows(root)
    if errors:
        raise EnterpriseOpsError("E_OUTCOME_LEDGER_TAMPERED", "; ".join(errors))
    payload = {"schema": OTEL_SCHEMA, "marker": "OTEL_EXPORT_WRITTEN", "resourceSpans": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": row["service"]}}, {"key": "deployment.environment", "value": {"stringValue": row["environment"]}}]}, "scopeSpans": [{"spans": [{"name": "factory.outcome", "startTimeUnixNano": int(_parse_timestamp(row["created_at"]) * 1_000_000_000), "durationNano": int(row["duration_ms"]) * 1_000_000, "status": {"code": "STATUS_CODE_OK" if row["result"] in {"success", "deployed"} else "STATUS_CODE_ERROR"}, "attributes": [{"key": "factory.result", "value": {"stringValue": row["result"]}}, {"key": "factory.deployed", "value": {"boolValue": bool(row["deployed"])}}, {"key": "factory.incident", "value": {"boolValue": bool(row["incident"])}}, {"key": "factory.rollback", "value": {"boolValue": bool(row["rollback"])}}]}]}]} for row in rows], "events": len(rows), "disclosure": "allowlisted outcome metadata only; no prompts, paths, source, or credentials"}
    path = _atomic_json(Path(out).resolve(), payload)
    return {**payload, "path": str(path)}


def _sla_manifest(manifest: Path | None) -> dict[str, Any]:
    if manifest is None:
        return {}
    supplied = _load_json(Path(manifest), code="E_SLA_MANIFEST_INVALID")
    if not isinstance(supplied, dict):
        raise EnterpriseOpsError("E_SLA_MANIFEST_INVALID", "SLA manifest must be a JSON object")
    gates = supplied.get("gates", supplied)
    if not isinstance(gates, dict):
        raise EnterpriseOpsError("E_SLA_MANIFEST_INVALID", "SLA manifest gates must be an object")
    return gates


def _sla_gate_result(gate: str, value: Any) -> dict[str, Any]:
    verified = isinstance(value, dict) and value.get("verified") is True and isinstance(value.get("evidence"), str) and bool(value["evidence"].strip())
    if gate == "signed_acceptance":
        verified = verified and isinstance(value, dict) and bool(re.fullmatch(r"[0-9a-f]{64}", str(value.get("signature_sha256", ""))))
    return {"verified": verified, "evidence": value.get("evidence") if isinstance(value, dict) else None}


def evaluate_sla(root: Path, manifest: Path | None = None, *, out: Path | None = None) -> dict[str, Any]:
    """Evaluate seven SLA activation gates without activating a contract."""
    _ensure_initialized(root)
    gates = _sla_manifest(manifest)
    results = {gate: _sla_gate_result(gate, gates.get(gate)) for gate in KNOWN_SLA_GATES}
    missing = [name for name, item in results.items() if not item["verified"]]
    payload = {"schema": SLA_SCHEMA, "marker": "SLA_READINESS_RECORDED", "eops_marker": "EOPS_SLA_READY", "status": "READY_FOR_CONTRACT" if not missing else "PROPOSED", "active": False, "gates": results, "missing_gates": missing, "authority": {"activate": False, "contract": False, "billing": False}, "claim_boundary": "readiness evidence is not a live SLA or response-time guarantee"}
    if out is not None:
        payload["path"] = str(_atomic_json(Path(out).resolve(), payload))
    return payload


def workspace_status(root: Path) -> dict[str, Any]:
    """Return the compact, novice-friendly golden-path status read model."""
    try:
        config = _ensure_initialized(root)
    except EnterpriseOpsError as exc:
        if exc.code != "E_OPS_NOT_INITIALIZED":
            raise
        return {"schema": OPS_SCHEMA, "marker": "OPS_NOT_INITIALIZED", "eops_marker": "EOPS_GOLDEN_READY", "markers": ["EOPS_GOLDEN_READY"], "initialized": False, "next": "factory ops init --tenant <tenant> --owner <subject>", "authority": {"merge": False, "deploy": False, "billing": False, "sso_enrollment": False, "sla_activation": False}}
    identities = _identities(root)
    verification = verify_workspace(root)
    outcome = outcome_summary(root)
    docker_available = shutil.which("docker") is not None
    active = sum(item.get("status") == "active" for item in identities)
    if not verification["valid"]:
        next_action = "factory ops export --out .factory/ops/evidence-export.json (investigate tamper first)"
    elif not active:
        next_action = "factory ops identity provision <subject> --role operator --actor <admin>"
    elif not docker_available:
        next_action = "install Docker for isolated proofs, or explicitly use --allow-process-boundary for local-only checks"
    else:
        next_action = "factory ops checks --changed <path> --proof <receipt.json>"
    status_marker = "EOPS_GOLDEN_READY" if verification["valid"] else "EOPS_FAIL_CLOSED"
    return {"schema": OPS_SCHEMA, "marker": "OPS_STATUS_READY", "eops_marker": status_marker, "markers": ["EOPS_EVIDENCE_READY" if verification["valid"] else "EOPS_FAIL_CLOSED", "EOPS_IDENTITY_READY", "EOPS_RUNNER_READY", "EOPS_CHECK_READY", "EOPS_OUTCOME_READY", "EOPS_SLA_READY", status_marker], "initialized": True, "tenant_id": config["tenant_id"], "evidence": verification["evidence"], "audit": {"events": verification["audit_events"], "valid": verification["valid"]}, "identities": {"total": len(identities), "active": active, "suspended": sum(item.get("status") == "suspended" for item in identities), "revoked": sum(item.get("status") == "revoked" for item in identities)}, "runner": {"docker_available": docker_available, "isolated_backend": "docker" if docker_available else None, "process_backend": "not-isolated", "network_enforcement": "none only in Docker backend"}, "checks": {"eops_marker": "EOPS_CHECK_READY", "decision": "NOT_EVALUATED", "authority": {"merge": False, "deploy": False, "release": False}}, "outcomes": outcome, "sla": evaluate_sla(root), "golden_path": config["golden_path"], "next": next_action, "authority": config["authority"]}
