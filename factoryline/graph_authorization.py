"""Named, expiring human authorizations for bounded Graph Ops actions.

An authorization is intentionally not a repair engine.  It can authorize one
re-run of an already sealed Reality Check, or record that a named reviewer has
accepted a ProofSearch repair plan for a separate runner.  It cannot apply a
patch, merge, publish, deploy, or contact a service.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

from .reality_check import RealityCheckError, run_reality_check, validate_reality_check_receipt, write_reality_check_artifacts


AUTHORIZATION_SCHEMA = "factory.graph-ops-authorization.v1"
MAX_TEXT = 600
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_SHA = re.compile(r"^[a-f0-9]{64}$")
_ACTIONS = {"reality_check_execution", "repair_plan_review"}
_AUTHORITY = {
    "reality_check_execution": {
        "execution": True, "test_execution": True, "repair": False, "source_write": False,
        "merge": False, "publication": False, "deployment": False, "signing": False,
        "messaging": False, "credential": False, "connector": False,
    },
    "repair_plan_review": {
        "execution": False, "test_execution": False, "repair": False, "source_write": False,
        "merge": False, "publication": False, "deployment": False, "signing": False,
        "messaging": False, "credential": False, "connector": False,
    },
}


class GraphAuthorizationError(ValueError):
    """Raised for invalid, expired, replayed, or out-of-scope authorizations."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _reject(code: str, message: str) -> None:
    raise GraphAuthorizationError(code, message)


def _text(value: object, field: str, *, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > MAX_TEXT:
        _reject("GRAPH_AUTHORIZATION_INVALID", f"{field} must be a non-empty string of at most {MAX_TEXT} characters")
    text = value.strip()
    if identifier and not _ID.fullmatch(text):
        _reject("GRAPH_AUTHORIZATION_INVALID", f"{field} has an unsupported format")
    return text


def _relative_existing(root: Path, value: object, field: str) -> tuple[Path, str]:
    if not isinstance(value, str) or not value.strip():
        _reject("GRAPH_AUTHORIZATION_INVALID", f"{field} must be a workspace-relative file")
    raw = value.replace("\\", "/").strip()
    if raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw) or ".." in raw.split("/"):
        _reject("GRAPH_AUTHORIZATION_INVALID", f"{field} must stay inside the workspace")
    path = (root / raw).resolve()
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        _reject("GRAPH_AUTHORIZATION_INVALID", f"{field} resolves outside the workspace")
    if not path.is_file():
        _reject("GRAPH_AUTHORIZATION_INVALID", f"{field} must name a readable file")
    return path, relative


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _expiry(value: object, now: datetime) -> str:
    if not isinstance(value, str):
        _reject("GRAPH_AUTHORIZATION_INVALID", "expires_at must be an ISO-8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _reject("GRAPH_AUTHORIZATION_INVALID", "expires_at must be an ISO-8601 UTC timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        _reject("GRAPH_AUTHORIZATION_INVALID", "expires_at must use UTC")
    parsed = parsed.astimezone(timezone.utc).replace(microsecond=0)
    if not now < parsed <= now + timedelta(days=7):
        _reject("GRAPH_AUTHORIZATION_INVALID", "expires_at must be after now and no more than seven days away")
    return parsed.isoformat().replace("+00:00", "Z")


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        _reject("GRAPH_AUTHORIZATION_INVALID", f"authorization cannot be read as JSON: {exc}")
    if not isinstance(value, dict):
        _reject("GRAPH_AUTHORIZATION_INVALID", "authorization must contain one JSON object")
    return value


def _write_new(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(_canonical(value))
    except FileExistsError:
        _reject("GRAPH_AUTHORIZATION_REPLAY", "authorization id already exists")


def _write_replace(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(_canonical(value))
    temporary.replace(path)


@contextmanager
def _authorization_lock(path: Path):
    """Hold one fail-closed local lock so an authorization cannot run twice concurrently."""
    lock = path.with_suffix(path.suffix + ".lock")
    try:
        with lock.open("x", encoding="utf-8") as handle:
            handle.write("Graph Ops authorization execution in progress.\n")
    except FileExistsError:
        _reject("GRAPH_AUTHORIZATION_IN_PROGRESS", "authorization is already executing; inspect its local lock before any manual recovery")
    try:
        yield
    finally:
        try:
            lock.unlink()
        except FileNotFoundError:
            pass


def _node_binding(root: Path, node_id: str, action: str) -> dict[str, Any]:
    # Imported lazily to keep Graph Ops projection independent from its command path.
    from .graph_ops import graph_ops_snapshot

    node = next((item for item in graph_ops_snapshot(root)["nodes"] if item["id"] == node_id), None)
    if node is None:
        _reject("GRAPH_AUTHORIZATION_TARGET_INVALID", "selected Graph Ops node is not present in the current local graph")
    if action == "reality_check_execution":
        if node.get("kind") != "reality_check" or node.get("status") != "verified":
            _reject("GRAPH_AUTHORIZATION_TARGET_INVALID", "only a verified Reality Check may authorize one re-run")
        source_path, source = _relative_existing(root, node.get("source"), "selected Reality Check source")
        try:
            receipt = validate_reality_check_receipt(_load(source_path))
        except RealityCheckError as exc:
            _reject(exc.code, str(exc))
        return {
            "node_id": node_id, "kind": "reality_check", "source": source,
            "source_sha256": sha256(source_path.read_bytes()).hexdigest(),
            "receipt_sha256": receipt["receipt_sha256"],
            "manifest_path": receipt["manifest"]["manifest_path"],
            "manifest_sha256": receipt["manifest"]["manifest_sha256"],
        }
    if node.get("kind") != "repair_candidate" or node.get("status") != "winner" or node.get("facts", {}).get("eligible") is not True:
        _reject("GRAPH_AUTHORIZATION_TARGET_INVALID", "only an eligible ProofSearch winner may receive a repair-plan review authorization")
    source_path, source = _relative_existing(root, node.get("source"), "selected repair source")
    return {
        "node_id": node_id, "kind": "repair_candidate", "source": source,
        "source_sha256": sha256(source_path.read_bytes()).hexdigest(),
        "candidate_id": node.get("label"),
    }


def create_graph_authorization(root: Path, payload: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Record one named, expiring, explicit human authorization from Graph Ops."""
    workspace = Path(root).resolve()
    if set(payload) != {"action", "id", "node_id", "approved_by", "rationale", "expires_at", "confirmation"}:
        _reject("GRAPH_AUTHORIZATION_INVALID", "authorization request has unsupported or missing fields")
    action = payload.get("action")
    if action not in _ACTIONS:
        _reject("GRAPH_AUTHORIZATION_INVALID", "action must authorize one supported Graph Ops action")
    authorization_id = _text(payload.get("id"), "id", identifier=True)
    if payload.get("confirmation") != f"AUTHORIZE {authorization_id}":
        _reject("GRAPH_AUTHORIZATION_CONFIRMATION_REQUIRED", f"confirmation must exactly equal AUTHORIZE {authorization_id}")
    issued = (now or _now()).astimezone(timezone.utc).replace(microsecond=0)
    binding = _node_binding(workspace, _text(payload.get("node_id"), "node_id"), action)
    core = {
        "schema": AUTHORIZATION_SCHEMA, "id": authorization_id, "action": action, "state": "approved",
        "approved_by": _text(payload.get("approved_by"), "approved_by"),
        "rationale": _text(payload.get("rationale"), "rationale"),
        "issued_at": issued.isoformat().replace("+00:00", "Z"), "expires_at": _expiry(payload.get("expires_at"), issued),
        "binding": binding, "authority": _AUTHORITY[action],
        "limits": [
            "This is a named human authorization, not a source, repair, merge, publication, or deployment permission.",
            "Reality Check authorizations run only the sealed local manifest once; repair-plan review authorizations require a separate approved runner.",
        ],
    }
    result = {**core, "authorization_sha256": _sha(core)}
    path = workspace / ".factory" / "graph-ops" / "authorizations" / f"{authorization_id}.json"
    _write_new(path, result)
    return {"schema": "factory.graph-ops-authorization-result.v1", "marker": "GRAPH_OPS_HUMAN_AUTHORIZATION_RECORDED", "path": str(path), "authorization": result}


def _authorization_shape(value: object) -> tuple[dict[str, Any], set[str], set[str]]:
    if not isinstance(value, dict) or value.get("schema") != AUTHORIZATION_SCHEMA:
        _reject("GRAPH_AUTHORIZATION_INVALID", f"a {AUTHORIZATION_SCHEMA} payload is required")
    required = {"schema", "id", "action", "state", "approved_by", "rationale", "issued_at", "expires_at", "binding", "authority", "limits", "authorization_sha256"}
    consumed_extra = {"consumed_at", "execution_receipt"}
    allowed = required | consumed_extra
    if set(value) - allowed or value.get("action") not in _ACTIONS or value.get("state") not in {"approved", "consumed"}:
        _reject("GRAPH_AUTHORIZATION_INVALID", "authorization has unsupported fields or state")
    return value, required, allowed


def _authorization_state_shape(value: dict[str, Any], required: set[str], allowed: set[str]) -> None:
    if value["state"] == "approved" and set(value) != required:
        _reject("GRAPH_AUTHORIZATION_INVALID", "an approved authorization cannot have execution fields")
    if value["state"] == "consumed" and set(value) != allowed:
        _reject("GRAPH_AUTHORIZATION_INVALID", "a consumed authorization must bind one execution receipt")


def _authorization_integrity(value: dict[str, Any]) -> None:
    if not isinstance(value.get("authorization_sha256"), str) or not _SHA.fullmatch(value["authorization_sha256"]):
        _reject("GRAPH_AUTHORIZATION_INVALID", "authorization SHA-256 is invalid")
    core = {key: value[key] for key in value if key != "authorization_sha256"}
    if value["authorization_sha256"] != _sha(core):
        _reject("GRAPH_AUTHORIZATION_INVALID", "authorization SHA-256 does not match")
    if value["authority"] != _AUTHORITY[value["action"]]:
        _reject("GRAPH_AUTHORIZATION_INVALID", "authorization authority does not match action")


def _authorization_identity(value: dict[str, Any]) -> None:
    _text(value.get("id"), "id", identifier=True); _text(value.get("approved_by"), "approved_by"); _text(value.get("rationale"), "rationale")
    if not isinstance(value.get("binding"), dict) or not isinstance(value["binding"].get("source"), str):
        _reject("GRAPH_AUTHORIZATION_INVALID", "authorization binding is invalid")


def _authorization_timestamps(value: dict[str, Any]) -> None:
    try:
        issued = datetime.fromisoformat(str(value["issued_at"]).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(str(value["expires_at"]).replace("Z", "+00:00"))
    except ValueError:
        _reject("GRAPH_AUTHORIZATION_INVALID", "authorization timestamps must be ISO-8601")
    if issued.tzinfo is None or expires.tzinfo is None or issued.utcoffset() != timedelta(0) or expires.utcoffset() != timedelta(0):
        _reject("GRAPH_AUTHORIZATION_INVALID", "authorization timestamps must use UTC")
    if not issued < expires <= issued + timedelta(days=7):
        _reject("GRAPH_AUTHORIZATION_INVALID", "authorization expiry must be after issuance and within seven days")


def validate_graph_authorization(value: object) -> dict[str, Any]:
    """Validate a sealed Graph Ops authorization without executing or consuming it."""
    value, required, allowed = _authorization_shape(value)
    _authorization_state_shape(value, required, allowed)
    _authorization_integrity(value)
    _authorization_identity(value)
    _authorization_timestamps(value)
    return value


def _authorization_path(root: Path, authorization_path: Path) -> Path:
    candidate = Path(authorization_path)
    if candidate.is_absolute():
        path = candidate.resolve()
        try:
            path.relative_to(root)
        except ValueError:
            _reject("GRAPH_AUTHORIZATION_INVALID", "authorization must stay inside the workspace")
        if not path.is_file():
            _reject("GRAPH_AUTHORIZATION_INVALID", "authorization must name a readable file")
        return path
    path, _ = _relative_existing(root, str(candidate), "authorization")
    return path


def _active_reality_authorization(path: Path, now: datetime) -> dict[str, Any]:
    authorization = validate_graph_authorization(_load(path))
    if authorization["action"] != "reality_check_execution" or authorization["state"] != "approved":
        _reject("GRAPH_AUTHORIZATION_NOT_EXECUTABLE", "authorization is not an unused Reality Check execution authorization")
    expires = datetime.fromisoformat(authorization["expires_at"].replace("Z", "+00:00"))
    if now >= expires:
        _reject("GRAPH_AUTHORIZATION_EXPIRED", "authorization has expired")
    return authorization


def _bound_reality_receipt(root: Path, authorization: dict[str, Any]) -> Path:
    binding = authorization["binding"]
    source_path, _ = _relative_existing(root, binding.get("source"), "bound Reality Check source")
    if sha256(source_path.read_bytes()).hexdigest() != binding.get("source_sha256"):
        _reject("GRAPH_AUTHORIZATION_STALE", "bound Reality Check receipt bytes changed after approval")
    try:
        source_receipt = validate_reality_check_receipt(_load(source_path))
    except RealityCheckError as exc:
        _reject(exc.code, str(exc))
    if source_receipt["receipt_sha256"] != binding.get("receipt_sha256"):
        _reject("GRAPH_AUTHORIZATION_STALE", "bound Reality Check receipt hash changed after approval")
    manifest_path, _ = _relative_existing(root, binding.get("manifest_path"), "bound manifest")
    if sha256(manifest_path.read_bytes()).hexdigest() != binding.get("manifest_sha256"):
        _reject("GRAPH_AUTHORIZATION_STALE", "bound Reality Check manifest bytes changed after approval")
    return manifest_path


def _consume(path: Path, authorization: dict[str, Any], current: datetime, receipt: dict[str, Any], outputs: dict[str, str], root: Path) -> None:
    consumed_core = {key: authorization[key] for key in authorization if key != "authorization_sha256"}
    consumed_core["state"] = "consumed"
    consumed_core["consumed_at"] = current.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    consumed_core["execution_receipt"] = {"path": str(Path(outputs["receipt"]).resolve().relative_to(root).as_posix()), "sha256": receipt["receipt_sha256"]}
    # A consumed authorization intentionally has an expanded schema; it is no longer reusable.
    consumed = {**consumed_core, "authorization_sha256": _sha(consumed_core)}
    _write_replace(path, consumed)


def run_authorized_reality_check(root: Path, authorization_path: Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Consume one unexpired Reality Check authorization and execute its sealed manifest once."""
    workspace = Path(root).resolve()
    path = _authorization_path(workspace, authorization_path)
    current = (now or _now()).astimezone(timezone.utc)
    with _authorization_lock(path):
        authorization = _active_reality_authorization(path, current)
        manifest_path = _bound_reality_receipt(workspace, authorization)
        try:
            receipt = run_reality_check(workspace, manifest_path)
        except RealityCheckError as exc:
            _reject(exc.code, str(exc))
        _bound_reality_receipt(workspace, authorization)
        outputs = write_reality_check_artifacts(receipt, workspace / ".factory" / "reality")
        _consume(path, authorization, current, receipt, outputs, workspace)
    return {"schema": "factory.graph-ops-execution-result.v1", "marker": "GRAPH_OPS_AUTHORIZED_REALITY_CHECK_EXECUTED", "authorization_path": str(path), "outputs": outputs, "receipt": receipt}
