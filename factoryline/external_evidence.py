"""Offline import and comparison of external runtime-test evidence.

This module is intentionally an evidence boundary, not a provider client.  A
runner adapter (for example, a TestSprite export adapter) must produce the
small normalized bundle accepted here.  Code Factory verifies the bundle and
its referenced artifacts, then records what was observed without executing a
provider, retaining source, or granting release/repair authority.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any


BUNDLE_SCHEMA = "factory.external-runtime-bundle.v1"
RECEIPT_SCHEMA = "factory.external-runtime-receipt.v1"
DIFF_SCHEMA = "factory.external-runtime-diff.v1"
MAX_SOURCE_BYTES = 1_048_576
MAX_ARTIFACT_BYTES = 1_048_576
MAX_ARTIFACTS = 100
MAX_TEXT = 512
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[a-f0-9]{64}$")
_PROVIDER = re.compile(r"^[a-z][a-z0-9._-]{1,63}$")
_VERDICTS = frozenset({"passed", "failed", "blocked", "unknown"})
_FAILURE_KINDS = frozenset({"none", "assertion", "timeout", "environment", "network", "unknown"})

_BUNDLE_FIELDS = frozenset({
    "schema", "provider", "project_id", "test_id", "run_id", "snapshot_id",
    "code_version", "environment", "verdict", "failure_kind",
    "first_failed_step", "hypothesis", "recommended_fix", "artifacts", "observed_at",
})
_ENVIRONMENT_FIELDS = frozenset({"fingerprint", "label"})
_STEP_FIELDS = frozenset({"index", "label"})
_ARTIFACT_FIELDS = frozenset({"path", "sha256", "kind"})

_AUTHORITY = {
    "execution": False,
    "test_execution": False,
    "approval": False,
    "repair": False,
    "source_write": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


class ExternalEvidenceError(ValueError):
    """Stable fail-closed error for an external evidence boundary."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ExternalEvidenceError("EXTERNAL_EVIDENCE_BUNDLE_INVALID", f"value is not canonical JSON: {exc}") from exc


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _sha_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _reject(code: str, message: str) -> None:
    raise ExternalEvidenceError(code, message)


def _safe_filename(value: str) -> str:
    """Keep a deterministic default filename valid on Windows and POSIX."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)[:64] or "run"


def _workspace_file(root: Path, value: object, field: str, *, exists: bool = True) -> tuple[Path, str]:
    if not isinstance(value, (str, Path)) or not str(value).strip():
        _reject("EXTERNAL_EVIDENCE_PATH_INVALID", f"{field} must be a non-empty workspace-relative path")
    raw = Path(value)
    candidate = raw.resolve() if raw.is_absolute() else (root / raw).resolve()
    try:
        relative = candidate.relative_to(root).as_posix()
    except ValueError as exc:
        _reject("EXTERNAL_EVIDENCE_PATH_OUTSIDE_ROOT", f"{field} must stay inside the workspace")
        raise AssertionError from exc
    if not relative or relative == "." or relative.startswith("../"):
        _reject("EXTERNAL_EVIDENCE_PATH_INVALID", f"{field} must be a file path")
    if exists and (not candidate.is_file()):
        _reject("EXTERNAL_EVIDENCE_PATH_INVALID", f"{field} must name a readable file")
    return candidate, relative


def _load_json(path: Path, field: str, *, max_bytes: int = MAX_SOURCE_BYTES) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        _reject("EXTERNAL_EVIDENCE_BUNDLE_INVALID", f"{field} cannot be read: {exc}")
    if len(raw) > max_bytes:
        _reject("EXTERNAL_EVIDENCE_SIZE_LIMIT", f"{field} exceeds {max_bytes} bytes")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _reject("EXTERNAL_EVIDENCE_BUNDLE_INVALID", f"{field} must be UTF-8 JSON: {exc}")
    if not isinstance(value, dict):
        _reject("EXTERNAL_EVIDENCE_BUNDLE_INVALID", f"{field} must contain one JSON object")
    return value, raw


def _text(value: object, field: str, *, identifier: bool = False, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        _reject("EXTERNAL_EVIDENCE_BUNDLE_INVALID", f"{field} must be a string")
    result = value.strip()
    if not result and not allow_empty:
        _reject("EXTERNAL_EVIDENCE_BUNDLE_INVALID", f"{field} must not be empty")
    if len(result) > MAX_TEXT:
        _reject("EXTERNAL_EVIDENCE_BUNDLE_INVALID", f"{field} exceeds {MAX_TEXT} characters")
    if identifier and not _ID.fullmatch(result):
        _reject("EXTERNAL_EVIDENCE_BUNDLE_INVALID", f"{field} has an unsupported identifier")
    return result


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        _reject("EXTERNAL_EVIDENCE_ARTIFACT_INVALID", f"{field} must be a lowercase SHA-256")
    return value


def _normalize_step(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _STEP_FIELDS:
        _reject("EXTERNAL_EVIDENCE_BUNDLE_INVALID", "first_failed_step must contain index and label")
    index = value.get("index")
    if index is not None and (isinstance(index, bool) or not isinstance(index, int) or index < 0):
        _reject("EXTERNAL_EVIDENCE_BUNDLE_INVALID", "first_failed_step.index must be a non-negative integer or null")
    label = value.get("label")
    if label is not None:
        label = _text(label, "first_failed_step.label")
    return {"index": index, "label": label}


def _normalize_artifacts(root: Path, value: object) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > MAX_ARTIFACTS:
        _reject("EXTERNAL_EVIDENCE_ARTIFACT_INVALID", f"artifacts must contain at most {MAX_ARTIFACTS} entries")
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict) or set(item) != _ARTIFACT_FIELDS:
            _reject("EXTERNAL_EVIDENCE_ARTIFACT_INVALID", f"artifacts[{index}] must contain path, sha256, and kind")
        path, relative = _workspace_file(root, item.get("path"), f"artifacts[{index}].path")
        if path.stat().st_size > MAX_ARTIFACT_BYTES:
            _reject("EXTERNAL_EVIDENCE_SIZE_LIMIT", f"artifact {relative} exceeds {MAX_ARTIFACT_BYTES} bytes")
        digest = _hash(item.get("sha256"), f"artifacts[{index}].sha256")
        actual = _sha_bytes(path.read_bytes())
        if actual != digest:
            _reject("EXTERNAL_EVIDENCE_ARTIFACT_STALE", f"artifact {relative} bytes do not match its SHA-256")
        kind = _text(item.get("kind"), f"artifacts[{index}].kind", identifier=True)
        if relative in seen:
            _reject("EXTERNAL_EVIDENCE_ARTIFACT_INVALID", f"artifact path {relative} is repeated")
        seen.add(relative)
        rows.append({"path": relative, "sha256": digest, "kind": kind})
    return sorted(rows, key=lambda item: (item["path"], item["sha256"], item["kind"]))


def _normalize_bundle(root: Path, value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _BUNDLE_FIELDS:
        _reject("EXTERNAL_EVIDENCE_BUNDLE_INVALID", "bundle has an unsupported field set")
    if value.get("schema") != BUNDLE_SCHEMA:
        _reject("EXTERNAL_EVIDENCE_BUNDLE_INVALID", f"schema must be {BUNDLE_SCHEMA}")
    provider = _text(value.get("provider"), "provider", identifier=True)
    if not _PROVIDER.fullmatch(provider):
        _reject("EXTERNAL_EVIDENCE_BUNDLE_INVALID", "provider has an unsupported identifier")
    for field in ("project_id", "test_id", "run_id", "snapshot_id", "code_version"):
        _text(value.get(field), field, identifier=True)
    environment = value.get("environment")
    if not isinstance(environment, dict) or set(environment) != _ENVIRONMENT_FIELDS:
        _reject("EXTERNAL_EVIDENCE_BUNDLE_INVALID", "environment must contain fingerprint and label")
    environment = {
        "fingerprint": _text(environment.get("fingerprint"), "environment.fingerprint", identifier=True),
        "label": _text(environment.get("label"), "environment.label"),
    }
    verdict = _text(value.get("verdict"), "verdict", identifier=True).lower()
    if verdict not in _VERDICTS:
        _reject("EXTERNAL_EVIDENCE_BUNDLE_INVALID", f"verdict must be one of {sorted(_VERDICTS)}")
    failure_kind = _text(value.get("failure_kind"), "failure_kind", identifier=True).lower()
    if failure_kind not in _FAILURE_KINDS:
        _reject("EXTERNAL_EVIDENCE_BUNDLE_INVALID", f"failure_kind must be one of {sorted(_FAILURE_KINDS)}")
    return {
        "schema": BUNDLE_SCHEMA,
        "provider": provider,
        "project_id": _text(value.get("project_id"), "project_id", identifier=True),
        "test_id": _text(value.get("test_id"), "test_id", identifier=True),
        "run_id": _text(value.get("run_id"), "run_id", identifier=True),
        "snapshot_id": _text(value.get("snapshot_id"), "snapshot_id", identifier=True),
        "code_version": _text(value.get("code_version"), "code_version", identifier=True),
        "environment": environment,
        "verdict": verdict,
        "failure_kind": failure_kind,
        "first_failed_step": _normalize_step(value.get("first_failed_step")),
        "hypothesis": _text(value.get("hypothesis"), "hypothesis", allow_empty=True),
        "recommended_fix": _text(value.get("recommended_fix"), "recommended_fix", allow_empty=True),
        "artifacts": _normalize_artifacts(root, value.get("artifacts")),
        "observed_at": _text(value.get("observed_at"), "observed_at"),
    }


def _receipt_core(value: dict[str, Any]) -> dict[str, Any]:
    return {key: value[key] for key in value if key != "receipt_sha256"}


def _receipt_from_bundle(bundle: dict[str, Any], source_path: str, source_digest: str) -> dict[str, Any]:
    core: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "marker": "EXTERNAL_EVIDENCE_IMPORTED",
        "provider": bundle["provider"],
        "project_id": bundle["project_id"],
        "test_id": bundle["test_id"],
        "run_id": bundle["run_id"],
        "snapshot_id": bundle["snapshot_id"],
        "code_version": bundle["code_version"],
        "environment": bundle["environment"],
        "verdict": bundle["verdict"],
        "failure_kind": bundle["failure_kind"],
        "first_failed_step": bundle["first_failed_step"],
        "hypothesis": bundle["hypothesis"],
        "recommended_fix": bundle["recommended_fix"],
        "artifacts": bundle["artifacts"],
        "observed_at": bundle["observed_at"],
        "source_bundle": {"path": source_path, "sha256": source_digest},
        "freshness": {
            "source_bundle_sha256": source_digest,
            "code_version": bundle["code_version"],
            "environment_fingerprint": bundle["environment"]["fingerprint"],
        },
        "authority": dict(_AUTHORITY),
        "trust": "observed_external",
        "markers": [
            "EXTERNAL_EVIDENCE_IMPORTED",
            "EXTERNAL_EVIDENCE_NO_PROVIDER_CALL",
            "EXTERNAL_EVIDENCE_RELEASE_AUTHORITY_RETAINED",
        ],
    }
    return {**core, "receipt_sha256": _sha(core)}


def _load_and_verify_receipt(root: Path, receipt_path: Path) -> tuple[dict[str, Any], str]:
    path, relative = _workspace_file(root, receipt_path, "receipt")
    value, raw = _load_json(path, "receipt")
    if value.get("schema") != RECEIPT_SCHEMA:
        _reject("EXTERNAL_EVIDENCE_RECEIPT_INVALID", f"receipt schema must be {RECEIPT_SCHEMA}")
    expected = value.get("receipt_sha256")
    if not isinstance(expected, str) or _sha(_receipt_core(value)) != expected:
        _reject("EXTERNAL_EVIDENCE_RECEIPT_STALE", "receipt canonical bytes do not match receipt_sha256")
    source = value.get("source_bundle")
    if not isinstance(source, dict) or set(source) != {"path", "sha256"}:
        _reject("EXTERNAL_EVIDENCE_RECEIPT_INVALID", "source_bundle must contain path and sha256")
    source_path, _source_relative = _workspace_file(root, source.get("path"), "source_bundle.path")
    source_digest = _hash(source.get("sha256"), "source_bundle.sha256")
    source_raw = source_path.read_bytes()
    if _sha_bytes(source_raw) != source_digest:
        _reject("EXTERNAL_EVIDENCE_BUNDLE_STALE", "source bundle bytes changed")
    source_value, _ = _load_json(source_path, "source_bundle")
    normalized = _normalize_bundle(root, source_value)
    if _receipt_from_bundle(normalized, str(source["path"]).replace("\\", "/"), source_digest) != value:
        _reject("EXTERNAL_EVIDENCE_RECEIPT_STALE", "receipt no longer matches its source bundle")
    # Re-run artifact checks against current bytes to catch a changed fixture.
    _normalize_artifacts(root, normalized["artifacts"])
    if value.get("authority") != _AUTHORITY or value.get("trust") != "observed_external":
        _reject("EXTERNAL_EVIDENCE_AUTHORITY_INVALID", "external evidence cannot carry execution or release authority")
    return value, relative


def import_external_runtime_bundle(root: Path, bundle: Path, provider: str, out: Path | None = None) -> dict[str, Any]:
    """Validate one local bundle and write one idempotent receipt."""
    workspace = Path(root).resolve()
    source_path, source_relative = _workspace_file(workspace, bundle, "bundle")
    source_value, source_raw = _load_json(source_path, "bundle")
    normalized = _normalize_bundle(workspace, source_value)
    requested_provider = _text(provider, "provider", identifier=True).lower()
    if normalized["provider"] != requested_provider:
        _reject("EXTERNAL_EVIDENCE_PROVIDER_MISMATCH", "bundle provider does not match --provider")
    receipt = _receipt_from_bundle(normalized, source_relative, _sha_bytes(source_raw))
    if out is None:
        out = workspace / ".factory" / "external-evidence" / (
            f"{normalized['provider']}-{_safe_filename(normalized['run_id'])}-{receipt['receipt_sha256'][:12]}.json"
        )
    out_path, out_relative = _workspace_file(workspace, out, "out", exists=False)
    if not out_relative.startswith(".factory/external-evidence/"):
        _reject("EXTERNAL_EVIDENCE_OUTPUT_INVALID", "receipt output must be below .factory/external-evidence/")
    encoded = _canonical(receipt) + b"\n"
    if out_path.exists():
        try:
            existing = out_path.read_bytes()
        except OSError as exc:
            _reject("EXTERNAL_EVIDENCE_OUTPUT_INVALID", f"existing output cannot be read: {exc}")
        if existing != encoded:
            _reject("EXTERNAL_EVIDENCE_OUTPUT_EXISTS", "output exists with different evidence")
        return {"status": "idempotent", "marker": "EXTERNAL_EVIDENCE_IMPORTED", "path": out_relative, "receipt": receipt}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(encoded)
    return {"status": "written", "marker": "EXTERNAL_EVIDENCE_IMPORTED", "path": out_relative, "receipt": receipt}


def diff_external_runtime_receipts(root: Path, left: Path, right: Path) -> dict[str, Any]:
    """Compare two verified receipts without treating either as an authority."""
    workspace = Path(root).resolve()
    left_value, left_relative = _load_and_verify_receipt(workspace, Path(left))
    right_value, right_relative = _load_and_verify_receipt(workspace, Path(right))
    same_identity = (
        left_value["provider"] == right_value["provider"]
        and left_value["project_id"] == right_value["project_id"]
        and left_value["test_id"] == right_value["test_id"]
        and left_value["run_id"] != right_value["run_id"]
    )
    identity = {
        "provider": left_value["provider"],
        "project_id": left_value["project_id"],
        "test_id": left_value["test_id"],
        "run_ids": [left_value["run_id"], right_value["run_id"]],
        "comparable": same_identity,
    }
    if not same_identity:
        core = {
            "schema": DIFF_SCHEMA,
            "marker": "EXTERNAL_DIFF_INCOMPARABLE",
            "comparable": False,
            "left": {"path": left_relative, "receipt_sha256": left_value["receipt_sha256"]},
            "right": {"path": right_relative, "receipt_sha256": right_value["receipt_sha256"]},
            "identity": identity,
            "deltas": {},
            "authority": dict(_AUTHORITY),
        }
        return {**core, "diff_sha256": _sha(core)}

    left_artifacts = {item["path"]: item["sha256"] for item in left_value["artifacts"]}
    right_artifacts = {item["path"]: item["sha256"] for item in right_value["artifacts"]}
    added = sorted(path for path in right_artifacts if path not in left_artifacts)
    removed = sorted(path for path in left_artifacts if path not in right_artifacts)
    changed = sorted(path for path in left_artifacts if path in right_artifacts and left_artifacts[path] != right_artifacts[path])
    deltas = {
        "verdict": {"from": left_value["verdict"], "to": right_value["verdict"], "changed": left_value["verdict"] != right_value["verdict"]},
        "failure_kind": {"from": left_value["failure_kind"], "to": right_value["failure_kind"], "changed": left_value["failure_kind"] != right_value["failure_kind"]},
        "first_failed_step": {"from": left_value["first_failed_step"], "to": right_value["first_failed_step"], "changed": left_value["first_failed_step"] != right_value["first_failed_step"]},
        "code_version": {"from": left_value["code_version"], "to": right_value["code_version"], "changed": left_value["code_version"] != right_value["code_version"]},
        "environment": {"from": left_value["environment"], "to": right_value["environment"], "changed": left_value["environment"] != right_value["environment"]},
        "artifacts": {"added": added, "removed": removed, "changed": changed},
    }
    core = {
        "schema": DIFF_SCHEMA,
        "marker": "EXTERNAL_DIFF_COMPARABLE",
        "comparable": True,
        "left": {"path": left_relative, "receipt_sha256": left_value["receipt_sha256"]},
        "right": {"path": right_relative, "receipt_sha256": right_value["receipt_sha256"]},
        "identity": identity,
        "deltas": deltas,
        "authority": dict(_AUTHORITY),
    }
    return {**core, "diff_sha256": _sha(core)}


def verify_external_runtime_receipt(root: Path, receipt: Path) -> dict[str, Any]:
    """Return a read-only verification projection for Graph Ops and callers."""
    value, relative = _load_and_verify_receipt(Path(root).resolve(), Path(receipt))
    return {
        "valid": True,
        "marker": "EXTERNAL_EVIDENCE_IMPORTED",
        "path": relative,
        "receipt": value,
    }


__all__ = [
    "BUNDLE_SCHEMA",
    "RECEIPT_SCHEMA",
    "DIFF_SCHEMA",
    "MAX_SOURCE_BYTES",
    "MAX_ARTIFACT_BYTES",
    "ExternalEvidenceError",
    "import_external_runtime_bundle",
    "diff_external_runtime_receipts",
    "verify_external_runtime_receipt",
]
