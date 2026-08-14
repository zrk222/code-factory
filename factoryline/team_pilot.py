"""Fail-closed Team Pilot readiness evidence.

This module makes the proposed Team Proof Hub operable as a *customer-managed
reference pilot* without pretending that Code Factory can sell, provision, or
operate a service.  It validates only locally supplied evidence files, binds
their bytes to a receipt, and leaves every commercial decision with a named
human owner and the external systems they choose.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any


TEAM_PILOT_MANIFEST_SCHEMA = "factory.team-pilot-launch.v1"
TEAM_PILOT_RECEIPT_SCHEMA = "factory.team-pilot-readiness.v1"
COMMERCIAL_PACKAGING_SCHEMA = "factory.commercial-packaging.v1"
REQUIRED_EVIDENCE_KINDS = frozenset({
    "commercial_terms_review",
    "data_retention_decision",
    "deployment_security_review",
    "design_partner_selection",
    "support_and_incident_owner",
})
RECEIPT_FIELDS = frozenset({
    "schema", "marker", "verdict", "manifest", "commercial_boundary", "evidence", "authority",
    "scope_limits", "receipt_sha256", "mermaid", "receipt_markdown",
})
_PILOT_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")

AUTHORITY = {
    "approval": False,
    "commercial_activation": False,
    "connector": False,
    "contracting": False,
    "credential": False,
    "deployment": False,
    "entitlement": False,
    "execution": False,
    "marketplace_activation": False,
    "messaging": False,
    "payment": False,
    "publication": False,
    "signing": False,
}


class TeamPilotError(ValueError):
    """A malformed Team Pilot package or a changed readiness receipt."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _reject(code: str, message: str) -> None:
    raise TeamPilotError(code, message)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _sha(value: object) -> str:
    return _sha_bytes(_canonical(value))


def _relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root).as_posix()


def _workspace_file(root: Path, value: object, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        _reject("E_TEAM_PILOT_EVIDENCE_PATH", f"{field} must be a non-empty workspace-relative path")
    raw = value.strip().replace("\\", "/")
    if raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw) or any(part == ".." for part in raw.split("/")):
        _reject("E_TEAM_PILOT_EVIDENCE_PATH", f"{field} must stay inside the workspace")
    candidate = (root / raw).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        _reject("E_TEAM_PILOT_EVIDENCE_PATH", f"{field} resolves outside the workspace")
    if not candidate.is_file():
        _reject("E_TEAM_PILOT_EVIDENCE_PATH", f"{field} must name an existing regular file")
    return candidate


def _load_json(root: Path, manifest_path: Path, *, code: str, label: str) -> tuple[dict[str, Any], Path, str]:
    candidate = Path(manifest_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        _reject(code, f"{label} path must stay inside the workspace")
    if not candidate.is_file():
        _reject(code, f"{label} path must name a readable JSON file")
    raw = candidate.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _reject(code, f"{label} must be valid UTF-8 JSON: {exc}")
    if not isinstance(value, dict):
        _reject(code, f"{label} must contain one JSON object")
    return value, candidate, _sha_bytes(raw)


def _text(value: object, field: str, *, pattern: re.Pattern[str] | None = None, limit: int = 128) -> str:
    if not isinstance(value, str) or not value.strip():
        _reject("E_TEAM_PILOT_SCHEMA", f"{field} must be a non-empty string")
    result = value.strip()
    if len(result) > limit or "\x00" in result:
        _reject("E_TEAM_PILOT_SCHEMA", f"{field} must be at most {limit} characters and contain no NUL byte")
    if pattern and not pattern.fullmatch(result):
        _reject("E_TEAM_PILOT_SCHEMA", f"{field} has an unsupported format")
    return result


def _validate_packaging(root: Path) -> dict[str, str | bool]:
    path = root / "docs" / "COMMERCIAL_PACKAGING.json"
    package, _, digest = _load_json(root, path, code="E_TEAM_PILOT_COMMERCIAL_BOUNDARY", label="commercial packaging")
    try:
        team = package["tiers"]["team_proof_hub"]
        valid = (
            package["schema"] == COMMERCIAL_PACKAGING_SCHEMA
            and package["governance"]["classification"] == "human_controlled"
            and package["governance"]["automation_may_activate"] is False
            and package["current_verdict"] == "COMMERCIALIZATION_STAGED_NOT_SELLABLE"
            and team["availability"] == "design_partner_only"
            and team["purchasable"] is False
        )
    except (KeyError, TypeError):
        valid = False
    if not valid:
        _reject(
            "E_TEAM_PILOT_COMMERCIAL_BOUNDARY",
            "commercial packaging must retain the human-controlled, design-partner-only, not-sellable Team boundary",
        )
    return {
        "path": _relative(root, path),
        "sha256": digest,
        "availability": "design_partner_only",
        "purchasable": False,
    }


def _validate_manifest_header(source: dict[str, Any]) -> int:
    allowed = {"schema", "pilot_id", "owner", "partner_count", "governance", "delivery_mode", "evidence"}
    if set(source) != allowed:
        _reject("E_TEAM_PILOT_SCHEMA", "manifest must contain exactly schema, pilot_id, owner, partner_count, governance, delivery_mode, and evidence")
    if source.get("schema") != TEAM_PILOT_MANIFEST_SCHEMA:
        _reject("E_TEAM_PILOT_SCHEMA", f"schema must be {TEAM_PILOT_MANIFEST_SCHEMA}")
    partner_count = source.get("partner_count")
    if isinstance(partner_count, bool) or not isinstance(partner_count, int) or not 1 <= partner_count <= 3:
        _reject("E_TEAM_PILOT_PARTNER_CAP", "partner_count must be an integer from 1 through 3")
    if source.get("governance") != "human_controlled":
        _reject("E_TEAM_PILOT_GOVERNANCE", "governance must be human_controlled")
    if source.get("delivery_mode") != "customer_managed_reference":
        _reject("E_TEAM_PILOT_DELIVERY_MODE", "delivery_mode must be customer_managed_reference; managed service delivery is not offered")
    return partner_count


def _validate_evidence_item(root: Path, item: object, index: int) -> dict[str, str]:
    if not isinstance(item, dict) or set(item) != {"kind", "path", "sha256"}:
        _reject("E_TEAM_PILOT_SCHEMA", f"evidence[{index}] must contain exactly kind, path, and sha256")
    kind = item.get("kind")
    if not isinstance(kind, str) or kind not in REQUIRED_EVIDENCE_KINDS:
        _reject("E_TEAM_PILOT_EVIDENCE_KIND", f"evidence[{index}].kind must be a required readiness evidence kind")
    evidence_path = _workspace_file(root, item.get("path"), f"evidence[{index}].path")
    digest = item.get("sha256")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        _reject("E_TEAM_PILOT_EVIDENCE_DIGEST", f"evidence[{index}].sha256 must be a lowercase SHA-256 digest")
    actual = _sha_bytes(evidence_path.read_bytes())
    if actual != digest:
        _reject("E_TEAM_PILOT_EVIDENCE_DIGEST", f"evidence[{index}] does not match the declared SHA-256 digest")
    return {"kind": kind, "path": _relative(root, evidence_path), "sha256": actual}


def _validate_evidence(root: Path, evidence: object) -> list[dict[str, str]]:
    if not isinstance(evidence, list) or len(evidence) != len(REQUIRED_EVIDENCE_KINDS):
        _reject("E_TEAM_PILOT_EVIDENCE_KIND", "evidence must contain exactly one item for every required readiness evidence kind")
    normalized: list[dict[str, str]] = []
    kinds: set[str] = set()
    paths: set[str] = set()
    for index, item in enumerate(evidence):
        validated = _validate_evidence_item(root, item, index)
        if validated["kind"] in kinds:
            _reject("E_TEAM_PILOT_EVIDENCE_KIND", "evidence kinds must not repeat")
        if validated["path"] in paths:
            _reject("E_TEAM_PILOT_EVIDENCE_PATH", "evidence paths must not repeat")
        kinds.add(validated["kind"])
        paths.add(validated["path"])
        normalized.append(validated)
    if kinds != REQUIRED_EVIDENCE_KINDS:
        _reject("E_TEAM_PILOT_EVIDENCE_KIND", "evidence does not cover every required readiness evidence kind")
    return sorted(normalized, key=lambda item: item["kind"])


def validate_team_pilot_manifest(root: Path, manifest_path: Path) -> dict[str, Any]:
    """Validate a bounded customer-managed pilot launch manifest without I/O beyond declared local evidence."""
    workspace = Path(root).resolve()
    source, path, manifest_sha256 = _load_json(workspace, manifest_path, code="E_TEAM_PILOT_SCHEMA", label="manifest")
    partner_count = _validate_manifest_header(source)
    return {
        "schema": TEAM_PILOT_MANIFEST_SCHEMA,
        "pilot_id": _text(source.get("pilot_id"), "pilot_id", pattern=_PILOT_ID, limit=63),
        "owner": _text(source.get("owner"), "owner"),
        "partner_count": partner_count,
        "governance": "human_controlled",
        "delivery_mode": "customer_managed_reference",
        "evidence": _validate_evidence(workspace, source.get("evidence")),
        "manifest_path": _relative(workspace, path),
        "manifest_sha256": manifest_sha256,
    }


def _mermaid(receipt: dict[str, Any]) -> str:
    return "\n".join([
        "flowchart LR",
        '  S["Selected design partners"] --> G["Team Pilot readiness gate"]',
        '  D["Security and retention decisions"] --> G',
        '  O["Named support and incident owner"] --> G',
        '  T["Commercial terms reviewed"] --> G',
        '  G --> R["TEAM_PILOT_READY_FOR_OWNER_REVIEW"]',
        '  R --> H["Named owner decides activation externally"]',
        "",
    ])


def _markdown(receipt: dict[str, Any]) -> str:
    manifest = receipt["manifest"]
    return "\n".join([
        "# Team Pilot readiness receipt",
        "",
        f"- Pilot: `{manifest['pilot_id']}`",
        f"- Owner: `{manifest['owner']}`",
        f"- Selected partners: `{manifest['partner_count']}` (maximum 3)",
        f"- Result: `{receipt['marker']}`",
        f"- Receipt SHA-256: `{receipt['receipt_sha256']}`",
        "",
        "## Evidence bound",
        "",
        *[f"- `{entry['kind']}`: `{entry['path']}` (`{entry['sha256']}`)" for entry in receipt["evidence"]],
        "",
        "## Scope limit",
        "",
        "This local receipt confirms only that the declared customer-managed pilot evidence was present and hash-bound. It does not accept a customer, create a contract, process payment, provision access, activate a Marketplace offer, deploy a managed service, or establish a security/compliance certification.",
        "",
    ])


def evaluate_team_pilot_readiness(root: Path, manifest_path: Path) -> dict[str, Any]:
    """Produce a deterministic owner-review receipt for a valid local Team Pilot manifest."""
    workspace = Path(root).resolve()
    manifest = validate_team_pilot_manifest(workspace, manifest_path)
    commercial = _validate_packaging(workspace)
    core = {
        "schema": TEAM_PILOT_RECEIPT_SCHEMA,
        "marker": "TEAM_PILOT_READY_FOR_OWNER_REVIEW",
        "verdict": "READY_FOR_OWNER_REVIEW",
        "manifest": manifest,
        "commercial_boundary": commercial,
        "evidence": manifest["evidence"],
        "authority": AUTHORITY,
        "scope_limits": [
            "The Team Proof Hub remains design-partner-only and not purchasable; this is not a checkout, trial, billing, or entitlement decision.",
            "The only supported delivery mode is customer_managed_reference. This receipt does not claim a managed service, hosted availability, SLA, SSO/SCIM, external KMS, or compliance certification.",
            "A named owner must make any contracting, payment, access, Marketplace, deployment, publication, or service-activation decision outside this local readiness gate.",
        ],
    }
    receipt = {**core, "receipt_sha256": _sha(core)}
    receipt["mermaid"] = _mermaid(receipt)
    receipt["receipt_markdown"] = _markdown(receipt)
    return receipt


def _validate_receipt_shape(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != TEAM_PILOT_RECEIPT_SCHEMA:
        _reject("E_TEAM_PILOT_RECEIPT_INVALID", f"a {TEAM_PILOT_RECEIPT_SCHEMA} payload is required")
    if set(value) != RECEIPT_FIELDS:
        _reject("E_TEAM_PILOT_RECEIPT_INVALID", "receipt has unsupported or missing fields")
    return value


def _validate_receipt_core(value: dict[str, Any]) -> None:
    if value["marker"] != "TEAM_PILOT_READY_FOR_OWNER_REVIEW" or value["verdict"] != "READY_FOR_OWNER_REVIEW":
        _reject("E_TEAM_PILOT_RECEIPT_INVALID", "receipt must preserve the owner-review-only terminal state")
    if value["authority"] != AUTHORITY:
        _reject("E_TEAM_PILOT_RECEIPT_INVALID", "receipt authority boundary changed")
    if not isinstance(value["receipt_sha256"], str) or not _SHA256.fullmatch(value["receipt_sha256"]):
        _reject("E_TEAM_PILOT_RECEIPT_INVALID", "receipt_sha256 must be a lowercase SHA-256 digest")
    core = {key: value[key] for key in RECEIPT_FIELDS - {"receipt_sha256", "mermaid", "receipt_markdown"}}
    if value["receipt_sha256"] != _sha(core):
        _reject("E_TEAM_PILOT_RECEIPT_INVALID", "receipt SHA-256 does not match")


def _validate_receipt_views(value: dict[str, Any]) -> None:
    if value["evidence"] != value["manifest"].get("evidence"):
        _reject("E_TEAM_PILOT_RECEIPT_INVALID", "receipt evidence must match the normalized manifest evidence")
    if value["mermaid"] != _mermaid(value) or value["receipt_markdown"] != _markdown(value):
        _reject("E_TEAM_PILOT_RECEIPT_INVALID", "receipt Markdown or Mermaid does not match the receipt facts")


def validate_team_pilot_receipt(value: object) -> dict[str, Any]:
    """Verify the immutable facts and presentation projections of a Team Pilot receipt."""
    receipt = _validate_receipt_shape(value)
    _validate_receipt_core(receipt)
    _validate_receipt_views(receipt)
    return receipt


def write_team_pilot_artifacts(receipt: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Write public Team Pilot receipt views below an explicit caller-provided directory."""
    validated = validate_team_pilot_receipt(receipt)
    destination = Path(out_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    stem = f"team-pilot-{validated['receipt_sha256'][:12]}"
    paths = {
        "json": destination / f"{stem}.json",
        "markdown": destination / f"{stem}.md",
        "mermaid": destination / f"{stem}.mmd",
    }
    contents = {
        "json": json.dumps(validated, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n",
        "markdown": validated["receipt_markdown"].encode("utf-8"),
        "mermaid": validated["mermaid"].encode("utf-8"),
    }
    digests: dict[str, str] = {}
    for name, content in contents.items():
        temporary = paths[name].with_name(f".{paths[name].name}.tmp")
        temporary.write_bytes(content)
        temporary.replace(paths[name])
        digests[name] = _sha_bytes(content)
    return {
        "marker": "TEAM_PILOT_ARTIFACTS_WRITTEN",
        "paths": {name: str(path) for name, path in paths.items()},
        "sha256": digests,
    }
