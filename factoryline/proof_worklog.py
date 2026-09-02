"""Create review-required worklog drafts from already verified local evidence.

This is deliberately not a ticketing connector.  It reads the sealed Oracle
Contract and existing local proof receipts, writes an immutable local draft on
an explicit CLI request, and never posts to GitHub, Jira, Linear, Slack, or any
other service.  A draft is a concise handoff aid, not evidence of a completed
release or an external delivery.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
from typing import Any

from .agent_proof_bridge import agent_proof_projection
from .atomic_proof_adapter import atomic_proof_projection
from .oracle_firewall import verify_oracle_contract


SCHEMA = "factory.proof-worklog-draft.v1"
MARKER = "PROOF_WORKLOG_DRAFT_REVIEW_REQUIRED"
MAX_BYTES = 1_048_576
AUTHORITY = {
    "execution": False,
    "approval": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


class ProofWorklogError(ValueError):
    """Stable refusal for a stale or unsafe local worklog request."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProofWorklogError("E_PROOF_WORKLOG_SCHEMA", "worklog must be canonical JSON") from exc


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _relative(root: Path, value: Path, field: str, *, exists: bool) -> Path:
    if value.is_absolute():
        target = value.resolve()
    else:
        target = (root / value).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ProofWorklogError("E_PROOF_WORKLOG_SCOPE", f"{field} must remain beneath the workspace") from exc
    if exists and not target.is_file():
        raise ProofWorklogError("E_PROOF_WORKLOG_EVIDENCE", f"{field} must name an existing workspace file")
    return target


def _write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False, prefix=".proof-worklog-", suffix=".tmp") as handle:
        handle.write(encoded)
        temporary = Path(handle.name)
    temporary.replace(path)


def _text(item: object, fallback: str) -> str:
    if isinstance(item, dict) and isinstance(item.get("statement"), str) and item["statement"].strip():
        return item["statement"].strip()[:240]
    return fallback


def _draft_text(contract: dict[str, Any], agent: dict[str, Any], atomic: dict[str, Any]) -> tuple[str, list[str]]:
    contract_id = str(contract.get("id", "sealed-contract"))
    scope = ", ".join(contract.get("scope_paths", [])) or "no declared scope"
    requirements = [_text(item, "Approved obligation") for item in contract.get("requirements", [])[:3]]
    forbidden = [_text(item, "Forbidden behavior") for item in contract.get("forbidden_behaviors", [])[:2]]
    lines = [
        f"# Proof review: {contract_id}",
        "",
        "This is a local review draft generated from hash-verified receipts. It has not been posted or sent anywhere.",
        "",
        "## Sealed intent",
        f"- Scope: `{scope}`",
        *[f"- Obligation: {item}" for item in requirements],
        *[f"- Guardrail: {item}" for item in forbidden],
        "",
        "## Observed local evidence",
        f"- Provider-neutral agent proof receipts currently bound: {agent['bound_count']}; invalid: {agent['invalid_count']}.",
        f"- Atomic workflow receipts currently bound: {atomic['bound_count']}; invalid: {atomic['invalid_count']}.",
        "",
        "## Human review requested",
        "- Confirm the observed receipts are relevant to this change.",
        "- Confirm the independent validators and negative cases are sufficient.",
        "- Decide whether to copy this draft into your tracker or worklog. Code Factory will not post it for you.",
    ]
    return "\n".join(lines) + "\n", requirements + forbidden


def create_proof_worklog(root: Path, contract_path: Path, out: Path | None = None) -> dict[str, Any]:
    """Write one immutable local, review-required worklog draft."""
    workspace = Path(root).resolve()
    contract_file = _relative(workspace, contract_path, "contract", exists=True)
    if contract_file.stat().st_size > MAX_BYTES:
        raise ProofWorklogError("E_PROOF_WORKLOG_EVIDENCE", "contract exceeds 1 MiB")
    checked = verify_oracle_contract(workspace, contract_file.relative_to(workspace))
    if not checked.get("ok"):
        raise ProofWorklogError("E_PROOF_WORKLOG_UNBOUND_INTENT", "worklog requires one current sealed Oracle Contract")
    contract = checked.get("contract")
    if not isinstance(contract, dict) or not isinstance(contract.get("contract_sha256"), str):
        raise ProofWorklogError("E_PROOF_WORKLOG_UNBOUND_INTENT", "sealed Oracle Contract is incomplete")
    agent, atomic = agent_proof_projection(workspace), atomic_proof_projection(workspace)
    markdown, obligations = _draft_text(contract, agent, atomic)
    core: dict[str, Any] = {
        "schema": SCHEMA,
        "marker": MARKER,
        "created_at": _now(),
        "contract": {
            "id": contract.get("id"),
            "path": contract_file.relative_to(workspace).as_posix(),
            "contract_sha256": contract["contract_sha256"],
            "scope_paths": list(contract.get("scope_paths", [])),
        },
        "obligation_summary": obligations,
        "evidence": {
            "agent_bridge": {"bound_count": agent["bound_count"], "invalid_count": agent["invalid_count"], "receipt_sha256s": [item["receipt_sha256"] for item in agent["receipts"]]},
            "atomic": {"bound_count": atomic["bound_count"], "invalid_count": atomic["invalid_count"], "receipt_sha256s": [item["receipt_sha256"] for item in atomic.get("receipts", [])]},
        },
        "markdown": markdown,
        "review_required": True,
        "authority": dict(AUTHORITY),
        "claim_boundary": "A local review draft from verified receipt summaries. It does not prove an external delivery, ticket update, production result, team acknowledgement, release, or approval and never posts to a third-party service.",
    }
    receipt = {**core, "draft_sha256": _sha(core)}
    destination = out or Path(".factory") / "worklogs" / f"{contract['id']}-{receipt['draft_sha256'][:12]}.json"
    target = _relative(workspace, destination, "out", exists=False)
    if target.exists():
        raise ProofWorklogError("E_PROOF_WORKLOG_EVIDENCE", "output draft already exists; use a new immutable path")
    _write(target, receipt)
    return {**receipt, "path": target.relative_to(workspace).as_posix()}


def verify_proof_worklog(root: Path, draft_path: Path) -> dict[str, Any]:
    """Verify one draft and current sealed contract binding without posting it."""
    workspace = Path(root).resolve()
    try:
        target = _relative(workspace, draft_path, "draft", exists=True)
        if target.stat().st_size > MAX_BYTES:
            raise ProofWorklogError("E_PROOF_WORKLOG_EVIDENCE", "draft exceeds 1 MiB")
        value = json.loads(target.read_text(encoding="utf-8-sig"))
        if not isinstance(value, dict) or value.get("schema") != SCHEMA:
            raise ProofWorklogError("E_PROOF_WORKLOG_SCHEMA", "draft schema is unsupported")
        core = {key: item for key, item in value.items() if key != "draft_sha256"}
        if value.get("draft_sha256") != _sha(core):
            raise ProofWorklogError("E_PROOF_WORKLOG_EVIDENCE", "draft digest does not match its canonical body")
        contract = value.get("contract")
        if not isinstance(contract, dict) or not isinstance(contract.get("path"), str):
            raise ProofWorklogError("E_PROOF_WORKLOG_UNBOUND_INTENT", "draft has no sealed contract binding")
        checked = verify_oracle_contract(workspace, Path(contract["path"]))
        if not checked.get("ok") or checked.get("contract", {}).get("contract_sha256") != contract.get("contract_sha256"):
            return {"ok": False, "marker": "PROOF_WORKLOG_DRAFT_INVALID", "reason": "oracle_binding_stale", "authority": dict(AUTHORITY)}
        return {"ok": True, "marker": "PROOF_WORKLOG_DRAFT_VALID", "draft": value, "path": target.relative_to(workspace).as_posix(), "authority": dict(AUTHORITY)}
    except (ProofWorklogError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {"ok": False, "marker": "PROOF_WORKLOG_DRAFT_INVALID", "reason": getattr(exc, "code", "E_PROOF_WORKLOG_SCHEMA"), "authority": dict(AUTHORITY)}


def proof_worklog_projection(root: Path) -> dict[str, Any]:
    """Return bounded, read-only draft facts for Graph Ops and MCP."""
    workspace = Path(root).resolve()
    drafts, invalid = [], []
    for path in sorted((workspace / ".factory" / "worklogs").glob("*.json"))[:200]:
        checked = verify_proof_worklog(workspace, path.relative_to(workspace))
        if not checked.get("ok"):
            invalid.append(path.relative_to(workspace).as_posix())
            continue
        draft = checked["draft"]
        drafts.append({"path": checked["path"], "contract_id": draft["contract"].get("id"), "contract_sha256": draft["contract"].get("contract_sha256"), "draft_sha256": draft["draft_sha256"], "review_required": True})
    return {"schema": "factory.proof-worklog-projection.v1", "marker": MARKER, "draft_count": len(drafts), "invalid_count": len(invalid), "latest": drafts[-1] if drafts else None, "drafts": drafts[-20:], "invalid": invalid[:100], "authority": dict(AUTHORITY), "claim_boundary": "Read-only local worklog draft facts. Nothing was sent, posted, approved, or released."}
