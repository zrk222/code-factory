"""Read-only repair comparisons and graph lineage; self-hashes grant no authority."""
from pathlib import Path
import re

from .deep_audit import _read_receipt
from .deep_audit_io import digest
from .runtime_audit_common import RuntimeAuditError


def _hash(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("missing or invalid digest")
    return value


def _load(root: Path, relative: str) -> dict:
    receipt, sha, _ = _read_receipt(root, root / relative)
    for key in ("ruleset_sha256", "canary_set_sha256", "candidate_sha256", "plan_sha256"):
        _hash(receipt[key])
    for key in ("report_hashes", "canary_hashes"):
        values = receipt[key]
        if not isinstance(values, dict) or not 1 <= len(values) <= 8:
            raise ValueError("missing analyzer coverage")
        for value in values.values():
            _hash(value)
    if set(receipt["report_hashes"]) != set(receipt["canary_hashes"]):
        raise ValueError("canary coverage differs")
    _validate_findings(receipt)
    return {**receipt, "receipt_sha256": sha}


def _validate_findings(receipt: dict) -> None:
    for key in ("findings", "repair_queue"):
        if not isinstance(receipt[key], list) or len(receipt[key]) > 20_000:
            raise ValueError("invalid evidence collection")
    identities = [_hash(item["finding_id"]) for item in receipt["findings"]]
    if len(identities) != len(set(identities)):
        raise ValueError("duplicate finding identity")
    for item in receipt["repair_queue"]:
        if not isinstance(item, dict) or not isinstance(item.get("code"), str):
            raise ValueError("invalid repair action")


def _action_ids(receipt: dict) -> set:
    return {digest({key: item.get(key) for key in ("code", "finding_id", "rule_id", "canary_id", "analyzer_id")})
            for item in receipt["repair_queue"]}


def _compare(before: dict, after: dict) -> dict:
    for key in ("ruleset_sha256", "canary_set_sha256"):
        if before[key] != after[key]:
            raise RuntimeAuditError("E_DEEP_POLICY_CHANGED", "Policy or canary set changed; request independent review.")
    if set(before["report_hashes"]) != set(after["report_hashes"]):
        raise RuntimeAuditError("E_DEEP_COVERAGE_CHANGED", "Analyzer coverage changed; comparison cannot justify progress.")
    old = {item["finding_id"] for item in before["findings"]}
    new = {item["finding_id"] for item in after["findings"]}
    introduced, resolved = sorted(new - old), sorted(old - new)
    new_actions = sorted(_action_ids(after) - _action_ids(before))
    if introduced or new_actions:
        state = "regressed"
    elif after["decision"] == "READY_FOR_HUMAN_REVIEW" and not after["repair_queue"]:
        state = "approval_required"
    elif resolved:
        state = "repair_required"
    else:
        state = "stagnated"
    return {"state": state, "introduced": introduced, "resolved": resolved,
            "new_blocker_ids": new_actions, "remaining_findings": len(new),
            "repair_queue": after["repair_queue"]}


def compare_deep_audits(root: Path, before_path: str, after_path: str) -> dict:
    """Compare two explicit local receipts; never authenticate, repair, approve or execute a loop."""
    root = Path(root).resolve()
    base = {"schema": "factory.deep-audit-comparison.v1", "authority": "none",
            "governance": "human_controlled", "verification": "self_hash_only_not_signature_or_freshness",
            "action_summary": "Compare findings and blockers; stop for human review on incompatibility, regression or no progress."}
    try:
        before, after = _load(root, before_path), _load(root, after_path)
        compared = _compare(before, after)
        return {**base, **compared, "before_sha256": before["receipt_sha256"], "after_sha256": after["receipt_sha256"]}
    except (ValueError, OSError, KeyError, TypeError) as exc:
        return {**base, "state": "blocked", "code": getattr(exc, "code", "E_DEEP_RECEIPT_INVALID")}


def deep_audit_lineage(root: Path, status: dict) -> dict:
    """Project at most fifty finding chains from the exact observed receipt, without trusting its signer."""
    base = {"state": status["state"], "chains": [], "truncated": False, "authority": "none"}
    if "receipt_path" not in status:
        return base
    try:
        root = Path(root).resolve()
        relative = Path(status["receipt_path"]).relative_to(root).as_posix()
        receipt = _load(root, relative)
        if receipt["receipt_sha256"] != status["receipt_sha256"]:
            raise ValueError("observation changed")
        chains = [_chain(item, receipt, relative) for item in receipt["findings"][:50]]
        return {**base, "receipt_path": relative, "receipt_sha256": receipt["receipt_sha256"],
                "chains": chains, "truncated": len(receipt["findings"]) > 50,
                "verification": "self_hash_only_not_signature_or_freshness"}
    except (ValueError, OSError, KeyError, TypeError, IndexError):
        return {**base, "state": "INCOMPLETE"}


def _chain(item: dict, receipt: dict, relative: str) -> dict:
    location = item["locations"][0]
    return {"finding_id": item["finding_id"], "source": location["path"],
            "source_sha256": location["source_sha256"], "obligation": item.get("obligation_id", "unmapped"),
            "trace_sha256": item["trace_sha256"], "receipt_path": relative,
            "decision": receipt["decision"], "handoff": "human_review_required"}
