"""Compact reference exchange; receivers revalidate instead of trusting sender claims."""
from .contract import MODULES
from .continuity import ContinuityError, _sha
from .engineering_memory import recall_engineering_memory


def _route(sender, receiver):
    if sender not in MODULES or receiver not in MODULES or sender == receiver:
        raise ContinuityError("E_HANDOFF_ROUTE", "distinct registered assembly modules required")


def _packet(memory, sender, receiver):
    _route(sender, receiver)
    body = {"schema": "factory.knowledge-handoff.v1", "sender": sender, "receiver": receiver,
            "scope_sha256": memory["scope_sha256"], "influence_sha256": memory["influence_sha256"],
            "record_digests": sorted({r["record_sha256"] for r in memory["records"]}),
            "evidence_digests": sorted({e["sha256"] for r in memory["records"] for e in r["evidence"]}),
            "excluded": memory["excluded"], "authority": "none",
            "action_summary": "Transfer reference fingerprints; receiving module must revalidate locally."}
    return {**body, "packet_sha256": _sha(body)}


def create_knowledge_handoff(root, principal, tenant, purpose, scope, sender, receiver):
    """Create a deterministic packet without transporting summaries or evidence contents."""
    _route(sender, receiver)
    return _packet(recall_engineering_memory(root, principal, tenant, purpose, scope), sender, receiver)


def receive_knowledge_handoff(root, principal, tenant, purpose, scope, sender, receiver, packet):
    """Verify the expected route and current evidence before exposing reference data."""
    _route(sender, receiver)
    current = recall_engineering_memory(root, principal, tenant, purpose, scope)
    if packet != _packet(current, sender, receiver):
        raise ContinuityError("E_HANDOFF_STALE_OR_INVALID", "packet differs from current authorized evidence or route")
    return {"schema": "factory.knowledge-received.v1", "sender": sender, "receiver": receiver,
            "packet_sha256": packet["packet_sha256"], "memory": current, "authority": "none",
            "action_summary": "Revalidated local references; no execution or gate approval granted."}
