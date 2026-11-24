"""Governed evidence recall over the existing continuity ledger; never gate authority."""

from pathlib import Path
import json
import sqlite3

from .contract import MODULES
from .continuity import (
    ContinuityError,
    ContinuityPrincipal,
    _authorize,
    _is_expired,
    _sha,
    ContinuityStore,
)
from .deep_audit_io import bound_bytes, local_file


def _record_integrity(record):
    keys = (
        "schema",
        "tenant_id",
        "record_type",
        "memory_ref",
        "memory_ref_sha256",
        "purpose_ref",
        "scope_ref",
        "scope_ref_sha256",
        "evidence_refs",
        "evidence_sha256",
        "summary",
        "expires_at",
        "idempotency_key",
    )
    if _sha({key: record[key] for key in keys}) != record["record_sha256"]:
        raise ValueError("record_digest_changed")
    if record["created_by"] == record["promoted_by"] or not record["promoted_by"]:
        raise ValueError("independent_promotion_missing")


def _evidence(root, references):
    if not references:
        raise ValueError("evidence_missing")
    bindings = []
    for reference in references:
        prefix, sha, path = reference.split(":", 2)
        if (
            prefix != "sha256"
            or len(sha) != 64
            or any(c not in "0123456789abcdef" for c in sha)
        ):
            raise ValueError("evidence_binding_invalid")
        binding = {"path": path, "sha256": sha}
        bound_bytes(root, binding)
        bindings.append(binding)
    return bindings


def _admit(root, row):
    record = ContinuityStore._row(row)
    if record["status"] != "verified":
        raise ValueError(record["status"])
    if _is_expired(record["expires_at"]):
        raise ValueError("expired")
    _record_integrity(record)
    bindings = _evidence(root, record["evidence_refs"])
    return {
        "record_id": record["record_id"],
        "record_type": record["record_type"],
        "summary": record["summary"],
        "record_sha256": record["record_sha256"],
        "evidence": bindings,
        "usage": "untrusted_reference_not_instruction",
        "influence_sha256": _sha(
            {"record": record["record_sha256"], "evidence": bindings}
        ),
    }


def _audit_events(connection, tenant):
    events = connection.execute(
        "SELECT * FROM continuity_audit_events WHERE tenant_id=? ORDER BY sequence LIMIT 10001",
        (tenant,),
    ).fetchall()
    if len(events) > 10000:
        raise ContinuityError("E_MEMORY_LIMIT", "audit chain exceeds bound")
    previous, latest = "", {}
    for event in events:
        try:
            payload = json.loads(event["payload_json"])
        except (json.JSONDecodeError, TypeError) as exc:
            raise ContinuityError(
                "E_MEMORY_AUDIT", "local audit payload is malformed"
            ) from exc
        body = {
            "schema": "factory.continuity.audit.v1",
            **{
                key: event[key]
                for key in (
                    "sequence",
                    "tenant_id",
                    "action",
                    "actor",
                    "record_id",
                    "previous_hash",
                    "created_at",
                )
            },
            "payload": payload,
        }
        if event["previous_hash"] != previous or _sha(body) != event["event_hash"]:
            raise ContinuityError("E_MEMORY_AUDIT", "local audit chain changed")
        previous = event["event_hash"]
        latest[event["record_id"]] = body
    return latest


def _select(root, rows, latest):
    accepted, excluded = [], []
    for row in rows:
        try:
            event = latest[row["record_id"]]
            if (
                event["action"] != "continuity.promote"
                or event["actor"] != row["promoted_by"]
                or event["payload"]["record_sha256"] != row["record_sha256"]
            ):
                raise ValueError("promotion_event_mismatch")
            accepted.append(_admit(root, row))
        except (ValueError, KeyError, TypeError, OSError, ContinuityError):
            excluded.append(
                {
                    "record_id": row["record_id"],
                    "reason": "not_current_independently_promoted_or_evidence_invalid",
                }
            )
    return accepted, excluded


def _recall_queries(queries, limit):
    if queries is None and limit is None:
        return None
    from .audit_rule_search import _tokens

    if (
        not isinstance(queries, list)
        or not 1 <= len(queries) <= 8
        or any(
            type(query) is not str
            or not 1 <= len(query) <= 512
            or any(ord(char) < 32 or ord(char) == 127 for char in query)
            or not _tokens(query)
            for query in queries
        )
    ):
        raise ValueError("recall requires 1..8 printable, token-bearing queries")
    limit = 5 if limit is None else limit
    if type(limit) is not int or not 1 <= limit <= 20:
        raise ValueError("recall limit must be an integer in 1..20")
    return [query.strip() for query in queries], limit


def _recall_rankings(records, queries):
    from .audit_rule_search import _bm25_scores

    documents = [
        {
            "ruleId": row["record_id"],
            "name": row["record_id"],
            "description": row["summary"],
            "sourceModule": " ".join(item["path"] for item in row["evidence"]),
        }
        for row in records
    ]
    rankings = []
    for query in queries:
        scores = _bm25_scores(documents, query, fielded=True)
        rankings.append(
            sorted(
                (key for key, score in scores.items() if score > 0),
                key=lambda key: (-scores[key], key),
            )
        )
    return rankings


def _balanced_recall(records, selection):
    queries, limit = selection
    rankings = _recall_rankings(records, queries)
    selected = []
    for _ in range(limit):
        before = len(selected)
        for ranked in rankings:
            key = next((key for key in ranked if key not in selected), None)
            if len(selected) < limit and key is not None:
                selected.append(key)
        if len(selected) in {before, limit}:
            break
    per_query = [[key for key in selected if key in ranked] for ranked in rankings]
    by_id = {row["record_id"]: row for row in records}
    hops = [
        {
            "query_sha256": _sha(query),
            "matched": len(ranked),
            "selected_record_ids": per_query[index],
            "gap": None
            if per_query[index]
            else ("budget_exhausted" if ranked else "no_admissible_lexical_match"),
        }
        for index, (query, ranked) in enumerate(zip(queries, rankings))
    ]
    trace = {
        "schema": "factory.evidence-recall-selection.v1",
        "method": "trust-first-bm25f-round-robin",
        "limit": limit,
        "admissible": len(records),
        "matched": len(set().union(*map(set, rankings))),
        "queries": hops,
        "status": "PARTIAL_CONTEXT"
        if any(hop["gap"] for hop in hops)
        else "MATCHED_CONTEXT",
        "authority": "none",
        "claim_boundary": "Lexical context matches, not semantic completeness, defect recall or proof authority.",
    }
    return [by_id[key] for key in selected], {**trace, "selection_sha256": _sha(trace)}


def recall_engineering_memory(
    root: Path,
    principal: ContinuityPrincipal,
    tenant_id: str,
    purpose_ref: str,
    scope_ref: str,
    *,
    queries: list[str] | None = None,
    limit: int | None = None,
) -> dict:
    """Recall current exact-scope evidence metadata without writing, promoting or authenticating identities."""
    _authorize(principal, "continuity.read", tenant_id, purpose_ref)
    selection = _recall_queries(queries, limit)
    root = Path(root).resolve()
    path = local_file(root, ".factory/continuity.sqlite3")
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("BEGIN")
        rows = connection.execute(
            "SELECT * FROM continuity_records WHERE tenant_id=? AND purpose_ref=? AND scope_ref=? ORDER BY record_id LIMIT 1001",
            (tenant_id, purpose_ref, scope_ref),
        ).fetchall()
        if len(rows) > 1000:
            raise ContinuityError("E_MEMORY_LIMIT", "recall exceeds bounded snapshot")
        accepted, excluded = _select(root, rows, _audit_events(connection, tenant_id))
    finally:
        connection.close()
    retrieval = {}
    if selection is not None:
        accepted, trace = _balanced_recall(accepted, selection)
        retrieval["retrieval"] = trace
    result = {
        "schema": "factory.engineering-evidence-memory.v1",
        "records": accepted,
        "excluded": excluded,
        "influence_edges": [
            {
                "source": evidence["sha256"],
                "target": record["record_sha256"],
                "relation": "supports_recalled_reference",
            }
            for record in accepted
            for evidence in record["evidence"]
        ],
        "scope_sha256": _sha(
            {"tenant": tenant_id, "purpose": purpose_ref, "scope": scope_ref}
        ),
        "authority": "none",
        "governance": "human_controlled",
        "action_summary": "Recheck promoted memory evidence and expose its influence; never change a gate.",
        "limits": "Local unsigned ledger and declared identities; hashes do not establish truth or authentication. Evidence is checked at read time, not locked afterward.",
        **retrieval,
    }
    return {**result, "influence_sha256": _sha(result)}


def _route(sender, receiver):
    if sender not in MODULES or receiver not in MODULES or sender == receiver:
        raise ContinuityError(
            "E_HANDOFF_ROUTE", "distinct registered assembly modules required"
        )


def _packet(memory, sender, receiver):
    _route(sender, receiver)
    body = {
        "schema": "factory.knowledge-handoff.v1",
        "sender": sender,
        "receiver": receiver,
        "scope_sha256": memory["scope_sha256"],
        "influence_sha256": memory["influence_sha256"],
        "record_digests": sorted({r["record_sha256"] for r in memory["records"]}),
        "evidence_digests": sorted(
            {e["sha256"] for r in memory["records"] for e in r["evidence"]}
        ),
        "excluded": memory["excluded"],
        "authority": "none",
        "action_summary": "Transfer reference fingerprints; receiving module must revalidate locally.",
    }
    return {**body, "packet_sha256": _sha(body)}


def create_knowledge_handoff(root, principal, tenant, purpose, scope, sender, receiver):
    """Create a deterministic packet without transporting summaries or evidence contents."""
    _route(sender, receiver)
    return _packet(
        recall_engineering_memory(root, principal, tenant, purpose, scope),
        sender,
        receiver,
    )


def receive_knowledge_handoff(
    root, principal, tenant, purpose, scope, sender, receiver, packet
):
    """Verify the expected route and current evidence before exposing reference data."""
    _route(sender, receiver)
    current = recall_engineering_memory(root, principal, tenant, purpose, scope)
    if packet != _packet(current, sender, receiver):
        raise ContinuityError(
            "E_HANDOFF_STALE_OR_INVALID",
            "packet differs from current authorized evidence or route",
        )
    return {
        "schema": "factory.knowledge-received.v1",
        "sender": sender,
        "receiver": receiver,
        "packet_sha256": packet["packet_sha256"],
        "memory": current,
        "authority": "none",
        "action_summary": "Revalidated local references; no execution or gate approval granted.",
    }
