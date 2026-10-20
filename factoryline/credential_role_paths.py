"""Bounded source-role witnesses for canonical HTTP URL and auth slots."""

import ast
import hashlib

from .credential_publication_catalog import endpoint_publications
from .credential_role_adapter_selection import default_session_evidence
from .credential_role_bindings import (
    auth_constructor_password,
    candidate_facts,
    matches_fact,
    url_use,
)
from .credential_role_constructor_flow import constructor_url_hops
from .credential_role_session_calls import session_request_context
from .credential_role_sources import SourceSnapshotIndex
from .semantic_credential_sensor import (
    _canonical_http_call,
    _provider_identity_uncertain,
)


def _slots(call, path, aliases, session_request=False):
    name = _canonical_http_call(call, aliases[path])
    if not name and session_request:
        name = "requests.Session.request"
    if not name:
        return []
    from .security_configuration import _keyword

    url = _keyword(call, "url", 1 if name.endswith(".request") else 0)
    rows = [("http_url", "endpoint_locator", url)] if url is not None else []
    auth = _keyword(call, "auth")
    if isinstance(auth, (ast.Tuple, ast.List)) and len(auth.elts) == 2:
        rows.append(("http_auth", "password", auth.elts[1]))
    headers = _keyword(call, "headers")
    if isinstance(headers, ast.Dict) and all(
        isinstance(key, ast.Constant) and isinstance(key.value, str)
        for key in headers.keys
    ):
        exact = {key.value: value for key, value in zip(headers.keys, headers.values)}
        value = next(
            (v for k, v in exact.items() if k.casefold() == "authorization"), None
        )
        if value is not None:
            rows.append(("http_header", "authorization", value))
    return rows


def _module_indexes(snapshots, audit):
    classes, aliases, duplicates = {}, {}, set()
    for path, tree in snapshots.items():
        if isinstance(tree, ast.Module):
            aliases[path] = audit._module_security_aliases(tree)
            for node in tree.body:
                if isinstance(node, ast.ClassDef):
                    key = (path, node.name)
                    if key in classes:
                        duplicates.add(key)
                    classes[key] = node
    for key in duplicates:
        classes.pop(key, None)
    return classes, aliases


def _sink_rows(snapshots, aliases, index, default_session):
    rows = []
    for path, tree in snapshots.items():
        if not isinstance(tree, ast.Module):
            continue
        mutation_profiles = {}
        nodes = tuple(ast.walk(tree))
        parents = None
        for call in (n for n in nodes if isinstance(n, ast.Call)):
            from .review_integrity import _security_flow_bindings

            lexical, _ = _security_flow_bindings(call, aliases[path])
            identity = session_request_context(call, index, path, aliases[path])
            session = bool(
                default_session and identity == default_session["get_adapter_canonical"]
            )
            session_meta = default_session if session else None
            slots = _slots(call, path, aliases, session)
            password = auth_constructor_password(call, path, aliases)
            if password is not None:
                slots.append(("http_auth", "password", password))
            if not any(row[2] is not None for row in slots):
                continue
            identity_key = tuple(sorted(lexical.items()))
            if identity_key not in mutation_profiles:
                if parents is None:
                    parents = {
                        id(child): node
                        for node in nodes
                        for child in ast.iter_child_nodes(node)
                    }
                mutation_profiles[identity_key] = _provider_identity_uncertain(
                    tree, lexical, nodes=nodes, parents=parents
                )
            if mutation_profiles[identity_key]:
                continue
            rows.extend(
                (path, call, *row, session_meta) for row in slots if row[2] is not None
            )
    return rows


def _fact_row(fact):
    return {
        "declaration": fact.public_facts(),
        "profile": "DECLARED_CLASS_MAY_FLOW",
        "url_witnesses": [],
        "known_auth_uses": [],
        "linked_unknown_uses": [],
    }


def _analyze_fact(fact, evidence, sinks, context, publications, aliases):
    for path, call, role, slot, expr, session_meta in sinks:
        records = record_use(fact, path, call, slot, expr, *context, aliases=aliases)
        for record in records or ():
            if session_meta:
                record["consumer_profile"] = session_meta["profile"]
                record["session_hops"] = session_meta["hops"]
                record["runtime_overrides"] = {
                    "setting_getter": session_meta["runtime_setting_getter"],
                    "adapter": session_meta["runtime_adapter_override"],
                }
            if role == "http_url":
                url_use(fact, record, evidence, publications)
            else:
                evidence["known_auth_uses"].append(record)


def _analyze(root, snapshots, imports, source_bytes, inventory, audit, integrity):
    index = SourceSnapshotIndex(root, snapshots, source_bytes, inventory)
    classes, aliases = _module_indexes(snapshots, audit)
    from .credential_role_chain_memo import ClassChainMemo

    index.class_chain_memo = ClassChainMemo(index, imports, classes, audit)
    default_session = default_session_evidence(
        index, snapshots, imports, classes, aliases, audit
    )
    publications = {row["value"]: row for row in endpoint_publications()}
    sink_rows = _sink_rows(snapshots, aliases, index, default_session)
    facts = candidate_facts(index, snapshots, sink_rows, publications)
    result = {}
    with index.class_chain_memo.analysis_batch() as batch:
        if not batch.started:
            return {}
        for fact in facts:
            key = (fact.path, fact.line, fact.member)
            evidence = result.setdefault(key, _fact_row(fact))
            _analyze_fact(
                fact,
                evidence,
                sink_rows,
                (index, imports, classes, audit, integrity),
                publications,
                aliases,
            )
            if evidence["url_witnesses"]:
                from .credential_role_use_audit import audit_value_uses

                audit_value_uses(fact, evidence, index, imports, classes, audit)
    return result if batch.accepted else {}


def endpoint_role_evidence(
    root, snapshots, imports, source_bytes, inventory, audit, integrity
):
    """Return exact publication-backed URL MAY_FLOW witnesses, never safety decisions."""
    rows = _analyze(root, snapshots, imports, source_bytes, inventory, audit, integrity)
    return {key: row for key, row in rows.items() if row["url_witnesses"]}


def known_auth_uses(
    root, snapshots, imports, source_bytes, inventory, audit, integrity
):
    """Return auth-slot uses separately from any endpoint publication evidence."""
    rows = _analyze(root, snapshots, imports, source_bytes, inventory, audit, integrity)
    return {
        key: row["known_auth_uses"]
        for key, row in rows.items()
        if row["known_auth_uses"]
    }


def record_use(
    fact,
    path,
    call,
    slot,
    expression,
    index,
    imports,
    classes,
    audit,
    integrity,
    aliases=None,
):
    paths = [[]]
    if not matches_fact(fact, path, expression, index, imports, classes, audit):
        hops = constructor_url_hops(
            fact, path, call, expression, index, imports, classes, audit, integrity
        )
        paths = [hops] if hops else []
        if not hops and slot == "endpoint_locator" and aliases is not None:
            from .credential_role_method_paths import method_url_hop_paths

            method_result = method_url_hop_paths(
                fact,
                path,
                call,
                expression,
                index,
                imports,
                classes,
                aliases,
                audit,
                integrity,
            )
            paths = (
                method_result.get("paths", [])
                if method_result.get("state") == "BRANCH_ENUMERATION_COMPLETE"
                else []
            )
        if not paths:
            return None
    if not index.validate(path):
        return None
    record = {
        "path": index.relative(path),
        "line": call.lineno,
        "column": call.col_offset,
        "slot": slot,
        "value_span": [
            expression.lineno,
            expression.col_offset,
            expression.end_lineno,
            expression.end_col_offset,
        ],
        "source_span": [fact.line, fact.column, fact.end_line, fact.end_column],
        "source_sha256": fact.source_sha256,
        "sink_sha256": hashlib.sha256(index.source_bytes[path]).hexdigest(),
        "profile": "DECLARED_CLASS_MAY_FLOW",
    }
    return [
        {
            **record,
            "hops": hops,
            "method_value_flow": any(
                h.get("role") == "canonical_http_url_sink" for h in hops
            ),
        }
        for hops in paths
    ]
