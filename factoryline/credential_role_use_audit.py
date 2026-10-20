"""Account for declared member-value reads before endpoint heuristic partition."""

import ast

from .credential_role_value_slices import (
    alias_is_closed,
    reflective_member_use,
    related_owners,
    source_scope,
    value_spans,
    within,
    inherited_fields,
)

PROFILE = "DECLARED_MEMBER_VALUE_READS_V1"


def _record(index, path, node, reason):
    return {
        "path": index.relative(path),
        "line": node.lineno,
        "column": node.col_offset,
        "reason": reason,
        "source_sha256": index.inventory[path],
    }


def audit_value_uses(fact, row, index, imports, classes, audit):
    """Finite declared-class profile; unresolved linked reads remain active alerts."""
    owners = related_owners(fact, index, imports, classes, audit)
    spans, fields = value_spans(row, index, imports, classes)
    method_unknown = _method_value_spans(
        row, index, spans, owners, (imports, classes, audit)
    )
    inherited_fields(fields, index, imports, classes, audit)
    for owner in owners:
        fields.setdefault(owner, set()).add(fact.member)
    carriers = _literal_carriers(fact, owners, index, imports, classes, audit)
    unknown, count = list(method_unknown), 0
    for path, tree in index.snapshots.items():
        records, reads = _audit_path(
            fact, path, tree, index, imports, classes, audit, fields, spans, carriers
        )
        unknown.extend(records)
        count += reads
    row["linked_unknown_uses"].extend(unknown)
    row["value_use_audit"] = {
        "state": "COMPLETE" if owners and count and not unknown else "INCOMPLETE",
        "profile": PROFILE,
        "declared_member_reads": count,
        "scope": "captured-source-declared-class-value-uses",
        "runtime_dispatch": "UNASSESSED",
    }


def _method_value_spans(row, index, spans, owners, context):
    traces = [
        witness["hops"]
        for witness in row["url_witnesses"]
        if witness.get("method_value_flow")
    ]
    if not traces:
        return []
    from .credential_role_method_use_audit import method_value_use_audit

    closure = method_value_use_audit(
        traces, index, related_owners=owners, context=context
    )
    row["method_value_use_audit"] = closure
    if closure.get("state") != "COMPLETE":
        return closure.get("unknown_uses") or [
            {"reason": "method_use_audit_incomplete"}
        ]
    for proof in closure["allowed_member_spans"]:
        span = [proof[k] for k in ("line", "column", "end_line", "end_column")]
        spans.setdefault(index.root / proof["path"], []).append(span)
    return []


def _attribute_link(node, owner, path, fields, fact, index, imports, classes, audit):
    if owner and node.attr in fields.get((path, owner.name), set()):
        return True
    from .credential_role_bindings import matches_fact
    from .credential_role_object_identity import declared_origins

    if any(
        node.attr in fields.get(origin, set())
        for origin in declared_origins(path, node.value, index, imports, classes)
    ):
        return True

    return node.attr == fact.member and matches_fact(
        fact, path, node, index, imports, classes, audit
    )


def _audit_path(
    fact, path, tree, index, imports, classes, audit, fields, spans, carriers
):
    names = set().union(*fields.values()) if fields else set()
    aliases = audit._module_security_aliases(tree)
    candidates = [
        n
        for n in ast.walk(tree)
        if (isinstance(n, ast.Attribute) and n.attr in names)
        or reflective_member_use(n, names, aliases) is not None
    ]
    capabilities = _capability_uses(path, index, imports, classes, audit)
    if not candidates and not capabilities:
        return [], 0
    if not index.validate(path):
        return [{"path": index.relative(path), "reason": "unbound_source"}], 0
    unknown = [
        _record(index, path, node, "candidate_class_capability_escape")
        for node, origins in capabilities
        if origins & carriers
    ]
    count, parents = 0, index.parents[path]
    for node in candidates:
        function, owner = source_scope(node, parents)
        if isinstance(node, ast.Attribute) and _attribute_link(
            node, owner, path, fields, fact, index, imports, classes, audit
        ):
            count += 1
            if _allowed_read(node, function, parents, spans.get(path, [])):
                continue
            unknown.append(_record(index, path, node, "unresolved_member_value_use"))
        if _linked_reflection(
            node, owner, path, fields, index, imports, classes, audit, aliases
        ):
            unknown.append(_record(index, path, node, "reflective_member_use"))
    return unknown, count


def _allowed_read(node, function, parents, spans):
    if any(within(node, span) for span in spans):
        return True
    return bool(
        function
        and isinstance(node.ctx, ast.Load)
        and alias_is_closed(node, function, parents, spans)
    )


def _linked_reflection(
    node, owner, path, fields, index, imports, classes, audit, aliases
):
    names = set().union(*fields.values()) if fields else set()
    target = reflective_member_use(node, names, aliases)
    if target is None:
        return False
    if isinstance(target, ast.Name) and target.id == "self":
        return owner is not None and (path, owner.name) in fields
    from .credential_role_bindings import _class_ref

    from .credential_role_object_identity import declared_origins

    resolved = _class_ref(path, target, imports, classes, audit)
    return resolved in fields or bool(
        declared_origins(path, target, index, imports, classes) & fields.keys()
    )


def _literal_carriers(fact, owners, index, imports, classes, audit):
    """Select actual member origins, not ancestors used for method dispatch."""
    from .credential_role_bindings import class_chain
    from .credential_role_field_origin import resolve_declared_field_origin

    if fact.source_role != "class_literal":
        return set()
    identity = (
        fact.path,
        (fact.line, fact.column, fact.end_line, fact.end_column),
        fact.source_sha256,
    )
    carriers = set()
    for key in owners:
        chain = class_chain(index, *key, imports, classes, audit)
        resolved = resolve_declared_field_origin(chain or (), fact.member, index)
        origin = resolved.get("origin", {})
        if (
            resolved.get("state") == "EXACT"
            and (
                origin.get("path"),
                tuple(origin.get("span", ())),
                origin.get("source_sha256"),
            )
            == identity
        ):
            carriers.add(key)
    return carriers


def _capability_uses(path, index, imports, classes, audit):
    """Share candidate-independent source capability escapes in one derivation."""
    from .credential_role_object_identity import declared_origins

    def derive():
        rows, parents = [], index.parents[path]
        modules = _module_capabilities(path, imports, classes)
        for node in ast.walk(index.snapshots[path]):
            if not isinstance(node, (ast.Name, ast.Attribute, ast.Call)):
                continue
            if not isinstance(node, ast.Call) and not isinstance(node.ctx, ast.Load):
                continue
            parent = parents.get(id(node))
            if (
                isinstance(parent, ast.Attribute)
                and parent.value is node
                and not parent.attr.startswith("__")
                or isinstance(parent, ast.Call)
                and parent.func is node
                or isinstance(parent, ast.ClassDef)
                and node in parent.bases
            ):
                continue
            origins = declared_origins(path, node, index, imports, classes)
            origins = origins | modules.get(audit._name(node), set())
            if origins:
                rows.append((node, frozenset(origins)))
        return tuple(rows)

    memo = getattr(index, "class_chain_memo", None)
    if memo is not None and memo.matches(imports, classes, audit):
        return memo.source_model(
            ("declared-class-capability-uses", path),
            derive,
            helper_epoch=lambda: (*_capability_helpers(), audit._name),
        )
    return derive()


def _module_capabilities(path, imports, classes):
    """A captured module namespace carries its reachable source class exports."""
    result = {}
    for alias, (target, symbol) in imports.get(path, {}).items():
        if symbol is not None:
            continue
        pending, seen, origins = [target], set(), set()
        while pending:
            source = pending.pop()
            if source in seen:
                continue
            seen.add(source)
            origins.update(key for key in classes if key[0] == source)
            for dependency, name in imports.get(source, {}).values():
                if (dependency, name) in classes:
                    origins.add((dependency, name))
                elif name is None:
                    pending.append(dependency)
        result[alias] = origins
    return result


def _capability_helpers():
    from types import FunctionType

    from . import credential_role_object_identity, credential_role_scope_bindings

    return (
        _capability_uses,
        _module_capabilities,
        *(
            value
            for module in (
                credential_role_object_identity,
                credential_role_scope_bindings,
            )
            for value in vars(module).values()
            if isinstance(value, FunctionType)
        ),
        credential_role_scope_bindings._SCOPES,
        credential_role_scope_bindings._COMPREHENSIONS,
    )
