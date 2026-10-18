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
    inherited_fields(fields, index, imports, classes, audit)
    for owner in owners:
        fields.setdefault(owner, set()).add(fact.member)
    unknown, count = [], 0
    for path, tree in index.snapshots.items():
        records, reads = _audit_path(
            fact, path, tree, index, imports, classes, audit, fields, spans
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


def _audit_path(fact, path, tree, index, imports, classes, audit, fields, spans):
    names = set().union(*fields.values()) if fields else set()
    aliases = audit._module_security_aliases(tree)
    candidates = [
        n
        for n in ast.walk(tree)
        if (isinstance(n, ast.Attribute) and n.attr in names)
        or reflective_member_use(n, names, aliases) is not None
    ]
    if not candidates:
        return [], 0
    if not index.validate(path):
        return [{"path": index.relative(path), "reason": "unbound_source"}], 0
    unknown, count, parents = [], 0, index.parents[path]
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
