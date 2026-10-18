"""Bounded getter and reflective-use closure over validated source snapshots."""

import ast

from .credential_role_method_use_callers import parameter_linked
from .credential_role_method_use_common import coordinates, span_key
from .credential_role_method_use_getters import (
    _reflective_getter,
    _self_call,
    _stable_self,
)
from .credential_role_method_use_relation import (
    candidate_getter_fields,
    class_identity,
    different_field_origin,
    exact_local_receiver_relation,
    owner_keys,
    snapshot_candidates,
)


def audit_getter_uses(
    traces, nodes, index, unknown, *, context=None, related_owners=None
):
    witnessed, names, owners, fields = _trace_context(
        traces, nodes, index, related_owners
    )
    if not names:
        return
    if not owners:
        unknown.append({"reason": "getter_candidate_class_unresolved"})
        return
    imports, classes, audit = context if context else ({}, {}, None)
    snapshots = snapshot_candidates(index)
    if len(snapshots) != len(index.snapshots):
        unknown.append({"reason": "getter_snapshot_validation_incomplete"})
    for path, tree, candidates in snapshots:
        _audit_snapshot(
            path,
            tree,
            candidates,
            names,
            fields,
            witnessed,
            owners,
            traces,
            nodes,
            index,
            context,
            related_owners,
            imports,
            classes,
            audit,
            unknown,
        )


def _trace_context(traces, nodes, index, related):
    witnessed, names, owners = set(), set(), owner_keys(index, related)
    fields = candidate_getter_fields(traces, nodes, index)
    paths = {index.relative(path): path for path in index.snapshots}
    for trace in traces:
        for row in trace:
            if row.get("role") == "declared_literal":
                literal = nodes.get(span_key(row))
                path = paths.get(row["path"])
                owner = class_identity(literal, index, path) if path else None
                if owner and not owners:
                    owners.add(owner)
            if row.get("role") == "method_call":
                call = nodes.get(span_key(row))
                if _self_call(call):
                    witnessed.add((row["path"], coordinates(call)))
                    names.add(call.func.attr)
    return witnessed, names, owners, fields


def _audit_snapshot(
    path,
    tree,
    candidates,
    names,
    fields,
    witnessed,
    owners,
    traces,
    nodes,
    index,
    context,
    related,
    imports,
    classes,
    audit,
    unknown,
):
    relative = index.relative(path)
    aliases = audit._module_security_aliases(tree) if audit else {}
    calls = [node for node in candidates if isinstance(node, ast.Call)]
    for node in candidates:
        if isinstance(node, ast.Attribute) and node.attr in names:
            if audit and _consumer_role(node, index, path, audit):
                continue
            _audit_attribute(
                node,
                path,
                relative,
                calls,
                witnessed,
                owners,
                fields,
                index,
                context,
                related,
                imports,
                classes,
                audit,
                unknown,
            )
        elif isinstance(node, ast.Call) and _reflective_getter(node, names, aliases):
            from .credential_role_method_use_getter_reflective import audit_reflective

            audit_reflective(
                node,
                path,
                relative,
                calls,
                owners,
                names,
                fields,
                index,
                context,
                related,
                imports,
                classes,
                audit,
                aliases,
                unknown,
                _related_receiver,
            )


def _consumer_role(node, index, path, audit):
    from .credential_role_getter_consumers import getter_consumer_role

    return getter_consumer_role(node, index, path, audit) is not None


def _audit_attribute(
    node,
    path,
    relative,
    calls,
    witnessed,
    owners,
    fields,
    index,
    context,
    related,
    imports,
    classes,
    audit,
    unknown,
):
    parent = index.parents[path].get(id(node))
    lexical = class_identity(node, index, path)
    stable = _stable_self(node.value, index, path, context)
    unrelated = stable and different_field_origin(
        lexical, node.attr, fields, index, imports, classes, audit
    )
    relation = _related_receiver(
        stable and lexical in owners and not unrelated,
        node.value,
        path,
        calls,
        node.attr,
        fields,
        index,
        context,
        related,
        imports,
        classes,
    )
    linked = relation == "LINKED"
    unrelated = unrelated or relation == "UNRELATED"
    if not linked and not unrelated:
        unknown.append(_unknown("getter_receiver_relation_unresolved", relative, node))
    elif linked and not _witnessed_call(parent, node, relative, witnessed):
        reason = "unrepresented_getter_reference"
        if isinstance(parent, ast.Call) and parent.func is node:
            reason = "unwitnessed_sibling_getter_call"
        unknown.append(_unknown(reason, relative, node))


def _related_receiver(
    linked,
    receiver,
    path,
    calls,
    getter,
    fields,
    index,
    context,
    related,
    imports,
    classes,
):
    if linked:
        return "LINKED"
    if not context:
        return "UNKNOWN"
    from .credential_role_object_identity import declared_origins

    origins = declared_origins(path, receiver, index, imports, classes)
    if origins & (related or set()):
        return "LINKED"
    if isinstance(receiver, ast.Name):
        if parameter_linked(
            path, receiver, calls, index, imports, classes, related or set()
        ):
            return "LINKED"
        # This tri-state result only bounds getter-use closure. UNRELATED never
        # creates a candidate, an exemption, or a MAY_FLOW disposition.
        return exact_local_receiver_relation(
            path,
            receiver,
            getter,
            index,
            imports,
            classes,
            context[2],
            related or set(),
            fields,
        )
    return "UNKNOWN"


def _witnessed_call(parent, node, relative, witnessed):
    return bool(
        isinstance(parent, ast.Call)
        and parent.func is node
        and (relative, coordinates(parent)) in witnessed
    )


def _unknown(reason, relative, node):
    return {
        "reason": reason,
        "path": relative,
        "line": node.lineno,
        "column": node.col_offset,
    }
