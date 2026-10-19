"""Related-class and snapshot indexing for getter-use closure."""

import ast


def owner_keys(index, owners):
    return {(index.relative(path), name) for path, name in owners or ()}


def candidate_getter_fields(traces, nodes, index):
    result = {}
    for trace in traces:
        members = []
        for position, row in enumerate(trace):
            if row.get("role") != "declared_member_read":
                continue
            member = nodes.get(_span_key(row))
            literal_row = next(
                (
                    item
                    for item in reversed(trace[:position])
                    if item.get("role") == "declared_literal"
                ),
                None,
            )
            literal = nodes.get(_span_key(literal_row)) if literal_row else None
            identity = _literal_field_identity(literal, member, literal_row)
            if identity:
                members.append((member.attr, identity))
        for row in trace:
            if row.get("role") != "method_call":
                continue
            call = nodes.get(_span_key(row))
            if _self_call(call):
                result.setdefault(call.func.attr, set()).update(members)
    return result


def different_field_origin(
    owner, getter, getter_fields, index, imports, classes, audit
):
    fields = getter_fields.get(getter, ())
    if owner is None or not fields or audit is None:
        return False
    from .credential_role_bindings import class_chain
    from .credential_role_field_origin import resolve_declared_field_origin

    chain = class_chain(index, index.root / owner[0], owner[1], imports, classes, audit)
    if not chain:
        return False
    for member, candidate in fields:
        if _candidate_ancestor(owner, candidate, index, imports, classes, audit):
            return False
        resolved = resolve_declared_field_origin(chain, member, index)
        if resolved.get("state") != "EXACT":
            return False
        origin = resolved["origin"]
        identity = origin["path"], tuple(origin["span"]), origin["source_sha256"]
        if identity == candidate:
            return False
    return True


def exact_local_receiver_relation(
    path, receiver, getter, index, imports, classes, audit, related_owners, fields
):
    """Classify a receiver with the witnessed getter and exact field origins."""
    candidates = fields.get(getter, ())
    if not candidates:
        return "UNKNOWN"
    from .credential_role_receiver_class import exact_receiver_class

    class_ref = exact_receiver_class(path, receiver, index, imports, classes, audit)
    if class_ref is None:
        return "UNKNOWN"
    from .credential_role_bindings import class_chain

    chain = class_chain(index, class_ref[0], class_ref[1], imports, classes, audit)
    if not chain:
        return "UNKNOWN"
    from .credential_role_receiver_lifetime import local_receiver_stable

    if not local_receiver_stable(path, receiver, getter, chain, index):
        return "UNKNOWN"
    candidate_methods = _candidate_getter_methods(
        candidates, getter, index, imports, classes, audit
    )
    if candidate_methods is None:
        return "UNKNOWN"
    if len(candidate_methods) != 1:
        return "UNKNOWN"
    from .credential_role_class_binding import effective_method

    candidate_identity = next(iter(candidate_methods))
    effective = effective_method(chain, getter)
    if not effective or _method_identity(effective, index) != candidate_identity:
        return "UNKNOWN"

    return _receiver_field_relation(candidates, chain, index)


def _candidate_getter_methods(candidates, getter, index, imports, classes, audit):
    from .credential_role_bindings import class_chain
    from .credential_role_class_binding import effective_method

    methods = set()
    for _, candidate in candidates:
        candidate_class = _candidate_class(candidate, index)
        if candidate_class is None:
            return None
        chain = class_chain(
            index, candidate_class[0], candidate_class[1], imports, classes, audit
        )
        row = effective_method(chain, getter) if chain else None
        if row is None:
            return None
        methods.add(_method_identity(row, index))
    return methods


def _receiver_field_relation(candidates, chain, index):
    from .credential_role_field_origin import resolve_declared_field_origin

    matches = []
    for member, candidate in candidates:
        resolved = resolve_declared_field_origin(chain, member, index)
        if resolved.get("state") != "EXACT":
            return "UNKNOWN"
        origin = resolved["origin"]
        identity = origin["path"], tuple(origin["span"]), origin["source_sha256"]
        matches.append(identity == candidate)
    if all(matches):
        return "LINKED"
    if not any(matches):
        return "UNRELATED"
    return "UNKNOWN"


def _candidate_class(candidate, index):
    relative, coordinates, digest = candidate
    paths = [path for path in index.snapshots if index.relative(path) == relative]
    if len(paths) != 1 or not index.validate(paths[0]):
        return None
    path = paths[0]
    declarations = [
        node
        for node in ast.walk(index.snapshots[path])
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and _coords(node) == tuple(coordinates)
        and index.inventory[path] == digest
    ]
    if len(declarations) != 1:
        return None
    owner = class_identity(declarations[0], index, path)
    return (path, owner[1]) if owner else None


def _method_identity(row, index):
    path, method = row
    return index.relative(path), _coords(method), index.inventory[path]


def _candidate_ancestor(owner, candidate, index, imports, classes, audit):
    from .credential_role_bindings import class_chain

    path = index.root / candidate[0]
    if not index.validate(path):
        return True
    declarations = [
        node
        for node in ast.walk(index.snapshots[path])
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and _coords(node) == tuple(candidate[1])
    ]
    if len(declarations) != 1:
        return True
    enclosing = index.parents[path].get(id(declarations[0]))
    if not isinstance(enclosing, ast.ClassDef):
        return True
    chain = class_chain(index, path, enclosing.name, imports, classes, audit)
    return not chain or any((index.relative(p), name) == owner for p, name, _ in chain)


def _literal_field_identity(literal, member, row):
    if not isinstance(member, ast.Attribute) or row is None:
        return None
    if not isinstance(literal, (ast.Assign, ast.AnnAssign)):
        return None
    targets = literal.targets if isinstance(literal, ast.Assign) else [literal.target]
    value = literal.value
    if not any(
        isinstance(target, ast.Name) and target.id == member.attr for target in targets
    ):
        return None
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
        return None
    return row["path"], _coords(literal), row["source_sha256"]


def _span_key(row):
    keys = ("path", "line", "column", "end_line", "end_column", "source_sha256", "role")
    return tuple(row.get(key) for key in keys)


def _self_call(node):
    return bool(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "self"
    )


def _coords(node):
    return node.lineno, node.col_offset, node.end_lineno, node.end_col_offset


def snapshot_candidates(index):
    signature = tuple(
        (path, index.inventory.get(path), id(tree))
        for path, tree in index.snapshots.items()
    )
    cached = getattr(index, "_credential_method_getter_candidates", None)
    if cached and cached[0] == signature:
        return cached[1]
    rows = []
    for path, tree in index.snapshots.items():
        if not index.validate(path):
            continue
        candidates = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Attribute, ast.Call))
        ]
        rows.append((path, tree, candidates))
    index._credential_method_getter_candidates = (signature, rows)
    return rows


def class_identity(node, index, path):
    owner = node
    while owner is not None:
        if isinstance(owner, ast.ClassDef):
            return (index.relative(path), owner.name)
        owner = index.parents[path].get(id(owner))
    return None
