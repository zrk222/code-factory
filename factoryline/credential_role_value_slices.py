"""Exact value spans and alias uses for finite endpoint-flow audits."""

import ast


def source_scope(node, parents):
    function = owner = None
    while node is not None:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and function is None
        ):
            function = node
        if isinstance(node, ast.ClassDef):
            owner = node
            break
        node = parents.get(id(node))
    return function, owner


def within(node, span):
    return (span[0], span[1]) <= (node.lineno, node.col_offset) and (
        node.end_lineno,
        node.end_col_offset,
    ) <= (span[2], span[3])


def value_spans(row, index, imports, classes):
    spans, fields = {}, {}
    for witness in row["url_witnesses"]:
        if witness.get("value_span"):
            spans.setdefault(index.root / witness["path"], []).append(
                witness["value_span"]
            )
        carrier = _selected_carrier(witness, index, imports, classes)
        for hop in witness.get("hops", []):
            if hop["role"] not in {"constructor_argument", "constructor_field_binding"}:
                continue
            path = index.root / hop["path"]
            span = [hop[k] for k in ("line", "column", "end_line", "end_column")]
            spans.setdefault(path, []).append(span)
            if hop["role"] == "constructor_field_binding" and index.validate(path):
                for node in ast.walk(index.snapshots[path]):
                    if isinstance(node, ast.Attribute) and within(node, span):
                        _, owner = source_scope(node, index.parents[path])
                        if owner:
                            fields.setdefault(carrier or (path, owner.name), set()).add(
                                node.attr
                            )
    return spans, fields


def _selected_carrier(witness, index, imports, classes):
    from .credential_role_class_binding import resolve_class

    for hop in witness.get("hops", []):
        if hop["role"] != "client_class_selection":
            continue
        path = index.root / hop["path"]
        if not index.validate(path):
            return None
        span = [hop[k] for k in ("line", "column", "end_line", "end_column")]
        for node in ast.walk(index.snapshots[path]):
            if isinstance(node, (ast.Name, ast.Attribute)) and within(node, span):
                resolved = resolve_class(path, node, imports, classes)
                if resolved in classes:
                    return resolved
    return None


def alias_is_closed(node, function, parents, spans):
    assignment = parents.get(id(node))
    if not (
        isinstance(assignment, ast.Assign)
        and assignment.value is node
        and assignment in function.body
        and len(assignment.targets) == 1
        and isinstance(assignment.targets[0], ast.Name)
    ):
        return False
    name = assignment.targets[0].id
    from .credential_role_scope_bindings import binding_occurrences

    bindings = binding_occurrences(function.body, name)
    if len(bindings) != 1 or bindings[0] is not assignment.targets[0]:
        return False
    loads = [
        n
        for n in ast.walk(function)
        if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load)
    ]
    return bool(loads) and all(
        any(within(load, span) for span in spans) for load in loads
    )


def inherited_fields(fields, index, imports, classes, audit):
    """Retain MAY-origin fields through each declared client descendant."""
    from .credential_role_bindings import class_chain

    from .credential_role_class_binding import effective_method

    origins = {key: set(names) for key, names in fields.items()}
    for origin, names in origins.items():
        selected = class_chain(index, *origin, imports, classes, audit)
        ctor = effective_method(selected or (), "__init__")
        for path, name in classes:
            chain = class_chain(index, path, name, imports, classes, audit)
            if (
                chain
                and origin in {(p, n) for p, n, _ in chain}
                and ctor
                and effective_method(chain, "__init__") == ctor
            ):
                fields.setdefault((path, name), set()).update(names)
        for path, name, _ in selected or ():
            fields.setdefault((path, name), set()).update(names)


def related_owners(fact, index, imports, classes, audit):
    from .credential_role_bindings import class_chain

    origin = (index.root / fact.path, fact.owner)
    owners = set()
    chain = class_chain(index, *origin, imports, classes, audit)
    if not chain:
        return owners
    owners.update((p, name) for p, name, _ in chain)
    for path, name in classes:
        ancestry = class_chain(index, path, name, imports, classes, audit)
        if ancestry and origin in {(p, n) for p, n, _ in ancestry}:
            owners.add((path, name))
    return owners


def reflective_member_use(node, fields, aliases=None):
    if isinstance(node, ast.Attribute) and node.attr in {
        "__dict__",
        "__getattribute__",
    }:
        return node.value
    if not isinstance(node, ast.Call) or not node.args:
        return None
    from .security_configuration import _canonical

    name = _canonical(node, aliases or {})
    if not name and isinstance(node.func, ast.Name):
        name = node.func.id
    name = name.removeprefix("builtins.")
    if name not in {"getattr", "setattr", "delattr", "vars"}:
        return None
    if name != "vars" and len(node.args) > 1:
        name = node.args[1]
        if isinstance(name, ast.Constant) and name.value not in fields:
            return None
    return node.args[0]
