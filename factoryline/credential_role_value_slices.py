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
    from .credential_role_scope_bindings import resolve_class

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

    from .credential_role_scope_bindings import effective_method

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


def discarded_callable_projection(node, parents):
    """Follow an exact tuple element through one finite for-unpack invocation."""
    current, position = node, []
    parent = parents.get(id(current))
    while isinstance(parent, ast.Tuple) and isinstance(parent.ctx, ast.Load):
        position.insert(
            0, next(i for i, child in enumerate(parent.elts) if child is current)
        )
        current, parent = parent, parents.get(id(parent))
    if not position or not isinstance(parent, ast.For) or parent.iter is not current:
        return False
    if not _finite_unpack_matches(current, parent.target):
        return False
    # The outermost index selects an iterator row, not an unpacked target.
    target = parent.target
    for selected in position[1:]:
        if not isinstance(target, ast.Tuple) or selected >= len(target.elts):
            return False
        target = target.elts[selected]
    if not isinstance(target, ast.Name):
        return False
    function, _ = source_scope(parent, parents)
    if function is None:
        return False
    from .credential_role_scope_bindings import binding_occurrences

    if binding_occurrences(function.body, target.id) != [target]:
        return False
    uses = [
        item
        for item in ast.walk(function)
        if isinstance(item, ast.Name)
        and item.id == target.id
        and isinstance(item.ctx, ast.Load)
    ]
    return bool(uses) and all(
        _discarded_callable_load(item, parent, parents) for item in uses
    )


def _discarded_callable_load(node, loop, parents):
    call = parents.get(id(node))
    statement = parents.get(id(call))
    if not (
        isinstance(call, ast.Call)
        and call.func is node
        and not call.args
        and not call.keywords
        and isinstance(statement, ast.Expr)
        and statement.value is call
    ):
        return False
    current = statement
    while current is not None and current is not loop:
        if current is not statement and not _finite_dispatch_region(current, parents):
            return False
        current = parents.get(id(current))
    return current is loop


def _finite_dispatch_region(node, parents):
    if isinstance(node, ast.With):
        return True
    if not isinstance(node, ast.For):
        return False
    value = node.iter
    if isinstance(value, ast.Name):
        from .credential_role_scope_bindings import binding_occurrences

        function, _ = source_scope(node, parents)
        bindings = binding_occurrences(function.body, value.id) if function else []
        assignment = parents.get(id(bindings[0])) if len(bindings) == 1 else None
        if (
            not isinstance(assignment, (ast.Assign, ast.AnnAssign))
            or assignment not in function.body
        ):
            return False
        value = assignment.value
    return (
        isinstance(value, (ast.Tuple, ast.List))
        and bool(value.elts)
        and all(not isinstance(item, ast.Starred) for item in value.elts)
    )


def _finite_unpack_matches(rows, target):
    if not isinstance(rows, ast.Tuple) or not rows.elts:
        return False
    return all(_unpack_matches(row, target) for row in rows.elts)


def _unpack_matches(value, target):
    if isinstance(target, ast.Name):
        return True
    return (
        isinstance(target, ast.Tuple)
        and isinstance(value, ast.Tuple)
        and len(target.elts) == len(value.elts)
        and all(
            _unpack_matches(item, binding)
            for item, binding in zip(value.elts, target.elts)
        )
    )
