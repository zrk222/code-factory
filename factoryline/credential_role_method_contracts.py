"""Small lexical transformations accepted by the method-flow tracer."""

import ast

import hashlib


def enclosing_function(node, index, path):
    while node is not None:
        node = index.parents[path].get(id(node))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node
    return None


def is_parameter(function, name):
    from .credential_role_scope_bindings import binding_occurrences

    args = function.args
    parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    return name in {item.arg for item in parameters} and not binding_occurrences(
        function.body, name
    )


def returned_parameter(function, expression):
    """Resolve a direct unique local alias chain to one formal parameter."""

    aliases, seen = [], set()
    while isinstance(expression, ast.Name) and expression.id not in seen:
        seen.add(expression.id)
        if is_parameter(function, expression.id):
            return expression.id, aliases
        found = alias_value(expression, function)
        if found is None:
            break
        expression, assignment = found
        aliases.append(assignment)
    return None, []


def method_returns(function, index, path):
    rows = [node for node in ast.walk(function) if isinstance(node, ast.Return)]
    accepted = []
    for row in rows:
        parent = index.parents[path].get(id(row))
        if (
            parent is function
            or (
                isinstance(parent, ast.If)
                and index.parents[path].get(id(parent)) is function
            )
            or _try_body_return(row, function, index, path)
        ):
            accepted.append(row)
    if len(accepted) != len(rows) or not 1 <= len(rows) <= 2:
        return []
    return accepted


def _try_body_return(row, function, index, path):
    parent = index.parents[path].get(id(row))
    if (
        not isinstance(parent, ast.Try)
        or index.parents[path].get(id(parent)) is not function
    ):
        return False
    if parent.body != [row] or parent.orelse or parent.finalbody:
        return False
    return bool(parent.handlers) and all(
        _reraise_only(handler) for handler in parent.handlers
    )


def _reraise_only(handler):
    if not handler.body or not isinstance(handler.body[-1], ast.Raise):
        return False
    if handler.body[-1].exc is not None or handler.body[-1].cause is not None:
        return False
    for statement in handler.body[:-1]:
        if not _exception_metadata_assignment(statement, handler.name):
            return False
    return True


def _exception_metadata_assignment(statement, name):
    return bool(
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Attribute)
        and isinstance(statement.targets[0].value, ast.Name)
        and statement.targets[0].value.id == name
        and isinstance(statement.value, ast.Constant)
    )


def format_receiver(expression):
    if not isinstance(expression, ast.Call) or not isinstance(
        expression.func, ast.Attribute
    ):
        return None
    if (
        expression.func.attr != "format"
        or expression.args
        or len(expression.keywords) != 1
    ):
        return None
    keyword = expression.keywords[0]
    return expression.func.value if keyword.arg is None else None


def verified_instance_receiver(node, function, owner, index, path, verified):
    from .credential_role_scope_bindings import instance_receiver

    if not function.decorator_list:
        return instance_receiver(node, function, owner, index, path)
    if (
        not verified
        or owner is None
        or index.parents[path].get(id(function)) is not owner
    ):
        return False
    args = function.args
    positional = [*args.posonlyargs, *args.args]
    if not positional or positional[0].arg != "self":
        return False
    from .credential_role_scope_bindings import binding_occurrences

    if binding_occurrences(function.body, "self"):
        return False
    current = node
    while current is not function:
        current = index.parents[path].get(id(current))
        if current is None or isinstance(
            current,
            (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
        ):
            return False
    return not any(arg.arg == "self" for arg in args.kwonlyargs) and not (
        (args.vararg and args.vararg.arg == "self")
        or (args.kwarg and args.kwarg.arg == "self")
    )


def alias_value(expression, function):
    """Return a unique direct local assignment RHS and its source statement."""
    if not isinstance(expression, ast.Name):
        return None
    from .credential_role_scope_bindings import binding_occurrences

    rows = []
    for statement in function.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if isinstance(target, ast.Name) and target.id == expression.id:
            rows.append((statement, target))
    occurrences = binding_occurrences(function.body, expression.id)
    if len(rows) != 1 or len(occurrences) != 1 or occurrences[0] is not rows[0][1]:
        return None
    return rows[0][0].value, rows[0][0]


def cast_value(expression, path, aliases):
    """Return the value position only for canonical, exact typing.cast calls."""
    from .security_configuration import _canonical

    if (
        not isinstance(expression, ast.Call)
        or _canonical(expression, aliases[path]) != "typing.cast"
        or len(expression.args) != 2
        or expression.keywords
    ):
        return None
    return expression.args[1]


def source_current(index, path):
    memo = getattr(index, "class_chain_memo", None)
    checks = getattr(memo, "method_flow_source_checks", None)
    if memo is not None and callable(getattr(memo, "valid", None)):
        if checks is None:
            checks = {}
            memo.method_flow_source_checks = checks
        if path not in checks:
            checks[path] = _source_current(index, path)
        return checks[path]
    return _source_current(index, path)


def _source_current(index, path):
    if not index.validate(path):
        return False
    tree, raw = index.snapshots.get(path), index.source_bytes.get(path)
    digest = hashlib.sha256(raw).hexdigest() if isinstance(raw, bytes) else None
    if digest is None or index.inventory.get(path) != digest:
        return False
    if getattr(tree, "_oracle_source_sha256", None) != digest:
        return False
    try:
        return ast.dump(ast.parse(raw), include_attributes=True) == ast.dump(
            tree, include_attributes=True
        )
    except (SyntaxError, ValueError, TypeError, RecursionError, MemoryError):
        return False


def source_span(index, path, node, role):
    return {
        "path": index.relative(path),
        "line": node.lineno,
        "column": node.col_offset,
        "end_line": getattr(node, "end_lineno", node.lineno),
        "end_column": getattr(node, "end_col_offset", node.col_offset),
        "source_sha256": hashlib.sha256(index.source_bytes[path]).hexdigest(),
        "role": role,
    }
