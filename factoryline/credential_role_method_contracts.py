"""Small lexical transformations accepted by the method-flow tracer."""

import ast
import hashlib


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
