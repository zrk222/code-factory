"""Small lexical transformations accepted by the method-flow tracer."""

import ast


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
