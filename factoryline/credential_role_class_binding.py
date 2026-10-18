"""Fail-closed effective bindings for source-role class flow."""

import ast


def _class_binding_statements(owner, name):
    from .credential_role_scope_bindings import binding_occurrences

    return binding_occurrences(owner.body, name)


def effective_method(chain, name, allowed_decorators=()):
    allowed = set(allowed_decorators)
    for path, _, owner in chain:
        bindings = _class_binding_statements(owner, name)
        if not bindings:
            continue
        rows = [
            node
            for node in owner.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ]
        if len(bindings) != 1 or len(rows) != 1 or bindings[0] is not rows[0]:
            return None
        row = rows[0]
        decorators = {_decorator_name(item) for item in row.decorator_list}
        if row.decorator_list and (
            any(not isinstance(item, ast.Name) for item in row.decorator_list)
            or None in decorators
            or decorators != allowed
        ):
            return None
        if decorators - allowed:
            return None
        return path, row
    return None


def _decorator_name(node):
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def class_attribute(chain, name):
    for path, _, owner in chain:
        bindings = _class_binding_statements(owner, name)
        if not bindings:
            continue
        rows = []
        for statement in owner.body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = (
                    statement.targets
                    if isinstance(statement, ast.Assign)
                    else [statement.target]
                )
                if any(
                    isinstance(target, ast.Name) and target.id == name
                    for target in targets
                ):
                    rows.append(statement.value)
        if len(bindings) != 1 or len(rows) != 1 or not isinstance(rows[0], ast.Name):
            return None
        return path, rows[0]
    return None


def resolve_class(path, expression, imports, classes):
    if isinstance(expression, ast.Name):
        imported = imports.get(path, {}).get(expression.id)
        if imported:
            return imported if imported[1] else None
        return (path, expression.id) if (path, expression.id) in classes else None
    if isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
        imported = imports.get(path, {}).get(expression.value.id)
        if imported and imported[1] is None:
            return imported[0], expression.attr
    return None


def scope_class(node, index, path):
    current = node
    while current is not None:
        current = index.parents[path].get(id(current))
        if isinstance(current, ast.ClassDef):
            return current
    return None


def instance_receiver(node, function, owner, index, path):
    """Only bind self.FIELD in a direct, unshadowed instance method."""
    if function is None or owner is None:
        return False
    parents = index.parents[path]
    if parents.get(id(function)) is not owner:
        return False
    args = function.args
    positional = [*args.posonlyargs, *args.args]
    if not positional or positional[0].arg != "self":
        return False
    from .credential_role_scope_bindings import binding_occurrences

    if function.decorator_list or binding_occurrences(function.body, "self"):
        return False
    current = node
    while current is not function:
        current = parents.get(id(current))
        if current is None or isinstance(
            current,
            (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
        ):
            return False
    return not any(item.arg == "self" for item in args.kwonlyargs) and not (
        (args.vararg and args.vararg.arg == "self")
        or (args.kwarg and args.kwarg.arg == "self")
    )
