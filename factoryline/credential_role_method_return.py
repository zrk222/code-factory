"""Return and transform shapes accepted by method-flow evidence."""

import ast


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
    from .credential_role_method_contracts import alias_value

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
    from .credential_role_class_binding import instance_receiver

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
