"""Recognize a complete lookup-loop fallthrough to a supplied default."""

import ast


def _doc(node):
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def fallback_method(function):
    """Recognize the exact un-decorated settings fallback method shape and return its lookup nodes only when names and branches are stable."""
    if function is None or function.decorator_list:
        return None
    if [arg.arg for arg in function.args.args][:3] != ["self", "name", "default"]:
        return None
    rows = [node for node in function.body if not _doc(node)]
    loops = [node for node in rows if isinstance(node, ast.For)]
    returns = [node for node in ast.walk(function) if isinstance(node, ast.Return)]
    if len(rows) != 4 or len(loops) != 1 or len(returns) != 2:
        return None
    if not _names_prep(rows[0]) or not _backend_prefix(rows[1]):
        return None
    if not _stable_names(function):
        return None
    loop, final = loops[0], rows[-1]
    if (
        not isinstance(final, ast.Return)
        or not isinstance(final.value, ast.Name)
        or final.value.id != "default"
    ):
        return None
    attempt = _lookup_attempt(loop)
    return (loop, attempt, final) if attempt else None


def _names_prep(node):
    return bool(
        isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "names"
        and isinstance(node.value, ast.List)
        and bool(node.value.elts)
    )


def _backend_prefix(node):
    return bool(
        isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "backend"
        and len(node.body) == 1
        and not node.orelse
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Call)
        and isinstance(node.body[0].value.func, ast.Attribute)
        and isinstance(node.body[0].value.func.value, ast.Name)
        and node.body[0].value.func.value.id == "names"
        and node.body[0].value.func.attr == "insert"
        and len(node.body[0].value.args) == 2
        and isinstance(node.body[0].value.args[0], ast.Constant)
        and node.body[0].value.args[0].value == 0
        and not node.body[0].value.keywords
    )


def _stable_names(function):
    if any(
        isinstance(target, ast.Subscript)
        and isinstance(target.value, ast.Name)
        and target.value.id == "names"
        for node in ast.walk(function)
        for target in _assignment_targets(node)
    ):
        return False
    writes = {
        name: [
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, ast.Store)
        ]
        for name in ("names", "name", "default", "backend")
    }
    initial = next(
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "names"
    )
    return (
        len(writes["names"]) == 1
        and writes["names"][0] is initial.targets[0]
        and all(not writes[name] for name in ("name", "default", "backend"))
        and _default_only_falls_through(function)
    )


def _default_only_falls_through(function):
    defaults = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and node.id == "default"
        and isinstance(node.ctx, ast.Load)
    ]
    returns = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Return)
        and isinstance(node.value, ast.Name)
        and node.value.id == "default"
    ]
    return len(defaults) == len(returns) == 1 and defaults[0] is returns[0].value


def _assignment_targets(node):
    if isinstance(node, ast.Assign):
        return node.targets
    if isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
        return [node.target]
    return []


def _lookup_attempt(loop):
    if not isinstance(loop.target, ast.Name) or not isinstance(loop.iter, ast.Name):
        return None
    if loop.orelse or (
        loop.iter.id != "names"
        or len(loop.body) != 1
        or not isinstance(loop.body[0], ast.Try)
    ):
        return None
    attempt = loop.body[0]
    if len(attempt.body) != 1 or not isinstance(attempt.body[0], ast.Return):
        return None
    call = attempt.body[0].value
    handlers = attempt.handlers
    if (
        not isinstance(call, ast.Call)
        or len(call.args) != 1
        or len(handlers) != 1
        or attempt.orelse
        or attempt.finalbody
    ):
        return None
    if not (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "self"
        and call.func.attr == "get_setting"
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == loop.target.id
        and not call.keywords
    ):
        return None
    caught = (
        handlers[0].type.elts
        if isinstance(handlers[0].type, ast.Tuple)
        else [handlers[0].type]
    )
    if {ast.unparse(item) for item in caught} != {"AttributeError", "KeyError"}:
        return None
    if len(handlers[0].body) != 1 or not isinstance(handlers[0].body[0], ast.Pass):
        return None
    return attempt
