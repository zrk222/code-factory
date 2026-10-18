"""Recognize source-scoped request calls without asserting runtime provider identity."""

import ast


def _receiver_preserved(owner, call, receiver):
    """Support only one receiver use in the whole block: this request call."""
    for node in ast.walk(owner):
        if isinstance(node, ast.Name) and node.id == receiver:
            if node is not call.func.value:
                return False
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and (
            node.name == receiver
        ):
            return False
        if isinstance(node, (ast.Import, ast.ImportFrom)) and any(
            alias.name == "*" or (alias.asname or alias.name.split(".")[0]) == receiver
            for alias in node.names
        ):
            return False
        if isinstance(node, ast.ExceptHandler) and node.name == receiver:
            return False
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name == receiver:
            return False
        if isinstance(node, ast.MatchMapping) and node.rest == receiver:
            return False
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and (node.func.id in {"exec", "locals", "globals", "vars"})
        ):
            return False
    return True


def _context_identity(context, owner, call, receiver, aliases):
    if not isinstance(context, ast.Call) or not isinstance(context.func, ast.Attribute):
        return False
    adapter_call = context.func.value
    if context.func.attr != "get_requests_session" or not isinstance(
        adapter_call, ast.Call
    ):
        return False
    if context.args or context.keywords or len(owner.items) != 1:
        return False
    if not all(_receiver_preserved(stmt, call, receiver) for stmt in owner.body):
        return False
    from .security_configuration import _canonical

    return _canonical(adapter_call, aliases)


def session_request_context(call, index, path, aliases):
    if not (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "request"
        and isinstance(call.func.value, ast.Name)
    ):
        return False
    if not index.validate(path):
        return False
    receiver, current = call.func.value.id, call
    while current is not None:
        current = index.parents[path].get(id(current))
        if isinstance(
            current,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef,
                ast.ClassDef,
                ast.Lambda,
                ast.ListComp,
                ast.SetComp,
                ast.DictComp,
                ast.GeneratorExp,
            ),
        ):
            return False
        if isinstance(current, ast.AsyncWith):
            return False
        if isinstance(current, ast.With):
            for item in current.items:
                context, value = item.context_expr, item.optional_vars
                if not isinstance(value, ast.Name) or value.id != receiver:
                    continue
                return _context_identity(context, current, call, receiver, aliases)
    return False
