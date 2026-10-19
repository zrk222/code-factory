"""Narrow source proofs for hollow type-intent tests."""

from __future__ import annotations

import ast
from collections.abc import Callable


def obviously_empty_test_body(node: ast.AST) -> bool:
    """Recognize bodies containing only pass and docstring-like literals."""
    return bool(node.body) and all(
        isinstance(statement, ast.Pass)
        or (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, (str, type(Ellipsis)))
        )
        for statement in node.body
    )


def inert_type_assertion_only_oracle(
    node: ast.AST,
    aliases: dict[str, str],
    *,
    module_aliases: dict[str, str],
    scope_parameters: set[str],
    provider_mutated: Callable[[ast.Module, dict[str, str]], bool],
    relative: str,
    provider_context_closed: Callable[[ast.Module, str], bool],
) -> bool:
    """Prove the body is only a canonical, runtime-inert assert_type call."""
    module = getattr(node, "_oracle_module", None)
    if not isinstance(module, ast.Module):
        return False
    if not provider_context_closed(module, relative):
        return False
    source_aliases = dict(module_aliases)
    source_aliases.update(aliases)
    body = [statement for statement in node.body if not _ignorable(statement)]
    call, local_assignment = _test_call(body, scope_parameters)
    if call is None or not _simple_type_call(call):
        return False
    canonical = _source_name(call.func, source_aliases)
    if canonical not in {"typing.assert_type", "typing_extensions.assert_type"}:
        return False
    lexical = _source_name(call.func, aliases)
    if lexical != canonical and local_assignment is None:
        return False
    if not _provider_references_are_closed(
        module, node, call, local_assignment, source_aliases, canonical
    ):
        return False
    if not provider_mutated(module, source_aliases):
        return True
    return _single_noop_provider_write(module, source_aliases, canonical, call)


def _ignorable(statement: ast.stmt) -> bool:
    return isinstance(statement, ast.Pass) or (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )


def _test_call(body: list[ast.stmt], parameters: set[str]):
    if len(body) == 1 and isinstance(body[0], ast.Expr):
        return body[0].value, None
    if (
        len(body) == 2
        and isinstance(body[0], ast.Assign)
        and isinstance(body[1], ast.Expr)
        and isinstance(body[1].value, ast.Call)
        and len(body[0].targets) == 1
        and isinstance(body[0].targets[0], ast.Name)
        and isinstance(body[1].value.func, ast.Name)
        and body[0].targets[0].id == body[1].value.func.id
        and body[0].lineno < body[1].lineno
        and body[0].targets[0].id not in parameters
        and _none_lambda(body[0].value)
    ):
        return body[1].value, body[0]
    return None, None


def _simple_type_call(call: ast.AST) -> bool:
    return (
        isinstance(call, ast.Call)
        and len(call.args) == 2
        and not call.keywords
        and all(isinstance(arg, (ast.Name, ast.Constant)) for arg in call.args)
        and not any(
            isinstance(child, ast.Call) and child is not call
            for child in ast.walk(call)
        )
    )


def _source_name(node: ast.AST, aliases: dict[str, str]) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name) or node.id not in aliases:
        return None
    return ".".join((aliases[node.id], *reversed(parts)))


def _provider_references_are_closed(
    module: ast.Module,
    test: ast.AST,
    call: ast.Call,
    local_assignment: ast.Assign | None,
    aliases: dict[str, str],
    canonical: str,
) -> bool:
    """Reject provider aliases, reflection, and opaque provider escapes."""
    provider = canonical.split(".", 1)[0]
    parent = {
        child: current
        for current in ast.walk(module)
        for child in ast.iter_child_nodes(current)
    }
    for reference in (item for item in ast.walk(module) if isinstance(item, ast.Name)):
        target = aliases.get(reference.id)
        if target not in {provider, canonical}:
            continue
        if target == provider:
            attribute = parent.get(reference)
            if not (
                isinstance(attribute, ast.Attribute)
                and attribute.value is reference
                and attribute.attr == "assert_type"
                and _allowed_provider_attribute(parent.get(attribute), call)
            ):
                return False
            continue
        use = parent.get(reference)
        if isinstance(use, ast.Call) and use.func is reference:
            if use is call or _source_name(use.func, aliases) == canonical:
                continue
        if (
            local_assignment is not None
            and reference is local_assignment.targets[0]
            and _within(reference, test)
        ):
            continue
        if _allowed_provider_attribute(use, call):
            continue
        return False
    return not any(
        isinstance(item, ast.Name) and item.id in {"exec", "eval"}
        for item in ast.walk(module)
    )


def _allowed_provider_attribute(parent: ast.AST | None, call: ast.Call) -> bool:
    if isinstance(parent, ast.Call) and parent.func is not None:
        return parent is call
    return isinstance(parent, ast.Assign) and any(
        isinstance(target, ast.Attribute) and target.attr == "assert_type"
        for target in parent.targets
    )


def _within(node: ast.AST, ancestor: ast.AST) -> bool:
    if node is ancestor:
        return True
    return any(
        child is node or _within(node, child)
        for child in ast.iter_child_nodes(ancestor)
    )


def _single_noop_provider_write(
    module: ast.Module, aliases: dict[str, str], canonical: str, call: ast.Call
) -> bool:
    writes = [
        item
        for item in ast.walk(module)
        if isinstance(item, ast.Attribute)
        and isinstance(item.ctx, (ast.Store, ast.Del))
        and item.attr == "assert_type"
        and _source_name(item, aliases)
        in {"typing.assert_type", "typing_extensions.assert_type"}
    ]
    if len(writes) != 1 or _source_name(writes[0], aliases) != canonical:
        return False
    assignments = [
        statement
        for statement in module.body
        if isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and statement.targets[0] is writes[0]
    ]
    return (
        len(assignments) == 1
        and assignments[0].lineno < call.lineno
        and _none_lambda(assignments[0].value)
    )


def _none_lambda(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Lambda)
        and isinstance(node.body, ast.Constant)
        and node.body.value is None
        and not node.args.defaults
        and not node.args.kw_defaults
    )


CACHE_HELPERS = (
    obviously_empty_test_body,
    inert_type_assertion_only_oracle,
    _ignorable,
    _test_call,
    _simple_type_call,
    _source_name,
    _provider_references_are_closed,
    _allowed_provider_attribute,
    _within,
    _single_noop_provider_write,
    _none_lambda,
)
