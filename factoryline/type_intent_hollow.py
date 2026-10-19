"""Narrow source proofs for hollow type-intent tests."""

from __future__ import annotations

import ast
from hashlib import sha256
from pathlib import Path

from . import type_intent_provider_provenance as provider


def captured_provider_context_closed(
    module, relative, selected_test, canonical, noop_write
) -> bool:
    context = getattr(module, "_security_oracle_context", None)
    source = getattr(module, "_security_source_context", None)
    if (
        not isinstance(context, dict)
        or not _valid_relative(relative)
        or not context.get("provider_source_inventory_complete")
        or not context.get("provider_source_closure_complete")
        or not isinstance(context.get("provider_source_closure"), list)
        or not isinstance(context.get("provider_owner_local_imports"), list)
        or any(
            not isinstance(alias, str)
            for alias in context["provider_owner_local_imports"]
        )
        or not isinstance(source, tuple)
        or len(source) != 2
        or not isinstance(source[0], Path)
        or not isinstance(source[1], dict)
    ):
        return False
    root, sources = source
    digest = getattr(module, "_oracle_source_sha256", None)
    raw = sources.get(root / relative)
    return bool(
        isinstance(digest, str)
        and len(digest) == 64
        and isinstance(raw, bytes)
        and sha256(raw).hexdigest() == digest
        and provider.owner_module_effects_closed(
            module,
            selected_test,
            canonical,
            noop_write,
            context["provider_owner_local_imports"],
        )
        and provider._captured_closure_closed(
            root, sources, context["provider_source_closure"]
        )
    )


def _valid_relative(value):
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts


def obviously_empty_test_body(node: ast.AST) -> bool:
    from .test_callback_closure import inert_registered_callback_body
    from .test_oracle_misuse import inert_test_body

    return inert_test_body(node) or inert_registered_callback_body(node)


def inert_type_assertion_only_oracle(
    node,
    aliases,
    *,
    module_aliases,
    scope_parameters,
    provider_mutated,
    relative,
    provider_context_closed,
) -> bool:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    module = getattr(node, "_oracle_module", None)
    if not isinstance(module, ast.Module):
        return False
    source_aliases = dict(module_aliases)
    source_aliases.update(aliases)
    body = [statement for statement in node.body if not _ignorable(statement)]
    call, local_assignment = _test_call(body, scope_parameters)
    if call is None or not provider._simple_type_call(call):
        return False
    canonical = provider._source_name(call.func, source_aliases)
    if canonical not in {"typing.assert_type", "typing_extensions.assert_type"}:
        return False
    lexical = provider._source_name(call.func, aliases)
    if lexical != canonical and local_assignment is None:
        return False
    if not _provider_references_are_closed(
        module, call, local_assignment, source_aliases, canonical
    ):
        return False
    noop_write = None
    if provider_mutated(module, source_aliases):
        noop_write = _single_noop_provider_write(
            module, source_aliases, canonical, call
        )
        if noop_write is None:
            return False
    return provider_context_closed(module, relative, node, canonical, noop_write)


def _ignorable(statement: ast.stmt, *, ellipsis: bool = False) -> bool:
    if isinstance(statement, ast.Pass):
        return True
    if not isinstance(statement, ast.Expr) or not isinstance(
        statement.value, ast.Constant
    ):
        return False
    value = statement.value.value
    return isinstance(value, str) or ellipsis and value is Ellipsis


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


def _provider_references_are_closed(module, call, local_assignment, aliases, canonical):
    provider_name = canonical.split(".", 1)[0]
    parent = {
        child: current
        for current in ast.walk(module)
        for child in ast.iter_child_nodes(current)
    }
    for reference in (item for item in ast.walk(module) if isinstance(item, ast.Name)):
        target = aliases.get(reference.id)
        if target not in {provider_name, canonical}:
            continue
        if target == provider_name:
            attribute = parent.get(reference)
            if not (
                isinstance(attribute, ast.Attribute)
                and attribute.value is reference
                and attribute.attr == "assert_type"
                and _allowed_provider_attribute(
                    parent.get(attribute), call, aliases, canonical
                )
            ):
                return False
            continue
        use = parent.get(reference)
        if isinstance(use, ast.Call) and use.func is reference:
            if use is call or (
                provider._source_name(use.func, aliases) == canonical
                and provider._simple_type_call(use)
            ):
                continue
        if local_assignment is not None and reference is local_assignment.targets[0]:
            continue
        if _allowed_provider_attribute(use, call, aliases, canonical):
            continue
        return False
    return not any(
        isinstance(item, ast.Name) and item.id in {"exec", "eval"}
        for item in ast.walk(module)
    )


def _allowed_provider_attribute(
    parent: ast.AST | None, call: ast.Call, aliases: dict[str, str], canonical: str
) -> bool:
    if isinstance(parent, ast.Call):
        return parent is call or (
            provider._source_name(parent.func, aliases) == canonical
            and provider._simple_type_call(parent)
        )
    return isinstance(parent, ast.Assign) and any(
        isinstance(target, ast.Attribute) and target.attr == "assert_type"
        for target in parent.targets
    )


def _single_noop_provider_write(
    module: ast.Module, aliases: dict[str, str], canonical: str, call: ast.Call
):
    writes = [
        item
        for item in ast.walk(module)
        if isinstance(item, ast.Attribute)
        and isinstance(item.ctx, (ast.Store, ast.Del))
        and item.attr == "assert_type"
        and provider._source_name(item, aliases)
        in {"typing.assert_type", "typing_extensions.assert_type"}
    ]
    if len(writes) != 1 or provider._source_name(writes[0], aliases) != canonical:
        return None
    assignments = [
        statement
        for statement in module.body
        if isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and statement.targets[0] is writes[0]
    ]
    if (
        len(assignments) == 1
        and assignments[0].lineno < call.lineno
        and _none_lambda(assignments[0].value)
    ):
        return assignments[0]
    return None


def _none_lambda(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Lambda)
        and isinstance(node.body, ast.Constant)
        and node.body.value is None
        and not node.args.defaults
        and not node.args.kw_defaults
    )


CACHE_HELPERS = tuple(
    helper
    for helper in globals().values()
    if callable(helper)
    and getattr(helper, "__module__", None) == __name__
    and hasattr(helper, "__code__")
)
