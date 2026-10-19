"""Reject opaque captured owner references and prove builtin identity uses."""

import ast
from functools import partial

from .credential_role_constructor_types import ordinary_type_operand
from .credential_role_scope_bindings import binding_occurrences
from .credential_role_constructor_provider_provenance import (
    class_index,
    owner_path,
    source_owner_consumer,
)


def _has_opaque_owner_capture(
    index, aliases_by_path, owners, filtered, field_aliases, consumers
):
    builtin_stable = not _captured_builtins_mutate_isinstance(index)
    classes = class_index(index, aliases_by_path)
    for path, tree in index.snapshots.items():
        aliases, parents = aliases_by_path[path], index.parents[path]
        fields = field_aliases

        ordinary_type = partial(
            ordinary_type_operand,
            tree=tree,
            parents=parents,
            index=index,
            classes=classes,
            aliases=aliases,
            owners=owners,
            aliases_by_path=aliases_by_path,
        )

        for node in ast.walk(tree):
            if id(node) in filtered.get(path, set()):
                continue
            if _owner_reflection_access(node, aliases, owners, fields):
                return True
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                value = node.value
                if (
                    isinstance(value, ast.Call)
                    and not value.args
                    and not value.keywords
                    and owner_path(value.func, aliases, fields) in owners
                ):
                    continue
                if _contains_owner_escape(
                    value,
                    tree,
                    parents,
                    aliases,
                    owners,
                    builtin_stable,
                    fields,
                    ordinary_type,
                ):
                    return True
            returned = _returned_value(node)
            if returned is not None and _contains_owner_escape(
                returned,
                tree,
                parents,
                aliases,
                owners,
                builtin_stable,
                fields,
                ordinary_type,
            ):
                return True
            if isinstance(node, (ast.Name, ast.Attribute)) and _owner_call_argument(
                node,
                path,
                tree,
                parents,
                index,
                aliases,
                classes,
                owners,
                builtin_stable,
                fields,
                consumers,
                ordinary_type,
                aliases_by_path,
            ):
                return True
    return False


def _returned_value(node):
    return (
        node.value if isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)) else None
    )


def _captured_builtins_mutate_isinstance(index):
    return any(
        isinstance(node, ast.Name)
        and node.id == "__builtins__"
        or isinstance(node, ast.Constant)
        and node.value in {"builtins", "__builtins__"}
        or isinstance(node, ast.Import)
        and any(item.name == "builtins" for item in node.names)
        or isinstance(node, ast.ImportFrom)
        and node.module == "builtins"
        or isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"exec", "eval"}
        for tree in index.snapshots.values()
        for node in ast.walk(tree)
    )


def _owner_reflection_access(node, aliases, owners, fields):
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return owner_path(node.value, aliases, fields) in owners
    return bool(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == "client_class"
        and owner_path(node.args[0], aliases, fields) in owners
    )


def _owner_call_argument(
    node,
    path,
    tree,
    parents,
    index,
    aliases,
    classes,
    owners,
    builtin_stable,
    fields,
    consumers,
    ordinary_type,
    aliases_by_path,
):
    from .provider_mutations import _provider_call_argument

    if (
        owner_path(node, aliases, fields) not in owners
        or not _provider_call_argument(node, parents)
        or _safe_isinstance_type(node, tree, parents, builtin_stable, ordinary_type)
    ):
        return False
    consumer = source_owner_consumer(
        node,
        path,
        tree,
        parents,
        index,
        aliases,
        classes,
        owners,
        builtin_stable,
        aliases_by_path,
    )
    if consumer is None:
        return True
    consumers.add(consumer)
    return False


def _contains_owner_escape(
    value, tree, parents, aliases, owners, builtin_stable, fields, ordinary_type
):
    return any(
        owner_path(item, aliases, fields) in owners
        and not _safe_isinstance_type(
            item, tree, parents, builtin_stable, ordinary_type
        )
        and getattr(parents.get(id(item)), "func", None) is not item
        for item in ast.walk(value)
        if isinstance(item, (ast.Name, ast.Attribute))
    )


def _safe_isinstance_type(node, tree, parents, builtin_stable, ordinary_type=None):
    call = parents.get(id(node))
    while call is not None and not isinstance(call, ast.Call):
        call = parents.get(id(call))
    if (
        not isinstance(call, ast.Call)
        or not isinstance(call.func, ast.Name)
        or call.func.id != "isinstance"
        or len(call.args) != 2
        or call.args[1] is not node
        or call.keywords
        or not builtin_stable
        or binding_occurrences(tree.body, "isinstance")
        or ordinary_type is None
        or not ordinary_type(call.args[1])
    ):
        return False
    scope = parents.get(id(call))
    while scope is not None:
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
            args.extend(arg for arg in (scope.args.vararg, scope.args.kwarg) if arg)
            if any(arg.arg == "isinstance" for arg in args) or binding_occurrences(
                scope.body, "isinstance"
            ):
                return False
        elif isinstance(scope, ast.ClassDef) and binding_occurrences(
            scope.body, "isinstance"
        ):
            return False
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
            isinstance(item, (ast.Global, ast.Nonlocal)) and "isinstance" in item.names
            for item in ast.walk(scope)
        ):
            return False
        scope = parents.get(id(scope))
    return True
