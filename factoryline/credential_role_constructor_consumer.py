"""Source-defined class-reference consumer effect checks."""

import ast

from .credential_role_identity_effects import summarize_identity_effect
from .credential_role_constructor_types import ordinary_type_operand
from .credential_role_scope_bindings import binding_occurrences
from .review_audits import _resolved_ast_name
from .review_integrity import bind_source_call


def source_owner_consumer(
    node,
    path,
    tree,
    parents,
    index,
    aliases,
    classes,
    owners,
    builtin_stable,
    aliases_by_path=None,
):
    call = parents.get(id(node))
    if (
        _resolved_ast_name(node, aliases) not in owners
        or not _is_call_argument(node, call)
        or not isinstance(call.func, ast.Attribute)
    ):
        return None
    receiver = call.func.value
    row = _captured_method(
        _resolved_ast_name(receiver, aliases), call.func.attr, classes, set()
    )
    if row is None:
        return None
    method_owner_path, method_path, owner, method = row
    if not _classmethod(method, owner, classes, builtin_stable):
        return None
    try:
        bound = bind_source_call(call, method, receiver=receiver, apply_defaults=False)
    except (TypeError, ValueError):
        return None
    formals = [name for name, value in bound.items() if value is node]
    if len(formals) != 1 or not _consumer_effect_safe(
        method,
        method_path,
        index,
        formals[0],
        builtin_stable,
        (classes, classes[method_owner_path][2], owners, aliases_by_path),
    ):
        return None
    if aliases_by_path is None or not ordinary_type_operand(
        node, tree, parents, index, classes, aliases, owners, aliases_by_path
    ):
        return None
    return method_owner_path + "." + method.name


def _captured_method(path, name, classes, seen):
    if path in seen:
        return None
    row = classes.get(path)
    if row is None:
        return None
    file_path, owner, aliases, _ = row
    definitions = binding_occurrences(owner.body, name)
    if definitions:
        if (
            len(definitions) == 1
            and isinstance(definitions[0], ast.FunctionDef)
            and definitions[0] in owner.body
        ):
            return path, file_path, owner, definitions[0]
        return None
    if len(owner.bases) == 1:
        return _captured_method(
            _resolved_ast_name(owner.bases[0], aliases), name, classes, seen | {path}
        )
    if owner.bases:
        first_path = _resolved_ast_name(owner.bases[0], aliases)
        first = classes.get(first_path)
        if first is not None:
            base = binding_occurrences(first[1].body, name)
            if (
                len(base) == 1
                and isinstance(base[0], ast.FunctionDef)
                and base[0] in first[1].body
            ):
                return first_path, first[0], first[1], base[0]
    return None


def _classmethod(method, owner, classes, builtin_stable):
    row = next((entry for entry in classes.values() if entry[1] is owner), None)
    return bool(
        row
        and builtin_stable
        and len(method.decorator_list) == 1
        and isinstance(method.decorator_list[0], ast.Name)
        and method.decorator_list[0].id == "classmethod"
        and not binding_occurrences(row[3].body, "classmethod")
        and binding_occurrences(owner.body, method.name) == [method]
    )


def _is_call_argument(node, call):
    return bool(
        isinstance(call, ast.Call)
        and (
            any(value is node for value in call.args)
            or any(k.value is node for k in call.keywords)
        )
    )


def _consumer_effect_safe(method, path, index, parameter, builtin_stable, types=None):
    nested = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
    if any(
        node is not method and isinstance(node, nested) for node in ast.walk(method)
    ):
        return False
    tree, parents = index.snapshots[path], index.parents[path]

    def ordinary_type(operand):
        if types is None:
            return False
        classes, aliases, owners, aliases_by_path = types
        if aliases_by_path is None:
            return False
        return ordinary_type_operand(
            operand, tree, parents, index, classes, aliases, owners, aliases_by_path
        )

    uses = [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Name)
        and node.id == parameter
        and isinstance(node.ctx, ast.Load)
    ]
    if not all(
        _is_safe_isinstance_value(node, tree, parents, builtin_stable, ordinary_type)
        for node in uses
    ):
        return False
    effects = summarize_identity_effect(method, path, index, {parameter: "owner"})
    allowed_unknowns = {
        "implicit special-method dispatch on tracked root",
        "return/yield contains unresolved tracked value",
    }
    return bool(
        not effects.class_writes
        and set(effects.escapes) <= {"owner"}
        and set(effects.unknowns) <= allowed_unknowns
    )


def _is_safe_isinstance_value(node, tree, parents, builtin_stable, ordinary_type=None):
    call = parents.get(id(node))
    if not (
        builtin_stable
        and isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "isinstance"
        and len(call.args) == 2
        and call.args[0] is node
        and not call.keywords
        and not binding_occurrences(tree.body, "isinstance")
        and ordinary_type is not None
        and ordinary_type(call.args[1])
    ):
        return False
    scope = parents.get(id(call))
    while scope is not None:
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
            if any(arg.arg == "isinstance" for arg in params) or binding_occurrences(
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
