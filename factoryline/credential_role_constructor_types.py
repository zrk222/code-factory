"""Prove ordinary source-bound type operands before treating isinstance as inert."""

import ast
from types import SimpleNamespace

from .credential_role_scope_bindings import binding_occurrences
from .provider_mutations import finite_provider_mutation_index
from .review_audits import _resolved_ast_name


def ordinary_type_operand(
    node, tree, parents, index, classes, aliases, owners, aliases_by_path
):
    if not isinstance(node, (ast.Name, ast.Attribute)):
        return False
    root = node
    while isinstance(root, ast.Attribute):
        root = root.value
    if not isinstance(root, ast.Name) or not _lexical_binding_stable(root, parents):
        return False
    canonical = _resolved_ast_name(node, aliases)
    return _ordinary_class(canonical, classes, set()) and _type_metadata_stable(
        canonical, index, owners, aliases_by_path
    )


def _lexical_binding_stable(node, parents):
    scope = parents.get(id(node))
    while scope is not None:
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
            args.extend(arg for arg in (scope.args.vararg, scope.args.kwarg) if arg)
            if any(arg.arg == node.id for arg in args):
                return False
            body = scope.body if isinstance(scope.body, list) else [scope.body]
            if binding_occurrences(body, node.id):
                return False
        scope = parents.get(id(scope))
    return True


def _ordinary_class(canonical, classes, seen):
    row = classes.get(canonical)
    if row is None or canonical in seen:
        return False
    _, owner, aliases, tree = row
    if owner.keywords or owner.decorator_list:
        return False
    for base in owner.bases:
        if isinstance(base, ast.Name) and base.id == "object":
            if binding_occurrences(tree.body, "object"):
                return False
        elif not _ordinary_class(
            _resolved_ast_name(base, aliases), classes, seen | {canonical}
        ):
            return False
    return True


def _type_metadata_stable(canonical, index, owners, aliases_by_path):
    audit = SimpleNamespace(_resolved_ast_name=_resolved_ast_name)
    for path, tree in index.snapshots.items():
        aliases = aliases_by_path.get(path)
        if aliases is None or not index.validate(path):
            return False
        parents = index.parents[path]
        nodes = [
            item
            for item in ast.walk(tree)
            if not _exact_type_argument(item, parents, tree)
        ]
        if canonical not in owners and any(
            isinstance(item, (ast.Name, ast.Attribute))
            and _resolved_ast_name(item, aliases) == canonical
            for item in nodes
        ):
            return False
        facts = finite_provider_mutation_index(nodes, aliases, audit, parents)
        if any(
            _metadata_overlap(provider, attr, canonical, owners)
            for provider, attr in facts
        ):
            return False
    return True


def _exact_type_argument(node, parents, tree):
    call = parents.get(id(node))
    return bool(
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "isinstance"
        and len(call.args) == 2
        and call.args[1] is node
        and not call.keywords
        and not binding_occurrences(tree.body, "isinstance")
        and _lexical_binding_stable(call.func, parents)
    )


def _metadata_overlap(provider, attribute, canonical, owners):
    if attribute == "*":
        return provider == canonical and canonical not in owners
    path = provider + "." + attribute
    return any(
        path == canonical + "." + name or path.startswith(canonical + "." + name + ".")
        for name in ("__bases__", "__class__", "__instancecheck__")
    )
