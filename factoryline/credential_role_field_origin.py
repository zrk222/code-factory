"""Resolve one effective literal field declaration from a validated class MRO."""

import ast

from .credential_role_scope_bindings import binding_occurrences

_HOOKS = {"__getattr__", "__getattribute__", "__setattr__", "__delattr__"}


def resolve_declared_field_origin(chain, member, index):
    """Return declaration identity only; ambiguous or mutable fields stay unknown."""
    if not isinstance(member, str) or not member.isidentifier() or not chain:
        return _unknown("invalid_query")
    traversed = []
    for path, _, owner in chain:
        tree = index.snapshots.get(path)
        if (
            not index.validate(path)
            or not isinstance(owner, ast.ClassDef)
            or not isinstance(tree, ast.Module)
            or not any(node is owner for node in tree.body)
        ):
            return _unknown("class_source_unbound")
        if any(binding_occurrences(owner.body, hook) for hook in _HOOKS):
            return _unknown("dynamic_attribute_hook")
        traversed.append((owner, path))
        bindings = binding_occurrences(owner.body, member)
        if not bindings:
            continue
        if len(bindings) != 1:
            return _unknown("member_binding_ambiguous")
        declaration = bindings[0]
        if isinstance(declaration, ast.Name):
            declaration = index.parents[path].get(id(declaration))
        result = _literal_binding(declaration, member, owner, index, path)
        if result is None:
            return _unknown("member_binding_dynamic")
        if any(_member_mutated(parent, member) for parent, _ in traversed):
            return _unknown("member_mutated_or_reflective")
        return _origin(index, path, declaration)
    return _unknown("member_not_declared")


def _literal_binding(statement, member, owner, index, path):
    if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
        return None
    if index.parents[path].get(id(statement)) is not owner:
        return None
    targets = (
        statement.targets if isinstance(statement, ast.Assign) else [statement.target]
    )
    value = getattr(statement, "value", None)
    return (
        statement
        if (
            len(targets) == 1
            and isinstance(targets[0], ast.Name)
            and targets[0].id == member
            and isinstance(value, ast.Constant)
            and (isinstance(value.value, str) or value.value is None)
        )
        else None
    )


def _member_mutated(owner, member):
    for method in owner.body:
        if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        arguments = [*method.args.posonlyargs, *method.args.args]
        if not arguments:
            continue
        receiver = arguments[0].arg
        if binding_occurrences(method.body, receiver):
            return True
        for node in ast.walk(method):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if (
                    node.value.id == receiver
                    and node.attr == member
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                ):
                    return True
                if node.value.id == receiver and node.attr in _HOOKS | {"__dict__"}:
                    return True
            if _reflective_mutation(node, receiver):
                return True
    return False


def _reflective_mutation(node, receiver):
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        return False
    return node.func.id in {"getattr", "setattr", "delattr", "vars"} and bool(
        node.args and isinstance(node.args[0], ast.Name) and node.args[0].id == receiver
    )


def _origin(index, path, node):
    return {
        "state": "EXACT",
        "origin": {
            "path": index.relative(path),
            "span": [
                node.lineno,
                node.col_offset,
                node.end_lineno,
                node.end_col_offset,
            ],
            "source_sha256": index.inventory[path],
        },
    }


def _unknown(reason):
    return {"state": "UNKNOWN", "reason": reason}
