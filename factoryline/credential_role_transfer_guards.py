"""Reject rebinding and conditional execution in declared constructor transfers."""

import ast

from .credential_role_class_binding import instance_receiver
from .credential_role_scope_bindings import binding_occurrences


def direct_factory_call(call, function, index, path):
    owner = index.parents[path].get(id(function))
    if not instance_receiver(call, function, owner, index, path):
        return False
    statement = index.parents[path].get(id(call))
    return (
        statement in function.body
        and isinstance(statement, (ast.Return, ast.Assign, ast.AnnAssign))
        and statement.value is call
    )


def exact_parameter_field(ctor, assignment, param, index, path):
    if assignment not in ctor.body or binding_occurrences(ctor.body, param):
        return False
    target = assignment.targets[0]
    owner = index.parents[path].get(id(ctor))
    if not instance_receiver(target, ctor, owner, index, path):
        return False
    reads = [
        n
        for n in ast.walk(ctor)
        if isinstance(n, ast.Name) and n.id == param and isinstance(n.ctx, ast.Load)
    ]
    if len(reads) != 1 or reads[0] is not assignment.value:
        return False
    writes = [
        n
        for n in ast.walk(ctor)
        if isinstance(n, ast.Attribute)
        and n.attr == target.attr
        and isinstance(n.ctx, (ast.Store, ast.Del))
    ]
    if len(writes) != 1 or writes[0] is not target:
        return False
    return not any(_reflective_mutation(n, target.attr) for n in ast.walk(ctor))


def _reflective_mutation(node, field):
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return isinstance(node.value, ast.Name) and node.value.id == "self"
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"setattr", "delattr", "exec", "locals", "vars"}
    ):
        return False
    if node.func.id in {"exec", "locals", "vars"}:
        return True
    return bool(
        node.args
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "self"
        and (
            len(node.args) < 2
            or not isinstance(node.args[1], ast.Constant)
            or node.args[1].value == field
        )
    )
