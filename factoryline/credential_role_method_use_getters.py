"""Close getter calls and bound getter references for one declared candidate."""

import ast

from .credential_role_method_use_common import ancestor
from .credential_role_bindings import class_chain
from .credential_role_class_binding import instance_receiver
from .credential_role_forwarding_decorator import method_rows
from .credential_role_method_return import verified_instance_receiver


def audit_getter_uses(
    traces, nodes, index, unknown, *, context=None, related_owners=None
):
    from .credential_role_method_use_getter_audit import audit_getter_uses as audit

    audit(traces, nodes, index, unknown, context=context, related_owners=related_owners)


def _reflective_getter(call, getter_names, aliases):
    from .security_configuration import _canonical

    name = _canonical(call, aliases)
    if name in {"builtins.getattr", "getattr"} and len(call.args) >= 2:
        return (
            isinstance(call.args[1], ast.Constant)
            and call.args[1].value in getter_names
        )
    return bool(
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "__getattribute__"
        and call.args
        and isinstance(call.args[0], ast.Constant)
        and call.args[0].value in getter_names
    )


def _reflective_receiver(call):
    if isinstance(call.func, ast.Attribute) and call.func.attr == "__getattribute__":
        return call.func.value
    return call.args[0] if call.args else None


def _getter_name(call, getter_names, aliases):
    if not _reflective_getter(call, getter_names, aliases):
        return None
    position = (
        0
        if isinstance(call.func, ast.Attribute) and call.func.attr == "__getattribute__"
        else 1
    )
    return call.args[position].value


def _self_call(node):
    return bool(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "self"
    )


def _stable_self(node, index, path, context=None):
    if not isinstance(node, ast.Name) or node.id != "self":
        return False
    function = ancestor(
        node, index, index.relative(path), (ast.FunctionDef, ast.AsyncFunctionDef)
    )
    owner = ancestor(node, index, index.relative(path), (ast.ClassDef,))
    if function is None or owner is None:
        return False
    if not function.decorator_list:
        return instance_receiver(node, function, owner, index, path)
    if context is None:
        return False
    imports, classes, audit = context
    chain = class_chain(
        index, index.root / index.relative(path), owner.name, imports, classes, audit
    )
    if not chain:
        return False
    methods, proofs = method_rows(chain, index, imports)
    row = methods.get(function.name)
    return bool(
        row
        and row[0] == path
        and row[1] is function
        and row[2] is owner
        and verified_instance_receiver(
            node, function, owner, index, path, bool(proofs.get(function.name))
        )
    )
