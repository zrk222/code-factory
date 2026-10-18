"""Resolve reflective getter references without weakening source obligations."""

from .credential_role_method_use_getters import (
    _getter_name,
    _reflective_receiver,
    _stable_self,
)
from .credential_role_method_use_relation import class_identity, different_field_origin


def audit_reflective(
    node,
    path,
    relative,
    calls,
    owners,
    names,
    fields,
    index,
    context,
    related,
    imports,
    classes,
    audit,
    aliases,
    unknown,
    link_receiver,
):
    receiver = _reflective_receiver(node)
    lexical = class_identity(node, index, path)
    stable = _stable_self(receiver, index, path, context)
    getter = _getter_name(node, names, aliases)
    unrelated = stable and different_field_origin(
        lexical, getter, fields, index, imports, classes, audit
    )
    relation = link_receiver(
        stable and lexical in owners and not unrelated,
        receiver,
        path,
        calls,
        getter,
        fields,
        index,
        context,
        related,
        imports,
        classes,
    )
    linked = relation == "LINKED"
    unrelated = unrelated or relation == "UNRELATED"
    if not linked and not unrelated:
        unknown.append(
            _unknown("reflective_getter_receiver_unresolved", relative, node)
        )
    elif linked:
        unknown.append(_unknown("reflective_getter_use", relative, node))


def _unknown(reason, relative, node):
    return {
        "reason": reason,
        "path": relative,
        "line": node.lineno,
        "column": node.col_offset,
    }
