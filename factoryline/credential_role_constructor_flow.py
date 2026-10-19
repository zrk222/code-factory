"""Source-bound class literal flow through a constructor into an HTTP URL slot."""

import ast
import hashlib

from .credential_role_bindings import class_chain, matches_fact
from .credential_role_class_binding import (
    class_attribute,
    effective_method,
    resolve_class,
    scope_class,
    instance_receiver,
)
from .credential_role_transfer_guards import (
    constructor_bindings_inert,
    direct_factory_call,
    exact_parameter_field,
)


def _function_alias(expression, function, source_name, use_line):
    if isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
        return expression.value.id == "self" and expression.attr == source_name
    if not isinstance(expression, ast.Name):
        return False
    from .credential_role_scope_bindings import binding_occurrences

    bindings = binding_occurrences(function.body, expression.id)
    if len(bindings) != 1 or not isinstance(bindings[0], ast.Name):
        return False
    rows = []
    for statement in function.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
        )
        if any(
            isinstance(target, ast.Name) and target.id == expression.id
            for target in targets
        ):
            rows.append(statement)
    return (
        len(rows) == 1
        and rows[0].lineno < use_line
        and isinstance(rows[0].value, ast.Attribute)
        and isinstance(rows[0].value.value, ast.Name)
        and rows[0].value.value.id == "self"
        and rows[0].value.attr == source_name
    )


def _hop(index, path, node, role):
    if not index.validate(path):
        return None
    relative = index.relative(path)
    if relative is None:
        return None
    raw = index.source_bytes[path]
    return {
        "path": relative,
        "line": node.lineno,
        "column": node.col_offset,
        "end_line": getattr(node, "end_lineno", node.lineno),
        "end_column": getattr(node, "end_col_offset", node.col_offset),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "role": role,
    }


def constructor_url_hops(
    fact, sink_path, call, expression, index, imports, classes, audit, integrity
):
    """Return verified transfer hops, or None when any source binding is ambiguous."""
    if not index.validate(sink_path):
        return None
    candidate_path = index.root / fact.path
    candidate_chain = class_chain(
        index, candidate_path, fact.owner, imports, classes, audit
    )
    if not candidate_chain or fact.owner == "<module>":
        return None
    client_attr = class_attribute(candidate_chain, "client_class")
    if client_attr is None:
        return None
    client_path, client_expr = client_attr
    client_ref = resolve_class(client_path, client_expr, imports, classes)
    if client_ref is None:
        return None
    client_chain = class_chain(index, *client_ref, imports, classes, audit)
    if not client_chain or not constructor_bindings_inert(client_chain, index, imports):
        return None

    transfer = _find_constructor_transfer(
        fact, candidate_chain, client_chain, index, imports, classes, audit, integrity
    )
    if transfer is None:
        return None
    ctor_call, factory, ctor, assignment, param, factory_path, ctor_path = transfer
    sink_owner = scope_class(call, index, sink_path)
    if not _inherits_transfer(
        sink_path,
        sink_owner,
        client_ref,
        ctor_path,
        ctor,
        index,
        imports,
        classes,
        audit,
    ):
        return None
    sink_function = _enclosing_function(call, index, sink_path)
    field = _assignment_field(assignment)
    if not instance_receiver(call, sink_function, sink_owner, index, sink_path):
        return None
    if sink_function is None or not _function_alias(
        expression, sink_function, field, call.lineno
    ):
        return None
    from .credential_role_transfer_hops import build_hops

    return build_hops(
        fact,
        index,
        client_path,
        client_expr,
        client_attr,
        ctor_call,
        factory,
        ctor,
        assignment,
        call,
        param,
        factory_path,
        ctor_path,
        sink_path,
    )


def _inherits_transfer(
    path, owner, origin, ctor_path, ctor, index, imports, classes, audit
):
    if owner is None:
        return False
    chain = class_chain(index, path, owner.name, imports, classes, audit)
    selected = class_chain(index, *origin, imports, classes, audit)
    if not chain or not selected:
        return False
    descendant = origin in {(p, name) for p, name, _ in chain}
    ancestor = (path, owner.name) in {(p, name) for p, name, _ in selected}
    active_chain = chain if descendant else selected
    return bool(
        (descendant or ancestor)
        and effective_method(active_chain, "__init__") == (ctor_path, ctor)
    )


def _find_constructor_transfer(
    fact, chain, client_chain, index, imports, classes, audit, integrity
):
    factory_row = effective_method(chain, "get_client")
    ctor_row = effective_method(client_chain, "__init__")
    if factory_row is None or ctor_row is None:
        return None
    factory_path, factory = factory_row
    ctor_path, ctor = ctor_row
    candidates = []
    for call in (node for node in ast.walk(factory) if isinstance(node, ast.Call)):
        func = call.func
        if not isinstance(func, ast.Attribute) or func.attr != "client_class":
            continue
        if not isinstance(func.value, ast.Name) or func.value.id != "self":
            continue
        if not direct_factory_call(call, factory, index, factory_path):
            continue
        matching = [
            arg
            for arg in call.args
            if matches_fact(fact, factory_path, arg, index, imports, classes, audit)
        ]
        if len(matching) != 1:
            continue
        try:
            bound = integrity.bind_source_call(
                call, ctor, ast.Name("_bound_self", ast.Load()), apply_defaults=False
            )
        except (TypeError, ValueError):
            continue
        param = next(
            (name for name, value in bound.items() if value is matching[0]), None
        )
        if param is None:
            continue
        assignments = [
            node
            for node in ctor.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Attribute)
            and isinstance(node.targets[0].value, ast.Name)
            and node.targets[0].value.id == "self"
            and isinstance(node.value, ast.Name)
            and node.value.id == param
        ]
        assignments = [
            node
            for node in assignments
            if exact_parameter_field(ctor, node, param, index, ctor_path)
        ]
        if len(assignments) == 1:
            candidates.append(
                (call, factory, ctor, assignments[0], param, factory_path, ctor_path)
            )
    return candidates[0] if len(candidates) == 1 else None


def _assignment_field(node):
    target = node.targets[0]
    return target.attr if isinstance(target, ast.Attribute) else None


def _enclosing_function(node, index, path):
    current = node
    while current is not None:
        current = index.parents[path].get(id(current))
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
    return None
