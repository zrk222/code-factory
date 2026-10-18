"""Exact expression spans for declared constructor transfers."""

import ast

from .credential_role_constructor_flow import _hop


def build_hops(
    fact,
    index,
    client_path,
    client_expr,
    client_attr,
    ctor_call,
    factory,
    ctor,
    assignment,
    sink,
    param,
    factory_path,
    ctor_path,
    sink_path,
):
    fact_path = index.root / fact.path
    fact_node = next(
        (
            node
            for node in ast.walk(index.snapshots[fact_path])
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            and getattr(node, "lineno", 0) == fact.line
            and getattr(node, "value", None) is not None
            and isinstance(node.value, ast.Constant)
            and node.value.value == fact._literal
        ),
        None,
    )
    param_node = next((node for node in ctor.args.args if node.arg == param), None)
    value_argument = next(
        (
            arg
            for arg in ctor_call.args
            if isinstance(arg, ast.Attribute) and arg.attr == fact.member
        ),
        None,
    )
    nodes = [
        (fact_path, fact_node, "declared_literal"),
        (client_path, client_expr, "client_class_selection"),
        (factory_path, value_argument, "constructor_argument"),
        (ctor_path, param_node, "constructor_parameter"),
        (ctor_path, assignment.targets[0], "constructor_field_binding"),
        (sink_path, sink, "canonical_http_url_consumer"),
    ]
    hops = [_hop(index, path, node, role) for path, node, role in nodes]
    return hops if all(hops) else None
