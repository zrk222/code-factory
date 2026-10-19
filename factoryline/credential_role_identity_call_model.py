"""Complete argument values and exact literal-field models for identity calls."""

import ast
from collections.abc import Mapping

from .credential_role_identity_effect_types import (
    ResolvedIdentityCall,
    SourceFieldLiteral,
    _Value,
)
from .credential_role_identity_value_model import (
    identity_value,
    maps_each_actual_once,
    tracked_roots,
)


def identity_fields(fields, index):
    if fields is None:
        return {}
    if not isinstance(fields, Mapping) or len(fields) > 64:
        return None
    result = {}
    for key, root in fields.items():
        literal = (
            _source_literal(root, index)
            if isinstance(root, SourceFieldLiteral)
            else None
        )
        if not (
            isinstance(key, tuple)
            and len(key) == 2
            and all(isinstance(item, str) and item for item in key)
            and (literal is not None or isinstance(root, str) and root)
            and key[1].isidentifier()
            and not key[1].startswith("__")
        ):
            return None
        result[key] = (
            literal if literal is not None else _Value(roots=frozenset({root}))
        )
    return result


def _source_literal(root, index):
    if not index.validate(root.path) or id(root.value) not in index.parents[root.path]:
        return None
    value = identity_value(root.value, {})
    return value if value.inert_kind is not None else None


def literal_dict_update(call, aliases):
    if not (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "update"
        and len(call.args) == 1
        and not call.keywords
    ):
        return False
    receiver, values = (
        identity_value(call.func.value, aliases),
        identity_value(call.args[0], aliases),
    )
    return receiver.inert_kind == values.inert_kind == "dict"


def mapped_call_values(call, aliases, involved, resolved, out):
    if any(isinstance(arg, ast.Starred) for arg in call.args) or any(
        keyword.arg is None for keyword in call.keywords
    ):
        out.unknowns.add("expanded call arguments are not an exact binding")
        return None
    if not isinstance(resolved, ResolvedIdentityCall):
        out.unknowns.add("invalid exact call binding")
        return None
    params = {
        arg.arg
        for arg in [
            *resolved.function.args.posonlyargs,
            *resolved.function.args.args,
            *resolved.function.args.kwonlyargs,
        ]
    }
    actuals = [*call.args, *(kw.value for kw in call.keywords)]
    if isinstance(call.func, ast.Attribute):
        actuals.append(call.func.value)
    if not maps_each_actual_once(actuals, resolved.arguments):
        out.unknowns.add("exact call mapping must cover each actual once")
        return None
    mapped = {}
    for formal, expr in resolved.arguments.items():
        if formal not in params or not any(expr is actual for actual in actuals):
            out.unknowns.add("call mapping is not an exact parameter binding")
            return
        value = identity_value(expr, aliases)
        roots = tracked_roots(value)
        if (
            not isinstance(expr, ast.expr)
            or value.unknown
            or len(roots) > 1
            or (value.items and roots)
        ):
            out.unknowns.add("ambiguous exact call root mapping")
            return None
        else:
            mapped[formal] = value
    if set().union(*(tracked_roots(value) for value in mapped.values())) != involved:
        out.unknowns.add("exact call mapping omits a tracked root")
        return None
    return mapped


def strict_read_effects(node, aliases, parents, out):
    """Unknown names/properties may hide implicit behavior despite no Call AST."""
    if not isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)) or not isinstance(
        node.ctx, ast.Load
    ):
        return
    parent = parents.get(id(node))
    if isinstance(parent, ast.Call) and parent.func is node:
        return  # The exact call resolver or literal intrinsic checks this edge.
    value = identity_value(node, aliases)
    if value.unknown or not (
        value.roots or value.class_roots or value.inert_kind or value.items
    ):
        out.unknowns.add("unresolved value in strict identity summary")


def strict_protocol_effects(node, aliases, out):
    operands = []
    if isinstance(node, ast.AugAssign):
        operands = [node.target, node.value]
    elif isinstance(node, ast.BinOp):
        operands = [node.left, node.right]
    elif isinstance(node, ast.UnaryOp):
        operands = [node.operand]
    elif isinstance(node, ast.Compare):
        operands = [node.left, *node.comparators]
    elif isinstance(node, ast.BoolOp):
        operands = node.values
    elif isinstance(node, (ast.If, ast.While, ast.IfExp, ast.Assert)):
        operands = [node.test]
    if any(identity_value(value, aliases).inert_kind is None for value in operands):
        out.unknowns.add("unresolved protocol operand in strict identity summary")


def summarize_identity_call(
    call, path, index, roots, *, resolve_call, field_roots=None
):
    """Summarize one captured call under caller-proved current heap/dispatch facts.

    Allocation, ownership, descriptors, prior mutations, and binding stability
    are separate caller obligations. This is not fixture admission or execution.
    """
    from .credential_role_identity_effects import _Analyzer
    from .credential_role_identity_effect_types import _Effects

    out = _Effects()
    if (
        not index.validate(path)
        or id(call) not in index.parents[path]
        or not isinstance(call, ast.Call)
    ):
        out.unknowns.add("call is not a validated captured expression")
        return out.freeze()
    analyzer = _Analyzer(index, resolve_call, 4, 512, field_roots, True)
    if analyzer.fields is None:
        out.unknowns.add("invalid initial field identity graph")
        return out.freeze()
    aliases = {name: _Value(roots=frozenset({root})) for name, root in roots.items()}
    aliases.update(analyzer.fields)
    analyzer._call(call, path, aliases, 0, frozenset(), out)
    return out.freeze()
