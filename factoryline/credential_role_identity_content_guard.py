"""Strict consumer checks for opaque identity-call results."""

import ast

from .credential_role_identity_value_model import (
    _has_unknown_content,
    call_argument_roots,
    identity_value,
    tracked_roots,
)


def record_opaque_call(call, aliases, involved, out, *, strict_calls=False):
    """Record tracked roots as escaping when an opaque call receives them; otherwise mark the call as unresolved."""
    if call_argument_roots(call, aliases, strict_calls=strict_calls):
        out.escapes.update(involved)
    else:
        out.unknowns.add("unresolved method call on tracked object")


def strict_read_effects(node, aliases, parents, out):
    """Unknown names and properties may hide behavior without a Call node."""
    if not isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)) or not isinstance(
        node.ctx, ast.Load
    ):
        return
    parent = parents.get(id(node))
    if isinstance(parent, ast.Call) and parent.func is node:
        return
    value = identity_value(node, aliases, strict_calls=True)
    if value.unknown or not (
        value.roots
        or value.class_roots
        or value.inert_kind
        or value.items
        or value.content_unknown
    ):
        out.unknowns.add("unresolved value in strict identity summary")


def strict_protocol_effects(node, aliases, parents, out):
    """Reject opaque content at consumers unless the operation is inert."""
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)) and not isinstance(
        node.ctx, ast.Load
    ):
        return
    if (
        isinstance(node, ast.expr)
        and _has_unknown_content(identity_value(node, aliases, strict_calls=True))
        and not _passive_content_use(node, parents)
    ):
        out.unknowns.add("unresolved consumer of strict identity content")
    operands = _protocol_operands(node)
    if operands and not all(
        identity_value(value, aliases, strict_calls=True).inert_kind
        for value in operands
    ):
        out.unknowns.add("unresolved protocol operand in strict identity summary")


def _passive_content_use(node, parents):
    parent = parents.get(id(node))
    if isinstance(parent, ast.Call) and parent.func is node:
        return True
    if isinstance(parent, (ast.List, ast.Tuple)) and node in parent.elts:
        return True
    if isinstance(parent, ast.Dict) and node in parent.values:
        return all(isinstance(key, ast.Constant) for key in parent.keys)
    if isinstance(parent, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
        return getattr(parent, "value", None) is node
    if isinstance(parent, ast.Expr) and parent.value is node:
        return True
    compare = node if isinstance(node, ast.Compare) else parent
    return isinstance(compare, ast.Compare) and all(
        isinstance(op, (ast.Is, ast.IsNot)) for op in compare.ops
    )


def _protocol_operands(node):
    if isinstance(node, ast.AugAssign):
        return [node.target, node.value]
    if isinstance(node, ast.BinOp):
        return [node.left, node.right]
    if isinstance(node, ast.UnaryOp):
        return [node.operand]
    if isinstance(node, ast.Compare):
        if all(isinstance(op, (ast.Is, ast.IsNot)) for op in node.ops):
            return []
        return [node.left, *node.comparators]
    if isinstance(node, ast.BoolOp):
        return node.values
    if isinstance(node, (ast.If, ast.While, ast.IfExp, ast.Assert)):
        if isinstance(node.test, ast.Compare) and all(
            isinstance(op, (ast.Is, ast.IsNot)) for op in node.test.ops
        ):
            return []
        return [node.test]
    if isinstance(node, ast.FormattedValue):
        return [node.value]
    return []


def implicit_protocol_roots(node, aliases, *, strict_calls=False):
    """Collect tracked roots used by iteration, context management, comparisons, operators, awaits, and comprehension iteration."""
    expressions = []
    if isinstance(node, (ast.For, ast.AsyncFor)):
        expressions.append(node.iter)
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        expressions.extend(item.context_expr for item in node.items)
    elif isinstance(
        node,
        (
            ast.Compare,
            ast.IfExp,
            ast.If,
            ast.While,
            ast.Assert,
            ast.BinOp,
            ast.UnaryOp,
            ast.BoolOp,
        ),
    ):
        expressions.extend(_protocol_operands(node))
    elif isinstance(node, ast.Await):
        expressions.append(node.value)
    elif isinstance(node, ast.comprehension):
        expressions.append(node.iter)
    return set().union(
        *(
            tracked_roots(identity_value(expr, aliases, strict_calls=strict_calls))
            for expr in expressions
        )
    )


def super_reference(node):
    """Recognize a loaded AST name spelled super, without inferring its runtime binding."""
    return (
        isinstance(node, ast.Name)
        and node.id == "super"
        and isinstance(node.ctx, ast.Load)
    )


def tracks_receiver(function, aliases):
    """Check whether the function's first positional receiver is present in the tracked alias map."""
    params = [*function.args.posonlyargs, *function.args.args]
    return bool(params and params[0].arg in aliases)


def record_implicit_effects(node, function, aliases, effects, *, strict_calls=False):
    """Mark unknown effects for implicit super dispatch, tracked special-method operations, or unresolved descriptor reads."""
    if tracks_receiver(function, aliases) and super_reference(node):
        effects.unknowns.add("super uses implicit or reflective receiver")
    if implicit_protocol_roots(node, aliases, strict_calls=strict_calls):
        effects.unknowns.add("implicit special-method dispatch on tracked root")
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Attribute):
        if identity_value(node.value, aliases, strict_calls=strict_calls).unknown:
            effects.unknowns.add("bare tracked attribute read may invoke a descriptor")
