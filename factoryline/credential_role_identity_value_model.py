"""Conservative source projections and writes for tracked identity roots."""

import ast

from .credential_role_identity_effect_types import _Value

_UNKNOWN_KEY = object()


def identity_value(node, aliases):
    """Project names, attributes, and literal containers without evaluation."""
    if isinstance(node, ast.Constant):
        return _Value(inert_kind="scalar")
    if isinstance(node, ast.Name):
        return aliases.get(node.id, _Value())
    if isinstance(node, ast.Attribute):
        return _attribute_value(node, aliases)
    if isinstance(node, (ast.List, ast.Tuple, ast.Dict)):
        return _container_value(node, aliases)
    if isinstance(node, ast.Subscript):
        base = identity_value(node.value, aliases)
        key = node.slice.value if isinstance(node.slice, ast.Constant) else None
        return dict(base.items).get(key, _Value(unknown=contains_tracked(base)))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "__class__" and contains_tracked(
            identity_value(node.func.value, aliases)
        ):
            return _Value(unknown=True)
    return _unknown_expression(node, aliases)


def _unknown_expression(node, aliases):
    roots = set()
    if isinstance(node, ast.expr):
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                roots.update(tracked_roots(aliases.get(child.id, _Value())))
    return _Value(roots=frozenset(roots), unknown=bool(roots))


def _container_value(node, aliases):
    if isinstance(node, (ast.List, ast.Tuple, ast.Dict)):
        pairs = (
            zip(node.keys, node.values)
            if isinstance(node, ast.Dict)
            else enumerate(node.elts)
        )
        items, unknown = [], False
        for key, item in pairs:
            value = identity_value(item, aliases)
            if isinstance(node, ast.Dict) and not isinstance(key, ast.Constant):
                key_value = (
                    identity_value(key, aliases)
                    if isinstance(key, ast.expr)
                    else _Value()
                )
                if contains_tracked(value) or contains_tracked(key_value):
                    unknown = True
                    items.append(
                        (
                            _UNKNOWN_KEY,
                            _Value(items=(("key", key_value), ("value", value))),
                        )
                    )
            else:
                items.append(
                    (key.value if isinstance(key, ast.Constant) else key, value)
                )
        return _Value(
            items=tuple(items),
            unknown=unknown,
            inert_kind=_inert_container(node, items),
        )
    return _Value()


def contains_tracked(value):
    return bool(value.roots or value.class_roots or value.unknown or value.items)


def tracked_roots(value):
    roots = set(value.roots | value.class_roots)
    for _, item in value.items:
        roots.update(tracked_roots(item))
    return roots


def call_has_unknown_value(call, aliases):
    args = [*call.args, *(item.value for item in call.keywords)]
    if isinstance(call.func, ast.Attribute):
        args.append(call.func.value)
    return any(identity_value(arg, aliases).unknown for arg in args)


def call_argument_roots(call, aliases):
    args = [*call.args, *(item.value for item in call.keywords)]
    return set().union(*(tracked_roots(identity_value(arg, aliases)) for arg in args))


def call_tracked_roots(call, aliases):
    roots = call_argument_roots(call, aliases)
    if isinstance(call.func, ast.Attribute):
        roots.update(tracked_roots(identity_value(call.func.value, aliases)))
    elif isinstance(call.func, ast.Call):
        roots.update(identity_value(call.func, aliases).class_roots)
    return roots


def maps_each_actual_once(actuals, arguments):
    expressions = tuple(arguments.values())
    return all(isinstance(expr, ast.expr) for expr in expressions) and sorted(
        map(id, expressions)
    ) == sorted(map(id, actuals))


def assignment_target(node):
    if isinstance(node, ast.Assign):
        return node.targets[0] if len(node.targets) == 1 else None
    return getattr(node, "target", None)


def implicit_protocol_roots(node, aliases):
    expressions = []
    if isinstance(node, (ast.For, ast.AsyncFor)):
        expressions.append(node.iter)
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        expressions.extend(item.context_expr for item in node.items)
    elif isinstance(node, ast.Compare):
        expressions.extend([node.left, *node.comparators])
    elif isinstance(node, (ast.IfExp, ast.If, ast.While, ast.Assert)):
        expressions.append(node.test)
    elif isinstance(node, ast.BinOp):
        expressions.extend([node.left, node.right])
    elif isinstance(node, ast.UnaryOp):
        expressions.append(node.operand)
    elif isinstance(node, ast.BoolOp):
        expressions.extend(node.values)
    elif isinstance(node, ast.Await):
        expressions.append(node.value)
    elif isinstance(node, ast.comprehension):
        expressions.append(node.iter)
    return set().union(
        *(tracked_roots(identity_value(expr, aliases)) for expr in expressions)
    )


def super_reference(node):
    return (
        isinstance(node, ast.Name)
        and node.id == "super"
        and isinstance(node.ctx, ast.Load)
    )


def tracks_receiver(function, aliases):
    params = [*function.args.posonlyargs, *function.args.args]
    return bool(params and params[0].arg in aliases)


def record_implicit_effects(node, function, aliases, effects):
    if tracks_receiver(function, aliases) and super_reference(node):
        effects.unknowns.add("super uses implicit or reflective receiver")
    if implicit_protocol_roots(node, aliases):
        effects.unknowns.add("implicit special-method dispatch on tracked root")
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Attribute):
        if identity_value(node.value, aliases).unknown:
            effects.unknowns.add("bare tracked attribute read may invoke a descriptor")


def nested_capture_roots(function, path, aliases, index):
    captured, tracked = set(), set(aliases)
    scopes = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
    for node in ast.walk(function):
        if node is function or not isinstance(node, scopes):
            continue
        parent = index.parents[path].get(id(node))
        while parent is not None and parent is not function:
            parent = index.parents[path].get(id(parent))
        if parent is not function:
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in tracked:
                captured.update(tracked_roots(aliases[child.id]))
    return captured


def record_write(target, value, aliases, effects):
    if isinstance(target, ast.Attribute):
        base = identity_value(target.value, aliases)
        if base.roots:
            if any((root, target.attr) in aliases for root in base.roots):
                effects.unknowns.add("projected field identity overwritten")
            if target.attr == "__class__":
                effects.class_writes.update(base.roots)
            else:
                effects.field_writes.update(
                    f"{root}.{target.attr}" for root in base.roots
                )
            effects.escapes.update(tracked_roots(value))
            if value.unknown:
                effects.unknowns.add("field stores unresolved tracked value")
        else:
            effects.escapes.update(tracked_roots(value))
            if contains_tracked(identity_value(target, aliases)):
                effects.unknowns.add("write through tracked value")
    elif isinstance(target, ast.Subscript):
        base = identity_value(target.value, aliases)
        if base.roots or contains_tracked(base) or base.inert_kind in {"dict", "list"}:
            effects.unknowns.add("write through tracked container")
        effects.escapes.update(tracked_roots(value))


def record_escape(node, aliases, effects, reason):
    value = identity_value(node, aliases)
    effects.escapes.update(tracked_roots(value))
    if value.unknown:
        effects.unknowns.add(reason + " contains unresolved tracked value")


def _inert_container(node, items):
    if isinstance(node, ast.Dict) and not all(
        isinstance(key, ast.Constant) for key in node.keys
    ):
        return None
    return (
        type(node).__name__.lower()
        if all(value.inert_kind is not None for _, value in items)
        else None
    )


def _attribute_value(node, aliases):
    base = identity_value(node.value, aliases)
    if node.attr == "__class__" and base.roots:
        return _Value(class_roots=base.roots)
    if len(base.roots) == 1 and not base.unknown and not base.class_roots:
        projected = aliases.get((next(iter(base.roots)), node.attr))
        if projected is not None:
            return projected
    return _Value(unknown=bool(base.roots or base.class_roots or base.unknown))
