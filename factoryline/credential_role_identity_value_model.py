"""Conservative source projections and writes for tracked identity roots."""

import ast

from .credential_role_identity_effect_types import (
    _has_unknown_content as _has_unknown_content,
)
from .credential_role_identity_effect_types import (
    _Value,
)
from .credential_role_identity_effect_types import (
    contains_tracked as contains_tracked,
)
from .credential_role_identity_effect_types import (
    maps_each_actual_once as maps_each_actual_once,
)
from .credential_role_identity_effect_types import (
    tracked_roots as tracked_roots,
)

_UNKNOWN_KEY = object()


def identity_value(node, aliases, *, strict_calls=False):
    """Project names, attributes, and literal containers without evaluation."""
    if isinstance(node, ast.Constant):
        return _Value(inert_kind="scalar")
    if isinstance(node, ast.Name):
        return aliases.get(node.id, _Value())
    if isinstance(node, ast.Attribute):
        return _attribute_value(node, aliases, strict_calls=strict_calls)
    if isinstance(node, (ast.List, ast.Tuple, ast.Dict)):
        return _container_value(node, aliases, strict_calls=strict_calls)
    if isinstance(node, ast.Subscript):
        return _subscript_value(node, aliases, strict_calls=strict_calls)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "__class__":
            if contains_tracked(
                identity_value(node.func.value, aliases, strict_calls=strict_calls)
            ):
                return _Value(unknown=True)
        if strict_calls:
            return _Value(content_unknown=True)
    return _unknown_expression(node, aliases, strict_calls=strict_calls)


def _subscript_value(node, aliases, *, strict_calls=False):
    base = identity_value(node.value, aliases, strict_calls=strict_calls)
    key = node.slice.value if isinstance(node.slice, ast.Constant) else None
    if strict_calls and base.content_unknown:
        return _Value(unknown=True)
    return dict(base.items).get(key, _Value(unknown=contains_tracked(base)))


def _unknown_expression(node, aliases, *, strict_calls=False):
    roots = set()
    if isinstance(node, ast.expr):
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                roots.update(tracked_roots(aliases.get(child.id, _Value())))
    return _Value(roots=frozenset(roots), unknown=bool(roots))


def _container_value(node, aliases, *, strict_calls=False):
    if isinstance(node, (ast.List, ast.Tuple, ast.Dict)):
        pairs = (
            zip(node.keys, node.values)
            if isinstance(node, ast.Dict)
            else enumerate(node.elts)
        )
        items, unknown = [], False
        for key, item in pairs:
            value = identity_value(item, aliases, strict_calls=strict_calls)
            if isinstance(node, ast.Dict) and not isinstance(key, ast.Constant):
                key_value = (
                    identity_value(key, aliases, strict_calls=strict_calls)
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


def call_has_unknown_value(call, aliases, *, strict_calls=False):
    args = [*call.args, *(item.value for item in call.keywords)]
    if isinstance(call.func, ast.Attribute):
        args.append(call.func.value)
    return any(
        _has_unknown_content(identity_value(arg, aliases, strict_calls=strict_calls))
        for arg in args
    )


def call_argument_roots(call, aliases, *, strict_calls=False):
    args = [*call.args, *(item.value for item in call.keywords)]
    return set().union(
        *(
            tracked_roots(identity_value(arg, aliases, strict_calls=strict_calls))
            for arg in args
        )
    )


def call_tracked_roots(call, aliases, *, strict_calls=False):
    roots = call_argument_roots(call, aliases, strict_calls=strict_calls)
    if isinstance(call.func, ast.Attribute):
        roots.update(
            tracked_roots(
                identity_value(call.func.value, aliases, strict_calls=strict_calls)
            )
        )
    elif isinstance(call.func, ast.Call):
        roots.update(
            identity_value(call.func, aliases, strict_calls=strict_calls).class_roots
        )
    return roots


def assignment_target(node):
    if isinstance(node, ast.Assign):
        return node.targets[0] if len(node.targets) == 1 else None
    return getattr(node, "target", None)


def nested_capture_roots(
    function, path, aliases, index, *, strict_calls=False, effects=None
):
    from .credential_role_identity_call_model import _definition_effects_unknown

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
        if strict_calls and _definition_effects_unknown(node):
            effects.unknowns.add("unmodeled nested definition-time effects")
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in tracked:
                captured.update(tracked_roots(aliases[child.id]))
                if strict_calls and _has_unknown_content(aliases[child.id]):
                    effects.unknowns.add(
                        "nested scope captures unresolved tracked value"
                    )
    return captured


def record_write(target, value, aliases, effects, *, strict_calls=False):
    if isinstance(target, ast.Attribute):
        return _record_attribute_write(
            target, value, aliases, effects, strict_calls=strict_calls
        )
    elif isinstance(target, ast.Subscript):
        base = identity_value(target.value, aliases, strict_calls=strict_calls)
        if base.roots or contains_tracked(base) or base.inert_kind in {"dict", "list"}:
            effects.unknowns.add("write through tracked container")
        if strict_calls and _has_unknown_content(value):
            effects.unknowns.add("field stores unresolved tracked value")
        effects.escapes.update(tracked_roots(value))


def record_escape(node, aliases, effects, reason, *, strict_calls=False):
    value = identity_value(node, aliases, strict_calls=strict_calls)
    effects.escapes.update(tracked_roots(value))
    if value.unknown or (strict_calls and _has_unknown_content(value)):
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


def _attribute_value(node, aliases, *, strict_calls=False):
    base = identity_value(node.value, aliases, strict_calls=strict_calls)
    if node.attr == "__class__" and base.roots:
        return _Value(class_roots=base.roots)
    if len(base.roots) == 1 and not base.unknown and not base.class_roots:
        projected = aliases.get((next(iter(base.roots)), node.attr))
        if projected is not None:
            return projected
    if strict_calls and base.roots and not base.class_roots and not base.unknown:
        return _Value(content_unknown=True)
    if strict_calls and base.content_unknown:
        return _Value(unknown=True)
    return _Value(unknown=bool(base.roots or base.class_roots or base.unknown))


def _record_attribute_write(target, value, aliases, effects, *, strict_calls=False):
    base = identity_value(target.value, aliases, strict_calls=strict_calls)
    if base.roots:
        if any((root, target.attr) in aliases for root in base.roots):
            effects.unknowns.add("projected field identity overwritten")
        if target.attr == "__class__":
            effects.class_writes.update(base.roots)
        else:
            effects.field_writes.update(f"{root}.{target.attr}" for root in base.roots)
        effects.escapes.update(tracked_roots(value))
        if value.unknown:
            effects.unknowns.add("field stores unresolved tracked value")
    else:
        effects.escapes.update(tracked_roots(value))
        if strict_calls and _has_unknown_content(value):
            effects.unknowns.add("field stores unresolved tracked value")
        if contains_tracked(identity_value(target, aliases, strict_calls=strict_calls)):
            effects.unknowns.add("write through tracked value")
