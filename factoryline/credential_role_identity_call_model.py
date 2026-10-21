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
    """Normalize field identities only for bounded mappings with valid owner/member keys and source-backed or literal roots."""
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


def literal_dict_update(call, aliases, *, strict_calls=False):
    """Recognize a one-argument dict update only when both receiver and input are inert dictionaries."""
    if not (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "update"
        and len(call.args) == 1
        and not call.keywords
    ):
        return False
    receiver, values = (
        identity_value(call.func.value, aliases, strict_calls=strict_calls),
        identity_value(call.args[0], aliases, strict_calls=strict_calls),
    )
    return receiver.inert_kind == values.inert_kind == "dict"


def mapped_call_values(call, aliases, involved, resolved, out, *, strict_calls=False):
    """Bind each call actual to exactly one resolved formal parameter; record uncertainty and return no mapping on ambiguity."""
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
        value = identity_value(expr, aliases, strict_calls=strict_calls)
        roots = tracked_roots(value)
        if (
            not isinstance(expr, ast.expr)
            or value.unknown
            or (strict_calls and value.content_unknown)
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
    return _with_inert_defaults(
        resolved.function, mapped, out, strict_calls=strict_calls
    )


def _with_inert_defaults(function, mapped, out, *, strict_calls=False):
    args = function.args
    positional = [*args.posonlyargs, *args.args]
    defaults = dict(
        zip((arg.arg for arg in positional[-len(args.defaults) :]), args.defaults)
    )
    defaults.update(
        (arg.arg, value) for arg, value in zip(args.kwonlyargs, args.kw_defaults)
    )
    for parameter in [*positional, *args.kwonlyargs]:
        if parameter.arg in mapped:
            continue
        default = defaults.get(parameter.arg)
        if not _immutable_default(default):
            out.unknowns.add(
                "missing formal or omitted default is not an immutable literal"
            )
            return None
        mapped[parameter.arg] = identity_value(default, {}, strict_calls=strict_calls)
    return mapped


def _immutable_default(node, depth=0):
    if depth >= 8:
        return False
    if isinstance(node, ast.Constant):
        return type(node.value) in (
            type(None),
            bool,
            int,
            float,
            complex,
            str,
            bytes,
            type(Ellipsis),
        )
    return (
        isinstance(node, ast.Tuple)
        and len(node.elts) <= 64
        and all(_immutable_default(item, depth + 1) for item in node.elts)
    )


def summarize_identity_call(
    call, path, index, roots, *, resolve_call, field_roots=None
):
    """Summarize one captured call under caller-proved current heap/dispatch facts.

    Allocation, ownership, descriptors, prior mutations, and binding stability
    are separate caller obligations. This is not fixture admission or execution.
    """
    from .credential_role_identity_effect_types import _Effects
    from .credential_role_identity_effects import _Analyzer

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


def captured_function_valid(function, path, index):
    """Confirm a function node belongs to a validated captured source snapshot."""
    return bool(
        isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
        and index.validate(path)
        and any(node is function for node in ast.walk(index.snapshots[path]))
    )


def own_function_nodes(function, path, index):
    """Return nodes owned by the function itself while excluding nested function, lambda, and class scopes."""
    parents, scopes, result = (
        index.parents[path],
        (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef),
        [],
    )
    for node in ast.walk(function):
        parent, nested = parents.get(id(node)), False
        while parent is not None and parent is not function:
            if isinstance(parent, scopes):
                nested = True
                break
            parent = parents.get(id(parent))
        if not nested:
            result.append(node)
    return result


def exported_names(nodes):
    """Names stored outside the owning function's already-separated scope."""
    return {
        name
        for node in nodes
        if isinstance(node, (ast.Global, ast.Nonlocal))
        for name in node.names
    }


def _definition_effects_unknown(node):
    if isinstance(node, ast.ClassDef):
        return True
    args = node.args
    params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    params.extend(arg for arg in (args.vararg, args.kwarg) if arg)
    return bool(
        getattr(node, "decorator_list", [])
        or any(not _immutable_default(value) for value in args.defaults)
        or any(
            value is not None and not _immutable_default(value)
            for value in args.kw_defaults
        )
        or getattr(node, "returns", None)
        or getattr(node, "type_params", ())
        or any(arg.annotation for arg in params)
    )
