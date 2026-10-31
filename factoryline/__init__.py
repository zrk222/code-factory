__version__ = "0.49.5"

import json as _json


def canonical_json_bytes(value: object) -> bytes:
    """Strict UTF-8 receipt encoding shared by byte-equivalent producers."""
    return _json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_json_compat_bytes(value: object) -> bytes:
    """Preserve existing UTF-8 receipt bytes, including legacy non-finite values."""
    return _json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=True
    ).encode("utf-8")


def canonical_ascii_json_compat_bytes(value: object) -> bytes:
    """Preserve existing ASCII-escaped receipt bytes and non-finite handling."""
    return _json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=True
    ).encode("utf-8")


def _source_call_signature(function):
    """Describe captured Python parameters without evaluating source tokens."""
    import ast
    from inspect import Parameter, Signature

    if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        raise ValueError("SOURCE_SIGNATURE_UNKNOWN")
    args = function.args
    positional = [*args.posonlyargs, *args.args]
    defaults = dict(
        zip(
            (n.arg for n in positional),
            [Parameter.empty] * (len(positional) - len(args.defaults)) + args.defaults,
        )
    )
    defaults.update(
        (n.arg, d) for n, d in zip(args.kwonlyargs, args.kw_defaults) if d is not None
    )

    def parameter(node, kind):
        return Parameter(
            node.arg,
            kind,
            default=defaults.get(node.arg, Parameter.empty),
            annotation=node.annotation or Parameter.empty,
        )

    parameters = [
        parameter(n, kind)
        for kind, nodes in (
            (Parameter.POSITIONAL_ONLY, args.posonlyargs),
            (Parameter.POSITIONAL_OR_KEYWORD, args.args),
            (Parameter.KEYWORD_ONLY, args.kwonlyargs),
        )
        for n in nodes
    ]
    if args.vararg:
        parameters.insert(
            len(positional), parameter(args.vararg, Parameter.VAR_POSITIONAL)
        )
    if args.kwarg:
        parameters.append(parameter(args.kwarg, Parameter.VAR_KEYWORD))
    return Signature(parameters)


def _bind_source_call(
    call, function, receiver=None, previous=None, *, apply_defaults=True
):
    """Associate AST tokens only; this proves neither execution nor safe effects."""
    import ast

    if (
        not isinstance(call, ast.Call)
        or any(isinstance(n, ast.Starred) for n in call.args)
        or any(n.arg is None for n in call.keywords)
    ):
        raise ValueError("SOURCE_ARGUMENT_EXPANSION_UNKNOWN")
    previous = {} if previous is None else previous

    def value(node):
        return previous.get(node.id, node) if isinstance(node, ast.Name) else node

    keywords = {n.arg: value(n.value) for n in call.keywords}
    if len(keywords) != len(call.keywords):
        raise ValueError("SOURCE_ARGUMENT_DUPLICATE_KEYWORD")
    try:
        bound = _source_call_signature(function).bind(
            *([receiver] if receiver is not None else []),
            *(value(n) for n in call.args),
            **keywords,
        )
        if apply_defaults:
            bound.apply_defaults()
        return bound.arguments
    except (TypeError, ValueError) as exc:
        raise ValueError("SOURCE_ARGUMENT_BINDING_UNKNOWN") from exc


def _source_binding_helpers():
    return (_source_call_signature, _bind_source_call)
