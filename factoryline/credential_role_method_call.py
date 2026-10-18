"""Trace one parameter through exact source-bound self-method calls."""

import ast

from .credential_role_method_return import verified_instance_receiver


def trace_call(flow, expression, function, path, seen, depth, bindings=None):
    from .semantic_credential_sensor import _provider_identity_uncertain

    from .credential_role_method_contracts import cast_value
    from .credential_role_strategy_default import setting_default

    casted = cast_value(expression, path, flow.aliases)
    if casted is not None:
        from .review_integrity import _security_flow_bindings

        lexical, _ = _security_flow_bindings(expression, flow.aliases[path])
        if _provider_identity_uncertain(
            flow.index.snapshots[path], lexical, roots=("typing",)
        ):
            casted = None
    if casted is not None:
        found = flow.trace(casted, function, path, seen, depth + 1, bindings)
        return flow._prepend("typing_cast_value", path, expression, found)
    fallback = setting_default(expression, flow.chain, flow.index, flow.classes)
    if fallback:
        value, contracts = fallback
        found = flow.trace(value, function, path, seen, depth + 1, bindings)
        for source_path, node, role in reversed(contracts):
            found = flow._prepend(role, source_path, node, found)
        return flow._prepend("declared_default_argument", path, value, found)
    return flow._return_call(expression, function, path, seen, depth, bindings)


def trace_return(
    flow,
    row,
    expression,
    row_path,
    function,
    caller,
    caller_path,
    seen,
    depth,
    caller_bindings=None,
    callee_bindings=None,
):
    from .credential_role_class_binding import scope_class
    from .credential_role_method_return import format_receiver, returned_parameter

    returned = row.value
    parameter_name, aliases = returned_parameter(function, returned)
    if parameter_name is not None:
        owner = scope_class(expression, flow.index, caller_path)
        if owner is None or not verified_instance_receiver(
            expression,
            caller,
            owner,
            flow.index,
            caller_path,
            bool(flow.decorator_proofs.get(caller.name)),
        ):
            return None
        try:
            bound = _bound_arguments(flow, expression, function)
        except (TypeError, ValueError):
            return None
        actual = bound.get(parameter_name)
        found = (
            flow.trace(actual, caller, caller_path, seen, depth + 1, caller_bindings)
            if actual is not None
            else None
        )
        found = flow._prepend("method_argument_binding", caller_path, actual, found)
        parameter = _parameter_node(function, parameter_name)
        found = flow._prepend("bound_method_parameter", row_path, parameter, found)
        for assignment in reversed(aliases):
            found = flow._prepend("unique_local_alias", row_path, assignment, found)
        return found
    receiver = format_receiver(returned)
    if receiver and ("{" in flow.fact._literal or "}" in flow.fact._literal):
        return None
    found = (
        flow.trace(receiver, function, row_path, seen, depth + 1, callee_bindings)
        if receiver
        else flow.trace(returned, function, row_path, seen, depth + 1, callee_bindings)
    )
    return (
        flow._prepend("declared_string_format_input", row_path, returned, found)
        if receiver
        else found
    )


def _bound_arguments(flow, call, function):
    return flow.integrity.bind_source_call(
        call, function, ast.Name("_receiver", ast.Load()), apply_defaults=False
    )


def _callee_bindings(flow, call, function, caller, caller_path, caller_bindings):
    try:
        actuals = _bound_arguments(flow, call, function)
    except (TypeError, ValueError):
        return None
    if actuals is None:
        return None
    return {
        name: (actual, caller, caller_path, caller_bindings)
        for name, actual in actuals.items()
        if name != "self"
    }


def call_argument(flow, name, function, seen, depth):
    for path, caller, call in _candidate_calls(flow, function):
        choice = ("caller", id(call))
        try:
            bound = flow.integrity.bind_source_call(
                call,
                function,
                ast.Name("_receiver", ast.Load()),
                apply_defaults=False,
            )
        except (TypeError, ValueError):
            continue
        actual = bound.get(name)
        if actual is None:
            continue
        found = flow.trace(actual, caller, path, seen, depth + 1)
        if found:
            flow.branch_choices.append(choice)
            for proof_path, proof_function in flow.decorator_proofs.get(
                caller.name, ()
            ):
                found = flow._prepend(
                    "verified_return_preserving_decorator",
                    proof_path,
                    proof_function,
                    found,
                )
            found = flow._prepend("method_argument_binding", path, actual, found)
            target_path = next(
                (
                    method_path
                    for method_path, method, _ in flow.methods.values()
                    if method is function
                ),
                path,
            )
            return flow._prepend(
                "bound_method_parameter",
                target_path,
                _parameter_node(function, name),
                found,
            )
    return None


def _candidate_calls(flow, function):
    for path, caller, owner in flow.methods.values():
        if not flow.index.validate(path):
            continue
        for call in (node for node in ast.walk(caller) if isinstance(node, ast.Call)):
            target = call.func
            if ("caller", id(call)) in flow.blocked_choices:
                continue
            if not isinstance(target, ast.Attribute) or target.attr != function.name:
                continue
            if not isinstance(target.value, ast.Name) or target.value.id != "self":
                continue
            if verified_instance_receiver(
                call,
                caller,
                owner,
                flow.index,
                path,
                bool(flow.decorator_proofs.get(caller.name)),
            ):
                yield path, caller, call


def _parameter_node(function, name):
    return next(
        (
            argument
            for argument in (
                *function.args.posonlyargs,
                *function.args.args,
                *function.args.kwonlyargs,
            )
            if argument.arg == name
        ),
        function,
    )
