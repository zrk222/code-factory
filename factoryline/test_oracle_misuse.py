"""Bounded, source-local recognizers for concrete ineffective test oracles."""

from __future__ import annotations

import ast


def _exception_names():
    return (
        "BaseException",
        "Exception",
        "RuntimeError",
        "AssertionError",
        "ValueError",
        "TypeError",
    )


def _static_expression(node: ast.AST) -> bool:
    dynamic = (
        ast.Name,
        ast.Call,
        ast.Await,
        ast.Yield,
        ast.YieldFrom,
        ast.Attribute,
        ast.Subscript,
        ast.NamedExpr,
        ast.Lambda,
    )
    return not any(isinstance(child, dynamic) for child in ast.walk(node))


def always_truthy_assertion_reason(node: ast.AST, constant_truth) -> str | None:
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)) and any(
        not isinstance(item, ast.Starred) for item in node.elts
    ):
        return (
            "nonempty container assertion is always truthy after successful evaluation"
        )
    if isinstance(node, ast.Dict) and any(key is not None for key in node.keys):
        return "nonempty mapping assertion is always truthy after successful evaluation"
    if _static_expression(node) and constant_truth(node, {}) is True:
        return "literal assertion is statically truthy and checks no expected behavior"
    return None


def discarded_comparison_reason(statement: ast.AST) -> str | None:
    if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Compare):
        return (
            "comparison result is discarded instead of being asserted "
            "against an expectation"
        )
    return None


def retain_local_oracle_diagnostics(weak):
    prefixes = (
        "nonempty container assertion",
        "nonempty mapping assertion",
        "literal assertion is statically truthy",
        "comparison result is discarded",
        "local command callback with assertions is never invoked",
    )
    return [(child, reason) for child, reason in weak if reason.startswith(prefixes)]


def weak_assertion_reason(node, aliases, universal_type_check, mock_argument_oracle):
    reason = always_truthy_assertion_reason(node, _constant_truth_value)
    if reason:
        return reason
    if isinstance(node, ast.Call):
        if universal_type_check(node):
            return "universal object type check does not verify the expected behavior"
        from .review_integrity import weak_assertion_call_reason

        return weak_assertion_call_reason(node, aliases)
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        if isinstance(node.ops[0], (ast.Eq, ast.Is)) and len(node.comparators) == 1:
            left, right = node.left, node.comparators[0]
            if (
                any(isinstance(value, ast.Call) for value in ast.walk(left))
                and any(isinstance(value, ast.Call) for value in ast.walk(right))
                and ast.dump(left) == ast.dump(right)
            ):
                return (
                    "repeated invocation compares a result to itself instead of "
                    "an independent expected value"
                )
        if isinstance(node.ops[0], ast.IsNot) and any(
            isinstance(value, ast.Constant) and value.value is None
            for value in (node.left, *node.comparators)
        ):
            return "non-null assertion does not verify the expected behavior"
        if any(
            isinstance(value, ast.Attribute) and value.attr in {"called", "call_count"}
            for operand in (node.left, *node.comparators)
            for value in ast.walk(operand)
        ):
            return "mock invocation state does not verify its result or arguments"
    if getattr(node, "attr", None) in {"called", "call_count"} or mock_argument_oracle(
        node, aliases, uncalled=True
    ):
        return "mock invocation state does not verify its result or arguments"
    return None


def _constant_truth_value(node: ast.expr, _known: dict) -> bool | None:
    from .review_audits import _constant_truth_value as constant_truth

    return constant_truth(node, {})


def _inert_literal_call(node, literal_calls):
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and not node.args
        and not node.keywords
        and node.func.id in (literal_calls or {})
    ):
        return True, literal_calls[node.func.id]
    return None


def _static_inert_literal(node):
    if sum(1 for _ in ast.walk(node)) > 128 or not _static_expression(node):
        return False, None
    try:
        return True, ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return False, None


def _inert_literal(node, known=None, literal_calls=None):
    if node is None:
        return True, None
    if isinstance(node, ast.Name):
        return (True, known[node.id]) if node.id in (known or {}) else (False, None)
    if isinstance(node, ast.BinOp):
        return _inert_integer_arithmetic(node, known, literal_calls)
    if isinstance(node, ast.BoolOp):
        for part in node.values:
            closed, value = _inert_literal(part, known, literal_calls)
            if not closed or bool(value) == isinstance(node.op, ast.Or):
                return closed, value
        return True, value
    if isinstance(node, ast.IfExp):
        closed, value = _inert_literal(node.test, known, literal_calls)
        return (
            _inert_literal(node.body if value else node.orelse, known, literal_calls)
            if closed
            else (False, None)
        )
    if (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.Eq)
    ):
        left, right = (
            _inert_literal(part, known, literal_calls)
            for part in (node.left, node.comparators[0])
        )
        return (True, left[1] == right[1]) if left[0] and right[0] else (False, None)
    call_value = _inert_literal_call(node, literal_calls)
    if call_value is not None:
        return call_value
    return _static_inert_literal(node)


def _inert_integer_arithmetic(node, known, literal_calls):
    if not isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod)):
        return False, None
    left_ok, left = _inert_literal(node.left, known, literal_calls)
    right_ok, right = _inert_literal(node.right, known, literal_calls)
    if not (left_ok and right_ok and type(left) is int and type(right) is int):
        return False, None
    if max(left.bit_length(), right.bit_length()) > 128:
        return False, None
    if isinstance(node.op, (ast.FloorDiv, ast.Mod)) and right == 0:
        return False, None
    value = _inert_integer_operation(node.op, left, right)
    return (True, value) if value.bit_length() <= 128 else (False, None)


def _inert_integer_operation(operation, left, right):
    if isinstance(operation, ast.Add):
        return left + right
    if isinstance(operation, ast.Sub):
        return left - right
    if isinstance(operation, ast.Mult):
        return left * right
    if isinstance(operation, ast.FloorDiv):
        return left // right
    return left % right


def _inert_definition(node):
    args = node.args
    annotations = [
        arg.annotation for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)
    ]
    annotations.extend(arg.annotation for arg in (args.vararg, args.kwarg) if arg)
    return (
        not node.decorator_list
        and not getattr(node, "type_params", ())
        and all(
            _inert_literal(value)[0]
            for value in (*args.defaults, *args.kw_defaults, *annotations, node.returns)
        )
    )


def _builtins_completion_context():
    names = {name: f"builtins.{name}" for name in _exception_names()}
    bases = {
        "builtins.BaseException": None,
        "builtins.Exception": "builtins.BaseException",
    }
    bases.update(
        {name: "builtins.Exception" for name in names.values() if name not in bases}
    )
    return names, bases


def _stored_names(module):
    return {
        n.id
        for n in ast.walk(module)
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))
    }


def _module_bindings(module):
    definitions, imports = {}, {}
    for item in module.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            definitions[item.name] = definitions.get(item.name, 0) + 1
        if isinstance(item, ast.ImportFrom):
            for alias in item.names:
                if alias.name == "*":
                    for name in _exception_names():
                        definitions[name] = definitions.get(name, 0) + 1
                    continue
                target = f"{item.module}.{alias.name}"
                imports.setdefault(alias.asname or alias.name, []).append(target)
        elif isinstance(item, ast.Import):
            for alias in item.names:
                imports.setdefault(
                    alias.asname or alias.name.split(".", 1)[0], []
                ).append(None)
    return definitions, imports


def _module_provider_aliases(module, test, module_name, attrs):
    definitions, imports = _module_bindings(module)
    parents = {
        child: parent
        for parent in ast.walk(module)
        for child in ast.iter_child_nodes(parent)
    }
    test_nodes = {id(child) for child in ast.walk(test)}
    stores = _stored_names(module)
    aliases = {}
    for item in module.body:
        if not isinstance(item, ast.Import):
            continue
        for alias in item.names:
            if alias.name.startswith(f"{module_name}."):
                return None
            if alias.name != module_name:
                continue
            bound = alias.asname or alias.name.split(".", 1)[0]
            if (
                bound in stores
                or definitions.get(bound)
                or imports.get(bound) != [None]
            ):
                return None
            refs = [
                node
                for node in ast.walk(module)
                if isinstance(node, ast.Name) and node.id == bound
            ]
            for ref in refs:
                attr = parents.get(ref)
                outer = parents.get(attr)
                safe = (
                    id(ref) in test_nodes
                    and isinstance(attr, ast.Attribute)
                    and attr.value is ref
                    and attr.attr in attrs
                    and isinstance(outer, ast.Call)
                    and outer.func is attr
                )
                if module_name == "builtins" and isinstance(attr, ast.Attribute):
                    safe = (
                        attr.value is ref
                        and attr.attr in attrs
                        and (
                            (
                                id(ref) in test_nodes
                                and isinstance(outer, ast.Call)
                                and outer.func is attr
                            )
                            or (
                                id(ref) in test_nodes
                                and isinstance(outer, ast.Raise)
                                and outer.exc is attr
                            )
                            or (
                                id(ref) in test_nodes
                                and isinstance(outer, ast.ExceptHandler)
                                and outer.type is attr
                            )
                            or (isinstance(outer, ast.ClassDef) and attr in outer.bases)
                        )
                    )
                if not safe:
                    return None
            aliases[bound] = module_name
    return aliases


def _imported_provider_names_closed(module, test, provider, allowed):
    parents = {
        child: parent
        for parent in ast.walk(module)
        for child in ast.iter_child_nodes(parent)
    }
    test_nodes = {id(child) for child in ast.walk(test)}
    stores = _stored_names(module)
    definitions, imports = _module_bindings(module)
    for item in module.body:
        if not isinstance(item, ast.ImportFrom) or item.module != provider:
            continue
        for alias in item.names:
            if alias.name == "*" or alias.name not in allowed:
                return False
            bound = alias.asname or alias.name
            if (
                bound in stores
                or definitions.get(bound)
                or len(imports.get(bound, ())) != 1
            ):
                return False
            refs = [
                node
                for node in ast.walk(module)
                if isinstance(node, ast.Name) and node.id == bound
            ]
            for ref in refs:
                parent = parents.get(ref)
                in_test = id(ref) in test_nodes
                if provider == "contextlib":
                    safe = (
                        in_test and isinstance(parent, ast.Call) and parent.func is ref
                    )
                else:
                    safe = in_test and (
                        (isinstance(parent, ast.Call) and parent.func is ref)
                        or (isinstance(parent, ast.Raise) and parent.exc is ref)
                        or (
                            isinstance(parent, ast.ExceptHandler) and parent.type is ref
                        )
                    )
                if not safe:
                    return False
    return True


def _completion_import_names(module, names, stores, providers):
    definitions, imports = _module_bindings(module)
    for name in set(names) & (stores | set(definitions) | set(imports)):
        names.pop(name, None)
    for name, targets in imports.items():
        if name in stores or name in definitions or len(targets) != 1:
            continue
        target = targets[0]
        if target in {
            "builtins.BaseException",
            "builtins.Exception",
            "builtins.RuntimeError",
            "builtins.AssertionError",
            "builtins.ValueError",
            "builtins.TypeError",
            "contextlib.nullcontext",
            "contextlib.suppress",
        } and providers.get(target.split(".", 1)[0], False):
            names[name] = target
    return names


def _simple_exception_classes(module, names, bases, stores, test):
    definitions, imports = _module_bindings(module)
    test_nodes = {id(child) for child in ast.walk(test)}
    for item in module.body:
        if (
            not isinstance(item, ast.ClassDef)
            or item.name in stores
            or definitions.get(item.name) != 1
            or item.name in imports
        ):
            continue
        if item.name in _exception_names():
            names.pop(item.name, None)
            continue
        if (
            item.decorator_list
            or item.keywords
            or getattr(item, "type_params", ())
            or len(item.bases) != 1
        ):
            continue
        base = (
            names.get(item.bases[0].id) if isinstance(item.bases[0], ast.Name) else None
        )
        body = item.body[1:] if item.body and _docstring(item.body[0]) else item.body
        refs = [
            n for n in ast.walk(module) if isinstance(n, ast.Name) and n.id == item.name
        ]
        if (
            base in bases
            and len(body) == 1
            and isinstance(body[0], ast.Pass)
            and all(id(n) in test_nodes for n in refs)
        ):
            identity = f"local.{item.name}"
            names[item.name], bases[identity] = identity, base


def _module_pass_helpers(module, stores, test):
    definitions, imports = _module_bindings(module)
    parents = {
        child: parent
        for parent in ast.walk(module)
        for child in ast.iter_child_nodes(parent)
    }
    test_nodes = {id(child) for child in ast.walk(test)}
    helpers = {}
    for item in module.body:
        if (
            not isinstance(item, ast.FunctionDef)
            or item.name in stores
            or definitions.get(item.name) != 1
            or item.name in imports
        ):
            continue
        args = item.args
        if (
            item.decorator_list
            or getattr(item, "type_params", ())
            or item.returns is not None
            or item.type_comment
        ):
            continue
        if any(
            (
                args.posonlyargs,
                args.args,
                args.kwonlyargs,
                args.vararg,
                args.kwarg,
                args.defaults,
                args.kw_defaults,
            )
        ):
            continue
        if len(item.body) != 1 or not isinstance(item.body[0], ast.Pass):
            continue
        refs = [
            n for n in ast.walk(module) if isinstance(n, ast.Name) and n.id == item.name
        ]
        if refs and all(
            id(n) in test_nodes
            and isinstance(parents.get(n), ast.Call)
            and parents[n].func is n
            for n in refs
        ):
            helpers[item.name] = item
    return helpers


def _local_literal_returns(test):
    nodes = tuple(ast.walk(test))
    if len(nodes) > 512:
        return {}
    parents = {
        child: parent for parent in nodes for child in ast.iter_child_nodes(parent)
    }
    definitions = [
        node
        for node in nodes
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    stores = {
        node.id
        for node in nodes
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
    }
    arguments = {node.arg for node in nodes if isinstance(node, ast.arg)}
    imports = set()
    for node in nodes:
        if isinstance(node, ast.Import):
            imports.update(
                alias.asname or alias.name.split(".", 1)[0] for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom):
            imports.update(
                alias.asname or alias.name for alias in node.names if alias.name != "*"
            )
            if any(alias.name == "*" for alias in node.names):
                return {}
    candidates = [
        node
        for node in definitions
        if isinstance(node, ast.FunctionDef) and parents.get(node) is test
    ]
    results = {}
    for function in candidates:
        name = function.name
        same_name = [node for node in definitions if node.name == name]
        if (
            len(same_name) != 1
            or name in stores
            or name in arguments
            or name in imports
            or function.decorator_list
            or getattr(function, "type_params", ())
            or function.returns is not None
            or function.type_comment
            or function.args.posonlyargs
            or function.args.args
            or function.args.vararg
            or function.args.kwonlyargs
            or function.args.kwarg
            or function.args.defaults
            or function.args.kw_defaults
            or len(function.body) != 1
            or not isinstance(function.body[0], ast.Return)
            or not isinstance(function.body[0].value, ast.Constant)
            or type(function.body[0].value.value)
            not in (str, bytes, int, bool, type(None))
        ):
            continue
        references = [
            node for node in nodes if isinstance(node, ast.Name) and node.id == name
        ]
        if not references or any(
            not isinstance(parents.get(node), ast.Call)
            or parents[node].func is not node
            for node in references
        ):
            continue
        results[name] = (function, function.body[0].value.value)
    return results


def _completion_context(test):
    names, bases = _builtins_completion_context()
    module = getattr(test, "_oracle_module", None)
    if not isinstance(module, ast.Module):
        return {
            "names": {},
            "bases": {},
            "helpers": {},
            "modules": {},
            "literal_functions": {},
            "literal_calls": {},
            "active_helpers": (),
        }
    stores = _stored_names(module)
    module_aliases = {
        "builtins": _module_provider_aliases(
            module, test, "builtins", set(_exception_names())
        ),
        "contextlib": _module_provider_aliases(
            module, test, "contextlib", {"nullcontext", "suppress"}
        ),
    }
    providers = {
        provider: module_aliases[provider] is not None
        and _imported_provider_names_closed(module, test, provider, allowed)
        for provider, allowed in (
            ("builtins", set(_exception_names())),
            ("contextlib", {"nullcontext", "suppress"}),
        )
    }
    providers["builtins"] = providers["builtins"] and not any(
        isinstance(n, ast.Name) and n.id == "__builtins__" for n in ast.walk(module)
    )
    if not providers["builtins"]:
        names, bases = {}, {}
    names = _completion_import_names(module, names, stores, providers)
    _simple_exception_classes(module, names, bases, stores, test)
    return {
        "names": names,
        "bases": bases,
        "helpers": _module_pass_helpers(module, stores, test),
        "literal_functions": _local_literal_returns(test),
        "literal_calls": {},
        "active_helpers": (),
        "modules": (
            {
                **(module_aliases["builtins"] if providers["builtins"] else {}),
                **(module_aliases["contextlib"] if providers["contextlib"] else {}),
            }
        ),
    }


def _completion_name(node, context, known):
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id not in known
    ):
        provider = context.get("modules", {}).get(node.value.id)
        if provider == "contextlib" and node.attr in {"nullcontext", "suppress"}:
            return f"contextlib.{node.attr}"
        if provider == "builtins" and f"builtins.{node.attr}" in context["bases"]:
            return f"builtins.{node.attr}"
    return (
        context["names"].get(node.id)
        if isinstance(node, ast.Name) and node.id not in known
        else None
    )


def _completion_catches(raised, caught, bases):
    if isinstance(caught, tuple):
        return any(_completion_catches(raised, item, bases) for item in caught)
    while raised is not None:
        if raised == caught:
            return True
        raised = bases.get(raised)
    return False


def _docstring(statement):
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )


def _local_bindings(test):
    bound = set()
    for node in ast.walk(test):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, ast.alias) and node.name != "*":
            bound.add(node.asname or node.name.split(".", 1)[0])
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            bound.update(node.names)
    return bound


def _helper_alias(stmt, helpers):
    return (
        isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
        and stmt.targets[0].id != "__builtins__"
        and isinstance(stmt.value, ast.Name)
        and stmt.value.id in helpers
    )


def _callback_helper(function, call, helpers):
    if (
        not isinstance(function, ast.FunctionDef)
        or call.keywords
        or len(call.args) != 1
        or not isinstance(call.args[0], ast.Name)
        or len(function.body) != 1
        or not isinstance(function.body[0], ast.Expr)
        or not isinstance(function.body[0].value, ast.Call)
    ):
        return None
    callback = helpers.get(call.args[0].id)
    if not isinstance(callback, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    if _function_needs_arguments(callback):
        return None
    invoke = function.body[0].value
    if invoke.args or invoke.keywords:
        return None
    parameters = (*function.args.posonlyargs, *function.args.args)
    direct_parameter_call = (
        len(parameters) == 1
        and function.args.vararg is None
        and not function.args.kwonlyargs
        and function.args.kwarg is None
        and not function.args.defaults
        and not function.args.kw_defaults
        and isinstance(invoke.func, ast.Name)
        and invoke.func.id == parameters[0].arg
    )
    first_vararg_call = (
        not parameters
        and function.args.vararg is not None
        and not function.args.kwonlyargs
        and function.args.kwarg is None
        and not function.args.defaults
        and not function.args.kw_defaults
        and isinstance(invoke.func, ast.Subscript)
        and isinstance(invoke.func.value, ast.Name)
        and invoke.func.value.id == function.args.vararg.arg
        and isinstance(invoke.func.slice, ast.Constant)
        and type(invoke.func.slice.value) is int
        and invoke.func.slice.value == 0
    )
    return callback if direct_parameter_call or first_vararg_call else None


def _run_inert_helper(helper, context, helpers):
    if isinstance(helper, ast.AsyncFunctionDef):
        return "NORMAL", None
    active = context.get("active_helpers", ())
    identity = id(helper)
    if identity in active or len(active) >= 8 or _function_needs_arguments(helper):
        return "UNKNOWN", None
    nested_helpers = dict(helpers)
    nested = {
        **context,
        "active_helpers": (*active, identity),
        "helpers": nested_helpers,
        "names": dict(context.get("names", {})),
        "modules": dict(context.get("modules", {})),
        "literal_calls": dict(context.get("literal_calls", {})),
    }
    for name in _local_bindings(helper):
        for key in ("helpers", "names", "modules", "literal_calls"):
            nested[key].pop(name, None)
    result = _inert_suite(helper.body, nested, helpers=nested_helpers)
    return ("NORMAL", None) if result[0] == "RETURN" else result


def _inert_expression(node, known, helpers, context):
    if not isinstance(node, ast.Call):
        return (
            ("NORMAL", None)
            if _inert_literal(node, known, context.get("literal_calls"))[0]
            else ("UNKNOWN", None)
        )
    if (
        isinstance(node.func, ast.Name)
        and node.func.id in helpers
        and node.func.id not in known
        and not node.keywords
    ):
        helper = helpers[node.func.id]
        if not node.args and not _function_needs_arguments(helper):
            return _run_inert_helper(helper, context, helpers)
        callback = _callback_helper(helper, node, helpers)
        if callback is not None:
            return _run_inert_helper(callback, context, helpers)
    identity = _completion_name(node.func, context, known)
    args = (*node.args, *(kw.value for kw in node.keywords))
    return (
        ("NORMAL", None)
        if identity in context["bases"]
        and not node.keywords
        and all(
            _inert_literal(arg, known, context.get("literal_calls"))[0] for arg in args
        )
        else ("UNKNOWN", None)
    )


def _function_needs_arguments(function):
    args = function.args
    return len((*args.posonlyargs, *args.args)) > len(args.defaults) or any(
        default is None for default in args.kw_defaults
    )


def _simple_completion(stmt, known, helpers, context):
    unknown = ("UNKNOWN", None)
    if isinstance(stmt, ast.Pass):
        return "NORMAL", None
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return ("NORMAL", None) if _inert_definition(stmt) else unknown
    if isinstance(stmt, ast.Expr):
        return _inert_expression(stmt.value, known, helpers, context)
    if isinstance(stmt, ast.Assert):
        closed, value = _inert_literal(stmt.test, known, context.get("literal_calls"))
        if closed and not value and stmt.msg is not None:
            message = _inert_expression(stmt.msg, known, helpers, context)
            if message[0] != "NORMAL":
                return message
        return (
            ("NORMAL", None)
            if closed and value
            else ("RAISE", "builtins.AssertionError")
            if closed
            else unknown
        )
    if isinstance(stmt, ast.Return):
        return (
            ("RETURN", None)
            if _inert_literal(stmt.value, known, context.get("literal_calls"))[0]
            else unknown
        )
    return unknown


def _raise_completion(stmt, known, context):
    if stmt.cause is not None:
        return "UNKNOWN", None
    expr = stmt.exc.func if isinstance(stmt.exc, ast.Call) else stmt.exc
    identity = _completion_name(expr, context, known)
    args = stmt.exc.args if isinstance(stmt.exc, ast.Call) else ()
    closed = identity in context["bases"] and all(
        _inert_literal(arg, known, context.get("literal_calls"))[0] for arg in args
    )
    if isinstance(stmt.exc, ast.Call):
        closed = closed and not stmt.exc.keywords
    return ("RAISE", identity) if closed else ("UNKNOWN", None)


def _assignment_completion(stmt, known, context):
    targets = getattr(stmt, "targets", ()) or (stmt.target,)
    closed = all(isinstance(target, ast.Name) for target in targets)
    closed = (
        closed and _inert_literal(stmt.value, known, context.get("literal_calls"))[0]
    )
    return ("NORMAL", None) if closed else ("UNKNOWN", None)


def _conditional_completion(stmt, known, helpers, context):
    closed, value = _inert_literal(stmt.test, known, context.get("literal_calls"))
    if not closed:
        return "UNKNOWN", None
    return _inert_suite(stmt.body if value else stmt.orelse, context, known, helpers)


def _loop_completion(stmt, known, helpers, context):
    expr = stmt.iter if isinstance(stmt, ast.For) else stmt.test
    closed, value = _inert_literal(expr, known, context.get("literal_calls"))
    empty_type = isinstance(stmt, ast.While) or type(value) in (
        tuple,
        list,
        dict,
        set,
        str,
        bytes,
    )
    if not closed or not empty_type or value:
        return "UNKNOWN", None
    return _inert_suite(stmt.orelse, context, known, helpers)


def _handler_identity(handler, known, context):
    if handler.type is None:
        return None
    caught = (
        tuple(_completion_name(n, context, known) for n in handler.type.elts)
        if isinstance(handler.type, ast.Tuple)
        else _completion_name(handler.type, context, known)
    )
    names = caught if isinstance(caught, tuple) else (caught,)
    return caught if all(name in context["bases"] for name in names) else None


def _try_completion(stmt, known, helpers, context):
    result = _inert_suite(stmt.body, context, known, helpers)
    if result[0] == "NORMAL":
        result = _inert_suite(stmt.orelse, context, {}, context["helpers"])
    elif result[0] == "RAISE":
        for handler in stmt.handlers:
            caught = _handler_identity(handler, {}, context)
            if handler.name is not None or caught is None:
                return "UNKNOWN", None
            if _completion_catches(result[1], caught, context["bases"]):
                result = _inert_suite(handler.body, context, {}, context["helpers"])
                break
    if stmt.finalbody:
        final = _inert_suite(stmt.finalbody, context, {}, context["helpers"])
        if result[0] == "UNKNOWN" or final[0] == "UNKNOWN":
            return "UNKNOWN", None
        if final[0] != "NORMAL":
            result = final
    return result


def _with_completion(stmt, known, helpers, context):
    if len(stmt.items) != 1 or stmt.items[0].optional_vars is not None:
        return "UNKNOWN", None
    item = stmt.items[0].context_expr
    if not isinstance(item, ast.Call) or item.keywords:
        return "UNKNOWN", None
    manager = _completion_name(item.func, context, known)
    if manager == "contextlib.nullcontext" and not item.args:
        return _inert_suite(stmt.body, context, known, helpers)
    if manager != "contextlib.suppress" or not item.args:
        return "UNKNOWN", None
    caught = tuple(_completion_name(n, context, known) for n in item.args)
    if any(name not in context["bases"] for name in caught):
        return "UNKNOWN", None
    result = _inert_suite(stmt.body, context, known, helpers)
    if result[0] == "RAISE" and any(
        _completion_catches(result[1], name, context["bases"]) for name in caught
    ):
        return "NORMAL", None
    return result


def _inert_statement(stmt, known, helpers, context):
    if isinstance(
        stmt,
        (
            ast.Pass,
            ast.FunctionDef,
            ast.AsyncFunctionDef,
            ast.Expr,
            ast.Assert,
            ast.Return,
        ),
    ):
        return _simple_completion(stmt, known, helpers, context)
    if isinstance(stmt, ast.Raise):
        return _raise_completion(stmt, known, context)
    if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
        if _helper_alias(stmt, helpers):
            return "NORMAL", None
        return _assignment_completion(stmt, known, context)
    if isinstance(stmt, ast.If):
        return _conditional_completion(stmt, known, helpers, context)
    if isinstance(stmt, (ast.For, ast.While)):
        return _loop_completion(stmt, known, helpers, context)
    if isinstance(stmt, ast.Try):
        return _try_completion(stmt, known, helpers, context)
    if isinstance(stmt, ast.With):
        return _with_completion(stmt, known, helpers, context)
    return "UNKNOWN", None


def _track_inert_definition(stmt, known, helpers, context):
    if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return
    helpers[stmt.name] = stmt
    known.pop(stmt.name, None)
    literal = context.get("literal_functions", {}).get(stmt.name)
    if literal is not None and literal[0] is stmt:
        context["literal_calls"][stmt.name] = literal[1]


def _track_inert_assignment(stmt, known, helpers, context):
    if not isinstance(stmt, (ast.Assign, ast.AnnAssign)) or stmt.value is None:
        return
    for target in getattr(stmt, "targets", ()) or (stmt.target,):
        if not isinstance(target, ast.Name):
            continue
        if _helper_alias(stmt, helpers):
            helpers[target.id] = helpers[stmt.value.id]
            known.pop(target.id, None)
        else:
            helpers.pop(target.id, None)
            closed, value = _inert_literal(stmt.value, known, context["literal_calls"])
            if closed:
                known[target.id] = value
            else:
                known.pop(target.id, None)
        context["literal_calls"].pop(target.id, None)


def _reset_inert_branch(stmt, known, context, literal_calls_before):
    if not isinstance(stmt, (ast.If, ast.For, ast.While, ast.Try, ast.With)):
        return None
    known.clear()
    context["literal_calls"] = literal_calls_before
    return dict(context["helpers"])


def _inert_suite(statements, context, known=None, helpers=None):
    context = {
        **context,
        "literal_calls": dict(context.get("literal_calls", {})),
    }
    known, helpers = (
        dict(known or {}),
        dict(context["helpers"] if helpers is None else helpers),
    )
    for stmt in statements:
        literal_calls_before = dict(context["literal_calls"])
        result = _inert_statement(stmt, known, helpers, context)
        if result[0] != "NORMAL":
            return result
        _track_inert_definition(stmt, known, helpers, context)
        _track_inert_assignment(stmt, known, helpers, context)
        reset_helpers = _reset_inert_branch(stmt, known, context, literal_calls_before)
        if reset_helpers is not None:
            helpers = reset_helpers
    return "NORMAL", None


def inert_test_completion(node):
    if (
        not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        or sum(1 for _ in ast.walk(node)) > 512
    ):
        return "UNKNOWN", None
    context = _completion_context(node)
    for name in _local_bindings(node):
        context["names"].pop(name, None)
        context["helpers"].pop(name, None)
        context["modules"].pop(name, None)
        context["literal_calls"].pop(name, None)
    for arg in (
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
        node.args.vararg,
        node.args.kwarg,
    ):
        if arg is not None:
            context["names"].pop(arg.arg, None)
    return _inert_suite(node.body, context)


def inert_test_body(node):
    return inert_test_completion(node)[0] in {"NORMAL", "RETURN"}


INERT_BODY_HELPERS = (
    _exception_names,
    _inert_literal,
    _inert_integer_arithmetic,
    _inert_integer_operation,
    _inert_definition,
    _completion_context,
    _completion_name,
    _completion_catches,
    _docstring,
    _local_bindings,
    _builtins_completion_context,
    _stored_names,
    _module_bindings,
    _module_provider_aliases,
    _imported_provider_names_closed,
    _completion_import_names,
    _simple_exception_classes,
    _module_pass_helpers,
    _inert_literal_call,
    _static_inert_literal,
    _local_literal_returns,
    _helper_alias,
    _callback_helper,
    _run_inert_helper,
    _track_inert_definition,
    _track_inert_assignment,
    _reset_inert_branch,
    _inert_expression,
    _function_needs_arguments,
    _simple_completion,
    _raise_completion,
    _assignment_completion,
    _conditional_completion,
    _loop_completion,
    _handler_identity,
    _try_completion,
    _with_completion,
    _inert_statement,
    _inert_suite,
    inert_test_completion,
    inert_test_body,
)
