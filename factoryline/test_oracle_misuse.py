"""Bounded, source-local recognizers for concrete ineffective test oracles."""

from __future__ import annotations

import ast

_BUILTIN_RANGE_CALL = object()


def _exception_names():
    return (
        "BaseException",
        "Exception",
        "RuntimeError",
        "AssertionError",
        "ValueError",
        "TypeError",
        "Warning",
        "UserWarning",
        "DeprecationWarning",
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
    """Explain an assertion that is statically always truthy without checking expected behavior, or return None."""
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
    """Explain a discarded comparison expression that never asserts or stores its result."""
    if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Compare):
        return (
            "comparison result is discarded instead of being asserted "
            "against an expectation"
        )
    return None


def retain_local_oracle_diagnostics(weak):
    """Retain only the selected local weak-oracle diagnostics from the broader weak-finding list."""
    prefixes = (
        "nonempty container assertion",
        "nonempty mapping assertion",
        "literal assertion is statically truthy",
        "comparison result is discarded",
        "local command callback with assertions is never invoked",
    )
    return [(child, reason) for child, reason in weak if reason.startswith(prefixes)]


def weak_assertion_reason(node, aliases, universal_type_check, mock_argument_oracle):
    """Explain statically weak assertions, self-comparisons, universal type checks, or delegated weak calls; return None when no weakness is proven."""
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


def _inert_literal_call(node, literal_calls, known):
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        return None
    if node.func.id not in (literal_calls or {}):
        return None
    result = literal_calls[node.func.id]
    if result is _BUILTIN_RANGE_CALL:
        return _inert_range_call(node, known, literal_calls)
    if (
        isinstance(result, tuple)
        and len(result) == 2
        and isinstance(result[0], ast.Lambda)
    ):
        return _inert_lambda_call(node, result, known, literal_calls)
    if not node.args and not node.keywords:
        return True, result
    return None


def _inert_range_call(node, known, literal_calls):
    if not 1 <= len(node.args) <= 3 or node.keywords:
        return None
    if any(isinstance(arg, ast.Starred) for arg in node.args):
        return None
    values = []
    for arg in node.args:
        closed, value = _inert_literal(arg, known, literal_calls)
        if not closed or type(value) is not int or abs(value).bit_length() > 31:
            return None
        values.append(value)
    try:
        value = range(*values)
        if len(value) > 128:
            return None
    except (OverflowError, TypeError, ValueError):
        return None
    return True, value


def _inert_lambda_call(node, summary, known, literal_calls):
    function, value = summary
    parameters = (*function.args.posonlyargs, *function.args.args)
    if len(parameters) != 1 or function.args.vararg or function.args.kwonlyargs:
        return None
    if function.args.kwarg or function.args.defaults or function.args.kw_defaults:
        return None
    if len(node.args) != 1 or node.keywords or isinstance(node.args[0], ast.Starred):
        return None
    closed, _ = _inert_literal(node.args[0], known, literal_calls)
    return (True, list(value)) if closed else None


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
    if isinstance(node, (ast.BoolOp, ast.IfExp)):
        return _inert_boolean_expression(node, known, literal_calls)
    if (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.Eq)
    ):
        return _inert_equality_expression(node, known, literal_calls)
    if isinstance(node, ast.List) and any(
        isinstance(element, ast.Starred) for element in node.elts
    ):
        return _inert_starred_list(node, known, literal_calls)
    call_value = _inert_literal_call(node, literal_calls, known)
    if call_value is not None:
        return call_value
    return _static_inert_literal(node)


def _inert_boolean_expression(node, known, literal_calls):
    if isinstance(node, ast.IfExp):
        closed, value = _inert_literal(node.test, known, literal_calls)
        if not closed:
            return False, None
        return _inert_literal(node.body if value else node.orelse, known, literal_calls)
    for part in node.values:
        closed, value = _inert_literal(part, known, literal_calls)
        if not closed or bool(value) == isinstance(node.op, ast.Or):
            return closed, value
    return True, value


def _inert_equality_expression(node, known, literal_calls):
    left = _inert_literal(node.left, known, literal_calls)
    right = _inert_literal(node.comparators[0], known, literal_calls)
    if left[0] and right[0]:
        return True, left[1] == right[1]
    return False, None


def _inert_starred_list(node, known, literal_calls):
    values = []
    for element in node.elts:
        value_node = element.value if isinstance(element, ast.Starred) else element
        closed, value = _inert_literal(value_node, known, literal_calls)
        if not closed:
            return False, None
        if isinstance(element, ast.Starred):
            if type(value) not in (tuple, list) or len(values) + len(value) > 128:
                return False, None
            values.extend(value)
        else:
            values.append(value)
    return True, values


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
    if isinstance(node, ast.ClassDef):
        return not any(
            (
                node.bases,
                node.keywords,
                node.decorator_list,
                getattr(node, "type_params", ()),
            )
        ) and all(isinstance(stmt, ast.Pass) or _docstring(stmt) for stmt in node.body)
    args = node.args
    annotations = [
        arg.annotation for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)
    ]
    annotations.extend(arg.annotation for arg in (args.vararg, args.kwarg) if arg)
    return (
        not getattr(node, "decorator_list", ())
        and not getattr(node, "type_params", ())
        and all(
            _inert_literal(value)[0]
            for value in (
                *args.defaults,
                *args.kw_defaults,
                *annotations,
                getattr(node, "returns", None),
            )
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
    for name in ("UserWarning", "DeprecationWarning"):
        bases[f"builtins.{name}"] = "builtins.Warning"
    names["range"] = "builtins.range"
    return names, bases


def _stored_names(module):
    stored = {
        n.id
        for n in ast.walk(module)
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))
    }
    for node in ast.walk(module):
        if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
            if node.name:
                stored.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            stored.add(node.rest)
    return stored


def _module_bindings(module):
    definitions, imports = {}, {}
    for item in module.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            definitions[item.name] = definitions.get(item.name, 0) + 1
        if isinstance(item, ast.ImportFrom):
            for alias in item.names:
                if alias.name == "*":
                    exports = _closed_star_exports(module, item)
                    if exports is not None:
                        imports.update(
                            {name: [target] for name, target in exports.items()}
                        )
                        continue
                    for name in {*_exception_names(), "range", *imports}:
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


def _captured_star_module_unambiguous(root, sources, name, selected):
    for path in sources:
        if path == selected:
            continue
        if path.name == name + ".py" or name in path.relative_to(root).parts[:-1]:
            return False
    return True


def _closed_star_import_source(module, statement):
    source = getattr(module, "_security_source_context", None)
    profile = getattr(module, "_security_oracle_context", {})
    if not source or not profile.get("provider_source_inventory_complete"):
        return None
    if statement.level or not (statement.module or "").isidentifier():
        return None
    root, sources = source
    # Admit a captured top-level module only; package initializers need their
    # own effect proof and are not silently treated as this simple case.
    path = root / (statement.module + ".py")
    if path not in sources or not _captured_star_module_unambiguous(
        root, sources, statement.module, path
    ):
        return None
    return sources[path]


def _canonical_star_export(statement):
    if not isinstance(statement, ast.ImportFrom) or statement.level:
        return None
    if statement.module != "contextlib":
        return None
    exports = {}
    for alias in statement.names:
        name = alias.asname or alias.name
        if alias.name != "nullcontext" or name.startswith("_") or name in exports:
            return None
        exports[name] = "contextlib.nullcontext"
    return exports


def _closed_star_exports(module, statement):
    raw = _closed_star_import_source(module, statement)
    if not isinstance(raw, bytes) or not _completion_provider_captured(
        module, "contextlib"
    ):
        return None
    try:
        tree = ast.parse(raw)
    except (SyntaxError, ValueError, UnicodeDecodeError, RecursionError):
        return None
    exports = {}
    for item in tree.body:
        if _docstring(item) or isinstance(item, ast.Pass):
            continue
        selected = _canonical_star_export(item)
        if selected is None or exports.keys() & selected.keys():
            return None
        exports.update(selected)
    return exports


def _provider_transfer_target(statement):
    if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
        return None
    target = statement.targets[0]
    return target if isinstance(target, ast.Name) else None


def _provider_transfer_implicit_binding(node, name):
    if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
        return node.name == name
    if isinstance(node, ast.MatchMapping):
        return node.rest == name
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return name in node.names
    return False


def _provider_transfer_rebound(node, target, statement):
    if _provider_transfer_implicit_binding(node, target.id):
        return True
    if isinstance(node, ast.Name) and node.id == target.id:
        return isinstance(node.ctx, (ast.Store, ast.Del)) and node is not target
    if isinstance(node, ast.arg):
        return node.arg == target.id
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name == target.id
    if isinstance(node, ast.alias):
        bound = node.asname or node.name.split(".", 1)[0]
        return bound == target.id and node.lineno > statement.lineno
    return False


def _provider_transfer_load_closed(node, parents, statement):
    call = parents.get(node)
    owner = parents.get(call)
    return (
        node.lineno > statement.lineno
        and isinstance(call, ast.Call)
        and call.func is node
        and isinstance(owner, ast.withitem)
        and owner.context_expr is call
    )


def _provider_transfer_closed(statement, module):
    target = _provider_transfer_target(statement)
    if target is None:
        return False
    parents = {
        child: node for node in ast.walk(module) for child in ast.iter_child_nodes(node)
    }
    for node in ast.walk(module):
        if _provider_transfer_rebound(node, target, statement):
            return False
        if (
            isinstance(node, ast.Name)
            and node.id == target.id
            and isinstance(node.ctx, ast.Load)
        ):
            if not _provider_transfer_load_closed(node, parents, statement):
                return False
    return True


def _completion_module_imports(module, provider):
    aliases = [
        alias
        for item in module.body
        if isinstance(item, ast.Import)
        for alias in item.names
    ]
    if any(alias.name.startswith(provider + ".") for alias in aliases):
        return None
    return [alias for alias in aliases if alias.name == provider]


def _provider_star_imports_closed(module, bound):
    for item in ast.walk(module):
        if not isinstance(item, ast.ImportFrom):
            continue
        if not any(alias.name == "*" for alias in item.names):
            continue
        exports = _closed_star_exports(module, item)
        if exports is None or bound in exports:
            return False
    return True


def _builtin_provider_reference_closed(outer, attr, in_test):
    if isinstance(outer, ast.ClassDef):
        return attr in outer.bases
    slots = {ast.Call: "func", ast.Raise: "exc", ast.ExceptHandler: "type"}
    return in_test and any(
        isinstance(outer, kind) and getattr(outer, slot) is attr
        for kind, slot in slots.items()
    )


def _provider_reference_transfer_closed(provider, attr, outer, module):
    return (
        provider == "contextlib"
        and attr.attr == "nullcontext"
        and isinstance(outer, ast.Assign)
        and outer.value is attr
        and _provider_transfer_closed(outer, module)
    )


def _provider_reference_closed(ref, parents, test_nodes, provider, attrs, module):
    attr = parents.get(ref)
    if (
        not isinstance(attr, ast.Attribute)
        or attr.value is not ref
        or attr.attr not in attrs
    ):
        return False
    outer = parents.get(attr)
    in_test = id(ref) in test_nodes
    if provider == "builtins":
        return _builtin_provider_reference_closed(outer, attr, in_test)
    direct = in_test and isinstance(outer, ast.Call) and outer.func is attr
    return direct or _provider_reference_transfer_closed(provider, attr, outer, module)


def _module_provider_aliases(module, test, module_name, attrs):
    imported = _completion_module_imports(module, module_name)
    if imported is None:
        return None
    parents = {
        child: parent
        for parent in ast.walk(module)
        for child in ast.iter_child_nodes(parent)
    }
    test_nodes = {id(child) for child in ast.walk(test)}
    aliases = {}
    for alias in imported:
        bound = alias.asname or alias.name
        if _module_binding_conflict(
            module, bound, alias
        ) or not _provider_star_imports_closed(module, bound):
            return None
        refs = [
            node
            for node in ast.walk(module)
            if isinstance(node, ast.Name) and node.id == bound
        ]
        if not all(
            _provider_reference_closed(
                ref, parents, test_nodes, module_name, attrs, module
            )
            for ref in refs
        ):
            return None
        aliases[bound] = module_name
    return aliases


def _imported_provider_names_closed(module, test, provider, allowed):
    if not any(
        isinstance(item, ast.ImportFrom) and item.module == provider
        for item in module.body
    ):
        return True
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
            "builtins.range",
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


def _inert_helper_stub(function):
    body = function.body
    if body and _docstring(body[0]):
        body = body[1:]
    if not body:
        return True
    if len(body) != 1:
        return False
    statement = body[0]
    return (
        isinstance(statement, ast.Pass)
        or isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and statement.value.value is Ellipsis
        or isinstance(statement, ast.Return)
        and (
            statement.value is None
            or isinstance(statement.value, ast.Constant)
            and type(statement.value.value)
            in (str, bytes, int, bool, float, complex, type(None))
        )
    )


def _inert_helper_signature(function):
    if not isinstance(function, ast.FunctionDef):
        return False
    args = function.args
    positional = (*args.posonlyargs, *args.args)
    return (
        isinstance(function, ast.FunctionDef)
        and not function.type_comment
        and _inert_definition(function)
        and len({argument.arg for argument in positional}) == len(positional)
        and not any(
            (
                args.vararg,
                args.kwonlyargs,
                args.kwarg,
                args.defaults,
                args.kw_defaults,
            )
        )
    )


def _inert_helper_call(call, function, known, literal_calls, helpers=None):
    if (
        not _inert_helper_signature(function)
        or not _inert_helper_stub(function)
        or any(isinstance(arg, ast.Starred) for arg in call.args)
        or call.keywords
        or len(call.args) != len((*function.args.posonlyargs, *function.args.args))
    ):
        return False
    helpers = helpers or {}
    return all(
        _inert_literal(arg, known, literal_calls)[0]
        or isinstance(arg, ast.Name)
        and arg.id not in known
        and isinstance(helpers.get(arg.id), (ast.FunctionDef, ast.AsyncFunctionDef))
        and _inert_definition(helpers[arg.id])
        for arg in call.args
    )


def _bound_name_identity_assertion(expression, function, namespace_closed):
    if not namespace_closed or not isinstance(
        function, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        return False
    if (
        not isinstance(expression, ast.Compare)
        or len(expression.ops) != 1
        or not isinstance(expression.ops[0], ast.Is)
        or len(expression.comparators) != 1
    ):
        return False
    left, right = expression.left, expression.comparators[0]
    if (
        not isinstance(left, ast.Name)
        or not isinstance(right, ast.Name)
        or left.id != right.id
    ):
        return False
    args = function.args
    if args.vararg or args.kwarg:
        return False
    parameters = (*args.posonlyargs, *args.args, *args.kwonlyargs)
    names = [argument.arg for argument in parameters]
    if left.id not in names or len(names) != len(set(names)):
        return False
    if any(
        isinstance(node, (ast.Global, ast.Nonlocal)) and left.id in node.names
        for node in ast.walk(function)
    ):
        return False
    references = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Name) and node.id == left.id
    ]
    return (
        len(references) == 2
        and all(isinstance(reference.ctx, ast.Load) for reference in references)
        and {id(reference) for reference in references} == {id(left), id(right)}
    )


def _module_pass_context_closed(module, namespace_closed):
    if not any(
        isinstance(item, ast.FunctionDef) and _inert_helper_stub(item)
        for item in module.body
    ):
        return False
    if namespace_closed is None:
        namespace_closed = _module_namespace_access_closed(module)
    return bool(namespace_closed)


def _inert_coroutine_signature(function):
    if (
        not isinstance(function, ast.AsyncFunctionDef)
        or function.type_comment
        or not _inert_definition(function)
    ):
        return False
    args = function.args
    positional = (*args.posonlyargs, *args.args)
    return len({argument.arg for argument in positional}) == len(
        positional
    ) and not any(
        (
            args.vararg,
            args.kwonlyargs,
            args.kwarg,
            args.defaults,
            args.kw_defaults,
        )
    )


def _coroutine_call_arity_matches(call, function):
    return (
        _inert_coroutine_signature(function)
        and not call.keywords
        and not any(isinstance(argument, ast.Starred) for argument in call.args)
        and len(call.args) == len((*function.args.posonlyargs, *function.args.args))
    )


def _module_helper_kind(function):
    if isinstance(function, ast.FunctionDef):
        if _inert_helper_signature(function) and _inert_helper_stub(function):
            return "stub"
        if _callback_helper_parameter(function) is not None:
            return "callback"
        if _inert_helper_signature(function):
            return "source"
    if _inert_coroutine_signature(function):
        return "coroutine"
    return None


def _module_pass_helpers(
    module, stores, test, namespace_closed=None, *, include_callbacks=False
):
    if not include_callbacks and not _module_pass_context_closed(
        module, namespace_closed
    ):
        return {}
    if namespace_closed is None:
        namespace_closed = _module_namespace_access_closed(module)
    candidates = [
        (item, _module_helper_kind(item))
        for item in module.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    candidates = [
        (item, kind)
        for item, kind in candidates
        if kind is not None and (include_callbacks or kind == "stub")
    ]
    if (
        not namespace_closed
        or not candidates
        or any(
            isinstance(node, ast.ImportFrom)
            and any(alias.name == "*" for alias in node.names)
            for node in ast.walk(module)
        )
    ):
        return {}
    definitions, imports = _module_bindings(module)
    parents = {
        child: parent
        for parent in ast.walk(module)
        for child in ast.iter_child_nodes(parent)
    }
    test_nodes = {id(child) for child in ast.walk(test)}
    references = {}
    for node in ast.walk(module):
        if isinstance(node, ast.Name):
            references.setdefault(node.id, []).append(node)
    helpers = {}
    for item, kind in candidates:
        if (
            item.name in stores
            or _module_binding_conflict(module, item.name, item)
            or definitions.get(item.name) != 1
            or item.name in imports
        ):
            continue
        refs = references.get(item.name, ())
        if kind == "coroutine":
            closed = any(id(node) in test_nodes for node in refs) and all(
                isinstance(parents.get(node), ast.Call)
                and parents[node].func is node
                and _coroutine_call_arity_matches(parents[node], item)
                for node in refs
            )
        else:
            closed = _module_helper_references_closed(
                refs, parents, test_nodes, allow_assignment=kind == "stub"
            )
        if closed:
            helpers[item.name] = item
    return helpers


def _module_helper_references_closed(
    references, parents, test_nodes, *, allow_assignment=False
):
    if not references:
        return False
    for reference in references:
        if id(reference) not in test_nodes:
            return False
        parent = parents.get(reference)
        if isinstance(parent, ast.Call) and parent.func is reference:
            continue
        targets = (
            parent.targets
            if isinstance(parent, ast.Assign)
            else (parent.target,)
            if isinstance(parent, ast.AnnAssign)
            else ()
        )
        if not (
            allow_assignment
            and isinstance(parent, (ast.Assign, ast.AnnAssign))
            and parent.value is reference
            and len(targets) == 1
            and isinstance(targets[0], ast.Name)
        ):
            return False
    return True


def _module_mock_imports(module):
    imported_classes = []
    for node in ast.walk(module):
        if isinstance(node, ast.Import) and any(
            alias.name == "unittest" or alias.name.startswith("unittest.")
            for alias in node.names
        ):
            return ()
        if not isinstance(node, ast.ImportFrom) or not (
            node.module == "unittest" or (node.module or "").startswith("unittest.")
        ):
            continue
        if node not in module.body or node.level or node.module != "unittest.mock":
            return ()
        if any(alias.name not in {"Mock", "AsyncMock"} for alias in node.names):
            return ()
        imported_classes.extend(node.names)

    return imported_classes


def _captured_mock_owner_is_exclusive(module):
    from hashlib import sha256

    context = getattr(module, "_security_oracle_context", {})
    capability_paths = context.get("mock_provider_capability_paths")
    root, sources = module._security_source_context
    if not isinstance(capability_paths, list) or len(capability_paths) != 1:
        return False
    captured = sources.get(root / capability_paths[0])
    if not isinstance(captured, bytes) or sha256(captured).hexdigest() != getattr(
        module, "_oracle_source_sha256", None
    ):
        return False
    return True


def _module_mock_constructors(module, test, namespace_closed):
    if not namespace_closed or any(
        isinstance(node, ast.ImportFrom)
        and any(alias.name == "*" for alias in node.names)
        for node in ast.walk(module)
    ):
        return {}
    definitions, imports = _module_bindings(module)
    stores = _stored_names(module)
    local_bindings = _local_bindings(test)
    parents = {
        child: parent
        for parent in ast.walk(module)
        for child in ast.iter_child_nodes(parent)
    }
    test_nodes = {id(child) for child in ast.walk(test)}
    references = {}
    for node in ast.walk(module):
        if isinstance(node, ast.Name):
            references.setdefault(node.id, []).append(node)
    imported_classes = _module_mock_imports(module)
    if not imported_classes:
        return {}
    from .type_intent_hollow import _captured_unittest_source_closed

    if not _captured_unittest_source_closed(module):
        return {}
    if not _captured_mock_owner_is_exclusive(module):
        return {}
    constructors = {}
    for alias in imported_classes:
        bound = alias.asname or alias.name
        target = f"unittest.mock.{alias.name}"
        if (
            bound in stores
            or bound in local_bindings
            or definitions.get(bound)
            or imports.get(bound) != [target]
            or _module_binding_conflict(module, bound, alias)
        ):
            return {}
        refs = references.get(bound, ())
        if not refs or not all(
            isinstance(node.ctx, ast.Load)
            and id(node) in test_nodes
            and isinstance(parents.get(node), ast.Call)
            and parents[node].func is node
            and not parents[node].args
            and not parents[node].keywords
            for node in refs
        ):
            return {}
        constructors[bound] = alias.name
    return constructors


def _module_binding_conflict(module, name, definition):
    for node in ast.walk(module):
        if node is definition:
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == name:
                return True
        elif isinstance(node, ast.alias):
            bound = node.asname or node.name.split(".", 1)[0]
            if bound == name:
                return True
        elif isinstance(node, ast.ExceptHandler) and node.name == name:
            return True
        elif (isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name == name) or (
            isinstance(node, ast.MatchMapping) and node.rest == name
        ):
            return True
    return False


def _local_literal_returns(test, namespace_closed=None):
    context = _literal_return_context(test, namespace_closed)
    if context is None:
        return {}
    results = {}
    for function in context["candidates"]:
        summary = _literal_return_function_summary(
            function,
            context["definition_counts"],
            context["stores"],
            context["arguments"],
            context["imports"],
            context["references"],
            context["test_nodes"],
            context["parents"],
        )
        if summary is not None:
            results[function.name] = summary
    for statement in test.body:
        summary = _literal_empty_lambda_summary(
            statement,
            context["definitions"],
            context["arguments"],
            context["imports"],
            context["references"],
            context["test_nodes"],
            context["parents"],
        )
        if summary is not None:
            results[statement.targets[0].id] = summary
    return results


def _literal_return_context(test, namespace_closed=None):
    scope_data = _literal_return_scope(test, namespace_closed)
    if scope_data is None:
        return None
    scope, nodes, test_nodes = scope_data
    parents = {
        child: parent for parent in nodes for child in ast.iter_child_nodes(parent)
    }
    definitions = [
        node
        for node in nodes
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    definition_counts = {}
    for node in definitions:
        definition_counts[node.name] = definition_counts.get(node.name, 0) + 1
    references_by_name = {}
    for node in nodes:
        if isinstance(node, ast.Name):
            references_by_name.setdefault(node.id, []).append(node)
    test_call_names = {
        node.func.id
        for node in ast.walk(test)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
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
                return None
    candidates = [
        node
        for node in definitions
        if isinstance(node, ast.FunctionDef)
        and node is not test
        and parents.get(node) in (test, scope)
        and node.name in test_call_names
    ]
    return {
        "candidates": candidates,
        "definitions": definitions,
        "definition_counts": definition_counts,
        "stores": stores,
        "arguments": arguments,
        "imports": imports,
        "references": references_by_name,
        "test_nodes": test_nodes,
        "parents": parents,
    }


def _literal_return_scope(test, namespace_closed=None):
    module = getattr(test, "_oracle_module", None)
    scope = module if isinstance(module, ast.Module) else test
    if namespace_closed is None:
        namespace_closed = _module_namespace_access_closed(scope)
    if not namespace_closed:
        return None
    test_nodes = {id(node) for node in ast.walk(test)}
    if len(test_nodes) > 512:
        return None
    nodes = tuple(ast.walk(scope))
    if len(nodes) > 2048:
        scope = test
        nodes = tuple(ast.walk(test))
    return scope, nodes, test_nodes


def _module_namespace_access_closed(module):
    from .context_efficiency import _module_has_dynamic_capability_access

    nodes = []
    for node in ast.walk(module):
        nodes.append(node)
        if len(nodes) > 2048:
            return False
    return not any(
        isinstance(node, ast.Attribute)
        and node.attr
        in {
            "__builtins__",
            "__closure__",
            "__dict__",
            "__globals__",
            "ag_frame",
            "cr_frame",
            "f_globals",
            "f_locals",
            "func_globals",
            "gi_frame",
        }
        for node in nodes
    ) and not _module_has_dynamic_capability_access(nodes)


def _literal_return_function_summary(
    function,
    definition_counts,
    stores,
    arguments,
    imports,
    references_by_name,
    test_nodes,
    parents,
):
    name = function.name
    if definition_counts.get(name) != 1 or name in stores | arguments | imports:
        return None
    if not _literal_zero_arg_constant_return(function):
        return None
    if not _literal_direct_references_closed(
        references_by_name.get(name, []), test_nodes, parents
    ):
        return None
    return function, function.body[0].value.value


def _literal_zero_arg_constant_return(function):
    if function.decorator_list or getattr(function, "type_params", ()):
        return False
    if function.returns is not None or function.type_comment:
        return False
    args = function.args
    if any(
        (
            args.posonlyargs,
            args.args,
            args.vararg,
            args.kwonlyargs,
            args.kwarg,
            args.defaults,
            args.kw_defaults,
        )
    ):
        return False
    if len(function.body) != 1 or not isinstance(function.body[0], ast.Return):
        return False
    value = function.body[0].value
    return isinstance(value, ast.Constant) and type(value.value) in (
        str,
        bytes,
        int,
        bool,
        type(None),
    )


def _literal_direct_references_closed(references, test_nodes, parents, binding=None):
    if not references:
        return False
    return all(
        node is binding
        or (
            id(node) in test_nodes
            and isinstance(parents.get(node), ast.Call)
            and parents[node].func is node
        )
        for node in references
    )


def _literal_empty_lambda_summary(
    statement,
    definitions,
    arguments,
    imports,
    references_by_name,
    test_nodes,
    parents,
):
    if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
        return None
    target, function = statement.targets[0], statement.value
    if not isinstance(target, ast.Name) or not isinstance(function, ast.Lambda):
        return None
    name = target.id
    stores_for_name = [
        node
        for node in references_by_name.get(name, [])
        if isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    if not _literal_empty_lambda(function):
        return None
    if not _literal_lambda_binding_closed(
        name, target, definitions, stores_for_name, arguments, imports
    ):
        return None
    if not _literal_direct_references_closed(
        references_by_name.get(name, []), test_nodes, parents, binding=target
    ):
        return None
    _, value = _static_inert_literal(function.body)
    return function, value


def _literal_empty_lambda(function):
    args = function.args
    parameters = (*args.posonlyargs, *args.args)
    if len(parameters) != 1 or args.vararg or args.kwonlyargs or args.kwarg:
        return False
    if args.defaults or args.kw_defaults:
        return False
    closed, value = _static_inert_literal(function.body)
    return closed and type(value) is list and not value


def _literal_lambda_binding_closed(
    name, target, definitions, stores, arguments, imports
):
    return (
        not any(node.name == name for node in definitions)
        and len(stores) == 1
        and stores[0] is target
        and name not in arguments
        and name not in imports
    )


def _canonical_completion_import(statement, providers):
    return isinstance(statement, ast.Import) and all(
        providers.get(alias.name, False) for alias in statement.names
    )


def _class_creation_context_closed(module, providers, stores):
    return (
        providers["builtins"]
        and "__name__" not in stores
        and not _module_binding_conflict(module, "__name__", None)
        and not _module_binding_conflict(module, "__builtins__", None)
        and all(
            isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and _inert_definition(item)
            or _docstring(item)
            or isinstance(item, ast.Pass)
            or _canonical_completion_import(item, providers)
            for item in module.body
        )
        and all(
            _canonical_completion_import(item, providers)
            for item in ast.walk(module)
            if isinstance(item, (ast.Import, ast.ImportFrom))
        )
    )


def _completion_provider_captured(module, provider):
    """Keep AST-only provider assumptions separate from native capture proof."""
    if not hasattr(module, "_security_source_context"):
        return True
    source = getattr(module, "_security_source_context", None)
    profile = getattr(module, "_security_oracle_context", {})
    if not source or not profile.get("provider_source_inventory_complete"):
        return False
    root, sources = source
    return not any(
        path.name == provider + ".py" or provider in path.relative_to(root).parts[:-1]
        for path in sources
    )


def _completion_context(test):
    names, bases = _builtins_completion_context()
    module = getattr(test, "_oracle_module", None)
    if not isinstance(module, ast.Module):
        return {
            "names": {},
            "bases": {},
            "helpers": {},
            "modules": {},
            "mock_constructors": {},
            "mock_instances": {},
            "namespace_closed": False,
            "literal_functions": {},
            "literal_calls": {},
            "active_helpers": (),
            "swallowed_function_projections": {},
        }
    namespace_closed = _module_namespace_access_closed(module)
    stores = _stored_names(module)
    module_aliases = {
        "builtins": _module_provider_aliases(
            module, test, "builtins", {*_exception_names(), "range"}
        ),
        "contextlib": _module_provider_aliases(
            module, test, "contextlib", {"nullcontext", "suppress"}
        ),
        "warnings": _module_provider_aliases(
            module, test, "warnings", {"catch_warnings", "simplefilter"}
        ),
    }
    providers = {
        provider: namespace_closed
        and _completion_provider_captured(module, provider)
        and module_aliases[provider] is not None
        and _imported_provider_names_closed(module, test, provider, allowed)
        for provider, allowed in (
            ("builtins", {*_exception_names(), "range"}),
            ("contextlib", {"nullcontext", "suppress"}),
            ("warnings", {"catch_warnings", "simplefilter"}),
        )
    }
    providers["builtins"] = providers["builtins"] and not any(
        isinstance(n, ast.Name) and n.id == "__builtins__" for n in ast.walk(module)
    )
    if namespace_closed:
        if not providers["builtins"]:
            names, bases = {}, {}
        names = _completion_import_names(module, names, stores, providers)
        _simple_exception_classes(module, names, bases, stores, test)
        literal_functions = _local_literal_returns(test, namespace_closed)
        helpers = _module_pass_helpers(
            module, stores, test, namespace_closed, include_callbacks=True
        )
        mock_constructors = _module_mock_constructors(module, test, namespace_closed)
    else:
        names, bases, literal_functions, helpers, mock_constructors = {}, {}, {}, {}, {}
    literal_calls = {
        name: _BUILTIN_RANGE_CALL
        for name, identity in names.items()
        if identity == "builtins.range"
    }
    for name, (function, value) in literal_functions.items():
        if function in module.body:
            literal_calls[name] = value
    context = {
        "names": names,
        "bases": bases,
        "namespace_closed": namespace_closed,
        "class_creation_closed": _class_creation_context_closed(
            module, providers, stores
        ),
        "helpers": helpers,
        "literal_functions": literal_functions,
        "literal_calls": literal_calls,
        "active_helpers": (),
        "mock_constructors": mock_constructors,
        "mock_instances": {},
        "swallowed_function_projections": {},
        "modules": (
            {
                **(module_aliases["builtins"] if providers["builtins"] else {}),
                **(module_aliases["contextlib"] if providers["contextlib"] else {}),
                **(module_aliases["warnings"] if providers["warnings"] else {}),
            }
        ),
    }
    context["module"] = module
    context["names"].update(_module_manager_names(module, context))
    return context


def _manager_transfer(statement, context, known):
    module = context.get("module")
    if not isinstance(module, ast.Module):
        return None
    target = _provider_transfer_target(statement)
    if target is None or not _provider_transfer_closed(statement, module):
        return None
    identity = _completion_name(statement.value, context, known)
    return (target.id, identity) if identity == "contextlib.nullcontext" else None


def _module_manager_names(module, context):
    result = {}
    for statement in module.body:
        transfer = _manager_transfer(statement, context, {})
        if transfer is None:
            continue
        root = (
            statement.value.value.id
            if isinstance(statement.value, ast.Attribute)
            else None
        )
        if not any(
            isinstance(item, ast.Import)
            and item.lineno < statement.lineno
            and any((alias.asname or alias.name) == root for alias in item.names)
            for item in module.body
        ):
            continue
        result[transfer[0]] = transfer[1]
    return result


def _mock_constructor_kind(node, context):
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and not node.args
        and not node.keywords
    ):
        return context.get("mock_constructors", {}).get(node.func.id)
    return None


def _mock_state_assertion_call(node, context):
    if (
        not isinstance(node, ast.Call)
        or node.args
        or node.keywords
        or not isinstance(node.func, ast.Attribute)
        or not isinstance(node.func.value, ast.Name)
    ):
        return False
    state = context.get("mock_instances", {}).get(node.func.value.id)
    if state is None:
        return False
    kind, calls = state
    return (
        node.func.attr == "assert_not_called"
        and calls == 0
        or node.func.attr == "assert_called_once"
        and calls == 1
        or node.func.attr == "assert_called"
        and calls > 0
        or node.func.attr == "assert_not_awaited"
        and kind == "AsyncMock"
    )


def _inert_mock_call(node, context):
    if not isinstance(node, ast.Call) or node.args or node.keywords:
        return False
    if not isinstance(node.func, ast.Name):
        return _mock_state_assertion_call(node, context)
    state = context.get("mock_instances", {}).get(node.func.id)
    if state is None:
        return False
    kind, calls = state
    context["mock_instances"][node.func.id] = (kind, min(calls + 1, 2))
    return True


def _inert_assigned_coroutine_creation(node, known, context):
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        return False
    helper = context.get("helpers", {}).get(node.func.id)
    if not _coroutine_call_arity_matches(node, helper):
        return False
    return all(
        _inert_literal(argument, known, context.get("literal_calls"))[0]
        or isinstance(argument, ast.Name)
        and argument.id not in known
        and argument.id in context.get("mock_instances", {})
        for argument in node.args
    )


def _completion_name(node, context, known):
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id not in known
    ):
        provider = context.get("modules", {}).get(node.value.id)
        if provider == "contextlib" and node.attr in {"nullcontext", "suppress"}:
            return f"contextlib.{node.attr}"
        if provider == "warnings" and node.attr in {"catch_warnings", "simplefilter"}:
            return f"warnings.{node.attr}"
        if provider == "builtins" and (
            f"builtins.{node.attr}" in context["bases"]
            or f"builtins.{node.attr}" in context["names"].values()
        ):
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


def _callback_helper_parameter(function):
    if (
        not isinstance(function, ast.FunctionDef)
        or not _inert_definition(function)
        or len(function.body) != 1
        or not isinstance(function.body[0], ast.Expr)
        or not isinstance(function.body[0].value, ast.Call)
    ):
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
    if direct_parameter_call:
        return parameters[0].arg
    return function.args.vararg.arg if first_vararg_call else None


def _callback_helper(function, call, helpers):
    if call.keywords or len(call.args) != 1 or not isinstance(call.args[0], ast.Name):
        return None
    callback = helpers.get(call.args[0].id)
    if (
        not isinstance(callback, (ast.FunctionDef, ast.AsyncFunctionDef))
        or _function_needs_arguments(callback)
        or _callback_helper_parameter(function) is None
    ):
        return None
    return callback


def _run_inert_helper(helper, context, helpers):
    if not _inert_definition(helper):
        return "UNKNOWN", None
    # Local class helpers are registered only after their definition and its
    # implicit providers pass _definition_completion in this execution path.
    if isinstance(helper, (ast.AsyncFunctionDef, ast.ClassDef)):
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
        "mock_constructors": dict(context.get("mock_constructors", {})),
        "mock_instances": dict(context.get("mock_instances", {})),
    }
    for name in _local_bindings(helper):
        for key in (
            "helpers",
            "names",
            "modules",
            "literal_calls",
            "mock_constructors",
            "mock_instances",
        ):
            nested[key].pop(name, None)
    result = _inert_suite(helper.body, nested, helpers=nested_helpers)
    captured = set(context["mock_instances"]) - _local_bindings(helper)
    for name in captured:
        context["mock_instances"].pop(name, None)
        if result[0] in {"NORMAL", "RETURN"} and name in nested["mock_instances"]:
            context["mock_instances"][name] = nested["mock_instances"][name]
    return ("NORMAL", None) if result[0] == "RETURN" else result


def _inert_warning_filter(node, known, context):
    if node.keywords or not 1 <= len(node.args) <= 2:
        return False
    closed, action = _inert_literal(node.args[0], known, context.get("literal_calls"))
    if not closed or type(action) is not str:
        return False
    if action not in {"error", "ignore", "always", "default", "module", "once"}:
        return False
    return len(node.args) == 1 or _completion_name(node.args[1], context, known) in {
        "builtins.Warning",
        "builtins.UserWarning",
        "builtins.DeprecationWarning",
    }


def _uncalled_mock_method_lookup(node, context):
    if not isinstance(node, ast.Attribute) or not isinstance(node.value, ast.Name):
        return False
    state = context.get("mock_instances", {}).get(node.value.id)
    if state is None or state[0] not in {"Mock", "AsyncMock"}:
        return False
    return node.attr in {
        "assert_called",
        "assert_called_once",
        "assert_called_with",
        "assert_called_once_with",
        "assert_any_call",
        "assert_has_calls",
        "assert_not_called",
    }


def _inert_created_expression(node, known, context):
    return (
        _uncalled_mock_method_lookup(node, context)
        or (isinstance(node, ast.Lambda) and _inert_definition(node))
        or (
            isinstance(node, ast.GeneratorExp)
            and _inert_empty_generator_creation(node, known, context)
        )
    )


def _inert_expression(node, known, helpers, context):
    if _inert_created_expression(node, known, context):
        return "NORMAL", None
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
        if _inert_helper_call(
            node, helper, known, context.get("literal_calls"), helpers
        ):
            return "NORMAL", None
        callback = _callback_helper(helper, node, helpers)
        if callback is not None:
            return _run_inert_helper(callback, context, helpers)
    if _mock_constructor_kind(node, context) is not None:
        return "NORMAL", None
    if _inert_mock_call(node, context):
        return "NORMAL", None
    if _inert_literal_call(node, context.get("literal_calls"), known) is not None:
        return "NORMAL", None
    return _canonical_call_completion(node, known, context)


def _canonical_call_completion(node, known, context):
    identity = _completion_name(node.func, context, known)
    if identity == "warnings.simplefilter" and _inert_warning_filter(
        node, known, context
    ):
        return "NORMAL", None
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
    if isinstance(function, ast.ClassDef):
        return False
    args = function.args
    return len((*args.posonlyargs, *args.args)) > len(args.defaults) or any(
        default is None for default in args.kw_defaults
    )


def _definition_completion(stmt, context):
    supported = _inert_definition(stmt) and (
        not isinstance(stmt, ast.ClassDef) or context.get("class_creation_closed")
    )
    return ("NORMAL", None) if supported else ("UNKNOWN", None)


def _simple_completion(stmt, known, helpers, context):
    unknown = ("UNKNOWN", None)
    if isinstance(stmt, ast.Pass):
        return "NORMAL", None
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return _function_definition_completion(stmt, helpers, context)
    if isinstance(stmt, ast.Expr):
        return _inert_expression(stmt.value, known, helpers, context)
    if isinstance(stmt, ast.Assert):
        closed, value = _inert_literal(stmt.test, known, context.get("literal_calls"))
        if not closed and _bound_name_identity_assertion(
            stmt.test, context.get("test_function"), context.get("namespace_closed")
        ):
            closed, value = True, True
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
    if _manager_transfer(stmt, context, known) is not None:
        return "NORMAL", None
    targets = getattr(stmt, "targets", ()) or (stmt.target,)
    closed = all(isinstance(target, ast.Name) for target in targets)
    if (
        isinstance(stmt, (ast.Assign, ast.AnnAssign))
        and len(targets) == 1
        and isinstance(targets[0], ast.Name)
        and _mock_constructor_kind(stmt.value, context) is not None
    ):
        return "NORMAL", None
    if (
        isinstance(stmt, (ast.Assign, ast.AnnAssign))
        and len(targets) == 1
        and isinstance(targets[0], ast.Name)
        and _inert_assigned_coroutine_creation(stmt.value, known, context)
    ):
        return "NORMAL", None
    if (
        isinstance(stmt, ast.Assign)
        and len(targets) == 1
        and isinstance(targets[0], ast.Name)
        and isinstance(stmt.value, ast.GeneratorExp)
        and _inert_empty_generator_creation(stmt.value, known, context)
    ):
        return "NORMAL", None
    if (
        isinstance(stmt, ast.Assign)
        and len(targets) == 1
        and isinstance(targets[0], ast.Name)
    ):
        literal = context.get("literal_functions", {}).get(targets[0].id)
        if (
            literal is not None
            and literal[0] is stmt.value
            and isinstance(stmt.value, ast.Lambda)
        ):
            return "NORMAL", None
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
    iterable_type = type(value) in (
        tuple,
        list,
        dict,
        set,
        str,
        bytes,
        range,
    )
    if not closed:
        return "UNKNOWN", None
    if isinstance(stmt, ast.While):
        return (
            _inert_suite(stmt.orelse, context, known, helpers)
            if not value
            else (
                "UNKNOWN",
                None,
            )
        )
    if not iterable_type:
        return "UNKNOWN", None
    try:
        size = len(value)
    except OverflowError:
        return "UNKNOWN", None
    if size == 0:
        return _inert_suite(stmt.orelse, context, known, helpers)
    if (
        isinstance(stmt.target, ast.Name)
        and stmt.body
        and isinstance(stmt.body[0], ast.Break)
    ):
        return "NORMAL", None
    return "UNKNOWN", None


def _inert_empty_generator_creation(node, known, context):
    if not isinstance(node, ast.GeneratorExp) or not node.generators:
        return False
    outer = node.generators[0]
    if outer.is_async:
        return False
    closed, value = _inert_literal(outer.iter, known, context.get("literal_calls"))
    if not closed or type(value) not in (tuple, list, dict, set, str, bytes, range):
        return False
    try:
        return len(value) == 0
    except OverflowError:
        return False


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
    context["mock_instances"].clear()
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


def _nullcontext_arguments_closed(arguments, known, context):
    """Prove evaluation of the optional stored enter result without invoking it."""
    if len(arguments) > 1:
        return False
    return all(
        _inert_literal(argument, known, context.get("literal_calls"))[0]
        or _completion_name(argument, context, known) in context["bases"]
        for argument in arguments
    )


def _with_completion(stmt, known, helpers, context):
    if len(stmt.items) != 1 or stmt.items[0].optional_vars is not None:
        return "UNKNOWN", None
    item = stmt.items[0].context_expr
    if not isinstance(item, ast.Call) or item.keywords:
        return "UNKNOWN", None
    manager = _completion_name(item.func, context, known)
    if manager == "warnings.catch_warnings" and not item.args:
        return _inert_suite(stmt.body, context, known, helpers)
    if manager == "contextlib.nullcontext" and _nullcontext_arguments_closed(
        item.args, known, context
    ):
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


def _captured_noop_import(statement, context):
    if not isinstance(statement, ast.ImportFrom) or len(statement.names) != 1:
        return None
    alias = statement.names[0]
    if alias.name == "*":
        return None
    module = context.get("module")
    if not isinstance(module, ast.Module):
        return None
    raw = _closed_star_import_source(module, statement)
    function = _captured_noop_definition(raw, alias.name)
    return (alias.asname or alias.name, function) if function is not None else None


def _captured_noop_definition(raw, symbol):
    if not isinstance(raw, bytes):
        return None
    try:
        tree = ast.parse(raw)
    except (SyntaxError, ValueError, UnicodeDecodeError, RecursionError):
        return None
    if len(tree.body) != 1:
        return None
    function = tree.body[0]
    if not _inert_helper_signature(function) or function.name != symbol:
        return None
    return function if _inert_helper_stub(function) else None


def _noop_import_completion(stmt, known, helpers, context):
    imported = _captured_noop_import(stmt, context)
    if imported is None:
        return "UNKNOWN", None
    name, function = imported
    helpers[name] = function
    known.pop(name, None)
    for key in (
        "names",
        "modules",
        "literal_calls",
        "mock_constructors",
        "mock_instances",
    ):
        context[key].pop(name, None)
    return "NORMAL", None


def _inert_statement(stmt, known, helpers, context):
    if isinstance(stmt, ast.ImportFrom):
        return _noop_import_completion(stmt, known, helpers, context)
    if isinstance(
        stmt,
        (
            ast.Pass,
            ast.FunctionDef,
            ast.AsyncFunctionDef,
            ast.ClassDef,
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
    if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return
    stmt = context.get("swallowed_function_projections", {}).pop(id(stmt), stmt)
    helpers[stmt.name] = stmt
    known.pop(stmt.name, None)
    context["mock_instances"].pop(stmt.name, None)
    literal = context.get("literal_functions", {}).get(stmt.name)
    if literal is not None and literal[0] is stmt:
        context["literal_calls"][stmt.name] = literal[1]


def _track_inert_assignment(stmt, known, helpers, context):
    if not isinstance(stmt, (ast.Assign, ast.AnnAssign)) or stmt.value is None:
        return
    transfer = _manager_transfer(stmt, context, known)
    if transfer is not None:
        name, identity = transfer
        context["names"][name] = identity
        known.pop(name, None)
        helpers.pop(name, None)
        context["literal_calls"].pop(name, None)
        return
    for target in getattr(stmt, "targets", ()) or (stmt.target,):
        if not isinstance(target, ast.Name):
            continue
        mock_kind = _mock_constructor_kind(stmt.value, context)
        if mock_kind is not None:
            context["mock_instances"][target.id] = (mock_kind, 0)
            known.pop(target.id, None)
            helpers.pop(target.id, None)
            context["literal_calls"].pop(target.id, None)
            continue
        context["mock_instances"].pop(target.id, None)
        if _helper_alias(stmt, helpers):
            helpers[target.id] = helpers[stmt.value.id]
            known.pop(target.id, None)
        else:
            helpers.pop(target.id, None)
            literal = context.get("literal_functions", {}).get(target.id)
            if (
                literal is not None
                and literal[0] is stmt.value
                and isinstance(stmt.value, ast.Lambda)
            ):
                known.pop(target.id, None)
                context["literal_calls"][target.id] = (stmt.value, literal[1])
            else:
                context["literal_calls"].pop(target.id, None)
                closed, value = _inert_literal(
                    stmt.value, known, context["literal_calls"]
                )
                if closed:
                    known[target.id] = value
                else:
                    known.pop(target.id, None)


def _reset_inert_branch(stmt, known, context, literal_calls_before):
    if not isinstance(stmt, (ast.If, ast.For, ast.While, ast.Try, ast.With)):
        return None
    preserve_mock_instances = (
        isinstance(stmt, ast.If)
        and isinstance(stmt.test, ast.Constant)
        and stmt.test.value is False
        and not stmt.orelse
    )
    known.clear()
    context["literal_calls"] = literal_calls_before
    if not preserve_mock_instances:
        context["mock_instances"].clear()
    return dict(context["helpers"])


def _inert_suite(statements, context, known=None, helpers=None):
    caller_context = context
    context = {
        **context,
        "names": dict(context.get("names", {})),
        "literal_calls": dict(context.get("literal_calls", {})),
        "mock_instances": dict(context.get("mock_instances", {})),
    }
    known, helpers = (
        dict(known or {}),
        dict(context["helpers"] if helpers is None else helpers),
    )
    for stmt in statements:
        literal_calls_before = dict(context["literal_calls"])
        result = _inert_statement(stmt, known, helpers, context)
        if result[0] != "NORMAL":
            caller_context["mock_instances"] = (
                dict(context["mock_instances"]) if result[0] == "RETURN" else {}
            )
            return result
        _track_inert_definition(stmt, known, helpers, context)
        _track_inert_assignment(stmt, known, helpers, context)
        reset_helpers = _reset_inert_branch(stmt, known, context, literal_calls_before)
        if reset_helpers is not None:
            helpers = reset_helpers
    caller_context["mock_instances"] = dict(context["mock_instances"])
    return "NORMAL", None


def inert_test_completion(node):
    """Classify bounded test completion as NORMAL, RETURN, RAISE, or UNKNOWN after excluding local bindings from inherited context."""
    if (
        not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        or sum(1 for _ in ast.walk(node)) > 512
    ):
        return "UNKNOWN", None
    context = _completion_context(node)
    context["test_function"] = node
    for name in _local_bindings(node):
        context["names"].pop(name, None)
        context["helpers"].pop(name, None)
        context["modules"].pop(name, None)
        context["literal_calls"].pop(name, None)
        context["mock_constructors"].pop(name, None)
        context["mock_instances"].pop(name, None)
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
    """Report an inert test body only when completion analysis proves normal fallthrough or return."""
    return inert_test_completion(node)[0] in {"NORMAL", "RETURN"}


def _source_profile_tree(profile, context):
    from pathlib import Path

    captured = context.get("_security_source_context")
    if not isinstance(captured, tuple) or len(captured) != 2:
        return None
    root, sources = captured
    source = Path(profile.get("source", "")).resolve()
    entry = context.get("_callback_source_trees", {}).get(source.as_posix())
    if not isinstance(entry, tuple) or len(entry) != 2:
        return None
    tree, snapshot_fingerprint = entry
    if not isinstance(tree, ast.Module):
        return None
    key = source if source in sources else root / source
    raw = sources.get(key)
    return (
        tree
        if _source_profile_identity_closed(tree, raw, snapshot_fingerprint, profile)
        else None
    )


def _source_none_guard(test, parameters):
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id in parameters
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Is)
        and len(test.comparators) == 1
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value is None
    )


def _source_virtual_call_is_hollow(
    invoke, overrides, call_method, call_statement, call, instance, node, audit
):
    if not isinstance(call_statement.value, ast.Await):
        return True
    if "__call__" in overrides:
        return _source_virtual_empty_body(call_method)
    if _source_virtual_dead_dispatch(invoke):
        return True
    if _source_virtual_dispatched_without_await(invoke, overrides, audit):
        return True
    if _source_virtual_guard_returns(
        invoke, call_statement, call, call_method, instance, node, audit
    ):
        return True
    return _source_virtual_weak_assertion(invoke, overrides, audit)


def _source_callback_if(
    statement, function, methods, aliases, bindings, result, depth, active, integrity
):
    closed, selected = _inert_literal(statement.test, {})
    if not closed:
        return False
    branch = statement.body if selected else statement.orelse
    return _source_callback_suite(
        branch, function, methods, aliases, bindings, result, depth, active, integrity
    )


def _source_virtual_test_case(node, subclass, init, audit):
    constructors = _source_virtual_constructors(node, subclass.name)
    calls = _source_virtual_test_calls(node)
    if len(constructors) != 1 or len(calls) != 1:
        return None
    constructor_row, (call_statement, call) = constructors[0], calls[0]
    constructor, instance = constructor_row[0], constructor_row[1]
    if not _source_virtual_test_shape(
        node, subclass, constructor, call_statement, call, instance
    ):
        return None
    if _source_name_rebound(node, instance, constructor.lineno, call.lineno, audit):
        return None
    if not _source_virtual_constructor_bound(constructor_row, init, instance, audit):
        return None
    return constructor_row, instance, call_statement, call


def _source_method_completion(
    call,
    awaited,
    target,
    caller,
    methods,
    aliases,
    bindings,
    result,
    depth,
    active,
    integrity,
):
    if not _source_method_reference_closed(call, target):
        return False
    try:
        actuals = integrity.bind_source_call(
            call, target, receiver=ast.Name(id="self"), apply_defaults=False
        )
    except (TypeError, ValueError):
        return False
    actual_bindings = _source_forwarded_bindings(actuals, caller, bindings)
    if isinstance(target, ast.AsyncFunctionDef) and not awaited:
        return True
    child = source_callback_flow_summary(target, methods, aliases, depth + 1, active)
    if child is None:
        return False
    for parameter, sites in child["calls"].items():
        forwarded = actual_bindings.get(parameter)
        if forwarded is not None:
            result["calls"].setdefault(forwarded, []).extend(sites)
    return True


def _source_scope_mapping_assignment(statement, name, mapping):
    target = statement.targets[0]
    if isinstance(target, ast.Name) and target.id == name:
        result = _source_literal_string_mapping(statement.value)
        return result is not None and mapping is None, result
    if _source_scope_item_target(target, name) and mapping is not None:
        closed, result = _inert_literal(statement.value, {})
        if not closed:
            return False, None
        mapping[target.slice.value] = result
    return True, mapping


def _source_self_method(value):
    return (
        value.attr
        if isinstance(value, ast.Attribute)
        and isinstance(value.value, ast.Name)
        and value.value.id == "self"
        else None
    )


def _source_virtual_base_closed(tree, profile, methods, init, invoke, audit):
    if not _source_virtual_base_structure(tree, profile, methods):
        return False
    if not isinstance(init, ast.FunctionDef) or not isinstance(
        invoke, ast.AsyncFunctionDef
    ):
        return False
    return _source_init_completion_closed(
        init, methods
    ) and _source_virtual_init_bindings_closed(methods, init, invoke, audit)


def _source_test_call_values_closed(call, node):
    functions = {
        item.name: item
        for item in node.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.end_lineno < call.lineno
    }
    values = [*call.args, *(item.value for item in call.keywords)]
    return all(
        _inert_literal(value, {})[0]
        or isinstance(value, ast.Name)
        and value.id in functions
        and _inert_definition(functions[value.id])
        for value in values
    )


def _source_callback_profile(source, symbol, tree, audit):
    from . import review_integrity as integrity

    classes = [
        item
        for item in tree.body
        if isinstance(item, ast.ClassDef) and item.name == symbol
    ]
    if len(classes) != 1:
        return None
    methods = audit._inherited_source_methods(classes[0], tree)
    function = methods.get("__call__")
    if not audit._source_methods_are_stable(methods) or not isinstance(
        function, ast.AsyncFunctionDef
    ):
        return None
    aliases = audit._module_security_aliases(tree)
    return {
        "parameters": [
            item.arg for item in [*function.args.posonlyargs, *function.args.args][1:]
        ],
        "invoked": sorted(
            audit._source_callback_parameters(function, methods, aliases=aliases)
        ),
        "call_method": "__call__",
        "source": source.as_posix(),
        "source_sha256": getattr(tree, "_oracle_source_sha256", None),
        "source_ast_sha256": audit._oracle_tree_fingerprint(tree),
        "symbol": symbol,
        "virtual_dispatch": integrity.virtual_dispatch_defaults(
            methods, aliases, audit._effective_assertion
        ),
    }


def _source_virtual_init_bindings_closed(methods, init, invoke, audit):
    if not audit.integrity._virtual_init_supported(init, invoke):
        return False
    arguments = [*init.args.posonlyargs, *init.args.args][1:]
    defaults = {
        item.arg
        for item, value in zip(
            arguments[-len(init.args.defaults) :], init.args.defaults
        )
        if isinstance(value, ast.Constant) and value.value is None
    }
    bindings, invalid = audit.integrity._virtual_init_bindings(init, defaults)
    return (
        "dispatch" in defaults
        and not invalid
        and bindings.get("self.dispatch_func") == "dispatch"
        and not audit.integrity._virtual_binding_mutations(methods, bindings)
        and _source_virtual_signatures_closed(methods)
    )


def _source_module_creation_closed(tree, consumer):
    names = set()
    for statement in tree.body:
        if _docstring(statement) or isinstance(statement, ast.Pass):
            continue
        if isinstance(statement, ast.ImportFrom) and not _completion_provider_captured(
            consumer, "functools"
        ):
            return False
        bound = _source_module_statement_names(statement)
        if bound is None or names.intersection(bound):
            return False
        names.update(bound)
    return True


def source_hollow_completion(node, context):
    """Prove a closed source callback cannot execute the test's local assertion."""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    module = getattr(node, "_oracle_module", None)
    if not isinstance(module, ast.Module):
        return False
    from . import review_audits as audit

    aliases = audit._scope_security_aliases(
        audit._module_security_aliases(module), node
    )
    return any(
        _source_callback_profile_hollow(node, local, profile, aliases, audit, context)
        for local, profile in context.get("callback_invokers", {}).items()
    )


def _source_callback_signature_closed(callback):
    args = callback.args
    return not any(
        (
            callback.decorator_list,
            getattr(callback, "type_params", ()),
            args.vararg,
            args.kwarg,
            args.kwonlyargs,
            args.defaults,
            args.kw_defaults,
            callback.returns is not None,
            any(arg.annotation is not None for arg in _source_arguments(callback)),
        )
    )


def _source_import_rebinding(item, local):
    if isinstance(item, ast.Name) and item.id == local:
        return isinstance(item.ctx, (ast.Store, ast.Del))
    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return item.name == local
    if isinstance(item, (ast.Import, ast.ImportFrom)):
        return any(
            (alias.asname or alias.name.split(".")[0]) == local for alias in item.names
        )
    return isinstance(item, (ast.Global, ast.Nonlocal)) and local in item.names


def source_callback_invokers(imports, snapshots, summaries=None):
    """Derive callback profiles from captured imported class definitions."""
    from . import review_audits as audit

    summaries = {} if summaries is None else summaries
    invokers = {}
    for local, (source, symbol) in imports.items():
        if source not in snapshots or symbol is None:
            continue
        key = (source, symbol)
        if key in summaries:
            profile = summaries[key]
        else:
            profile = _source_callback_profile(source, symbol, snapshots[source], audit)
            summaries[key] = profile
        if profile is not None:
            invokers[local] = profile
    return invokers


def _source_partial_binding(
    statement, function, methods, aliases, bindings, result, integrity
):
    if not _source_partial_shape(statement, aliases, bindings):
        return False
    name = statement.targets[0].id
    target_expr = statement.value.args[0]
    method_name = _source_self_method(target_expr)
    target = methods.get(method_name)
    if not method_name or not isinstance(
        target, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        return False
    actuals = statement.value.args[1:]
    if not all(_source_safe_value(value, function, bindings) for value in actuals):
        return False
    try:
        probe = ast.Call(func=ast.Name(id=method_name), args=list(actuals), keywords=[])
        integrity.bind_source_call(
            probe, target, receiver=ast.Name(id="self"), apply_defaults=False
        )
    except (TypeError, ValueError):
        return False
    bound = {
        arg.id: bindings.get(arg.id) for arg in actuals if isinstance(arg, ast.Name)
    }
    bindings[name] = (target, tuple(actuals), bound)
    return True


def _source_callback_suite(
    statements, function, methods, aliases, bindings, result, depth, active, integrity
):
    for statement in statements:
        if isinstance(statement, ast.Pass) or _docstring(statement):
            continue
        if isinstance(statement, ast.If):
            if not _source_callback_if(
                statement,
                function,
                methods,
                aliases,
                bindings,
                result,
                depth,
                active,
                integrity,
            ):
                return False
            continue
        if isinstance(statement, ast.Assign):
            if not _source_partial_binding(
                statement, function, methods, aliases, bindings, result, integrity
            ):
                return False
            continue
        if not _source_callback_expression(
            statement,
            function,
            methods,
            aliases,
            bindings,
            result,
            depth,
            active,
            integrity,
        ):
            return False
    return True


def source_callback_snapshot_state(snapshots, fingerprints):
    """Retain captured callback trees with their source fingerprints."""
    return (
        {
            path.resolve(): (tree, fingerprints.get(path))
            for path, tree in snapshots.items()
        },
        {},
    )


def _source_profile_import_bound(node, local, profile):
    from pathlib import Path
    from hashlib import sha256

    if profile.get("call_method") != "__call__":
        return False
    module = getattr(node, "_oracle_module", None)
    statement = _source_single_import(module, local, profile.get("symbol"))
    if statement is None:
        return False
    raw = _closed_star_import_source(module, statement)
    context = getattr(module, "_security_source_context", None)
    if not isinstance(raw, bytes) or not context:
        return False
    expected = context[0] / (statement.module + ".py")
    return expected.resolve() == Path(profile.get("source", "")).resolve() and sha256(
        raw
    ).hexdigest() == profile.get("source_sha256")


def _source_import_binding_closed(node, local):
    if not _source_test_import_closed(node, local):
        return False
    arguments = [*_source_arguments(node), *node.args.kwonlyargs]
    arguments.extend(arg for arg in (node.args.vararg, node.args.kwarg) if arg)
    if any(arg.arg == local for arg in arguments):
        return False
    for item in ast.walk(node):
        if _source_import_rebinding(item, local):
            return False
    return True


def _source_forwarded_bindings(actuals, caller, bindings):
    names = {arg.arg for arg in _source_arguments(caller)}
    return {
        parameter: bindings.get(value.id)
        if isinstance(value, ast.Name) and value.id in names
        else None
        for parameter, value in actuals.items()
    }


def _source_call_actuals_closed(call, function, bindings):
    return not call.keywords and all(
        _source_safe_value(value, function, bindings) for value in call.args
    )


def _source_virtual_dispatch_stmt(statement):
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Await)
        and isinstance(statement.value.value, ast.Call)
        and _source_self_method(statement.value.value.func) == "dispatch_func"
    )


def _source_callback_instance(node, local, aliases, audit):
    constructors = [
        statement
        for statement in node.body
        if isinstance(statement, (ast.Assign, ast.AnnAssign))
        and _source_assignment_target(statement) is not None
        and isinstance(getattr(statement, "value", None), ast.Call)
        and isinstance(statement.value.func, ast.Name)
        and statement.value.func.id == local
    ]
    if (
        len(constructors) != 1
        or constructors[0].value.args
        or constructors[0].value.keywords
    ):
        return None
    name = _source_assignment_target(constructors[0])
    return (name, constructors[0]) if isinstance(name, str) else None


def _source_callback_test_shape(node, constructor, call, body_nodes):
    operations = [
        statement
        for statement in node.body
        if statement is not constructor
        and not isinstance(statement, ast.AsyncFunctionDef)
        and not _docstring(statement)
    ]
    if len(operations) != 1 or not isinstance(operations[0], ast.Expr):
        return False
    if constructor.end_lineno >= call.lineno:
        return False
    if node.body[-1] is not operations[0]:
        return False
    value = operations[0].value
    return (
        value is call or isinstance(value, ast.Await) and value.value is call
    ) and not any(isinstance(item, ast.Assert) for item in body_nodes)


def _source_callback_targets_closed(
    actuals, method, flow, node, aliases, audit, context
):
    callback_names = {
        item.arg: actuals.get(item.arg)
        for item in [*method.args.posonlyargs, *method.args.args][1:]
        if isinstance(actuals.get(item.arg), ast.Name)
    }
    definitions = {
        item.name: item for item in node.body if isinstance(item, ast.AsyncFunctionDef)
    }
    sites = flow.get("calls", {})
    if any(site.get("awaited") for values in sites.values() for site in values):
        return False
    hollow = False
    for parameter, actual in callback_names.items():
        calls = sites.get(parameter, ())
        callback = definitions.get(actual.id) if isinstance(actual, ast.Name) else None
        if not calls and callback is None:
            continue
        if callback is None or not _source_callback_target_closed(
            callback, calls, aliases, audit, context
        ):
            return False
        hollow = True
    return hollow


def _source_scope_item_target(target, name):
    return (
        isinstance(target, ast.Subscript)
        and isinstance(target.value, ast.Name)
        and target.value.id == name
        and isinstance(target.slice, ast.Constant)
        and isinstance(target.slice.value, str)
    )


def _source_callback_class_closed(node, methods, audit):
    names = {name for name in methods if not name.startswith("__")}
    names.update({"__call__", "__init__"})
    return (
        not node.bases
        and not node.keywords
        and not node.decorator_list
        and not getattr(node, "type_params", ())
        and _source_class_methods(node, names) is not None
        and audit._source_methods_are_stable(methods)
    )


def _source_method_signature_closed(function):
    args = function.args
    return (
        not function.decorator_list
        and not getattr(function, "type_params", ())
        and not args.vararg
        and not args.kwarg
        and not args.kwonlyargs
        and _source_formals_unique(function)
        and not function.returns
        and all(arg.annotation is None for arg in _source_arguments(function))
        and _source_method_defaults_closed(args)
    )


def _source_virtual_order_closed(
    node, subclass, constructor, call_statement, call, instance
):
    return (
        _source_test_definitions_closed(node)
        and isinstance(call.func, ast.Name)
        and call.func.id == instance
        and not call.keywords
        and subclass.end_lineno < constructor.lineno
        and constructor.end_lineno < call_statement.lineno
        and node.body[-1] is call_statement
    )


def _source_virtual_constructors(node, class_name):
    rows = []
    for statement in node.body:
        value = getattr(statement, "value", None)
        target = (
            _source_assignment_target(statement)
            if isinstance(statement, (ast.Assign, ast.AnnAssign))
            else None
        )
        if (
            target
            and isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == class_name
        ):
            rows.append((statement, target, value))
    return rows


def _source_partial_shape(statement, aliases, bindings):
    return not (
        len(statement.targets) != 1
        or not isinstance(statement.targets[0], ast.Name)
        or not isinstance(statement.value, ast.Call)
        or not isinstance(statement.value.func, ast.Name)
        or statement.value.func.id in bindings
        or aliases.get(statement.value.func.id) != "functools.partial"
        or len(statement.value.args) < 1
        or statement.value.keywords
    )


def _source_class_methods(node, allowed):
    functions = [
        item
        for item in node.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    names = [item.name for item in functions]
    if len(names) != len(set(names)) or set(names) - allowed:
        return None
    if not all(_inert_definition(item) for item in functions):
        return None
    if not all(
        isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Pass))
        or _docstring(item)
        for item in node.body
    ):
        return None
    return {item.name: item for item in functions}


def source_callback_snapshot_context(captured_imports, root, index, summaries=None):
    """Rebuild callback context using the captured in-workspace imports."""
    from pathlib import Path

    root = Path(root).resolve()
    imports = {}
    for local, value in captured_imports.items():
        if (
            not isinstance(value, (tuple, list))
            or len(value) != 2
            or not isinstance(value[0], str)
        ):
            continue
        source = (root / value[0]).resolve()
        if source in index and source.is_relative_to(root):
            imports[local] = (source, value[1])
    trees = {path: row[0] for path, row in index.items()}
    invokers = source_callback_invokers(imports, trees, summaries)
    return {
        "callback_invokers": invokers,
        "_callback_source_trees": {
            Path(profile["source"]).resolve().as_posix(): index[
                Path(profile["source"]).resolve()
            ]
            for profile in invokers.values()
        },
    }


def _source_assignment_target(statement):
    targets = (
        statement.targets if isinstance(statement, ast.Assign) else [statement.target]
    )
    return (
        targets[0].id
        if len(targets) == 1 and isinstance(targets[0], ast.Name)
        else None
    )


def _source_test_import_closed(node, local):
    module = getattr(node, "_oracle_module", None)
    if not isinstance(module, ast.Module) or not _module_namespace_access_closed(
        module
    ):
        return False
    definitions = []
    providers = []
    for statement in module.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            definitions.append(statement)
        elif isinstance(statement, ast.ImportFrom):
            providers.extend(_source_plain_import_names(statement))
        elif not _docstring(statement) and not isinstance(statement, ast.Pass):
            return False
    return definitions == [node] and providers == [local]


def _source_literal_string_mapping(value):
    closed, result = _inert_literal(value, {})
    if not closed or not isinstance(result, dict):
        return None
    return result if all(isinstance(key, str) for key in result) else None


def _source_virtual_call_binds(call, target, caller, audit):
    try:
        audit.integrity.bind_source_call(
            call, target, receiver=ast.Name(id="instance"), apply_defaults=False
        )
    except (TypeError, ValueError):
        return False
    caller_names = {item.arg for item in _source_arguments(caller)}
    return not call.keywords and all(
        _inert_literal(value, {})[0]
        or isinstance(value, ast.Name)
        and value.id in caller_names
        for value in call.args
    )


def _source_profile_identity_closed(tree, raw, snapshot_fingerprint, profile):
    from hashlib import sha256
    from .import_context import structural_ast_fingerprint

    digest = structural_ast_fingerprint(tree)
    return (
        isinstance(raw, bytes)
        and sha256(raw).hexdigest() == profile.get("source_sha256")
        and digest == profile.get("source_ast_sha256")
        and digest == snapshot_fingerprint
    )


def _source_virtual_test_flow(
    node, subclass, overrides, profile, tree, methods, aliases, audit
):
    init, invoke = methods.get("__init__"), methods.get("__call__")
    if not _source_virtual_base_closed(tree, profile, methods, init, invoke, audit):
        return False
    if "__init__" in overrides:
        return False
    call_method = overrides.get("__call__", invoke)
    case = _source_virtual_test_case(node, subclass, init, audit)
    if case is None:
        return False
    constructor_row, instance, call_statement, call = case
    if not _source_virtual_call_binding(call, call_method, instance, audit):
        return False
    return _source_virtual_call_is_hollow(
        invoke, overrides, call_method, call_statement, call, instance, node, audit
    )


def _source_virtual_dead_dispatch(invoke):
    statements = [item for item in invoke.body if not _docstring(item)]
    if len(statements) != 1 or not isinstance(statements[0], ast.If):
        return False
    closed, selected = _inert_literal(statements[0].test, {})
    return closed and not selected and not statements[0].orelse


def _source_virtual_class_closed(node, audit):
    methods = _source_class_methods(node, {"dispatch", "__call__"})
    return (
        not node.decorator_list
        and not node.keywords
        and not getattr(node, "type_params", ())
        and methods is not None
        and all(isinstance(item, ast.AsyncFunctionDef) for item in methods.values())
        and _source_virtual_signatures_closed(methods)
        and audit._source_methods_are_stable(methods)
    )


def _source_class_creation_shape(statement):
    return isinstance(statement, ast.ClassDef) and not any(
        (
            statement.bases,
            statement.keywords,
            statement.decorator_list,
            getattr(statement, "type_params", ()),
        )
    )


def _source_method_reference_closed(call, target):
    if not isinstance(target, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    if isinstance(call.func, ast.Attribute):
        return _source_self_method(call.func) == target.name
    return isinstance(call.func, ast.Name) and call.func.id == target.name


def _source_callback_call(
    call,
    awaited,
    function,
    methods,
    aliases,
    bindings,
    result,
    depth,
    active,
    integrity,
):
    if not _source_call_actuals_closed(call, function, bindings):
        return False
    partial = bindings.get(call.func.id) if isinstance(call.func, ast.Name) else None
    if isinstance(partial, tuple):
        target, prefix, captured = partial
        if call.args or not isinstance(target, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        probe = ast.Call(
            func=ast.Name(id=target.name),
            args=list(prefix) + list(call.args),
            keywords=[],
        )
        return _source_method_completion(
            probe,
            awaited,
            target,
            function,
            methods,
            aliases,
            captured,
            result,
            depth,
            active,
            integrity,
        )
    if isinstance(call.func, ast.Name) and call.func.id in {
        arg.arg for arg in _source_arguments(function)
    }:
        root = bindings.get(call.func.id)
        if root is None:
            return False
        result["calls"].setdefault(root, []).append(
            {"positional": len(call.args), "keywords": (), "awaited": awaited}
        )
        return True
    method_name = _source_self_method(call.func)
    target = methods.get(method_name) if method_name else None
    return _source_method_completion(
        call,
        awaited,
        target,
        function,
        methods,
        aliases,
        bindings,
        result,
        depth,
        active,
        integrity,
    )


def _source_virtual_call_binding(call, call_method, instance, audit):
    if not isinstance(call_method, ast.AsyncFunctionDef):
        return False
    try:
        audit.integrity.bind_source_call(
            call, call_method, receiver=ast.Name(id=instance), apply_defaults=False
        )
    except (TypeError, ValueError):
        return False
    return True


def _source_virtual_dispatched_without_await(invoke, overrides, audit):
    call = _source_virtual_dispatch_call(invoke)
    target = overrides.get("dispatch")
    return (
        isinstance(call, ast.Call)
        and not isinstance(invoke.body[0].value, ast.Await)
        and _source_self_method(call.func) == "dispatch_func"
        and isinstance(target, ast.AsyncFunctionDef)
        and _source_virtual_signatures_closed({"dispatch": target})
        and _source_virtual_call_binds(call, target, invoke, audit)
    )


def _source_arguments(function):
    return [*function.args.posonlyargs, *function.args.args]


def _source_safe_value(value, function, bindings):
    if isinstance(value, ast.Name):
        return value.id in bindings or value.id in {
            arg.arg for arg in _source_arguments(function)
        }
    return _inert_literal(value, {})[0]


def _source_virtual_hollow_test(
    node, local, profile, tree, base_methods, aliases, audit
):
    classes = [
        item
        for item in node.body
        if isinstance(item, ast.ClassDef)
        and len(item.bases) == 1
        and isinstance(item.bases[0], ast.Name)
        and item.bases[0].id == local
    ]
    if len(classes) != 1 or not _source_virtual_class_closed(classes[0], audit):
        return False
    subclass = classes[0]
    overrides = {
        item.name: item
        for item in subclass.body
        if isinstance(item, ast.AsyncFunctionDef)
    }
    if len(overrides) != sum(
        isinstance(item, ast.AsyncFunctionDef) for item in subclass.body
    ):
        return False
    return _source_virtual_test_flow(
        node, subclass, overrides, profile, tree, base_methods, aliases, audit
    )


def _source_callback_test(node, local, flow, method, aliases, audit, context):
    if (
        not isinstance(flow, dict)
        or not flow.get("closed")
        or not isinstance(method, ast.AsyncFunctionDef)
        or not _source_formals_unique(method)
    ):
        return False
    instance = _source_callback_instance(node, local, aliases, audit)
    if instance is None:
        return False
    name, constructor = instance
    call = _source_callback_invocation(node, name, constructor, aliases, audit)
    if call is None:
        return False
    try:
        actuals = audit.integrity.bind_source_call(
            call, method, receiver=ast.Name(id=name), apply_defaults=False
        )
    except (TypeError, ValueError):
        return False
    return _source_callback_targets_closed(
        actuals, method, flow, node, aliases, audit, context
    )


def _source_callback_invocation(node, name, constructor, aliases, audit):
    if any(
        item.name == name
        for item in node.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    ):
        return None
    body_nodes = audit._test_oracle_body_nodes(node, aliases)
    calls = [
        call
        for call in body_nodes
        if isinstance(call, ast.Call) and audit._name(call.func) == name
    ]
    if (
        len(calls) != 1
        or not _source_callback_test_shape(node, constructor, calls[0], body_nodes)
        or not _source_test_definitions_closed(node)
        or not _source_test_call_values_closed(calls[0], node)
        or audit._name_rebound(body_nodes, name, constructor.lineno, calls[0].lineno)
    ):
        return None
    return calls[0]


def _source_virtual_guard_mismatch(node, call_statement, value, guard):
    mapping = _source_virtual_scope_mapping(node, call_statement, value)
    if mapping is None:
        return False
    return mapping.get(guard["key"]) != guard["value"]


def _source_callback_method_flow(method, methods, aliases):
    if isinstance(method, ast.AsyncFunctionDef) and "__init__" not in methods:
        return source_callback_flow_summary(method, methods, aliases)
    return None


def _source_init_completion_closed(init, methods):
    parameters = _source_arguments(init)
    if not parameters or parameters[0].arg != "self":
        return False
    names = {item.arg for item in parameters[1:]}
    fields = set()
    for statement in init.body:
        if isinstance(statement, ast.Pass) or _docstring(statement):
            continue
        if not _source_init_assignment_closed(statement, names, fields, methods):
            return False
    return True


def source_node_reachable(node):
    """Exclude calls in a branch whose literal condition proves it cannot run."""
    for parent, child in getattr(node, "_oracle_ancestors", ()):
        if not isinstance(parent, ast.If):
            continue
        closed, selected = _inert_literal(parent.test, {})
        if closed and (
            child in parent.body and not selected or child in parent.orelse and selected
        ):
            return False
    return True


def _source_virtual_test_shape(
    node, subclass, constructor, call_statement, call, instance
):
    if not _source_virtual_order_closed(
        node, subclass, constructor, call_statement, call, instance
    ):
        return False
    scope_names = {item.id for item in call.args if isinstance(item, ast.Name)}
    bound_scopes = set()
    for statement in node.body:
        if statement is call_statement:
            return _source_virtual_call_values_closed(call, bound_scopes)
        if statement in (subclass, constructor) or _docstring(statement):
            continue
        if isinstance(statement, ast.AsyncFunctionDef):
            continue
        if not _source_virtual_scope_assignment(statement, scope_names, bound_scopes):
            return False
    return False


def source_callback_flow_summary(function, methods, aliases, depth=0, active=()):
    """Summarize a closed source callback flow without executing source methods."""
    from . import review_integrity as integrity

    if (
        depth >= 4
        or id(function) in active
        or not _source_method_signature_closed(function)
    ):
        return None
    lexical_names = _local_bindings(function)
    aliases = {
        name: value for name, value in aliases.items() if name not in lexical_names
    }
    parameters = {arg.arg: arg.arg for arg in _source_arguments(function)}
    result = {"closed": False, "calls": {}}
    if _source_callback_suite(
        function.body,
        function,
        methods,
        aliases,
        parameters,
        result,
        depth,
        (*active, id(function)),
        integrity,
    ):
        result["closed"] = True
        return result
    return None


def _source_init_value_closed(value, parameters, methods):
    if isinstance(value, ast.Name):
        return value.id in parameters
    if not isinstance(value, ast.IfExp):
        return _inert_literal(value, {})[0]
    test = value.test
    if not _source_none_guard(test, parameters):
        return False
    return (
        isinstance(value.orelse, ast.Name)
        and value.orelse.id == test.left.id
        and _source_self_method(value.body) in methods
    )


def _source_callback_expression(
    statement, function, methods, aliases, bindings, result, depth, active, integrity
):
    if not isinstance(statement, ast.Expr):
        return False
    expression = statement.value
    awaited = isinstance(expression, ast.Await)
    call = expression.value if awaited else expression
    return isinstance(call, ast.Call) and _source_callback_call(
        call,
        awaited,
        function,
        methods,
        aliases,
        bindings,
        result,
        depth,
        active,
        integrity,
    )


def _source_test_definitions_closed(node):
    definitions = [
        item
        for item in node.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    names = [item.name for item in definitions]
    return (
        _inert_definition(node)
        and len(names) == len(set(names))
        and all(_inert_definition(item) for item in definitions)
    )


def _source_virtual_signatures_closed(methods):
    for name, method in methods.items():
        if (
            not _inert_definition(method)
            or not _source_formals_unique(method)
            or method.args.vararg
            or method.args.kwarg
            or method.args.kwonlyargs
        ):
            return False
    return True


def _source_plain_import_names(statement):
    if statement.level or statement.module is None:
        return [None]
    return [
        None if alias.name == "*" else alias.asname or alias.name
        for alias in statement.names
    ]


def _source_virtual_scope_binding(value, name, bound_scopes):
    closed, mapping = _inert_literal(value, {})
    if not closed or not isinstance(mapping, dict) or name in bound_scopes:
        return False
    if any(not isinstance(key, str) for key in mapping):
        return False
    bound_scopes.add(name)
    return True


def _source_virtual_dispatch_call(invoke):
    statements = [item for item in invoke.body if not _docstring(item)]
    if len(statements) != 1 or not isinstance(statements[0], ast.Expr):
        return None
    value = statements[0].value
    call = value.value if isinstance(value, ast.Await) else value
    return call if isinstance(call, ast.Call) else None


def _source_name_rebound(node, name, start, end, audit):
    return audit._name_rebound(
        audit._test_oracle_body_nodes(node, {}), name, start, end
    )


def _source_virtual_scope_assignment(statement, scope_names, bound_scopes):
    if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
        return False
    target = statement.targets[0]
    if isinstance(target, ast.Name) and target.id in scope_names:
        return _source_virtual_scope_binding(statement.value, target.id, bound_scopes)
    return _source_virtual_scope_item_write(
        statement, target, scope_names, bound_scopes
    )


def _source_formals_unique(function):
    args = function.args
    names = [item.arg for item in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
    names.extend(item.arg for item in (args.vararg, args.kwarg) if item is not None)
    return len(names) == len(set(names))


def _source_default_closed(value):
    return _inert_literal(value, {})[0]


def _source_virtual_weak_assertion(invoke, overrides, audit):
    call = _source_virtual_dispatch_call(invoke)
    target = overrides.get("dispatch")
    return (
        isinstance(call, ast.Call)
        and isinstance(invoke.body[0].value, ast.Await)
        and _source_self_method(call.func) == "dispatch_func"
        and isinstance(target, ast.AsyncFunctionDef)
        and len(target.body) == 1
        and isinstance(target.body[0], ast.Assert)
        and isinstance(target.body[0].test, ast.Constant)
        and target.body[0].test.value is True
        and _source_virtual_call_binds(call, target, invoke, audit)
    )


def _source_virtual_constructor_bound(constructor, init, instance, audit):
    statement, _, call = constructor
    try:
        bound = audit.integrity.bind_source_call(
            call, init, receiver=ast.Name(id=instance), apply_defaults=True
        )
    except (TypeError, ValueError):
        return False
    return (
        all(
            name == "self" or _inert_literal(value, {})[0]
            for name, value in bound.items()
        )
        and isinstance(bound.get("dispatch"), ast.Constant)
        and bound["dispatch"].value is None
    )


def _source_method_defaults_closed(args):
    return all(_source_default_closed(value) for value in args.defaults) and all(
        value is None or _source_default_closed(value) for value in args.kw_defaults
    )


def _source_virtual_empty_body(method):
    return all(isinstance(item, ast.Pass) or _docstring(item) for item in method.body)


def _source_single_import(module, local, symbol):
    if not isinstance(module, ast.Module):
        return None
    for statement in module.body:
        if not isinstance(statement, ast.ImportFrom) or len(statement.names) != 1:
            continue
        (alias,) = statement.names
        if alias.name == symbol and (alias.asname or alias.name) == local:
            return statement
    return None


def _source_virtual_call_values_closed(call, bound_scopes):
    return all(
        _inert_literal(value, {})[0]
        or isinstance(value, ast.Name)
        and value.id in bound_scopes
        for value in call.args
    )


def _source_callback_target_closed(callback, sites, aliases, audit, context):
    if not _source_callback_signature_closed(callback):
        return False
    if not audit._strong_local_assertion(
        callback, aliases, set(context.get("helpers", ()))
    ):
        return False
    from . import review_integrity as integrity

    try:
        for site in sites:
            probe = ast.Call(
                func=ast.Name(id=callback.name),
                args=[ast.Constant(value=None)] * site["positional"],
                keywords=[
                    ast.keyword(arg=name, value=ast.Constant(value=None))
                    for name in site["keywords"]
                ],
            )
            integrity.bind_source_call(probe, callback, apply_defaults=False)
    except (KeyError, TypeError, ValueError):
        return False
    return True


def _source_virtual_scope_item_write(statement, target, scope_names, bound_scopes):
    return (
        isinstance(target, ast.Subscript)
        and isinstance(target.value, ast.Name)
        and target.value.id in scope_names
        and target.value.id in bound_scopes
        and isinstance(target.slice, ast.Constant)
        and isinstance(target.slice.value, str)
        and _inert_literal(statement.value, {})[0]
    )


def _source_virtual_test_calls(node):
    return [
        (
            statement,
            statement.value.value
            if isinstance(statement.value, ast.Await)
            else statement.value,
        )
        for statement in node.body
        if isinstance(statement, ast.Expr)
        and isinstance(statement.value, (ast.Call, ast.Await))
        and isinstance(
            statement.value.value
            if isinstance(statement.value, ast.Await)
            else statement.value,
            ast.Call,
        )
        and isinstance(
            (
                statement.value.value
                if isinstance(statement.value, ast.Await)
                else statement.value
            ).func,
            ast.Name,
        )
    ]


def _source_virtual_return_branch(branch):
    if not isinstance(branch, ast.If) or branch.orelse or len(branch.body) != 1:
        return False
    return isinstance(branch.body[0], ast.Return) and branch.body[0].value is None


def _source_virtual_base_structure(tree, profile, methods):
    declarations = [
        item
        for item in tree.body
        if isinstance(item, ast.ClassDef) and item.name == profile.get("symbol")
    ]
    if len(declarations) != 1:
        return False
    declaration = declarations[0]
    source_methods = _source_class_methods(
        declaration, {"__init__", "__call__", "dispatch"}
    )
    if (
        declaration.bases
        or declaration.decorator_list
        or declaration.keywords
        or getattr(declaration, "type_params", ())
        or source_methods is None
        or set(methods) - {"__init__", "__call__", "dispatch"}
    ):
        return False
    return True


def _source_virtual_guard_returns(
    invoke, call_statement, call, call_method, instance, node, audit
):
    guards = audit.integrity._virtual_scope_guards(invoke)
    if not guards or len(invoke.body) != 2:
        return False
    branch, dispatch = invoke.body
    if not _source_virtual_return_branch(branch) or not _source_virtual_dispatch_stmt(
        dispatch
    ):
        return False
    try:
        bound = audit.integrity.bind_source_call(
            call, call_method, receiver=ast.Name(id=instance), apply_defaults=False
        )
    except (TypeError, ValueError):
        return False
    return any(
        _source_virtual_guard_mismatch(
            node, call_statement, bound.get(guard["parameter"]), guard
        )
        for guard in guards
    )


def _source_module_statement_names(statement):
    if isinstance(statement, ast.ImportFrom):
        if statement.level or statement.module != "functools":
            return None
        if any(alias.name != "partial" for alias in statement.names):
            return None
        return {alias.asname or alias.name for alias in statement.names}
    if not _source_class_creation_shape(statement):
        return None
    methods = {
        item.name
        for item in statement.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if _source_class_methods(statement, methods) is None:
        return None
    return {statement.name}


def _source_callback_profile_hollow(node, local, profile, aliases, audit, context):
    if not _source_profile_import_bound(node, local, profile):
        return False
    tree = _source_profile_tree(profile, context)
    if (
        tree is None
        or not _source_module_creation_closed(
            tree, getattr(node, "_oracle_module", None)
        )
        or not _source_import_binding_closed(node, local)
    ):
        return False
    classes = [
        item
        for item in tree.body
        if isinstance(item, ast.ClassDef) and item.name == profile.get("symbol")
    ]
    if len(classes) != 1:
        return False
    methods = audit._inherited_source_methods(classes[0], tree)
    if not _source_callback_class_closed(classes[0], methods, audit):
        return False
    method = methods.get("__call__")
    source_aliases = audit._module_security_aliases(tree)
    flow = _source_callback_method_flow(method, methods, source_aliases)
    return _source_callback_test(
        node, local, flow, method, aliases, audit, context
    ) or (
        _source_virtual_hollow_test(node, local, profile, tree, methods, aliases, audit)
    )


def _source_virtual_scope_mapping(node, call_statement, value):
    if isinstance(value, ast.Dict):
        return _source_literal_string_mapping(value)
    if not isinstance(value, ast.Name):
        return None
    mapping = None
    for statement in node.body:
        if statement is call_statement:
            break
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        valid, mapping = _source_scope_mapping_assignment(statement, value.id, mapping)
        if not valid:
            return None
    return mapping


def _source_init_assignment_closed(statement, parameters, fields, methods):
    if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
        return False
    target = statement.targets[0]
    if not _source_self_method(target):
        return False
    name = target.attr
    if name.startswith("_") or name in fields or name in methods:
        return False
    if not _source_init_value_closed(statement.value, parameters, methods):
        return False
    fields.add(name)
    return True


def _project_swallowed_function(function, helpers):
    if not isinstance(function, ast.FunctionDef) or len(function.decorator_list) != 1:
        return None
    if _own_scope_yield(function) or not _plain_zero_arg_signature(
        function, decorated=True
    ):
        return None
    decorator = function.decorator_list[0]
    if not isinstance(decorator, ast.Name):
        return None
    wrapper = helpers.get(decorator.id)
    attempt = _swallower_try(wrapper) if wrapper is not None else None
    if attempt is None:
        return None
    projected = _swallowed_function_projection(function, attempt)
    return projected if _inert_definition(projected) else None


def _swallower_handler(attempt):
    if len(attempt.handlers) != 1 or attempt.orelse or attempt.finalbody:
        return False
    (handler,) = attempt.handlers
    if handler.name is not None or not isinstance(handler.type, ast.Name):
        return False
    if handler.type.id != "AssertionError" or len(handler.body) != 1:
        return False
    return isinstance(handler.body[0], ast.Pass)


def _own_scope_yield(function):
    pending = list(function.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            return True
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        pending.extend(ast.iter_child_nodes(node))
    return False


def _swallower_try(wrapper):
    attempt = _wrapper_attempt(wrapper)
    if attempt is None:
        return None
    callback = wrapper.args.args[0].arg
    inner = wrapper.body[0]
    if inner.name == callback or callback == "AssertionError":
        return None
    return (
        attempt
        if _swallower_call(attempt, callback) and _swallower_handler(attempt)
        else None
    )


def _single_callback_function(function):
    if not isinstance(function, ast.FunctionDef) or not _inert_definition(function):
        return False
    args = function.args
    return (
        len(args.args) == 1
        and not any(
            (
                args.posonlyargs,
                args.vararg,
                args.kwonlyargs,
                args.kwarg,
                args.defaults,
                args.kw_defaults,
            )
        )
        and args.args[0].annotation is None
    )


def _wrapper_attempt(wrapper):
    if not _single_callback_function(wrapper) or len(wrapper.body) != 2:
        return None
    inner, returned = wrapper.body
    if not _plain_zero_arg_signature(inner) or len(inner.body) != 1:
        return None
    if not _returns_named_function(returned, inner):
        return None
    attempt = inner.body[0]
    return attempt if isinstance(attempt, ast.Try) else None


def _returns_named_function(statement, function):
    return (
        isinstance(statement, ast.Return)
        and isinstance(statement.value, ast.Name)
        and statement.value.id == function.name
    )


def _plain_zero_arg_signature(function, *, decorated=False):
    if not isinstance(function, ast.FunctionDef):
        return False
    args = function.args
    return not any(
        (
            function.decorator_list if not decorated else (),
            getattr(function, "type_params", ()),
            function.returns,
            args.posonlyargs,
            args.args,
            args.vararg,
            args.kwonlyargs,
            args.kwarg,
            args.defaults,
            args.kw_defaults,
            function.type_comment,
        )
    )


def _function_definition_completion(stmt, helpers, context):
    if _swallow_projection_statement(stmt, helpers, context):
        return "NORMAL", None
    return _definition_completion(stmt, context)


def _swallowed_function_projection(function, attempt):
    fields = {
        name: getattr(function, name)
        for name in function._fields
        if name not in {"body", "decorator_list"}
    }
    fields["body"] = [
        ast.Try(
            body=list(function.body),
            handlers=attempt.handlers,
            orelse=attempt.orelse,
            finalbody=attempt.finalbody,
        )
    ]
    fields["decorator_list"] = []
    projected = ast.FunctionDef(**fields)
    for name in function._attributes:
        setattr(projected, name, getattr(function, name, None))
    return projected


def _swallow_projection_statement(statement, helpers, context):
    if not isinstance(statement, ast.FunctionDef) or not statement.decorator_list:
        return False
    projected = _project_swallowed_function(statement, helpers)
    if projected is None:
        return False
    context["swallowed_function_projections"][id(statement)] = projected
    return True


def _swallower_call(attempt, callback):
    if len(attempt.body) != 1:
        return False
    statement = attempt.body[0]
    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        return False
    call = statement.value
    if not isinstance(call.func, ast.Name) or call.func.id != callback:
        return False
    return not call.args and not call.keywords


INERT_BODY_HELPERS = (
    _captured_noop_definition,
    _captured_noop_import,
    _noop_import_completion,
    _inert_created_expression,
    _uncalled_mock_method_lookup,
    _canonical_call_completion,
    _captured_star_module_unambiguous,
    _completion_module_imports,
    _provider_star_imports_closed,
    _builtin_provider_reference_closed,
    _provider_reference_transfer_closed,
    _provider_reference_closed,
    _provider_transfer_implicit_binding,
    _closed_star_import_source,
    _canonical_star_export,
    _closed_star_exports,
    _provider_transfer_target,
    _provider_transfer_rebound,
    _provider_transfer_load_closed,
    _provider_transfer_closed,
    _manager_transfer,
    _module_manager_names,
    _canonical_completion_import,
    _inert_warning_filter,
    _completion_provider_captured,
    _nullcontext_arguments_closed,
    _exception_names,
    _inert_literal,
    _inert_integer_arithmetic,
    _inert_integer_operation,
    _inert_definition,
    _class_creation_context_closed,
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
    _module_pass_context_closed,
    _module_pass_helpers,
    _inert_coroutine_signature,
    _coroutine_call_arity_matches,
    _module_mock_imports,
    _captured_mock_owner_is_exclusive,
    _module_mock_constructors,
    _module_helper_references_closed,
    _module_binding_conflict,
    _module_helper_kind,
    _inert_helper_stub,
    _inert_helper_signature,
    _inert_helper_call,
    _inert_literal_call,
    _inert_range_call,
    _inert_lambda_call,
    _static_inert_literal,
    _inert_boolean_expression,
    _inert_equality_expression,
    _inert_starred_list,
    _local_literal_returns,
    _module_namespace_access_closed,
    _literal_return_context,
    _literal_return_scope,
    _literal_return_function_summary,
    _literal_zero_arg_constant_return,
    _literal_direct_references_closed,
    _literal_empty_lambda_summary,
    _literal_empty_lambda,
    _literal_lambda_binding_closed,
    _helper_alias,
    _callback_helper_parameter,
    _callback_helper,
    _mock_constructor_kind,
    _mock_state_assertion_call,
    _inert_mock_call,
    _inert_assigned_coroutine_creation,
    _run_inert_helper,
    _track_inert_definition,
    _track_inert_assignment,
    _reset_inert_branch,
    _inert_expression,
    _function_needs_arguments,
    _simple_completion,
    _definition_completion,
    _bound_name_identity_assertion,
    _raise_completion,
    _assignment_completion,
    _conditional_completion,
    _loop_completion,
    _inert_empty_generator_creation,
    _handler_identity,
    _try_completion,
    _with_completion,
    _inert_statement,
    _inert_suite,
    inert_test_completion,
    inert_test_body,
    _source_profile_import_bound,
    _source_single_import,
    _source_test_import_closed,
    _source_plain_import_names,
    _source_callback_if,
    _source_callback_expression,
    _source_partial_shape,
    _source_call_actuals_closed,
    _source_method_reference_closed,
    _source_forwarded_bindings,
    _source_profile_identity_closed,
    _source_callback_signature_closed,
    _source_literal_string_mapping,
    _source_scope_mapping_assignment,
    _source_scope_item_target,
    _source_class_creation_shape,
    _source_virtual_order_closed,
    _source_import_binding_closed,
    _source_import_rebinding,
    _source_module_creation_closed,
    _source_module_statement_names,
    _source_init_completion_closed,
    _source_init_assignment_closed,
    _source_init_value_closed,
    _source_none_guard,
    source_callback_flow_summary,
    source_callback_invokers,
    source_callback_snapshot_context,
    source_callback_snapshot_state,
    _source_arguments,
    _source_formals_unique,
    _source_method_signature_closed,
    _source_method_defaults_closed,
    _source_default_closed,
    _source_callback_profile,
    _source_callback_suite,
    _source_partial_binding,
    _source_callback_call,
    _source_method_completion,
    _source_safe_value,
    _source_self_method,
    source_node_reachable,
    source_hollow_completion,
    _source_callback_profile_hollow,
    _source_callback_method_flow,
    _source_profile_tree,
    _source_callback_class_closed,
    _source_callback_test,
    _source_callback_instance,
    _source_callback_invocation,
    _source_callback_targets_closed,
    _source_assignment_target,
    _source_test_definitions_closed,
    _source_test_call_values_closed,
    _source_callback_test_shape,
    _source_callback_target_closed,
    _source_virtual_hollow_test,
    _source_virtual_class_closed,
    _source_virtual_test_flow,
    _source_virtual_test_case,
    _source_virtual_call_binding,
    _source_virtual_call_is_hollow,
    _source_virtual_base_closed,
    _source_virtual_base_structure,
    _source_virtual_init_bindings_closed,
    _source_virtual_signatures_closed,
    _source_class_methods,
    _source_virtual_constructors,
    _source_virtual_test_calls,
    _source_virtual_test_shape,
    _source_virtual_scope_assignment,
    _source_virtual_scope_binding,
    _source_virtual_scope_item_write,
    _source_virtual_call_values_closed,
    _source_name_rebound,
    _source_virtual_constructor_bound,
    _source_virtual_empty_body,
    _source_virtual_dispatch_call,
    _source_virtual_dispatched_without_await,
    _source_virtual_dead_dispatch,
    _source_virtual_call_binds,
    _source_virtual_guard_returns,
    _source_virtual_return_branch,
    _source_virtual_dispatch_stmt,
    _source_virtual_guard_mismatch,
    _source_virtual_scope_mapping,
    _source_virtual_weak_assertion,
    _swallowed_function_projection,
    _function_definition_completion,
    _plain_zero_arg_signature,
    _single_callback_function,
    _returns_named_function,
    _wrapper_attempt,
    _swallower_call,
    _swallower_handler,
    _swallower_try,
    _own_scope_yield,
    _project_swallowed_function,
    _swallow_projection_statement,
)


def _protocol_demand_summary(path, test, call, state):
    from . import context_efficiency as context

    summary = dict(
        protocol="python.iteration",
        test=test.name,
        line=call.lineno,
        output_checked=False,
        runtime_observed=False,
        status="UNKNOWN",
        demand_chain=[],
        dependencies=[],
        unknown_reasons=[],
    )
    summary["unresolved_effects"] = [
        "PATH_CONSTRUCTOR_AND_GENERATOR_EFFECTS_NOT_VERIFIED"
    ]
    summary.update(item_produced=None, exhausted=None, conditional_on_path=True)
    state["demand_targets"] = []
    state["receiver_safe_calls"] = set()
    state["source_arguments"] = {}
    state["constructor_effect_dependencies"] = summary["dependencies"]
    try:
        preceding = context._protocol_reachable_call(
            path, test, call, state, parameters=True
        )
        context._require(
            all(
                (
                    context._protocol_preceding_statement(s)
                    or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Call))
                    for s in preceding
                )
            ),
            "PRECEDING_CONTROL_OR_EFFECT_UNKNOWN",
        )
        summary["dependencies"].append(
            context._protocol_dependency(path, test, "test", state)
        )
        context._protocol_demand_visit(call, path, test, summary, state)
        phases = {step["phase"] for step in summary["demand_chain"]}
        if not phases.intersection({"created", "body_entered"}):
            return None
        summary["status"] = (
            "WEAK_PROTOCOL" if "body_entered" in phases else "CREATED_ONLY"
        )
        summary["exception_channels"] = ["may_propagate", "opaque_effects_unresolved"]
    except ValueError as exc:
        summary["unknown_reasons"].append(str(exc))
        if not any((s["phase"] != "returns" for s in summary["demand_chain"])):
            return None
    summary["dependencies"].extend(
        (
            context._protocol_dependency(p, cls, "demand_allocation", state)
            for p, cls in state["demand_targets"]
        )
    )
    return summary


def _protocol_demand_visit(call, path, scope, summary, state):
    from . import context_efficiency as context

    forced, visiting, origin = (False, set(), (path, scope))
    while isinstance(call, ast.Call) and len(visiting) < 16:
        consumer = None
        if len(call.args) == 1 and (not call.keywords):
            func = call.func
            if isinstance(func, ast.Name) and func.id in {"tuple", "list"}:
                consumer = func.id
                context._protocol_builtin_unshadowed(path, scope, state, consumer)
            elif (
                isinstance(func, ast.Attribute)
                and func.attr == "join"
                and isinstance(func.value, ast.Constant)
                and isinstance(func.value.value, str)
            ):
                consumer = "str.join"
        if consumer:
            state.setdefault("receiver_safe_calls", set()).add(call)
            summary["demand_chain"].append(
                dict(phase="forces", consumer=consumer, line=call.lineno)
            )
            call, forced = (call.args[0], True)
            continue
        source, function = context._protocol_demand_target(
            call.func, path, scope, state
        )
        if (
            (source, id(function)) in visiting
            or not isinstance(function, ast.FunctionDef)
            or function.decorator_list
        ):
            raise ValueError("DEMAND_CALLABLE_OR_CYCLE_UNKNOWN")
        previous = {
            name: value
            for name, value in state["source_arguments"]
            .get((path, id(scope)), {})
            .items()
            if not any(
                (
                    name in context._protocol_class_bound_names(s)
                    for s in scope.body
                    if s.lineno < call.lineno
                )
            )
        }
        state["source_arguments"][source, id(function)] = state[
            "audit"
        ].integrity.bind_source_call(
            call, function, receiver=state["demand_receiver"], previous=previous
        )
        visiting.add((source, id(function)))
        dependency = context._protocol_dependency(
            source, function, "demand_callable", state
        )
        summary["dependencies"].append(dependency)
        nodes = [n for s in function.body for n in state["audit"]._body_nodes(s)]
        yields = [n for n in nodes if isinstance(n, (ast.Yield, ast.YieldFrom))]
        summary["demand_chain"].append(
            dict(
                dependency,
                phase=("body_entered" if forced else "created")
                if yields
                else "returns",
            )
        )
        context._protocol_dependencies_closed(
            *origin, [*state["demand_targets"], (source, function)], state
        )
        if yields:
            context._require(
                not any((isinstance(n, (ast.With, ast.AsyncWith)) for n in nodes)),
                "GENERATOR_CONTEXT_MANAGER_UNKNOWN",
            )
            if not any(
                (
                    isinstance(n, ast.Yield)
                    and n.value is not None
                    and (not isinstance(n.value, ast.Constant))
                    for n in yields
                )
            ):
                raise ValueError("CONSTANT_OR_EMPTY_GENERATOR")
            if any(
                (
                    isinstance(n, ast.Try)
                    and any(
                        (
                            not h.body or not isinstance(h.body[-1], ast.Raise)
                            for h in n.handlers
                        )
                    )
                    for n in nodes
                )
            ) or any((state["audit"]._finally_suppresses_exception(n) for n in nodes)):
                raise ValueError("GENERATOR_FAILURE_MAY_BE_SWALLOWED")
            return
        context._require(
            not any(
                (
                    isinstance(
                        s, (ast.If, ast.For, ast.While, ast.Try, ast.With, ast.Match)
                    )
                    or isinstance(s, ast.Raise)
                    for s in function.body
                )
            ),
            "SOURCE_RETURN_CONTROL_UNKNOWN",
        )
        returned = [s.value for s in function.body if isinstance(s, ast.Return)]
        context._require(len(returned) == 1, "SOURCE_RETURN_DEMAND_UNKNOWN")
        call, path, scope = (returned[0], source, function)
    raise ValueError("DEMAND_DEPTH_OR_EXPRESSION_UNKNOWN")


def _protocol_demand_target(expression, path, scope, state):
    from . import context_efficiency as context

    state["demand_receiver"] = None
    receiver = expression.value if isinstance(expression, ast.Attribute) else None
    name = receiver.id if isinstance(receiver, ast.Name) else None
    bindings = [
        s
        for s in scope.body
        if s.lineno < expression.lineno
        and name in context._protocol_class_bound_names(s)
    ]
    if not bindings:
        return context._protocol_class_reference(expression, path, scope, state)
    origin, *transfers = bindings
    context._require(
        isinstance(origin, ast.Assign)
        and len(origin.targets) == 1
        and isinstance(origin.targets[0], ast.Name)
        and isinstance(origin.value, ast.Call),
        "LOCAL_RECEIVER_ALLOCATION_UNKNOWN",
    )
    chain, _ = context._protocol_class_chain(
        context._protocol_class_reference(origin.value.func, path, scope, state), state
    )
    allowed = {origin.targets[0]}
    for transfer in transfers:
        context._require(
            isinstance(transfer, ast.Assign)
            and len(transfer.targets) == 1
            and isinstance(transfer.value, ast.Call),
            "LOCAL_RECEIVER_IDENTITY_UNKNOWN",
        )
        call = transfer.value
        context._require(
            isinstance(transfer.targets[0], ast.Name)
            and transfer.targets[0].id == name
            and call.args
            and isinstance(call.args[0], ast.Name)
            and (call.args[0].id == name),
            "LOCAL_RECEIVER_IDENTITY_UNKNOWN",
        )
        target = context._protocol_identity_decorator(
            call.func, path, state, transfer=chain, call=call
        )
        state["demand_targets"].append(target)
        allowed.update((transfer.targets[0], call.args[0]))
    state["transfer_source"] = path
    context._protocol_receiver_transfer(
        scope, chain, state, local=(name, allowed, expression, origin.value)
    )
    state["demand_targets"].extend(chain)
    state["demand_receiver"] = origin.value
    return context._protocol_repr_method(chain, expression.attr)


def _protocol_fresh_list_append(call, scope, chain=()):
    """A literal list's append stores one object without invoking its hooks."""
    from . import context_efficiency as context

    match call:
        case ast.Call(
            func=ast.Attribute(
                value=ast.Attribute(value=ast.Name(id=receiver), attr=field),
                attr="append",
            ),
            args=[_],
            keywords=[],
        ):
            if not scope.args.args or (
                not chain and receiver != scope.args.args[0].arg
            ):
                return False
            if chain:
                scope = context._protocol_repr_method(chain, "__init__")[1]
                receiver = scope.args.args[0].arg
            fields = [
                n
                for n in ast.walk(scope)
                if isinstance(n, ast.Attribute)
                and isinstance(n.value, ast.Name)
                and (n.value.id == receiver)
                and (n.attr == field)
                and isinstance(n.ctx, (ast.Store, ast.Del))
            ]
            if len(fields) == 1:
                target = fields[0]
                parent = context._ast_parent_map(ast.walk(scope)).get(id(target))
                return (
                    isinstance(parent, ast.Assign)
                    and parent in scope.body
                    and (parent.targets == [target])
                    and isinstance(parent.value, ast.List)
                    and (not parent.value.elts)
                    and (field not in context._protocol_chain_bindings(chain))
                    and (bool(chain) or parent.lineno < call.lineno)
                )
    return False


def _protocol_receiver_transfer(function, chain, state, local=None):
    from . import context_efficiency as context

    receiver = local[0] if local else state["transfer_receiver"]
    dependencies = state["constructor_effect_dependencies"]
    nodes = [
        n for statement in function.body for n in state["audit"]._body_nodes(statement)
    ]
    safe = set(local[1]) if local else {function.body[-1].value}
    for call in (n for n in nodes if isinstance(n, ast.Call)):
        if local and (call.func is local[2] or call is local[3]):
            safe.add(local[2].value)
            state.setdefault("receiver_safe_calls", set()).add(call)
            continue
        if (
            context._protocol_fresh_list_append(call, function, chain)
            and context._leftmost_name(call.func).id == receiver
        ):
            safe.add(call.func.value.value)
        elif (
            isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and (call.func.value.id == receiver)
        ):
            path, method = context._protocol_repr_method(chain, call.func.attr)
            context._require(
                not method.decorator_list and (not call.args) and (not call.keywords),
                "RECEIVER_METHOD_EFFECT_UNKNOWN",
            )
            context._protocol_constructor_receiver_safe(method)
            context._require(
                all(
                    (
                        isinstance(s, ast.Assign)
                        and context._protocol_preceding_statement(s)
                        for s in method.body
                    )
                ),
                "RECEIVER_METHOD_EFFECT_UNKNOWN",
            )
            fields = {n.attr for n in ast.walk(method) if isinstance(n, ast.Attribute)}
            bound = context._protocol_chain_bindings(chain)
            context._require(
                not fields.intersection(bound)
                and (not any((f.startswith("__") for f in fields))),
                "RECEIVER_METHOD_DISPATCH_MUTATION",
            )
            dependencies.append(
                context._protocol_dependency(path, method, "receiver_effect", state)
            )
            safe.add(call.func.value)
        else:
            continue
        state.setdefault("receiver_safe_calls", set()).add(call)
    context._protocol_constructor_bindings_closed(
        chain[0][0],
        chain[0][1],
        {(p, id(c)) for p, c in chain},
        {p for p, _ in chain},
        state,
        functions=[(state["transfer_source"], function)],
    )
    context._require(
        all((n in safe for n in nodes if isinstance(n, ast.Name) and n.id == receiver)),
        "IDENTITY_RETURN_RECEIVER_ESCAPE_OR_MUTATION",
    )


def _protocol_chain_bindings(chain):
    from . import context_efficiency as context

    return set().union(
        *(context._protocol_class_bound_names(n) for _, cls in chain for n in cls.body)
    )
