"""Bounded source-role witnesses for canonical HTTP URL and auth slots."""

import ast
import hashlib
from .credential_role_constructor_provider import (
    effective_method,
    binding_occurrences,
    class_chain,
    matches_fact,
    scope_class,
    auth_constructor_password,
    candidate_facts,
    url_use,
    constructor_url_hops,
    SourceSnapshotIndex,
)
from importlib.util import resolve_name
from .credential_endpoint_admission import (
    session_factory_witness,
    endpoint_publications,
)
from .semantic_credential_sensor import (
    _canonical_http_call,
    _provider_identity_uncertain,
)

"""Bounded source-role witnesses for canonical HTTP URL and auth slots."""


def useful_body(function):
    """Return executable statements while excluding string-expression docstrings from a function body."""
    return [
        n
        for n in function.body
        if not (
            isinstance(n, ast.Expr)
            and isinstance(n.value, ast.Constant)
            and isinstance(n.value.value, str)
        )
    ]


def single_return(function):
    """Check whether the function body contains exactly one non-docstring statement and that it is a return."""
    body = useful_body(function)
    return len(body) == 1 and isinstance(body[0], ast.Return)


def default_getter(call):
    """Recognize the exact settings getter lambda shape used to fetch ALLAUTH_SETTING_GETTER with a default."""
    lam = _settings_getter_lambda(call)
    return lam is not None and _settings_getter_lambda_is_exact(lam)


def _settings_getter_lambda(call):
    if not (
        isinstance(call.func, ast.Name)
        and call.func.id == "getattr"
        and len(call.args) == 3
        and not call.keywords
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == "settings"
        and isinstance(call.args[1], ast.Constant)
        and call.args[1].value == "ALLAUTH_SETTING_GETTER"
        and isinstance(call.args[2], ast.Lambda)
    ):
        return None
    return call.args[2]


def _settings_getter_lambda_is_exact(lam):
    args = lam.args
    if [n.arg for n in args.args] != ["name", "dflt"]:
        return False
    if (
        args.posonlyargs
        or args.kwonlyargs
        or args.vararg
        or args.kwarg
        or args.defaults
    ):
        return False
    body = lam.body
    return _settings_getter_body_is_exact(body)


def _settings_getter_body_is_exact(body):
    return bool(
        isinstance(body, ast.Call)
        and isinstance(body.func, ast.Name)
        and body.func.id == "getattr"
        and not body.keywords
        and len(body.args) == 3
        and all(isinstance(n, ast.Name) for n in body.args)
        and [n.id for n in body.args] == ["settings", "name", "dflt"]
    )


def getter_environment(tree, function):
    """Confirm the module uses the expected Django settings and import helpers without rebinding their names."""
    if function.decorator_list:
        return False
    if any(binding_occurrences(tree.body, name) for name in ("getattr", "callable")):
        return False
    settings = binding_occurrences(tree.body, "settings")
    if len(settings) != 1 or not _import(settings[0], "django.conf", "settings"):
        return False
    imported = binding_occurrences(tree.body, "import_string")
    if len(imported) != 1 or not _import(
        imported[0], "django.utils.module_loading", "import_string"
    ):
        return False
    rows = binding_occurrences(tree.body, "import_callable")
    if len(rows) != 1 or not isinstance(rows[0], ast.FunctionDef):
        return False
    return _callable_bridge(rows[0])


def _import(node, module, name):
    return bool(
        isinstance(node, ast.ImportFrom)
        and not node.level
        and node.module == module
        and len(node.names) == 1
        and node.names[0].name == name
        and node.names[0].asname in {None, name}
    )


def _callable_bridge(function):
    if function.decorator_list or [a.arg for a in function.args.args] != [
        "path_or_callable"
    ]:
        return False
    body = useful_body(function)
    if (
        len(body) != 2
        or not isinstance(body[0], ast.If)
        or not isinstance(body[1], ast.Return)
    ):
        return False
    branch, returned = body
    expected = ast.parse(
        "if not callable(path_or_callable):\n"
        "    ret = import_string(path_or_callable)\n"
        "else:\n    ret = path_or_callable\nreturn ret\n"
    ).body
    return all(
        ast.dump(actual) == ast.dump(wanted)
        for actual, wanted in zip([branch, returned], expected)
    )


def property_default(owner):
    """Recognize an adapter property that returns a dotted setting name through self._setting and return its source nodes."""
    function = _property_default_method(owner)
    if function is None:
        return None
    row = _property_default_return(function)
    if row is None:
        return None
    return function, row[0], row[1], row[1].value


def _property_default_method(owner):
    if owner.decorator_list or owner.keywords:
        return None
    row = effective_method([(None, owner.name, owner)], "ADAPTER", {"property"})
    if row is None:
        return None
    function = row[1]
    if not single_return(function):
        return None
    return function


def _property_default_return(function):
    if not any(
        (isinstance(item, ast.Name) and item.id == "property")
        or (isinstance(item, ast.Attribute) and item.attr == "property")
        for item in function.decorator_list
    ):
        return None
    returns = [n for n in function.body if isinstance(n, ast.Return)]
    if len(returns) != 1 or not isinstance(returns[0].value, ast.Call):
        return None
    call = returns[0].value
    argument = _property_default_argument(call)
    return (returns[0], argument) if argument is not None else None


def _property_default_argument(call):
    if not (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "_setting"
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "self"
        and len(call.args) == 2
        and not call.keywords
        and isinstance(call.args[0], ast.Constant)
        and call.args[0].value == "ADAPTER"
        and isinstance(call.args[1], ast.Constant)
        and isinstance(call.args[1].value, str)
        and "." in call.args[1].value
    ):
        return None
    return call.args[1]


def method_rows(chain, index, imports):
    """Collect effective inherited methods and proof records only for methods with stable forwarding decorators."""
    rows, proofs = {}, {}
    for path, _, owner in chain:
        for node in owner.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            found = [
                (
                    decorator,
                    forwarding_definition(path, decorator, index, imports)
                    if _consumer_binding_stable(path, decorator, owner, index, imports)
                    else None,
                )
                for decorator in node.decorator_list
            ]
            allowed = {
                decorator.id
                for decorator, proof in found
                if isinstance(decorator, ast.Name) and proof
            }
            if effective_method(chain, node.name, allowed) == (path, node) and (
                not node.decorator_list or len(allowed) == len(node.decorator_list)
            ):
                rows[node.name] = (path, node, owner)
                if allowed:
                    proofs[node.name] = [proof for _, proof in found]
    return rows, proofs


def _consumer_binding_stable(path, decorator, owner, index, imports):
    if not isinstance(decorator, ast.Name):
        return False
    if not _consumer_module_binding_stable(path, decorator.id, index, imports):
        return False
    from .credential_role_constructor_provider import binding_occurrences

    return not binding_occurrences(owner.body, decorator.id)


def _consumer_module_binding_stable(path, name, index, imports):
    imported = imports.get(path, {}).get(name)
    if not imported or not imported[1]:
        return False
    tree = index.snapshots.get(path)
    if not isinstance(tree, ast.Module):
        return False
    from .credential_role_constructor_provider import binding_occurrences

    bindings = binding_occurrences(tree.body, name)
    if len(bindings) != 1 or not isinstance(bindings[0], ast.ImportFrom):
        return False
    item = next(
        (entry for entry in bindings[0].names if (entry.asname or entry.name) == name),
        None,
    )
    if item is None or item.name != imported[1]:
        return False
    return True


def forwarding_definition(path, decorator, index, imports):
    """Resolve an imported forwarding decorator to its source definition only when the import binding is stable."""
    if not isinstance(decorator, ast.Name):
        return None
    if not _consumer_module_binding_stable(path, decorator.id, index, imports):
        return None
    imported = imports.get(path, {}).get(decorator.id)
    if not imported or not imported[1]:
        return None
    return _decorator_target(path, imported, index)


def _decorator_target(path, imported, index):
    target_path, function = _source_function(imported, index)
    if function is None or not _transparent_forwarder(target_path, function, index):
        return None
    return target_path, function


def _source_function(imported, index):
    target_path, target_name = imported
    if not index.validate(target_path):
        return target_path, None
    tree = index.snapshots[target_path]
    rows = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == target_name
    ]
    if len(rows) != 1:
        return target_path, None
    function = rows[0]
    from .credential_role_constructor_provider import binding_occurrences

    if len(binding_occurrences(tree.body, target_name)) != 1:
        return target_path, None
    return target_path, function


def _transparent_forwarder(target_path, function, index):
    if _decorator_arguments(function) or function.decorator_list:
        return False
    nested, returns = _decorator_body(function)
    if nested is None:
        return False
    wrapper = nested
    if not _wrapper_arguments(wrapper):
        return False
    if len(wrapper.decorator_list) != 1 or not _wraps_func(
        target_path, wrapper.decorator_list[0], index
    ):
        return False
    if not _returns_wrapper(returns[0], wrapper):
        return False
    if len(wrapper.body) != 1 or not isinstance(wrapper.body[0], ast.Try):
        return False
    attempt = wrapper.body[0]
    if attempt.orelse or attempt.finalbody or not attempt.handlers:
        return False
    if not _try_forward(attempt, function, wrapper):
        return False
    if any(
        len(handler.body) != 1 or not isinstance(handler.body[0], ast.Raise)
        for handler in attempt.handlers
    ):
        return False
    return True


def _decorator_arguments(function):
    args = function.args
    return not (
        len(args.args) == 1
        and args.args[0].arg == "func"
        and not args.posonlyargs
        and not args.kwonlyargs
        and args.vararg is None
        and args.kwarg is None
        and not args.defaults
        and not args.kw_defaults
    )


def _decorator_body(function):
    body = [node for node in function.body if not _doc(node)]
    if (
        len(body) == 2
        and isinstance(body[0], ast.FunctionDef)
        and isinstance(body[1], ast.Return)
    ):
        return body[0], [body[1]]
    return None, []


def _doc(node):
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def _wrapper_arguments(wrapper):
    args = wrapper.args
    return bool(
        not args.posonlyargs
        and not args.args
        and not args.kwonlyargs
        and not args.defaults
        and not args.kw_defaults
        and args.vararg
        and args.vararg.arg == "args"
        and args.kwarg
        and args.kwarg.arg == "kwargs"
    )


def _returns_wrapper(statement, wrapper):
    return isinstance(statement.value, ast.Name) and statement.value.id == wrapper.name


def _try_forward(attempt, function, wrapper):
    if len(attempt.body) != 1 or not isinstance(attempt.body[0], ast.Return):
        return False
    from .credential_role_constructor_provider import binding_occurrences

    if any(
        binding_occurrences(wrapper.body, name)
        for name in (function.args.args[0].arg, "args", "kwargs")
    ):
        return False
    call = attempt.body[0].value
    return bool(
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == function.args.args[0].arg
        and len(call.args) == 1
        and isinstance(call.args[0], ast.Starred)
        and isinstance(call.args[0].value, ast.Name)
        and call.args[0].value.id == "args"
        and len(call.keywords) == 1
        and call.keywords[0].arg is None
        and isinstance(call.keywords[0].value, ast.Name)
        and call.keywords[0].value.id == "kwargs"
    )


def _wraps_func(path, decorator, index):
    from .review_audits import _module_security_aliases
    from .security_configuration import _canonical

    tree = index.snapshots[path]
    aliases = _module_security_aliases(tree)
    from .review_integrity import _security_flow_bindings
    from .semantic_credential_sensor import _provider_identity_uncertain

    lexical, _ = _security_flow_bindings(decorator, aliases)
    if _provider_identity_uncertain(tree, lexical, roots=("functools",)):
        return False
    return bool(
        isinstance(decorator, ast.Call)
        and _canonical(decorator, aliases) == "functools.wraps"
        and len(decorator.args) == 1
        and isinstance(decorator.args[0], ast.Name)
        and decorator.args[0].id == "func"
        and not decorator.keywords
    )


def enclosing_function(node, index, path):
    """Find the nearest enclosing function or async function through the validated parent index."""
    while node is not None:
        node = index.parents[path].get(id(node))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node
    return None


def is_parameter(function, name):
    """Confirm a name is a formal parameter with no competing binding in the function body."""
    from .credential_role_constructor_provider import binding_occurrences

    args = function.args
    parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    return name in {item.arg for item in parameters} and not binding_occurrences(
        function.body, name
    )


def returned_parameter(function, expression):
    """Resolve a direct unique local alias chain to one formal parameter."""

    aliases, seen = [], set()
    while isinstance(expression, ast.Name) and expression.id not in seen:
        seen.add(expression.id)
        if is_parameter(function, expression.id):
            return expression.id, aliases
        found = alias_value(expression, function)
        if found is None:
            break
        expression, assignment = found
        aliases.append(assignment)
    return None, []


def method_returns(function, index, path):
    """Return only the small supported set of direct, conditional, or try-body method returns."""
    rows = [node for node in ast.walk(function) if isinstance(node, ast.Return)]
    accepted = []
    for row in rows:
        parent = index.parents[path].get(id(row))
        if (
            parent is function
            or (
                isinstance(parent, ast.If)
                and index.parents[path].get(id(parent)) is function
            )
            or _try_body_return(row, function, index, path)
        ):
            accepted.append(row)
    if len(accepted) != len(rows) or not 1 <= len(rows) <= 2:
        return []
    return accepted


def _try_body_return(row, function, index, path):
    parent = index.parents[path].get(id(row))
    if (
        not isinstance(parent, ast.Try)
        or index.parents[path].get(id(parent)) is not function
    ):
        return False
    if parent.body != [row] or parent.orelse or parent.finalbody:
        return False
    return bool(parent.handlers) and all(
        _reraise_only(handler) for handler in parent.handlers
    )


def _reraise_only(handler):
    if not handler.body or not isinstance(handler.body[-1], ast.Raise):
        return False
    if handler.body[-1].exc is not None or handler.body[-1].cause is not None:
        return False
    for statement in handler.body[:-1]:
        if not _exception_metadata_assignment(statement, handler.name):
            return False
    return True


def _exception_metadata_assignment(statement, name):
    return bool(
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Attribute)
        and isinstance(statement.targets[0].value, ast.Name)
        and statement.targets[0].value.id == name
        and isinstance(statement.value, ast.Constant)
    )


def format_receiver(expression):
    """Return the receiver only for a keyword-expanded string format call with no positional arguments."""
    if not isinstance(expression, ast.Call) or not isinstance(
        expression.func, ast.Attribute
    ):
        return None
    if (
        expression.func.attr != "format"
        or expression.args
        or len(expression.keywords) != 1
    ):
        return None
    keyword = expression.keywords[0]
    return expression.func.value if keyword.arg is None else None


def verified_instance_receiver(node, function, owner, index, path, verified):
    """Validate an instance receiver directly, or require a proven decorated method with an unshadowed self parameter."""
    from .credential_role_constructor_provider import instance_receiver

    if not function.decorator_list:
        return instance_receiver(node, function, owner, index, path)
    return _verified_decorated_receiver(node, function, owner, index, path, verified)


def _verified_decorated_receiver(node, function, owner, index, path, verified):
    from .credential_role_constructor_provider import binding_occurrences

    if (
        not verified
        or owner is None
        or index.parents[path].get(id(function)) is not owner
    ):
        return False
    args = function.args
    positional = [*args.posonlyargs, *args.args]
    if not positional or positional[0].arg != "self":
        return False
    if binding_occurrences(function.body, "self"):
        return False
    return _verified_receiver_ancestry(node, function, index, path, args)


def _verified_receiver_ancestry(node, function, index, path, args):
    current = node
    while current is not function:
        current = index.parents[path].get(id(current))
        if current is None or isinstance(
            current,
            (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
        ):
            return False
    return not any(arg.arg == "self" for arg in args.kwonlyargs) and not (
        (args.vararg and args.vararg.arg == "self")
        or (args.kwarg and args.kwarg.arg == "self")
    )


def alias_value(expression, function):
    """Return a unique direct local assignment RHS and its source statement."""
    if not isinstance(expression, ast.Name):
        return None
    from .credential_role_constructor_provider import binding_occurrences

    rows = []
    for statement in function.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if isinstance(target, ast.Name) and target.id == expression.id:
            rows.append((statement, target))
    occurrences = binding_occurrences(function.body, expression.id)
    if len(rows) != 1 or len(occurrences) != 1 or occurrences[0] is not rows[0][1]:
        return None
    return rows[0][0].value, rows[0][0]


def cast_value(expression, path, aliases):
    """Return the value position only for canonical, exact typing.cast calls."""
    from .security_configuration import _canonical

    if (
        not isinstance(expression, ast.Call)
        or _canonical(expression, aliases[path]) != "typing.cast"
        or len(expression.args) != 2
        or expression.keywords
    ):
        return None
    return expression.args[1]


def source_current(index, path):
    """Check the cached source-current result for a path, recomputing it when the path has not been memoized."""
    memo = getattr(index, "class_chain_memo", None)
    checks = getattr(memo, "method_flow_source_checks", None)
    if memo is not None and callable(getattr(memo, "valid", None)):
        if checks is None:
            checks = {}
            memo.method_flow_source_checks = checks
        if path not in checks:
            checks[path] = _source_current(index, path)
        return checks[path]
    return _source_current(index, path)


def _source_current(index, path):
    if not index.validate(path):
        return False
    tree, raw = index.snapshots.get(path), index.source_bytes.get(path)
    digest = hashlib.sha256(raw).hexdigest() if isinstance(raw, bytes) else None
    if digest is None or index.inventory.get(path) != digest:
        return False
    if getattr(tree, "_oracle_source_sha256", None) != digest:
        return False
    try:
        return ast.dump(ast.parse(raw), include_attributes=True) == ast.dump(
            tree, include_attributes=True
        )
    except (SyntaxError, ValueError, TypeError, RecursionError, MemoryError):
        return False


def source_span(index, path, node, role):
    """Build a source-hop record from the indexed relative path, AST span, source digest, and role; this helper does not validate the path itself."""
    return {
        "path": index.relative(path),
        "line": node.lineno,
        "column": node.col_offset,
        "end_line": getattr(node, "end_lineno", node.lineno),
        "end_column": getattr(node, "end_col_offset", node.col_offset),
        "source_sha256": hashlib.sha256(index.source_bytes[path]).hexdigest(),
        "role": role,
    }


def _bound_module_settings(statement):
    from .review_audits import _bound_names

    names = _bound_names(statement)
    names.update(
        n.name
        for n in ast.walk(statement)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )
    return names


def _returns(function):
    return [node for node in function.body if isinstance(node, ast.Return)]


def _hook_return(node):
    return bool(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) == 2
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "_app_settings"
        and isinstance(node.args[1], ast.Name)
        and node.args[1].id == "name"
    )


def settings_module_bridge(snapshots, settings_path, owner, module_binding):
    """Prove the module-level AppSettings and _app_settings bridge shape, returning its hook and assignment or None."""
    tree = snapshots.get(settings_path)
    if not isinstance(tree, ast.Module) or owner.name != "AppSettings":
        return None
    if not _settings_bridge_class(tree, owner, module_binding):
        return None
    hook = module_binding(tree, "__getattr__", (ast.FunctionDef, ast.AsyncFunctionDef))
    assignments = _settings_bridge_assignment(tree)
    if not _settings_bridge_hook(hook):
        return None
    if not _settings_bridge_assignment_binding(tree, assignments, module_binding):
        return None
    assignment = assignments[0]
    if not _settings_bridge_constructor(assignment.value, owner):
        return None
    return _settings_bridge_return(tree, hook, assignment)


def _settings_bridge_class(tree, owner, module_binding):
    classes = [
        item
        for item in tree.body
        if isinstance(item, ast.ClassDef) and item.name == owner.name
    ]
    if (
        len(classes) != 1
        or classes[0] is not owner
        or module_binding(tree, owner.name, ast.ClassDef) is not owner
        or owner.decorator_list
        or owner.keywords
    ):
        return False
    return True


def _settings_bridge_assignment(tree):
    assignments = [
        item
        for item in tree.body
        if isinstance(item, ast.Assign)
        and len(item.targets) == 1
        and isinstance(item.targets[0], ast.Name)
        and item.targets[0].id == "_app_settings"
    ]
    return assignments


def _settings_bridge_hook(hook):
    if (
        not isinstance(hook, ast.FunctionDef)
        or hook.decorator_list
        or [arg.arg for arg in hook.args.args] != ["name"]
        or hook.args.posonlyargs
        or hook.args.kwonlyargs
        or hook.args.vararg
        or hook.args.kwarg
    ):
        return False
    return True


def _settings_bridge_assignment_binding(tree, assignments, module_binding):
    return (
        len(assignments) == 1
        and module_binding(tree, "_app_settings", ast.Assign) is assignments[0]
    )


def _settings_bridge_constructor(call, owner):
    return bool(
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == owner.name
        and len(call.args) == 1
        and not call.keywords
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
    )


def _settings_bridge_return(tree, hook, assignment):
    returns = _returns(hook)
    from .credential_role_paths import single_return

    if not single_return(hook):
        return None
    if len(returns) != 1 or not _hook_return(returns[0].value):
        return None
    from .credential_role_constructor_provider import binding_occurrences

    if binding_occurrences(tree.body, "getattr"):
        return None
    return hook, assignment


def module_binding(tree, name, kind):
    """Return the unique top-level binding statement of the requested kind, or None when absent or ambiguous."""
    from .credential_role_constructor_provider import binding_statements

    rows = binding_statements(tree.body, name)
    return rows[0] if len(rows) == 1 and isinstance(rows[0], kind) else None


def _doc(node):
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def fallback_method(function):
    """Recognize the exact un-decorated settings fallback method shape and return its lookup nodes only when names and branches are stable."""
    shape = _fallback_rows(function)
    return _fallback_attempt(shape, function) if shape else None


def _fallback_rows(function):
    if function is None or function.decorator_list:
        return None
    if [arg.arg for arg in function.args.args][:3] != ["self", "name", "default"]:
        return None
    rows = [node for node in function.body if not _doc(node)]
    loops = [node for node in rows if isinstance(node, ast.For)]
    returns = [node for node in ast.walk(function) if isinstance(node, ast.Return)]
    if len(rows) != 4 or len(loops) != 1 or len(returns) != 2:
        return None
    if not _names_prep(rows[0]) or not _backend_prefix(rows[1]):
        return None
    if not _stable_names(function):
        return None
    return rows, loops[0]


def _fallback_attempt(shape, function):
    rows, loop = shape
    final = rows[-1]
    if (
        not isinstance(final, ast.Return)
        or not isinstance(final.value, ast.Name)
        or final.value.id != "default"
    ):
        return None
    attempt = _lookup_attempt(loop)
    return (loop, attempt, final) if attempt else None


def _names_prep(node):
    return bool(
        isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "names"
        and isinstance(node.value, ast.List)
        and bool(node.value.elts)
    )


def _backend_prefix(node):
    return bool(
        isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "backend"
        and len(node.body) == 1
        and not node.orelse
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Call)
        and isinstance(node.body[0].value.func, ast.Attribute)
        and isinstance(node.body[0].value.func.value, ast.Name)
        and node.body[0].value.func.value.id == "names"
        and node.body[0].value.func.attr == "insert"
        and len(node.body[0].value.args) == 2
        and isinstance(node.body[0].value.args[0], ast.Constant)
        and node.body[0].value.args[0].value == 0
        and not node.body[0].value.keywords
    )


def _stable_names(function):
    if any(
        isinstance(target, ast.Subscript)
        and isinstance(target.value, ast.Name)
        and target.value.id == "names"
        for node in ast.walk(function)
        for target in _assignment_targets(node)
    ):
        return False
    writes = {
        name: [
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, ast.Store)
        ]
        for name in ("names", "name", "default", "backend")
    }
    initial = next(
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "names"
    )
    return (
        len(writes["names"]) == 1
        and writes["names"][0] is initial.targets[0]
        and all(not writes[name] for name in ("name", "default", "backend"))
        and _default_only_falls_through(function)
    )


def _default_only_falls_through(function):
    defaults = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and node.id == "default"
        and isinstance(node.ctx, ast.Load)
    ]
    returns = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Return)
        and isinstance(node.value, ast.Name)
        and node.value.id == "default"
    ]
    return len(defaults) == len(returns) == 1 and defaults[0] is returns[0].value


def _assignment_targets(node):
    if isinstance(node, ast.Assign):
        return node.targets
    if isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
        return [node.target]
    return []


def _lookup_attempt(loop):
    if not isinstance(loop.target, ast.Name) or not isinstance(loop.iter, ast.Name):
        return None
    if loop.orelse or (
        loop.iter.id != "names"
        or len(loop.body) != 1
        or not isinstance(loop.body[0], ast.Try)
    ):
        return None
    attempt = loop.body[0]
    if len(attempt.body) != 1 or not isinstance(attempt.body[0], ast.Return):
        return None
    call = attempt.body[0].value
    handlers = attempt.handlers
    if (
        not isinstance(call, ast.Call)
        or len(call.args) != 1
        or len(handlers) != 1
        or attempt.orelse
        or attempt.finalbody
    ):
        return None
    if not (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "self"
        and call.func.attr == "get_setting"
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == loop.target.id
        and not call.keywords
    ):
        return None
    caught = (
        handlers[0].type.elts
        if isinstance(handlers[0].type, ast.Tuple)
        else [handlers[0].type]
    )
    if {ast.unparse(item) for item in caught} != {"AttributeError", "KeyError"}:
        return None
    if len(handlers[0].body) != 1 or not isinstance(handlers[0].body[0], ast.Pass):
        return None
    return attempt


def trace_call(flow, expression, function, path, seen, depth, bindings=None):
    """Trace values through verified typing casts, declared setting defaults, or return-call flow, adding source hops only along a bounded path."""
    from .semantic_credential_sensor import _provider_identity_uncertain

    from .credential_role_paths import cast_value
    from .credential_role_paths import setting_default

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
    """Trace returned method values through a bound caller parameter or the accepted string-format receiver path."""
    from .credential_role_constructor_provider import scope_class
    from .credential_role_paths import format_receiver, returned_parameter

    returned = row.value
    parameter_name, aliases = returned_parameter(function, returned)
    if parameter_name is not None:
        return _trace_bound_parameter(
            flow,
            expression,
            row_path,
            function,
            caller,
            caller_path,
            seen,
            depth,
            caller_bindings,
            parameter_name,
            aliases,
            scope_class,
        )
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


def _trace_bound_parameter(
    flow,
    expression,
    row_path,
    function,
    caller,
    caller_path,
    seen,
    depth,
    caller_bindings,
    parameter_name,
    aliases,
    scope_class,
):
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
    """Trace a method parameter back through candidate calls, preserving verified decorator and argument-binding hops."""
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


_default_getter = default_getter


def _returns(function):
    return [node for node in function.body if isinstance(node, ast.Return)]


def _bound_setting_boundary(statement):
    from .review_audits import _bound_names

    return _bound_names(statement)


def _module_binding(tree, name, kind):
    from .credential_role_constructor_provider import binding_statements

    rows = binding_statements(tree.body, name)
    return rows[0] if len(rows) == 1 and isinstance(rows[0], kind) else None


def _setting_getter_shape(snapshots):
    matches = []
    for path, tree in snapshots.items():
        if not isinstance(tree, ast.Module):
            continue
        function = _module_binding(
            tree, "get_setting", (ast.FunctionDef, ast.AsyncFunctionDef)
        )
        if (
            not isinstance(function, ast.FunctionDef)
            or function.args.vararg
            or function.args.kwarg
            or not getter_environment(tree, function)
        ):
            continue
        if [arg.arg for arg in function.args.args] != [
            "name",
            "dflt",
        ] or function.args.posonlyargs:
            continue
        assignments = [
            node
            for node in function.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Call)
        ]
        getter_rows = [row for row in assignments if row.targets[0].id == "getter"]
        if len(getter_rows) != 2 or not _default_getter(getter_rows[0].value):
            continue
        binding_rows = [
            row for row in function.body if "getter" in _bound_setting_boundary(row)
        ]
        if binding_rows != getter_rows:
            continue
        if not _import_callable(getter_rows[1].value):
            continue
        returns = _returns(function)
        if len(returns) != 1 or not _getter_return(returns[0].value):
            continue
        if len(assignments) != 2 or not _only_setting_statements(
            function, assignments, returns[0]
        ):
            continue
        matches.append((path, function))
    return matches[0] if len(matches) == 1 else None


def _import_callable(node):
    return bool(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "import_callable"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "getter"
    )


def _getter_return(node):
    return bool(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getter"
        and len(node.args) == 2
        and not node.keywords
        and all(isinstance(arg, ast.Name) for arg in node.args)
        and [arg.id for arg in node.args] == ["name", "dflt"]
    )


def _only_setting_statements(function, assignments, returned):
    useful = {id(row) for row in assignments} | {id(returned)}
    rows = [node for node in function.body if not _docstring(node)]
    return len(rows) == 3 and all(id(row) in useful for row in rows)


def _docstring(node):
    return bool(
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def _setting_boundary_method(root, settings_path, owner, getter_shape, aliases):
    row = effective_method([(settings_path, owner.name, owner)], "_setting")
    if row is None or row[0] != settings_path:
        return None
    function = row[1]
    args = function.args
    if function.decorator_list or [arg.arg for arg in args.args] != [
        "self",
        "name",
        "dflt",
    ]:
        return None
    if args.posonlyargs or args.kwonlyargs or args.vararg or args.kwarg:
        return None
    returns = _returns(function)
    if len(returns) != 1 or not isinstance(returns[0].value, ast.Call):
        return None
    statements = [node for node in function.body if not _docstring(node)]
    if len(statements) != 2 or any(
        not isinstance(node, (ast.ImportFrom, ast.Return)) for node in statements
    ):
        return None
    call = returns[0].value
    from .security_configuration import _canonical

    getter_path, _ = getter_shape
    canonical_module = _path_module(root, getter_path)
    if _canonical(call, aliases) != canonical_module + ".get_setting":
        return None
    if len(call.args) != 2 or call.keywords:
        return None
    first, second = call.args
    if not (
        isinstance(first, ast.BinOp)
        and isinstance(first.op, ast.Add)
        and isinstance(first.left, ast.Attribute)
        and isinstance(first.left.value, ast.Name)
        and first.left.value.id == "self"
        and first.left.attr == "prefix"
        and isinstance(first.right, ast.Name)
        and first.right.id == "name"
        and isinstance(second, ast.Name)
        and second.id == "dflt"
    ):
        return None
    imports = [node for node in statements if isinstance(node, ast.ImportFrom)]
    if (
        len(imports) != 1
        or imports[0].module != canonical_module
        or not any(
            item.name == "get_setting" and item.asname in {None, "get_setting"}
            for item in imports[0].names
        )
    ):
        return None
    return function, call, getter_path, getter_shape[1]


def _path_module(root, path):
    parts = path.relative_to(root).as_posix().split("/")
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    else:
        parts[-1] = parts[-1].removesuffix(".py")
    return ".".join(parts)


def setting_boundary_nodes(index, snapshots, settings_path, owner, aliases):
    """Return source nodes for the declared setting bridge, or None if uncertain."""
    from .credential_role_paths import settings_module_bridge

    getter_shape = _setting_getter_shape(snapshots)
    bridge = settings_module_bridge(snapshots, settings_path, owner, _module_binding)
    method = (
        _setting_boundary_method(
            index.root, settings_path, owner, getter_shape, aliases
        )
        if getter_shape
        else None
    )
    if not getter_shape or not bridge or not method:
        return None
    hook, instance = bridge
    setting, call, getter_path, getter = method
    return {
        "module_getattr": (settings_path, hook),
        "settings_instance": (settings_path, instance),
        "setting_method": (settings_path, setting),
        "setting_transfer": (settings_path, call),
        "get_setting": (getter_path, getter),
    }


def module_path(index, module):
    """Resolve a dotted module name to a captured .py or package initializer path."""
    stem = module.replace(".", "/")
    for suffix in (".py", "/__init__.py"):
        path = index.root / (stem + suffix)
        if path in index.snapshots:
            return path
    return None


def module_name(index, path):
    """Convert a captured source path to a dotted module name, returning None for paths outside the root."""
    relative = index.relative(path)
    if not relative:
        return None
    return relative.removesuffix(".py").replace("/", ".").removesuffix(".__init__")


def source_hop(index, path, node, role):
    """Build source-hashed provenance for a validated node and role, returning None for missing or stale source."""
    if node is None or not index.validate(path):
        return None
    return {
        "path": index.relative(path),
        "line": node.lineno,
        "column": node.col_offset,
        "end_line": getattr(node, "end_lineno", node.lineno),
        "end_column": getattr(node, "end_col_offset", node.col_offset),
        "source_sha256": hashlib.sha256(index.source_bytes[path]).hexdigest(),
        "role": role,
    }


def _doc(node):
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def _strategy_setting_method(function):
    if function is None or function.decorator_list:
        return None
    rows = [node for node in function.body if not _doc(node)]
    if len(rows) != 1 or not isinstance(rows[0], ast.Return):
        return None
    call = rows[0].value
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
        return None
    target = call.func
    if not isinstance(target.value, ast.Attribute) or not isinstance(
        target.value.value, ast.Name
    ):
        return None
    if (target.value.value.id, target.value.attr, target.attr) != (
        "self",
        "strategy",
        "setting",
    ):
        return None
    if (
        len(call.args) != 1
        or not isinstance(call.args[0], ast.Name)
        or call.args[0].id != "name"
    ):
        return None
    keywords = {item.arg: item.value for item in call.keywords}
    if set(keywords) != {"default", "backend"}:
        return None
    if (
        not isinstance(keywords["default"], ast.Name)
        or keywords["default"].id != "default"
    ):
        return None
    if (
        not isinstance(keywords["backend"], ast.Name)
        or keywords["backend"].id != "self"
    ):
        return None
    return rows[0], call


def _typed_strategy(index, path, names, classes):
    tree = index.snapshots.get(path)
    if not isinstance(tree, ast.Module):
        return None
    found = [
        target
        for guard in tree.body
        if _type_checking_guard(guard)
        for node in ast.walk(guard)
        if isinstance(node, ast.ImportFrom)
        for target in _strategy_import_targets(index, path, node, names, classes)
    ]
    return found[0] if len(set(found)) == 1 else None


def _type_checking_guard(node):
    return bool(
        isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "TYPE_CHECKING"
    )


def _strategy_import_targets(index, path, node, names, classes):
    module = "." * node.level + (node.module or "")
    try:
        resolved = resolve_name(module, _package(index, path)) if node.level else module
    except ImportError:
        return []
    return [
        (target, item.name)
        for item in node.names
        if (item.asname or item.name) in names
        for target in _class_module_paths(index, resolved, item.name, classes)
    ]


def _class_module_paths(index, module, name, classes):
    base = module.replace(".", "/")
    return [
        target
        for suffix in (".py", "/__init__.py")
        if (target := index.root / (base + suffix), name) in classes
    ]


def _package(index, path):
    relative = index.relative(path)
    return ".".join(relative.removesuffix(".py").split("/")[:-1]) if relative else ""


def _strategy_assignment(function, argument):
    matches = []
    for node in ast.walk(function):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Attribute):
            continue
        target, value = targets[0], node.value
        if (
            not isinstance(target.value, ast.Name)
            or target.value.id != "self"
            or target.attr != "strategy"
        ):
            continue
        test = value.test if isinstance(value, ast.IfExp) else None
        if (
            isinstance(value, ast.IfExp)
            and isinstance(value.body, ast.Name)
            and value.body.id == argument.arg
            and isinstance(test, ast.Compare)
            and isinstance(test.left, ast.Name)
            and test.left.id == argument.arg
            and len(test.ops) == len(test.comparators) == 1
            and isinstance(test.ops[0], ast.IsNot)
            and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value is None
        ):
            matches.append(node)
    writes = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Attribute)
        and node.attr == "strategy"
        and isinstance(node.ctx, ast.Store)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    ]
    return matches[0] if len(matches) == len(writes) == 1 else None


def setting_default(expression, chain, index, classes):
    """Return source default plus evidence nodes only for the verified strategy route."""
    route = _setting_default_route(expression, chain, index, classes)
    if route is None:
        return None
    row, forward, init, initializer, strategy, verified = route
    from .review_integrity import bind_source_call

    try:
        bound = bind_source_call(
            expression, row[1], ast.Name("_self", ast.Load()), apply_defaults=False
        )
    except (TypeError, ValueError):
        return None
    default = bound.get("default")
    return (
        (
            default,
            [
                (row[0], forward[1], "declared_setting_default_forward"),
                (init[0], initializer, "nominal_strategy_annotation"),
                (strategy[0], verified[1], "strategy_lookup_fallback"),
            ],
        )
        if default is not None
        else None
    )


def _setting_default_route(expression, chain, index, classes):
    if not isinstance(expression, ast.Call) or not isinstance(
        expression.func, ast.Attribute
    ):
        return None
    if (
        not isinstance(expression.func.value, ast.Name)
        or expression.func.value.id != "self"
        or expression.func.attr != "setting"
    ):
        return None
    row = effective_method(chain, "setting")
    init = effective_method(chain, "__init__")
    if row is None or init is None:
        return None
    strategy_route = _setting_strategy_route(row, init, index, classes)
    if strategy_route is None:
        return None
    forward, initializer, strategy, verified = strategy_route
    return row, forward, init, initializer, strategy, verified


def _setting_strategy_route(row, init, index, classes):
    forward = _strategy_setting_method(row[1])
    initializer = init[1]
    arg = next((item for item in initializer.args.args if item.arg == "strategy"), None)
    if forward is None or arg is None or arg.annotation is None:
        return None
    if _strategy_assignment(initializer, arg) is None:
        return None
    names = {item.id for item in ast.walk(arg.annotation) if isinstance(item, ast.Name)}
    target = _typed_strategy(index, init[0], names, classes)
    if target is None or not index.validate(target[0]):
        return None
    return _resolved_strategy(index, classes, target, initializer, forward)


def _resolved_strategy(index, classes, target, initializer, forward):
    owner = classes[target]
    strategy = effective_method([(target[0], target[1], owner)], "setting")
    verified = fallback_method(strategy[1]) if strategy else None
    if verified is None:
        return None
    return forward, initializer, strategy, verified


_property_default = property_default
_module_name = module_name
_module_path = module_path
_hop = source_hop


def _returns(function):
    return [node for node in function.body if isinstance(node, ast.Return)]


def _get_adapter(path, tree, aliases, imports, expected_settings_path):
    from .security_configuration import _canonical
    from .credential_role_constructor_provider import binding_statements

    bindings = binding_statements(tree.body, "get_adapter")
    if len(bindings) != 1 or not isinstance(bindings[0], ast.FunctionDef):
        return None
    matches = []
    for function in tree.body:
        if (
            not isinstance(function, ast.FunctionDef)
            or function.name != "get_adapter"
            or function.decorator_list
        ):
            continue
        returns = _returns(function)
        if len(returns) != 1 or not isinstance(returns[0].value, ast.Call):
            continue
        outer = returns[0].value
        inner = outer.func
        if not isinstance(inner, ast.Call) or not isinstance(outer.func, ast.Call):
            continue
        if not (
            isinstance(inner.func, (ast.Name, ast.Attribute)) and len(inner.args) == 1
        ):
            continue
        canonical_import = _canonical(inner, aliases)
        source = inner.args[0]
        imported = (
            imports.get(path, {}).get(source.value.id)
            if isinstance(source, ast.Attribute) and isinstance(source.value, ast.Name)
            else None
        )
        if (
            canonical_import == "django.utils.module_loading.import_string"
            and isinstance(source, ast.Attribute)
            and source.attr == "ADAPTER"
            and imported
            and imported[0] == expected_settings_path
            and len(outer.args) == 1
            and not outer.keywords
        ):
            matches.append((function, returns[0], inner))
    return matches[0] if len(matches) == 1 else None


def _declared_default(index, snapshots):
    defaults = []
    for path, tree in snapshots.items():
        if not isinstance(tree, ast.Module):
            continue
        from .credential_role_constructor_provider import binding_occurrences

        if binding_occurrences(tree.body, "property"):
            continue
        for owner in (node for node in tree.body if isinstance(node, ast.ClassDef)):
            found = _property_default(owner)
            if found:
                module, name = found[-1].rsplit(".", 1)
                target_path = _module_path(index, module)
                target = snapshots.get(target_path)
                owners = (
                    [
                        n
                        for n in target.body
                        if isinstance(n, ast.ClassDef) and n.name == name
                    ]
                    if isinstance(target, ast.Module)
                    else []
                )
                if len(owners) == 1 and effective_method(
                    [(target_path, name, owners[0])], "get_requests_session"
                ):
                    defaults.append((path, owner, *found))
    getter_shape = _setting_getter_shape(snapshots)
    if len(defaults) != 1 or getter_shape is None:
        return None
    settings_path, settings_owner, prop, prop_return, literal, default = defaults[0]
    module, class_name = default.rsplit(".", 1)
    adapter_path = _module_path(index, module)
    settings_module = _module_name(index, settings_path)
    if adapter_path is None or settings_module is None:
        return None
    getter_path, getter_function = getter_shape
    return (
        settings_path,
        prop,
        prop_return,
        literal,
        default,
        module,
        class_name,
        adapter_path,
        settings_module,
        getter_path,
        getter_function,
        settings_owner,
    )


def _selected_adapter(index, snapshots, imports, classes, aliases, audit, selected):
    (
        settings_path,
        _,
        _,
        _,
        _,
        module,
        class_name,
        adapter_path,
        settings_module,
        getter_path,
        getter_function,
        _,
    ) = selected
    adapter_tree = snapshots.get(adapter_path)
    if not isinstance(adapter_tree, ast.Module):
        return None
    getter = _get_adapter(
        adapter_path, adapter_tree, aliases[adapter_path], imports, settings_path
    )
    if getter is None or (adapter_path, class_name) not in classes:
        return None
    owner = classes.get((adapter_path, class_name))
    method_row = effective_method(
        [(adapter_path, class_name, owner)] if owner is not None else (),
        "get_requests_session",
    )
    if method_row is None:
        return None
    factory_path, factory = method_row
    factory_record = session_factory_witness(
        factory_path, factory, index, aliases[factory_path]
    )
    if factory_record is None or _module_name(index, adapter_path) != module:
        return None
    _, getter_return, import_call = getter
    return (
        factory_record,
        factory_path,
        factory,
        getter_path,
        getter_function,
        adapter_path,
        getter_return,
        import_call,
    )


def default_session_evidence(index, snapshots, imports, classes, aliases, audit):
    """Bind the declared default class to its validated Session factory summary."""
    selected = _declared_default(index, snapshots)
    if selected is None:
        return None
    settings_path, settings_owner = selected[0], selected[-1]
    boundary = setting_boundary_nodes(
        index, snapshots, settings_path, settings_owner, aliases[settings_path]
    )
    if boundary is None:
        return None
    defaulted = _selected_adapter(
        index, snapshots, imports, classes, aliases, audit, selected
    )
    if defaulted is None:
        return None
    (
        factory_record,
        factory_path,
        factory,
        getter_path,
        getter_function,
        adapter_path,
        getter_return,
        import_call,
    ) = defaulted
    settings_path, prop, prop_return, _, _, _, _, _, _, _, _, _ = selected
    path_module = _module_name(index, adapter_path)
    hops = [
        _hop(index, settings_path, prop, "declared_default_adapter"),
        _hop(index, settings_path, prop_return, "settings_default_transfer"),
        _hop(index, *boundary["module_getattr"], "settings_module_getattr"),
        _hop(index, *boundary["settings_instance"], "settings_module_instance"),
        _hop(index, *boundary["setting_method"], "settings_get_setting_transfer"),
        _hop(index, *boundary["setting_transfer"], "settings_get_setting_call"),
        _hop(index, *boundary["get_setting"], "runtime_setting_override"),
        _hop(index, getter_path, getter_function, "runtime_setting_override_boundary"),
        _hop(index, adapter_path, getter_return, "adapter_factory_selection"),
        _hop(index, adapter_path, import_call, "default_adapter_import"),
        *factory_record["hops"],
    ]
    if not all(hops):
        return None
    return {
        "provider": factory_record["provider"],
        "profile": "DECLARED_DEFAULT_MAY_FLOW",
        "get_adapter_canonical": path_module + ".get_adapter",
        "runtime_setting_getter": "UNASSESSED",
        "runtime_adapter_override": "UNASSESSED",
        "hops": hops,
    }


_current = source_current
_span = source_span


class _Flow:
    def __init__(
        self,
        fact,
        chain,
        index,
        imports,
        classes,
        aliases,
        audit,
        integrity,
        blocked_choices=frozenset(),
        method_table=None,
    ):
        self.fact, self.chain, self.index = fact, chain, index
        self.imports = imports
        self.classes = classes
        self.aliases = aliases
        self.audit = audit
        self.integrity = integrity
        self.blocked_choices = blocked_choices
        self.branch_choices = []
        self.methods, self.decorator_proofs = method_table or method_rows(
            chain, index, imports
        )

    def trace(
        self, expression, function, path, seen=frozenset(), depth=0, bindings=None
    ):
        """Trace an expression through declared facts, aliases, calls, and boolean branches with a depth limit and validated snapshots."""
        if depth > 8 or not self.index.validate(path):
            return None
        marker = (path, id(function), id(expression))
        if marker in seen:
            return None
        seen = seen | {marker}
        if matches_fact(
            self.fact,
            path,
            expression,
            self.index,
            self.imports,
            self.classes,
            self.audit,
        ):
            return [(path, expression, "declared_member_read")]
        if isinstance(expression, ast.Name):
            return self._trace_name(expression, function, path, seen, depth, bindings)
        if isinstance(expression, ast.Call):
            return trace_call(self, expression, function, path, seen, depth, bindings)
        if isinstance(expression, ast.BoolOp):
            return self._trace_boolean(
                expression, function, path, seen, depth, bindings
            )
        return None

    def _trace_name(self, expression, function, path, seen, depth, bindings):
        if is_parameter(function, expression.id):
            if bindings is not None:
                context = bindings.get(expression.id)
                if context is None:
                    return None
                actual, caller, caller_path, parent_bindings = context
                return self.trace(
                    actual, caller, caller_path, seen, depth + 1, parent_bindings
                )
            return self._call_argument(expression.id, function, seen, depth)
        alias = alias_value(expression, function)
        if alias:
            found = self.trace(alias[0], function, path, seen, depth + 1, bindings)
            return self._prepend("unique_local_alias", path, alias[1], found)
        return None

    def _trace_boolean(self, expression, function, path, seen, depth, bindings):
        if not isinstance(expression.op, ast.Or):
            return None
        for offset, operand in enumerate(expression.values):
            choice = ("boolean", id(expression), offset)
            if choice in self.blocked_choices:
                continue
            found = self.trace(operand, function, path, seen, depth + 1, bindings)
            if found:
                self.branch_choices.append(choice)
                found = self._prepend("declared_boolean_operand", path, operand, found)
                return self._prepend(
                    "declared_boolean_value_choice", path, expression, found
                )
            if isinstance(operand, ast.Constant) and bool(operand.value):
                break
        return None

    def _return_call(self, expression, caller, caller_path, seen, depth, bindings=None):
        target = expression.func
        if (
            not isinstance(target, ast.Attribute)
            or not isinstance(target.value, ast.Name)
            or target.value.id != "self"
        ):
            return None
        row = self.methods.get(target.attr)
        if row is None:
            return None
        receiver_owner = scope_class(expression, self.index, caller_path)
        if receiver_owner is None or not verified_instance_receiver(
            expression,
            caller,
            receiver_owner,
            self.index,
            caller_path,
            bool(self.decorator_proofs.get(caller.name)),
        ):
            return None
        path, function, _ = row
        returns = method_returns(function, self.index, path)
        if not returns:
            return None
        from .credential_role_paths import _callee_bindings

        callee_bindings = _callee_bindings(
            self, expression, function, caller, caller_path, bindings
        )
        if callee_bindings is None:
            return None
        traces = []
        for row in returns:
            choice = ("return", id(expression), id(row))
            if choice in self.blocked_choices:
                continue
            traced = trace_return(
                self,
                row,
                expression,
                path,
                function,
                caller,
                caller_path,
                seen,
                depth,
                bindings,
                callee_bindings,
            )
            if traced:
                self.branch_choices.append(choice)
                traces = self._prepend("declared_method_return", path, row, traced)
                break
        found = traces or None
        for proof_path, proof_function in self.decorator_proofs.get(target.attr, ()):
            found = self._prepend(
                "verified_return_preserving_decorator",
                proof_path,
                proof_function,
                found,
            )
        return self._prepend("method_call", caller_path, expression, found)

    def _call_argument(self, name, function, seen, depth):
        return call_argument(self, name, function, seen, depth)

    @staticmethod
    def _prepend(role, path, node, found):
        return [(path, node, role), *found] if found else None


def method_url_hops(
    fact,
    sink_path,
    call,
    expression,
    index,
    imports,
    classes,
    aliases,
    audit,
    integrity,
):
    """Trace URL arguments through source-defined self-method returns/calls."""
    from .security_configuration import _keyword
    from .semantic_credential_sensor import _canonical_http_call

    if sink_path not in aliases or _canonical_http_call(
        call, aliases[sink_path]
    ) not in {"requests.request", "httpx.request"}:
        return None
    if _keyword(call, "url", 1) is not expression:
        return None
    route = _method_url_route(
        fact, sink_path, call, index, imports, classes, aliases, audit
    )
    if route is None:
        return None
    chain, function = route
    traced = _Flow(
        fact, chain, index, imports, classes, aliases, audit, integrity
    ).trace(expression, function, sink_path)
    if not traced:
        return None
    hops = [
        {
            "path": fact.path,
            "line": fact.line,
            "column": fact.column,
            "end_line": fact.end_line,
            "end_column": fact.end_column,
            "source_sha256": fact.source_sha256,
            "role": "declared_literal",
        }
    ]
    for path, node, role in reversed(traced):
        if not index.validate(path):
            return None
        hops.append(_span(index, path, node, role))
    hops.append(_span(index, sink_path, call, "canonical_http_url_sink"))
    return hops


def _method_url_route(fact, sink_path, call, index, imports, classes, aliases, audit):
    if not _current(index, sink_path):
        return None
    source_path = index.root / fact.path
    chain = class_chain(index, source_path, fact.owner, imports, classes, audit)
    if chain is None or any(not _current(index, path) for path, _, _ in chain):
        return None
    owner, function = (
        scope_class(call, index, sink_path),
        enclosing_function(call, index, sink_path),
    )
    if not chain or owner is None or function is None:
        return None
    if (sink_path, owner.name) not in {(path, name) for path, name, _ in chain}:
        return None
    if effective_method(chain, function.name) != (sink_path, function):
        return None
    return chain, function


_MAX_STATES = 128
_MAX_PATHS = 32


def method_url_hop_paths(
    fact,
    sink_path,
    call,
    expression,
    index,
    imports,
    classes,
    aliases,
    audit,
    integrity,
):
    """Return distinct caller/branch paths; status concerns enumeration only."""
    from .security_configuration import _keyword
    from .semantic_credential_sensor import _canonical_http_call

    if sink_path not in aliases or _canonical_http_call(
        call, aliases[sink_path]
    ) not in {"requests.request", "httpx.request"}:
        return _result("INCOMPLETE", [], "unsupported_sink")
    if _keyword(call, "url", 1) is not expression:
        return _result("INCOMPLETE", [], "unsupported_url_binding")
    if not source_current(index, sink_path):
        return _result("INCOMPLETE", [], "stale_sink_source")
    source_path = index.root / fact.path
    chain = _chain(fact, source_path, index, imports, classes, audit)
    if not chain:
        return _result("INCOMPLETE", [], "unresolved_class_chain")
    owner, function = (
        scope_class(call, index, sink_path),
        enclosing_function(call, index, sink_path),
    )
    if not _sink_method(chain, owner, function, sink_path):
        return _result("INCOMPLETE", [], "unresolved_sink_method")
    return _enumerate(
        fact,
        chain,
        index,
        imports,
        classes,
        aliases,
        audit,
        integrity,
        sink_path,
        call,
        expression,
        function,
    )


def _chain(fact, source_path, index, imports, classes, audit):
    from .credential_role_constructor_provider import class_chain

    if not source_current(index, source_path):
        return None
    chain = class_chain(index, source_path, fact.owner, imports, classes, audit)
    if chain is None or any(not source_current(index, path) for path, _, _ in chain):
        return None
    return chain


def _sink_method(chain, owner, function, sink_path):
    return bool(
        chain
        and owner
        and function
        and (sink_path, owner.name) in {(path, name) for path, name, _ in chain}
        and effective_method(chain, function.name) == (sink_path, function)
    )


def _enumerate(
    fact,
    chain,
    index,
    imports,
    classes,
    aliases,
    audit,
    integrity,
    sink_path,
    call,
    expression,
    function,
):
    memo = getattr(index, "class_chain_memo", None)
    shared_methods = None
    deferred = bool(
        memo is not None and memo.defers_validation(index, imports, classes, audit)
    )
    if memo is not None:
        if not callable(getattr(memo, "valid", None)) or (
            not deferred and not memo.valid()
        ):
            return _result("INCOMPLETE", [], "snapshot_revalidation_failed")
        shared_methods = method_rows(chain, index, imports)
    pending, seen_states, seen_paths, paths = [frozenset()], set(), set(), []
    while pending and len(seen_states) < _MAX_STATES and len(paths) < _MAX_PATHS:
        blocked = pending.pop(0)
        if blocked in seen_states:
            continue
        seen_states.add(blocked)
        flow = _Flow(
            fact,
            chain,
            index,
            imports,
            classes,
            aliases,
            audit,
            integrity,
            blocked,
            shared_methods,
        )
        traced = flow.trace(expression, function, sink_path)
        if traced:
            path = _format_path(fact, traced, sink_path, call, index)
            key = tuple((r["path"], r["line"], r["column"], r["role"]) for r in path)
            if key not in seen_paths:
                seen_paths.add(key)
                paths.append(path)
        for choice in flow.branch_choices:
            candidate = blocked | {choice}
            if candidate not in seen_states and candidate not in pending:
                pending.append(candidate)
    complete = not pending
    if shared_methods is not None and not deferred and not memo.valid():
        return _result("INCOMPLETE", [], "snapshot_revalidation_failed")
    state = "BRANCH_ENUMERATION_COMPLETE" if complete else "INCOMPLETE"
    return _result(state, paths, None if complete else "branch_budget_exhausted")


def _format_path(fact, traced, sink_path, call, index):
    hops = [
        {
            "path": fact.path,
            "line": fact.line,
            "column": fact.column,
            "end_line": fact.end_line,
            "end_column": fact.end_column,
            "source_sha256": fact.source_sha256,
            "role": "declared_literal",
        }
    ]
    for path, node, role in reversed(traced):
        if not source_current(index, path):
            return []
        hops.append(source_span(index, path, node, role))
    hops.append(source_span(index, sink_path, call, "canonical_http_url_sink"))
    return hops


def _result(state, paths, reason):
    return {"state": state, "paths": paths, "reason": reason}


def _receiver_preserved(owner, call, receiver):
    """Support only one receiver use in the whole block: this request call."""
    for node in ast.walk(owner):
        if isinstance(node, ast.Name) and node.id == receiver:
            if node is not call.func.value:
                return False
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and (
            node.name == receiver
        ):
            return False
        if isinstance(node, (ast.Import, ast.ImportFrom)) and any(
            alias.name == "*" or (alias.asname or alias.name.split(".")[0]) == receiver
            for alias in node.names
        ):
            return False
        if isinstance(node, ast.ExceptHandler) and node.name == receiver:
            return False
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name == receiver:
            return False
        if isinstance(node, ast.MatchMapping) and node.rest == receiver:
            return False
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and (node.func.id in {"exec", "locals", "globals", "vars"})
        ):
            return False
    return True


def _context_identity(context, owner, call, receiver, aliases):
    if not isinstance(context, ast.Call) or not isinstance(context.func, ast.Attribute):
        return False
    adapter_call = context.func.value
    if context.func.attr != "get_requests_session" or not isinstance(
        adapter_call, ast.Call
    ):
        return False
    if context.args or context.keywords or len(owner.items) != 1:
        return False
    if not all(_receiver_preserved(stmt, call, receiver) for stmt in owner.body):
        return False
    from .security_configuration import _canonical

    return _canonical(adapter_call, aliases)


def session_request_context(call, index, path, aliases):
    """Recognize a request call under a synchronous context manager that binds the same receiver; reject async or nested scopes."""
    if not (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "request"
        and isinstance(call.func.value, ast.Name)
    ):
        return False
    if not index.validate(path):
        return False
    return _session_context_encloses(call, index, path, aliases, call.func.value.id)


def _session_context_encloses(call, index, path, aliases, receiver):
    current = call
    while current is not None:
        current = index.parents[path].get(id(current))
        if isinstance(
            current,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef,
                ast.ClassDef,
                ast.Lambda,
                ast.ListComp,
                ast.SetComp,
                ast.DictComp,
                ast.GeneratorExp,
            ),
        ):
            return False
        if isinstance(current, ast.AsyncWith):
            return False
        if isinstance(current, ast.With):
            for item in current.items:
                context, value = item.context_expr, item.optional_vars
                if not isinstance(value, ast.Name) or value.id != receiver:
                    continue
                return _context_identity(context, current, call, receiver, aliases)
    return False


def _slots(call, path, aliases, session_request=False):
    name = _canonical_http_call(call, aliases[path])
    if not name and session_request:
        name = "requests.Session.request"
    if not name:
        return []
    from .security_configuration import _keyword

    url = _keyword(call, "url", 1 if name.endswith(".request") else 0)
    rows = [("http_url", "endpoint_locator", url)] if url is not None else []
    auth = _keyword(call, "auth")
    if isinstance(auth, (ast.Tuple, ast.List)) and len(auth.elts) == 2:
        rows.append(("http_auth", "password", auth.elts[1]))
    headers = _keyword(call, "headers")
    if isinstance(headers, ast.Dict) and all(
        isinstance(key, ast.Constant) and isinstance(key.value, str)
        for key in headers.keys
    ):
        exact = {key.value: value for key, value in zip(headers.keys, headers.values)}
        value = next(
            (v for k, v in exact.items() if k.casefold() == "authorization"), None
        )
        if value is not None:
            rows.append(("http_header", "authorization", value))
    return rows


def _module_indexes(snapshots, audit):
    classes, aliases, duplicates = {}, {}, set()
    for path, tree in snapshots.items():
        if isinstance(tree, ast.Module):
            aliases[path] = audit._module_security_aliases(tree)
            for node in tree.body:
                if isinstance(node, ast.ClassDef):
                    key = (path, node.name)
                    if key in classes:
                        duplicates.add(key)
                    classes[key] = node
    for key in duplicates:
        classes.pop(key, None)
    return classes, aliases


def _sink_rows(snapshots, aliases, index, default_session):
    rows = []
    for path, tree in snapshots.items():
        if not isinstance(tree, ast.Module):
            continue
        mutation_profiles = {}
        nodes = tuple(ast.walk(tree))
        parents = None
        for call in (n for n in nodes if isinstance(n, ast.Call)):
            from .review_integrity import _security_flow_bindings

            lexical, _ = _security_flow_bindings(call, aliases[path])
            identity = session_request_context(call, index, path, aliases[path])
            session = bool(
                default_session and identity == default_session["get_adapter_canonical"]
            )
            session_meta = default_session if session else None
            slots = _slots(call, path, aliases, session)
            password = auth_constructor_password(call, path, aliases)
            if password is not None:
                slots.append(("http_auth", "password", password))
            if not any(row[2] is not None for row in slots):
                continue
            identity_key = tuple(sorted(lexical.items()))
            if identity_key not in mutation_profiles:
                if parents is None:
                    parents = {
                        id(child): node
                        for node in nodes
                        for child in ast.iter_child_nodes(node)
                    }
                mutation_profiles[identity_key] = _provider_identity_uncertain(
                    tree, lexical, nodes=nodes, parents=parents
                )
            if mutation_profiles[identity_key]:
                continue
            rows.extend(
                (path, call, *row, session_meta) for row in slots if row[2] is not None
            )
    return rows


def _fact_row(fact):
    return {
        "declaration": fact.public_facts(),
        "profile": "DECLARED_CLASS_MAY_FLOW",
        "url_witnesses": [],
        "known_auth_uses": [],
        "linked_unknown_uses": [],
    }


def _analyze_fact(fact, evidence, sinks, context, publications, aliases):
    for path, call, role, slot, expr, session_meta in sinks:
        records = record_use(fact, path, call, slot, expr, *context, aliases=aliases)
        for record in records or ():
            if session_meta:
                record["consumer_profile"] = session_meta["profile"]
                record["session_hops"] = session_meta["hops"]
                record["runtime_overrides"] = {
                    "setting_getter": session_meta["runtime_setting_getter"],
                    "adapter": session_meta["runtime_adapter_override"],
                }
            if role == "http_url":
                url_use(fact, record, evidence, publications)
            else:
                evidence["known_auth_uses"].append(record)


def _analyze(root, snapshots, imports, source_bytes, inventory, audit, integrity):
    index = SourceSnapshotIndex(root, snapshots, source_bytes, inventory)
    classes, aliases = _module_indexes(snapshots, audit)
    from .credential_role_constructor_provider import ClassChainMemo

    index.class_chain_memo = ClassChainMemo(index, imports, classes, audit)
    default_session = default_session_evidence(
        index, snapshots, imports, classes, aliases, audit
    )
    publications = {row["value"]: row for row in endpoint_publications()}
    sink_rows = _sink_rows(snapshots, aliases, index, default_session)
    facts = candidate_facts(index, snapshots, sink_rows, publications)
    result = {}
    with index.class_chain_memo.analysis_batch() as batch:
        if not batch.started:
            return {}
        for fact in facts:
            key = (fact.path, fact.line, fact.member)
            evidence = result.setdefault(key, _fact_row(fact))
            _analyze_fact(
                fact,
                evidence,
                sink_rows,
                (index, imports, classes, audit, integrity),
                publications,
                aliases,
            )
            if evidence["url_witnesses"]:
                from .credential_role_method_use_getter_audit import audit_value_uses

                audit_value_uses(fact, evidence, index, imports, classes, audit)
    return result if batch.accepted else {}


def endpoint_role_evidence(
    root, snapshots, imports, source_bytes, inventory, audit, integrity
):
    """Return exact publication-backed URL MAY_FLOW witnesses, never safety decisions."""
    rows = _analyze(root, snapshots, imports, source_bytes, inventory, audit, integrity)
    return {key: row for key, row in rows.items() if row["url_witnesses"]}


def known_auth_uses(
    root, snapshots, imports, source_bytes, inventory, audit, integrity
):
    """Return auth-slot uses separately from any endpoint publication evidence."""
    rows = _analyze(root, snapshots, imports, source_bytes, inventory, audit, integrity)
    return {
        key: row["known_auth_uses"]
        for key, row in rows.items()
        if row["known_auth_uses"]
    }


def record_use(
    fact,
    path,
    call,
    slot,
    expression,
    index,
    imports,
    classes,
    audit,
    integrity,
    aliases=None,
):
    """Record a validated direct or indirect credential use with source and sink hashes and any available hops; return None without a complete current-source route."""
    paths = [[]]
    if not matches_fact(fact, path, expression, index, imports, classes, audit):
        hops = constructor_url_hops(
            fact, path, call, expression, index, imports, classes, audit, integrity
        )
        paths = [hops] if hops else []
        if not hops and slot == "endpoint_locator" and aliases is not None:
            from .credential_role_paths import method_url_hop_paths

            method_result = method_url_hop_paths(
                fact,
                path,
                call,
                expression,
                index,
                imports,
                classes,
                aliases,
                audit,
                integrity,
            )
            paths = (
                method_result.get("paths", [])
                if method_result.get("state") == "BRANCH_ENUMERATION_COMPLETE"
                else []
            )
        if not paths:
            return None
    if not index.validate(path):
        return None
    record = {
        "path": index.relative(path),
        "line": call.lineno,
        "column": call.col_offset,
        "slot": slot,
        "value_span": [
            expression.lineno,
            expression.col_offset,
            expression.end_lineno,
            expression.end_col_offset,
        ],
        "source_span": [fact.line, fact.column, fact.end_line, fact.end_column],
        "source_sha256": fact.source_sha256,
        "sink_sha256": hashlib.sha256(index.source_bytes[path]).hexdigest(),
        "profile": "DECLARED_CLASS_MAY_FLOW",
    }
    return [
        {
            **record,
            "hops": hops,
            "method_value_flow": any(
                h.get("role") == "canonical_http_url_sink" for h in hops
            ),
        }
        for hops in paths
    ]
