"""Conservative local proof that a Click callback is never entered."""

from __future__ import annotations

import ast
from . import review_integrity as ri

_click_provider_escapes = ri._click_provider_escapes


def _outside_callback(node, callback):
    yield node
    if node is callback:
        for field, value in ast.iter_fields(node):
            if field == "body":
                continue
            values = value if isinstance(value, list) else [value]
            for child in values:
                if isinstance(child, ast.AST):
                    yield from _outside_callback(child, callback)
        return
    for child in ast.iter_child_nodes(node):
        yield from _outside_callback(child, callback)


def _has_callback_escape(nodes, callback):
    reflective = {"locals", "globals", "vars", "eval", "exec", "getattr"}
    return any(
        isinstance(node, ast.Name)
        and node.id in reflective
        and isinstance(node.ctx, ast.Load)
        or isinstance(node, (ast.Global, ast.Nonlocal))
        and callback.name in node.names
        for node in nodes
    )


def _callback_is_referenced(nodes, callback):
    return any(
        isinstance(node, ast.Name)
        and node.id == callback.name
        and isinstance(node.ctx, ast.Load)
        for node in nodes
    )


def uninvoked_callback_reason(test, is_command, has_oracle):
    for callback in test.body:
        if not isinstance(callback, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        visible = list(_outside_callback(test, callback))
        if _has_callback_escape(visible, callback):
            continue
        if not is_command(callback) or not has_oracle(callback):
            continue
        if _callback_is_referenced(visible, callback):
            continue
        return (
            callback,
            "local command callback with assertions is never invoked or referenced",
        )
    return None


def _click_provider_node_escapes(node, roots, commands, calls, parents):
    if isinstance(node, ast.Name):
        if isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in roots | commands:
            return True
        parent = parents.get(node)
        if (
            isinstance(node.ctx, ast.Load)
            and node.id in roots
            and (not isinstance(parent, ast.Attribute) or parent not in calls)
        ):
            return True
        if (
            isinstance(node.ctx, ast.Load)
            and node.id in commands
            and (not isinstance(parent, ast.Call) or parent.func is not node)
        ):
            return True
    if isinstance(node, ast.Attribute):
        root = ast.unparse(node.value).split(".", 1)[0]
        if root in roots and isinstance(node.ctx, (ast.Store, ast.Del)):
            return True
        if (
            root in roots
            and isinstance(node.ctx, ast.Load)
            and (node not in calls or node.attr.startswith("__"))
        ):
            return True
    return isinstance(node, ast.Call) and any(
        isinstance(arg, ast.Constant)
        and isinstance(arg.value, str)
        and arg.value.startswith("click.")
        for arg in [*node.args, *(kw.value for kw in node.keywords)]
    )


def _default_click_command(callback, aliases, audits):
    if not callback.decorator_list:
        return False
    decorator = callback.decorator_list[0]
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    return (
        audits._resolved_ast_name(target, aliases) == "click.command"
        and (
            not isinstance(decorator, ast.Call)
            or not decorator.args
            and not decorator.keywords
        )
        and audits._propagating_click_decorators(callback, aliases)
    )


def uninvoked_click_callback(test, aliases, helper_names):
    from . import review_audits as audits

    def eligible(callback):
        return _default_click_command(
            callback, aliases, audits
        ) and audits._meaningful_local_assertion(
            callback,
            audits._scope_security_aliases(aliases, callback),
            helper_names,
        )

    eligible_ids = {
        id(child)
        for child in test.body
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
        and eligible(child)
    }
    if not eligible_ids:
        return None
    module = getattr(test, "_oracle_module", None)
    if module is None or _click_provider_escapes(module, aliases):
        return None
    return uninvoked_callback_reason(
        test,
        lambda callback: id(callback) in eligible_ids,
        lambda callback: id(callback) in eligible_ids,
    )


def _registry_kind(test, register, registry, callback, functions):
    if isinstance(register, ast.AsyncFunctionDef):
        return "empty"
    if _registry_rebound_identity_decorator(test, register, callback, functions):
        return "empty"
    body = [stmt for stmt in register.body if not ri._is_docstring(stmt)]
    param = register.args.args[0].arg
    if (
        len(body) == 1
        and isinstance(body[0], ast.Return)
        and isinstance(body[0].value, ast.Name)
        and body[0].value.id == param
    ):
        return "empty"
    if ri._callback_registration_body(register, registry):
        if len(callback.decorator_list) > 1:
            return "noop"
        return "callback"
    append = body[0].value if len(body) == 2 and isinstance(body[0], ast.Expr) else None
    if (
        isinstance(append, ast.Call)
        and isinstance(append.func, ast.Attribute)
        and append.func.attr == "append"
        and isinstance(append.func.value, ast.Name)
        and append.func.value.id == registry
        and len(append.args) == 1
        and not append.keywords
        and ri._registry_noop_lambda(append.args[0])
        and isinstance(body[1], ast.Return)
        and isinstance(body[1].value, ast.Name)
        and body[1].value.id == param
    ):
        return "noop"


def _registry_rebound_identity_decorator(test, register, callback, functions):
    if len(functions) != 2 or len(callback.decorator_list) != 1:
        return False
    body = [stmt for stmt in test.body if not ri._is_docstring(stmt)]
    return (
        len(body) >= 4
        and body[0] is not register
        and body[1] is register
        and isinstance(body[2], ast.Assign)
        and len(body[2].targets) == 1
        and isinstance(body[2].targets[0], ast.Name)
        and body[2].targets[0].id == register.name
        and ri._registry_identity_lambda(body[2].value, register.args.args[0].arg)
        and body[3] is callback
        and isinstance(callback.decorator_list[0], ast.Name)
        and callback.decorator_list[0].id == register.name
    )


def _registry_callback_has_no_freevars(test, callback):
    try:
        module = ast.Module(body=[test], type_ignores=[])
        code = compile(module, "<callback-closure-proof>", "exec")
    except (MemoryError, RecursionError, SyntaxError, TypeError, ValueError):
        return False
    pending = [code]
    matches = []
    while pending:
        current = pending.pop()
        pending.extend(
            value for value in current.co_consts if isinstance(value, type(code))
        )
        if current.co_name == callback.name:
            matches.append(current)
    return len(matches) == 1 and not matches[0].co_freevars


def _registry_callback_code_compatible(test, callback):
    args = callback.args if isinstance(callback, ast.FunctionDef) else None
    return bool(
        args
        and len(args.args) == 1
        and not any(
            (
                args.posonlyargs,
                args.kwonlyargs,
                args.defaults,
                args.kw_defaults,
                args.vararg,
                args.kwarg,
            )
        )
        and not any(
            isinstance(node, (ast.Yield, ast.YieldFrom, ast.Await))
            for node in ri._lexical_nodes(callback)
        )
        and _registry_callback_has_no_freevars(test, callback)
    )


def _registry_noop_code_assignment(stmt, target, test, callback):
    return bool(
        isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Attribute)
        and stmt.targets[0].attr == "__code__"
        and isinstance(stmt.targets[0].value, ast.Name)
        and stmt.targets[0].value.id == target
        and isinstance(stmt.value, ast.Attribute)
        and stmt.value.attr == "__code__"
        and isinstance(stmt.value.value, ast.Lambda)
        and ri._registry_noop_lambda(stmt.value.value)
        and _registry_callback_code_compatible(test, callback)
    )


def _registry_callback_never_executes_or_asserts(callback):
    if isinstance(callback, ast.AsyncFunctionDef) or any(
        isinstance(node, (ast.Yield, ast.YieldFrom))
        for node in ri._lexical_nodes(callback)
    ):
        return True
    body = [stmt for stmt in callback.body if not ri._is_docstring(stmt)]
    return bool(
        len(body) == 1
        and isinstance(body[0], ast.If)
        and isinstance(body[0].test, ast.Constant)
        and body[0].test.value is False
        and not body[0].orelse
        and len(body[0].body) == 1
        and isinstance(body[0].body[0], ast.Assert)
        or len(body) == 2
        and isinstance(body[0], ast.Return)
        and body[0].value is None
        and isinstance(body[1], ast.Assert)
    )


def _registry_early_return(stmt):
    return bool(
        isinstance(stmt, ast.If)
        and isinstance(stmt.test, ast.Constant)
        and stmt.test.value is True
        and len(stmt.body) == 1
        and isinstance(stmt.body[0], ast.Return)
        and stmt.body[0].value is None
        and not stmt.orelse
    )


def _registry_update(stmt, registry, aliases, state, reserved, callback, test):
    if (
        isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
    ):
        name = stmt.targets[0].id
        if (
            name == registry
            and isinstance(stmt.value, ast.List)
            and not stmt.value.elts
        ):
            return "empty" if len(aliases) == 1 else None
        if isinstance(stmt.value, ast.Name) and stmt.value.id in aliases:
            if name in reserved and name != registry:
                return None
            aliases.add(name)
            return state
        return None
    if (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Call)
        and isinstance(stmt.value.func, ast.Attribute)
        and stmt.value.func.attr == "clear"
        and isinstance(stmt.value.func.value, ast.Name)
        and stmt.value.func.value.id in aliases
        and not stmt.value.args
        and not stmt.value.keywords
    ):
        return "empty"
    if _registry_noop_code_assignment(stmt, callback.name, test, callback):
        return state if state == "empty" else "noop"
    return state if isinstance(stmt, ast.Pass) else None


def _registry_call(stmt, target):
    if not isinstance(stmt, ast.Expr) or not isinstance(stmt.value, ast.Call):
        return None
    call = stmt.value
    return (
        call
        if isinstance(call.func, ast.Name)
        and call.func.id == target
        and len(call.args) == 1
        and isinstance(call.args[0], ast.Constant)
        and not call.keywords
        else None
    )


def _registry_body_prefix(test, initial, register, callback, functions):
    body = [stmt for stmt in test.body if not ri._is_docstring(stmt)]
    wrappers = [fn for fn in functions if fn not in (register, callback)]
    rebound = _registry_rebound_identity_decorator(test, register, callback, functions)
    prefix = [initial, register]
    if rebound:
        prefix.extend((body[2], callback))
    else:
        prefix.extend((*wrappers, callback))
    if body[: len(prefix)] != prefix:
        return None
    return body, wrappers, rebound


def _registry_skip_definition(
    stmt, initial, register, callback, wrappers, rebound, body
):
    return bool(
        stmt in (initial, register, callback, *wrappers)
        or rebound
        and stmt is body[2]
        or ri._is_docstring(stmt)
    )


def _registry_loop_inert(test, stmt, registry, aliases, reserved, state, callback):
    guarded = isinstance(stmt, ast.Try)
    loop = stmt.body[0] if guarded and len(stmt.body) == 1 else stmt
    if (
        not isinstance(loop, ast.For)
        or loop.orelse
        or not isinstance(loop.target, ast.Name)
    ):
        return False
    target = loop.target.id
    if target in reserved or target in aliases:
        return False
    if guarded and (
        stmt.orelse
        or stmt.finalbody
        or len(stmt.handlers) != 1
        or not isinstance(stmt.handlers[0].type, ast.Name)
        or stmt.handlers[0].type.id != "AssertionError"
        or stmt.handlers[0].name is not None
        or not all(isinstance(node, ast.Pass) for node in stmt.handlers[0].body)
    ):
        return False
    known_iter = (
        isinstance(loop.iter, ast.List)
        and not loop.iter.elts
        or (isinstance(loop.iter, ast.Name) and loop.iter.id in aliases)
    )
    if not known_iter:
        return False
    if not loop.body:
        return True
    if (
        len(loop.body) == 3
        and isinstance(loop.body[0], ast.Assign)
        and len(loop.body[0].targets) == 1
        and isinstance(loop.body[0].targets[0], ast.Name)
        and loop.body[0].targets[0].id not in reserved | aliases | {target}
        and isinstance(loop.body[0].value, ast.Name)
        and loop.body[0].value.id == target
        and _registry_noop_code_assignment(
            loop.body[1], loop.body[0].targets[0].id, test, callback
        )
        and _registry_call(loop.body[2], target) is not None
    ):
        return True
    if isinstance(loop.body[0], ast.Break):
        return (
            len(loop.body) == 1
            or len(loop.body) == 2
            and _registry_call(loop.body[1], target) is not None
        )
    dead = loop.body[0]
    if (
        len(loop.body) == 1
        and isinstance(dead, ast.If)
        and isinstance(dead.test, ast.Constant)
        and dead.test.value is False
        and not dead.orelse
        and len(dead.body) == 1
        and _registry_call(dead.body[0], target)
    ):
        return True
    call = _registry_call(loop.body[-1], target)
    if call is None:
        return False
    rebound = (
        len(loop.body) == 2
        and isinstance(loop.body[0], ast.Assign)
        and len(loop.body[0].targets) == 1
        and isinstance(loop.body[0].targets[0], ast.Name)
        and loop.body[0].targets[0].id == target
        and ri._registry_noop_lambda(loop.body[0].value)
    )
    canonical = len(loop.body) == 1 or rebound
    empty = isinstance(loop.iter, ast.List) or state == "empty"
    caught = (
        guarded
        and isinstance(loop.iter, ast.Name)
        and loop.iter.id == registry
        and state == "callback"
        and ri._registry_swallowed_assertion(test, callback, call)
    )
    return bool(
        canonical
        and (
            empty
            or rebound
            or state == "noop"
            or caught
            or state == "callback"
            and _registry_callback_never_executes_or_asserts(callback)
        )
    )


def inert_registered_callback_body(test):
    """Prove inertness only for a bounded, closed local callback registry."""
    context = ri._callback_registry_context(
        test, {}, closed=True, inert_kind=_registry_kind
    )
    if context is None:
        return False
    initial, registry, register, callbacks, functions, state = context
    callback = callbacks[0]
    owned = {registry, register.name, callback.name, register.args.args[0].arg}
    if (
        len(owned) != 4
        or getattr(register, "type_params", ())
        or getattr(callback, "type_params", ())
    ):
        return False
    prefix = _registry_body_prefix(test, initial, register, callback, functions)
    if prefix is None:
        return False
    body, wrappers, rebound = prefix
    reserved = owned
    aliases = {registry}
    for stmt in test.body:
        if _registry_skip_definition(
            stmt, initial, register, callback, wrappers, rebound, body
        ):
            continue
        if isinstance(stmt, ast.Return) and stmt.value is None:
            return True
        if _registry_early_return(stmt):
            return True
        updated = _registry_update(
            stmt, registry, aliases, state, reserved, callback, test
        )
        if updated is not None:
            state = updated
            continue
        if not _registry_loop_inert(
            test, stmt, registry, aliases, reserved, state, callback
        ):
            return False
    return True


_REGISTRY_LOCAL_HELPERS = (
    _registry_kind,
    _registry_rebound_identity_decorator,
    _registry_callback_has_no_freevars,
    _registry_callback_code_compatible,
    _registry_noop_code_assignment,
    _registry_callback_never_executes_or_asserts,
    _registry_early_return,
    _registry_body_prefix,
    _registry_skip_definition,
    _registry_update,
    _registry_call,
    _registry_loop_inert,
)

CACHE_HELPERS = (
    _outside_callback,
    _has_callback_escape,
    _callback_is_referenced,
    uninvoked_callback_reason,
    _click_provider_node_escapes,
    _click_provider_escapes,
    _default_click_command,
    uninvoked_click_callback,
    inert_registered_callback_body,
    *_REGISTRY_LOCAL_HELPERS,
    *ri._CALLBACK_REGISTRY_HELPERS,
)
