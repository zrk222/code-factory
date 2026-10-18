"""Conservative local proof that a Click callback is never entered."""

from __future__ import annotations

import ast


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


def _root_name(node):
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else ""


def _click_provider_escapes(module, aliases):
    roots = {name for name, value in aliases.items() if value == "click"}
    commands = {name for name, value in aliases.items() if value == "click.command"}
    if not roots:
        return True
    targets = _click_call_targets(module, roots, commands)
    return any(
        _click_reference_escapes(node, roots, commands, *targets)
        for node in ast.walk(module)
    )


def _click_call_targets(module, roots, commands):
    calls = tuple(node for node in ast.walk(module) if isinstance(node, ast.Call))
    call_attributes = {
        id(node.func)
        for node in calls
        if isinstance(node.func, ast.Attribute) and _root_name(node.func) in roots
    }
    call_commands = {
        id(node.func)
        for node in calls
        if isinstance(node.func, ast.Name) and node.func.id in commands
    }
    allowed_root_names = {
        id(node.value)
        for node in ast.walk(module)
        if isinstance(node, ast.Attribute) and id(node) in call_attributes
    }
    return call_attributes, call_commands, allowed_root_names


def _click_reference_escapes(
    node, roots, commands, call_attributes, call_commands, allowed_root_names
):
    if isinstance(node, ast.Name):
        if isinstance(node.ctx, ast.Store) and node.id in roots | commands:
            return True
        if isinstance(node.ctx, ast.Load) and node.id in roots:
            return id(node) not in allowed_root_names
        if (
            isinstance(node.ctx, ast.Load)
            and node.id in commands
            and id(node) not in call_commands
        ):
            return True
    if isinstance(node, ast.Attribute):
        if (
            isinstance(node.ctx, (ast.Store, ast.Del))
            and _root_name(node.value) in roots
        ):
            return True
        if (
            isinstance(node.ctx, ast.Load)
            and _root_name(node) in roots
            and id(node) not in call_attributes
        ):
            return True
        if (
            node.attr.startswith("__")
            and isinstance(node.ctx, ast.Load)
            and _root_name(node.value) in roots
        ):
            return True
    return _passes_click_provider_reference(node)


def _passes_click_provider_reference(node):
    if not isinstance(node, ast.Call):
        return False
    return any(
        isinstance(arg, ast.Constant)
        and isinstance(arg.value, str)
        and arg.value.startswith("click.")
        for arg in [*node.args, *(item.value for item in node.keywords)]
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


CACHE_HELPERS = (
    _outside_callback,
    _has_callback_escape,
    _callback_is_referenced,
    uninvoked_callback_reason,
    _root_name,
    _click_provider_escapes,
    _click_call_targets,
    _click_reference_escapes,
    _passes_click_provider_reference,
    _default_click_command,
    uninvoked_click_callback,
)
