"""Validate a source-defined decorator that transparently returns its call."""

import ast

from .credential_role_class_binding import effective_method


def method_rows(chain, index, imports):
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
    from .credential_role_scope_bindings import binding_occurrences

    return not binding_occurrences(owner.body, decorator.id)


def _consumer_module_binding_stable(path, name, index, imports):
    imported = imports.get(path, {}).get(name)
    if not imported or not imported[1]:
        return False
    tree = index.snapshots.get(path)
    if not isinstance(tree, ast.Module):
        return False
    from .credential_role_scope_bindings import binding_occurrences

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
    from .credential_role_scope_bindings import binding_occurrences

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
    from .credential_role_scope_bindings import binding_occurrences

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
