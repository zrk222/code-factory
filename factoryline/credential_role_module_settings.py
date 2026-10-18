"""Bind a module-level setting hook to its directly constructed settings object."""

import ast


def _bound(statement):
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
    tree = snapshots.get(settings_path)
    if not isinstance(tree, ast.Module) or owner.name != "AppSettings":
        return None
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
        return None
    hook = module_binding(tree, "__getattr__", (ast.FunctionDef, ast.AsyncFunctionDef))
    assignments = [
        item
        for item in tree.body
        if isinstance(item, ast.Assign)
        and len(item.targets) == 1
        and isinstance(item.targets[0], ast.Name)
        and item.targets[0].id == "_app_settings"
    ]
    if (
        not isinstance(hook, ast.FunctionDef)
        or hook.decorator_list
        or [arg.arg for arg in hook.args.args] != ["name"]
        or hook.args.posonlyargs
        or hook.args.kwonlyargs
        or hook.args.vararg
        or hook.args.kwarg
        or len(assignments) != 1
        or module_binding(tree, "_app_settings", ast.Assign) is not assignments[0]
    ):
        return None
    call = assignments[0].value
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == owner.name
        and len(call.args) == 1
        and not call.keywords
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
    ):
        return None
    returns = _returns(hook)
    from .credential_role_default_contract import single_return

    if not single_return(hook):
        return None
    if len(returns) != 1 or not _hook_return(returns[0].value):
        return None
    from .credential_role_scope_bindings import binding_occurrences

    if binding_occurrences(tree.body, "getattr"):
        return None
    return hook, assignments[0]


def module_binding(tree, name, kind):
    from .credential_role_object_identity import binding_statements

    rows = binding_statements(tree.body, name)
    return rows[0] if len(rows) == 1 and isinstance(rows[0], kind) else None
