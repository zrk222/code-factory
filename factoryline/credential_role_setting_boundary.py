"""Source shapes for the declared setting value and runtime override boundary."""

import ast
import hashlib

from .credential_role_scope_bindings import effective_method
from .credential_role_default_contract import (
    default_getter as _default_getter,
    getter_environment,
)


def _returns(function):
    return [node for node in function.body if isinstance(node, ast.Return)]


def _bound(statement):
    from .review_audits import _bound_names

    return _bound_names(statement)


def _module_binding(tree, name, kind):
    from .credential_role_scope_bindings import binding_statements

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
        binding_rows = [row for row in function.body if "getter" in _bound(row)]
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


def _setting_method(root, settings_path, owner, getter_shape, aliases):
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
    from .credential_role_module_settings import settings_module_bridge

    getter_shape = _setting_getter_shape(snapshots)
    bridge = settings_module_bridge(snapshots, settings_path, owner, _module_binding)
    method = (
        _setting_method(index.root, settings_path, owner, getter_shape, aliases)
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
    stem = module.replace(".", "/")
    for suffix in (".py", "/__init__.py"):
        path = index.root / (stem + suffix)
        if path in index.snapshots:
            return path
    return None


def module_name(index, path):
    relative = index.relative(path)
    if not relative:
        return None
    return relative.removesuffix(".py").replace("/", ".").removesuffix(".__init__")


def source_hop(index, path, node, role):
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
