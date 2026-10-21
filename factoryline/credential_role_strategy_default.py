"""Verify source-declared strategy default forwarding without runtime claims."""

import ast
from importlib.util import resolve_name

from .credential_role_scope_bindings import effective_method
from .credential_role_strategy_fallback import fallback_method


def _doc(node):
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def _setting_method(function):
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
    forward = _setting_method(row[1])
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
    owner = classes[target]
    strategy = effective_method([(target[0], target[1], owner)], "setting")
    verified = fallback_method(strategy[1]) if strategy else None
    if verified is None:
        return None
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
