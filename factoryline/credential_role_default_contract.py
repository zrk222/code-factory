"""Finite default-getter contracts; reject arbitrary code around a matching return."""

import ast
from .credential_role_scope_bindings import effective_method

from .credential_role_scope_bindings import binding_occurrences


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
        return False
    lam = call.args[2]
    args = lam.args
    if (
        [n.arg for n in args.args] != ["name", "dflt"]
        or args.posonlyargs
        or args.kwonlyargs
        or args.vararg
        or args.kwarg
        or args.defaults
    ):
        return False
    body = lam.body
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
    if owner.decorator_list or owner.keywords:
        return None
    row = effective_method([(None, owner.name, owner)], "ADAPTER", {"property"})
    if row is None:
        return None
    function = row[1]
    if not single_return(function):
        return None
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
    return function, returns[0], call.args[1], call.args[1].value
