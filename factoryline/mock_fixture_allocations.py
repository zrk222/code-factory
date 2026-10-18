"""Conservative source shapes for fixture-provided mock evidence."""

from __future__ import annotations

import ast

_ASSERTION_METHODS = frozenset(
    "assert_called_with assert_called_once_with assert_called assert_called_once "
    "assert_any_call assert_has_calls assert_not_called assert_awaited_with "
    "assert_awaited_once_with assert_any_await assert_has_awaits "
    "assert_not_awaited assert_awaited assert_awaited_once".split()
)


def direct_mock_return(fixture, aliases, audit):
    body = fixture.body
    if len(body) != 1 or not isinstance(body[0], ast.Return):
        return False
    value = body[0].value
    local_aliases = audit._scope_security_aliases(aliases, fixture)
    return (
        isinstance(value, ast.Call)
        and not value.args
        and not value.keywords
        and audit._normalized_call_name(value, local_aliases)
        in audit._UNITTEST_MOCK_CONSTRUCTORS
    )


def inert_assertion_methods(module, fixture, audit):
    body = fixture.body
    value = (
        body[0].value if len(body) == 1 and isinstance(body[0], ast.Return) else None
    )
    if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Name):
        return []
    classes = [
        n
        for n in module.body
        if isinstance(n, ast.ClassDef) and n.name == value.func.id
    ]
    if len(classes) != 1 or classes[0].bases or classes[0].keywords:
        return []
    cls = classes[0]
    if cls.decorator_list or any(
        s is not cls and cls.name in audit._bound_names(s) for s in module.body
    ):
        return []
    if any(
        not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in cls.body
    ):
        return []
    if any(
        n.decorator_list
        or len(n.body) != 1
        or not isinstance(n.body[0], (ast.Pass, ast.Return))
        or isinstance(n.body[0], ast.Return)
        and n.body[0].value is not None
        for n in cls.body
    ):
        return []
    return [n.name for n in cls.body if n.name in _ASSERTION_METHODS]


def fixture_registration(decorator, function_name, aliases, audit):
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if audit._resolved_ast_name(target, aliases) != "pytest.fixture":
        return None, False
    names = (
        [keyword.value for keyword in decorator.keywords if keyword.arg == "name"]
        if isinstance(decorator, ast.Call)
        else []
    )
    if not names:
        return function_name, True
    value = names[0]
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value, False
    return None, False


CACHE_HELPERS = (direct_mock_return, inert_assertion_methods, fixture_registration)
