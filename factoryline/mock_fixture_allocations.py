"""Conservative source shapes for fixture-provided mock evidence."""

from __future__ import annotations

import ast

_ASSERTION_METHODS = frozenset(
    "assert_called_with assert_called_once_with assert_called assert_called_once "
    "assert_any_call assert_has_calls assert_not_called assert_awaited_with "
    "assert_awaited_once_with assert_any_await assert_has_awaits "
    "assert_not_awaited assert_awaited assert_awaited_once".split()
)


def _closed_method_signature(method):
    if method.decorator_list:
        return False
    arguments = method.args
    defaults = [
        *arguments.defaults,
        *(item for item in arguments.kw_defaults if item is not None),
    ]
    if any(not isinstance(item, ast.Constant) for item in defaults):
        return False
    annotated = [
        item.annotation
        for item in [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
        ]
        if item.annotation is not None
    ]
    if arguments.vararg and arguments.vararg.annotation is not None:
        annotated.append(arguments.vararg.annotation)
    if arguments.kwarg and arguments.kwarg.annotation is not None:
        annotated.append(arguments.kwarg.annotation)
    if method.returns is not None:
        annotated.append(method.returns)
    return all(isinstance(item, ast.Constant) for item in annotated)


def _class_is_unmutated(module, spec, name):
    for node in ast.walk(module):
        if isinstance(node, ast.Name) and node.id == name and node is not spec:
            return False
    return True


def _has_wildcard_import(module):
    return any(
        isinstance(node, ast.ImportFrom)
        and any(alias.name == "*" for alias in node.names)
        for node in ast.walk(module)
    )


def _source_closed_class_spec(module, fixture, spec, audit):
    if (
        not isinstance(spec, ast.Name)
        or spec.id in audit._scope_parameters(fixture)
        or any(
            isinstance(node, ast.Name)
            and node.id == spec.id
            and isinstance(node.ctx, (ast.Store, ast.Del))
            for node in ast.walk(fixture)
        )
    ):
        return False
    classes = [
        node
        for node in module.body
        if isinstance(node, ast.ClassDef) and node.name == spec.id
    ]
    if len(classes) != 1:
        return False
    cls = classes[0]
    if (
        cls.bases
        or cls.keywords
        or cls.decorator_list
        or _has_wildcard_import(module)
        or not _class_is_unmutated(module, spec, spec.id)
        or any(
            statement is not cls and spec.id in audit._bound_names(statement)
            for statement in module.body
        )
    ):
        return False
    for statement in cls.body:
        if isinstance(statement, ast.Pass):
            continue
        if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        if not _closed_method_signature(statement):
            return False
    return True


def direct_mock_return(module, fixture, aliases, audit):
    body = fixture.body
    if len(body) != 1 or not isinstance(body[0], ast.Return):
        return False
    value = body[0].value
    local_aliases = audit._scope_security_aliases(aliases, fixture)
    if not isinstance(value, ast.Call):
        return False
    constructor = audit._normalized_call_name(value, local_aliases)
    if constructor not in audit._UNITTEST_MOCK_CONSTRUCTORS:
        return False
    if constructor == "unittest.mock.create_autospec":
        return (
            isinstance(fixture, ast.FunctionDef)
            and not audit._scope_parameters(fixture)
            and len(value.args) == 1
            and not value.keywords
            and _source_closed_class_spec(module, fixture, value.args[0], audit)
        )
    return not value.args and not value.keywords


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


CACHE_HELPERS = (
    _closed_method_signature,
    _class_is_unmutated,
    _has_wildcard_import,
    _source_closed_class_spec,
    direct_mock_return,
    inert_assertion_methods,
    fixture_registration,
)
