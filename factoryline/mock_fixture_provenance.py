"""Bind mock fixture credit to retained source snapshots."""

from __future__ import annotations

import ast
from pathlib import Path


def fixture_bindings_for_source(tree):
    from . import review_audits as audit
    from . import mock_fixture_allocations as allocation

    aliases = audit._scope_security_aliases(audit._module_security_aliases(tree), tree)
    fixtures = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for item in node.decorator_list:
                name, supported = allocation.fixture_registration(
                    item, node.name, aliases, audit
                )
                if name is not None:
                    fixtures.setdefault(name, []).append((node, supported))
    if not fixtures:
        return {}
    mock_provider_safe = _mock_providers_are_closed(tree, aliases, audit)
    pytest_provider_safe = _pytest_fixture_provider_safe(tree, audit)
    result = {}
    for name, items in fixtures.items():
        fixture, supported_name = items[0] if len(items) == 1 else (None, False)
        controlled = bool(
            fixture
            and supported_name
            and len(fixture.decorator_list) == 1
            and not any(
                s is not fixture and name in audit._bound_names(s) for s in tree.body
            )
            and pytest_provider_safe
        )
        result[name] = {
            "mock": bool(
                controlled
                and mock_provider_safe
                and allocation.direct_mock_return(tree, fixture, aliases, audit)
            ),
            "inert_methods": (
                allocation.inert_assertion_methods(tree, fixture, audit)
                if controlled
                else []
            ),
        }
    return result


def fixtures_for_file(path: Path, sources: dict[Path, dict[str, dict]]):
    parents = sorted(
        (
            p
            for p in sources
            if p.name == "conftest.py" and path.parent.is_relative_to(p.parent)
        ),
        key=lambda p: len(p.parts),
    )
    result = {}
    for parent in parents:
        result.update(sources[parent])
    result.update(sources.get(path, {}))
    return result


def fixture_is_mock(module, name):
    mapping = getattr(module, "_oracle_mock_fixture_provenance", {})
    profile = mapping.get(name, {}) if isinstance(mapping, dict) else {}
    return isinstance(profile, dict) and profile.get("mock") is True


def inert_fixture_assertion_reason(call, aliases):
    if (
        not isinstance(call, ast.Call)
        or not isinstance(call.func, ast.Attribute)
        or not isinstance(call.func.value, ast.Name)
    ):
        return None
    scope = getattr(call, "_oracle_scope", None)
    module = getattr(scope, "_oracle_module", None)
    profiles = getattr(module, "_oracle_mock_fixture_provenance", {})
    from . import review_audits as audit

    receiver = audit._mock_root_name(call.func.value, scope, aliases)
    profile = profiles.get(receiver, {}) if isinstance(profiles, dict) else {}
    return (
        "assertion method is source-proven to have an inert implementation"
        if call.func.attr in profile.get("inert_methods", ())
        else None
    )


def inert_fixture_assertions(nodes, aliases):
    return [
        (node, reason)
        for node in nodes
        if isinstance(node, ast.Call)
        and (reason := inert_fixture_assertion_reason(node, aliases)) is not None
    ]


def _mock_providers_are_closed(module, aliases, audit):
    imports = [n for n in module.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    providers = {
        n
        for n, target in audit._security_aliases(imports).items()
        if target == "unittest" or target.startswith("unittest.mock")
    }
    if not providers or any(
        p in audit._bound_names(s)
        for s in module.body
        if not isinstance(s, (ast.Import, ast.ImportFrom))
        for p in providers
    ):
        return False
    allowed = {
        id(child)
        for call in ast.walk(module)
        if isinstance(call, ast.Call)
        and audit._normalized_call_name(call, aliases)
        in audit._UNITTEST_MOCK_CONSTRUCTORS
        for child in ast.walk(call.func)
    }
    allowed.update(
        id(child)
        for item in ast.walk(module)
        if isinstance(item, ast.arg) and item.annotation
        for child in ast.walk(item.annotation)
    )
    for node in ast.walk(module):
        if (
            isinstance(node, (ast.Name, ast.Attribute))
            and _root_name(node) in providers
        ):
            if (
                isinstance(node.ctx, (ast.Store, ast.Del))
                or isinstance(node.ctx, ast.Load)
                and id(node) not in allowed
            ):
                return False
        if isinstance(node, ast.Call) and any(
            isinstance(a, ast.Constant)
            and isinstance(a.value, str)
            and a.value.startswith("unittest.mock.")
            for a in [*node.args, *(k.value for k in node.keywords)]
        ):
            return False
    return True


def _root_name(node):
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else ""


def _pytest_fixture_provider_safe(module, audit):
    imports = [n for n in module.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    roots = {
        n
        for n, target in audit._security_aliases(imports).items()
        if target == "pytest"
    }
    parents = {id(c): p for p in ast.walk(module) for c in ast.iter_child_nodes(p)}
    for node in ast.walk(module):
        if (
            isinstance(node, ast.Name)
            and node.id in roots
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            return False
        if isinstance(node, ast.Attribute) and _root_name(node.value) in roots:
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                return False
            if node.attr == "fixture" and isinstance(node.ctx, ast.Load):
                parent = parents.get(id(node))
                if not (
                    isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node in parent.decorator_list
                    or isinstance(parent, ast.Call)
                    and parent.func is node
                ):
                    return False
    return True


CACHE_HELPERS = (
    fixture_bindings_for_source,
    fixtures_for_file,
    fixture_is_mock,
    inert_fixture_assertion_reason,
    inert_fixture_assertions,
    _mock_providers_are_closed,
    _root_name,
    _pytest_fixture_provider_safe,
)
