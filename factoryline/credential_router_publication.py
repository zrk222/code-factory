from __future__ import annotations

import ast

from .credential_httpx_origins import factory_fixture_consumer_status


def router_factory_call_published(graph, path, call):
    """Close a router factory published through an exact pytest app factory."""
    return _memo(
        graph,
        "_credential_router_publication_cache",
        (path, id(call)),
        lambda: _router_factory_call_published(graph, path, call),
    )


def _router_factory_call_published(graph, path, call):
    parent = graph.parents.get(id(call))
    scope = getattr(call, "_security_lexical_scope", None)
    if (
        not isinstance(parent, ast.Assign)
        or len(parent.targets) != 1
        or not isinstance(parent.targets[0], ast.Name)
        or parent.value is not call
        or not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
    ):
        return False
    alias = parent.targets[0]
    if graph._unique_name_assignment(scope, alias.id) is not parent:
        return False
    fixture = graph.parents.get(id(scope))
    if (
        not isinstance(fixture, (ast.FunctionDef, ast.AsyncFunctionDef))
        or scope not in fixture.body
        or not graph._is_pytest_fixture(path, fixture)
        or scope.decorator_list
        or not _fixture_returns_factory(graph, fixture, scope)
    ):
        return False
    app_assignments = [
        node
        for node in scope.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.Call)
        and graph.integrity.security_call_name(node.value, graph.aliases[path])
        == "fastapi.FastAPI"
        and not node.value.args
        and not node.value.keywords
    ]
    returns = [node for node in scope.body if isinstance(node, ast.Return)]
    if len(app_assignments) != 1 or len(returns) != 1:
        return False
    app = app_assignments[0].targets[0]
    includes = [
        node
        for node in scope.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute)
        and node.value.func.attr == "include_router"
        and isinstance(node.value.func.value, ast.Name)
        and node.value.func.value.id == app.id
        and len(node.value.args) == 1
        and isinstance(node.value.args[0], ast.Name)
        and _include_router_options(node.value)
        and graph._provider_is_unmodified("fastapi", {"FastAPI"})
    ]
    published = [node for node in includes if node.value.args[0].id == alias.id]
    if (
        not isinstance(returns[0].value, ast.Name)
        or returns[0].value.id != app.id
        or graph._unique_name_assignment(scope, app.id) is not app_assignments[0]
        or not includes
        or len(published) != 1
    ):
        return False
    if not _local_name_uses(
        graph, scope, alias, {parent.targets[0], published[0].value.args[0]}
    ):
        return False
    if not _local_name_uses(
        graph,
        scope,
        app,
        {
            app_assignments[0].targets[0],
            *(node.value.func.value for node in includes),
            returns[0].value,
        },
    ):
        return False
    return _memo(
        graph,
        "_credential_app_factory_consumers_cache",
        (path, id(fixture)),
        lambda: _factory_fixture_consumers(graph, path, fixture),
    )


def _fixture_returns_factory(graph, fixture, factory):
    body = [
        node
        for node in fixture.body
        if not (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        )
    ]
    return (
        len(body) == 2
        and body[0] is factory
        and isinstance(body[1], ast.Return)
        and body[1].value is not None
        and isinstance(body[1].value, ast.Name)
        and body[1].value.id == factory.name
    )


def _factory_fixture_consumers(graph, path, fixture):
    found = False
    for source, tree in graph.trees.items():
        for caller in graph._walk(tree):
            status = factory_fixture_consumer_status(
                graph,
                path,
                fixture,
                source,
                caller,
                _fixture_app_consumers_closed,
                _route_lookup_only,
            )
            if status is False:
                return False
            found = found or status is True
    return found


def _fixture_app_consumers_closed(graph, path, fixture):
    return _memo(
        graph,
        "_credential_app_fixture_consumers_cache",
        (path, id(fixture)),
        lambda: _fixture_app_consumers_closed_uncached(graph, path, fixture),
    )


def _fixture_app_consumers_closed_uncached(graph, path, fixture):
    consumers = 0
    for source, tree in graph.trees.items():
        for caller in graph._walk(tree):
            status = _app_fixture_consumer_status(graph, path, fixture, source, caller)
            if status is False:
                return False
            consumers += status is True
    return consumers == 0 or consumers > 0


def _app_route_lookups_closed(graph, path, caller, parameter):
    relative = path.relative_to(graph.root)
    if "tests" not in relative.parts or not caller.name.startswith("test_"):
        return False
    uses = [
        node
        for node in graph._walk(caller)
        if isinstance(node, ast.Name) and node.id == parameter
    ]
    return bool(uses) and all(
        isinstance(node.ctx, ast.Load)
        and isinstance(graph.parents.get(id(node)), ast.Attribute)
        and graph.parents[id(node)].value is node
        and graph.parents[id(node)].attr == "url_path_for"
        and isinstance(graph.parents.get(id(graph.parents[id(node)])), ast.Call)
        and graph.parents[id(graph.parents[id(node)])].func is graph.parents[id(node)]
        for node in uses
    )


def _include_router_options(call):
    if len(call.args) != 1:
        return False
    return all(
        keyword.arg == "prefix"
        and isinstance(keyword.value, ast.Constant)
        and type(keyword.value.value) is str
        for keyword in call.keywords
    )


def _route_lookup_only(graph, path, caller, call):
    relative = path.relative_to(graph.root)
    method = graph.parents.get(id(call))
    outer = graph.parents.get(id(method))
    return bool(
        "tests" in relative.parts
        and caller.name.startswith("test_")
        and isinstance(method, ast.Attribute)
        and method.value is call
        and method.attr == "url_path_for"
        and isinstance(outer, ast.Call)
        and outer.func is method
        and outer.args
        and isinstance(outer.args[0], ast.Constant)
        and type(outer.args[0].value) is str
        and all(
            isinstance(value, ast.Constant)
            or isinstance(value, ast.Attribute)
            and isinstance(value.value, ast.Name)
            for value in [*outer.args[1:], *(kw.value for kw in outer.keywords)]
        )
    )


def _local_name_uses(graph, scope, target, allowed):
    return all(
        node in allowed
        for node in graph._walk(scope)
        if isinstance(node, ast.Name) and node.id == target.id
    )


def _memo(graph, attribute, key, compute):
    cache = getattr(graph, attribute, None)
    if cache is None:
        cache = {}
        setattr(graph, attribute, cache)
    if key in cache:
        return cache[key]
    result = compute()
    if graph.complete:
        cache[key] = result
    return result


def _app_fixture_consumer_status(graph, path, fixture, source, caller):
    if not isinstance(caller, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    parameters = [
        arg.arg
        for arg in (
            *caller.args.posonlyargs,
            *caller.args.args,
            *caller.args.kwonlyargs,
        )
        if arg.arg == fixture.name
    ]
    if not parameters:
        return None
    origin = graph._nearest_fixture(source, fixture.name, caller)
    if origin is None:
        return False if source == path else None
    if origin != (path, fixture):
        return None
    return bool(
        len(parameters) == 1
        and (
            graph._app_client_consumer(source, caller, parameters[0])
            or graph._app_openapi_consumer(source, caller, parameters[0])
            or _app_route_lookups_closed(graph, source, caller, parameters[0])
        )
    )
