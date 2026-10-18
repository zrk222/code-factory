from __future__ import annotations

import ast

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


def _request_client_origin(graph, path, function, request):
    name = request.value.func.value.id
    if any(
        arg.arg == name
        for arg in (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        )
    ):
        return _direct_httpx_fixture(graph, path, function, name, request)
    writes = [
        node
        for node in graph._walk(function)
        if isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    if len(writes) != 1 or isinstance(writes[0].ctx, ast.Del):
        return False
    assignment = graph.parents.get(id(writes[0]))
    if not isinstance(assignment, ast.Tuple) and not isinstance(assignment, ast.List):
        return False
    owner = graph.parents.get(id(assignment))
    if (
        not isinstance(owner, ast.Assign)
        or len(owner.targets) != 1
        or owner.targets[0] is not assignment
        or not isinstance(owner.value, ast.Name)
    ):
        return False
    fixture_name = owner.value.id
    leaves = assignment.elts
    if (
        not leaves
        or leaves[0] is not writes[0]
        or any(not isinstance(leaf, ast.Name) for leaf in leaves)
    ):
        return False
    from .credential_role_flows import binding_dominates

    if not binding_dominates(owner, request, graph.parents, function):
        return False
    fixture = graph._nearest_fixture(path, fixture_name, function)
    return bool(
        fixture
        and _tuple_httpx_fixture(graph, fixture[0], fixture[1], owner.value)
        and _client_uses_closed(graph, function, name, request)
    )


def _direct_httpx_fixture(graph, path, function, name, request):
    if any(name in graph.audit._bound_names(statement) for statement in function.body):
        return False
    fixture = graph._nearest_fixture(path, name, function)
    if not fixture or not _closed_fixture_decorator(graph, fixture[0], fixture[1]):
        return False
    loops = [
        node
        for node in fixture[1].body
        if isinstance(node, ast.AsyncFor)
        and isinstance(node.iter, ast.Call)
        and isinstance(node.iter.func, ast.Name)
        and len(node.iter.args) == 1
        and isinstance(node.iter.args[0], ast.Name)
        and isinstance(node.target, ast.Name)
    ]
    return bool(
        len(loops) == 1
        and graph._test_client_fixture(
            fixture[0], fixture[1], loops[0].iter.args[0].id, loops[0].target.id
        )
        and _client_uses_closed(graph, function, name, request)
    )


def _closed_fixture_decorator(graph, path, fixture):
    if graph._is_pytest_fixture(path, fixture):
        return True
    if len(fixture.decorator_list) != 1:
        return False
    decorator = fixture.decorator_list[0]
    if not isinstance(decorator, ast.Call) or decorator.args:
        return False
    if graph.audit._resolved_ast_name(decorator.func, graph.aliases[path]) not in {
        "pytest.fixture",
        "pytest_asyncio.fixture",
    }:
        return False
    keywords = {item.arg: item.value for item in decorator.keywords}
    if set(keywords) != {"params", "ids"}:
        return False
    params, ids = keywords["params"], keywords["ids"]
    return bool(
        isinstance(params, ast.List)
        and params.elts
        and all(
            isinstance(item, ast.Constant)
            and type(item.value) in {str, int, bool, type(None)}
            for item in params.elts
        )
        and isinstance(ids, ast.List)
        and len(ids.elts) == len(params.elts)
        and all(
            isinstance(item, ast.Constant) and type(item.value) is str
            for item in ids.elts
        )
        and graph._provider_is_unmodified("pytest", {"fixture"})
    )


def _client_uses_closed(graph, function, name, request):
    for node in graph._walk(function):
        if not isinstance(node, ast.Name) or node.id != name:
            continue
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            continue
        attr = graph.parents.get(id(node))
        if isinstance(attr, ast.Attribute) and attr.value is node:
            call = graph.parents.get(id(attr))
            if (
                isinstance(call, ast.Call)
                and call.func is attr
                and attr.attr in _HTTP_METHODS
                and call is request.value
            ):
                continue
            if _cookie_write(graph, node, attr):
                continue
        return False
    return True


def _cookie_write(graph, name, attribute):
    cookies = attribute
    setter = graph.parents.get(id(cookies))
    call = graph.parents.get(id(setter))
    return bool(
        isinstance(cookies, ast.Attribute)
        and cookies.value is name
        and cookies.attr == "cookies"
        and isinstance(setter, ast.Attribute)
        and setter.value is cookies
        and setter.attr == "set"
        and isinstance(call, ast.Call)
        and call.func is setter
        and call.args
        and all(isinstance(arg, ast.Constant) for arg in call.args)
        and not call.keywords
    )


def _tuple_httpx_fixture(graph, path, fixture, fixture_parameter):
    if not _closed_fixture_decorator(graph, path, fixture):
        return False
    loops = [
        node
        for node in fixture.body
        if isinstance(node, ast.AsyncFor)
        and isinstance(node.target, ast.Name)
        and isinstance(node.iter, ast.Call)
        and isinstance(node.iter.func, ast.Name)
        and node.iter.args
        and isinstance(node.iter.args[0], ast.Name)
    ]
    if len(loops) != 1:
        return False
    loop = loops[0]
    if (
        len(loop.body) != 1
        or not isinstance(loop.body[0], ast.Expr)
        or not isinstance(loop.body[0].value, ast.Yield)
        or not isinstance(loop.body[0].value.value, ast.Tuple)
        or not loop.body[0].value.value.elts
        or not isinstance(loop.body[0].value.value.elts[0], ast.Name)
        or loop.body[0].value.value.elts[0].id != loop.target.id
        or loop.iter.args[0].id != "app"
        or not isinstance(fixture_parameter, ast.Name)
        or not any(arg.arg == loop.iter.func.id for arg in fixture.args.args)
        or not isinstance(loop.iter.func, ast.Name)
    ):
        return False
    # The remaining tuple fields must be constants or pytest parameter echoes.
    for item in loop.body[0].value.value.elts[1:]:
        if isinstance(item, ast.Constant):
            continue
        if not isinstance(item, ast.Name):
            return False
        binding = graph._unique_name_assignment(fixture, item.id)
        if not isinstance(binding, ast.Assign) or not isinstance(
            binding.value, ast.Attribute
        ):
            return False
        if binding.value.attr != "param" or not isinstance(
            binding.value.value, ast.Name
        ):
            return False
    origin = graph._nearest_fixture(path, loop.iter.func.id)
    return bool(
        origin
        and graph._returned_httpx_client(*origin)
        and _fixture_app_uses_only_client(graph, fixture, loop)
    )


def _fixture_app_uses_only_client(graph, fixture, loop):
    app = loop.iter.args[0]
    bindings = [
        node
        for node in fixture.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and isinstance(app, ast.Name)
        and node.targets[0].id == app.id
    ]
    return bool(
        len(bindings) == 1
        and isinstance(app, ast.Name)
        and graph._unique_name_assignment(fixture, app.id) is bindings[0]
        and all(
            not isinstance(node, ast.Name)
            or node.id != app.id
            or node in {bindings[0].targets[0], app}
            or graph.parents.get(id(node)) in {bindings[0], loop.iter}
            for node in graph._walk(fixture)
        )
    )


tuple_httpx_fixture = _tuple_httpx_fixture
request_client_origin = _request_client_origin


def factory_fixture_consumer_status(
    graph, path, fixture, source, caller, app_consumers_closed, route_lookup_only
):
    if not isinstance(caller, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    parameters = [
        arg.arg
        for arg in (
            *caller.args.posonlyargs,
            *caller.args.args,
            *caller.args.kwonlyargs,
        )
    ]
    if fixture.name not in parameters:
        return None
    if graph._nearest_fixture(source, fixture.name, caller) != (path, fixture):
        return False if source == path else None
    uses = [
        node
        for node in graph._walk(caller)
        if isinstance(node, ast.Name) and node.id == fixture.name
    ]
    if not uses or not all(
        isinstance(graph.parents.get(id(node)), ast.Call)
        and graph.parents[id(node)].func is node
        for node in uses
    ):
        return False
    calls = [graph.parents[id(node)] for node in uses]
    if len(calls) != 1:
        return False
    call = calls[0]
    parent = graph.parents.get(id(call))
    if isinstance(parent, ast.Return) and parent.value is call:
        return bool(
            graph._is_pytest_fixture(source, caller)
            and app_consumers_closed(graph, source, caller)
        )
    if route_lookup_only(graph, source, caller, call):
        return True
    if (
        isinstance(parent, ast.Assign)
        and len(parent.targets) == 1
        and isinstance(parent.targets[0], ast.Name)
    ):
        return bool(tuple_httpx_fixture(graph, source, caller, parent.targets[0]))
    return False
