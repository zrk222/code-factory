from __future__ import annotations

import ast

from .credential_httpx_origins import request_client_origin

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


def public_json_assertion(graph, path, node, parent):
    """Accept only a source-bound JSON comparison dominated by its request."""
    from .credential_role_scope_bindings import binding_dominates

    container = node
    while isinstance(parent, (ast.Dict, ast.List, ast.Tuple)):
        container = parent
        parent = graph.parents.get(id(parent))
    if (
        not isinstance(container, (ast.Dict, ast.Attribute))
        or not isinstance(parent, ast.Compare)
        or len(parent.ops) != 1
        or not isinstance(parent.ops[0], ast.Eq)
        or len(parent.comparators) != 1
    ):
        return False
    projection = parent.comparators[0] if parent.left is container else parent.left
    if projection is container:
        return False
    assertion = graph.parents.get(id(parent))
    function = graph._containing_function(assertion)
    if not isinstance(assertion, ast.Assert) or function is None:
        return False
    if (
        not isinstance(projection, ast.Subscript)
        or not isinstance(projection.value, ast.Name)
        or not isinstance(projection.slice, ast.Constant)
        or projection.slice.value != "detail"
    ):
        return False
    data_name = projection.value.id
    assignment = graph._unique_name_assignment(function, data_name)
    if (
        not isinstance(assignment, ast.Assign)
        or not isinstance(assignment.value, ast.Call)
        or graph.audit._resolved_ast_name(assignment.value.func, graph.aliases[path])
        != "typing.cast"
        or len(assignment.value.args) != 2
        or assignment.value.keywords
        or not binding_dominates(assignment, assertion, graph.parents, function)
    ):
        return False
    response_call = assignment.value.args[1]
    if (
        not isinstance(response_call, ast.Call)
        or not isinstance(response_call.func, ast.Attribute)
        or response_call.func.attr != "json"
        or response_call.args
        or response_call.keywords
        or not isinstance(response_call.func.value, ast.Name)
    ):
        return False
    response_name = response_call.func.value.id
    response_assignment = graph._unique_name_assignment(function, response_name)
    request = (
        response_assignment.value
        if isinstance(response_assignment, ast.Assign)
        else None
    )
    if (
        not isinstance(response_assignment, ast.Assign)
        or not binding_dominates(
            response_assignment, assignment, graph.parents, function
        )
        or not isinstance(request, ast.Await)
        or not isinstance(request.value, ast.Call)
        or not isinstance(request.value.func, ast.Attribute)
        or request.value.func.attr not in _HTTP_METHODS
        or not isinstance(request.value.func.value, ast.Name)
    ):
        return False
    return (
        request_client_origin(graph, path, function, request)
        and graph._provider_is_unmodified("typing", {"cast"})
        and _assertion_values(
            graph, path, function, container, data_name, response_name
        )
    )


def _assertion_values(graph, path, function, expected, data_name, response_name):
    names = [
        node
        for node in graph._walk(function)
        if isinstance(node, ast.Name) and node.id in {data_name, response_name}
    ]
    if (
        sum(node.id == data_name and isinstance(node.ctx, ast.Load) for node in names)
        != 1
    ):
        return False
    responses = [
        node
        for node in names
        if node.id == response_name and isinstance(node.ctx, ast.Load)
    ]
    if not responses:
        return False
    for node in responses:
        attribute = graph.parents.get(id(node))
        parent = graph.parents.get(id(attribute))
        if not isinstance(attribute, ast.Attribute) or attribute.value is not node:
            return False
        if attribute.attr == "json":
            if (
                not isinstance(parent, ast.Call)
                or parent.func is not attribute
                or parent.args
                or parent.keywords
            ):
                return False
        elif attribute.attr != "status_code" or isinstance(parent, ast.Call):
            return False
    if isinstance(expected, ast.Attribute):
        return _public_enum_member(graph, path, expected)
    return isinstance(expected, ast.Dict) and all(
        isinstance(key, ast.Constant)
        and type(key.value) is str
        and _public_expected_value(graph, path, value)
        for key, value in zip(expected.keys, expected.values)
    )


def _public_expected_value(graph, path, value):
    if isinstance(value, ast.Constant):
        return type(value.value) in {str, int, bool, type(None)}
    return isinstance(value, ast.Attribute) and _public_enum_member(graph, path, value)


def _public_enum_member(graph, path, value):
    if graph._json_expected_member(path, ast.Constant("detail"), value):
        return True
    origin = graph.resolve(path, tuple(graph.audit._name(value).split(".")))
    resolved_bases = []
    if origin and origin[0] == "class":
        owner = graph.objects.get(origin[1:3])
        if isinstance(owner, ast.ClassDef):
            resolved_bases = [
                graph.audit._resolved_ast_name(base, graph.aliases[path])
                for base in owner.bases
            ]
            resolved_bases = [
                graph.aliases[path].get(base, base) for base in resolved_bases
            ]
    if not origin or origin[0] != "class" or len(origin[3]) != 1:
        return False
    owner = graph.objects.get(origin[1:3])
    if (
        not isinstance(owner, ast.ClassDef)
        or owner.decorator_list
        or owner.keywords
        or resolved_bases != ["str", "enum.Enum"]
        or not graph._provider_is_unmodified("enum", {"Enum"})
    ):
        return False
    members = {}
    for statement in owner.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            return False
        target = statement.targets[0]
        if not isinstance(target, ast.Name) or not isinstance(
            statement.value, ast.Constant
        ):
            return False
        if type(statement.value.value) is not str or statement.value.value != target.id:
            return False
        members[target.id] = statement
    return origin[3][0] in members
