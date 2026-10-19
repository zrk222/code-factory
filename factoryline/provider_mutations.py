"""Source-bound reflective writes and escapes for provider APIs."""

import ast
from collections import defaultdict


def finite_provider_mutation_index(
    nodes, aliases, audit, parents, *, capture_predicate=None
):
    bindings = _provider_alias_bindings(nodes)
    facts = set()
    for node in nodes:
        if isinstance(node, ast.Attribute) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            _record_provider_paths(
                node.value, node.attr, aliases, audit, bindings, facts
            )
        elif isinstance(node, ast.Call):
            _reflective_provider_write(node, aliases, audit, bindings, facts)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            if capture_predicate is None or capture_predicate(node):
                _record_provider_capture(node, aliases, audit, bindings, facts)
        elif isinstance(node, (ast.Name, ast.Attribute)):
            if _provider_call_argument(node, parents):
                _record_provider_paths(node, "*", aliases, audit, bindings, facts)
        elif isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)):
            _record_provider_paths(node.value, "*", aliases, audit, bindings, facts)
    return facts


def _record_provider_paths(node, attribute, aliases, audit, bindings, facts):
    paths, uncertain = _provider_paths(node, aliases, audit, bindings)
    facts.update((path, attribute) for path in paths)
    if uncertain:
        facts.update((path, "*") for path in paths)


def _record_provider_capture(node, aliases, audit, bindings, facts):
    value = node.value
    paths, _ = _provider_paths(value, aliases, audit, bindings)
    facts.update((path, "*") for path in paths)


def _provider_alias_bindings(nodes):
    bindings = defaultdict(list)
    for node in nodes:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bindings[target.id].append(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None:
                bindings[node.target.id].append(node.value)
    return bindings


def _provider_paths(node, aliases, audit, bindings, seen=frozenset(), depth=0):
    if depth > 16 or not isinstance(node, (ast.Name, ast.Attribute)):
        return set(), True
    if isinstance(node, ast.Attribute):
        paths, uncertain = _provider_paths(
            node.value, aliases, audit, bindings, seen, depth + 1
        )
        return {path + "." + node.attr for path in paths}, uncertain
    canonical = audit._resolved_ast_name(node, aliases)
    if "." in canonical:
        return {canonical}, False
    if aliases.get(node.id) == canonical and canonical:
        return {canonical}, False
    if node.id in seen:
        return set(), True
    values = bindings.get(node.id)
    if not values:
        return set(), True
    paths = set()
    uncertain = False
    for value in values:
        found, unknown = _provider_paths(
            value, aliases, audit, bindings, seen | {node.id}, depth + 1
        )
        paths.update(found)
        uncertain = uncertain or unknown or not found
    return paths, uncertain and bool(paths)


def _provider_call_argument(node, parents):
    child = node
    parent = parents.get(id(child))
    while parent is not None and not isinstance(parent, ast.Call):
        child = parent
        parent = parents.get(id(parent))
    return bool(
        isinstance(parent, ast.Call)
        and (
            any(argument is child for argument in parent.args)
            or any(keyword.value is child for keyword in parent.keywords)
        )
    )


def _reflective_provider_write(call, aliases, audit, bindings, facts):
    function = call.func
    canonical = audit._resolved_ast_name(function, aliases)
    receiver = None
    attribute = None
    if canonical in {"setattr", "builtins.setattr"} and len(call.args) >= 2:
        receiver, attribute = call.args[:2]
    elif (
        isinstance(function, ast.Attribute)
        and function.attr == "__setattr__"
        and call.args
    ):
        receiver, attribute = function.value, call.args[0]
    if receiver is None:
        return
    paths, uncertain = _provider_paths(receiver, aliases, audit, bindings)
    name = (
        attribute.value
        if isinstance(attribute, ast.Constant) and type(attribute.value) is str
        else "*"
    )
    facts.update((path, name) for path in paths)
    if uncertain:
        facts.update((path, "*") for path in paths)
