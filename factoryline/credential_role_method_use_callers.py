"""Exact source call binding for candidate-linked getter receivers."""

import ast

from .credential_role_method_use_common import ancestor
from .credential_role_scope_bindings import binding_occurrences


def parameter_linked(path, receiver, calls, index, imports, classes, owners):
    function = ancestor(
        receiver, index, index.relative(path), (ast.FunctionDef, ast.AsyncFunctionDef)
    )
    if function is None:
        return False
    _, possible_parameters = _parameter_alias(function, receiver.id)
    if not possible_parameters:
        return False
    for call in calls:
        if not _targets_function(call, function, path, index):
            continue
        from .review_integrity import bind_source_call

        try:
            actuals = bind_source_call(call, function, apply_defaults=False)
        except (TypeError, ValueError):
            continue
        from .credential_role_object_identity import declared_origins

        for name in possible_parameters:
            actual = actuals.get(name)
            if actual is None:
                continue
            if declared_origins(path, actual, index, imports, classes) & owners or (
                isinstance(actual, ast.Name)
                and _related_method_self(call, actual, index, path, owners)
            ):
                return True
    return False


def _related_method_self(call, actual, index, path, owners):
    relative = index.relative(path)
    owner = class_identity(call, index, path)
    if owner is None or (index.root / owner[0], owner[1]) not in owners:
        return False
    caller = ancestor(call, index, relative, (ast.FunctionDef, ast.AsyncFunctionDef))
    if caller is None or class_identity(caller, index, path) != owner:
        return False
    positional = [*caller.args.posonlyargs, *caller.args.args]
    return bool(
        positional
        and positional[0].arg == actual.id
        and not binding_occurrences(caller.body, actual.id)
    )


def _parameter_alias(function, name):
    parameters = [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]
    parameter_names = {item.arg for item in parameters}
    exact, seen = name, set()
    for _ in range(5):
        if exact in parameter_names:
            return exact, {exact}
        if exact in seen:
            break
        seen.add(exact)
        bindings = binding_occurrences(function.body, exact)
        assignment = _assignment_for_bindings(function, bindings)
        if len(bindings) != 1 or assignment is None:
            break
        if not isinstance(assignment.value, ast.Name):
            break
        exact = assignment.value.id
    return None, _possible_formals(function, name, parameter_names)


def _possible_formals(function, name, parameters):
    found, pending, seen = set(), [name], set()
    while pending and len(seen) < 5:
        current = pending.pop()
        if current in parameters:
            found.add(current)
            continue
        if current in seen:
            continue
        seen.add(current)
        bindings = binding_occurrences(function.body, current)
        for assignment in _assignments_for_bindings(function, bindings):
            if assignment.value is None:
                continue
            pending.extend(
                node.id
                for node in ast.walk(assignment.value)
                if isinstance(node, ast.Name)
            )
    return found


def _assignments_for_bindings(function, bindings):
    return [
        node
        for node in ast.walk(function)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and any(
            target in bindings
            for target in (
                node.targets if isinstance(node, ast.Assign) else [node.target]
            )
        )
    ]


def _assignment_for_bindings(function, bindings):
    assignments = _assignments_for_bindings(function, bindings)
    return assignments[0] if len(assignments) == 1 else None


def _targets_function(call, function, path, index):
    if not isinstance(call.func, ast.Name):
        return False
    if call.func.id == function.name:
        return True
    tree = index.snapshots[path]
    caller = ancestor(
        call, index, index.relative(path), (ast.FunctionDef, ast.AsyncFunctionDef)
    )
    scopes = [caller.body] if caller else []
    scopes.append(tree.body)
    for statements in scopes:
        aliases, targets = {}, {}
        for node in statements:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            values = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(values) == 1 and isinstance(values[0], ast.Name):
                targets[values[0].id] = values[0]
                if isinstance(node.value, ast.Name):
                    aliases[values[0].id] = node.value.id
        alias, seen = call.func.id, set()
        while alias in aliases and alias not in seen:
            seen.add(alias)
            binding = targets.get(alias)
            if binding is None or binding_occurrences(statements, alias) != [binding]:
                break
            alias = aliases[alias]
        if alias == function.name:
            return True
    return False


def class_identity(node, index, path):
    owner = node
    while owner is not None:
        if isinstance(owner, ast.ClassDef):
            return (index.relative(path), owner.name)
        owner = index.parents[path].get(id(owner))
    return None
