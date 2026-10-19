"""Exact class-field aliases and source-proven constructor consumers."""

import ast

from .credential_role_constructor_consumer import (
    _captured_method,
    _classmethod,
    _consumer_effect_safe,
    _is_call_argument,
    _is_safe_isinstance_value,
    source_owner_consumer,
)
from . import credential_role_constructor_consumer as _consumer

from .credential_role_scope_bindings import binding_occurrences
from .review_audits import _resolved_ast_name


def class_binding(owner, name, parents):
    bindings = binding_occurrences(owner.body, name)
    if not bindings:
        return None
    if len(bindings) != 1:
        return False
    target = bindings[0]
    statement = parents.get(id(target))
    if parents.get(id(statement)) is not owner:
        return False
    targets = getattr(statement, "targets", [getattr(statement, "target", None)])
    if (
        len(targets) != 1
        or targets[0] is not target
        or not isinstance(getattr(statement, "value", None), (ast.Name, ast.Attribute))
    ):
        return False
    return statement.value


def init_override(owner, parents):
    bindings = binding_occurrences(owner.body, "__init__")
    if not bindings:
        return None
    return (
        len(bindings) == 1
        and isinstance(bindings[0], (ast.FunctionDef, ast.AsyncFunctionDef))
        and parents.get(id(bindings[0])) is owner
    )


def capture_holder_instances(
    tree, parents, aliases, owners, roots, path, filtered, field_aliases, resolve
):
    for node, target in _single_name_assignments(tree):
        name, parent = target.id, parents.get(id(node))
        value = node.value
        if name != "client_class" and isinstance(value, (ast.Name, ast.Attribute)):
            holder = resolve(value, aliases)
            if holder in owners:
                if not _capture_class_alias(
                    tree, parent, name, holder, aliases, field_aliases, resolve
                ):
                    return False
                filtered.setdefault(path, set()).add(id(node))
            continue
        if not isinstance(value, ast.Call):
            continue
        holder = resolve(value.func, aliases)
        if holder not in owners:
            continue
        if not isinstance(parent, ast.Module):
            if not _local_holder_unused_selector(parent, parents, name):
                return False
            continue
        if len(binding_occurrences(tree.body, name)) != 1:
            return False
        aliases[name] = holder
        roots.add(holder + ".client_class")
    return True


def _single_name_assignments(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(targets) == 1 and isinstance(targets[0], ast.Name):
                yield node, targets[0]


def _local_holder_unused_selector(parent, parents, name):
    scope = parent
    while scope is not None and not isinstance(
        scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    ):
        scope = parents.get(id(scope))
    return isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and not any(
        isinstance(item, ast.Attribute)
        and item.attr == "client_class"
        and isinstance(item.value, ast.Name)
        and item.value.id == name
        for item in ast.walk(scope)
    )


def _capture_class_alias(tree, parent, name, holder, aliases, fields, resolve):
    scope = parent if parent is tree or isinstance(parent, ast.ClassDef) else None
    if scope is None or len(binding_occurrences(scope.body, name)) != 1:
        return False
    if scope is tree:
        aliases[name] = holder
    else:
        class_path = resolve(ast.Name(scope.name, ast.Load()), aliases)
        if not class_path.startswith("captured_"):
            return False
        fields[class_path + "." + name] = holder
    return True


def instance_selector_edges(tree, aliases, owners, roots, path, filtered, resolve):
    selected = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Attribute):
            continue
        target = targets[0]
        owner = resolve(target.value, aliases)
        if (
            target.attr == "client_class"
            and owner.startswith("captured_")
            and resolve(node.value, aliases) in roots
        ):
            selected.append((node, owner))
    for node, owner in selected:
        if sum(item == owner for _, item in selected) != 1:
            return False
        owners.add(owner)
        roots.add(owner + ".client_class")
        filtered.setdefault(path, set()).add(id(node))
    return True


def field_alias_path(provider, aliases):
    return next(
        (
            owner + provider[len(alias) :]
            for alias, owner in aliases.items()
            if provider == alias or provider.startswith(alias + ".")
        ),
        provider,
    )


def owner_path(node, aliases, fields):
    return field_alias_path(_resolved_ast_name(node, aliases), fields)


def class_index(index, aliases_by_path):
    rows = {}
    for path, tree in index.snapshots.items():
        aliases = aliases_by_path[path]
        for owner in tree.body:
            if isinstance(owner, ast.ClassDef):
                rows[aliases.get(owner.name)] = (path, owner, aliases, tree)
    return {name: row for name, row in rows.items() if name}


def constructor_provider_provenance_epoch():
    return (
        class_binding,
        init_override,
        capture_holder_instances,
        _capture_class_alias,
        _local_holder_unused_selector,
        _single_name_assignments,
        instance_selector_edges,
        field_alias_path,
        owner_path,
        class_index,
        source_owner_consumer,
        _captured_method,
        _classmethod,
        _is_call_argument,
        _consumer_effect_safe,
        _is_safe_isinstance_value,
        binding_occurrences,
        _consumer.summarize_identity_effect,
        _consumer.bind_source_call,
        _resolved_ast_name,
    )
