"""Project bounded class-selector aliases into provider mutation roots."""

import ast

from .credential_role_constructor_provider_provenance import (
    capture_holder_instances,
    class_binding,
    constructor_provider_provenance_epoch,
    init_override,
    instance_selector_edges,
)
from .credential_role_scope_bindings import binding_occurrences


def constructor_provider_model(selected, index, imports, source_aliases, capture_guard):
    from .review_audits import _resolved_ast_name

    roots, owners, shared = set(selected), set(), set()
    filtered, aliases_by_path, field_aliases, consumers = {}, {}, {}, set()
    for path, tree in index.snapshots.items():
        if not index.validate(path):
            return None
        aliases_by_path[path] = source_aliases(path, tree, imports.get(path, {}), index)
    if (
        not _class_selector_edges(
            index, aliases_by_path, roots, owners, filtered, _resolved_ast_name
        )
        or not _class_descendant_edges(
            index, aliases_by_path, selected, owners, roots, shared, _resolved_ast_name
        )
        or not _instance_aliases(
            index,
            aliases_by_path,
            owners,
            roots,
            filtered,
            field_aliases,
            _resolved_ast_name,
        )
        or capture_guard(
            index, aliases_by_path, owners, filtered, field_aliases, consumers
        )
    ):
        return None
    return roots, aliases_by_path, filtered, shared, field_aliases, consumers


def _class_selector_edges(index, aliases_by_path, roots, owners, filtered, resolve):
    for path, tree in index.snapshots.items():
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            owner = index.parents[path].get(id(node))
            if (
                len(targets) != 1
                or not isinstance(targets[0], ast.Name)
                or targets[0].id != "client_class"
                or not isinstance(node.value, (ast.Name, ast.Attribute))
                or not isinstance(owner, ast.ClassDef)
            ):
                continue
            owner = ast.Name(id=owner.name, ctx=ast.Load())
            owner_path = resolve(owner, aliases_by_path[path])
            if resolve(node.value, aliases_by_path[path]) not in roots:
                continue
            if not owner_path.startswith("captured_"):
                return False
            roots.add(owner_path + ".client_class")
            owners.add(owner_path)
            filtered.setdefault(path, set()).add(id(node))
    return True


def _class_descendant_edges(
    index, aliases_by_path, selected, owners, roots, shared, resolve
):
    init_classes = set(selected)
    for _ in range(16):
        changed = False
        for path, tree in index.snapshots.items():
            aliases, parents = aliases_by_path[path], index.parents[path]
            for child in (item for item in tree.body if isinstance(item, ast.ClassDef)):
                result = _descendant_edges_for_class(
                    child,
                    aliases,
                    parents,
                    owners,
                    roots,
                    init_classes,
                    shared,
                    resolve,
                )
                if result is None:
                    return False
                changed |= result
        if not changed:
            return True
    return False


def _descendant_edges_for_class(
    child, aliases, parents, owners, roots, init_classes, shared, resolve
):
    path = resolve(ast.Name(child.name, ast.Load()), aliases)
    bases = [resolve(base, aliases) for base in child.bases]
    selector_parent = any(base in owners for base in bases)
    init_parent = any(base in init_classes for base in bases)
    if not selector_parent and not init_parent:
        return False
    if len(bases) != 1 or not path.startswith("captured_"):
        return None
    changed = False
    if selector_parent and path not in owners:
        field = class_binding(child, "client_class", parents)
        value = (
            resolve(field, aliases) if field is not None and field is not False else ""
        )
        if field is False or (
            field is not None
            and value not in roots
            and not value.startswith("captured_")
        ):
            return None
        if field is None or value in roots:
            owners.add(path)
            roots.add(path + ".client_class")
            changed = True
    if init_parent:
        override = init_override(child, parents)
        if override is False:
            return None
        if override is None and path not in init_classes:
            init_classes.add(path)
            shared.add(path + ".__init__")
            changed = True
    return changed


def _instance_aliases(
    index, aliases_by_path, owners, roots, filtered, field_aliases, resolve
):
    for path, tree in index.snapshots.items():
        aliases = aliases_by_path[path]
        if not capture_holder_instances(
            tree,
            index.parents[path],
            aliases,
            owners,
            roots,
            path,
            filtered,
            field_aliases,
            resolve,
        ):
            return False
        if not instance_selector_edges(
            tree, aliases, owners, roots, path, filtered, resolve
        ):
            return False
    return True


def constructor_provider_model_helper_epoch():
    from .review_audits import _resolved_ast_name

    return (
        constructor_provider_model,
        _class_selector_edges,
        _class_descendant_edges,
        _descendant_edges_for_class,
        _instance_aliases,
        binding_occurrences,
        _resolved_ast_name,
        *constructor_provider_provenance_epoch(),
    )
