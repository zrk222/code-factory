"""Detect unmodeled namespace and reflection capabilities in captured code."""

from __future__ import annotations

import ast

_DYNAMIC_BUILTINS = {
    "__builtins__",
    "__import__",
    "delattr",
    "eval",
    "exec",
    "getattr",
    "globals",
    "locals",
    "setattr",
    "vars",
}


def dynamic_provider_capability(tree):
    """Reject unresolved capability loads; allow only direct sys.version reads."""
    sys_modules, opaque_modules, dynamic_names = set(), set(), set(_DYNAMIC_BUILTINS)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            _collect_imports(node, sys_modules, opaque_modules)
        elif isinstance(node, ast.ImportFrom):
            _collect_from(node, dynamic_names)
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    return _has_unmodeled_load(
        tree, parents, sys_modules, opaque_modules, dynamic_names
    )


def _collect_imports(node, sys_modules, opaque_modules):
    for item in node.names:
        alias = item.asname or item.name.split(".")[0]
        if item.name == "sys":
            sys_modules.add(alias)
        else:
            opaque_modules.add(alias)


def _collect_from(node, dynamic_names):
    for item in node.names:
        # Imported values have no inert-effect contract here. Namespace mappings,
        # frame readers and aliases can all reach or replace the oracle provider.
        dynamic_names.add(item.asname or item.name)


def _has_unmodeled_load(tree, parents, sys_modules, opaque_modules, dynamic_names):
    if "*" in dynamic_names:
        return True
    for node in ast.walk(tree):
        if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load):
            continue
        if node.id in dynamic_names or node.id in opaque_modules:
            return True
        if node.id in sys_modules and not _safe_version_read(node, parents):
            return True
    return False


def _safe_version_read(node, parents):
    parent = parents.get(node)
    return bool(
        isinstance(parent, ast.Attribute)
        and parent.value is node
        and parent.attr == "version"
    )


CACHE_HELPERS = (
    dynamic_provider_capability,
    _collect_imports,
    _collect_from,
    _has_unmodeled_load,
    _safe_version_read,
)
