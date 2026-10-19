"""Hash-bound local provider closure for type-intent fallback decisions."""

from __future__ import annotations

import ast
from hashlib import sha256
from pathlib import Path

from factoryline.type_intent_dynamic_capability import (
    CACHE_HELPERS as _DYNAMIC_CAPABILITY_HELPERS,
)
from factoryline.type_intent_dynamic_capability import (
    dynamic_provider_capability as _dynamic_provider_capability,
)

_PROVIDER_MODULES = {"typing", "typing_extensions"}
_MAX_CLOSURE_MODULES = 64


def captured_local_import_closure(root, imports, snapshots, eligible, resolver):
    """Return bounded transitive local imports with exact snapshot hashes."""
    pending = [source for source, _symbol in imports.values()]
    seen = set()
    rows = []
    while pending:
        source = pending.pop()
        if source in seen:
            continue
        seen.add(source)
        if len(seen) > _MAX_CLOSURE_MODULES:
            return [], False
        tree = snapshots.get(source)
        digest = getattr(tree, "_oracle_source_sha256", None)
        if not isinstance(tree, ast.Module) or not isinstance(digest, str):
            return [], False
        rows.append({"path": source.relative_to(root).as_posix(), "sha256": digest})
        pending.extend(
            child for child, _symbol in resolver(root, source, tree, eligible).values()
        )
    rows.sort(key=lambda item: item["path"])
    return rows, True


def captured_provider_context_closed(module: ast.Module, relative: str) -> bool:
    """Prove reachable local imports cannot replace or redirect assert_type."""
    context = getattr(module, "_security_oracle_context", None)
    source_context = getattr(module, "_security_source_context", None)
    digest = getattr(module, "_oracle_source_sha256", None)
    if not _provider_context_ready(context, relative):
        return False
    if not _source_context_ready(source_context):
        return False
    root, sources = source_context
    if not _source_matches(root, relative, digest, sources):
        return False
    return _captured_closure_closed(root, sources, context["provider_source_closure"])


def provider_source_inventory_complete(inventory):
    """Require all enumerated Python inputs to be read and byte-retained."""
    return bool(inventory) and all(
        item.get("state") == "read" and item.get("retained") is True
        for item in inventory
    )


def bind_provider_inventory(contexts, complete):
    """Attach current manifest completeness to each projected source context."""
    for context in contexts.values():
        context["provider_source_inventory_complete"] = bool(complete)


def _provider_context_ready(context, relative):
    return bool(
        isinstance(context, dict)
        and _valid_relative(relative)
        and context.get("provider_source_inventory_complete")
        and context.get("provider_source_closure_complete")
        and isinstance(context.get("provider_source_closure"), list)
    )


def _source_context_ready(source_context):
    return bool(
        isinstance(source_context, tuple)
        and len(source_context) == 2
        and isinstance(source_context[0], Path)
        and isinstance(source_context[1], dict)
    )


def _captured_closure_closed(root, sources, closure):
    if not isinstance(closure, list) or len(closure) > _MAX_CLOSURE_MODULES:
        return False
    for item in closure:
        if not isinstance(item, dict):
            return False
        path, expected = item.get("path"), item.get("sha256")
        if not _valid_relative(path) or not isinstance(expected, str):
            return False
        raw = sources.get(root / path)
        if not isinstance(raw, bytes) or sha256(raw).hexdigest() != expected:
            return False
        if _is_provider_path(path):
            return False
        try:
            tree = ast.parse(raw, filename=path)
        except (SyntaxError, ValueError, RecursionError):
            return False
        if _provider_alias_used(tree) or _dynamic_provider_capability(tree):
            return False
    return True


def _source_matches(root, relative, expected, sources):
    if not isinstance(expected, str) or len(expected) != 64:
        return False
    raw = sources.get(root / relative)
    return isinstance(raw, bytes) and sha256(raw).hexdigest() == expected


def _valid_relative(value):
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts


def _is_provider_path(value):
    parts = Path(value).parts
    return bool(
        parts
        and (
            parts[-1] in {"typing.py", "typing_extensions.py"}
            or len(parts) >= 2
            and parts[-1] == "__init__.py"
            and parts[-2] in _PROVIDER_MODULES
        )
    )


def _provider_alias_used(tree):
    aliases = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases.update(
                item.asname or item.name.split(".")[0]
                for item in node.names
                if item.name in _PROVIDER_MODULES
            )
        elif isinstance(node, ast.ImportFrom) and node.module in _PROVIDER_MODULES:
            aliases.update(
                item.asname or item.name for item in node.names if item.name != "*"
            )
    if any(
        isinstance(node, ast.Name) and node.id in aliases for node in ast.walk(tree)
    ):
        return True
    return any(
        isinstance(node, ast.Constant) and node.value in _PROVIDER_MODULES
        for node in ast.walk(tree)
    )


CACHE_HELPERS = (
    captured_local_import_closure,
    captured_provider_context_closed,
    provider_source_inventory_complete,
    bind_provider_inventory,
    _provider_context_ready,
    _source_context_ready,
    _captured_closure_closed,
    _source_matches,
    _valid_relative,
    _is_provider_path,
    _provider_alias_used,
    *_DYNAMIC_CAPABILITY_HELPERS,
)
