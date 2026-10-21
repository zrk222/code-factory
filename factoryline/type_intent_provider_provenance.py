"""Hash-bound local provider closure for type-intent fallback decisions."""

from __future__ import annotations

import ast
import json
from copy import copy
from hashlib import sha256
from pathlib import Path

_MAX_CLOSURE_MODULES = 64


def _captured_closure_closed(root, sources, closure):
    if not isinstance(closure, list) or len(closure) > _MAX_CLOSURE_MODULES:
        return False
    seen = set()
    for row in closure:
        if not isinstance(row, dict):
            return False
        path, digest, local = (
            row.get("path"),
            row.get("sha256"),
            row.get("local_imports"),
        )
        if (
            not isinstance(path, str)
            or not isinstance(digest, str)
            or not isinstance(local, list)
            or any(not isinstance(alias, str) for alias in local)
            or path in seen
        ):
            return False
        seen.add(path)
        parts = Path(path).parts
        if (
            parts
            and parts[-1] in {"typing.py", "typing_extensions.py"}
            or (
                len(parts) > 1
                and parts[-1] == "__init__.py"
                and parts[-2] in {"typing", "typing_extensions"}
            )
        ):
            return False
        raw = sources.get(root / path)
        if not isinstance(raw, bytes) or sha256(raw).hexdigest() != digest:
            return False
        try:
            tree = ast.parse(raw, filename=path)
        except (SyntaxError, ValueError, RecursionError):
            return False
        if dynamic_provider_capability(tree, local):
            return False
    return True


def dynamic_provider_capability(tree, local_imports=()):
    """Report dynamic provider capability when imports, bindings, or module effects escape the modeled inert subset."""
    if not isinstance(tree, ast.Module):
        return True
    local, sys_names, typing_names, type_names = set(local_imports), set(), set(), set()
    bindings = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            imports = [(item.asname or item.name, item.name) for item in node.names]
            names = {name for name, _module in imports}
            if len(names) < len(imports) or bindings.intersection(names):
                return True
            if any(
                name not in local and module not in {"sys", "typing"}
                for name, module in imports
            ):
                return True
            sys_names.update(
                n for n, module in imports if module == "sys" and n not in local
            )
            typing_names.update(
                n for n, module in imports if module == "typing" and n not in local
            )
            bindings.update(names)
        elif isinstance(node, ast.ImportFrom):
            names = [(item.asname or item.name, item.name) for item in node.names]
            bound_names = {name for name, _symbol in names}
            if (
                any(symbol == "*" or name not in local for name, symbol in names)
                or len(bound_names) < len(names)
                or bindings.intersection(bound_names)
            ):
                return True
            if node.level == 0 and node.module == "typing":
                type_names.update(n for n, symbol in names if symbol == "assert_type")
            bindings.update(bound_names)
    protected = sys_names | typing_names | type_names
    profile = local, protected, sys_names, type_names, typing_names
    return not _inert_body(tree.body, profile)


def owner_module_effects_closed(
    tree, selected_test, canonical, noop_write=None, local_imports=()
):
    """Confirm the provider module is closed after removing the selected assert_type test and any proven no-op write."""
    if (
        canonical != "typing.assert_type"
        or not isinstance(tree, ast.Module)
        or not isinstance(selected_test, (ast.FunctionDef, ast.AsyncFunctionDef))
        or sum(statement is selected_test for statement in tree.body) != 1
        or noop_write is not None
        and sum(statement is noop_write for statement in tree.body) != 1
    ):
        return False
    allowed_imports = set(local_imports) | {
        alias.asname or alias.name
        for statement in tree.body
        if isinstance(statement, ast.ImportFrom)
        and statement.level == 0
        and statement.module == "typing"
        for alias in statement.names
        if alias.name == "assert_type"
    }
    body = [
        _without_selected_test_body(item) if item is selected_test else item
        for item in tree.body
        if item is not noop_write
    ]
    return not dynamic_provider_capability(
        ast.Module(body=body, type_ignores=tree.type_ignores), allowed_imports
    )


def _without_selected_test_body(statement):
    shell = copy(statement)
    shell.body = []
    return shell


def _inert_body(body, profile, imports_allowed=True):
    local, protected, sys_names, type_names, typing_names = profile
    for node in body:
        if isinstance(node, ast.Pass):
            continue
        if imports_allowed and isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(node, ast.Expr) and (
            _inert_value(node.value, sys_names)
            or _canonical_type_call(node.value, type_names, typing_names)
        ):
            continue
        if isinstance(node, ast.Return) and (
            node.value is None or _inert_value(node.value, sys_names)
        ):
            continue
        if isinstance(node, ast.Assign) and _inert_assignment(
            node, protected, sys_names
        ):
            continue
        if isinstance(node, ast.FunctionDef) and _inert_function(node, profile):
            continue
        return False
    return True


def _inert_assignment(node, protected, sys_names):
    return bool(
        node.targets
        and all(
            isinstance(target, ast.Name)
            and target.id != "pytest_plugins"
            and target.id not in protected
            for target in node.targets
        )
        and _inert_value(node.value, sys_names)
    )


def _inert_function(node, profile):
    local, protected, sys_names, type_names, typing_names = profile
    args = node.args
    parameters = (*args.posonlyargs, *args.args, *args.kwonlyargs)
    parameters += tuple(arg for arg in (args.vararg, args.kwarg) if arg is not None)
    return bool(
        not node.decorator_list
        and not args.defaults
        and not any(args.kw_defaults)
        and not node.returns
        and not any(arg.annotation for arg in parameters)
        and not getattr(node, "type_params", ())
        and node.name not in protected
        and not any(arg.arg in protected for arg in parameters)
        and _inert_body(node.body, profile, imports_allowed=False)
    )


def _inert_value(node, sys_modules):
    return (
        isinstance(node, ast.Constant)
        or (
            isinstance(node, ast.Tuple)
            and all(_inert_value(item, sys_modules) for item in node.elts)
        )
        or isinstance(node, ast.Attribute)
        and isinstance(node.ctx, ast.Load)
        and node.attr == "version"
        and isinstance(node.value, ast.Name)
        and node.value.id in sys_modules
    )


def _simple_type_call(call):
    return (
        isinstance(call, ast.Call)
        and len(call.args) == 2
        and not call.keywords
        and all(isinstance(arg, (ast.Name, ast.Constant)) for arg in call.args)
        and not any(
            isinstance(child, ast.Call) and child is not call
            for child in ast.walk(call)
        )
    )


def _canonical_type_call(call, type_names, typing_names):
    if not _simple_type_call(call):
        return False
    function = call.func
    return (
        isinstance(function, ast.Name)
        and function.id in type_names
        or isinstance(function, ast.Attribute)
        and function.attr == "assert_type"
        and isinstance(function.value, ast.Name)
        and function.value.id in typing_names
    ) and not any(
        isinstance(arg, ast.Name) and arg.id in (type_names | typing_names)
        for arg in call.args
    )


def _source_name(node, aliases):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name) or node.id not in aliases:
        return None
    return ".".join((aliases[node.id], *reversed(parts)))


def bind_provider_context(
    context, root, path, imports, snapshots, eligible, resolver, initializer_lookup=None
):
    """Bind transitive local imports and ancestor conftests to one test source."""
    from .context_efficiency import captured_local_import_closure

    conftests = sorted(
        (
            source
            for source in snapshots
            if source.name == "conftest.py"
            and source != path
            and path.is_relative_to(source.parent)
        ),
        key=lambda source: (len(source.parts), source.as_posix()),
    )
    closure, complete = captured_local_import_closure(
        root, imports, snapshots, eligible, resolver, conftests, initializer_lookup
    )
    context["provider_source_closure"] = closure
    context["provider_source_closure_complete"] = complete
    context["provider_owner_local_imports"] = sorted(imports)


def _module_import_alias_candidates(statement, target_module, api=None):
    """List imported names that bind the target module or one of its parents."""
    if isinstance(statement, ast.Import):
        bindings = [
            (
                item.asname or item.name.split(".", 1)[0],
                item.name if item.asname else item.name.split(".", 1)[0],
                item,
            )
            for item in statement.names
        ]
    elif isinstance(statement, ast.ImportFrom) and statement.level == 0:
        module_name = statement.module or ""
        has_relevant_star = any(item.name == "*" for item in statement.names) and (
            _module_path_controls_target(module_name, target_module)
        )
        if has_relevant_star:
            return None
        bindings = [
            (
                item.asname or item.name,
                f"{module_name}.{item.name}" if module_name else item.name,
                item,
            )
            for item in statement.names
            if item.name != "*"
        ]
    else:
        return []
    return [
        item
        for item in bindings
        if _module_path_controls_target(item[1], target_module) or item[1] == api
    ]


def _module_path_controls_target(imported_path, target_module):
    """Whether a nonempty imported module controls this target path."""
    if not isinstance(imported_path, str) or not isinstance(target_module, str):
        return False
    return bool(imported_path and target_module) and (
        imported_path == target_module or target_module.startswith(imported_path + ".")
    )


def _capability_reflection_names():
    return {
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


def _module_has_dynamic_capability_access(nodes):
    """Fail closed on reflective calls that can reacquire imported modules."""
    dynamic_names = _capability_reflection_names()
    dynamic_aliases = set(dynamic_names)
    for node in nodes:
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.module == "sys" and any(item.name == "*" for item in node.names):
            return True
        if node.module in {"builtins", "importlib", "sys"}:
            dynamic_aliases.update(
                item.asname or item.name
                for item in node.names
                if item.name in dynamic_names
                or node.module == "importlib"
                and item.name == "import_module"
                or node.module == "sys"
                and item.name == "modules"
            )
    return any(
        isinstance(node, ast.Name)
        and node.id in dynamic_aliases
        or isinstance(node, ast.Attribute)
        and node.attr in dynamic_names | {"import_module", "modules"}
        for node in nodes
    )


def _mock_provider_capability(raw):
    from .context_efficiency import _module_has_dynamic_capability_access

    try:
        nodes = tuple(ast.walk(ast.parse(raw)))
    except (SyntaxError, ValueError, RecursionError, UnicodeDecodeError):
        return True
    return _module_has_dynamic_capability_access(nodes) or any(
        isinstance(node, ast.Import)
        and any(
            alias.name == "unittest" or alias.name.startswith("unittest.")
            for alias in node.names
        )
        or isinstance(node, ast.ImportFrom)
        and (
            node.module == "unittest"
            or (node.module or "").startswith("unittest.")
            or any(alias.name == "*" for alias in node.names)
        )
        for node in nodes
    )


def provider_source_inventory(root, source_bytes, manifest, output=None):
    """Retain the scanned Python inventory used by type-intent source proofs."""
    retained = {
        path.relative_to(root).as_posix(): raw for path, raw in source_bytes.items()
    }
    rows = [
        {
            "path": row["path"],
            "state": row["state"],
            "retained": row["path"] in retained,
            "sha256": sha256(retained[row["path"]]).hexdigest()
            if row["path"] in retained
            else None,
            "mock_provider_capability": _mock_provider_capability(retained[row["path"]])
            if row["path"] in retained
            else True,
        }
        for row in manifest
        if row["path"].lower().endswith(".py")
    ]
    if output is not None:
        output.extend(rows)
    return rows


def bind_provider_inventory(contexts, inventory):
    """Bind inventory completeness, capable paths, and a deterministic digest into each context, then return whether the inventory is complete."""
    complete = bool(inventory) and all(
        row.get("state") == "read" and row.get("retained") is True for row in inventory
    )
    capability_paths = sorted(
        row["path"]
        for row in inventory
        if row.get("mock_provider_capability") is not False
    )
    inventory_digest = sha256(
        json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    for context in contexts.values():
        context["provider_source_inventory_complete"] = complete
        context["mock_provider_capability_paths"] = capability_paths
        context["mock_provider_inventory_sha256"] = inventory_digest
    return complete


def provider_cache_fields(context):
    """Return the provider capability paths, inventory digest, and captured source-closure fields from an oracle context."""
    return {
        "mock_provider_capability_paths": context.get("mock_provider_capability_paths"),
        "mock_provider_inventory_sha256": context.get("mock_provider_inventory_sha256"),
        "provider_source_closure": context.get("provider_source_closure", []),
        "provider_owner_local_imports": context.get("provider_owner_local_imports", []),
        "provider_source_closure_complete": bool(
            context.get("provider_source_closure_complete", False)
        ),
        "provider_source_inventory_complete": bool(
            context.get("provider_source_inventory_complete", False)
        ),
    }


CACHE_HELPERS = tuple(
    helper
    for helper in globals().values()
    if getattr(helper, "__module__", None) == __name__
)
