"""Hash-bound local provider closure for type-intent fallback decisions."""

from __future__ import annotations

import ast
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


def bind_provider_context(context, root, path, imports, snapshots, eligible, resolver):
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
        root, imports, snapshots, eligible, resolver, conftests
    )
    context["provider_source_closure"] = closure
    context["provider_source_closure_complete"] = complete
    context["provider_owner_local_imports"] = sorted(imports)


def provider_source_inventory(root, source_bytes, manifest, output=None):
    """Retain the scanned Python inventory used by type-intent source proofs."""
    retained = {path.relative_to(root).as_posix() for path in source_bytes}
    rows = [
        {
            "path": row["path"],
            "state": row["state"],
            "retained": row["path"] in retained,
        }
        for row in manifest
        if row["path"].lower().endswith(".py")
    ]
    if output is not None:
        output.extend(rows)
    return rows


def bind_provider_inventory(contexts, inventory):
    complete = bool(inventory) and all(
        row.get("state") == "read" and row.get("retained") is True for row in inventory
    )
    for context in contexts.values():
        context["provider_source_inventory_complete"] = complete
    return complete


def provider_cache_fields(context):
    return {
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
