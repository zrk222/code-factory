"""Three fail-closed senior-review controls: intent/diff, freshness, and policy ownership."""

from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import io
import json
import os
import re
import tempfile
import ast
import tokenize
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from .revenueforge import AUTHORITY, RevenueForgeError


def _name(node: ast.AST | None) -> str:
    return ast.unparse(node) if node is not None else ""


def _resolve(node: ast.AST | None, aliases: dict[str, str]) -> str:
    name = _name(node)
    head, dot, tail = name.partition(".")
    return aliases.get(head, head) + dot + tail


def import_smoke_oracle(node: ast.AST) -> bool:
    """Recognize import-availability/export smoke tests, not semantic coverage."""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    if not node.name.startswith("test_import_"):
        return False
    body = node.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    return bool(body) and all(
        isinstance(statement, ast.Import)
        or (
            isinstance(statement, ast.ImportFrom)
            and all(alias.name != "*" for alias in statement.names)
        )
        for statement in body
    )


def _oracle_body(node: ast.AST) -> list[ast.stmt]:
    body = list(node.body)
    if body and _is_docstring(body[0]):
        body.pop(0)
    return body


def _structural_oracle_context(
    tree: ast.Module, imports: dict, snapshots: dict
) -> dict:
    """Summarize direct bindings and visible local module behavior for test oracles."""
    module_imports, rebound = {}, set()
    for stmt in tree.body:
        if isinstance(stmt, ast.Import):
            module_imports.update(
                {a.asname or a.name.split(".")[0]: a.name for a in stmt.names}
            )
        elif isinstance(stmt, ast.ImportFrom):
            module_imports.update(
                {
                    a.asname or a.name: stmt.module or ""
                    for a in stmt.names
                    if a.name != "*"
                }
            )
        else:
            rebound.update(_oracle_bound_names(stmt))
    dynamic, classes = set(), {}
    for alias, (source, symbol) in imports.items():
        module = snapshots.get(source)
        body = getattr(module, "body", ())
        if any(
            isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name == "__getattr__"
            for n in body
        ):
            dynamic.add(alias)
        if symbol and any(
            isinstance(n, ast.ClassDef) and n.name == symbol for n in body
        ):
            classes[alias] = symbol
    return {
        "module_imports": module_imports,
        "module_rebindings": rebound,
        "dynamic_getattr_modules": dynamic,
        "class_imports": classes,
        "source_classes": set(classes),
    }


def _attribute_chain_root(node: ast.AST) -> str | None:
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _attribute_access_oracle(node: ast.AST, context: dict) -> bool:
    """Credit only pure reads from a direct, non-mock module import."""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    params = {
        a.arg for a in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
    }
    params.update(a.arg for a in (node.args.vararg, node.args.kwarg) if a)
    body = _oracle_body(node)
    reads = [s for s in body if isinstance(s, ast.Expr)]
    if not reads or not all(
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Attribute)
        and all(
            not isinstance(part, ast.Call) or (not part.args and not part.keywords)
            for part in ast.walk(stmt.value)
        )
        for stmt in reads
    ):
        return False
    imports = context.get("module_imports", {})
    bound = context.get("module_rebindings", set())
    roots = {_attribute_chain_root(s.value) for s in reads}
    body_bindings = set().union(*(_oracle_bound_names(stmt) for stmt in body))
    if (
        not roots
        or None in roots
        or roots & params
        or roots & bound
        or roots & body_bindings
    ):
        return False
    for root in roots:
        imported = imports.get(root, "")
        if not imported or imported.startswith(("unittest.mock", "mock")):
            return False
        if root in context.get("dynamic_getattr_modules", set()):
            return False
    return all(
        (isinstance(s, ast.Expr) and isinstance(s.value, ast.Attribute))
        or isinstance(s, ast.Import)
        or (isinstance(s, ast.ImportFrom) and all(a.name != "*" for a in s.names))
        for s in body
    )


def _typed_stub_parts(body: list[ast.stmt]):
    defs = [
        s
        for s in body
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    if not defs or body[: len(defs)] != defs:
        return None
    functions = [d for d in defs if not isinstance(d, ast.ClassDef)]
    classes = [d for d in defs if isinstance(d, ast.ClassDef)]
    return (
        (defs, functions, classes)
        if functions and all(_annotated_stub(fn) for fn in functions)
        else None
    )


def _typed_stub_decorators_known(functions: list, context: dict) -> bool:
    imports = context.get("module_imports", {})
    return all(
        isinstance(d, ast.Name)
        and d.id == "asynccontextmanager"
        and imports.get(d.id) == "contextlib"
        for fn in functions
        for d in fn.decorator_list
    )


def _typed_class_imports(node: ast.AST, context: dict) -> dict:
    params = {
        a.arg for a in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
    }
    params.update(a.arg for a in (node.args.vararg, node.args.kwarg) if a)
    rebound = context.get("module_rebindings", set())
    return {
        name: symbol
        for name, symbol in context.get("class_imports", {}).items()
        if name not in params and name not in rebound
    }


def _typed_classes_safe(classes: list, imported: dict) -> bool:
    for cls in classes:
        if (
            cls.decorator_list
            or cls.keywords
            or any(
                not _stub_statement(s)
                for s in cls.body
                if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))
            )
        ):
            return False
        if any(
            not isinstance(base, ast.Name) or base.id not in imported
            for base in cls.bases
        ):
            return False
        if any(
            isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) for s in cls.body
        ):
            return False
    return True


def _typed_call_passes_stub(call: ast.Call, names: set[str]) -> bool:
    if any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in names
        for n in ast.walk(call)
    ):
        return False
    passed = {
        n.id
        for part in (*call.args, *(k.value for k in call.keywords))
        for n in ast.walk(part)
        if isinstance(n, ast.Name)
    }
    return bool(passed & names)


def _typed_call_is_source_bound(
    call: ast.Call, classes: list, imported: dict, local: set, params: set
) -> bool:
    name = call.func.id if isinstance(call.func, ast.Name) else None
    if name in params:
        return False
    subclasses = {
        cls.name
        for cls in classes
        if cls.bases
        and not cls.decorator_list
        and not cls.keywords
        and all(
            isinstance(base, ast.Name) and base.id in imported for base in cls.bases
        )
    }
    return name in subclasses or name in imported and name not in local


def _typed_calls_trusted(
    calls: list,
    names: set[str],
    classes: list,
    imported: dict,
    body: list,
    node: ast.AST,
) -> bool:
    if not calls:
        return False
    params = {
        a.arg for a in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
    }
    params.update(a.arg for a in (node.args.vararg, node.args.kwarg) if a)
    local = set().union(*(_oracle_bound_names(stmt) for stmt in body))
    trusted = False
    for stmt in calls:
        if not isinstance(stmt, ast.Expr) or not isinstance(stmt.value, ast.Call):
            return False
        call = stmt.value
        if not _typed_call_passes_stub(call, names):
            return False
        trusted |= _typed_call_is_source_bound(call, classes, imported, local, params)
    return trusted


def annotated_callable_oracle(node: ast.AST, context: dict) -> bool:
    """Identify typed-stub construction only when the callee class is source-bound."""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    body = _oracle_body(node)
    parts = _typed_stub_parts(body)
    if not parts:
        return False
    defs, functions, classes = parts
    imported = _typed_class_imports(node, context)
    return (
        _typed_stub_decorators_known(functions, context)
        and _typed_classes_safe(classes, imported)
        and _typed_calls_trusted(
            body[len(defs) :],
            {fn.name for fn in functions},
            classes,
            imported,
            body,
            node,
        )
    )


def structural_oracle_status(node: ast.AST, context: dict) -> str | None:
    """Return the proven structural test behavior, or None when evidence is insufficient."""
    if import_smoke_oracle(node):
        return "import"
    if _attribute_access_oracle(node, context):
        return "attribute"
    if annotated_callable_oracle(node, context):
        return "typed"
    return None


def structural_oracle_finding(
    node: ast.AST, relative: str, context: dict
) -> dict | bool | None:
    """Map a structural oracle to an exemption or an explicitly unverified finding."""
    status = structural_oracle_status(node, context)
    if status in {"import", "attribute"}:
        return True
    if status == "typed":
        from .review_audits import _security_finding

        return _security_finding(
            "QUALITY_TYPECHECK_NOT_VERIFIED",
            relative,
            node,
            "Source-bound API construction passed; no type-checker receipt was verified.",
            "INFO",
            symbol=node.name,
            state="INCOMPLETE",
            typecheck="NOT_VERIFIED",
        )
    return None


def _stub_statement(stmt: ast.stmt) -> bool:
    if isinstance(stmt, ast.Pass) or _is_docstring(stmt):
        return True
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
        return stmt.value.value is Ellipsis or isinstance(stmt.value.value, str)
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Yield):
        return (
            stmt.value.value is None
            or isinstance(stmt.value.value, ast.Constant)
            and stmt.value.value.value is None
        )
    if isinstance(stmt, ast.Raise) and stmt.exc is not None:
        exc = stmt.exc.func if isinstance(stmt.exc, ast.Call) else stmt.exc
        return isinstance(exc, ast.Name) and exc.id == "NotImplementedError"
    return False


def _annotated_stub(fn: ast.AST) -> bool:
    args = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
    args += [a for a in (fn.args.vararg, fn.args.kwarg) if a]
    return (
        fn.returns is not None
        and all(a.annotation is not None for a in args)
        and all(_stub_statement(s) for s in fn.body)
    )


def assigned_sync_function_call(
    call: ast.Call, scope: ast.AST, module: ast.AST
) -> bool:
    """Accept assigned calls only when their direct callee is a stable source function."""
    if isinstance(call.func, ast.Lambda):
        return True
    if not isinstance(call.func, ast.Name):
        return False
    name = call.func.id
    local = [
        item
        for item in scope.body
        if isinstance(item, ast.FunctionDef) and item.name == name
    ]
    if local:
        candidates, body = local, scope.body
    else:
        if _oracle_function_shadowed(scope, name):
            return False
        candidates = [
            item
            for item in module.body
            if isinstance(item, ast.FunctionDef) and item.name == name
        ]
        body = module.body
    if not _oracle_unique_sync(candidates):
        return False
    if candidates[0].lineno >= call.lineno:
        return False
    bindings = [
        item
        for statement in body
        for item in _oracle_bound_names(statement)
        if item in {name, "*"}
    ]
    return len(bindings) == 1 and "*" not in bindings


def _oracle_function_shadowed(scope, name):
    parameters = [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
    parameters += [item for item in (scope.args.vararg, scope.args.kwarg) if item]
    if any(item.arg == name for item in parameters):
        return True
    return any(name in _oracle_bound_names(statement) for statement in scope.body)


def _oracle_unique_sync(candidates):
    return len(candidates) == 1 and not candidates[0].decorator_list


def _oracle_binding_nodes(statement):
    pending = [statement]
    while pending:
        node = pending.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            pending.extend(ast.iter_child_nodes(node))


def _oracle_bound_names(statement: ast.AST) -> set[str]:
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {statement.name}
    names = set()
    for child in _oracle_binding_nodes(statement):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(child.name)
        elif isinstance(child, ast.Name) and isinstance(
            child.ctx, (ast.Store, ast.Del)
        ):
            names.add(child.id)
        elif isinstance(child, (ast.Import, ast.ImportFrom)):
            if isinstance(child, ast.ImportFrom) and any(
                item.name == "*" for item in child.names
            ):
                names.add("*")
            names.update(
                item.asname or item.name.split(".")[0]
                for item in child.names
                if item.name != "*"
            )
        elif isinstance(child, ast.ExceptHandler) and child.name:
            names.add(child.name)
        elif isinstance(child, (ast.MatchAs, ast.MatchStar)) and child.name:
            names.add(child.name)
        elif isinstance(child, ast.MatchMapping) and child.rest:
            names.add(child.rest)
    return names


def _nearest_native_function_scope(node: ast.AST, parents: dict) -> bool:
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(
            current,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ):
            return isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef))
    return False


def _native_call_probe_lines(node: ast.AST) -> list[int]:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return []
    walked = list(ast.walk(node))
    parents = {
        child: parent for parent in walked for child in ast.iter_child_nodes(parent)
    }
    statements: dict[int, list[ast.stmt]] = {}
    for child in walked:
        if isinstance(child, ast.stmt):
            statements.setdefault(child.lineno, []).append(child)
    lines = set()
    for child in walked:
        if not isinstance(child, ast.Expr):
            continue
        if not isinstance(child.value, ast.Call):
            continue
        if not _nearest_native_function_scope(child, parents):
            continue
        if statements.get(child.lineno) != [child]:
            continue
        if sum(isinstance(part, ast.Call) for part in ast.walk(child.value)) != 1:
            continue
        lines.add(child.lineno)
    return sorted(lines)[:32]


def native_test_probe(relative: str, node: ast.AST) -> dict[str, Any]:
    """Build advisory assertion and standalone-call probe guidance for one test."""
    lines = sorted(
        {child.lineno for child in ast.walk(node) if isinstance(child, ast.Assert)}
    )[:32]
    call_lines = _native_call_probe_lines(node)
    command = [
        "python",
        "-m",
        "factoryline.pytest_readiness",
        "--root",
        ".",
        "--nodeid",
        "<exact collected pytest node ID>",
        "--line",
        "<assertion line>",
        "--timeout",
        "30",
    ]
    call_command = [
        "python",
        "-m",
        "factoryline.pytest_readiness",
        "--kind",
        "call",
        "--root",
        ".",
        "--nodeid",
        "<exact collected pytest node ID>",
        "--line",
        "<call line>",
        "--timeout",
        "30",
    ]
    return {
        "available": bool(lines),
        "assertion_lines": lines,
        "nodeid_hint": relative + "::" + getattr(node, "name", ""),
        "exact_collection_id_required": True,
        "command": command,
        "execution": "Explicit local execution only; never started by a static scan",
        "interpretation": "Reachability and failure propagation only; review semantic strength separately; no automatic suppression",
        "call_available": bool(call_lines),
        "call_lines": call_lines,
        "call_command": call_command,
        "call_limits": [
            "Candidates are standalone call statements only; the runtime CLI validates the exact target again",
            "Injection is before the selected statement and reports reachability and failure escape only",
            "Production-function mutation sensitivity and semantic quality are not assessed",
            "No automatic detection change, finding clearance, or execution by static scan",
        ],
    }


def callback_argument(call: ast.Call, function: ast.AST, parameter: str) -> str | None:
    """Return a plainly bound callback name for a positional or keyword argument."""
    positional = [*function.args.posonlyargs, *function.args.args]
    names = [argument.arg for argument in positional]
    if parameter in names:
        index = names.index(parameter)
        if index < len(call.args) and isinstance(call.args[index], ast.Name):
            return call.args[index].id
    return next(
        (
            keyword.value.id
            for keyword in call.keywords
            if keyword.arg == parameter and isinstance(keyword.value, ast.Name)
        ),
        None,
    )


def _callback_registry_store(node: ast.AST, name: str) -> bool:
    return (
        isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, (ast.Store, ast.Del))
    )


def _callback_registry_alias(test: ast.AST, name: str) -> bool:
    return any(
        isinstance(node, (ast.Assign, ast.AnnAssign))
        and isinstance(node.value, ast.Name)
        and node.value.id == name
        for node in ast.walk(test)
    )


def _callback_registry_mutated(
    test: ast.AST, name: str, initial: ast.AST, append: ast.AST
) -> bool:
    for node in ast.walk(test):
        if node is initial.targets[0]:
            continue
        if _callback_registry_store(node, name):
            return True
        if (
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and isinstance(node.value, ast.Name)
            and node.value.id == name
        ):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == name:
                if node is not append.value:
                    return True
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
            if node.value.id == name and isinstance(node.ctx, (ast.Store, ast.Del)):
                return True
    return _callback_registry_alias(test, name)


def _callback_catches_assertion(function: ast.AST) -> bool:
    for node in ast.walk(function):
        if not isinstance(node, ast.Try):
            continue
        for handler in node.handlers:
            if handler.type is None:
                return True
            caught = {
                item.id for item in ast.walk(handler.type) if isinstance(item, ast.Name)
            }
            if caught & {"AssertionError", "Exception", "BaseException"}:
                return True
    return False


def _registered_callback_functions(functions, aliases):
    local_names = {fn.name for fn in functions}
    used = {
        dec.id
        for fn in functions
        for dec in fn.decorator_list
        if isinstance(dec, ast.Name)
        and _resolve(dec, aliases) == dec.id
        and dec.id in local_names
    }
    if len(used) != 1:
        return None
    name = next(iter(used))
    register = [fn for fn in functions if fn.name == name]
    callbacks = [
        fn
        for fn in functions
        if len(fn.decorator_list) == 1
        and isinstance(fn.decorator_list[0], ast.Name)
        and fn.decorator_list[0].id == name
    ]
    if len(register) != 1 or not callbacks:
        return None
    return register[0], callbacks


def _callback_registration_body(register, registry):
    if isinstance(register, ast.AsyncFunctionDef) or register.decorator_list:
        return None
    params = [arg.arg for arg in [*register.args.posonlyargs, *register.args.args]]
    statements = [s for s in register.body if not _is_docstring(s)]
    if len(params) != 1 or len(statements) != 2:
        return None
    append, returned = statements
    valid_append = (
        isinstance(append, ast.Expr)
        and isinstance(append.value, ast.Call)
        and isinstance(append.value.func, ast.Attribute)
        and append.value.func.attr == "append"
        and isinstance(append.value.func.value, ast.Name)
        and append.value.func.value.id == registry
        and len(append.value.args) == 1
        and isinstance(append.value.args[0], ast.Name)
        and append.value.args[0].id == params[0]
        and not append.value.keywords
    )
    valid_return = (
        isinstance(returned, ast.Return)
        and isinstance(returned.value, ast.Name)
        and returned.value.id == params[0]
    )
    return append if valid_append and valid_return else None


def _callback_has_live_assertion(
    callback, aliases, strong_assertion, effective_assertion
):
    if isinstance(callback, ast.AsyncFunctionDef) or _callback_catches_assertion(
        callback
    ):
        return False
    if any(isinstance(node, (ast.Yield, ast.YieldFrom)) for node in ast.walk(callback)):
        return False
    return strong_assertion(callback, aliases) and any(
        isinstance(node, ast.Assert) and effective_assertion(node, aliases)
        for node in ast.walk(callback)
    )


def _callback_registry_dispatch(test, registry, registration, register, callbacks):
    names = {fn.name for fn in callbacks}
    if any(
        isinstance(node, ast.Name)
        and (
            (node.id == register.name and isinstance(node.ctx, (ast.Store, ast.Del)))
            or (
                node.id in names
                and isinstance(node.ctx, (ast.Load, ast.Store, ast.Del))
            )
        )
        for node in ast.walk(test)
    ):
        return False
    for loop in (node for node in test.body if isinstance(node, ast.For)):
        if not (
            isinstance(loop.iter, ast.Name)
            and loop.iter.id == registry
            and isinstance(loop.target, ast.Name)
        ):
            continue
        target = loop.target.id
        if any(
            isinstance(
                node,
                (ast.Try, ast.With, ast.Break, ast.Continue, ast.Return, ast.Raise),
            )
            for statement in loop.body
            for node in ast.walk(statement)
        ):
            continue
        if any(
            isinstance(node, ast.Name)
            and node.id == target
            and isinstance(node.ctx, (ast.Store, ast.Del))
            for statement in loop.body
            for node in ast.walk(statement)
        ):
            continue
        if any(
            isinstance(statement, (ast.Return, ast.Raise))
            and statement.lineno < loop.lineno
            for statement in test.body
        ):
            continue
        allowed_before = {id(register), *(id(fn) for fn in callbacks)}
        if any(
            statement.lineno < loop.lineno
            and id(statement) not in allowed_before
            and not (
                isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and statement.targets[0].id == registry
            )
            and not _is_docstring(statement)
            for statement in test.body
        ):
            continue
        calls = [
            statement.value
            for statement in loop.body
            if isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Call)
            and isinstance(statement.value.func, ast.Name)
            and statement.value.func.id == target
        ]
        if (
            len(calls) != len([s for s in loop.body if not _is_docstring(s)])
            or not calls
        ):
            continue
        if any(
            isinstance(node, ast.Name)
            and node.id == registry
            and isinstance(node.ctx, ast.Load)
            and id(node) not in {id(registration.value.func.value), id(loop.iter)}
            for node in ast.walk(test)
        ):
            continue
        return True
    return False


def _empty_callback_registries(test):
    """Find direct, single-name empty-list initializers without executing code."""
    return [
        node
        for node in test.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.List)
        and not node.value.elts
    ]


def registered_callback_oracle(test, aliases, strong_assertion, effective_assertion):
    """Prove a narrow local append-registry decorator and direct callback loop.

    Cross-file registries, metaclasses, dynamic tags, and indirect dispatch remain
    unsupported. Unsupported syntax returns false; it is never treated as proven.
    """
    if not isinstance(test, ast.FunctionDef):
        return False
    initializers = _empty_callback_registries(test)
    if len(initializers) != 1:
        return False
    initial = initializers[0]
    registry = initial.targets[0].id
    functions = [node for node in test.body if isinstance(node, ast.FunctionDef)]
    pair = _registered_callback_functions(functions, aliases)
    if pair is None:
        return False
    register, callbacks = pair
    if initial.lineno >= register.lineno or any(
        register.lineno >= fn.lineno for fn in callbacks
    ):
        return False
    registration = _callback_registration_body(register, registry)
    if registration is None or _callback_registry_mutated(
        test, registry, initial, registration
    ):
        return False
    if any(
        not _callback_has_live_assertion(
            fn, aliases, strong_assertion, effective_assertion
        )
        for fn in callbacks
    ):
        return False
    return _callback_registry_dispatch(
        test, registry, registration, register, callbacks
    )


def _is_docstring(node: ast.stmt) -> bool:
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def _targets(stmt: ast.AST) -> list[str]:
    targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
    return [
        n.id
        for t in targets
        for n in ast.walk(t)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
    ]


def _true_arg(call: ast.AST, key: str) -> bool:
    return isinstance(call, ast.Call) and any(
        k.arg == key and isinstance(k.value, ast.Constant) and k.value.value is True
        for k in call.keywords
    )


def mock_patch_dict_slot(
    receiver,
    root,
    assertion,
    aliases,
    nodes,
    constructors,
    normalize,
    rebound,
    effective,
    root_name,
):
    """Prove an unchanged literal Mock slot inside a resolved patch.dict context."""
    while isinstance(receiver, ast.Attribute):
        receiver = receiver.value
    if (
        not isinstance(receiver, ast.Subscript)
        or root_name(receiver.value, None, {}) != root
        or not isinstance(receiver.slice, ast.Constant)
    ):
        return False
    context = _patch_dict_context(root, assertion, aliases, nodes, normalize, rebound)
    return context is not None and _literal_mock_slot(
        root,
        receiver.slice.value,
        context,
        assertion,
        aliases,
        nodes,
        constructors,
        normalize,
        rebound,
        effective,
    )


def _patch_dict_context(root, assertion, aliases, nodes, normalize, rebound):
    ancestors = getattr(assertion, "_oracle_ancestors", ())
    for node in nodes:
        if not isinstance(node, ast.With) or not any(
            parent is node for parent, _ in ancestors
        ):
            continue
        for item in node.items:
            call = item.context_expr
            if (
                not isinstance(call, ast.Call)
                or normalize(call, aliases) != "unittest.mock.patch.dict"
                or len(call.args) not in {1, 2}
                or call.keywords
                or not isinstance(call.args[-1], ast.Name)
                or call.args[-1].id != root
                or rebound(nodes, root, call.lineno, assertion.lineno)
            ):
                continue
            return call
    return None


def _literal_mock_slot(
    root,
    key,
    context,
    assertion,
    aliases,
    nodes,
    constructors,
    normalize,
    rebound,
    effective,
):
    for statement in nodes:
        if not isinstance(statement, ast.Assign) or statement.lineno >= context.lineno:
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == root
            for target in statement.targets
        ):
            continue
        if not isinstance(statement.value, ast.Dict) or not effective(
            statement, aliases
        ):
            return False
        if rebound(nodes, root, statement.lineno, assertion.lineno):
            return False
        if not _mapping_use_is_confined(root, statement, context, assertion, nodes):
            return False
        keys = [
            node.value
            for node in statement.value.keys
            if isinstance(node, ast.Constant)
        ]
        if len(keys) != len(statement.value.keys) or len(set(keys)) != len(keys):
            return False
        return any(
            isinstance(key_node, ast.Constant)
            and key_node.value == key
            and isinstance(value, ast.Call)
            and normalize(value, aliases) in constructors
            for key_node, value in zip(statement.value.keys, statement.value.values)
        )
    return False


def _mapping_use_is_confined(root, statement, context, assertion, nodes):
    allowed = context.args[-1] if context.args else None
    start = (statement.end_lineno, statement.end_col_offset)
    end = (assertion.lineno, assertion.col_offset)
    return not any(
        isinstance(node, ast.Name)
        and node.id == root
        and isinstance(node.ctx, ast.Load)
        and start < (node.lineno, node.col_offset) < end
        and node is not allowed
        for item in nodes
        for node in ast.walk(item)
    )


def _fixture_name(fn: ast.AST, aliases: dict[str, str]) -> str | None:
    for dec in getattr(fn, "decorator_list", ()):
        call = dec if isinstance(dec, ast.Call) else None
        if _resolve(call.func if call else dec, aliases) in {
            "pytest.fixture",
            "_pytest.fixture",
        }:
            return (
                next(
                    (
                        k.value.value
                        for k in (call.keywords if call else ())
                        if k.arg == "name"
                        and isinstance(k.value, ast.Constant)
                        and isinstance(k.value.value, str)
                    ),
                    None,
                )
                or fn.name
            )
    return None


def _fixture_step(
    stmt: ast.AST, app: str | None, testing: bool, aliases: dict
) -> tuple[str | None, bool]:
    if (
        app
        and isinstance(stmt, (ast.If, ast.Try, ast.For, ast.While, ast.With))
        and _mutated(ast.Module(body=[stmt], type_ignores=[]), {app})
    ):
        return app, False
    if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
        value, names = stmt.value, _targets(stmt)
        if (
            isinstance(value, ast.Call)
            and _resolve(value.func, aliases) == "flask.Flask"
        ):
            return names[0] if len(names) == 1 else None, False
        if app and app in names:
            return None, False
        if app and any(
            _name(t).endswith((".testing", ".config['TESTING']", '.config["TESTING"]'))
            and _name(t).rsplit(".", 1)[0] == app
            for t in (stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target])
        ):
            return app, isinstance(value, ast.Constant) and value.value is True
    if (
        isinstance(stmt, ast.Expr)
        and app is not None
        and isinstance(stmt.value, ast.Call)
        and _name(stmt.value.func) == app + ".config.update"
    ):
        if stmt.value.args or any(
            keyword.arg is None for keyword in stmt.value.keywords
        ):
            return app, False
        setting = next(
            (k.value for k in stmt.value.keywords if k.arg == "TESTING"), None
        )
        if setting is not None:
            return app, isinstance(setting, ast.Constant) and setting.value is True
    return app, testing


def _fixture_terminal(
    stmt: ast.AST, app: str | None, testing: bool, aliases: dict
) -> bool | None:
    if isinstance(stmt, ast.Return):
        value = stmt.value
    elif isinstance(stmt, ast.Expr) and isinstance(
        stmt.value, (ast.Yield, ast.YieldFrom)
    ):
        value = stmt.value.value
    else:
        return None
    if value is None:
        return False
    return testing if isinstance(value, ast.Name) and value.id == app else False


def _fixture_testing(fn: ast.AST, aliases: dict[str, str]) -> bool:
    shadowed = {
        item.arg for item in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
    }
    aliases = {name: value for name, value in aliases.items() if name not in shadowed}
    app, testing = None, False
    for stmt in getattr(fn, "body", ()):
        app, testing = _fixture_step(stmt, app, testing, aliases)
        result = _fixture_terminal(stmt, app, testing, aliases)
        if result is not None:
            return result
    return False


def flask_fixture_apps(tree: ast.AST, aliases: dict[str, str]) -> dict[str, bool]:
    """Summarize testing-enabled Flask fixture source; does not prove runtime execution."""
    return {
        name: _fixture_testing(fn, aliases)
        for fn in getattr(tree, "body", ())
        if (name := _fixture_name(fn, aliases))
    }


def _test_nodes(test: ast.AST):
    stack = list(getattr(test, "body", ()))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            stack.extend(ast.iter_child_nodes(node))


def _source_name_aliases(
    scope: ast.AST, roots: set[str], endpoint: ast.AST
) -> set[str]:
    """Resolve simple local Name aliases established before an AST endpoint."""
    aliases = set(roots)
    boundary = endpoint.lineno, endpoint.col_offset
    statements = sorted(
        (
            node
            for node in _test_nodes(scope)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
        ),
        key=lambda node: (node.lineno, node.col_offset),
    )
    for statement in statements:
        if (statement.lineno, statement.col_offset) >= boundary:
            break
        targets = set(_targets(statement)) - roots
        value = getattr(statement, "value", None)
        if isinstance(value, ast.Name) and value.id in aliases:
            aliases.update(targets)
        else:
            aliases.difference_update(targets)
    return aliases


def _flask_alias_roots(test: ast.AST, roots: set[str]) -> set[str]:
    aliases = set(roots)
    changed = True
    while changed:
        changed = False
        for stmt in _test_nodes(test):
            if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                continue
            value = getattr(stmt, "value", None)
            source = _dispatch_root(value)
            if source in aliases:
                before = len(aliases)
                aliases.update(_targets(stmt))
                changed |= len(aliases) != before
    return aliases


def _mutated(test: ast.AST, apps: set[str], roots: set[str] | None = None) -> bool:
    roots = roots or apps
    for n in _test_nodes(test):
        if (
            isinstance(n, ast.Name)
            and n.id in apps
            and isinstance(n.ctx, (ast.Store, ast.Del))
        ):
            return True
        if (
            isinstance(n, ast.Attribute)
            and _dispatch_root(n.value) in roots
            and (
                isinstance(n.ctx, (ast.Store, ast.Del))
                or n.attr in {"config", "testing"}
            )
        ):
            return True
        if (
            isinstance(n, ast.Subscript)
            and isinstance(n.ctx, (ast.Store, ast.Del))
            and _dispatch_root(n) in roots
        ):
            return True
        if (
            isinstance(n, ast.Call)
            and n.args
            and _dispatch_root(n.args[0]) in roots
            and _resolve(n.func, {}) in {"setattr", "delattr"}
        ):
            return True
    return False


def _route(fn: ast.AST, aliases: dict[str, str], apps: set[str], effective):
    if len(fn.decorator_list) != 1:
        return None
    dec = fn.decorator_list[0]
    if (
        not isinstance(dec, ast.Call)
        or len(dec.args) != 1
        or dec.keywords
        or not isinstance(dec.func, ast.Attribute)
    ):
        return None
    path = dec.args[0]
    if (
        dec.func.attr != "route"
        or _name(dec.func.value) not in apps
        or not isinstance(path, ast.Constant)
        or not isinstance(path.value, str)
        or any(ch in path.value for ch in "<>")
        or not effective(dec, aliases)
    ):
        return None
    return path.value


def _flask_routes(test: ast.AST, aliases: dict, apps: set[str], effective) -> dict:
    routes = {}
    for fn in (
        n
        for n in ast.walk(test)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ):
        path = _route(fn, aliases, apps, effective)
        if path is not None:
            routes.setdefault(path, []).append(fn)
    return routes


def _flask_clients(
    test: ast.AST, apps: set[str], effective, aliases: dict
) -> tuple[dict, set]:
    clients, bad, other = {}, set(), set()
    for stmt in _test_nodes(test):
        if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            continue
        value, targets = stmt.value, _targets(stmt)
        if len(targets) != 1:
            other.update(targets)
            continue
        app = (
            value.func.value.id
            if isinstance(value, ast.Call)
            and not value.args
            and not value.keywords
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "test_client"
            and isinstance(value.func.value, ast.Name)
            and value.func.value.id in apps
            and effective(value, aliases)
            else None
        )
        target = targets[0]
        if app:
            if target in clients and clients[target] != app:
                bad.add(target)
            clients[target] = app
        else:
            other.add(target)
    return clients, bad | (other & clients.keys())


def _literal_client_get(call, clients, bad):
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
        return False
    if call.func.attr != "get" or len(call.args) != 1 or call.keywords:
        return False
    if not isinstance(call.func.value, ast.Name):
        return False
    return call.func.value.id in clients and call.func.value.id not in bad


def _effective_get_path(call, clients, bad, aliases, effective):
    if not _literal_client_get(call, clients, bad):
        return None
    path = call.args[0]
    if not isinstance(path, ast.Constant) or not isinstance(path.value, str):
        return None
    return path.value if effective(call, aliases) else None


def _dispatch_root(node):
    while True:
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and node.args
        ):
            node = node.args[0]
        else:
            break
    return node.id if isinstance(node, ast.Name) else None


def _flask_dispatch_mutated(test, apps, clients):
    app_roots = _flask_alias_roots(test, apps)
    client_roots = _flask_alias_roots(test, set(clients))
    roots = app_roots | client_roots
    for node in _test_nodes(test):
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            if (
                isinstance(node.ctx, (ast.Store, ast.Del))
                and _dispatch_root(node) in roots
            ):
                return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            root = _dispatch_root(node.func)
            if root in app_roots and node.func.attr not in {
                "route",
                "test_client",
            }:
                return True
            if root in client_roots and node.func.attr != "get":
                return True
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            if isinstance(node.value, (ast.Attribute, ast.Subscript)):
                if _dispatch_root(node.value) in roots:
                    return True
    return False


def flask_invoked_callbacks(
    test: ast.AST,
    aliases: dict[str, str],
    apps: set[str],
    strong_callback_names: set[str],
    effective,
) -> set[str]:
    """Credit only local literal routes reached by an effective exact GET on a proven app.

    This bounded AST summary does not prove Flask runtime dispatch.
    """
    if not apps or _mutated(test, apps):
        return set()
    routes = _flask_routes(test, aliases, apps, effective)
    clients, bad = _flask_clients(test, apps, effective, aliases)
    if _mutated(test, apps, _flask_alias_roots(test, apps | set(clients))):
        return set()
    if _flask_dispatch_mutated(test, apps, clients):
        return set()
    invoked = set()
    for call in _test_nodes(test):
        path = _effective_get_path(call, clients, bad, aliases, effective)
        if path is None:
            continue
        callbacks = routes.get(path, ())
        if (
            len(callbacks) == 1
            and callbacks[0].name in strong_callback_names
            and callbacks[0].lineno < call.lineno
        ):
            invoked.add(callbacks[0].name)
    return invoked


def _virtual_default(value, defaults):
    if not isinstance(value, ast.IfExp) or not isinstance(value.test, ast.Compare):
        return None
    test = value.test
    if len(test.ops) != 1 or not isinstance(test.ops[0], ast.Is):
        return None
    if len(test.comparators) != 1 or not isinstance(test.comparators[0], ast.Constant):
        return None
    if test.comparators[0].value is not None or _name(test.left) not in defaults:
        return None
    if _name(value.orelse) != _name(test.left):
        return None
    name = _name(value.body)
    return name.removeprefix("self.") if name.startswith("self.") else None


def _virtual_init_supported(init, invoke):
    if init is None or invoke is None:
        return False
    if init.decorator_list or invoke.decorator_list:
        return False
    if init.args.vararg or init.args.kwarg or init.args.kwonlyargs:
        return False
    return not any(
        not isinstance(item, (ast.Assign, ast.AnnAssign, ast.Pass))
        for item in init.body
    )


def _virtual_init_bindings(init, defaults):
    bindings, invalid = {}, set()
    for node in ast.walk(init):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
            continue
        targets = (
            node.targets
            if isinstance(node, (ast.Assign, ast.Delete))
            else [node.target]
        )
        for target in targets:
            name = _name(target)
            if not name.startswith("self."):
                continue
            if (
                name in bindings
                or not isinstance(node, ast.Assign)
                or node not in init.body
            ):
                invalid.add(name)
            bindings[name] = _virtual_default(getattr(node, "value", None), defaults)
    return bindings, invalid


def virtual_dispatch_defaults(methods, aliases, effective):
    """Summarize an omitted-argument virtual method binding, never execute it."""
    init, invoke = methods.get("__init__"), methods.get("__call__")
    if not _virtual_init_supported(init, invoke):
        return {}
    arguments = [*init.args.posonlyargs, *init.args.args][1:]
    defaults = {
        item.arg
        for item, value in zip(
            arguments[-len(init.args.defaults) :], init.args.defaults
        )
        if isinstance(value, ast.Constant) and value.value is None
    }
    required = len(arguments) - len(init.args.defaults)
    bindings, invalid = _virtual_init_bindings(init, defaults)
    invalid.update(_virtual_binding_mutations(methods, bindings))
    resolved = _awaited_virtual_bindings(
        invoke, bindings, invalid, methods, aliases, effective
    )
    guards = _virtual_scope_guards(invoke)
    return (
        {"methods": sorted(resolved), "required_arguments": required, "guards": guards}
        if resolved and guards is not None
        else {}
    )


def _virtual_scope_guards(invoke):
    guards = []
    for item in invoke.body:
        if not isinstance(item, ast.If) or not any(
            isinstance(n, ast.Return) for n in item.body
        ):
            continue
        test = item.test
        if (
            not isinstance(test, ast.Compare)
            or len(test.ops) != 1
            or not isinstance(test.ops[0], ast.NotEq)
        ):
            return None
        left = test.left
        if not isinstance(left, ast.Subscript) or not isinstance(left.value, ast.Name):
            return None
        if (
            not isinstance(left.slice, ast.Constant)
            or len(test.comparators) != 1
            or not isinstance(test.comparators[0], ast.Constant)
            or not isinstance(left.slice.value, str)
            or type(test.comparators[0].value) not in (str, int, bool, type(None))
        ):
            return None
        parameters = [
            arg.arg for arg in [*invoke.args.posonlyargs, *invoke.args.args][1:]
        ]
        if left.value.id not in parameters:
            return None
        guards.append(
            {
                "index": parameters.index(left.value.id),
                "parameter": left.value.id,
                "key": left.slice.value,
                "value": test.comparators[0].value,
            }
        )
    return guards


def _virtual_binding_mutations(methods, bindings):
    return {
        _name(node)
        for name, method in methods.items()
        if name != "__init__"
        for node in ast.walk(method)
        if isinstance(node, ast.Attribute)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and _name(node) in bindings
    }


def _awaited_virtual_bindings(invoke, bindings, invalid, methods, aliases, effective):
    resolved = set()
    for node in _test_nodes(invoke):
        if not isinstance(node, ast.Await) or not isinstance(node.value, ast.Call):
            continue
        name = _name(node.value.func)
        method = bindings.get(name)
        if name not in invalid and method in methods and effective(node.value, aliases):
            resolved.add(method)
    return resolved


def _sha(v: object) -> str:
    return hashlib.sha256(
        json.dumps(v, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _read(root: Path, path: Path) -> tuple[dict[str, Any], Path]:
    p = path.resolve() if path.is_absolute() else (root / path).resolve()
    try:
        p.relative_to(root)
    except ValueError as e:
        raise RevenueForgeError(
            "REVIEW_INTEGRITY_PATH_REJECTED", "paths must remain inside the workspace"
        ) from e
    try:
        v = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise RevenueForgeError(
            "REVIEW_INTEGRITY_INPUT_INVALID", "inputs must be JSON objects"
        ) from e
    if not isinstance(v, dict):
        raise RevenueForgeError(
            "REVIEW_INTEGRITY_INPUT_INVALID", "inputs must be JSON objects"
        )
    return v, p


def _write(root: Path, path: Path, core: dict[str, Any]) -> dict[str, Any]:
    target = path.resolve() if path.is_absolute() else (root / path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    result = {**core, "receipt_sha256": _sha(core)}
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=".receipt.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return {**result, "path": target.relative_to(root).as_posix()}


def _base(
    kind: str, ok: bool, findings: list[str], sources: dict[str, str]
) -> dict[str, Any]:
    return {
        "schema": f"factory.review-integrity.{kind}-receipt.v1",
        "marker": f"REVIEW_{kind.upper()}_READY"
        if ok
        else f"REVIEW_{kind.upper()}_BLOCKED",
        "ok": ok,
        "findings": findings,
        "sources": sources,
        "authority": {
            **AUTHORITY,
            "execution": False,
            "release": False,
            "policy_override": False,
        },
        "claim_boundary": "Local deterministic metadata validation only; not semantic code understanding, environment execution, signature verification, or release approval.",
    }


def _instant(value: object) -> datetime | None:
    """Parse a timezone-aware ISO-8601 instant or return None for ambiguous timestamp input."""
    if not isinstance(value, str) or "T" not in value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _validate_intent_contract(contract: dict[str, Any]) -> None:
    if (
        set(contract) != {"schema", "approved_paths", "forbidden_terms", "approval"}
        or contract.get("schema") != "factory.intent-diff-contract.v1"
        or not isinstance(contract.get("approved_paths"), list)
    ):
        raise RevenueForgeError(
            "INTENT_DIFF_CONTRACT_INVALID",
            "contract needs approved_paths, forbidden_terms, and human/trusted approval",
        )


def _validate_diff_manifest(manifest: dict[str, Any]) -> None:
    if (
        set(manifest)
        != {"schema", "base_sha", "head_sha", "changed_paths", "added_text"}
        or manifest.get("schema") != "factory.diff-manifest.v1"
        or not isinstance(manifest.get("changed_paths"), list)
        or not isinstance(manifest.get("added_text"), str)
    ):
        raise RevenueForgeError(
            "INTENT_DIFF_MANIFEST_INVALID", "diff manifest must be explicit and bounded"
        )


def _intent_authority_findings(contract: dict[str, Any]) -> list[str]:
    approval = contract["approval"]
    if not isinstance(approval, dict) or approval.get("origin") not in {
        "human_confirmed",
        "trusted_source",
    }:
        return ["E_INTENT_AUTHORITY_MISSING"]
    return []


def _scope_allows_path(path: object, approved_paths: list[Any]) -> bool:
    if not isinstance(path, str):
        return False
    return any(
        scope == "." or path == scope or path.startswith(scope.rstrip("/") + "/")
        for scope in approved_paths
    )


def _intent_scope_findings(
    contract: dict[str, Any], manifest: dict[str, Any]
) -> list[str]:
    findings: list[str] = []
    for path in manifest["changed_paths"]:
        if not _scope_allows_path(path, contract["approved_paths"]):
            findings.append("E_INTENT_SCOPE_DRIFT:" + str(path))
    return findings


def _forbidden_term_findings(
    contract: dict[str, Any], manifest: dict[str, Any]
) -> list[str]:
    added_text = manifest["added_text"].lower()
    return [
        "E_INTENT_FORBIDDEN_BEHAVIOR:" + term
        for term in contract.get("forbidden_terms", [])
        if isinstance(term, str) and term and term.lower() in added_text
    ]


def _intent_diff_core(
    root: Path,
    contract_path: Path,
    diff_path: Path,
    contract: dict[str, Any],
    manifest: dict[str, Any],
    findings: list[str],
) -> dict[str, Any]:
    core = _base(
        "intent_diff",
        not findings,
        findings,
        {
            "contract": contract_path.relative_to(root).as_posix(),
            "diff": diff_path.relative_to(root).as_posix(),
        },
    )
    core.update(
        {
            "action_summary": "Compare a declared diff against human-approved scope and forbidden behaviors before review promotion.",
            "base_sha": manifest["base_sha"],
            "head_sha": manifest["head_sha"],
            "repair_plan": [
                "Remove or separately approve the out-of-scope path or forbidden behavior."
                for _ in findings
            ],
        }
    )
    return core


def verify_intent_diff(
    root: Path, contract_path: Path, diff_path: Path, out: Path
) -> dict[str, Any]:
    """Fail closed when a declared change exceeds approved intent or forbidden behavior."""
    root = Path(root).resolve()
    c, cp = _read(root, contract_path)
    d, dp = _read(root, diff_path)
    _validate_intent_contract(c)
    find = _intent_authority_findings(c)
    _validate_diff_manifest(d)
    find.extend(_intent_scope_findings(c, d))
    find.extend(_forbidden_term_findings(c, d))
    core = _intent_diff_core(root, cp, dp, c, d, find)
    return _write(root, out, core)


def _validate_freshness_manifest(manifest: dict[str, Any]) -> None:
    if (
        set(manifest)
        != {"schema", "current_commit", "environment_sha256", "now", "receipts"}
        or manifest.get("schema") != "factory.receipt-freshness-manifest.v1"
        or not isinstance(manifest.get("receipts"), list)
    ):
        raise RevenueForgeError(
            "RECEIPT_FRESHNESS_MANIFEST_INVALID",
            "manifest needs current commit, environment digest, time, and receipts",
        )


def _freshness_metadata_valid(receipt: object) -> bool:
    return isinstance(receipt, dict) and set(receipt) == {
        "id",
        "commit",
        "environment_sha256",
        "expires_at",
        "nonce",
    }


def _freshness_expired(receipt: dict[str, Any], manifest: dict[str, Any]) -> bool:
    expires_at, manifest_now = (
        _instant(receipt["expires_at"]),
        _instant(manifest["now"]),
    )
    current_now = datetime.now(timezone.utc)
    reference_now = (
        max(current_now, manifest_now) if manifest_now is not None else current_now
    )
    return (
        not isinstance(receipt["nonce"], str)
        or not receipt["nonce"]
        or expires_at is None
        or manifest_now is None
        or expires_at <= reference_now
    )


def _freshness_receipt_findings(
    receipt: object, manifest: dict[str, Any], seen: set[Any]
) -> list[str]:
    if not _freshness_metadata_valid(receipt):
        return ["E_RECEIPT_METADATA_LOOSE"]
    if receipt["id"] in seen:
        return ["E_RECEIPT_REPLAY:" + str(receipt["id"])]
    seen.add(receipt["id"])
    findings = []
    if receipt["commit"] != manifest["current_commit"]:
        findings.append("E_RECEIPT_STALE_COMMIT:" + str(receipt["id"]))
    if receipt["environment_sha256"] != manifest["environment_sha256"]:
        findings.append("E_RECEIPT_ENVIRONMENT_DRIFT:" + str(receipt["id"]))
    if _freshness_expired(receipt, manifest):
        findings.append("E_RECEIPT_EXPIRED:" + str(receipt["id"]))
    return findings


def _freshness_core(
    root: Path, path: Path, manifest: dict[str, Any], findings: list[str]
) -> dict[str, Any]:
    core = _base(
        "freshness",
        not findings,
        findings,
        {"manifest": path.relative_to(root).as_posix()},
    )
    core.update(
        {
            "action_summary": "Reject stale, replayed, expired, or environment-mismatched release-critical receipts.",
            "receipt_count": len(manifest["receipts"]),
            "repair_plan": [
                "Re-run the exact gate for the current commit and environment with a new expiry and nonce."
                for _ in findings
            ],
        }
    )
    return core


def verify_receipt_freshness(
    root: Path, manifest_path: Path, out: Path
) -> dict[str, Any]:
    """Reject release receipts that are stale, replayed, expired, or environment mismatched."""
    root = Path(root).resolve()
    manifest, source = _read(root, manifest_path)
    _validate_freshness_manifest(manifest)
    seen: set[Any] = set()
    findings = []
    for receipt in manifest["receipts"]:
        findings.extend(_freshness_receipt_findings(receipt, manifest, seen))
    core = _freshness_core(root, source, manifest, findings)
    return _write(root, out, core)


def _validate_policy_pack(pack: dict[str, Any]) -> None:
    if (
        set(pack) != {"schema", "owner", "version", "approval", "rules"}
        or pack.get("schema") != "factory.team-policy-pack.v1"
        or not isinstance(pack.get("rules"), list)
    ):
        raise RevenueForgeError(
            "TEAM_POLICY_PACK_INVALID", "pack needs human-owned versioned rules"
        )


def _policy_identity_findings(pack: dict[str, Any]) -> list[str]:
    valid = (
        isinstance(pack.get("owner"), str)
        and bool(pack["owner"].strip())
        and isinstance(pack.get("version"), str)
        and bool(pack["version"].strip())
    )
    return [] if valid else ["E_POLICY_OWNER_OR_VERSION_MISSING"]


def _policy_approval_findings(pack: dict[str, Any]) -> list[str]:
    approval = pack.get("approval")
    if not isinstance(approval, dict) or approval.get("origin") not in {
        "human_confirmed",
        "trusted_source",
    }:
        return ["E_POLICY_AGENT_OWNED"]
    return []


def _policy_rule_valid(rule: object) -> bool:
    return (
        isinstance(rule, dict)
        and set(rule) == {"id", "requirement", "gate"}
        and all(isinstance(rule[key], str) and rule[key] for key in rule)
    )


def _policy_rule_findings(pack: dict[str, Any]) -> list[str]:
    rules = pack["rules"]
    if not rules or not all(_policy_rule_valid(rule) for rule in rules):
        return ["E_POLICY_RULE_LOOSE"]
    return []


def _policy_core(
    root: Path, path: Path, pack: dict[str, Any], findings: list[str]
) -> dict[str, Any]:
    core = _base(
        "policy_pack",
        not findings,
        findings,
        {"pack": path.relative_to(root).as_posix()},
    )
    core.update(
        {
            "action_summary": "Verify a human-owned, versioned team policy pack before it is selected as a review baseline.",
            "owner": pack.get("owner"),
            "version": pack.get("version"),
            "rule_count": len(pack["rules"]),
            "repair_plan": [
                "Have the designated human/trusted owner approve explicit rule-to-gate mappings."
                for _ in findings
            ],
        }
    )
    return core


def verify_policy_pack(root: Path, pack_path: Path, out: Path) -> dict[str, Any]:
    """Verify that a selected team policy pack is explicit, versioned, and human owned."""
    root = Path(root).resolve()
    p, pp = _read(root, pack_path)
    _validate_policy_pack(p)
    find = _policy_identity_findings(p)
    find.extend(_policy_approval_findings(p))
    find.extend(_policy_rule_findings(p))
    core = _policy_core(root, pp, p, find)
    return _write(root, out, core)


_IMPLEMENTATION_PLACEHOLDERS = {
    "coming soon",
    "demo_only",
    "fixme",
    "not implemented",
    "not implemented yet",
    "placeholder",
    "tbd",
    "todo",
}
_MOCK_APIS = {
    "unittest.mock.AsyncMock",
    "unittest.mock.MagicMock",
    "unittest.mock.Mock",
    "unittest.mock.NonCallableMagicMock",
    "unittest.mock.NonCallableMock",
    "unittest.mock.PropertyMock",
    "unittest.mock.create_autospec",
    "unittest.mock.mock_open",
    "unittest.mock.patch",
    "unittest.mock.patch.dict",
    "unittest.mock.patch.multiple",
    "unittest.mock.patch.object",
    "pytest.MonkeyPatch",
}
_OMISSION_COMMENT = re.compile(
    r"\b(?:TODO|FIXME|XXX)\b(?:\s*[:\-]\s*|\s+)"
    r"(?:implement|add|finish|complete|replace|remove|validate|handle|support|wire)\b",
    re.IGNORECASE,
)


def _implementation_imports(nodes: list[ast.AST]) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for item in node.names:
                local = item.asname or item.name.split(".", 1)[0]
                target = item.name if item.asname else local
                resolved[local] = target
        elif isinstance(node, ast.ImportFrom) and node.module:
            module = "." * node.level + node.module
            for item in node.names:
                if item.name == "*":
                    continue
                local = item.asname or item.name
                target = f"{module}.{item.name}"
                if (
                    node.level == 0
                    and node.module == "unittest"
                    and item.name == "mock"
                ):
                    target = "unittest.mock"
                resolved[local] = target
    return resolved


def _implementation_scope_nodes(scope: ast.AST) -> list[ast.AST]:
    body = getattr(scope, "body", ())
    if not isinstance(body, (list, tuple)):
        body = [body]
    found, pending = [], list(reversed(body))
    while pending:
        node = pending.pop()
        found.append(node)
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        pending.extend(reversed(list(ast.iter_child_nodes(node))))
    return found


def _implementation_bound_names(scope: ast.AST) -> set[str]:
    nodes = _implementation_scope_nodes(scope)
    names = {
        node.id
        for node in nodes
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
    }
    names.update(
        node.name for node in nodes if isinstance(node, ast.ExceptHandler) and node.name
    )
    names.update(
        node.name
        for node in nodes
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name
    )
    names.update(
        node.rest for node in nodes if isinstance(node, ast.MatchMapping) and node.rest
    )
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        arguments = scope.args
        names.update(
            item.arg
            for item in [
                *arguments.posonlyargs,
                *arguments.args,
                *arguments.kwonlyargs,
            ]
        )
        if arguments.vararg:
            names.add(arguments.vararg.arg)
        if arguments.kwarg:
            names.add(arguments.kwarg.arg)
    names.update(
        node.name
        for node in nodes
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )
    return names


def _implementation_scope_aliases(
    scope: ast.AST, inherited: dict[str, str]
) -> dict[str, str]:
    nodes = _implementation_scope_nodes(scope)
    imports = _implementation_imports(nodes)
    bound = _implementation_bound_names(scope)
    aliases = {name: value for name, value in inherited.items() if name not in bound}
    aliases.update(
        {name: value for name, value in imports.items() if name not in bound}
    )
    return aliases


def _implementation_call_name(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        value = _implementation_call_name(node.value, aliases)
        return f"{value}.{node.attr}"
    if isinstance(node, ast.Subscript):
        return _implementation_call_name(node.value, aliases)
    return ""


def _implementation_parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }


def _implementation_scope_chain(
    node: ast.AST, parents: dict[ast.AST, ast.AST]
) -> list[ast.AST]:
    scopes = []
    parent = parents.get(node)
    while parent is not None:
        if isinstance(
            parent,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            scopes.append(parent)
        parent = parents.get(parent)
    return list(reversed(scopes))


def _implementation_fixture_scope(
    scope: ast.AST, parents: dict[ast.AST, ast.AST]
) -> bool:
    module: ast.AST = scope
    while module in parents:
        module = parents[module]
    aliases = _implementation_scope_aliases(
        module, _implementation_imports(module.body)
    )
    return bool(
        _implementation_decorator_names(scope, aliases).intersection(
            {"pytest.fixture", "_pytest.fixture"}
        )
    )


def _implementation_aliases_for(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
    module_aliases: dict[str, str],
    module: ast.Module,
) -> dict[str, str]:
    aliases = _implementation_scope_aliases(module, module_aliases)
    for scope in _implementation_scope_chain(node, parents):
        aliases = _implementation_scope_aliases(scope, aliases)
    return aliases


def _implementation_is_test_path(relative: str) -> bool:
    path = Path(relative.replace("\\", "/"))
    name = path.name.casefold()
    return (
        path.suffix.casefold() == ".pyi"
        or name == "conftest.py"
        or name.startswith("test_")
        or name.endswith("_test.py")
        or any(part.casefold() in {"test", "tests"} for part in path.parts)
    )


def _implementation_is_test_function(
    node: ast.AST, parents: dict[ast.AST, ast.AST]
) -> bool:
    return (
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
        or any(
            isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
            and scope.name.startswith("test_")
            for scope in _implementation_scope_chain(node, parents)
        )
        or any(
            isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
            and _implementation_fixture_scope(scope, parents)
            for scope in _implementation_scope_chain(node, parents)
        )
    )


def _implementation_docstring_body(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.stmt]:
    body = list(node.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
    ):
        if isinstance(body[0].value.value, str):
            body.pop(0)
    return body


def _implementation_protocol_class(
    node: ast.AST, parents: dict[ast.AST, ast.AST], aliases: dict[str, str]
) -> bool:
    parent = parents.get(node)
    while parent is not None:
        if isinstance(parent, ast.ClassDef):
            if any(
                _implementation_call_name(base, aliases)
                in {"typing.Protocol", "typing_extensions.Protocol"}
                for base in parent.bases
            ):
                return True
        parent = parents.get(parent)
    return False


def _implementation_decorator_names(
    node: ast.FunctionDef | ast.AsyncFunctionDef, aliases: dict[str, str]
) -> set[str]:
    return {
        _implementation_call_name(
            decorator.func if isinstance(decorator, ast.Call) else decorator,
            aliases,
        )
        for decorator in node.decorator_list
    }


def _implementation_placeholder_raise(node: ast.stmt) -> bool:
    if not isinstance(node, ast.Raise) or node.exc is None:
        return False
    value = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
    return ast.unparse(value) in {"NotImplementedError", "builtins.NotImplementedError"}


def _implementation_comment_findings(
    relative: str,
    source: str,
    tree: ast.Module,
    parents: dict[ast.AST, ast.AST],
    module_aliases: dict[str, str],
) -> list[dict[str, Any]]:
    findings = []
    excluded_lines = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        aliases = _implementation_aliases_for(node, parents, module_aliases, tree)
        decorators = _implementation_decorator_names(node, aliases)
        if not node.name.startswith("test_") and not decorators.intersection(
            {"pytest.fixture", "_pytest.fixture"}
        ):
            continue
        excluded_lines.update(
            range(node.lineno, getattr(node, "end_lineno", node.lineno) + 1)
        )
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for token in tokens:
            if (
                token.type == tokenize.COMMENT
                and token.start[0] not in excluded_lines
                and _OMISSION_COMMENT.search(token.string)
            ):
                findings.append(
                    {
                        "code": "QUALITY_OMISSION_MARKER",
                        "severity": "MEDIUM",
                        "path": relative,
                        "line": token.start[0],
                        "column": token.start[1],
                        "message": "An actionable omission marker appears in a source comment; review whether the work is still outstanding.",
                        "facts": {
                            "rule": "omission-marker",
                            "intent": "UNKNOWN_REVIEW_REQUIRED",
                            "action": "Confirm the marker is resolved or document why it remains intentional.",
                        },
                    }
                )
    except (IndentationError, tokenize.TokenError):
        return findings
    return findings


def _implementation_is_exempt(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    parents: dict[ast.AST, ast.AST],
    aliases: dict[str, str],
) -> bool:
    decorators = _implementation_decorator_names(node, aliases)
    exempt_decorators = {
        "abc.abstractmethod",
        "builtins.abstractmethod",
        "typing.overload",
        "typing_extensions.overload",
        "pytest.fixture",
        "_pytest.fixture",
    }
    return (
        node.name in {"__init_subclass__", "__subclasshook__"}
        or bool(decorators & exempt_decorators)
        or _implementation_protocol_class(node, parents, aliases)
    )


def _implementation_stub_statement(statement: ast.stmt) -> bool:
    if isinstance(statement, ast.Pass) or _implementation_placeholder_raise(statement):
        return True
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and statement.value.value is Ellipsis
    )


def _implementation_stub_finding(relative: str, node: ast.AST) -> dict[str, Any]:
    return {
        "code": "QUALITY_EMPTY_IMPLEMENTATION",
        "severity": "MEDIUM",
        "path": relative,
        "line": node.lineno,
        "column": node.col_offset,
        "message": "The function body contains only a stub statement; review whether this production implementation is intentionally incomplete.",
        "facts": {
            "rule": "production-empty-body",
            "symbol": node.name,
            "intent": "UNKNOWN_REVIEW_REQUIRED",
            "action": "Implement the behavior or document the intentional extension point.",
        },
    }


def _implementation_return_finding(
    relative: str, function: ast.AST, statement: ast.Return
) -> dict[str, Any] | None:
    if not isinstance(statement.value, ast.Constant) or not isinstance(
        statement.value.value, str
    ):
        return None
    sentinel = statement.value.value
    if sentinel.strip().casefold() not in _IMPLEMENTATION_PLACEHOLDERS:
        return None
    return {
        "code": "QUALITY_PLACEHOLDER_OUTPUT",
        "severity": "MEDIUM",
        "path": relative,
        "line": statement.lineno,
        "column": statement.col_offset,
        "message": "The function returns an exact placeholder string; review whether this is intended output.",
        "facts": {
            "rule": "explicit-static-output-sentinel",
            "symbol": function.name,
            "sentinel": sentinel,
            "intent": "UNKNOWN_REVIEW_REQUIRED",
            "action": "Replace the sentinel with a real result or document the bounded preview contract.",
        },
    }


def _implementation_function_nodes(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
):
    pending = list(function.body)
    while pending:
        node = pending.pop()
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        yield node
        pending.extend(ast.iter_child_nodes(node))


def _implementation_function_findings(
    relative: str,
    tree: ast.Module,
    parents: dict[ast.AST, ast.AST],
    module_aliases: dict[str, str],
) -> list[dict[str, Any]]:
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if _implementation_is_test_function(node, parents):
            continue
        aliases = _implementation_aliases_for(node, parents, module_aliases, tree)
        if _implementation_is_exempt(node, parents, aliases):
            continue
        body = _implementation_docstring_body(node)
        if len(body) == 1 and _implementation_stub_statement(body[0]):
            findings.append(_implementation_stub_finding(relative, node))
        for child in _implementation_function_nodes(node):
            if isinstance(child, ast.Return):
                finding = _implementation_return_finding(relative, node, child)
                if finding is not None:
                    findings.append(finding)
    return findings


def _implementation_mock_findings(
    relative: str,
    tree: ast.Module,
    parents: dict[ast.AST, ast.AST],
    module_aliases: dict[str, str],
) -> list[dict[str, Any]]:
    findings = []
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        if _implementation_is_test_function(call, parents):
            continue
        aliases = _implementation_aliases_for(call, parents, module_aliases, tree)
        api = _implementation_call_name(call.func, aliases)
        if api not in _MOCK_APIS:
            continue
        findings.append(
            {
                "code": "QUALITY_PRODUCTION_MOCK",
                "severity": "MEDIUM",
                "path": relative,
                "line": call.lineno,
                "column": call.col_offset,
                "message": "Production code constructs or applies a test-mocking API; review whether this is an intentional adapter seam.",
                "facts": {
                    "rule": "production-mock-provenance",
                    "api": api,
                    "intent": "UNKNOWN_REVIEW_REQUIRED",
                    "action": "Confirm the mocked dependency is an intentional production seam and not placeholder behavior.",
                },
            }
        )
    return findings


def implementation_completeness_findings(
    relative: str,
    tree: ast.AST,
    source: str | bytes,
    aliases: Mapping[str, str] | None = None,
    test_source: bool = False,
) -> list[dict[str, Any]]:
    """Return bounded review signals for explicit Python implementation omissions.

    Findings describe candidates for review and do not establish defect, runtime
    behavior, or complete placeholder coverage.
    """
    if not isinstance(tree, ast.Module):
        return []
    if isinstance(source, bytes):
        try:
            encoding, _ = tokenize.detect_encoding(io.BytesIO(source).readline)
            source = source.decode(encoding)
        except (SyntaxError, UnicodeDecodeError, LookupError) as exc:
            raise ValueError("source bytes have an invalid Python encoding") from exc
    elif not isinstance(source, str):
        raise TypeError("source must be str or bytes")
    if test_source or _implementation_is_test_path(relative):
        return []
    supplied = {
        name: target
        for name, target in (aliases or {}).items()
        if isinstance(name, str) and isinstance(target, str)
    }
    module_aliases = _implementation_imports(tree.body)
    module_aliases.update(supplied)
    parents = _implementation_parents(tree)
    findings = _implementation_comment_findings(
        relative, source, tree, parents, module_aliases
    )
    findings.extend(
        _implementation_function_findings(relative, tree, parents, module_aliases)
    )
    findings.extend(
        _implementation_mock_findings(relative, tree, parents, module_aliases)
    )
    return sorted(
        findings,
        key=lambda item: (
            item["line"],
            item["column"],
            item["code"],
            item["facts"].get("symbol", item["facts"].get("api", "")),
        ),
    )
