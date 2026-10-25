"""Three fail-closed senior-review controls: intent/diff, freshness, and policy ownership."""

from __future__ import annotations
import hashlib
import io
import re
import ast
import tokenize
import configparser
import shlex
from collections.abc import Mapping
from .runtime_audit_integrity import (
    assigned_sync_function_call as assigned_sync_function_call,
    test_execution_findings as test_execution_findings,
    native_test_probe as native_test_probe,
    _oracle_call_candidates as _oracle_call_candidates,
    _oracle_stable_call as _oracle_stable_call,
    _later_test_binding as _later_test_binding,
    _asserted_coroutine_call as _asserted_coroutine_call,
    _unawaited_coroutine_finding as _unawaited_coroutine_finding,
    _nearest_native_function_scope as _nearest_native_function_scope,
    _native_call_probe_lines as _native_call_probe_lines,
    native_execution_helpers as native_execution_helpers,
    runtime_callback_coverage as runtime_callback_coverage,
    _LiteralConsumers as _LiteralConsumers,
)
from pathlib import Path
from typing import Any
from .runtime_audit_common import RuntimeAuditError
from .provenance import NativeOraclePayload as NativeOraclePayload
from . import _source_binding_helpers as _package_source_binding_helpers

source_signature, bind_source_call = _package_source_binding_helpers()


def source_binding_helpers():
    """Return the deduplicated package source-binding helpers plus source-call signature and binding utilities."""
    return tuple(
        dict.fromkeys(
            (*_package_source_binding_helpers(), source_signature, bind_source_call)
        )
    )


def _name(node: ast.AST | None) -> str:
    return ast.unparse(node) if node is not None else ""


def _resolve(node: ast.AST | None, aliases: dict[str, str]) -> str:
    name = _name(node)
    head, dot, tail = name.partition(".")
    return aliases.get(head, head) + dot + tail


def _click_provider_escapes(module, aliases):
    roots = {name for name, value in aliases.items() if value == "click"}
    commands = {name for name, value in aliases.items() if value == "click.command"}
    if not roots:
        return True
    nodes = tuple(ast.walk(module))
    calls = {node.func for node in nodes if isinstance(node, ast.Call)}
    parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
    from .test_callback_closure import _click_provider_node_escapes

    return any(
        _click_provider_node_escapes(node, roots, commands, calls, parents)
        for node in nodes
    )


def _lexical_nodes(node: ast.AST):
    from .review_audits import _body_nodes

    yield node
    for child in ast.iter_child_nodes(node):
        yield from _body_nodes(child)


def _reachable_scope_nodes(statements):
    for statement in statements:
        if isinstance(statement, ast.For):
            yield from _reachable_scope_nodes(statement.body)
        elif isinstance(
            statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            yield statement
        else:
            yield from _lexical_nodes(statement)


def _direct_vacuous_assertions(node, aliases, vacuous_check, remember):
    body = getattr(node, "body", None)
    if not isinstance(body, list):
        return set()
    known, vacuous = {}, set()
    for statement in body:
        if isinstance(statement, ast.Assert):
            if vacuous_check(statement.test, known):
                vacuous.add(id(statement))
            continue
        remember(statement, known)
    return vacuous


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
    from .type_intent_hollow import negative_type_expectation

    if annotated_callable_oracle(node, context):
        return "typed"
    if negative_type_expectation(node, context):
        return "negative_typed"
    return None


def structural_oracle_finding(
    node: ast.AST, relative: str, context: dict
) -> dict | bool | None:
    """Map a structural oracle to an exemption or an explicitly unverified finding."""
    if context.get("codspeed_benchmark") and _benchmark_has_work(node, context):
        from .review_audits import _security_finding

        return _security_finding(
            "QUALITY_BENCHMARK_NOT_VERIFIED",
            relative,
            node,
            "Declared CodSpeed workload; no performance measurement or functional oracle was verified.",
            "INFO",
            symbol=node.name,
            state="INCOMPLETE",
            benchmark="NOT_VERIFIED",
        )
    status = structural_oracle_status(node, context)
    if status in {"import", "attribute"}:
        return True
    if status in {"typed", "negative_typed"}:
        from .review_audits import _security_finding

        return _security_finding(
            "QUALITY_TYPECHECK_NOT_VERIFIED",
            relative,
            node,
            (
                "Declared static-type expectation; no type-checker receipt was verified."
                if status == "negative_typed"
                else "Source-bound API construction passed; no type-checker receipt was verified."
            ),
            "INFO",
            symbol=node.name,
            state="INCOMPLETE",
            typecheck="NOT_VERIFIED",
        )
    return None


def _benchmark_has_work(node, context):
    unsupported = (
        ast.If,
        ast.While,
        ast.Try,
        ast.With,
        ast.AsyncWith,
        ast.AsyncFor,
        ast.Match,
        ast.GeneratorExp,
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.BoolOp,
        ast.IfExp,
        ast.Return,
        ast.Raise,
        ast.Break,
        ast.Continue,
        ast.Yield,
        ast.YieldFrom,
        ast.Await,
    )
    lexical = list(_lexical_nodes(node))
    if any(isinstance(n, unsupported) for n in lexical):
        return False
    if any(
        isinstance(n, ast.For) and not _benchmark_loop_nonempty(n, node, context)
        for n in lexical
    ):
        return False
    nodes = list(_reachable_scope_nodes(_oracle_body(node)))
    if any(isinstance(n, ast.Assert) for n in nodes):
        return False
    for statement in nodes:
        if isinstance(statement, ast.ClassDef) and statement.decorator_list:
            return True
        if isinstance(statement, (ast.Call, ast.Attribute, ast.Compare, ast.BinOp)):
            return True
    return False


def _benchmark_loop_nonempty(loop, test, context):
    blocked = _benchmark_rebindings(test)
    value = loop.iter
    if isinstance(value, (ast.List, ast.Tuple)):
        return bool(value.elts) and not any(
            isinstance(item, ast.Starred) for item in value.elts
        )
    if not (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == "range"
        and len(value.args) == 1
        and not value.keywords
    ):
        return False
    constants = context.get("benchmark_constants", {})
    if not constants.get("__range_builtin__") or "range" in blocked:
        return False
    argument = value.args[0]
    if isinstance(argument, ast.Constant):
        bound = argument.value
    elif isinstance(argument, ast.Name):
        if argument.id in blocked:
            return False
        bound = constants.get(argument.id)
    else:
        return False
    return type(bound) is int and 0 < bound <= 10_000_000


def _benchmark_rebindings(test):
    names = {
        a.arg for a in (*test.args.posonlyargs, *test.args.args, *test.args.kwonlyargs)
    }
    names.update(a.arg for a in (test.args.vararg, test.args.kwarg) if a)
    names.update(name for stmt in test.body for name in _oracle_bound_names(stmt))
    return names


def _module_benchmark_marker(tree):
    imports = {
        a.asname or a.name: a.name
        for n in tree.body
        if isinstance(n, ast.Import)
        for a in n.names
    }
    marks = [
        n
        for n in tree.body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "pytestmark" for t in n.targets)
    ]
    if len(marks) != 1 or len(marks[0].targets) != 1:
        return False
    value = marks[0].value
    value = value.func if isinstance(value, ast.Call) else value
    name = _name(value)
    head = name.split(".", 1)[0]
    if (
        imports.get(head) != "pytest"
        or _resolve(value, imports) != "pytest.mark.benchmark"
    ):
        return False
    return not any(
        head in _oracle_bound_names(n) or "pytestmark" in _oracle_bound_names(n)
        for n in tree.body
        if n is not marks[0] and not isinstance(n, ast.Import)
    )


def _configured_benchmark_targets(config, root, files):
    targets = set()
    for section in config.sections():
        if not section.startswith("testenv"):
            continue
        for line in config.get(section, "commands", fallback="").splitlines():
            if not line.strip().startswith("pytest "):
                continue
            argv = shlex.split(line)
            if not argv or argv[0] != "pytest" or "--codspeed" not in argv:
                continue
            targets.update(p for p in files if p.relative_to(root).as_posix() in argv)
    return targets


def benchmark_configuration(root, files, read_bytes, limit):
    """Bind exact CodSpeed argv targets; malformed or missing inputs grant nothing."""
    identity = {"path": "tox.ini", "state": "missing"}
    try:
        data = read_bytes(root, "tox.ini")
        if len(data) > limit:
            return set(), [], {"path": "tox.ini", "state": "oversized"}, False
        binding = {
            "path": "tox.ini",
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        }
        config = configparser.ConfigParser(interpolation=None)
        config.read_string(data.decode("utf-8"))
        targets = _configured_benchmark_targets(config, root, files)
        return targets, [binding], binding, True
    except FileNotFoundError:
        return set(), [], identity, True
    except RuntimeAuditError as exc:
        return (
            set(),
            [],
            {**identity, "state": exc.code},
            exc.code == "E_SOURCE_MISSING",
        )
    except (OSError, UnicodeError, ValueError, configparser.Error) as exc:
        return set(), [], {**identity, "state": type(exc).__name__}, False


def oracle_configuration(root, files, typecheck_inputs, read_bytes, limit):
    """Combine bounded type-checker and benchmark configuration identities."""
    types, bindings, identity, cacheable = typecheck_inputs(root, files)
    from .context_efficiency import application_profile_configuration

    application_bindings, application_identity, application_valid = (
        application_profile_configuration(root, read_bytes, limit)
    )
    benchmarks, added, config, valid = benchmark_configuration(
        root, files, read_bytes, limit
    )
    return (
        types,
        bindings + added + application_bindings,
        {
            "typecheck": identity,
            "benchmark": config,
            "application_profiles": application_identity,
        },
        cacheable and valid and application_valid,
        benchmarks,
    )


def bind_benchmark_context(contexts, snapshots, benchmark_sources):
    """Bind module markers and immutable loop bounds without running project code."""
    for path, context in contexts.items():
        context["codspeed_benchmark"] = (
            path in benchmark_sources and _module_benchmark_marker(snapshots[path])
        )
        tree = snapshots[path]
        names = [_oracle_bound_names(stmt) for stmt in tree.body]
        constants = {
            stmt.targets[0].id: stmt.value.value
            for stmt in tree.body
            if isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and isinstance(stmt.value, ast.Constant)
            and type(stmt.value.value) is int
            and sum(stmt.targets[0].id in row for row in names) == 1
        }
        constants["__range_builtin__"] = not any("range" in row for row in names)
        context["benchmark_constants"] = constants


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


def _oracle_bound_names(statement: ast.AST) -> set[str]:
    from .review_audits import _body_nodes, _bound_names

    names = _bound_names(statement)
    for child in _body_nodes(statement):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(child.name)
        if isinstance(child, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef)):
            for default in [*child.args.defaults, *child.args.kw_defaults]:
                if default is not None:
                    names.update(_oracle_bound_names(default))
    return names


def callback_argument(call: ast.Call, function: ast.AST, parameter: str) -> str | None:
    """Return an explicitly supplied name from a valid source call binding."""
    try:
        value = bind_source_call(call, function, apply_defaults=False).get(parameter)
    except ValueError:
        return None
    return value.id if isinstance(value, ast.Name) else None


def _callback_registry_store(node: ast.AST, name: str) -> bool:
    return (
        isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, (ast.Store, ast.Del))
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
    return False


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


def _closed_registered_callback_functions(functions, aliases, registry):
    """Select one local registrar by its exact append body, allowing stacked names."""
    names = {
        decorator.id
        for function in functions
        for decorator in function.decorator_list
        if isinstance(decorator, ast.Name)
        and _resolve(decorator, aliases) == decorator.id
    }
    candidates = []
    for name in names:
        definitions = [function for function in functions if function.name == name]
        if len(definitions) != 1:
            continue
        register = definitions[0]
        if not (
            isinstance(register, ast.AsyncFunctionDef)
            or isinstance(register, ast.FunctionDef)
            and _callback_registration_body(register, registry) is not None
        ):
            continue
        callbacks = [
            function
            for function in functions
            if any(
                isinstance(decorator, ast.Name) and decorator.id == name
                for decorator in function.decorator_list
            )
        ]
        if len(callbacks) == 1 and callbacks[0] is not register:
            candidates.append((register, callbacks))
    return candidates[0] if len(candidates) == 1 else None


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


def _registry_noop_lambda(node):
    args = node.args if isinstance(node, ast.Lambda) else None
    return bool(
        args
        and len(args.args) == 1
        and not any(
            (
                args.posonlyargs,
                args.kwonlyargs,
                args.defaults,
                args.kw_defaults,
                args.vararg,
                args.kwarg,
            )
        )
        and isinstance(node.body, ast.Constant)
        and node.body.value is None
    )


def _registry_identity_lambda(node, parameter):
    args = node.args if isinstance(node, ast.Lambda) else None
    return bool(
        args
        and len(args.args) == 1
        and args.args[0].arg == parameter
        and not any(
            (
                args.posonlyargs,
                args.kwonlyargs,
                args.defaults,
                args.kw_defaults,
                args.vararg,
                args.kwarg,
            )
        )
        and isinstance(node.body, ast.Name)
        and node.body.id == parameter
    )


def _registry_noop_decorator(function):
    if (
        not isinstance(function, ast.FunctionDef)
        or function.decorator_list
        or getattr(function, "type_params", ())
        or not _registered_callback_args(function)
    ):
        return False
    body = [statement for statement in function.body if not _is_docstring(statement)]
    return (
        len(body) == 1
        and isinstance(body[0], ast.Return)
        and _registry_noop_lambda(body[0].value)
    )


def _registry_callback_decorators_inert(register, callback, functions):
    decorators = callback.decorator_list
    if (
        not decorators
        or not isinstance(decorators[0], ast.Name)
        or decorators[0].id != register.name
    ):
        return False
    wrappers = [
        function for function in functions if function not in (register, callback)
    ]
    extra = decorators[1:]
    if len(wrappers) != len(extra):
        return False
    if not extra:
        return True
    if any(not isinstance(decorator, ast.Name) for decorator in extra):
        return False
    wrapper_names = {decorator.id for decorator in extra}
    return (
        len(wrapper_names) == len(extra)
        and wrapper_names == {function.name for function in wrappers}
        and all(_registry_noop_decorator(function) for function in wrappers)
    )


def _registered_callback_args(function):
    args = function.args
    return (
        len(args.args) == 1
        and not any(
            (
                args.posonlyargs,
                args.kwonlyargs,
                args.vararg,
                args.kwarg,
                args.defaults,
                args.kw_defaults,
            )
        )
        and args.args[0].annotation is None
        and function.returns is None
    )


def _registry_swallowed_assertion(test, callback, call):
    module = getattr(test, "_oracle_module", None)
    provider_mutation = module is not None and any(
        isinstance(node, ast.Call)
        and ast.unparse(node.func).rsplit(".", 1)[-1] in {"setattr", "delattr"}
        for node in ast.walk(module)
    )
    if (
        module is None
        or {"AssertionError", "__builtins__", "*"}
        & (_security_scope_local_names(test) | _security_scope_local_names(module))
        or any(
            arg and arg.arg == "AssertionError"
            for arg in [
                *test.args.posonlyargs,
                *test.args.args,
                *test.args.kwonlyargs,
                test.args.vararg,
                test.args.kwarg,
            ]
        )
        or provider_mutation
        or any(
            isinstance(node, ast.Attribute)
            and node.attr == "AssertionError"
            and isinstance(node.ctx, (ast.Store, ast.Del))
            for node in ast.walk(module)
        )
    ):
        return False
    body = [stmt for stmt in callback.body if not _is_docstring(stmt)]
    if not (len(body) == 1 and isinstance(body[0], ast.Assert) and body[0].msg is None):
        return False
    compare = body[0].test
    if not (
        isinstance(compare, ast.Compare)
        and len(compare.ops) == 1
        and isinstance(compare.ops[0], (ast.Eq, ast.NotEq))
        and len(compare.comparators) == 1
    ):
        return False
    if len(callback.args.args) != 1 or len(call.args) != 1 or call.keywords:
        return False
    left, right, actual = compare.left, compare.comparators[0], call.args[0]
    name, literal = (left, right) if isinstance(left, ast.Name) else (right, left)
    return (
        isinstance(name, ast.Name)
        and name.id == callback.args.args[0].arg
        and isinstance(literal, ast.Constant)
        and isinstance(actual, ast.Constant)
        and type(literal.value) is type(actual.value)
        and type(actual.value) in (type(None), bool, int, float, str, bytes)
    )


def _callback_has_live_assertion(
    callback, aliases, strong_assertion, effective_assertion
):
    if _callback_catches_assertion(callback):
        return False
    nodes = list(_lexical_nodes(callback))
    if any(isinstance(node, (ast.Yield, ast.YieldFrom)) for node in nodes):
        return False
    return strong_assertion(callback, aliases) and any(
        isinstance(node, ast.Assert) and effective_assertion(node, aliases)
        for node in nodes
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
    return [
        node
        for node in test.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.List)
        and not node.value.elts
    ]


def _callback_registry_selection(test, functions, aliases, closed):
    initializers = _empty_callback_registries(test)
    if closed and not initializers:
        return None
    if closed:
        sync_functions = [
            node for node in functions if isinstance(node, ast.FunctionDef)
        ]
        pair = _registered_callback_functions(sync_functions, aliases)
        if pair is None or len(pair[1]) != 1:
            pair = _closed_registered_callback_functions(
                functions, aliases, initializers[0].targets[0].id
            )
    else:
        pair = _registered_callback_functions(
            [node for node in functions if isinstance(node, ast.FunctionDef)], aliases
        )
    if pair is None:
        return None
    register, callbacks = pair
    if closed:
        initializers = [node for node in initializers if node.lineno < register.lineno]
    valid_counts = (len(functions), len(callbacks)) in {(2, 1), (3, 1)}
    if len(initializers) != 1 or closed and not valid_counts:
        return None
    initial = initializers[0]
    if initial.lineno >= register.lineno or any(
        register.lineno >= fn.lineno for fn in callbacks
    ):
        return None
    return initial, register, callbacks


def _callback_registry_context(test, aliases, *, closed=False, inert_kind=None):
    if (
        not isinstance(test, ast.FunctionDef)
        or closed
        and sum(1 for _ in ast.walk(test)) > 512
    ):
        return None
    functions = [
        node
        for node in test.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    selection = _callback_registry_selection(test, functions, aliases, closed)
    if selection is None:
        return None
    initial, register, callbacks = selection
    if closed:
        callback = callbacks[0]
        if (
            register is callback
            or register.decorator_list
            or not callback.body
            or not _registry_callback_decorators_inert(register, callback, functions)
            or not _registered_callback_args(register)
            or not _registered_callback_args(callback)
            or inert_kind is None
        ):
            return None
        state = inert_kind(test, register, initial.targets[0].id, callback, functions)
        if state is None:
            return None
    else:
        state = None
    return initial, initial.targets[0].id, register, callbacks, functions, state


def registered_callback_oracle(test, aliases, strong_assertion, effective_assertion):
    """Prove direct local append-registry dispatch; unsupported syntax is unproven."""
    context = _callback_registry_context(test, aliases)
    if context is None:
        return False
    initial, registry, register, callbacks, _functions, _state = context
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


_CALLBACK_REGISTRY_HELPERS = (
    _callback_registry_context,
    _registered_callback_args,
    _registry_noop_lambda,
    _registry_swallowed_assertion,
    _callback_registration_body,
    _registered_callback_functions,
    _closed_registered_callback_functions,
    _registry_identity_lambda,
    _registry_noop_decorator,
    _registry_callback_decorators_inert,
    _empty_callback_registries,
    _callback_registry_selection,
    _is_docstring,
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


def verify_intent_diff(
    root: Path, contract_path: Path, diff_path: Path, out: Path
) -> dict[str, Any]:
    """Validate intent diff against approved contract and write receipt."""
    from .change_review import verify_intent_diff as verify

    return verify(root, contract_path, diff_path, out)


def verify_receipt_freshness(
    root: Path, manifest_path: Path, out: Path
) -> dict[str, Any]:
    """Check receipt age and manifest context; write result."""
    from .change_review import verify_receipt_freshness as verify

    return verify(root, manifest_path, out)


def verify_policy_pack(root: Path, pack_path: Path, out: Path) -> dict[str, Any]:
    """Verify the versioned human-owned pack and write receipt."""
    from .change_review import verify_policy_pack as verify

    return verify(root, pack_path, out)


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


def _implementation_bound_names(scope: ast.AST, nodes=None) -> set[str]:
    nodes = _implementation_scope_nodes(scope) if nodes is None else nodes
    names = {
        node.id
        for node in nodes
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
    }
    definitions = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    names.update(
        n.name
        for n in nodes
        if isinstance(n, definitions)
        or (isinstance(n, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and n.name)
    )
    names.update(
        node.rest for node in nodes if isinstance(node, ast.MatchMapping) and node.rest
    )
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        names.update(
            item.arg
            for item in ast.iter_child_nodes(scope.args)
            if isinstance(item, ast.arg)
        )
    return names


def _implementation_scope_aliases(
    scope: ast.AST, inherited: dict[str, str]
) -> dict[str, str]:
    nodes = _implementation_scope_nodes(scope)
    imports = _implementation_imports(nodes)
    bound = _implementation_bound_names(scope, nodes)
    return {
        name: value
        for name, value in {**inherited, **imports}.items()
        if name not in bound
    }


def _implementation_call_name(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        return f"{_implementation_call_name(node.value, aliases)}.{node.attr}"
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
    if not scope.decorator_list:
        return False
    module: ast.AST = scope
    while module in parents:
        module = parents[module]
    aliases = _implementation_aliases_for(
        module, parents, _implementation_imports(module.body), module
    )
    aliases.setdefault("pytest", "")
    aliases.setdefault("_pytest", "")
    return bool(
        _implementation_decorator_names(scope, aliases)
        & {"pytest.fixture", "_pytest.fixture"}
    )


def _implementation_aliases_for(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
    module_aliases: dict[str, str],
    module: ast.Module,
) -> dict[str, str]:
    cache = getattr(module, "_implementation_alias_cache", None)
    scopes = tuple(_implementation_scope_chain(node, parents))
    key = (scopes, tuple(module_aliases.items())) if cache is not None else None
    if cache is not None and key in cache:
        return dict(cache[key])
    aliases = _implementation_scope_aliases(module, module_aliases)
    for scope in scopes:
        aliases = _implementation_scope_aliases(scope, aliases)
    if cache is not None:
        cache[key] = dict(aliases)
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
    start = 1 if ast.get_docstring(node, clean=False) is not None else 0
    return list(node.body[start:])


def _implementation_static_interface(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
    aliases: dict[str, str],
    tree: ast.Module,
) -> bool:
    child, parent = node, parents.get(node)
    while parent is not None:
        if isinstance(parent, ast.ClassDef) and any(
            _implementation_call_name(base, aliases)
            in {"typing.Protocol", "typing_extensions.Protocol"}
            for base in parent.bases
        ):
            return True
        if isinstance(parent, ast.If) and child in parent.body:
            condition_aliases = _implementation_aliases_for(
                parent.test, parents, {}, tree
            )
            scopes = (tree, *_implementation_scope_chain(parent.test, parents))
            writes = any(
                isinstance(item, ast.Attribute)
                and item.attr == "TYPE_CHECKING"
                and isinstance(item.ctx, (ast.Store, ast.Del))
                for scope in scopes
                for item in _implementation_scope_nodes(scope)
            )
            if (
                not writes
                and _implementation_call_name(parent.test, condition_aliases)
                == "typing.TYPE_CHECKING"
            ):
                return True
        child, parent = parent, parents.get(parent)
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
    findings, excluded_lines = [], set()
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
    tree: ast.Module,
) -> bool:
    from .intent_quality import intentional_implementation_contract

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
        or _implementation_static_interface(node, parents, aliases, tree)
        or intentional_implementation_contract(node, parents, aliases)
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


def _implementation_function_nodes(function: ast.FunctionDef | ast.AsyncFunctionDef):
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
        if _implementation_is_exempt(node, parents, aliases, tree):
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
    module_aliases = {**_implementation_imports(tree.body), **supplied}
    parents = _implementation_parents(tree)
    tree._implementation_alias_cache = {}
    try:
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
    finally:
        tree.__dict__.pop("_implementation_alias_cache", None)


def _invalidate_mutable_constants(statement, known):
    from .review_audits import _body_nodes

    if any(
        isinstance(item, (ast.Call, ast.Subscript)) for item in _body_nodes(statement)
    ):
        for name, prior in list(known.items()):
            if isinstance(prior, (list, dict, set, tuple)):
                known.pop(name, None)


def remember_direct_constant_assignment(
    statement: ast.stmt, known: dict[str, Any]
) -> None:
    """Preserve the existing direct-assignment constant-folding behavior."""
    from .review_audits import (
        _UNKNOWN_CONSTANT,
        _bound_names,
        _constant_value,
    )

    targets: list[ast.expr] = []
    value: Any = _UNKNOWN_CONSTANT
    _invalidate_mutable_constants(statement, known)
    if isinstance(statement, ast.Assign):
        value = _constant_value(statement.value, known)
        targets = statement.targets
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        value = _constant_value(statement.value, known)
        targets = [statement.target]
    for name in _bound_names(statement):
        known.pop(name, None)
    if value is _UNKNOWN_CONSTANT:
        return
    for target in targets:
        if isinstance(target, ast.Name):
            known[target.id] = value


_STRUCTURAL_SET_FIELDS = (
    "module_rebindings",
    "dynamic_getattr_modules",
    "source_classes",
) + ("implementation_contract_lines",)
_STRUCTURAL_MAP_FIELDS = ("module_imports", "class_imports", "benchmark_constants")


def encode_structural_context(context):
    """Encode all structural oracle bindings for the bounded in-memory cache."""
    return {
        **{key: sorted(context.get(key, set())) for key in _STRUCTURAL_SET_FIELDS},
        **{key: context.get(key, {}) for key in _STRUCTURAL_MAP_FIELDS},
    }


def decode_structural_context(payload):
    """Restore structural oracle bindings without weakening their source identity."""
    return {
        **{key: set(payload.get(key, [])) for key in _STRUCTURAL_SET_FIELDS},
        **{key: payload.get(key, {}) for key in _STRUCTURAL_MAP_FIELDS},
    }


def tls_verification_disabled(call: str, node: ast.Call) -> bool:
    """Recognize explicit verification bypasses on known TLS API boundaries."""
    if call == "ssl._create_unverified_context":
        return True
    methods = {"get", "post", "put", "patch", "delete", "head", "options", "request"}
    supported = {
        f"{module}.{method}" for module in ("requests", "httpx") for method in methods
    }
    supported.update({"httpx.Client", "httpx.AsyncClient", "httpx.stream"})
    if call not in supported:
        return False
    return any(
        keyword.arg == "verify"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is False
        for keyword in node.keywords
    )


def bind_security_call_scopes(tree: ast.AST) -> None:
    """Retain lexical parameter shadowing for nested security call readers."""
    tree._security_sanitizer_provider_cache = {}
    tree._security_parent_scope = None
    tree._security_scope_kind = "module"
    tree._security_local_names = set()
    tree._security_nonlocal_names = set()
    tree._security_calls_by_statement = {}
    _bind_security_scope_node(tree, tree, set(), tree)


def _security_ast_span_contains(node, container):
    return (container.lineno, container.col_offset) <= (
        node.lineno,
        node.col_offset,
    ) and (node.end_lineno, node.end_col_offset) <= (
        container.end_lineno,
        container.end_col_offset,
    )


def _bind_security_scope_node(node, scope, shadowed, tree, flow_statement=None):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        _bind_security_function(node, scope, shadowed, tree, flow_statement)
        return
    if isinstance(node, ast.ClassDef):
        _bind_security_class(node, scope, shadowed, tree, flow_statement)
        return
    if isinstance(node, ast.Call):
        node._security_shadowed_names = shadowed
        node._security_lexical_scope = scope
        node._security_flow_statement = flow_statement
        calls = getattr(scope, "_security_calls_by_statement", {})
        calls.setdefault(id(flow_statement), []).append(node)
        scope._security_calls_by_statement = calls
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        node._security_lexical_scope = scope
    if isinstance(node, ast.Attribute):
        node._security_lexical_scope = scope
        node._security_flow_statement = flow_statement
    for child in ast.iter_child_nodes(node):
        direct = child if node is scope else flow_statement
        _bind_security_scope_node(child, scope, shadowed, tree, direct)


def _bind_security_function(node, scope, shadowed, tree, flow_statement):
    arguments = node.args
    body = node.body if isinstance(node.body, list) else [node.body]
    definition_statement = flow_statement or node
    for decorator in getattr(node, "decorator_list", []):
        _bind_security_scope_node(
            decorator, scope, shadowed, tree, definition_statement
        )
    for default in [*arguments.defaults, *arguments.kw_defaults]:
        if default is not None:
            _bind_security_scope_node(
                default, scope, shadowed, tree, definition_statement
            )
    for annotation in _function_annotations(node):
        _bind_security_scope_node(
            annotation, scope, shadowed, tree, definition_statement
        )
    lexical_parent = (
        getattr(scope, "_security_parent_scope", tree)
        if isinstance(scope, ast.ClassDef)
        else scope
    )
    node._security_parent_scope = lexical_parent
    node._security_class_scope = scope if isinstance(scope, ast.ClassDef) else None
    arguments_names = {
        argument.arg
        for argument in [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            *[arg for arg in (arguments.vararg, arguments.kwarg) if arg],
        ]
    }
    node._security_parameter_names = arguments_names
    node._security_local_names = _security_scope_local_names(node)
    node._security_nonlocal_names = _security_scope_nonlocal_names(node)
    node._security_scope_kind = "function"
    node._security_calls_by_statement = {}
    child_shadowed = shadowed | arguments_names | node._security_local_names
    for child in body:
        _bind_security_scope_node(child, node, child_shadowed, tree, child)


def _bind_security_class(node, scope, shadowed, tree, flow_statement):
    for child in [*node.decorator_list, *node.bases]:
        _bind_security_scope_node(child, scope, shadowed, tree, flow_statement or node)
    for keyword in node.keywords:
        _bind_security_scope_node(
            keyword.value, scope, shadowed, tree, flow_statement or node
        )
    node._security_parent_scope = scope
    node._security_scope_kind = "class"
    node._security_local_names = _security_scope_local_names(node)
    node._security_nonlocal_names = _security_scope_nonlocal_names(node)
    node._security_calls_by_statement = {}
    for child in node.body:
        _bind_security_scope_node(child, node, shadowed, tree, child)


def _function_annotations(node):
    args = node.args
    values = [
        arg.annotation for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]
    ]
    values.extend(arg.annotation for arg in (args.vararg, args.kwarg) if arg)
    if getattr(node, "returns", None) is not None:
        values.append(node.returns)
    return [value for value in values if value is not None]


def _security_scope_local_names(scope):
    from . import review_audits as audit

    names = set()
    body = getattr(scope, "body", [])
    statements = body if isinstance(body, list) else [body]
    for statement in statements:
        if not isinstance(statement, ast.AST):
            continue
        names.update(audit._bound_names(statement))
    return (
        names
        - _security_scope_declared_names(scope, ast.Global)
        - (_security_scope_declared_names(scope, ast.Nonlocal))
    )


def _security_scope_nonlocal_names(scope):
    return _security_scope_declared_names(scope, ast.Nonlocal)


def _security_scope_declared_names(scope, declaration):
    body = getattr(scope, "body", [])
    statements = body if isinstance(body, list) else [body]
    names = set()
    pending = list(statements)
    while pending:
        node = pending.pop()
        if not isinstance(node, ast.AST):
            continue
        if node is not scope and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        if isinstance(node, declaration):
            names.update(node.names)
        pending.extend(ast.iter_child_nodes(node))
    return names


def session_tls_findings(relative, node, aliases, emit):
    """Recognize verify=False assignments only on a direct, unrebound Session."""
    if not isinstance(node.value, ast.Constant) or node.value.value is not False:
        return []
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    scope = getattr(node, "_security_lexical_scope", None) or getattr(
        node, "_oracle_scope", None
    )
    constructors = _session_tls_constructor_map(scope, node, aliases)
    if constructors is None:
        return []
    return [
        emit(
            "SECURITY_TLS_VERIFY_DISABLED",
            relative,
            node,
            "TLS certificate verification is disabled on a proven Requests session.",
            "HIGH",
            call="requests.Session.verify",
            receiver=target.value.id,
        )
        for target in targets
        if isinstance(target, ast.Attribute)
        and target.attr == "verify"
        and isinstance(target.value, ast.Name)
        and target.value.id in constructors
    ]


def _session_tls_constructor_map(scope, node, aliases):
    from . import review_audits as audit

    constructors = {}
    for statement in getattr(scope, "body", []):
        if statement is node:
            return constructors
        bindings = audit._bound_names(statement)
        constructors = {
            name: value for name, value in constructors.items() if name not in bindings
        }
        if isinstance(statement, ast.Assign) and isinstance(statement.value, ast.Call):
            call = security_call_name(statement.value, aliases)
            resolved, _ = _security_flow_bindings(statement.value, aliases)
            head = audit._call_name(statement.value).split(".", 1)[0]
            if call == "requests.Session" and head in resolved:
                constructors.update(
                    {
                        target.id: call
                        for target in statement.targets
                        if isinstance(target, ast.Name)
                    }
                )
    return None


def security_assignment_findings(relative, node, aliases):
    """Combine literal diagnostics with proven session verification changes."""
    from . import intent_quality, review_audits as audit

    literal_findings = intent_quality._literal_assignment_diagnostics(
        relative,
        node,
        aliases,
        audit._literal_assignment_diagnostics(relative, node, aliases),
    )
    from .provenance import public_symbolic_findings
    import sys

    literal_findings = public_symbolic_findings(
        relative, node, literal_findings, sys.modules[__name__]
    )
    return literal_findings + session_tls_findings(
        relative, node, aliases, audit._security_finding
    )


_REDIRECT_EXCEPTION_TYPES = {
    "HTTPMultipleChoices",
    "HTTPMovedPermanently",
    "HTTPFound",
    "HTTPSeeOther",
    "HTTPUseProxy",
    "HTTPTemporaryRedirect",
    "HTTPPermanentRedirect",
}


def redirect_source_findings(relative, tree, aliases, nodes):
    """Find bounded request-path flows into imported redirect exception APIs."""
    api = _redirect_api_bindings(tree)
    if not api["requests"] or not api["redirects"]:
        return []
    functions = [
        node
        for node in nodes
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    helpers = _redirect_clone_summaries(functions, api)
    findings = []
    for function in functions:
        function_api = _redirect_scope_api(api, function)
        requests = _redirect_request_parameters(function, function_api["requests"])
        sinks = _redirect_sink_parameters(function, function_api)
        if not requests or not sinks:
            continue
        findings.extend(
            _redirect_function_flow(
                relative, function, requests, sinks, api, helpers, aliases
            )
        )
    return findings


def _redirect_api_bindings(tree):
    api = {"requests": set(), "redirects": set(), "moves": set(), "regex": set()}
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            _redirect_add_import_bindings(node, api)
        else:
            _redirect_remove_api_bindings(node, api)
    return api


def _redirect_remove_api_bindings(node, api):
    from . import review_audits as audit

    names = audit._bound_names(node)
    for values in api.values():
        values.difference_update(names)


def _redirect_scope_api(api, function):
    scoped = {key: values.copy() for key, values in api.items()}
    bound = _security_scope_local_names(function)
    bound.update(
        item.arg
        for item in [
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        ]
    )
    for values in scoped.values():
        values.difference_update(bound)
    return scoped


def _redirect_add_import_bindings(node, api):
    if isinstance(node, ast.Import):
        api["regex"].update(
            item.asname or "re" for item in node.names if item.name == "re"
        )
    if isinstance(node, ast.ImportFrom):
        _redirect_add_from_bindings(node, api)


def _redirect_add_from_bindings(node, api):
    module = node.module or ""
    if _redirect_request_import(node, module):
        api["requests"].update(
            item.asname or item.name for item in node.names if item.name == "Request"
        )
    if _redirect_exception_import(node, module):
        for item in node.names:
            if item.name in _REDIRECT_EXCEPTION_TYPES | {"HTTPMove"}:
                local = item.asname or item.name
                if item.name == "HTTPMove":
                    api["moves"].add(local)
                else:
                    api["redirects"].add(local)


def _redirect_request_import(node, module):
    return module in {"aiohttp.web_request", "aiohttp.web"} or bool(
        node.level and module == "web_request"
    )


def _redirect_exception_import(node, module):
    return module in {"aiohttp.web_exceptions", "aiohttp.web"} or bool(
        node.level and module == "web_exceptions"
    )


def _redirect_request_parameters(function, request_types):
    parameters = [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]
    return {
        parameter.arg
        for parameter in parameters
        if isinstance(parameter.annotation, ast.Name)
        and parameter.annotation.id in request_types
    }


def _redirect_clone_summaries(functions, api):
    summaries = {}
    for function in functions:
        summary = _redirect_clone_summary(function, api["requests"])
        if summary is not None or _redirect_clone_assignment(
            function, _redirect_request_parameters(function, api["requests"])
        ):
            summaries[function.name] = summary
    return summaries


def _redirect_clone_summary(function, request_types):
    requests = _redirect_request_parameters(function, request_types)
    if not requests:
        return None
    result = _redirect_clone_assignment(function, set(requests))
    if result is None:
        return None
    clone_name, path_name = result
    if not _redirect_clone_binding_stable(function, clone_name):
        return None
    positions, return_safe = _redirect_return_positions(function, clone_name, requests)
    if positions is None or len(positions) != 1:
        return None
    clone_index, success_index = next(iter(positions))
    return (
        function.name,
        _redirect_parameter_index(function, path_name),
        path_name,
        clone_index,
        success_index,
        return_safe,
    )


def _redirect_clone_binding_stable(function, clone_name):
    writes = 0
    for node in _redirect_walk_body(function):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if clone_name in _redirect_target_names(targets):
                writes += 1
    return writes == 1


def _redirect_clone_assignment(function, aliases):
    result = None
    for node in _redirect_walk_body(function):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
            if node.value.id in aliases:
                aliases.update(_redirect_target_names(node.targets))
        if not _redirect_clone_uses_request(node, aliases):
            continue
        path = next((kw.value for kw in node.keywords if kw.arg == "rel_url"), None)
        assignment = getattr(node, "_security_flow_statement", None)
        if isinstance(path, ast.Name) and isinstance(assignment, ast.Assign):
            targets = _redirect_target_names(assignment.targets)
            if len(targets) == 1 and isinstance(assignment.value, ast.Call):
                result = next(iter(targets)), path.id
    return result


def _redirect_clone_uses_request(node, aliases):
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "clone"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in aliases
    )


def _redirect_parameter_index(function, name):
    parameters = [
        *function.args.posonlyargs,
        *function.args.args,
    ]
    return next(
        (index for index, item in enumerate(parameters) if item.arg == name), -1
    )


def _redirect_walk_body(function):
    pending = list(function.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield node
        pending.extend(ast.iter_child_nodes(node))


def _redirect_target_names(targets):
    return {
        node.id
        for target in targets
        for node in ast.walk(target)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    }


def _redirect_return_positions(function, clone_name, requests):
    positions = set()
    return_safe = True
    for node in _redirect_walk_body(function):
        has_success, current, safe = _redirect_success_return_pair(
            node, clone_name, requests
        )
        if not has_success:
            continue
        if current is None or (positions and positions != {current}):
            return None, False
        positions.add(current)
        return_safe = return_safe and safe
    return positions, return_safe


def _redirect_success_return_pair(node, clone_name, requests):
    if not isinstance(node, ast.Return):
        return False, None, False
    if _redirect_explicit_failure_return(node.value):
        return False, None, False
    if not isinstance(node.value, (ast.Tuple, ast.List)):
        return True, None, False
    return _redirect_tuple_return_pair(node.value.elts, clone_name, requests)


def _redirect_tuple_return_pair(elements, clone_name, requests):
    candidates = [
        index
        for index, item in enumerate(elements)
        if isinstance(item, ast.Name) and item.id in requests | {clone_name}
    ]
    if len(candidates) != 1:
        return True, None, False
    request_index = candidates[0]
    statuses = [index for index in range(len(elements)) if index != request_index]
    if len(statuses) != 1:
        return True, None, False
    success_index = statuses[0]
    success = elements[success_index]
    if isinstance(success, ast.Constant) and success.value is False:
        return False, None, False
    if isinstance(success, ast.Constant) and not success.value:
        return False, None, False
    pair = request_index, success_index
    return True, pair, elements[request_index].id == clone_name


def _redirect_explicit_failure_return(value):
    return isinstance(value, ast.Constant) and value.value is False


def _redirect_sink_parameters(function, api):
    scopes = [function]
    parent = getattr(function, "_security_parent_scope", None)
    while isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
        scopes.append(parent)
        parent = getattr(parent, "_security_parent_scope", None)
    sinks = set().union(*(_redirect_scope_sink_names(scope, api) for scope in scopes))
    return sinks | api["redirects"]


def _redirect_scope_sink_names(scope, api):
    try:
        parameters = source_signature(scope).parameters.values()
    except ValueError:
        return set()
    return {
        p.name for p in parameters if _redirect_is_sink_parameter(p, p.default, api)
    }


def _redirect_is_sink_parameter(parameter, default, api):
    annotation = parameter.annotation
    if not isinstance(annotation, ast.Subscript):
        return False
    item = annotation.slice
    return (
        _name(annotation.value).split(".")[-1] == "Type"
        and isinstance(item, ast.Name)
        and item.id in api["moves"]
        and isinstance(default, ast.Name)
        and default.id in api["redirects"]
    )


def _redirect_function_flow(relative, function, requests, sinks, api, helpers, aliases):
    bound = _security_scope_local_names(function)
    bound.update(
        item.arg
        for item in [
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        ]
    )
    helpers = {
        name: None if name in bound else summary for name, summary in helpers.items()
    }
    state = {"requests": set(requests), "values": {}, "lists": {}, "guarded": {}}
    return _redirect_flow_block(
        relative, function.body, state, sinks, api, helpers, aliases, function
    )[1]


def _redirect_flow_block(
    relative, statements, state, sinks, api, helpers, aliases, function
):
    findings = []
    current = _redirect_copy_state(state)
    for statement in statements:
        if isinstance(statement, ast.If):
            results = [
                _redirect_flow_block(
                    relative,
                    block,
                    _redirect_guard_branch(current, statement.test, truth),
                    sinks,
                    api,
                    helpers,
                    aliases,
                    function,
                )
                for block, truth in (
                    (statement.body, True),
                    (statement.orelse, False),
                )
            ]
            current = _redirect_merge_states([row[0] for row in results])
            findings.extend(item for row in results for item in row[1])
            continue
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            loop_state, loop_findings = _redirect_for_flow(
                relative,
                statement,
                current,
                sinks,
                api,
                helpers,
                aliases,
                function,
            )
            findings.extend(loop_findings)
            current = loop_state
            continue
        findings.extend(
            _redirect_statement_sinks(
                relative, statement, current, sinks, api, function
            )
        )
        findings.extend(
            _redirect_apply_statement(statement, current, api, helpers, aliases)
        )
    return current, findings


def _redirect_for_flow(
    relative, statement, state, sinks, api, helpers, aliases, function
):
    findings = []
    current = state
    for _ in range(3):
        nested = _redirect_copy_state(current)
        iterable = _redirect_expression_state(statement.iter, current, api, aliases)
        list_name = statement.iter.id if isinstance(statement.iter, ast.Name) else None
        status = current["lists"].get(list_name, iterable)
        if status in {"path", "url", "unsafe"}:
            for name in _redirect_target_names([statement.target]):
                nested["values"][name] = status
        nested, found = _redirect_flow_block(
            relative, statement.body, nested, sinks, api, helpers, aliases, function
        )
        findings.extend(found)
        merged = _redirect_merge_states([state, nested])
        if merged == current:
            break
        current = merged
    unique = {}
    for finding in findings:
        key = (finding.get("code"), finding.get("line"), finding.get("sink"))
        unique[key] = finding
    return current, list(unique.values())


def _redirect_copy_state(state):
    return {key: value.copy() for key, value in state.items()}


def _redirect_guard_branch(state, test, truth):
    name = test.id if isinstance(test, ast.Name) else None
    if (
        isinstance(test, ast.UnaryOp)
        and isinstance(test.op, ast.Not)
        and isinstance(test.operand, ast.Name)
    ):
        name = test.operand.id
        truth = not truth
    for request, (guard, status) in state["guarded"].items():
        if name == guard:
            if truth and status == "safe":
                state["requests"].discard(request)
            else:
                state["requests"].add(request)
        else:
            state["requests"].add(request)
    return state


def _redirect_merge_states(states):
    merged = {"requests": set(), "values": {}, "lists": {}, "guarded": {}}
    for key in merged:
        names = set().union(*(state[key] for state in states))
        if key == "requests":
            merged[key] = names
            continue
        if key == "guarded":
            for name in names:
                values = {state[key].get(name) for state in states}
                if len(values) == 1:
                    merged[key][name] = next(iter(values))
            continue
        for name in names:
            values = {state[key].get(name) for state in states}
            merged[key][name] = _redirect_merge_status(*values)
    return merged


def _redirect_expression_state(node, state, api, aliases):
    source = _redirect_source_kind(node, state)
    if source is not None:
        return source
    if isinstance(node, ast.Name):
        return state["values"].get(node.id)
    statuses = _redirect_child_statuses(node, state, api, aliases)
    return _redirect_merge_status(*statuses)


def _redirect_source_kind(node, state):
    if isinstance(node, ast.Attribute):
        return _redirect_request_attribute(node, state)
    if isinstance(node, ast.Call):
        return _redirect_query_value(node, state)


def _redirect_request_attribute(node, state):
    if not isinstance(node.value, ast.Name) or node.value.id not in state["requests"]:
        return None
    return {"raw_path": "path", "url": "url"}.get(node.attr)


def _redirect_query_value(node, state):
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "get":
        return None
    query = node.func.value
    if not isinstance(query, ast.Attribute) or query.attr != "query":
        return None
    request = query.value
    return (
        "url"
        if isinstance(request, ast.Name) and request.id in state["requests"]
        else None
    )


def _redirect_child_statuses(node, state, api, aliases):
    return {
        value
        for child in ast.iter_child_nodes(node)
        if (value := _redirect_expression_state(child, state, api, aliases)) is not None
    }


def _redirect_is_sanitizer(node, state, api, aliases):
    if not isinstance(node, ast.Call) or len(node.args) != 3 or node.keywords:
        return False
    from .review_audits import security_call_name

    pattern, replacement, value = node.args
    return (
        security_call_name(node, aliases) == "re.sub"
        and bool(api["regex"])
        and isinstance(pattern, ast.Constant)
        and pattern.value == "^//+"
        and isinstance(replacement, ast.Constant)
        and replacement.value == "/"
        and _redirect_expression_state(value, state, api, aliases) == "path"
    )


def _redirect_apply_statement(statement, state, api, helpers, aliases):
    _redirect_record_append(statement, state, api, aliases)
    if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
        return []
    value = statement.value
    targets = (
        statement.targets if isinstance(statement, ast.Assign) else [statement.target]
    )
    names = _redirect_target_names(targets)
    call = value.value if isinstance(value, ast.Await) else value
    if _redirect_is_clone_helper_call(call, helpers):
        _redirect_invalidate_guards(names, state)
        summary = helpers[call.func.id]
        if summary is None:
            _redirect_mark_unknown_clone_result(targets, state)
        else:
            _redirect_apply_clone_call(call, targets, summary, state)
        return []
    _redirect_apply_assignment(value, targets, names, state, api, aliases)
    return []


def _redirect_apply_assignment(value, targets, names, state, api, aliases):
    _redirect_invalidate_guards(names, state)
    _redirect_transfer_request_aliases(value, names, state)
    status = (
        "safe"
        if _redirect_is_sanitizer(value, state, api, aliases)
        else _redirect_expression_state(value, state, api, aliases)
    )
    split_values = _redirect_split_values(value, targets, state, api, aliases)
    _redirect_store_values(names, status, split_values, value, state)


def _redirect_transfer_request_aliases(value, names, state):
    for name in names:
        state["requests"].discard(name)
    if isinstance(value, ast.Name) and value.id in state["requests"]:
        state["requests"].update(name for name in names if name != value.id)


def _redirect_store_values(names, status, split_values, value, state):
    for name in names:
        state["values"].pop(name, None)
        state["lists"].pop(name, None)
    if split_values:
        state["values"].update(split_values)
    elif isinstance(value, (ast.List, ast.Tuple)) and status is not None:
        for name in names:
            state["lists"][name] = status
    elif status is not None:
        for name in names:
            state["values"][name] = status


def _redirect_invalidate_guards(names, state):
    state["guarded"] = {
        request: binding
        for request, binding in state["guarded"].items()
        if request not in names and binding[0] not in names
    }


def _redirect_record_append(statement, state, api, aliases):
    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        return
    call = statement.value
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "append":
        return
    name = _name(call.func.value)
    status = (
        _redirect_expression_state(call.args[0], state, api, aliases)
        if call.args
        else None
    )
    if status is not None:
        state["lists"][name] = _redirect_merge_status(state["lists"].get(name), status)


def _redirect_is_clone_helper_call(call, helpers):
    return (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id in helpers
    )


def _redirect_mark_unknown_clone_result(targets, state):
    target = (
        targets[0]
        if len(targets) == 1 and isinstance(targets[0], (ast.Tuple, ast.List))
        else None
    )
    if target is None:
        return
    state["requests"].update(
        item.id for item in target.elts if isinstance(item, ast.Name)
    )


def _redirect_split_values(value, targets, state, api, aliases):
    if not _redirect_is_query_split(value, state, api, aliases):
        return {}
    target = (
        targets[0] if len(targets) == 1 and isinstance(targets[0], ast.Tuple) else None
    )
    if target is None or len(target.elts) != 2:
        return {}
    first, second = target.elts
    if not isinstance(first, ast.Name) or not isinstance(second, ast.Name):
        return {}
    return {first.id: "unsafe", second.id: "safe"}


def _redirect_is_query_split(value, state, api, aliases):
    if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Attribute):
        return False
    if value.func.attr != "split" or not value.args:
        return False
    delimiter = value.args[0]
    return (
        isinstance(delimiter, ast.Constant)
        and delimiter.value == "?"
        and _redirect_expression_state(value.func.value, state, api, aliases) == "path"
    )


def _redirect_apply_clone_call(call, targets, summary, state):
    _helper, path_index, path_name, tuple_index, success_index, return_safe = summary
    actual = _redirect_call_argument(call, path_index, path_name)
    status = state["values"].get(actual) if actual else None
    target = (
        targets[0]
        if len(targets) == 1 and isinstance(targets[0], (ast.Tuple, ast.List))
        else None
    )
    if target is None or tuple_index >= len(target.elts):
        return
    request_target = target.elts[tuple_index]
    success_target = target.elts[success_index]
    if not isinstance(request_target, ast.Name) or not isinstance(
        success_target, ast.Name
    ):
        return
    state["requests"].add(request_target.id)
    state["guarded"][request_target.id] = (
        success_target.id,
        status if return_safe else "unsafe",
    )


def _redirect_call_argument(call, index, name):
    if 0 <= index < len(call.args) and isinstance(call.args[index], ast.Name):
        return call.args[index].id
    keyword_value = next(
        (
            keyword.value.id
            for keyword in call.keywords
            if keyword.arg == name and isinstance(keyword.value, ast.Name)
        ),
        None,
    )
    if keyword_value is not None:
        return keyword_value
    return None


def _redirect_statement_sinks(relative, statement, state, sinks, api, function):
    from . import review_audits as audit

    findings = []
    for node in ast.walk(statement):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        imported_sink = node.func.id in api["redirects"]
        if not imported_sink and (
            node.func.id not in sinks or not isinstance(statement, ast.Raise)
        ):
            continue
        if not _redirect_sink_argument_unsafe(node, state, api):
            continue
        findings.append(
            audit._security_finding(
                "SECURITY_OPEN_REDIRECT",
                relative,
                node,
                "A request-derived path reaches an aiohttp redirect response without a proven leading-slash normalization.",
                "HIGH",
                cwe="CWE-601",
                source="aiohttp Request.raw_path",
                sink=node.func.id,
                flow="request clone helper and returned tuple slot",
            )
        )
    return findings


def _redirect_sink_argument_unsafe(call, state, api):
    values = [*call.args, *(keyword.value for keyword in call.keywords)]
    return any(
        _redirect_expression_state(value, state, api, {}) in {"path", "url", "unsafe"}
        for value in values
    )


def _redirect_merge_status(*values):
    if "url" in values:
        return "url"
    if set(values) & {"path", "unsafe"}:
        return "path"
    return "safe" if set(values) == {"safe"} else "unknown"


def _security_flow_bindings(node, aliases):
    """Read unconditional preceding bindings; uncertain branches invalidate them."""
    scope = getattr(node, "_security_lexical_scope", None) or getattr(
        node, "_oracle_scope", None
    )
    if scope is None:
        return dict(aliases), {}
    return _security_flow_scope_snapshots(scope, aliases).get(id(node), ({}, {}))


def _security_flow_scope_snapshots(scope, aliases):
    key = tuple(sorted(aliases.items()))
    cache = getattr(scope, "_security_flow_cache", {})
    if key not in cache:
        cache[key] = _security_flow_snapshots(scope, aliases)
        scope._security_flow_cache = cache
    return cache[key]


def _security_scope_body(scope):
    if isinstance(
        scope,
        (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
    ):
        return scope.body
    if isinstance(scope, ast.Lambda):
        return [scope.body]
    return []


def _security_module_scope(scope):
    pending = [scope]
    while pending:
        current = pending.pop()
        if isinstance(current, ast.Module):
            return current
        parent = getattr(current, "_security_parent_scope", None)
        if parent is not None:
            pending.append(parent)
        class_scope = getattr(current, "_security_class_scope", None)
        if class_scope is not None:
            pending.append(class_scope)
    return None


def _security_scope_initial(scope, aliases):
    if isinstance(scope, ast.Module):
        return {}, {}
    parent = getattr(scope, "_security_parent_scope", None)
    if parent is not None:
        _security_flow_scope_snapshots(parent, aliases)
    resolved, constants = _security_scope_base(scope, aliases)
    closure, shadowed = _security_scope_closure(scope)
    _security_remove_bindings(resolved, constants, shadowed)
    if closure is not None:
        resolved.update(closure[0])
        constants.update(closure[1])
    if getattr(scope, "_security_scope_kind", None) == "function":
        locals_ = (
            getattr(scope, "_security_local_names", set())
            | getattr(scope, "_security_parameter_names", set())
            | getattr(scope, "_security_nonlocal_names", set())
        )
        _security_remove_bindings(resolved, constants, locals_)
    return resolved, constants


def _security_scope_base(scope, aliases):
    if isinstance(scope, ast.ClassDef):
        seed = getattr(scope, "_security_scope_seed", ({}, {}))
        return dict(seed[0]), dict(seed[1])
    module = _security_module_scope(scope)
    if module is None:
        return {}, {}
    _security_flow_scope_snapshots(module, aliases)
    resolved, constants = getattr(module, "_security_flow_final", ({}, {}))
    return dict(resolved), dict(constants)


def _security_scope_closure(scope):
    closure = getattr(scope, "_security_closure_seed", None)
    closure_shadowed = getattr(scope, "_security_closure_shadowed", set())
    class_scope = getattr(scope, "_security_class_scope", None)
    if class_scope is not None:
        closure = getattr(class_scope, "_security_closure_seed", closure)
        closure_shadowed = getattr(
            class_scope, "_security_closure_shadowed", closure_shadowed
        )
    if closure is None and isinstance(scope, ast.ClassDef):
        closure = getattr(scope, "_security_scope_seed", None)
    return closure, closure_shadowed


def _security_remove_bindings(resolved, constants, names):
    for name in names:
        resolved.pop(name, None)
        constants.pop(name, None)


def _security_definition_seed(child, parent, resolved, constants, remaining):
    if isinstance(child, ast.ClassDef):
        child._security_scope_seed = (dict(resolved), dict(constants))
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            child._security_scope_shadowed = (
                set(getattr(parent, "_security_local_names", set()))
                | set(getattr(parent, "_security_parameter_names", set()))
                | set(getattr(parent, "_security_nonlocal_names", set()))
            )
        else:
            child._security_scope_shadowed = set()
    if not isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return
    from . import review_audits as audit

    stable_names = set(getattr(parent, "_security_local_names", set()))
    inherited_shadowed = set(getattr(parent, "_security_closure_shadowed", set()))
    stable_names.update(inherited_shadowed)
    shadowed_names = (
        stable_names
        | set(getattr(parent, "_security_parameter_names", set()))
        | set(getattr(parent, "_security_nonlocal_names", set()))
    )
    unstable = set(getattr(child, "_security_nonlocal_names", set()))
    for statement in remaining:
        unstable.update(audit._bound_names(statement))
    stable_names -= unstable
    child._security_closure_shadowed = shadowed_names
    child._security_closure_seed = (
        {name: resolved[name] for name in stable_names if name in resolved},
        {name: constants[name] for name in stable_names if name in constants},
    )


def _security_flow_snapshots(scope, aliases):
    from . import review_audits as audit

    resolved, constants = _security_scope_initial(scope, aliases)
    snapshots = {}
    body = _security_scope_body(scope)
    calls_by_statement = getattr(scope, "_security_calls_by_statement", {})
    for index, statement in enumerate(body):
        for call in calls_by_statement.get(id(statement), ()):
            snapshots[id(call)] = _security_flow_snapshot(call, resolved, constants)
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _security_definition_seed(
                statement, scope, resolved, constants, body[index + 1 :]
            )
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            resolved.update(audit._security_aliases([statement]))
            continue
        _security_flow_assignment(statement, resolved, constants)
    scope._security_flow_final = (dict(resolved), dict(constants))
    return snapshots


def _security_flow_snapshot(node, resolved, constants):
    from . import review_audits as audit

    head = audit._call_name(node).split(".", 1)[0]
    shell = next((kw.value for kw in node.keywords if kw.arg == "shell"), None)
    names = {shell.id} if isinstance(shell, ast.Name) else set()
    return (
        {head: resolved[head]} if head in resolved else {},
        {name: constants[name] for name in names if name in constants},
    )


def _security_flow_logger_factory_alias(value, resolved, call_name):
    if not isinstance(value, ast.Call):
        return None
    called = call_name(value.func)
    head, _, tail = called.partition(".")
    reference = resolved.get(head)
    if reference is None:
        return None
    factory = reference + ("." + tail if tail else "")
    return (
        "logging.Logger" if factory in {"logging.getLogger", "logging.Logger"} else None
    )


def _security_flow_assignment(statement, resolved, constants):
    from . import review_audits as audit

    value = getattr(statement, "value", None)
    if isinstance(statement, (ast.Global, ast.Nonlocal)):
        for name in statement.names:
            resolved.pop(name, None)
            constants.pop(name, None)
        return
    name = audit._name(value) if isinstance(value, ast.AST) else ""
    head, _, tail = name.partition(".")
    reference = resolved.get(head)
    alias = reference + ("." + tail if tail else "") if reference else None
    factory_alias = _security_flow_logger_factory_alias(value, resolved, audit._name)
    if factory_alias is not None:
        alias = factory_alias
    literal = value.value if isinstance(value, ast.Constant) else constants.get(name)
    bindings = audit._bound_names(statement)
    for binding in bindings:
        resolved.pop(binding, None)
        constants.pop(binding, None)
    if isinstance(statement, (ast.Assign, ast.AnnAssign)):
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
        )
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            if alias is not None:
                resolved[target.id] = alias
            if type(literal) is bool:
                constants[target.id] = literal


def security_call_name(node, aliases):
    """Resolve a call through preceding imports and stable local aliases.

    Calls whose names are shadowed in their lexical scope are left unresolved
    when their raw spelling would otherwise trigger a security diagnostic.
    """
    from . import review_audits as audit

    resolved, _constants = _security_flow_bindings(node, aliases)
    name = audit._call_name(node)
    head, _, tail = name.partition(".")
    if head in resolved:
        reference = resolved[head]
        if name == reference or name.startswith(reference + "."):
            return name
        return reference + ("." + tail if tail else "")
    if head in aliases:
        return ""
    if head in getattr(node, "_security_shadowed_names", set()):
        if audit._security_call_finding(name, "", node) is not None:
            return ""
    return name


def security_source_sink_findings(relative, tree, nodes, aliases):
    """Return bounded static findings for proven request and parameter sink flows."""
    from . import intent_quality

    bind_security_call_scopes(tree)
    token = intent_quality._SECURITY_REQUEST_ALIAS_MEMO.set(
        intent_quality._new_security_request_alias_memo(tree)
    )
    try:
        return _security_source_sink_findings_bound(relative, tree, nodes, aliases)
    finally:
        intent_quality._SECURITY_REQUEST_ALIAS_MEMO.reset(token)


def _security_source_sink_findings_bound(relative, tree, nodes, aliases):
    """Analyze one bound tree while its private alias memo is active."""
    from .audit_log_flow import audit_log_source_findings
    from .semantic_credential_sensor import security_precondition_providers_stable

    tree._security_precondition_providers_stable = (
        security_precondition_providers_stable(tree, aliases, nodes)
    )

    helpers = _security_connector_cursor_helpers(tree, aliases)
    findings = []
    scopes = [
        node
        for node in nodes
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    for scope in scopes:
        findings.extend(
            _security_scope_source_sink_findings(relative, scope, aliases, helpers)
        )
    findings.extend(audit_log_source_findings(relative, tree, nodes, aliases))
    return findings


def _security_connector_cursor_helpers(tree, aliases):
    from . import review_audits as audit

    helpers = {}
    for statement in tree.body:
        names = audit._bound_names(statement)
        for name in names:
            helpers.pop(name, None)
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            kind = _security_function_connector_return_kind(statement, aliases, helpers)
            if kind:
                helpers[statement.name] = kind
    return helpers


def _security_function_connector_return_kind(function, aliases, helpers):
    connections = set()
    cursors = set()
    for statement in function.body:
        kind = _security_return_kind(statement, aliases, helpers, connections, cursors)
        if kind:
            return kind
        _security_track_connector_assignment(
            statement, aliases, helpers, connections, cursors
        )
    return ""


def _security_return_kind(statement, aliases, helpers, connections, cursors):
    from .intent_quality import sql_return_kind

    return sql_return_kind(
        statement,
        aliases,
        helpers,
        connections,
        cursors,
        _security_sql_connection_driver,
        _security_sql_cursor_driver,
        _security_helper_call,
    )


def _security_track_connector_assignment(
    statement, aliases, helpers, connections, cursors
):
    from .intent_quality import track_sql_assignment

    track_sql_assignment(
        statement,
        aliases,
        helpers,
        connections,
        cursors,
        lambda value: _security_sql_connection_driver(value, aliases, connections),
        lambda value: _security_sql_cursor_driver(
            value, aliases, connections, cursors, helpers
        ),
        _security_helper_call,
    )


def _security_sql_connection_driver(node, aliases, connections):
    from .intent_quality import scoped_sql_connection_driver

    return scoped_sql_connection_driver(
        node, aliases, connections, _security_scope_request_aliases, security_call_name
    )


def _security_sql_cursor_driver(node, aliases, connections, cursors, helpers):
    from .intent_quality import scoped_sql_driver

    return scoped_sql_driver(
        node,
        aliases,
        connections,
        cursors,
        helpers,
        _security_scope_request_aliases,
        security_call_name,
        _security_helper_call,
        _security_call_leaf,
    )


def _security_helper_call(node, kind, aliases, helpers):
    if not isinstance(node, ast.Call):
        return False
    name = security_call_name(node, aliases)
    return helpers.get(name) == kind and _security_call_unshadowed(node, name)


def _security_call_leaf(node):
    return node.func.attr if isinstance(node.func, ast.Attribute) else ""


def _security_scope_source_sink_findings(relative, scope, aliases, helpers):
    states = tuple(set() for _ in range(5))
    states[2].update(getattr(scope, "_security_parameter_names", set()))
    return _security_analyze_source_sink_block(
        relative, scope.body, scope, aliases, *states, helpers
    )


def _security_analyze_source_sink_block(
    relative,
    body,
    scope,
    aliases,
    requests,
    password_fields,
    parameters,
    connection_names,
    cursor_names,
    helpers,
):
    findings = []
    flow = (requests, password_fields, parameters, connection_names, cursor_names)
    sink_flow = (requests, parameters, connection_names, cursor_names)
    for statement in body:
        value = getattr(statement, "test", getattr(statement, "value", None))
        password_finding = _security_password_comparison_finding(
            relative, value, password_fields, aliases, scope, statement
        )
        if password_finding is not None:
            findings.append(password_finding)
        from .intent_quality import sqlalchemy_with_findings

        with_findings = sqlalchemy_with_findings(
            statement,
            aliases,
            scope,
            connection_names,
            cursor_names,
            security_call_name,
            lambda statements: _security_analyze_source_sink_block(
                relative, statements, scope, aliases, *flow, helpers
            ),
        )
        if with_findings is not None:
            findings.extend(with_findings)
            continue
        if isinstance(statement, ast.If):
            findings.extend(
                _security_statement_call_findings(
                    relative, statement.test, scope, aliases, *sink_flow, helpers
                )
            )
            findings.extend(
                _security_branch_findings(
                    relative, statement, scope, aliases, *flow, helpers
                )
            )
            continue
        if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            findings.extend(
                _security_loop_findings(
                    relative, statement, scope, aliases, *flow, helpers
                )
            )
            continue
        if isinstance(
            statement,
            (
                ast.Assign,
                ast.AnnAssign,
                ast.AugAssign,
                ast.Expr,
                ast.Return,
                ast.Assert,
                ast.Raise,
            ),
        ):
            findings.extend(
                _security_statement_call_findings(
                    relative, statement, scope, aliases, *sink_flow, helpers
                )
            )
        if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            _security_flow_source_assignment(statement, aliases, *flow, helpers)
        elif not isinstance(statement, (ast.Expr, ast.Return, ast.Assert, ast.Raise)):
            from . import review_audits as audit

            bound = audit._bound_names(statement)
            for names in flow:
                names.difference_update(bound)
            _security_clear_upload_tags(requests, bound, password_fields)
    return findings


def _security_branch_findings(
    relative,
    statement,
    scope,
    aliases,
    requests,
    password_fields,
    parameters,
    connections,
    cursors,
    helpers,
):
    states = (requests, password_fields, parameters, connections, cursors)
    before = tuple(values.copy() for values in states)
    branches = []
    findings = []
    for body in (statement.body, statement.orelse):
        branch = [values.copy() for values in before]
        branches.append(branch)
        if body:
            findings.extend(
                _security_analyze_source_sink_block(
                    relative, body, scope, aliases, *branch, helpers
                )
            )
    _security_merge_branch_states(states, branches)
    return findings


def _security_merge_branch_states(target, branches):
    for index, values in enumerate(target):
        merged = set().union(*(branch[index] for branch in branches))
        if index == 0:
            safe = set.intersection(*(branch[index] for branch in branches))
            unsafe_safety = {
                item
                for item in merged
                if isinstance(item, tuple)
                and item[0]
                in {"secure-upload-leaf", "request-type:bytes", "request-type:text"}
            } - safe
            merged.difference_update(unsafe_safety)
        values.clear()
        values.update(merged)


def _security_loop_findings(
    relative,
    statement,
    scope,
    aliases,
    requests,
    password_fields,
    parameters,
    connections,
    cursors,
    helpers,
):
    states = (requests, password_fields, parameters, connections, cursors)
    before = tuple(values.copy() for values in states)
    test = (
        statement.iter
        if isinstance(statement, (ast.For, ast.AsyncFor))
        else statement.test
    )
    found = _security_statement_call_findings(
        relative,
        test,
        scope,
        aliases,
        requests,
        parameters,
        connections,
        cursors,
        helpers,
    )
    found.extend(
        _security_analyze_source_sink_block(
            relative, statement.body, scope, aliases, *states, helpers
        )
    )
    _security_merge_branch_states(
        states,
        [before, states],
    )
    return found


def _security_statement_call_findings(
    relative,
    statement,
    scope,
    aliases,
    requests,
    parameters,
    connections,
    cursors,
    helpers,
):
    findings = []
    for call in _lexical_nodes(statement):
        if (
            not isinstance(call, ast.Call)
            or getattr(call, "_security_lexical_scope", None) is not scope
        ):
            continue
        from .semantic_credential_sensor import (
            supported_security_precondition,
            security_precondition_call_shape,
            security_precondition_path_possible,
            request_payload_value_kind,
        )

        canonical = security_call_name(call, aliases)
        from . import review_audits as audit
        from .finite_capture import security_forward_helper_sources

        security_forward_helper_sources(relative, call, aliases, requests, helpers)

        primitive = audit._security_call_finding(canonical, relative, call)
        if (
            getattr(
                _security_module_scope(scope),
                "_security_precondition_providers_stable",
                False,
            )
            and primitive is not None
            and primitive["code"]
            in {
                "SECURITY_DYNAMIC_EXECUTION",
                "SECURITY_OS_COMMAND",
                "SECURITY_SHELL_COMMAND",
                "SECURITY_UNSAFE_DESERIALIZATION",
                "SECURITY_UNSAFE_YAML",
            }
            and call.args
            and security_precondition_call_shape(call, canonical)
            and security_precondition_path_possible(call)
            and _security_expr_tainted(call.args[0], requests, set(), aliases)
            and (
                canonical not in {"pickle.loads", "_pickle.loads", "dill.loads"}
                or request_payload_value_kind(
                    call.args[0], requests, aliases, _security_scope_request_aliases
                )
                == "bytes"
            )
        ):
            call._security_supported_precondition = supported_security_precondition(
                call, "untrusted_request", canonical
            )
            from .finite_capture import security_input_value_flow

            if trace := security_input_value_flow(call.args[0], requests, aliases):
                call._security_supported_precondition["input_value_flow"] = trace
        finding = _security_source_sink_call(
            relative, call, aliases, requests, parameters, connections, cursors, helpers
        )
        if finding is not None:
            findings.append(finding)
    return findings


def _security_source_sink_call(
    relative,
    call,
    aliases,
    requests,
    parameters,
    connection_names,
    cursor_names,
    helpers,
):
    from . import review_audits as audit

    name = security_call_name(call, aliases)
    if _security_unsafe_flask_file_save(call, aliases, requests):
        return audit._security_finding(
            "SECURITY_PATH_TRAVERSAL",
            relative,
            call,
            "An uploaded filename reaches Flask FileStorage.save without secure_filename sanitization.",
            "HIGH",
            call="flask.FileStorage.save",
        )
    if _security_unsafe_open(call, requests, aliases):
        return audit._security_finding(
            "SECURITY_PATH_TRAVERSAL",
            relative,
            call,
            "Request-derived path reaches open without a proven containment check.",
            "HIGH",
            call="open",
        )
    sql_driver = _security_unsafe_sql(
        call,
        name,
        parameters,
        requests,
        aliases,
        connection_names,
        cursor_names,
        helpers,
    )
    if sql_driver:
        from .intent_quality import sql_injection_finding

        return sql_injection_finding(
            audit._security_finding, relative, call, sql_driver
        )
    if _security_unsafe_request_url(call, name, requests, aliases):
        return audit._security_finding(
            "SECURITY_SSRF",
            relative,
            call,
            "Request-derived URL reaches a Requests outbound call without a parsed-host allowlist.",
            "HIGH",
            call=name,
        )
    return None


def _security_clear_upload_tags(
    requests, names, password_fields, statement=None, collection=False
):
    requests.difference_update(
        item
        for item in tuple(requests)
        if isinstance(item, tuple) and len(item) == 2 and item[1] in names
    )
    from .intent_quality import _track_credential_request_collection

    _track_credential_request_collection(names, statement, password_fields, collection)


def _security_unsafe_flask_file_save(call, aliases, requests):
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "save":
        return False
    receiver = call.func.value
    if not (
        isinstance(receiver, ast.Name) and ("flask-upload", receiver.id) in requests
    ):
        return False
    destination = (
        call.args[0]
        if call.args
        else next(
            (keyword.value for keyword in call.keywords if keyword.arg == "dst"), None
        )
    )
    return _security_upload_path_expression(
        destination,
        aliases,
        requests,
        getattr(call, "_security_lexical_scope", None),
        call,
    )


def _security_upload_path_expression(node, aliases, requests, scope, flow_statement):
    if isinstance(node, ast.Name):
        return ("upload-path", node.id) in requests
    if isinstance(node, ast.Attribute) and node.attr == "filename":
        return _security_flask_upload_expression(
            node.value, aliases, scope, flow_statement
        ) or (
            isinstance(node.value, ast.Name)
            and ("flask-upload", node.value.id) in requests
        )
    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(value, ast.FormattedValue)
            and _security_upload_path_expression(
                value.value, aliases, requests, scope, flow_statement
            )
            for value in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div)):
        return _security_upload_path_expression(
            node.left, aliases, requests, scope, flow_statement
        ) or _security_upload_path_expression(
            node.right, aliases, requests, scope, flow_statement
        )
    if not isinstance(node, ast.Call):
        return False
    if _security_is_proven_secure_filename(node, aliases):
        return False
    if security_call_name(node, aliases) in {
        "os.path.join",
        "pathlib.Path",
        "pathlib.PurePath",
    } and any(
        _security_expr_tainted(argument, requests, set(), aliases)
        and not (
            isinstance(argument, ast.Call)
            and _security_is_proven_secure_filename(argument, aliases)
        )
        and not (
            isinstance(argument, ast.Name)
            and ("secure-upload-leaf", argument.id) in requests
        )
        for argument in [*node.args, *(keyword.value for keyword in node.keywords)]
    ):
        return True
    return any(
        _security_upload_path_expression(
            argument, aliases, requests, scope, flow_statement
        )
        for argument in [*node.args, *(keyword.value for keyword in node.keywords)]
    )


def _security_is_proven_secure_filename(call, aliases):
    return _security_proven_callee(call, aliases, "werkzeug.utils.secure_filename")


def _security_proven_callee(call, aliases, expected):
    from .intent_quality import sanitizer_provider_unchanged

    return security_call_name(
        call, aliases
    ) == expected and sanitizer_provider_unchanged(
        call, aliases, expected, _security_module_scope
    )


def _security_flask_upload_expression(node, aliases, scope, flow_statement):
    from .intent_quality import flask_upload_expression

    return flask_upload_expression(
        node, aliases, scope, flow_statement, _security_flask_request_collection
    )


def _security_flask_request_collection(
    node, aliases, scope, flow_statement, collection
):
    from .intent_quality import flask_request_collection

    return flask_request_collection(
        node,
        aliases,
        scope,
        flow_statement,
        collection,
        _security_scope_request_aliases,
    )


def _security_unsafe_open(call, requests, aliases):
    from .intent_quality import unsafe_open

    return unsafe_open(
        call, requests, aliases, _security_expr_tainted, _security_proven_callee
    )


def _security_unsafe_sql(
    call, name, parameters, requests, aliases, connection_names, cursor_names, helpers
):
    from .intent_quality import scoped_unsafe_sql_driver

    return scoped_unsafe_sql_driver(
        call,
        requests,
        parameters,
        aliases,
        connection_names,
        cursor_names,
        _security_scope_request_aliases,
        security_call_name,
        helpers,
        _security_sql_cursor_driver,
        _security_helper_call,
        _security_expr_tainted,
    )


def _security_unsafe_request_url(call, name, tainted, aliases):
    from .intent_quality import unsafe_request_url

    return unsafe_request_url(
        call,
        name,
        tainted,
        aliases,
        _security_expr_tainted,
        _security_parsed_host_allowlist,
    )


def _security_parsed_host_allowlist(call, aliases):
    from .intent_quality import parsed_host_allowlist

    return parsed_host_allowlist(
        call, aliases, security_call_name, _security_proven_callee
    )


def _security_password_comparison_finding(
    relative, test, password_fields, aliases, scope=None, flow_statement=None
):
    from .intent_quality import password_comparison_finding

    return password_comparison_finding(
        relative,
        test,
        password_fields,
        aliases,
        scope,
        flow_statement,
        _security_password_source,
        _security_hardcoded_password_literal,
    )


def _security_hardcoded_password_literal(node):
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return False
    return bool(node.value.strip())


def _security_password_source(
    node, password_fields, aliases, scope=None, flow_statement=None
):
    if isinstance(node, ast.Name):
        return node.id in password_fields
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _security_password_source(
            node.left, password_fields, aliases, scope, flow_statement
        ) or _security_password_source(
            node.right, password_fields, aliases, scope, flow_statement
        )
    from .intent_quality import credential_password_request_value

    return credential_password_request_value(
        node,
        password_fields,
        aliases,
        scope,
        flow_statement,
        _security_request_args,
        _security_django_request_parameter,
    )


def _security_django_request_parameter(node, aliases, scope=None, flow_statement=None):
    from .intent_quality import django_request_parameter

    return django_request_parameter(
        node, aliases, scope, flow_statement, _security_scope_request_aliases
    )


def _security_expr_tainted(node, requests, parameters, aliases):
    if isinstance(node, ast.Name):
        return node.id in requests or node.id in parameters
    if isinstance(node, ast.Call):
        return _security_call_source_tainted(node, requests, parameters, aliases)
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        from .semantic_credential_sensor import http_request_payload

        return http_request_payload(
            node,
            aliases,
            getattr(node, "_security_lexical_scope", None),
            getattr(node, "_security_flow_statement", None),
            _security_scope_request_aliases,
        )
    if isinstance(node, ast.JoinedStr):
        return any(
            _security_expr_tainted(value.value, requests, parameters, aliases)
            for value in node.values
            if isinstance(value, ast.FormattedValue)
        )
    if isinstance(node, ast.FormattedValue):
        return _security_expr_tainted(node.value, requests, parameters, aliases)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div, ast.Mod)):
        return _security_expr_tainted(
            node.left, requests, parameters, aliases
        ) or _security_expr_tainted(node.right, requests, parameters, aliases)
    return False


def _security_call_source_tainted(node, requests, parameters, aliases):
    from .review_audits import _name
    from .semantic_credential_sensor import (
        http_request_payload,
        request_payload_value_kind,
    )

    name = security_call_name(node, aliases) if aliases else ""
    if (
        isinstance(node.func, ast.Attribute)
        and node.func.attr in {"decode", "encode"}
        and not node.args
        and not node.keywords
        and request_payload_value_kind(
            node, requests, aliases, _security_scope_request_aliases
        )
        is not None
    ):
        return True
    if http_request_payload(
        node,
        aliases,
        getattr(node, "_security_lexical_scope", None),
        getattr(node, "_security_flow_statement", None),
        _security_scope_request_aliases,
    ):
        return True
    if name in {"os.path.join", "pathlib.Path", "pathlib.PurePath"} or _name(
        node.func
    ).endswith("secure_filename"):
        return any(
            _security_expr_tainted(arg, requests, parameters, aliases)
            for arg in node.args
        )
    definition = _security_local_helper_definition(node)
    return definition is not None and _security_helper_return_tainted(
        node, definition, requests, parameters, aliases
    )


def _security_local_helper_definition(call):
    from . import review_audits as audit

    if not isinstance(call.func, ast.Name):
        return None
    name = call.func.id
    scope = current = getattr(call, "_security_lexical_scope", None)
    while scope is not None:
        bindings = {}
        for item in _security_scope_body(scope):
            if scope is current and item is call._security_flow_statement:
                break
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                bindings[item.name] = item
            else:
                bound = audit._bound_names(item)
                value = getattr(item, "value", None)
                targets = getattr(item, "targets", [getattr(item, "target", None)])
                alias = bindings.get(value.id) if isinstance(value, ast.Name) else None
                for bound_name in bound:
                    bindings[bound_name] = (
                        alias
                        if (
                            len(targets) == 1
                            and isinstance(targets[0], ast.Name)
                            and targets[0].id == bound_name
                        )
                        else None
                    )
        local = getattr(scope, "_security_local_names", set()) | getattr(
            scope, "_security_parameter_names", set()
        )
        if isinstance(scope, ast.Module):
            return bindings.get(name)
        if name in local:
            return bindings.get(name)
        if name in _security_scope_declared_names(scope, ast.Global):
            scope = _security_module_scope(scope)
        else:
            current, scope = scope, getattr(scope, "_security_parent_scope", None)
    return None


def _security_helper_return_tainted(call, function, requests, parameters, aliases):
    from .finite_capture import security_helper_return_tainted

    return security_helper_return_tainted(call, function, requests, parameters, aliases)


def _security_request_args(node, aliases, scope=None, flow_statement=None):
    return any(
        _security_flask_request_collection(node, aliases, scope, flow_statement, part)
        for part in ("args", "form")
    ) or _security_django_request_parameter(node, aliases, scope, flow_statement)


def _security_scope_request_aliases(scope, aliases, flow_statement=None):
    """Resolve scope bindings through the bounded per-scan SQL analysis helper."""
    from .intent_quality import _security_scope_request_aliases as resolve

    return resolve(scope, aliases, flow_statement)


def _security_apply_import_bindings(body, resolved, stop, audit):
    for statement in body:
        if statement is stop:
            break
        imported = audit._security_aliases([statement])
        for name in audit._bound_names(statement):
            resolved.pop(name, None)
            if name in imported:
                resolved[name] = imported[name]
    return resolved


def _security_flow_source_assignment(
    statement,
    aliases,
    requests,
    password_fields,
    parameters,
    connection_names,
    cursor_names,
    helpers,
):
    from . import review_audits as audit

    value = getattr(statement, "value", None)
    if isinstance(statement, ast.AugAssign):
        value = ast.BinOp(left=statement.target, op=statement.op, right=value)
    bindings = audit._bound_names(statement)
    scope = getattr(statement, "_security_lexical_scope", None)
    from . import intent_quality
    from .semantic_credential_sensor import request_payload_value_kind

    value_kind = request_payload_value_kind(
        value, requests, aliases, _security_scope_request_aliases
    )

    request_collection = intent_quality._credential_request_collection(
        value, password_fields, _security_request_args, aliases, scope, statement
    )
    flags = (
        isinstance(value, ast.AST)
        and _security_expr_tainted(value, requests, set(), aliases),
        isinstance(value, ast.AST)
        and _security_password_source(
            value,
            password_fields,
            aliases,
            getattr(statement, "_security_lexical_scope", None),
            statement,
        ),
        isinstance(value, ast.AST)
        and _security_expr_tainted(value, requests, parameters, aliases),
    )
    upload_object = isinstance(value, ast.AST) and (
        _security_flask_upload_expression(value, aliases, scope, statement)
        or (isinstance(value, ast.Name) and ("flask-upload", value.id) in requests)
    )
    upload_path = isinstance(value, ast.AST) and _security_upload_path_expression(
        value, aliases, requests, scope, statement
    )
    safe_upload_leaf = isinstance(
        value, ast.Call
    ) and _security_is_proven_secure_filename(value, aliases)
    known = (requests, password_fields, parameters, connection_names, cursor_names)
    for names in known:
        names.difference_update(bindings)
    intent_quality.track_sql_assignment(
        statement,
        aliases,
        helpers,
        connection_names,
        cursor_names,
        lambda value: _security_sql_connection_driver(value, aliases, connection_names),
        lambda value: _security_sql_cursor_driver(
            value, aliases, connection_names, cursor_names, helpers
        ),
        _security_helper_call,
    )
    _security_clear_upload_tags(
        requests, bindings, password_fields, statement, request_collection
    )
    _security_transfer_assignment_targets(
        statement,
        requests,
        value_kind,
        flags,
        known,
        (upload_object, upload_path, safe_upload_leaf),
    )


def _security_transfer_assignment_targets(
    statement, requests, value_kind, flags, known, upload_flags
):
    upload_object, upload_path, safe_upload_leaf = upload_flags
    targets = getattr(statement, "targets", None) or [statement.target]
    for target in targets:
        if isinstance(target, ast.Name):
            if value_kind is not None:
                requests.add(("request-type:" + value_kind, target.id))
            for tainted, names in zip(flags, known):
                if tainted:
                    names.add(target.id)
            if upload_object:
                requests.add(("flask-upload", target.id))
            if upload_path:
                requests.add(("upload-path", target.id))
            if safe_upload_leaf:
                requests.add(("secure-upload-leaf", target.id))


def _security_call_unshadowed(node, name):
    from .review_audits import _call_name

    raw = _call_name(node)
    head = raw.split(".", 1)[0]
    return head == name and head not in getattr(node, "_security_shadowed_names", set())


def shell_execution_enabled(node):
    """Return true only when shell execution is statically proven enabled."""
    from . import review_audits as audit

    shell = next((kw.value for kw in node.keywords if kw.arg == "shell"), None)
    if isinstance(shell, ast.Constant):
        return shell.value is True
    if not isinstance(shell, ast.Name):
        return False
    scope = getattr(node, "_security_lexical_scope", None)
    aliases = (
        audit._module_security_aliases(scope) if isinstance(scope, ast.Module) else {}
    )
    _resolved, constants = _security_flow_bindings(node, aliases)
    return constants.get(shell.id) is True


def runtime_finding_coverage(workspace, finding, row, schema, config_sources):
    """Keep incomplete callback and parameter-case evidence visible in findings."""
    from . import review_audits as audit

    unknown = finding["code"] == "QUALITY_UNKNOWN_TEST_ORACLE"
    if row is None or (unknown and schema != "factory.test-oracle-verification.v3"):
        return False
    if finding["code"] != "QUALITY_HOLLOW_TEST" and not unknown:
        return False
    loaded = _runtime_finding_node(workspace, row)
    if loaded is None:
        return False
    tree, node = loaded
    cases = row["baseline"]["case_ids"]
    parameterized = _runtime_test_is_parameterized(cases, node)
    from .runtime_attestation import (
        TEST_ORACLE_VERIFICATION_SCHEMA,
        TEST_ORACLE_VERIFICATION_SCHEMA_V2,
    )

    if not unknown and _runtime_completion_only_eligible(
        schema,
        finding.get("facts", {}).get("runtime_oracle_eligible"),
        parameterized,
        TEST_ORACLE_VERIFICATION_SCHEMA,
        TEST_ORACLE_VERIFICATION_SCHEMA_V2,
    ):
        return True
    qualname = cases[0].split("[", 1)[0].split("::", 1)[1].replace("::", ".")
    coverage = runtime_callback_coverage(
        node,
        row,
        verified_schema=schema,
        test_qualname=qualname,
        current_config_manifest={
            item["path"]: item["sha256"] for item in config_sources
        },
        strong_assertion=audit._strong_local_assertion,
        effective_assertion=audit._effective_assertion,
        aliases=audit._module_security_aliases(tree),
    )
    finding["facts"]["runtime_case_coverage"] = coverage
    return coverage["eligible"]


def _runtime_finding_node(workspace, row):
    from . import review_audits as audit

    try:
        raw = audit._security_source_bytes(workspace, row["path"])
        if hashlib.sha256(raw).hexdigest() != row["test_sha256"]:
            return None
        tree = ast.parse(raw)
        node = next(
            (
                item
                for item in ast.walk(tree)
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                and item.lineno == row["line"]
                and item.name == row["symbol"]
            ),
            None,
        )
    except (OSError, KeyError, SyntaxError, TypeError, ValueError):
        return None
    if node is None:
        return None
    return tree, node


def _runtime_test_is_parameterized(cases, node):
    return any("[" in case for case in cases) or any(
        "parametrize" in ast.unparse(decorator) for decorator in node.decorator_list
    )


def _runtime_completion_only_eligible(
    schema, eligible, parameterized, schema_v1, schema_v2
):
    if schema in {schema_v1, schema_v2} and eligible and not parameterized:
        return True
    return False


def weak_assertion_call_reason(node, aliases):
    """Explain weak assertion call shapes without changing their evidence class."""
    from . import review_audits as audit

    if builtin_repr_type_check(node):
        return "repr type check does not verify the expected representation"
    if audit._click_callback_oracle(node, aliases) == "weak":
        return "invoked command callback exposes only a weak assertion"
    leaf = audit._normalized_call_name(node, aliases).rsplit(".", 1)[-1]
    return _weak_assertion_leaf_reason(node, leaf, aliases, audit)


def _weak_assertion_leaf_reason(node, leaf, aliases, audit):
    if leaf == "assertIsNotNone" or (
        leaf == "assertIs"
        and len(node.args) == 2
        and any(
            isinstance(arg, ast.Constant) and arg.value is None for arg in node.args
        )
    ):
        return "non-null assertion does not verify the expected behavior"
    if leaf in {"assert_called", "assert_called_once"}:
        weak_mock = not audit._mock_argument_oracle(node, aliases)
    else:
        weak_mock = leaf == "assert_called_once_with" and audit._mock_self_check(node)
    if weak_mock:
        return "mock invocation state does not verify its result or arguments"
    return None


def builtin_repr_type_check(node):
    """Match a repr type-only oracle only when its names resolve to builtins."""
    if not _builtin_repr_is_call(node, "isinstance", 2) or _builtin_repr_names_shadowed(
        node
    ):
        return False
    rendered, expected_type = node.args
    return (
        _builtin_repr_is_call(rendered, "repr", 1)
        and isinstance(expected_type, ast.Name)
        and expected_type.id == "str"
    )


def _builtin_repr_is_call(node, name, argument_count):
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == name
        and len(node.args) == argument_count
        and not node.keywords
    )


def _builtin_repr_names_shadowed(node, names=None):
    from .review_audits import _scope_parameters

    builtin_names = names or {"isinstance", "repr", "str"}
    if builtin_names & set(getattr(node, "_security_shadowed_names", set())):
        return True
    scope = getattr(node, "_security_lexical_scope", None) or getattr(
        node, "_oracle_scope", None
    )
    if scope is None:
        return False
    scope_names = set(getattr(scope, "_security_local_names", set()))
    scope_names.update(_security_scope_local_names(scope))
    scope_names.update(getattr(scope, "_security_parameter_names", set()))
    scope_names.update(getattr(scope, "_security_nonlocal_names", set()))
    scope_names.update(_scope_parameters(scope))
    if builtin_names & scope_names:
        return True
    module = _security_module_scope(scope) or getattr(node, "_oracle_module", None)
    return bool(module and builtin_names & _security_scope_local_names(module))


def _completion_only_oracle(node: ast.AST) -> bool:
    """Runtime mutation evidence may credit calls, never ineffective assertions."""
    children = list(ast.walk(node))[1:]
    disallowed = (
        ast.Assert,
        ast.Raise,
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.Lambda,
    )
    if any(isinstance(child, disallowed) for child in children):
        return False
    calls = [child for child in children if isinstance(child, ast.Call)]
    return bool(calls) and not any(
        "assert" in ast.unparse(call.func).lower()
        or "fail" in ast.unparse(call.func).lower()
        for call in calls
    )


def discarded_assertion_error_findings(relative, function):
    """Identify an inert exception construction, without claiming its path ran."""
    from .review_audits import _body_nodes, _handler_reraises, _security_finding

    findings = []
    for handler in _body_nodes(ast.Module(body=function.body, type_ignores=[])):
        if not isinstance(handler, ast.ExceptHandler) or _handler_reraises(handler):
            continue
        for statement in handler.body:
            if not _discarded_builtin_assertion_error(statement):
                continue
            findings.append(
                _security_finding(
                    "QUALITY_WEAK_TEST_ORACLE",
                    relative,
                    statement,
                    "This handler constructs and discards AssertionError instead of raising it; if reached, this statement does not reject the behavior.",
                    "MEDIUM",
                    symbol=function.name,
                    reasons=["discarded AssertionError construction"],
                    evidence_scope="local_statement_semantics",
                    execution_state="NOT_ESTABLISHED",
                    whole_test_oracle="UNASSESSED",
                )
            )
    return findings


def _discarded_builtin_assertion_error(statement):
    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        return False
    call = statement.value
    if not (
        isinstance(call.func, ast.Name)
        and call.func.id == "AssertionError"
        and not call.keywords
        and len(call.args) <= 1
        and all(isinstance(arg, ast.Constant) for arg in call.args)
    ) or _builtin_repr_names_shadowed(call, {"AssertionError"}):
        return False
    module = _security_module_scope(getattr(call, "_security_lexical_scope", None))
    if module is None:
        return False
    # Dynamic or explicitly mutated builtin providers do not support this model.
    return not any(
        isinstance(item, ast.ImportFrom)
        and (item.module == "builtins" or any(a.name == "*" for a in item.names))
        or isinstance(item, ast.Import)
        and any(a.name == "builtins" for a in item.names)
        or isinstance(item, ast.Name)
        and item.id
        in {"__builtins__", "globals", "locals", "vars", "exec", "eval", "getattr"}
        or isinstance(item, ast.Attribute)
        and (
            item.attr
            in {
                "__dict__",
                "__globals__",
                "__builtins__",
                "__getattribute__",
                "setattr",
                "delattr",
                "getattr",
            }
            or item.attr == "AssertionError"
            and isinstance(item.ctx, (ast.Store, ast.Del))
        )
        or isinstance(item, ast.Call)
        and isinstance(item.func, ast.Name)
        and item.func.id in {"setattr", "delattr", "exec", "eval"}
        for item in ast.walk(module)
    )


def fixed_program_witness(relative, node, call_name):
    """Build a fixed-program witness through the shared primitive-observation validator."""
    import sys

    from .primitive_observation_binding import fixed_program_witness as witness

    return witness(sys.modules[__name__], relative, node, call_name)


def bind_fixed_program_workspace(
    root, contexts, snapshots, files, source_bytes=None, imports=None
):
    """Populate fixed-program workspace evidence through the shared source and consumer binders."""
    import sys

    from .primitive_observation_binding import (
        bind_fixed_program_workspace as bind_workspace,
    )

    return bind_workspace(
        sys.modules[__name__], root, contexts, snapshots, files, source_bytes, imports
    )


def fixed_program_workspace_helpers():
    """Expose the helper functions used to build fixed-program and credential-consumer workspace evidence."""
    import sys

    from .primitive_observation_binding import (
        fixed_program_workspace_helpers as workspace_helpers,
    )

    return workspace_helpers(sys.modules[__name__])


def _fixed_program_builtin_identity(node, module, call_name):
    import sys

    from .primitive_observation_binding import fixed_program_builtin_identity

    return fixed_program_builtin_identity(
        sys.modules[__name__], node, module, call_name
    )


def partition_proven_primitive_observations(core):
    """Keep proved fixed programs visible without describing them as defects."""
    import sys

    from .primitive_observation_binding import (
        partition_proven_primitive_observations as partition,
    )

    return partition(core, sys.modules[__name__])


def _fixed_primitive_binding(finding, sources, bindings, source_bytes=None):
    from .primitive_observation_binding import fixed_primitive_binding
    import sys

    return fixed_primitive_binding(
        finding, sources, bindings, sys.modules[__name__], source_bytes
    )


def bind_credential_consumers(
    root, snapshots, imports, contexts, source_bytes, *, inventory
):
    """Bind credential-consumer evidence through the shared provenance analyzer using this module as its audit context."""
    import sys
    from .provenance import bind_credential_consumers as bind

    return bind(
        sys.modules[__name__],
        root,
        snapshots,
        imports,
        contexts,
        source_bytes,
        inventory=inventory,
    )


def credential_consumer_helpers():
    """Expose the source-binding and evidence helpers required by credential-consumer analysis."""
    import sys
    from .provenance import credential_consumer_helpers as helpers

    return helpers(sys.modules[__name__])


def credential_context_cache_schema():
    """Return the credential-context cache schema version selected from the publication catalog."""
    from .primitive_observation_binding import credential_context_cache_schema as schema

    return schema()


def _closed_declaration_binding(finding):
    import sys

    from .primitive_observation_binding import closed_declaration_binding

    return closed_declaration_binding(finding, sys.modules[__name__])


def _valid_source_span(span):
    from .primitive_observation_binding import valid_source_span

    return valid_source_span(span)


def _finite_eval_binding(finding):
    import sys
    from .primitive_observation_binding import finite_eval_binding

    return finite_eval_binding(finding, sys.modules[__name__])
