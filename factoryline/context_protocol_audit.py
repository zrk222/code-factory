"""Source-bound protocol dispatch and its deterministic helper inventory."""

from __future__ import annotations

_PROTOCOL_EXTERNAL_BINDINGS = frozenset(
    "abc abc.ABC abc.ABCMeta contextlib contextlib.suppress typing typing.TYPE_CHECKING sys sys.version_info".split()
)


def protocol_call_context(
    root,
    files,
    snapshots,
    *,
    source_hashes=None,
    max_nodes=None,
    python_profile=None,
    import_resolver=None,
    eligible=None,
):
    """Describe captured repr dispatch; never grant an assertion or suppress a finding."""
    from .context_efficiency import (
        MAX_AST_NODES,
    )

    from . import review_audits as audit
    import sys

    limit = MAX_AST_NODES if max_nodes is None else max_nodes
    if (
        not isinstance(limit, int)
        or not 1 <= limit <= MAX_AST_NODES
        or len(snapshots) > 460
    ):
        return {}
    profile = (
        python_profile
        if python_profile is not None
        else {
            "implementation": sys.implementation.name,
            "version": ".".join(map(str, sys.version_info[:3])),
        }
    )
    state = {
        "root": root,
        "snapshots": snapshots,
        "eligible": {p.resolve(): p for p in files} if eligible is None else eligible,
        "import_resolver": audit._oracle_imports
        if import_resolver is None
        else import_resolver,
        "records": {},
        "limit": limit,
        "hashes": source_hashes,
        "profile": profile,
        "audit": audit,
    }
    result = {}
    for path in snapshots:
        relative = path.relative_to(root).as_posix()
        summary = _protocol_context_for_snapshot(path, state)
        if summary is not None:
            result[relative] = summary
    return result


def _protocol_context_for_snapshot(path, state):
    from .context_efficiency import (
        ast,
    )

    try:
        record = _protocol_source_record(path, state)
    except ValueError as exc:
        return dict(schema="factory.protocol-context.v1", summaries=[], gaps=[str(exc)])
    summaries = []
    for test in record["nodes"]:
        is_function = isinstance(test, (ast.FunctionDef, ast.AsyncFunctionDef))
        if not is_function or not test.name.startswith("test_"):
            continue
        test_nodes = list(ast.walk(test))
        state["active_test_nodes"] = (
            test,
            test_nodes,
            any(isinstance(node, (ast.Yield, ast.YieldFrom)) for node in test_nodes),
        )
        summaries.extend(
            summary
            for call in test_nodes
            if isinstance(call, ast.Call)
            if (
                summary := (
                    _protocol_call_summary
                    if isinstance(call.func, ast.Name) and call.func.id == "repr"
                    else _protocol_demand_summary
                )(path, test, call, state)
            )
            is not None
        )
    if not summaries:
        return None
    return dict(schema="factory.protocol-context.v1", summaries=summaries, gaps=[])


def _protocol_source_record(path, state):
    """Reuse producer trees and the established import resolver without another parser."""
    from .context_efficiency import (
        _ast_parent_map,
        _bounded_ast_nodes,
        _is_sha256,
        _require,
        ast,
    )

    if path in state["records"]:
        return state["records"][path]
    tree = state["snapshots"].get(path)
    _require(isinstance(tree, ast.Module), "SOURCE_UNAVAILABLE")
    nodes = _bounded_ast_nodes(tree)
    _require(not (nodes is None or len(nodes) > state["limit"]), "AST_NODE_LIMIT")
    source_sha = getattr(tree, "_oracle_source_sha256", None)
    _require(_is_sha256(source_sha), "SOURCE_IDENTITY_MISSING")
    expected = state["hashes"]
    if (
        expected is not None
        and expected.get(path, expected.get(path.relative_to(state["root"]).as_posix()))
        != source_sha
    ):
        raise ValueError("SOURCE_IDENTITY_DRIFT")
    record = {
        "tree": tree,
        "nodes": nodes,
        "parents": _ast_parent_map(nodes),
        "sha256": source_sha,
        "imports": state["import_resolver"](
            state["root"], path, tree, state["eligible"]
        ),
    }
    state["records"][path] = record
    return record


def _protocol_dependency(path, node, role, state):
    from .context_efficiency import (
        ast,
        hashlib,
    )

    record = _protocol_source_record(path, state)
    return {
        "source": path.relative_to(state["root"]).as_posix(),
        "sha256": record["sha256"],
        "ast_sha256": hashlib.sha256(
            ast.dump(node, include_attributes=True).encode()
        ).hexdigest(),
        "symbol": getattr(node, "name", "<module>"),
        "line": getattr(node, "lineno", 1),
        "end_line": getattr(node, "end_lineno", None),
        "role": role,
    }


def _protocol_call_summary(path, test, call, state):
    from .context_efficiency import (
        ast,
        deepcopy,
    )

    summary = {
        "status": "UNKNOWN",
        "python_profile": deepcopy(state["profile"]),
        "protocol": "builtins.repr",
        "test": test.name,
        "line": call.lineno,
        "column": call.col_offset,
        "output_checked": False,
        "runtime_observed": False,
        "conditional_on_successful_construction": True,
        "conditional_on_unchanged_dispatch": True,
        "dependencies": [],
        "assumptions": [],
        "unresolved_effects": [
            "CONSTRUCTOR_SUCCESS_AND_EFFECTS_NOT_VERIFIED",
            "CLASS_BODY_EFFECTS_NOT_VERIFIED",
            "NESTED_FORMAT_PROTOCOLS_NOT_VERIFIED",
        ],
        "unknown_reasons": [],
    }
    state["constructor_effect_dependencies"] = []
    state["receiver_safe_calls"] = set()
    try:
        summary["dependencies"].append(_protocol_dependency(path, test, "test", state))
        _protocol_reachable_repr(path, test, call, state)
        receiver = call.args[0]
        target = _protocol_class_reference(receiver.func, path, test, state)
        if (
            not isinstance(target, tuple)
            or len(target) != 2
            or not isinstance(target[1], ast.ClassDef)
        ):
            raise ValueError("RECEIVER_CLASS_UNRESOLVED")
        declaration_parent = _protocol_source_record(target[0], state)["parents"].get(
            id(target[1])
        )
        if declaration_parent is test and target[1].lineno >= call.lineno:
            raise ValueError("LOCAL_CLASS_NOT_YET_DECLARED")
        chain, assumptions = _protocol_class_chain(target, state)
        summary["assumptions"].extend(assumptions)
        summary["dependencies"].extend(
            _protocol_dependency(p, cls, "receiver_class", state) for p, cls in chain
        )
        method_path, method = _protocol_repr_method(chain)
        summary["dependencies"].append(
            _protocol_dependency(method_path, method, "protocol_method", state)
        )
        summary["receiver"] = {
            "source": target[0].relative_to(state["root"]).as_posix(),
            "class": target[1].name,
            "allocation_line": receiver.lineno,
        }
        summary["method_decorators"] = [
            ast.unparse(item) for item in method.decorator_list
        ]
        decorators = _protocol_validate_repr_method(method_path, method, state)
        summary["dependencies"].extend(
            _protocol_dependency(p, fn, "identity_decorator", state)
            for p, fn in decorators
        )
        if decorators:
            summary["assumptions"].append(
                {
                    "contract": "source.metadata-identity-transfer.v1",
                    "profile": deepcopy(state["profile"]),
                    "boundary": "Supported source shape returns the exact input with only boolean __override__/__final__ writes; typing.TYPE_CHECKING is false at runtime; standard contextlib.suppress handles only AttributeError/TypeError. No runtime purity is proved.",
                }
            )
        _protocol_dependencies_closed(path, test, [*chain, *decorators], state)
        summary.update(
            status="WEAK_PROTOCOL",
            builtin_identity="unshadowed builtins.repr",
            dispatch="source lookup conditional on unchanged bindings across construction",
            exception_edge="propagates from direct statement if construction and dispatch execute",
        )
    except ValueError as exc:
        summary["unknown_reasons"].append(str(exc.args[0]))
        if len(exc.args) > 1:
            summary["blocking_evidence"] = exc.args[1]
    summary["dependencies"].extend(state["constructor_effect_dependencies"])
    return summary


def _protocol_reachable_repr(path, test, call, state):
    from .context_efficiency import (
        ast,
    )

    preceding = _protocol_reachable_call(path, test, call, state)
    _protocol_builtin_unshadowed(path, test, state)
    if len(call.args) != 1 or call.keywords or not isinstance(call.args[0], ast.Call):
        raise ValueError("RECEIVER_NOT_DIRECT_ALLOCATION")
    for statement in preceding:
        if not _protocol_preceding_statement(statement):
            raise ValueError("PRECEDING_CONTROL_OR_EFFECT_UNKNOWN")
    if call.args[0].args or call.args[0].keywords:
        raise ValueError("DYNAMIC_CONSTRUCTOR_ARGUMENTS")


def _protocol_preceding_statement(statement):
    from .context_efficiency import (
        ast,
    )

    if isinstance(statement, (ast.ClassDef, ast.Import, ast.ImportFrom)):
        return True
    if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
        return True
    return isinstance(statement, (ast.Assign, ast.AnnAssign)) and isinstance(
        statement.value, ast.Constant
    )


def _protocol_class_reference(expression, path, scope, state, depth=0):
    """Resolve only direct captured imports, class declarations and dotted members."""
    from .context_efficiency import (
        _require,
        ast,
    )

    _require(not depth >= 16, "REFERENCE_DEPTH_LIMIT")
    if isinstance(expression, ast.Attribute):
        parent = _protocol_class_reference(
            expression.value, path, scope, state, depth + 1
        )
        if (
            parent in {"abc", "contextlib", "typing", "sys"}
            if isinstance(parent, str)
            else False
        ):
            return parent + "." + expression.attr
        if isinstance(parent, tuple) and parent[1] is None:
            return _protocol_class_name(expression.attr, parent[0], None, state)
        if isinstance(parent, tuple):
            return (*parent, expression.attr)
        raise ValueError("DYNAMIC_MEMBER_REFERENCE")
    _require(isinstance(expression, ast.Name), "DYNAMIC_CLASS_REFERENCE")
    return _protocol_class_name(expression.id, path, scope, state)


def _protocol_class_name(name, path, scope, state, visited=()):
    from .context_efficiency import (
        _require,
        ast,
    )

    if (path, name) in visited or len(visited) >= 16:
        raise ValueError("IMPORT_REFERENCE_CYCLE_OR_DEPTH_LIMIT")
    visited = (*visited, (path, name))
    audit = state["audit"]
    record = _protocol_source_record(path, state)
    local = _protocol_local_class(name, scope, state)
    if local is not None:
        return path, local
    bound = [n for n in record["tree"].body if name in audit._bound_names(n)]
    if not bound and name == "object":
        return "builtins.object"
    if len(bound) != 1 or isinstance(bound[0], ast.If):
        bound = [_protocol_active_binding(name, path, state)]
    if isinstance(bound[0], (ast.ClassDef, ast.FunctionDef)):
        return path, bound[0]
    resolved = audit._module_security_aliases(record["tree"]).get(name)
    if resolved in _PROTOCOL_EXTERNAL_BINDINGS:
        return resolved
    imported = record["imports"].get(name)
    _require(imported is not None, "IMPORT_SOURCE_UNAVAILABLE")
    source, symbol = imported
    if (
        symbol is None
        or symbol == source.stem
        or (source.name == "__init__.py" and symbol == source.parent.name)
    ):
        return source, None
    return _protocol_class_name(symbol, source, None, state, visited)


def _protocol_class_chain(target, state):
    from .context_efficiency import (
        _require,
        ast,
    )

    chain, assumptions, visited = [], [], set()
    while (
        isinstance(target, tuple)
        and len(target) == 2
        and isinstance(target[1], ast.ClassDef)
    ):
        path, cls = target
        key = path, id(cls)
        if key in visited or len(chain) >= 16:
            raise ValueError("INHERITANCE_CYCLE_OR_DEPTH_LIMIT")
        visited.add(key)
        _protocol_class_shape(cls)
        chain.append(target)
        if not cls.bases:
            return chain, assumptions
        _require(not len(cls.bases) != 1, "MULTIPLE_OR_DYNAMIC_BASES")
        parent = _protocol_source_record(path, state)["parents"].get(id(cls))
        scope = parent if isinstance(parent, ast.FunctionDef) else None
        target = _protocol_class_reference(cls.bases[0], path, scope, state)
    if target == "builtins.object":
        return chain, assumptions
    if target == "abc.ABC":
        if state["profile"] != {"implementation": "cpython", "version": "3.11.9"}:
            raise ValueError("ABC_PROFILE_UNSUPPORTED")
        assumptions.append(
            {
                "contract": "stdlib.abc-transparent-method-lookup.cpython-3.11.9.v1",
                "profile": state["profile"],
                "boundary": "Unmodified imported abc.ABC and inherited ABCMeta are transparent only for method lookup; constructor success, hooks, purity and runtime execution are not proved.",
            }
        )
        return chain, assumptions
    raise ValueError("EXTERNAL_OR_DYNAMIC_BASE")


def _protocol_class_shape(cls):
    from .context_efficiency import (
        _require,
        _scope_has_reflective_capability_access,
        ast,
    )

    constructors = [n for n in cls.body if "__init__" in _protocol_class_bound_names(n)]
    if any(not isinstance(n, ast.FunctionDef) for n in constructors):
        raise ValueError("CONSTRUCTOR_BINDING_UNRESOLVED")
    if any(isinstance(n, (ast.If, ast.Try, ast.For, ast.With)) for n in cls.body):
        raise ValueError("DYNAMIC_CLASS_BODY")
    _require(not (cls.decorator_list or cls.keywords), "CLASS_DECORATOR_OR_METACLASS")
    hooks = set(
        "__new__ __getattr__ __getattribute__ __init_subclass__ __mro_entries__ __setattr__ __delattr__".split()
    )
    if any(hooks.intersection(_protocol_class_bound_names(n)) for n in cls.body):
        raise ValueError("DYNAMIC_CLASS_HOOK")
    for method in constructors:
        _require(not method.decorator_list, "DYNAMIC_CONSTRUCTOR_DECORATOR")
        _protocol_constructor_receiver_safe(method)
        nodes = list(ast.walk(method))
        if isinstance(
            method, ast.AsyncFunctionDef
        ) or _scope_has_reflective_capability_access(nodes):
            raise ValueError("DYNAMIC_CONSTRUCTOR_EFFECTS")
        if any(
            isinstance(n, ast.Attribute)
            and isinstance(n.ctx, (ast.Store, ast.Del))
            and n.attr in {"__class__", "__repr__", "__dict__", "__bases__"}
            for n in nodes
        ):
            raise ValueError("CONSTRUCTOR_TYPE_OR_METHOD_MUTATION")


def _protocol_repr_method(chain, name="__repr__"):
    from .context_efficiency import (
        ast,
    )

    for path, cls in chain:
        bound = [n for n in cls.body if name in _protocol_class_bound_names(n)]
        if not bound:
            continue
        if len(bound) != 1 or not isinstance(bound[0], ast.FunctionDef):
            raise ValueError("PROTOCOL_METHOD_BINDING_AMBIGUOUS")
        return path, bound[0]
    raise ValueError("CONSTANT_OR_DEFAULT_REPRESENTATION")


def _protocol_validate_repr_method(path, method, state):
    from .context_efficiency import (
        _async_runner_docstring,
        ast,
    )

    decorators = [
        _protocol_identity_decorator(item, path, state)
        for item in method.decorator_list
    ]
    body = method.body[1:] if _async_runner_docstring(method.body) else method.body
    if len(body) != 1 or not isinstance(body[0], ast.Return) or not method.args.args:
        raise ValueError("PROTOCOL_BODY_UNSUPPORTED")
    receiver = method.args.args[0].arg
    nodes = list(ast.walk(body[0].value))
    if not any(
        isinstance(n, ast.Attribute)
        and isinstance(n.value, ast.Name)
        and n.value.id == receiver
        and isinstance(n.ctx, ast.Load)
        for n in nodes
    ):
        raise ValueError("CONSTANT_OR_DEFAULT_REPRESENTATION")
    deferred = tuple(
        getattr(ast, kind)
        for kind in "Yield YieldFrom Await Lambda IfExp BoolOp GeneratorExp".split()
    )
    if any(isinstance(n, deferred) for n in nodes):
        raise ValueError("DEFERRED_OR_CONDITIONAL_PROTOCOL_BODY")
    return decorators


def _protocol_class_bound_names(node):
    from . import review_audits as audit

    return audit._bound_names(node)


def _protocol_executed_nodes(tree, test, state):
    """Walk definition-time effects and this test, excluding deferred bodies."""
    from .context_efficiency import (
        ast,
    )

    pending, nodes = [*tree.body, *(test.body if test is not None else ())], []
    while pending:
        node = pending.pop()
        nodes.append(node)
        children = ast.iter_child_nodes(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            body = node.body if isinstance(node.body, list) else [node.body]
            children = (child for child in children if child not in body)
        pending.extend(children)
    return nodes


def _protocol_dependencies_closed(path, test, chain, state):
    from .context_efficiency import (
        _module_has_dynamic_capability_access,
        ast,
    )

    targets = {(p, id(cls)) for p, cls in chain}
    paths = {p for p, _ in chain} | {path}
    for source in sorted(paths):
        record = _protocol_source_record(source, state)
        scope = test if source == path else None
        nodes = _protocol_executed_nodes(record["tree"], scope, state)
        if _module_has_dynamic_capability_access(nodes) or any(
            isinstance(n, ast.Attribute) and n.attr in {"__annotations__", "__dict__"}
            for n in nodes
        ):
            raise ValueError("REFLECTIVE_DEPENDENCY_EFFECTS")
        _protocol_builtin_repr_closed(source, nodes, state)
        _protocol_closed_nodes(source, scope, nodes, targets, paths, state)
        for owner, cls in chain:
            if owner == source:
                _protocol_constructor_bindings_closed(
                    source, cls, targets, paths, state
                )


def _protocol_closed_nodes(path, scope, nodes, targets, paths, state):
    from .context_efficiency import (
        ast,
    )

    record = _protocol_source_record(path, state)
    parents = record["parents"]
    for node in nodes:
        if not isinstance(node, (ast.Name, ast.Attribute)):
            continue
        try:
            target = _protocol_class_reference(node, path, scope, state)
        except ValueError:
            continue
        if not _protocol_target_relevant(target, targets, paths):
            continue
        parent = parents.get(id(node))
        if (
            target == "typing.TYPE_CHECKING"
            and isinstance(parent, ast.If)
            and parent.test is node
        ):
            continue
        if target == "sys.version_info" and isinstance(parent, ast.Compare):
            _protocol_profile_truth(parent, record, state)
            continue
        if not isinstance(node.ctx, ast.Load) or not _protocol_reference_use_closed(
            node, parent
        ):
            raise ValueError(
                "DEPENDENCY_MUTATION_OR_ALIAS_ESCAPE",
                {
                    "source": path.relative_to(state["root"]).as_posix(),
                    "line": getattr(node, "lineno", None),
                    "reference": ast.unparse(node),
                    "parent": type(parent).__name__,
                },
            )
        if isinstance(parent, ast.Attribute) and parent.attr in {
            "__dict__",
            "__class__",
            "__mro__",
            "__bases__",
            "__subclasses__",
            "__setattr__",
            "__delattr__",
        }:
            raise ValueError("REFLECTIVE_DEPENDENCY_ACCESS")


def _protocol_target_relevant(target, targets, paths):
    if isinstance(target, str):
        return target in _PROTOCOL_EXTERNAL_BINDINGS
    if not isinstance(target, tuple):
        return False
    return (
        target[0] in paths
        if target[1] is None
        else (target[0], id(target[1])) in targets
    )


def _protocol_reference_use_closed(node, parent):
    from .context_efficiency import (
        ast,
    )

    match parent:
        case ast.arg(annotation=annotation) | ast.AnnAssign(annotation=annotation):
            return annotation is node
        case (
            ast.FunctionDef(returns=returns, decorator_list=decorators)
            | ast.AsyncFunctionDef(returns=returns, decorator_list=decorators)
        ):
            return returns is node or node in decorators
        case ast.Attribute(value=value, ctx=ctx):
            return value is node and isinstance(ctx, ast.Load)
        case ast.Call(func=func):
            return func is node
        case ast.ClassDef(bases=bases, keywords=[], decorator_list=[]):
            return node in bases
    return False


def _protocol_constructor_receiver_safe(method):
    from .context_efficiency import (
        _ast_parent_map,
        _require,
        ast,
    )

    _require(method.args.args, "CONSTRUCTOR_RECEIVER_UNKNOWN")
    receiver = method.args.args[0].arg
    nodes = list(ast.walk(method))
    parents = _ast_parent_map(nodes)
    safe = {
        n.func.value.value
        for n in nodes
        if isinstance(n, ast.Call) and _protocol_fresh_list_append(n, method)
    }
    for node in nodes:
        if node in safe:
            continue
        if isinstance(node, (ast.Yield, ast.YieldFrom, ast.Raise)):
            raise ValueError("CONSTRUCTOR_COMPLETION_UNKNOWN")
        if isinstance(node, ast.Name) and node.id == receiver:
            parent = parents.get(id(node))
            if not isinstance(parent, ast.Attribute) or not isinstance(
                parent.ctx, ast.Store
            ):
                raise ValueError("CONSTRUCTOR_RECEIVER_ESCAPE_OR_DYNAMIC_CALL")


def _protocol_builtin_repr_closed(path, nodes, state):
    from .context_efficiency import (
        ast,
    )

    audit = state["audit"]
    record = _protocol_source_record(path, state)
    aliases = audit._module_security_aliases(record["tree"])
    for node in nodes:
        if (
            isinstance(node, (ast.Name, ast.Attribute))
            and audit._resolved_ast_name(node, aliases) == "builtins.repr"
        ):
            parent = record["parents"].get(id(node))
            if not isinstance(parent, ast.Call) or parent.func is not node:
                raise ValueError("BUILTIN_REPR_MUTATED_OR_ESCAPED")


def _protocol_builtin_unshadowed(path, test, state, name="repr"):
    from .context_efficiency import (
        _scope_has_reflective_capability_access,
        ast,
    )

    audit = state["audit"]
    if audit._scope_binds_name(test, name) or name in audit._scope_parameters(test):
        raise ValueError("BUILTIN_SHADOWED")
    record = _protocol_source_record(path, state)
    if any(name in audit._bound_names(s) for s in record["tree"].body):
        raise ValueError("BUILTIN_SHADOWED")
    active = state.get("active_test_nodes")
    nodes = active[1] if active and active[0] is test else list(ast.walk(test))
    if _scope_has_reflective_capability_access(nodes):
        raise ValueError("REFLECTIVE_TEST_EFFECTS")


def _protocol_local_class(name, scope, state):
    from .context_efficiency import (
        _require,
        ast,
    )

    if scope is None:
        return None
    audit = state["audit"]
    local = [n for n in scope.body if isinstance(n, ast.ClassDef) and n.name == name]
    bound = [n for n in scope.body if name in audit._bound_names(n)]
    _require(name not in audit._scope_parameters(scope), "CONSTRUCTOR_PARAMETER_SHADOW")
    if not bound:
        return None
    if len(bound) == len(local) == 1:
        return local[0]
    raise ValueError("CONSTRUCTOR_LOCAL_REBINDING")


def _protocol_constructor_bindings_closed(
    path, cls, targets, paths, state, functions=()
):
    from .context_efficiency import (
        _scope_has_reflective_capability_access,
        ast,
    )

    pending = [
        (path, n)
        for n in cls.body
        if isinstance(n, ast.FunctionDef) and n.name == "__init__"
    ]
    pending.extend(functions)
    visited = set()
    while pending:
        source, function = pending.pop()
        key = source, id(function)
        if key in visited or len(visited) >= 16:
            raise ValueError("CONSTRUCTOR_EFFECT_GRAPH_LIMIT_OR_CYCLE")
        visited.add(key)
        nodes = [n for stmt in function.body for n in ast.walk(stmt)]
        state["constructor_effect_dependencies"].append(
            _protocol_dependency(source, function, "constructor_effect", state)
        )
        if any(
            isinstance(n, (ast.Import, ast.ImportFrom, ast.Yield, ast.YieldFrom))
            for n in nodes
        ) or _scope_has_reflective_capability_access(nodes):
            raise ValueError("CONSTRUCTOR_EFFECT_UNRESOLVED")
        _protocol_closed_nodes(source, function, nodes, targets, paths, state)
        for call in (n for n in nodes if isinstance(n, ast.Call)):
            pending.extend(_protocol_constructor_callee(call, source, function, state))


def _protocol_constructor_callee(call, path, scope, state):
    from .context_efficiency import (
        _leftmost_name,
        ast,
    )

    audit = state["audit"]
    module = _protocol_source_record(path, state)["tree"]
    if isinstance(call.func, ast.Name) and call.func.id == "super":
        if (
            "super" in audit._scope_parameters(scope)
            or audit._scope_binds_name(scope, "super")
            or any("super" in audit._bound_names(n) for n in module.body)
        ):
            raise ValueError("CONSTRUCTOR_SUPER_SHADOWED")
        return ()
    if (
        call in state.get("receiver_safe_calls", ())
        or _protocol_fresh_list_append(call, scope)
        or (
            isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Call)
            and isinstance(call.func.value.func, ast.Name)
            and call.func.value.func.id == "super"
        )
    ):
        return ()
    try:
        target = _protocol_class_reference(call.func, path, scope, state)
    except ValueError as exc:
        if str(exc) != "IMPORT_SOURCE_UNAVAILABLE":
            raise
        root = _leftmost_name(call.func)
        origin = _protocol_active_binding(root.id, path, state)
        if isinstance(origin, (ast.Import, ast.ImportFrom)):
            return ()  # Unresolved imports require the unchanged-dispatch condition.
        raise ValueError("CONSTRUCTOR_CALLEE_EFFECT_UNKNOWN") from None
    if isinstance(target, tuple) and len(target) == 2:
        source, node = target
        if isinstance(node, ast.FunctionDef):
            return [target]
        if isinstance(node, ast.ClassDef):
            chain, _ = _protocol_class_chain(target, state)
            state["constructor_effect_dependencies"].extend(
                _protocol_dependency(p, cls, "constructor_effect_class", state)
                for p, cls in chain
            )
            return [
                (p, fn)
                for p, cls in chain
                for fn in cls.body
                if isinstance(fn, ast.FunctionDef) and fn.name == "__init__"
            ]

    raise ValueError("CONSTRUCTOR_CALLEE_EFFECT_UNKNOWN")


def protocol_call_helpers():
    """Bind the producer, deterministic local helper inventory, and inventory code."""
    from .context_efficiency import (
        _capability_reflection_names,
        _require,
    )

    from .review_integrity import source_binding_helpers
    from .context_efficiency import protocol_call_context
    from . import test_oracle_misuse as oracle

    helpers = tuple(
        fn
        for name, fn in sorted(globals().items())
        if name.startswith("_protocol_") and callable(fn)
    )
    return (
        protocol_call_context,
        protocol_call_helpers,
        _capability_reflection_names,
        _require,
        *helpers,
        *(
            getattr(oracle, name)
            for name in (
                "_protocol_chain_bindings",
                "_protocol_demand_summary",
                "_protocol_demand_target",
                "_protocol_demand_visit",
                "_protocol_fresh_list_append",
                "_protocol_receiver_transfer",
            )
        ),
        *source_binding_helpers(),
    )


def _protocol_active_binding(name, path, state):
    from .context_efficiency import (
        _require,
        ast,
    )

    record = _protocol_source_record(path, state)
    pending, matches = list(record["tree"].body), []
    while pending:
        node = pending.pop()
        if isinstance(node, ast.If):
            relevant = any(
                name in _protocol_class_bound_names(n)
                for n in (*node.body, *node.orelse)
            )
            if relevant:
                selected = _protocol_profile_truth(node.test, record, state)
                pending.extend(node.body if selected else node.orelse)
        elif name in _protocol_class_bound_names(node):
            matches.append(node)
    _require(not len(matches) != 1, "PROFILE_BINDING_AMBIGUOUS")
    return matches[0]


def _protocol_profile_truth(test, record, state):
    from .context_efficiency import (
        ast,
    )

    audit = state["audit"]
    aliases = audit._module_security_aliases(record["tree"])
    if audit._resolved_ast_name(test, aliases) == "typing.TYPE_CHECKING":
        return False
    if (
        isinstance(test, ast.Compare)
        and len(test.ops) == len(test.comparators) == 1
        and audit._resolved_ast_name(test.left, aliases) == "sys.version_info"
    ):
        comparator = test.comparators[0]
        if isinstance(comparator, ast.Tuple) and all(
            isinstance(n, ast.Constant) and type(n.value) is int
            for n in comparator.elts
        ):
            if state["profile"] != {"implementation": "cpython", "version": "3.11.9"}:
                raise ValueError("DECORATOR_PROFILE_UNSUPPORTED")
            version, bound = (3, 11, 9), tuple(n.value for n in comparator.elts)
            operations = {ast.GtE: version >= bound, ast.Lt: version < bound}
            if type(test.ops[0]) in operations:
                return operations[type(test.ops[0])]
    raise ValueError("DECORATOR_BRANCH_UNKNOWN")


def _protocol_identity_decorator(expression, path, state, transfer=False, call=None):
    from .context_efficiency import (
        _async_runner_docstring,
        _require,
        ast,
    )

    target = _protocol_class_reference(expression, path, None, state)
    if (
        not isinstance(target, tuple)
        or len(target) != 2
        or not isinstance(target[1], ast.FunctionDef)
    ):
        raise ValueError("DECORATOR_SOURCE_UNRESOLVED")
    source, function = target
    args = function.args
    if not transfer and (
        len(args.args) != 1
        or args.posonlyargs
        or args.kwonlyargs
        or args.defaults
        or args.vararg
        or args.kwarg
    ):
        raise ValueError("DECORATOR_IDENTITY_SIGNATURE_UNKNOWN")
    _require(not function.decorator_list, "DECORATOR_IDENTITY_SIGNATURE_UNKNOWN")
    body = (
        function.body[1:] if _async_runner_docstring(function.body) else function.body
    )
    _require(
        body
        and isinstance(body[-1], ast.Return)
        and isinstance(body[-1].value, ast.Name),
        "DECORATOR_RETURN_NOT_IDENTITY",
    )
    parameter = body[-1].value.id
    _require(transfer or parameter == args.args[0].arg, "DECORATOR_RETURN_NOT_IDENTITY")
    if transfer:
        returns = [
            n
            for s in body
            for n in state["audit"]._body_nodes(s)
            if isinstance(n, ast.Return)
        ]
        _require(len(returns) == 1, "IDENTITY_RETURN_CONTROL_UNKNOWN")
        arguments = state["audit"].integrity.bind_source_call(call, function)
        _require(
            arguments.get(parameter) is call.args[0], "IDENTITY_RETURN_ARGUMENT_UNKNOWN"
        )
        state["transfer_receiver"] = parameter
        state["transfer_source"] = source
        _protocol_receiver_transfer(function, transfer, state)
    else:
        for statement in body[:-1]:
            _protocol_metadata_statement(statement, parameter, source, state)
    return target


def _protocol_metadata_statement(statement, parameter, path, state):
    from .context_efficiency import (
        ast,
    )

    match statement:
        case ast.With(
            items=[
                ast.withitem(context_expr=ast.Call() as context, optional_vars=None)
            ],
            body=body,
        ):
            record = _protocol_source_record(path, state)
            aliases = state["audit"]._module_security_aliases(record["tree"])
            if (
                state["audit"]._resolved_ast_name(context.func, aliases)
                != "contextlib.suppress"
                or context.keywords
                or not context.args
            ):
                raise ValueError("DECORATOR_CONTEXT_UNKNOWN")
            if any(
                not isinstance(arg, ast.Name)
                or arg.id not in {"AttributeError", "TypeError"}
                or any(
                    arg.id in _protocol_class_bound_names(n)
                    for n in record["tree"].body
                )
                for arg in context.args
            ):
                raise ValueError("DECORATOR_EXCEPTION_BINDING_UNKNOWN")
            if any(isinstance(child, ast.With) for child in body):
                raise ValueError("DECORATOR_CONTEXT_NESTING_UNSUPPORTED")
            for child in body:
                _protocol_metadata_statement(child, parameter, path, state)
        case ast.Assign(
            targets=[ast.Attribute(value=ast.Name(id=name), attr=attr)],
            value=ast.Constant(value=value),
        ) if (
            name == parameter
            and attr in {"__override__", "__final__"}
            and type(value) is bool
        ):
            return
        case _:
            raise ValueError("DECORATOR_EFFECT_NOT_METADATA")


def _protocol_annotate_finding(finding, node, context):
    from .context_efficiency import (
        deepcopy,
    )

    observations = context.get("protocol_observations", {})
    if not isinstance(observations, dict):
        return finding
    summaries = observations.get("summaries")
    if not isinstance(summaries, list):
        return finding
    matched = []
    for summary in summaries:
        if isinstance(summary, dict) and summary.get("test") == node.name:
            dependencies = summary.get("dependencies")
            if not isinstance(dependencies, list):
                continue
            positions = [
                d.get("line")
                for d in dependencies
                if isinstance(d, dict)
                and d.get("role") == "test"
                and type(d.get("line")) is int
            ]
            if node.lineno in positions:
                matched.append(summary)
    if matched:
        finding.setdefault("facts", {})["protocol_observations"] = dict(
            schema="factory.protocol-observations.v1", summaries=deepcopy(matched)
        )
    return finding


def _protocol_demand_summary(path, test, call, state):
    """Delegate iteration-demand analysis to the canonical oracle owner."""
    from .test_oracle_misuse import _protocol_demand_summary as analyze

    return analyze(path, test, call, state)


def _protocol_demand_visit(call, path, scope, summary, state):
    """Delegate iteration-demand analysis to the canonical oracle owner."""
    from .test_oracle_misuse import _protocol_demand_visit as analyze

    return analyze(call, path, scope, summary, state)


def _protocol_demand_target(expression, path, scope, state):
    """Delegate iteration-demand analysis to the canonical oracle owner."""
    from .test_oracle_misuse import _protocol_demand_target as analyze

    return analyze(expression, path, scope, state)


def _protocol_reachable_call(path, test, call, state, parameters=False):
    """Require a direct synchronous call; return its preceding statements."""
    from .context_efficiency import (
        _require,
        ast,
    )

    active = state.get("active_test_nodes")
    has_yield = (
        active[2]
        if active and active[0] is test
        else any(isinstance(n, (ast.Yield, ast.YieldFrom)) for n in ast.walk(test))
    )
    _require(
        not isinstance(test, ast.AsyncFunctionDef) and not has_yield,
        "DEFERRED_EXECUTION",
    )
    statements = [s for s in test.body if isinstance(s, ast.Expr) and s.value is call]
    _require(len(statements) == 1, "CALL_NOT_DIRECT_UNSUPPRESSED_STATEMENT")
    _require(
        not test.decorator_list
        or parameters
        and all(
            _protocol_parameter_decorator(d, path, test, state)
            for d in test.decorator_list
        ),
        "TEST_DECORATOR_EFFECTS",
    )
    return test.body[: test.body.index(statements[0])]


def _protocol_parameter_decorator(decorator, path, test, state):
    """Support only literal ordinary parametrization, with an intact pytest API."""
    from .context_efficiency import (
        _leftmost_name,
        _module_import_aliases_are_closed,
        _module_import_binding_origin,
        ast,
    )

    match decorator:
        case ast.Call(
            func=func,
            args=[ast.Constant(value=str()), ast.List() | ast.Tuple() as values],
            keywords=[],
        ):
            record = _protocol_source_record(path, state)
            root = _leftmost_name(func)
            api = "pytest.mark.parametrize"
            origin = _module_import_binding_origin(
                record["tree"], root.id if root else "", api
            )
            return (
                all(
                    isinstance(n, (ast.Constant, ast.List, ast.Tuple, ast.Load))
                    for n in ast.walk(values)
                )
                and origin is not None
                and _module_import_aliases_are_closed(
                    record["tree"],
                    "pytest",
                    state["audit"],
                    api=api,
                    effect_nodes=_protocol_executed_nodes(record["tree"], test, state),
                )
            )
    return False


def _protocol_fresh_list_append(call, scope, chain=()):
    """Delegate iteration-demand analysis to the canonical oracle owner."""
    from .test_oracle_misuse import _protocol_fresh_list_append as analyze

    return analyze(call, scope, chain)


def _protocol_receiver_transfer(function, chain, state, local=None):
    """Delegate iteration-demand analysis to the canonical oracle owner."""
    from .test_oracle_misuse import _protocol_receiver_transfer as analyze

    return analyze(function, chain, state, local)


def _protocol_chain_bindings(chain):
    """Delegate iteration-demand analysis to the canonical oracle owner."""
    from .test_oracle_misuse import _protocol_chain_bindings as analyze

    return analyze(chain)
