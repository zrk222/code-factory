"""Source-bound captured security evidence shared by verification consumers."""

import ast
import hashlib
from hashlib import sha256
import json
import re
from copy import deepcopy
from pathlib import Path, PurePosixPath


def _native_span(node):
    span = [
        getattr(node, key, None)
        for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
    ]
    if (
        any(type(value) is not int for value in span)
        or span[0] < 1
        or min(span[1], span[3]) < 0
        or tuple(span[:2]) > tuple(span[2:])
    ):
        return None
    return span


def _captured_sink_failure(schema, code, reason, base=None):
    return {
        **(base or {"schema": schema, "status": "INCOMPLETE"}),
        "code": code,
        "truncation": [reason],
    }


def _captured_sink_source(
    path_arg, expected, index, raw, tree, max_sources, max_states, max_output, schema
):
    import io
    import tokenize

    limits = (max_sources, max_states, max_output)
    if any(type(value) is not int or value < 1 for value in limits) or max_output < 256:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_INVALID", "invalid_limit"
            )
        }
    limits = tuple(
        min(value, ceiling) for value, ceiling in zip(limits, (64, 512, 64000))
    )
    path = path_arg.as_posix() if hasattr(path_arg, "as_posix") else path_arg
    tree_supplied = tree is not None
    indexed = index is not None
    if indexed:
        capture = _captured_sink_index(index, path_arg, raw, path, schema)
        if "error" in capture:
            return capture
        raw, tree, parents = capture["raw"], capture["tree"], capture["parents"]
    else:
        parents = None
    if not isinstance(path, str) or not path:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "invalid_source_path"
            )
        }
    if not isinstance(raw, bytes) or len(raw) > 1_000_000:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_EXHAUSTED", "max_source_bytes"
            )
        }
    digest = hashlib.sha256(raw).hexdigest()
    if not isinstance(expected, str) or expected != digest:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_hash_mismatch"
            )
        }
    if not indexed:
        capture = _captured_sink_raw_tree(path, raw, tree, schema)
        if "error" in capture:
            return capture
        tree, parents = capture["tree"], capture["parents"]
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        text = raw.decode(encoding)
    except (SyntaxError, UnicodeError, LookupError):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_encoding_invalid"
            )
        }
    base = {
        "schema": schema,
        "status": "INCOMPLETE",
        "source": {"path": path[:1024], "sha256": digest, "bytes": len(raw)},
        "source_count": 1,
    }
    return {
        "tree": tree,
        "parents": parents,
        "text": text,
        "base": base,
        "digest": digest,
        "limits": limits,
        "indexed": indexed,
        "tree_supplied": tree_supplied,
    }


def _captured_sink_index(index, path_arg, raw, path, schema):
    inventory = getattr(index, "source_bytes", {})
    if not isinstance(path, str) or path_arg not in getattr(index, "snapshots", {}):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_not_indexed"
            )
        }
    if (
        sum(len(value) for value in inventory.values() if isinstance(value, bytes))
        > 32_000_000
    ):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_EXHAUSTED", "max_inventory_bytes"
            )
        }
    captured = inventory.get(path_arg)
    if raw is not None and raw != captured:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_bytes_changed"
            )
        }
    if not isinstance(captured, bytes) or len(captured) > 1_000_000:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_EXHAUSTED", "max_source_bytes"
            )
        }
    validation_inputs = getattr(index, "_validation_inputs", None)
    if not isinstance(validation_inputs, dict):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_validation_cache_unavailable"
            )
        }
    validation_inputs.pop(path_arg, None)
    if not index.validate(path_arg):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_snapshot_invalid"
            )
        }
    return {
        "raw": captured,
        "tree": index.snapshots[path_arg],
        "parents": index.parents[path_arg],
    }


def _captured_sink_raw_tree(path, raw, tree, schema):
    try:
        parsed = ast.parse(raw, filename=path)
        if tree is not None and ast.dump(parsed, include_attributes=True) != ast.dump(
            tree, include_attributes=True
        ):
            return {
                "error": _captured_sink_failure(
                    schema, "SINK_SOURCE_STALE", "ast_source_mismatch"
                )
            }
        tree = tree or parsed
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_parse_failed"
            )
        }
    return {"tree": tree, "parents": {}}


def _captured_sink_location(node, ctx):
    base, tree, parents = ctx["base"], ctx["tree"], ctx["parents"]
    schema = base["schema"]
    span = _native_span(node) if isinstance(node, ast.AST) else None
    if span is None:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_LOCATION_UNRESOLVED", "invalid_sink_span", base
            )
        }
    if ctx["indexed"] and isinstance(node, ast.Call) and id(node) in parents:
        return {"node": node, "parents": parents, "source_ast_nodes_examined": 0}
    if ctx["indexed"]:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_LOCATION_UNRESOLVED", "sink_not_in_captured_tree", base
            )
        }
    matches = []
    for count, item in enumerate(ast.walk(tree), 1):
        if count > 200_000:
            return {
                "error": _captured_sink_failure(
                    schema, "SINK_BUDGET_EXHAUSTED", "max_source_ast_nodes", base
                )
            }
        parents.update({id(child): item for child in ast.iter_child_nodes(item)})
        if (
            isinstance(item, ast.Call)
            and _native_span(item) == span
            and ast.dump(item, include_attributes=True)
            == ast.dump(node, include_attributes=True)
        ):
            matches.append(item)
    if ctx["tree_supplied"] and id(node) not in parents:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_LOCATION_UNRESOLVED", "sink_not_in_supplied_tree", base
            )
        }
    if len(matches) == 1:
        return {
            "node": matches[0],
            "parents": parents,
            "source_ast_nodes_examined": count,
        }
    return {
        "error": _captured_sink_failure(
            schema, "SINK_LOCATION_UNRESOLVED", "sink_span_not_unique", base
        )
    }


def _captured_sink_fact(item, path, digest, status="OBSERVED"):
    span = _native_span(item)
    return (
        {"status": status, "source": {"path": path, "sha256": digest, "span": span}}
        if span is not None
        else {"status": "UNKNOWN", "reason": "span_unavailable"}
    )


def _captured_sink_excerpt(item, text, truncation):
    excerpt = ast.get_source_segment(text, item)
    if not isinstance(excerpt, str):
        return ""
    if len(excerpt) > 512:
        if "excerpt_truncated" not in truncation:
            truncation.append("excerpt_truncated")
        return excerpt[:512] + "[truncated]"
    return excerpt


def _captured_sink_scope(node, parents, fact, budget, base):
    scope = node
    while id(scope) in parents:
        scope = parents[id(scope)]
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            break
    else:
        scope = None
    row, body, statement = (
        {"status": "UNKNOWN", "reason": "no_enclosing_callable"},
        None,
        None,
    )
    if scope is not None:
        statement = node
        while id(statement) in parents and parents[id(statement)] is not scope:
            statement = parents[id(statement)]
        if (
            isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
            and statement in scope.body
        ):
            body = scope.body
            row = {
                "status": "OBSERVED",
                "name": scope.name,
                "kind": type(scope).__name__,
                **fact(scope),
            }
        else:
            row = {
                "status": "UNKNOWN",
                "reason": "sink_outside_callable_body",
                **fact(scope),
            }
    nodes, stack = [], [scope] if body is not None else []
    while stack:
        item = stack.pop()
        nodes.append(item)
        if len(nodes) > budget:
            return {
                "error": _captured_sink_failure(
                    base["schema"], "SINK_BUDGET_EXHAUSTED", "max_states", base
                )
            }
        if item is not scope and isinstance(
            item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        stack.extend(ast.iter_child_nodes(item))
    return {
        "scope": scope,
        "body": body,
        "statement": statement,
        "nodes": nodes,
        "row": row,
    }


def _captured_sink_arguments(node, fact, excerpt):
    arguments, names = [], set()
    for index, value in enumerate(node.args):
        arguments.append(
            {
                "position": index,
                "kind": "starred" if isinstance(value, ast.Starred) else "positional",
                "expression": excerpt(value),
                "span": _native_span(value),
                **fact(value),
            }
        )
        names.update(
            item.id
            for item in ast.walk(value)
            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
        )
    for keyword in node.keywords:
        value = keyword.value
        arguments.append(
            {
                "keyword": keyword.arg,
                "kind": "expanded_keyword" if keyword.arg is None else "keyword",
                "expression": excerpt(value),
                "span": _native_span(value),
                **fact(value),
            }
        )
        names.update(
            item.id
            for item in ast.walk(value)
            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
        )
    callees = [
        item
        for item in ast.walk(node.func)
        if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
    ]
    names.update(item.id for item in callees)
    return arguments, names, callees


def _captured_sink_imports(tree, scope, nodes, parents, fact, budget, base):
    from .credential_role_constructor_provider import binding_occurrences

    modules = [
        item for item in tree.body if isinstance(item, (ast.Import, ast.ImportFrom))
    ]
    if len(nodes) + len(modules) > budget:
        return {
            "error": _captured_sink_failure(
                base["schema"], "SINK_BUDGET_EXHAUSTED", "max_states", base
            )
        }
    rows, params = [], _captured_sink_parameter_names(scope)
    for item in modules + [
        row for row in nodes if isinstance(row, (ast.Import, ast.ImportFrom))
    ]:
        owner = _captured_sink_enclosing_callable(item, parents)
        if owner not in (None, scope):
            continue
        container = owner.body if owner is not None else tree.body
        for alias in item.names:
            name = alias.asname or (
                alias.name.split(".")[0] if isinstance(item, ast.Import) else alias.name
            )
            wildcard = isinstance(item, ast.ImportFrom) and alias.name == "*"
            stable = (
                not wildcard
                and binding_occurrences(container, name) == [item]
                and name not in params
            )
            status = "OBSERVED" if stable else "UNKNOWN"
            rows.append(
                {
                    "name": name,
                    "module": (
                        item.module if isinstance(item, ast.ImportFrom) else alias.name
                    ),
                    "kind": type(item).__name__,
                    "status": status,
                    "reason": None if stable else "binding_replaced_or_ambiguous",
                    "span": _native_span(item),
                    **fact(item, status),
                }
            )
    return {
        "rows": rows,
        "module_imports": modules,
        "states_used": sum(len(item.names) for item in modules),
        "binding_occurrences": binding_occurrences,
    }


def _captured_sink_values(
    node, names, scope, body, statement, nodes, parents, tree, fact, excerpt
):
    from .credential_role_constructor_provider import binding_occurrences

    if body is None:
        return [
            {
                "name": name,
                "status": "UNKNOWN",
                "reason": "no_supported_callable_scope",
                "origin": "UNRESOLVED",
                "definitions": [],
                "replacements": [],
            }
            for name in sorted(names)
        ]
    params = _captured_sink_parameter_names(scope)
    reflective = _captured_sink_reflective_barrier(node, scope, nodes, parents)
    pending, visited, result = sorted(names), set(), []
    while pending:
        name = pending.pop(0)
        if name in visited:
            continue
        visited.add(name)
        evidence = _captured_sink_value(
            name,
            scope,
            body,
            statement,
            parents,
            tree,
            params,
            fact,
            excerpt,
            binding_occurrences,
        )
        value, assignment = evidence["value"], evidence["assignment"]
        if assignment is not None:
            pending.extend(
                row.id
                for row in ast.walk(assignment.value)
                if isinstance(row, ast.Name)
                and isinstance(row.ctx, ast.Load)
                and row.id not in visited
                and row.id not in pending
            )
        if reflective:
            value.update(
                status="UNKNOWN",
                reason="reflective_binding_possible",
                origin="UNRESOLVED",
            )
            value["replacements"].append(
                {"kind": "REFLECTIVE_WRITE_POSSIBLE", **fact(node, "UNKNOWN")}
            )
        result.append(value)
    return result


def _captured_sink_reflective_barrier(node, scope, nodes, parents):
    """Return whether a reflective call can precede or feed this selected sink."""
    reflective_names = {
        "exec",
        "eval",
        "globals",
        "locals",
        "vars",
        "setattr",
        "delattr",
    }
    selected_span = _native_span(node)
    selected_start = tuple(selected_span[:2]) if selected_span else None
    selected_subtree = {id(item) for item in ast.walk(node)}
    for item in nodes:
        if (
            not isinstance(item, ast.Call)
            or not isinstance(item.func, ast.Name)
            or item.func.id not in reflective_names
            or item is node
        ):
            continue
        if id(item) in selected_subtree:
            return True
        if _captured_sink_enclosing_callable(item, parents) is not scope:
            continue
        span = _native_span(item)
        if selected_start is None or span is None:
            return True
        if tuple(span[:2]) <= selected_start:
            return True
    return False


def _captured_sink_value(
    name,
    scope,
    body,
    statement,
    parents,
    tree,
    params,
    fact,
    excerpt,
    binding_occurrences,
):
    bindings = binding_occurrences(body, name)
    rows = []
    for binding in bindings:
        statement_node = (
            parents.get(id(binding)) if isinstance(binding, ast.Name) else binding
        )
        if statement_node is None:
            statement_node = binding
        rows.append(
            {
                "kind": type(binding).__name__,
                "binding_span": _native_span(binding),
                "expression": excerpt(statement_node),
                **fact(statement_node, "UNKNOWN"),
            }
        )
    assignment = None
    if (
        len(bindings) == 1
        and isinstance(bindings[0], ast.Name)
        and isinstance(bindings[0].ctx, ast.Store)
    ):
        candidate = parents.get(id(bindings[0]))
        targets = (
            candidate.targets
            if isinstance(candidate, ast.Assign)
            else [candidate.target]
            if isinstance(candidate, ast.AnnAssign)
            else []
        )
        if (
            candidate in body
            and body.index(candidate) < body.index(statement)
            and getattr(candidate, "value", None) is not None
            and len(targets) == 1
            and targets[0] is bindings[0]
        ):
            assignment = candidate
    if assignment is not None:
        value = {
            "name": name,
            "status": "INFERRED",
            "reason": None,
            "origin": "LOCAL_DEFINITION",
            "definitions": [
                {
                    "expression": excerpt(assignment.value),
                    "span": _native_span(assignment),
                    **fact(assignment),
                }
            ],
            "replacements": [],
        }
        value["definitions"][0]["target_source"] = fact(
            assignment.targets[0]
            if isinstance(assignment, ast.Assign)
            else assignment.target
        )
    elif not bindings and name in params:
        args = (
            *scope.args.posonlyargs,
            *scope.args.args,
            *scope.args.kwonlyargs,
            *([scope.args.vararg] if scope.args.vararg else []),
            *([scope.args.kwarg] if scope.args.kwarg else []),
        )
        arg = next(row for row in args if row.arg == name)
        value = {
            "name": name,
            "status": "INFERRED",
            "reason": None,
            "origin": "CALLABLE_PARAMETER",
            "definitions": [
                {"kind": "PARAMETER", "span": _native_span(arg), **fact(arg)}
            ],
            "replacements": [],
        }
    elif not bindings and any(
        row in tree.body for row in binding_occurrences(tree.body, name)
    ):
        module_bindings = binding_occurrences(tree.body, name)
        if len(module_bindings) == 1 and isinstance(
            module_bindings[0], (ast.Import, ast.ImportFrom)
        ):
            value = {
                "name": name,
                "status": "INFERRED",
                "reason": None,
                "origin": "LEXICAL_IMPORT",
                "definitions": [
                    {
                        "kind": type(module_bindings[0]).__name__,
                        "span": _native_span(module_bindings[0]),
                        **fact(module_bindings[0]),
                    }
                ],
                "replacements": [],
            }
        else:
            value = {
                "name": name,
                "status": "UNKNOWN",
                "reason": "module_binding_ambiguous",
                "origin": "UNRESOLVED",
                "definitions": [],
                "replacements": rows,
            }
    else:
        value = {
            "name": name,
            "status": "UNKNOWN",
            "reason": (
                "binding_replaced_or_not_straight_line"
                if bindings
                else "no_source_definition_or_parameter"
            ),
            "origin": "UNRESOLVED",
            "definitions": [],
            "replacements": rows,
        }
    return {"value": value, "assignment": assignment}


def _captured_sink_guards(node, scope, parents, fact, excerpt):
    guards, current = [], node
    control = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        getattr(ast, "TryStar", ast.Try),
        ast.With,
        ast.AsyncWith,
        ast.Match,
        ast.Assert,
    )
    while id(current) in parents and parents[id(current)] is not scope:
        current = parents[id(current)]
        if isinstance(current, control):
            test = getattr(current, "test", None) or getattr(current, "subject", None)
            guards.append(
                {
                    "kind": type(current).__name__,
                    "expression": excerpt(test) if test is not None else "",
                    "semantics": "UNKNOWN",
                    "span": _native_span(current),
                    **fact(current),
                }
            )
    return guards


def _captured_sink_callee_binding(names, scope, body, tree, module_imports, fact):
    from .credential_role_constructor_provider import binding_occurrences

    name = names[0].id if names else None
    row = {"status": "UNKNOWN", "reason": "unresolved_callee_binding", "name": name}
    if name is None or body is None:
        return row
    if any(
        isinstance(item, ast.ImportFrom)
        and any(alias.name == "*" for alias in item.names)
        for item in module_imports
    ):
        row["reason"] = "wildcard_import_may_bind_name"
    elif not binding_occurrences(
        body, name
    ) and name not in _captured_sink_parameter_names(scope):
        bindings = binding_occurrences(tree.body, name)
        if (
            len(bindings) == 1
            and bindings[0] in tree.body
            and isinstance(bindings[0], (ast.Import, ast.ImportFrom))
        ):
            row = {
                "status": "INFERRED",
                "reason": None,
                "name": name,
                "declaration": fact(bindings[0]),
            }
    return row


def _captured_sink_enclosing_callable(node, parents):
    current = node
    while id(current) in parents:
        current = parents[id(current)]
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return current
    return None


def _captured_sink_parameter_names(scope):
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        return set()
    args = scope.args
    parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    parameters.extend(item for item in (args.vararg, args.kwarg) if item is not None)
    return {item.arg for item in parameters}


def _security_request_binary_decode_kind(
    value, requests, aliases, scope, statement, *, audit
):
    """Carry request text through an exact, source-stable base64-to-bytes transform."""
    if not isinstance(value, ast.Call) or len(value.args) != 1 or value.keywords:
        return None
    if any((isinstance(argument, ast.Starred) for argument in value.args)):
        return None
    if audit.security_call_name(value, aliases) not in {
        "base64.b64decode",
        "base64.urlsafe_b64decode",
    }:
        return None
    from .semantic_credential_sensor import (
        _provider_identity_uncertain,
        request_payload_value_kind,
    )

    module = audit._security_module_scope(scope)
    if module is None or _provider_identity_uncertain(
        module, aliases, roots=(audit.security_call_name(value, aliases),)
    ):
        return None
    source = value.args[0]
    if request_payload_value_kind(
        source,
        requests,
        aliases,
        audit._security_scope_request_aliases,
        scope,
        statement,
    ) == "text" and audit._security_expr_tainted(source, requests, set(), aliases):
        return "bytes"
    return None


def _security_bind_local_native_input_precondition(
    call, canonical, primitive, scope, requests, aliases, *, audit
):
    """Bind one sink against its own provider identities when unrelated module code is ambiguous."""
    from .semantic_credential_sensor import (
        _native_input_request_is_supported,
        security_precondition_call_shape,
        security_precondition_path_possible,
        supported_security_precondition,
    )
    from .finite_capture import security_input_value_flow

    eligible = {
        "SECURITY_DYNAMIC_EXECUTION",
        "SECURITY_OS_COMMAND",
        "SECURITY_SHELL_COMMAND",
        "SECURITY_UNSAFE_DESERIALIZATION",
        "SECURITY_UNSAFE_YAML",
    }
    if primitive.get("code") not in eligible or not call.args:
        return
    module = audit._security_module_scope(scope)
    if module is None or not (
        security_precondition_call_shape(call, canonical)
        or audit._security_shell_call_shape_for_flow(call, canonical)
    ):
        return
    if not security_precondition_path_possible(call):
        return
    supported = getattr(requests, "supported_view", lambda: requests)()
    if supported is None or not _native_input_request_is_supported(
        call, canonical, supported, aliases, scope, audit
    ):
        return
    if audit._security_local_request_provider_identity_uncertain(module, aliases):
        return
    provider_roots = (
        ("subprocess",)
        if canonical.startswith("subprocess.")
        else ("os.system",)
        if canonical == "os.system"
        else ("_pickle",)
        if canonical.startswith("_pickle.")
        else ("pickle",)
        if canonical.startswith("pickle.")
        else ("dill",)
        if canonical.startswith("dill.")
        else ("yaml",)
        if canonical.startswith("yaml.")
        else ("builtins",)
    )
    if audit._security_local_provider_identity_uncertain(
        module, aliases, provider_roots, audit=audit
    ):
        return
    premise = supported_security_precondition(call, "untrusted_request", canonical)
    if trace := security_input_value_flow(call.args[0], supported, aliases):
        premise["input_value_flow"] = trace
    call._security_supported_precondition = premise


def _security_local_request_provider_identity_uncertain(module, aliases):
    """Keep request-provider mutations in every captured module as source blockers."""
    from .review_audits import _security_aliases
    from .semantic_credential_sensor import (
        _native_input_inventory_epoch,
        _native_input_provider_inventory,
        _provider_identity_uncertain,
    )

    selected_providers = (
        "flask.request",
        *(
            path
            for path in aliases.values()
            if path.split(".")[0] in {"flask", "django"}
        ),
    )
    source_model = getattr(module, "_security_source_model", None)
    trees = (
        tuple(source_model.snapshots.values())
        if source_model is not None
        else (module,)
    )
    for tree in trees:
        nodes = list(ast.walk(tree))
        source_aliases = aliases if tree is module else _security_aliases(nodes)
        inventory = _native_input_provider_inventory(tree, source_aliases, nodes)
        parents = {
            id(child): parent
            for parent in nodes
            for child in ast.iter_child_nodes(parent)
        }
        if _provider_identity_uncertain(
            tree,
            source_aliases,
            roots=selected_providers,
            selected_paths=True,
            nodes=inventory,
            parents=parents,
            inventory_projector=_native_input_provider_inventory,
            inventory_dependencies=_native_input_inventory_epoch(),
        ):
            return True
    return False


def _security_shell_call_shape_for_flow(call, canonical):
    """Allow inert process options around an explicitly enabled shell sink."""
    if (
        canonical
        not in {
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.Popen",
        }
        or len(call.args) != 1
        or isinstance(call.args[0], ast.Starred)
    ):
        return False
    keywords = {item.arg: item.value for item in call.keywords}
    if (
        None in keywords
        or len(keywords) != len(call.keywords)
        or "shell" not in keywords
        or (not isinstance(keywords["shell"], ast.Constant))
        or (keywords["shell"].value is not True)
    ):
        return False
    inert_options = {
        "shell",
        "stdin",
        "stdout",
        "stderr",
        "timeout",
        "check",
        "cwd",
        "env",
        "text",
        "encoding",
        "errors",
        "universal_newlines",
        "bufsize",
        "close_fds",
        "start_new_session",
        "creationflags",
    }
    return set(keywords).issubset(inert_options)


def _security_local_provider_identity_uncertain(module, aliases, roots, *, audit):
    """Ignore only read-only subprocess stream constants in otherwise exact provider checks."""
    from types import SimpleNamespace
    from .finite_capture import finite_provider_mutation_index
    from .review_audits import _resolved_ast_name

    nodes = list(ast.walk(module))
    parents = {
        id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)
    }
    mutations = finite_provider_mutation_index(
        nodes, aliases, SimpleNamespace(_resolved_ast_name=_resolved_ast_name), parents
    )
    if "subprocess" in roots:
        inert = set()
        for node in nodes:
            if not (
                isinstance(node, ast.Attribute)
                and node.attr in {"STDOUT", "PIPE", "DEVNULL"}
                and isinstance(node.ctx, ast.Load)
                and (audit._resolve(node, aliases) == f"subprocess.{node.attr}")
            ):
                continue
            keyword = parents.get(id(node))
            call = (
                parents.get(id(keyword)) if isinstance(keyword, ast.keyword) else None
            )
            if (
                isinstance(keyword, ast.keyword)
                and keyword.value is node
                and (keyword.arg in {"stdin", "stdout", "stderr"})
                and isinstance(call, ast.Call)
                and audit.security_call_name(call, aliases).startswith("subprocess.")
            ):
                inert.add((f"subprocess.{node.attr}", "*"))
        mutations = [item for item in mutations if item not in inert]
    return any(
        (
            path == root or path.startswith(root + ".")
            for path, _attribute in mutations
            for root in roots
        )
    )


_NATIVE_INPUT_EPOCH_BINDINGS = tuple(
    (module, names.split())
    for module, names in {
        "factoryline.semantic_credential_sensor": """
        _signing_provider_clear _signing_provider_reads _signing_bound_providers_clear
        _security_builtin_identity_closed _provider_identity_uncertain _provider_path_conflicts
        _native_input_provider_inventory http_request_payload
        _http_request_subscript_payload _http_request_call_payload
        _http_request_attribute_payload _flask_request_body_kind
        _credential_get_source_key _http_request_mapping
        _request_mapping_value_unchanged _request_mapping_aliases
        _request_mapping_mutation _django_http_body_payload
        _native_request_data_member _new_security_request_alias_memo
        _security_scope_request_aliases _security_scope_request_aliases_uncached
        _security_request_alias_module_bindings
        _security_store_request_alias_bindings
        supported_security_precondition tls_finding log_security_precondition
        bind_request_sink_precondition _security_request_sink_slot
        """,
        "factoryline.captured_security_audit": """
        _security_request_binary_decode_kind _security_bind_local_native_input_precondition _security_local_request_provider_identity_uncertain _security_shell_call_shape_for_flow _security_local_provider_identity_uncertain _native_input_inventory_epoch
        """,
        "factoryline.import_context": """
        finite_key_reflection_reads _finite_loop_reflection_reads _finite_dictionary_key_domain _finite_dictionary_key_use_closed _finite_key_reflection_call _finite_table_peers_closed import_resolution_helpers close_selected_import_sources eager_import_closure _eager_import_model_roots _eager_import_edges _eager_import_target
        """,
        "factoryline.credential_endpoint_admission": """
        _django_setting_import_closure _django_setting_import_aliases _django_setting_import_sites _django_setting_import_operand _django_import_namespace_unknown _django_importer_external
        """,
        "factoryline.credential_role_constructor_provider": """
        binding_occurrences _binds
        """,
        "factoryline.credential_role_identity_effects": """
        source_symbol_index
        """,
        "factoryline.mock_fixture_provenance": """
        _django_import_rows _django_name _django_assignment
        """,
        "factoryline.review_integrity": """
        _security_request_binary_decode_kind _security_bind_local_native_input_precondition _security_local_request_provider_identity_uncertain _security_shell_call_shape_for_flow _security_local_provider_identity_uncertain
        bind_security_call_scopes _bind_security_scope_node _bind_security_function
        _bind_security_class _function_annotations _security_scope_local_names
        _security_scope_nonlocal_names _security_scope_declared_names
        _security_module_scope _security_apply_import_bindings
        _security_scope_request_aliases
        _security_unsafe_flask_file_save _security_upload_path_expression
        tls_verification_disabled
        """,
        "factoryline.audit_log_flow": """
        audit_log_source_findings
        """,
        "factoryline.finite_capture": """
        finite_provider_mutation_index _provider_mutation_for_node
        _provider_mutation_facts _record_provider_paths _record_provider_capture
        _provider_alias_bindings _provider_paths _provider_call_argument
        _reflective_provider_write _foreign_provider_inputs
        _foreign_provider_source_mutations _project_provider_inventory
        """,
        "factoryline.credential_role_paths": """
        matches_regenerated_security_precondition valid_security_precondition
        security_effect_fact_matches logging_consumer_configuration
        logging_security_effect_witness logging_security_precondition source_span
        upload_path_expression bind_request_sink_precondition tls_security_finding
        upload_name_origin upload_join_effect upload_concat_effect source_domain_guarded
        _upload_filename_domain_kind _upload_guard_dominates
        _upload_control_path _upload_definition_reaches _upload_receiver_names
        _upload_prior_field_write _upload_filename_mutated
        bind_upload_sink_precondition
        regenerate_security_source_model
        _logging_configuration _logging_direct_configuration
        _logging_declared_configuration _logging_active_settings
        _logging_node_possible _logging_reference _logging_dict_fields
        _logging_literal _logging_assignment _logging_receiver
        _logging_receiver_name _logging_receiver_assignments _logging_call_level
        _logging_logger_route _logging_logger_entry _logging_root_route
        _logging_plain_handler_routes _logging_plain_handler_route
        _logging_plain_formatter _logging_route_facts _logging_config_sections
        _logging_mutation_present _logging_local_mutation_present
        _logging_filter_provider_uncertain
        logging_input_value_trace logging_merge_log_flow
        """,
        "factoryline.review_audits": """
        _name _resolved_ast_name _security_aliases _bound_names _binding_name
        _iter_ast_nodes
        """,
        "factoryline.intent_quality": """
        _security_scope_request_aliases
        """,
        "factoryline": """
        _source_binding_helpers _bind_source_call _source_call_signature
        """,
    }.items()
)


def _native_input_inventory_epoch(_cache_owner):
    from importlib import import_module
    from . import review_audits, intent_quality, semantic_credential_sensor
    from . import credential_role_paths
    from . import audit_log_flow

    functions = [
        getattr(import_module(module), name)
        for module, names in import_module(
            _cache_owner.__module__
        )._NATIVE_INPUT_EPOCH_BINDINGS
        for name in names
    ]
    helpers = import_module("factoryline.import_context").import_resolution_helpers()
    functions.extend(helpers if isinstance(helpers, tuple) else ())
    identity = (
        tuple(
            (
                (
                    fn,
                    getattr(fn, "__code__", None),
                    id(getattr(fn, "__defaults__", None)),
                )
                for fn in functions
            )
        ),
        semantic_credential_sensor.SECURITY_EFFECT_WITNESS_SCHEMA,
        import_module("factoryline.import_context")._eager_import_model_roots(),
        semantic_credential_sensor.SECURITY_EFFECT_CONTRACTS,
        semantic_credential_sensor._SECURITY_EFFECT_WITNESS_SCHEMA_BASELINE,
        semantic_credential_sensor._SECURITY_EFFECT_CONTRACTS_BASELINE,
        tuple(sorted(credential_role_paths._LOG_LEVEL_VALUES.items())),
        tuple(sorted(credential_role_paths._LOG_STANDARD_HANDLERS)),
        tuple(
            (
                (name, fn, getattr(fn, "__code__", None))
                for name, fn in vars(audit_log_flow._LogReader).items()
                if callable(fn)
            )
        ),
        audit_log_flow._LOGGING_LEVELS,
        audit_log_flow.log_evidence,
        ast.dump(semantic_credential_sensor._FLASK_BODY_SIGNATURE),
        review_audits._FUNCTION_NODES,
        intent_quality._SECURITY_REQUEST_ALIAS_MEMO,
        intent_quality._SECURITY_REQUEST_ALIAS_MAX_ENTRIES,
        intent_quality._SECURITY_REQUEST_ALIAS_MAX_PAIRS,
        intent_quality._SECURITY_REQUEST_ALIAS_MAX_BYTES,
    )
    cached = getattr(_cache_owner, "_cached_epoch", None)
    if cached is None or cached[0] != identity:
        cached = (identity, object())
        _cache_owner._cached_epoch = cached
    return cached[1]


_SOURCE_ROLE_COMPONENTS = frozenset(
    {
        "test",
        "tests",
        "example",
        "examples",
        "example_projects",
        "demo",
        "demo_project",
        "demos",
        "archive",
    }
)


def _source_role_path(relative):
    if not isinstance(relative, str):
        return None
    normalized = relative.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        return None
    path = PurePosixPath(normalized)
    parts = path.parts
    if path.is_absolute() or ".." in parts or path.suffix.lower() != ".py":
        return None
    role = next(
        (
            part.lower()
            for part in parts[:-1]
            if part.lower() in _SOURCE_ROLE_COMPONENTS
        ),
        None,
    )
    return (path, role) if role is not None else None


def source_role_distribution_domain(
    captured, relative, *, line=None, credential_name=None
):
    """Resolve source-role authority from bound package or archive evidence."""
    resolved = _source_role_path(relative)
    if not isinstance(captured, dict) or resolved is None:
        return None
    path, role = resolved
    if role == "archive":
        redaction = _archive_redaction_domain(
            captured, path, line=line, credential_name=credential_name
        )
        if redaction is not None:
            return redaction
    from .pytest_collection_audit import _distribution_selection_excludes_source

    proof = _distribution_selection_excludes_source(captured, path)
    if proof is None:
        return None
    return {
        "schema": "factory.security.source-role-package-scope.v1",
        "role": role,
        "application_authority": "UNKNOWN",
        "proof_scope": "source_bound_distribution_package_selection",
        "package_scope": "EXCLUDED_FROM_CAPTURED_STATIC_PACKAGE_SELECTION",
        "selection_basis": proof["basis"],
        "claim_boundary": "Package selection only; repository source may still be runnable.",
        "candidate_path": path.as_posix(),
        "manifest_path": proof["path"],
        "manifest_sha256": proof["sha256"],
        "supporting_sources": {proof["path"]: proof["sha256"]},
    }


def selected_django_credential_domain(
    context, path, observation, selected, finding, index
):
    """Prefer captured Django test evidence before checking distribution scope."""
    from .credential_identity_audit import django_test_domain_evidence

    domain = django_test_domain_evidence(context, path, observation, selected)
    if domain is not None:
        return domain
    distribution = source_role_distribution_domain(
        context.get("captured", {}),
        index.relative(path),
        line=finding.get("line"),
        credential_name=(finding.get("facts") or {}).get("name"),
    )
    if _mapped_distribution_scope(distribution) and not _mapped_scope_contains_loaders(
        context, path, index, distribution
    ):
        return None
    return distribution


def _mapped_distribution_scope(domain):
    return (
        isinstance(domain, dict)
        and domain.get("selection_basis") == "setuptools_mapped_source_root"
    )


def _mapped_scope_contains_loaders(context, path, index, domain):
    from .semantic_credential_sensor import _django_signing_consumer

    parts = PurePosixPath(index.relative(path)).parts
    depth = next(
        i + 1 for i, part in enumerate(parts) if part.lower() == domain["role"]
    )
    scope = tuple(part.casefold() for part in parts[:depth])
    loaders = (
        tuple(part.casefold() for part in PurePosixPath(index.relative(other)).parts)
        for other, tree in index.snapshots.items()
        if _django_signing_consumer(path, other, tree, context) is not None
    )
    contained = False
    for loader in loaders:
        if loader[:depth] != scope:
            return False
        contained = True
    return contained


def _source_role_candidate(finding, bound, credential_evidence, generated):
    unresolved = (generated is None and credential_evidence is None) or (
        isinstance(generated, dict) and generated.get("authority_domain") is None
    )
    facts = finding.get("facts")
    return (
        unresolved
        and bound
        and finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and isinstance(facts, dict)
        and isinstance(facts.get("name"), str)
    )


def source_role_context_fallback(
    finding, bound, credential_evidence, generated, context, source_bindings
):
    """Attach independently bound role evidence to an unresolved secret finding."""
    if not _source_role_candidate(finding, bound, credential_evidence, generated):
        return None
    if not isinstance(context, dict) or not isinstance(source_bindings, dict):
        return None
    index = context.get("index")
    path = Path(finding.get("path", ""))
    if index is None or not index.validate(path):
        return None
    domain = source_role_distribution_domain(
        context.get("captured", {}),
        index.relative(path),
        line=finding.get("line"),
        credential_name=finding["facts"]["name"],
    )
    if _mapped_distribution_scope(domain):
        # A package root is not an independent witness of runtime ownership.
        return None
    supporting = _bound_role_support(domain, source_bindings)
    if not supporting:
        return None
    observation = {
        "schema": "factory.security.source-role-context-observation.v1",
        "proof_scope": domain["proof_scope"],
        "credential_key": finding["facts"]["name"],
        "source_role": domain["role"],
        "authority_domain": domain,
        "supporting_sources": [
            {"path": source, "sha256": digest}
            for source, digest in sorted(supporting.items())
        ],
    }
    if generated is not None:
        observation["selected_framework_observation"] = generated
    return (
        "NEEDS_CONTEXT",
        domain["proof_scope"],
        {"credential_authority_observation": observation},
    )


def _bound_role_support(domain, bindings):
    supporting = domain.get("supporting_sources") if isinstance(domain, dict) else None
    if isinstance(supporting, dict) and all(
        bindings.get(source) == digest for source, digest in supporting.items()
    ):
        return supporting
    return None


def source_role_tier_override(
    finding, bound, credential_evidence, context, source_bindings
):
    """Resolve operative signing and role context from the same captured inputs."""
    from .credential_endpoint_admission import operative_signing_default_evidence

    generated = (
        operative_signing_default_evidence(finding, context)
        if bound and credential_evidence is None and context is not None
        else None
    )
    fallback = source_role_context_fallback(
        finding, bound, credential_evidence, generated, context, source_bindings
    )
    return generated, fallback


def source_role_capture_context(source_bytes, bindings, context):
    """Bind auxiliary role bytes without modifying the Python inventory."""
    support = getattr(source_bytes, "source_role_sources", {})
    if not (
        isinstance(support, dict)
        and all(
            isinstance(path, str)
            and isinstance(raw, bytes)
            and len(raw) <= 1_000_000
            and (
                path not in bindings
                or hashlib.sha256(raw).hexdigest() == bindings[path]
            )
            for path, raw in support.items()
        )
    ):
        support = {}
    role_bindings = dict(bindings)
    role_bindings.update(
        {path: hashlib.sha256(raw).hexdigest() for path, raw in support.items()}
    )
    role_context = context
    if (
        support
        and isinstance(context, dict)
        and isinstance(context.get("captured"), dict)
    ):
        role_context = {
            **context,
            "captured": {**context["captured"], **support},
        }
    return role_context, role_bindings


def _archive_redaction_domain(captured, path, *, line, credential_name):
    if (
        not isinstance(line, int)
        or not isinstance(credential_name, str)
        or not re.search(
            r"secret|password|token|credential|api[_-]?key|private[_-]?key",
            credential_name,
            re.IGNORECASE,
        )
    ):
        return None
    candidate_path = path.as_posix()
    source = captured.get(candidate_path)
    manifest = captured.get("archive/manifest.json")
    readme = captured.get("archive/README.md")
    if not all(isinstance(raw, bytes) for raw in (source, manifest, readme)):
        return None
    try:
        source_hash = hashlib.sha256(source).hexdigest()
        manifest_rows = json.loads(manifest)
        document = ast.parse(source.decode("utf-8"))
        readme_text = readme.decode("utf-8").lower()
    except (UnicodeDecodeError, SyntaxError, ValueError, TypeError):
        return None
    if not isinstance(manifest_rows, list) or not all(
        phrase in readme_text
        for phrase in ("historical source archive", "sanitized", "secret")
    ):
        return None
    manifest_row = next(
        (
            row
            for row in manifest_rows
            if isinstance(row, dict)
            and row.get("published") == candidate_path
            and row.get("published_sha256") == source_hash
            and isinstance(row.get("transformations"), list)
            and any(
                isinstance(item, str)
                and "secret" in item.lower()
                and re.search(r"(?:removed|redacted|sanitized)", item, re.I)
                for item in row["transformations"]
            )
        ),
        None,
    )
    if manifest_row is None:
        return None
    for node in ast.walk(document):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.lineno != line:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = {
            target.id if isinstance(target, ast.Name) else target.attr
            for root in targets
            for target in ast.walk(root)
            if isinstance(target, ast.Name | ast.Attribute)
        }
        value = node.value
        if (
            credential_name in names
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and re.fullmatch(
                r"[\[({<]\s*(?:removed|redacted|sanitized)"
                r"(?:[-_\s]+[A-Za-z][A-Za-z0-9]{0,23}){1,4}\s*[\])}>]",
                value.value,
                re.I,
            )
        ):
            return {
                "schema": "factory.security.source-role-archive-redaction.v1",
                "role": "archive",
                "application_authority": "UNKNOWN",
                "proof_scope": "source_bound_archive_redaction_manifest",
                "redaction": "DECLARED_SECRET_REMOVAL",
                "candidate_path": candidate_path,
                "candidate_sha256": source_hash,
                "credential_name": credential_name,
                "assignment_line": line,
                "manifest_path": "archive/manifest.json",
                "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                "documentation_path": "archive/README.md",
                "documentation_sha256": hashlib.sha256(readme).hexdigest(),
                "claim_boundary": (
                    "The captured archive manifest identifies this exact credential "
                    "assignment as sanitized; the raw finding remains and runtime "
                    "or deployment safety is unassessed."
                ),
                "supporting_sources": {
                    candidate_path: source_hash,
                    "archive/manifest.json": hashlib.sha256(manifest).hexdigest(),
                    "archive/README.md": hashlib.sha256(readme).hexdigest(),
                },
            }
    return None


def _application_configuration_hashes(class_profiles):
    """Select only bounded configuration digests from explicit class profiles."""
    from .import_context import application_configuration_names

    config_hashes = {}
    for evidence in class_profiles:
        configured = evidence.get("configuration_sha256", {})
        if not isinstance(configured, dict):
            continue
        for name, digest in configured.items():
            if (
                name in application_configuration_names((name,))
                and isinstance(digest, str)
                and len(digest) == 64
            ):
                config_hashes[name] = digest
    return config_hashes


def _captured_application_source_bytes(
    workspace, findings, bindings, source_bytes, *, capture_all_sources=False
):
    from .primitive_observation_binding import fixed_program_proof_dispositions

    program_proofs = fixed_program_proof_dispositions()
    # Byte binding is evidence substrate for every finding, never defect credit.
    paths = {finding.get("path") for finding in findings}
    for finding in findings:
        evidence = finding.get("facts", {}).get("fixture_evidence", {})
        closure = evidence.get("consumer_use_closure", {})
        if evidence.get("classification") == "APPLICATION_TEST_CREDENTIAL_ROLE":
            paths.update(
                row.get("path")
                for row in closure.get("operations", [])
                if isinstance(row, dict)
            )
    hashes = {row["path"]: row["sha256"] for row in bindings}
    whole_inventory = capture_all_sources or any(
        finding.get("facts", {}).get("disposition") in program_proofs
        or isinstance(finding.get("facts", {}).get("security_precondition"), dict)
        for finding in findings
    )
    paths.update(hashes if whole_inventory else ())
    needs_signing_sources = any(
        finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and finding.get("facts", {}).get("name") == "SECRET_KEY"
        for finding in findings
    )
    paths.update(name for name in hashes if needs_signing_sources)
    class_profiles = [
        finding.get("facts", {}).get("fixture_evidence", {})
        for finding in findings
        if finding.get("facts", {}).get("fixture_evidence", {}).get("classification")
        in {
            "APPLICATION_TEST_CREDENTIAL_ROLE",
            "PRESENTATION_METADATA_ROLE",
        }
    ]
    config_hashes = _application_configuration_hashes(class_profiles)
    if class_profiles:
        # These profiles independently recompute over the whole inventory.
        paths.update(name for name in hashes if name.endswith(".py"))
    paths.update(config_hashes)
    hashes.update(config_hashes)
    jwt_findings = [
        finding
        for finding in findings
        if finding.get("facts", {}).get("disposition")
        in {
            "PROVEN_LOCAL_CRYPTO_TEST_PRIMITIVE",
            "PROVEN_CLOSED_OPERATION_COMMAND_SYNTAX",
            "PROVEN_CLOSED_LITERAL_PICKLE_BYTES",
            "ENDPOINT_DECLARATION_ROLE_PROVEN",
        }
    ]
    if jwt_findings:
        # Revalidation uses the complete current source inventory, including
        # imported initializers and shadows; selective capture would omit risks.
        paths.update(hashes)
    captured = {}
    for relative in paths:
        if (
            not isinstance(relative, str)
            or relative.startswith(("/", "\\"))
            or ":" in relative
            or ".." in relative.replace("\\", "/").split("/")
        ):
            continue
        data = source_bytes.get(workspace / relative)
        if relative in config_hashes and not isinstance(data, bytes):
            try:
                data = (workspace / relative).read_bytes()
            except OSError:
                continue
        if (
            isinstance(data, bytes)
            and len(data) <= 1_000_000
            and sha256(data).hexdigest() == hashes.get(relative)
        ):
            captured[relative] = data
    from .audit_action_refs import _CapturedSecuritySources

    sources, bindings = _capture_archive_support(workspace, findings, captured)
    return _CapturedSecuritySources(
        captured,
        source_role_sources=sources,
        source_role_bindings=bindings,
        source_role_workspace=workspace if sources else None,
    )


def _capture_archive_support(workspace, findings, captured):
    bindings = []
    role_sources = {}
    if any(
        finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and isinstance(finding.get("path"), str)
        and finding["path"].replace("\\", "/").startswith("archive/")
        and finding.get("path") in captured
        for finding in findings
    ):
        from . import review_audits as audit

        for relative in ("archive/README.md", "archive/manifest.json"):
            try:
                data = audit._security_source_bytes(workspace, relative)
            except (OSError, audit.ReviewAuditError):
                role_sources = {}
                break
            if len(data) > 1_000_000:
                role_sources = {}
                break
            role_sources[relative] = data
        if role_sources:
            bindings = [
                {
                    "path": relative,
                    "sha256": sha256(data).hexdigest(),
                    "bytes": len(data),
                }
                for relative, data in role_sources.items()
            ]
            try:
                audit._verify_security_bindings(workspace, bindings)
            except audit.ReviewAuditError:
                role_sources = {}
    return role_sources, bindings if role_sources else ()


def _tier_report_has_archive_role_support(tier_report):
    expected = {"archive/README.md", "archive/manifest.json"}
    for row in (tier_report or {}).get("ledger", []):
        if not isinstance(row, dict):
            continue
        observation = row.get("credential_authority_observation")
        supporting = (
            observation.get("supporting_sources", [])
            if isinstance(observation, dict)
            else []
        )
        if any(
            isinstance(source, dict) and source.get("path") in expected
            for source in supporting
        ):
            return True
    return False


def _archive_support_current(audit, capture):
    support = capture.get("sources")
    bindings = capture.get("bindings")
    workspace = capture.get("workspace")
    expected = {"archive/README.md", "archive/manifest.json"}
    if not (
        isinstance(support, dict)
        and set(support) == expected
        and isinstance(bindings, list)
        and len(bindings) == len(expected)
        and isinstance(workspace, Path)
    ):
        return False
    by_path = {
        row["path"]: row
        for row in bindings
        if isinstance(row, dict) and isinstance(row.get("path"), str)
    }
    if set(by_path) != expected or not _archive_support_matches(support, by_path):
        return False
    try:
        audit._verify_security_bindings(workspace, bindings)
    except (OSError, audit.ReviewAuditError, audit.RuntimeAuditError):
        return False
    return True


def _archive_support_matches(support, bindings):
    return all(
        isinstance(raw, bytes)
        and len(raw) == bindings[path].get("bytes")
        and sha256(raw).hexdigest() == bindings[path].get("sha256")
        for path, raw in support.items()
    )


def _revalidate_scan_role_support(audit, core, captured, primitive, native_rows):
    role_capture = getattr(captured, "source_role_capture", None)
    if isinstance(role_capture, dict) and role_capture.get("sources"):
        invalidate_role_support = not _archive_support_current(audit, role_capture)
    else:
        invalidate_role_support = _tier_report_has_archive_role_support(
            core.get("finding_tier_report")
        )
    if invalidate_role_support:
        if isinstance(role_capture, dict):
            role_capture.update(sources={}, bindings=[], workspace=None)
        ledger = core.get("finding_tier_report", {}).get("ledger", [])
        raw_findings = [
            deepcopy(row["raw_finding"])
            for row in ledger
            if isinstance(row, dict) and isinstance(row.get("raw_finding"), dict)
        ]
        coverage_complete = core.get("audit_coverage", {}).get("complete") is True
        core["finding_tier_report"] = primitive.build_finding_tier_report(
            raw_findings,
            core.get("primitive_observations", []),
            core.get("sources", []),
            captured,
            coverage_state=coverage_complete,
            partition_state="VALIDATED" if coverage_complete else "INCOMPLETE",
            _verifier_native_rows=native_rows,
        )
