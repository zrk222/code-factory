"""Hash-bound closure audit for method-flow value uses."""

import ast

from .credential_role_method_evidence import source_current
from .credential_role_scope_bindings import binding_occurrences

_ROLES = set(
    "declared_literal declared_member_read unique_local_alias typing_cast_value "
    "declared_string_format_input declared_method_return declared_default_argument "
    "declared_setting_default_forward strategy_lookup_fallback nominal_strategy_annotation "
    "verified_return_preserving_decorator method_call method_argument_binding "
    "bound_method_parameter canonical_http_url_sink "
    "declared_boolean_value_choice declared_boolean_operand".split()
)


def method_value_use_audit(witness, index, *, context=None, related_owners=None):
    """Audit one trace or a collection of related traces; unknown uses stay incomplete."""
    traces = _traces(witness)
    allowed, unknown, nodes = [], [], {}
    if not traces:
        return _result([], [{"reason": "missing_or_malformed_witness"}])
    for trace in traces:
        if not _trace(trace):
            unknown.append({"reason": "malformed_trace"})
            continue
        for row in trace:
            node, error = _resolve(row, index)
            if error:
                unknown.append({"reason": error, "evidence": public_span(row)})
                continue
            nodes[span_key(row)] = node
            role = row["role"]
            if role not in _ROLES:
                unknown.append(
                    {"reason": "unsupported_role", "evidence": public_span(row)}
                )
            elif role == "declared_member_read":
                allowed.append(public_span(row))
            elif role == "canonical_http_url_sink":
                _audit_sink(row, node, allowed, unknown)
            elif (
                role == "method_call"
                and isinstance(node, ast.Call)
                and (node.args or node.keywords)
            ):
                unknown.append(
                    {
                        "reason": "getter_call_has_unverified_arguments",
                        "evidence": public_span(row),
                    }
                )
    audit_value_closure(traces, nodes, index, unknown)
    _boolean_value_choices(traces, nodes, unknown)
    from .credential_role_method_use_getter_audit import audit_getter_uses

    audit_getter_uses(
        traces, nodes, index, unknown, context=context, related_owners=related_owners
    )
    return _result(allowed, unknown)


def _traces(witness):
    if _trace(witness):
        return [witness]
    return list(witness) if isinstance(witness, (list, tuple)) else []


def _audit_sink(row, node, allowed, unknown):
    expression = _url_argument(node) if isinstance(node, ast.Call) else None
    if expression is None:
        unknown.append(
            {"reason": "sink_url_argument_unresolved", "evidence": public_span(row)}
        )
    else:
        allowed.append(_derived_span(row, expression))


def _boolean_value_choices(traces, nodes, unknown):
    for trace in traces:
        for position, row in enumerate(trace):
            role = row.get("role")
            if role == "declared_boolean_operand":
                paired = (
                    position + 1 < len(trace)
                    and trace[position + 1].get("role")
                    == "declared_boolean_value_choice"
                )
                expression = (
                    nodes.get(span_key(trace[position + 1])) if paired else None
                )
                operand = nodes.get(span_key(row))
                if not (
                    paired
                    and isinstance(expression, ast.BoolOp)
                    and any(operand is child for child in expression.values)
                ):
                    unknown.append(
                        {
                            "reason": "boolean_operand_edge_unresolved",
                            "evidence": public_span(row),
                        }
                    )
                continue
            if role != "declared_boolean_value_choice":
                continue
            expression = nodes.get(span_key(row))
            operand_row = trace[position - 1] if position else {}
            operand = (
                nodes.get(span_key(operand_row))
                if operand_row.get("role") == "declared_boolean_operand"
                else None
            )
            prior = next(
                (
                    nodes.get(span_key(item))
                    for item in reversed(trace[:position])
                    if item.get("role") == "declared_member_read"
                ),
                None,
            )
            selected = _boolean_operand(expression, operand, prior)
            if selected is None:
                unknown.append(
                    {
                        "reason": "boolean_choice_operand_unresolved",
                        "evidence": public_span(row),
                    }
                )
                continue
            if isinstance(prior, ast.Attribute) and any(
                isinstance(item, ast.Attribute)
                and item.attr == prior.attr
                and item is not prior
                for item in ast.walk(expression)
            ):
                unknown.append(
                    {
                        "reason": "boolean_choice_has_untraced_candidate_read",
                        "evidence": public_span(row),
                    }
                )


def _boolean_operand(expression, operand, prior):
    if not isinstance(expression, ast.BoolOp) or prior is None:
        return None
    if operand is not None:
        return operand if any(operand is child for child in expression.values) else None
    choices = [
        child
        for child in expression.values
        if any(prior is node for node in ast.walk(child))
    ]
    return choices[0] if len(choices) == 1 else None


def _trace(value):
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(row, dict) for row in value)
    )


def _resolve(row, index):
    if not isinstance(row, dict) or not isinstance(row.get("path"), str):
        return None, "malformed_span"
    paths = [path for path in index.snapshots if index.relative(path) == row["path"]]
    if len(paths) != 1 or not source_current(index, paths[0]):
        return None, "source_missing_or_stale"
    path = paths[0]
    if row.get("source_sha256") != index.inventory[path]:
        return None, "source_hash_mismatch"
    values = tuple(row.get(key) for key in ("line", "column", "end_line", "end_column"))
    if any(
        not isinstance(value, int) or value < (0 if i % 2 else 1)
        for i, value in enumerate(values)
    ):
        return None, "invalid_coordinates"
    matches = [
        node
        for node in ast.walk(index.snapshots[path])
        if hasattr(node, "lineno") and coordinates(node) == values
    ]
    return (
        (matches[0], None) if len(matches) == 1 else (None, "span_not_unique_ast_node")
    )


def _url_argument(call):
    if len(call.args) > 1:
        return call.args[1]
    return next(
        (keyword.value for keyword in call.keywords if keyword.arg == "url"), None
    )


def _derived_span(row, node):
    return dict(
        zip(
            (
                "path",
                "line",
                "column",
                "end_line",
                "end_column",
                "source_sha256",
                "role",
            ),
            (
                row["path"],
                *coordinates(node),
                row["source_sha256"],
                "canonical_http_url_argument",
            ),
        )
    )


def _result(allowed, unknown):
    spans = {span_key(row): row for row in allowed}
    issues = {repr(sorted(row.items())): row for row in unknown}
    return {
        "state": "COMPLETE" if spans and not issues else "INCOMPLETE",
        "allowed_member_spans": list(spans.values()),
        "unknown_uses": list(issues.values()),
    }


def audit_value_closure(traces, nodes, index, unknown):
    _bindings(traces, nodes, index, unknown)
    _parameter_uses(traces, nodes, index, unknown)
    alias_uses(traces, nodes, index, unknown)


def _bindings(traces, nodes, index, unknown):
    for trace in traces:
        for position, row in enumerate(trace):
            if row.get("role") != "method_argument_binding":
                continue
            target_row = next(
                (
                    item
                    for item in trace[position + 1 :]
                    if item.get("role") == "bound_method_parameter"
                ),
                None,
            )
            actual = nodes.get(span_key(row))
            target = nodes.get(span_key(target_row)) if target_row else None
            call = (
                argument_call(actual, index, row["path"])
                if isinstance(actual, ast.expr)
                else None
            )
            function = (
                ancestor(
                    target,
                    index,
                    target_row["path"],
                    (ast.FunctionDef, ast.AsyncFunctionDef),
                )
                if isinstance(target, ast.arg)
                else None
            )
            if not (call and function and maps(call, actual, target.arg, function)):
                unknown.append(
                    {"reason": "method_binding_not_exact", "span": span_key(row)}
                )
            elif function.args.vararg or function.args.kwarg:
                unknown.append(
                    {
                        "reason": "variadic_target_parameter",
                        "span": span_key(target_row),
                    }
                )


def _parameter_uses(traces, nodes, index, unknown):
    sinks, targets = set(), []
    for trace in traces:
        for row in trace:
            if row.get("role") == "canonical_http_url_sink":
                call = nodes.get(span_key(row))
                expression = url_argument(call) if isinstance(call, ast.Call) else None
                if expression is None:
                    unknown.append(
                        {
                            "reason": "sink_url_argument_unresolved",
                            "span": span_key(row),
                        }
                    )
                else:
                    sinks.add((row["path"], coordinates(expression)))
            elif row.get("role") == "bound_method_parameter" and isinstance(
                nodes.get(span_key(row)), ast.arg
            ):
                targets.append((row, nodes[span_key(row)]))
    for row, target in targets:
        _audit_parameter_target(row, target, sinks, traces, nodes, index, unknown)


def _audit_parameter_target(row, target, sinks, traces, nodes, index, unknown):
    function = ancestor(
        target, index, row["path"], (ast.FunctionDef, ast.AsyncFunctionDef)
    )
    path = absolute_path(index, row["path"])
    if function is None or path is None:
        unknown.append(
            {"reason": "parameter_function_unresolved", "span": span_key(row)}
        )
        return
    if binding_occurrences(function.body, target.arg):
        unknown.append(
            {
                "reason": "parameter_name_rebound",
                "path": row["path"],
                "parameter": target.arg,
            }
        )
    for node in ast.walk(function):
        if not isinstance(node, ast.Name) or node.id != target.arg:
            continue
        if isinstance(node.ctx, ast.Store):
            unknown.append(
                {
                    "reason": "parameter_rebinding",
                    "path": row["path"],
                    "line": node.lineno,
                }
            )
        elif (
            isinstance(node.ctx, ast.Load)
            and (row["path"], coordinates(node)) not in sinks
            and not covered_value_edge(node, row["path"], traces, nodes)
        ):
            unknown.append(
                {
                    "reason": "unrepresented_parameter_use",
                    "path": row["path"],
                    "line": node.lineno,
                    "column": node.col_offset,
                }
            )


def absolute_path(index, relative):
    def derive():
        rows = {}
        for path in index.snapshots:
            rows.setdefault(index.relative(path), []).append(path)
        return rows

    def epoch():
        relative_helper = index.relative
        return (
            absolute_path,
            getattr(relative_helper, "__func__", relative_helper),
            getattr(relative_helper, "__self__", None),
        )

    memo = getattr(index, "class_chain_memo", None)
    key = ("relative-source-paths", index.root, tuple(index.snapshots))
    rows = memo.source_model(key, derive, helper_epoch=epoch) if memo else derive()
    matches = rows.get(relative, ())
    return matches[0] if len(matches) == 1 and index.validate(matches[0]) else None


def ancestor(node, index, relative, types):
    path, current = absolute_path(index, relative), node
    while path and current:
        if isinstance(current, types):
            return current
        current = index.parents[path].get(id(current))
    return None


def coordinates(node):
    return (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)


def span_key(row):
    return tuple(
        row.get(key)
        for key in (
            "path",
            "line",
            "column",
            "end_line",
            "end_column",
            "source_sha256",
            "role",
        )
    )


def public_span(row):
    return dict(
        zip(
            (
                "path",
                "line",
                "column",
                "end_line",
                "end_column",
                "source_sha256",
                "role",
            ),
            span_key(row),
        )
    )


def alias_uses(traces, nodes, index, unknown):
    for trace in traces:
        for row in trace:
            if row.get("role") != "unique_local_alias":
                continue
            assignment = nodes.get(span_key(row))
            if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
                unknown.append(
                    {"reason": "alias_assignment_unresolved", "span": span_key(row)}
                )
                continue
            targets = (
                assignment.targets
                if isinstance(assignment, ast.Assign)
                else [assignment.target]
            )
            if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                unknown.append(
                    {"reason": "alias_shape_unsupported", "span": span_key(row)}
                )
                continue
            name = targets[0].id
            function = ancestor(
                assignment, index, row["path"], (ast.FunctionDef, ast.AsyncFunctionDef)
            )
            if function is None:
                unknown.append(
                    {"reason": "alias_function_unresolved", "span": span_key(row)}
                )
                continue
            bindings = binding_occurrences(function.body, name)
            if len(bindings) != 1 or bindings[0] is not targets[0]:
                unknown.append(
                    {
                        "reason": "alias_name_rebound",
                        "path": row["path"],
                        "name": name,
                    }
                )
            _audit_alias_reads(function, targets[0], name, row, traces, nodes, unknown)


def _audit_alias_reads(function, target, name, row, traces, nodes, unknown):
    for node in ast.walk(function):
        if not isinstance(node, ast.Name) or node.id != name:
            continue
        if isinstance(node.ctx, ast.Store) and node is not target:
            unknown.append(
                {
                    "reason": "alias_rebinding",
                    "path": row["path"],
                    "line": node.lineno,
                }
            )
        elif isinstance(node.ctx, ast.Load) and not covered_value_edge(
            node, row["path"], traces, nodes
        ):
            unknown.append(
                {
                    "reason": "unrepresented_alias_use",
                    "path": row["path"],
                    "line": node.lineno,
                    "column": node.col_offset,
                }
            )


def covered_value_edge(node, path, traces, nodes):
    for trace in traces:
        for row in trace:
            if row.get("path") != path:
                continue
            parent, role = nodes.get(span_key(row)), row.get("role")
            if role == "method_argument_binding" and parent is node:
                return True
            if (
                role == "unique_local_alias"
                and isinstance(parent, (ast.Assign, ast.AnnAssign))
                and parent.value is node
            ):
                return True
            if (
                role == "canonical_http_url_sink"
                and isinstance(parent, ast.Call)
                and url_argument(parent) is node
            ):
                return True
            if (
                role == "declared_method_return"
                and isinstance(parent, ast.Return)
                and parent.value is node
            ):
                return True
            if (
                role == "declared_string_format_input"
                and _format_receiver(parent) is node
            ):
                return True
            if role == "typing_cast_value" and _cast_value(parent) is node:
                return True
    return False


def _format_receiver(parent):
    if (
        not isinstance(parent, ast.Call)
        or not isinstance(parent.func, ast.Attribute)
        or parent.func.attr != "format"
    ):
        return None
    return (
        parent.func.value
        if not parent.args
        and len(parent.keywords) == 1
        and parent.keywords[0].arg is None
        else None
    )


def _cast_value(parent):
    return (
        parent.args[1]
        if isinstance(parent, ast.Call)
        and len(parent.args) == 2
        and not parent.keywords
        else None
    )


def url_argument(call):
    if len(call.args) > 1:
        return call.args[1]
    return next(
        (keyword.value for keyword in call.keywords if keyword.arg == "url"), None
    )


def argument_call(actual, index, relative):
    path, current = absolute_path(index, relative), actual
    while path and current:
        parent = index.parents[path].get(id(current))
        if isinstance(parent, ast.Call) and (
            any(value is actual for value in parent.args)
            or any(item.value is actual for item in parent.keywords)
        ):
            return parent
        current = parent
    return None


def maps(call, actual, name, function):
    positional = [*function.args.posonlyargs, *function.args.args]
    target = call.func
    if (
        not positional
        or positional[0].arg != "self"
        or not isinstance(target, ast.Attribute)
        or not isinstance(target.value, ast.Name)
        or target.value.id != "self"
        or target.attr != function.name
    ):
        return False
    for position, value in enumerate(call.args):
        if value is actual:
            return (
                position + 1 < len(positional) and positional[position + 1].arg == name
            )
    return any(item.value is actual and item.arg == name for item in call.keywords)
