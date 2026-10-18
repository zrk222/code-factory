"""Close local alias and formal-parameter uses for method-flow traces."""

import ast

from .credential_role_method_use_common import (
    absolute_path,
    ancestor,
    coordinates,
    span_key,
)
from .credential_role_method_use_edges import (
    argument_call,
    alias_uses,
    covered_value_edge,
    maps,
    url_argument,
)
from .credential_role_scope_bindings import binding_occurrences


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
        function = ancestor(
            target, index, row["path"], (ast.FunctionDef, ast.AsyncFunctionDef)
        )
        path = absolute_path(index, row["path"])
        if function is None or path is None:
            unknown.append(
                {"reason": "parameter_function_unresolved", "span": span_key(row)}
            )
            continue
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
