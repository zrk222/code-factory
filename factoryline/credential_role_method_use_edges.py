"""Exact alias value-edge helpers for method-use closure."""

import ast

from .credential_role_method_use_common import absolute_path, ancestor, span_key
from .credential_role_scope_bindings import binding_occurrences


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
            for node in ast.walk(function):
                if not isinstance(node, ast.Name) or node.id != name:
                    continue
                if isinstance(node.ctx, ast.Store) and node is not targets[0]:
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
