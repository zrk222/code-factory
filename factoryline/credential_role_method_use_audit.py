"""Hash-bound closure audit for method-flow value uses."""

import ast

from .credential_role_method_evidence import source_current
from .credential_role_method_use_closure import audit_value_closure
from .credential_role_method_use_common import coordinates, public_span, span_key
from .credential_role_method_use_getters import audit_getter_uses

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
    traces = (
        [witness]
        if _trace(witness)
        else list(witness)
        if isinstance(witness, (list, tuple))
        else []
    )
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
                expression = _url_argument(node) if isinstance(node, ast.Call) else None
                if expression is None:
                    unknown.append(
                        {
                            "reason": "sink_url_argument_unresolved",
                            "evidence": public_span(row),
                        }
                    )
                else:
                    allowed.append(_derived_span(row, expression))
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
    audit_getter_uses(
        traces, nodes, index, unknown, context=context, related_owners=related_owners
    )
    return _result(allowed, unknown)


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
        return (
            operand
            if any(operand is child for child in expression.values)
            else None
        )
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
