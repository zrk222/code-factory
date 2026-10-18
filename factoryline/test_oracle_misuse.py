"""Bounded, source-local recognizers for concrete ineffective test oracles."""

from __future__ import annotations

import ast


def _static_expression(node: ast.AST) -> bool:
    dynamic = (
        ast.Name,
        ast.Call,
        ast.Await,
        ast.Yield,
        ast.YieldFrom,
        ast.Attribute,
        ast.Subscript,
        ast.NamedExpr,
        ast.Lambda,
    )
    return not any(isinstance(child, dynamic) for child in ast.walk(node))


def always_truthy_assertion_reason(node: ast.AST, constant_truth) -> str | None:
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)) and any(
        not isinstance(item, ast.Starred) for item in node.elts
    ):
        return (
            "nonempty container assertion is always truthy after successful evaluation"
        )
    if isinstance(node, ast.Dict) and any(key is not None for key in node.keys):
        return "nonempty mapping assertion is always truthy after successful evaluation"
    if _static_expression(node) and constant_truth(node, {}) is True:
        return "literal assertion is statically truthy and checks no expected behavior"
    return None


def discarded_comparison_reason(statement: ast.AST) -> str | None:
    if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Compare):
        return "comparison result is discarded instead of being asserted against an expectation"
    return None


def retain_local_oracle_diagnostics(weak):
    prefixes = (
        "nonempty container assertion",
        "nonempty mapping assertion",
        "literal assertion is statically truthy",
        "comparison result is discarded",
        "local command callback with assertions is never invoked",
    )
    return [(child, reason) for child, reason in weak if reason.startswith(prefixes)]


def weak_assertion_reason(node, aliases, universal_type_check, mock_argument_oracle):
    reason = always_truthy_assertion_reason(node, _constant_truth_value)
    if reason:
        return reason
    if isinstance(node, ast.Call):
        if universal_type_check(node):
            return "universal object type check does not verify the expected behavior"
        from .review_integrity import weak_assertion_call_reason

        return weak_assertion_call_reason(node, aliases)
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        if isinstance(node.ops[0], (ast.Eq, ast.Is)) and len(node.comparators) == 1:
            left, right = node.left, node.comparators[0]
            if (
                any(isinstance(value, ast.Call) for value in ast.walk(left))
                and any(isinstance(value, ast.Call) for value in ast.walk(right))
                and ast.dump(left) == ast.dump(right)
            ):
                return "repeated invocation compares a result to itself instead of an independent expected value"
        if isinstance(node.ops[0], ast.IsNot) and any(
            isinstance(value, ast.Constant) and value.value is None
            for value in (node.left, *node.comparators)
        ):
            return "non-null assertion does not verify the expected behavior"
        if any(
            isinstance(value, ast.Attribute) and value.attr in {"called", "call_count"}
            for operand in (node.left, *node.comparators)
            for value in ast.walk(operand)
        ):
            return "mock invocation state does not verify its result or arguments"
    if getattr(node, "attr", None) in {"called", "call_count"} or mock_argument_oracle(
        node, aliases, uncalled=True
    ):
        return "mock invocation state does not verify its result or arguments"
    return None


def _constant_truth_value(node: ast.expr, _known: dict) -> bool | None:
    from .review_audits import _constant_truth_value as constant_truth

    return constant_truth(node, {})
