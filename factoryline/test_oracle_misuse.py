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
        return (
            "comparison result is discarded instead of being asserted "
            "against an expectation"
        )
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
                return (
                    "repeated invocation compares a result to itself instead of "
                    "an independent expected value"
                )
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


def _inert_literal(node, known=None):
    if node is None:
        return True, None
    if isinstance(node, ast.Name):
        return (True, known[node.id]) if node.id in (known or {}) else (False, None)
    if isinstance(node, ast.BoolOp):
        for part in node.values:
            closed, value = _inert_literal(part, known)
            if not closed or bool(value) == isinstance(node.op, ast.Or):
                return closed, value
        return True, value
    if isinstance(node, ast.IfExp):
        closed, value = _inert_literal(node.test, known)
        return (
            _inert_literal(node.body if value else node.orelse, known)
            if closed
            else (False, None)
        )
    if (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.Eq)
    ):
        left, right = (
            _inert_literal(node.left, known),
            _inert_literal(node.comparators[0], known),
        )
        return (True, left[1] == right[1]) if left[0] and right[0] else (False, None)
    if sum(1 for _ in ast.walk(node)) > 128 or not _static_expression(node):
        return False, None
    try:
        return True, ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return False, None


def _inert_definition(node):
    if node.decorator_list:
        return False
    args = node.args
    annotations = [
        arg.annotation for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)
    ]
    annotations += [arg.annotation for arg in (args.vararg, args.kwarg) if arg]
    expressions = [*args.defaults, *args.kw_defaults, *annotations, node.returns]
    return not getattr(node, "type_params", ()) and all(
        _inert_literal(value)[0] for value in expressions
    )


def _inert_expression(node, known, helpers):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        helper = helpers.get(node.func.id)
        if node.args or node.keywords:
            return False
        if not isinstance(helper, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        args = helper.args
        return not any(
            (args.posonlyargs, args.args, args.kwonlyargs, args.vararg, args.kwarg)
        ) and (isinstance(helper, ast.AsyncFunctionDef) or _inert_suite(helper.body))
    return _inert_literal(node, known)[0]


def _inert_statement(statement, known, helpers):
    if isinstance(statement, ast.Pass):
        return True
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return _inert_definition(statement)
    if isinstance(statement, ast.Expr):
        return _inert_expression(statement.value, known, helpers)
    if isinstance(statement, ast.Assert):
        value = _inert_literal(statement.test, known)
        return value[0] and bool(value[1])
    if isinstance(statement, ast.Return):
        return _inert_literal(statement.value, known)[0]
    if isinstance(statement, (ast.Assign, ast.AnnAssign)):
        targets = getattr(statement, "targets", ()) or (statement.target,)
        return (
            all(isinstance(target, ast.Name) for target in targets)
            and _inert_literal(statement.value, known)[0]
        )
    if isinstance(statement, ast.If):
        closed, value = _inert_literal(statement.test, known)
        return closed and _inert_suite(
            statement.body if value else statement.orelse, known, helpers
        )
    if isinstance(statement, (ast.For, ast.While)):
        expression = (
            statement.iter if isinstance(statement, ast.For) else statement.test
        )
        closed, value = _inert_literal(expression, known)
        return (
            closed
            and (
                isinstance(statement, ast.While)
                or type(value) in (tuple, list, dict, set, str, bytes)
            )
            and not value
            and _inert_suite(statement.orelse)
        )
    return False


def _inert_suite(statements, known=None, helpers=None):
    known, helpers = dict(known or {}), dict(helpers or {})
    for statement in statements:
        if not _inert_statement(statement, known, helpers):
            return False
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            helpers[statement.name] = statement
            known.pop(statement.name, None)
        if (
            isinstance(statement, (ast.Assign, ast.AnnAssign))
            and statement.value is not None
        ):
            targets = getattr(statement, "targets", ()) or (statement.target,)
            for target in targets:
                known[target.id] = _inert_literal(statement.value, known)[1]
                helpers.pop(target.id, None)
        if isinstance(statement, ast.Return):
            break
        if isinstance(statement, (ast.If, ast.For, ast.While)):
            known.clear()
            helpers.clear()
    return True


def inert_test_body(node):
    """Prove body-level absence; opaque delegated work is never declared hollow."""
    return (
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and sum(1 for _ in ast.walk(node)) <= 512
        and _inert_suite(node.body)
    )


INERT_BODY_HELPERS = (
    _inert_literal,
    _inert_definition,
    _inert_expression,
    _inert_statement,
    _inert_suite,
    inert_test_body,
)
