import ast

import pytest

from factoryline import finite_capture


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("eval(value)\n", True),
        ("def handler(value):\n    return eval(value)\n", False),
        ("def handler(value=eval(source)):\n    return value\n", True),
        ("handler = lambda value: eval(value)\n", False),
        ("class Handler:\n    value = eval(source)\n", True),
        ('exec("eval(value)")\n', True),
        ("def dangerous():\n    eval(value)\ndangerous()\n", True),
        ("class Handler(Base):\n    pass\nHandler()\n", True),
    ],
)
def test_provider_risk_preserves_module_scope(source, expected):
    assert (
        finite_capture._fixed_eval_builtin_provider_risk(ast.parse(source)) is expected
    )


def test_provider_risk_reuses_parent_map_only_within_one_tree(monkeypatch):
    original = finite_capture._fixed_eval_module_scope
    calls = []

    def observe(tree, target, parents=None):
        before = len(parents)
        result = original(tree, target, parents)
        calls.append((parents, before, len(parents)))
        return result

    monkeypatch.setattr(finite_capture, "_fixed_eval_module_scope", observe)
    tree = ast.parse("def handler(value):\n" + "    eval(value)\n" * 12)
    assert finite_capture._fixed_eval_builtin_provider_risk(tree) is False
    first = calls[0][0]
    assert len(calls) == 12
    assert calls[0][1] == 0 and calls[0][2] > 0
    assert all(parents is first and before > 0 for parents, before, _ in calls[1:])
    calls.clear()
    other = ast.parse("def other(value):\n    eval(value)\n")
    assert finite_capture._fixed_eval_builtin_provider_risk(other) is False
    assert calls[0][0] is not first and calls[0][1] == 0


def test_provider_scope_cache_does_not_survive_tree_mutation():
    tree = ast.parse("def handler(value):\n    eval(value)\n")
    assert finite_capture._fixed_eval_builtin_provider_risk(tree) is False
    expression = tree.body[0].body.pop()
    tree.body[0].body.append(ast.Pass())
    tree.body.append(expression)
    assert finite_capture._fixed_eval_builtin_provider_risk(tree) is True
