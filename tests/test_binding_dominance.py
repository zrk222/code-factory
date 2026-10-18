"""Source-only ordering controls for branch-local response evidence."""

import ast
import textwrap

import pytest

from factoryline.credential_role_flows import binding_dominates


@pytest.mark.parametrize(
    "body,expected",
    [
        ("data = {}\nassert data", True),
        ("if condition:\n    data = {}\n    assert data", True),
        ("data = {}\nif condition:\n    assert data", True),
        ("if condition:\n    pass\nelse:\n    data = {}\n    assert data", True),
        ("if condition:\n    data = {}\nassert data", False),
        ("if condition:\n    data = {}\nelse:\n    assert data", False),
        ("assert data\ndata = {}", False),
        ("for item in items:\n    data = {}\nassert data", False),
        ("while condition:\n    data = {}\nassert data", False),
        ("try:\n    data = {}\nexcept Exception:\n    pass\nassert data", False),
        ("try:\n    data = {}\n    assert data\nexcept Exception:\n    pass", True),
        ("data = {}\ndef inner():\n    assert data", False),
        ("def inner():\n    data = {}\nassert data", False),
        ("data = {}\nclass Inner:\n    assert data", False),
    ],
)
def test_binding_order_requires_the_same_execution_branch(body, expected):
    tree = ast.parse("def outer():\n" + textwrap.indent(body, "    "))
    scope = tree.body[0]
    parents = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    binding = next(node for node in ast.walk(scope) if isinstance(node, ast.Assign))
    use = next(node for node in ast.walk(scope) if isinstance(node, ast.Assert))
    before = ast.dump(tree, include_attributes=True)
    assert binding_dominates(binding, use, parents, scope) is expected
    assert ast.dump(tree, include_attributes=True) == before


def test_assignment_cannot_prove_its_own_rhs_and_malformed_parents_fail_closed():
    tree = ast.parse("def outer():\n    data = source(data)\n")
    scope = tree.body[0]
    binding = scope.body[0]
    use = binding.value
    parents = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    assert not binding_dominates(binding, use, parents, scope)
    assert not binding_dominates(binding, use, {}, scope)
    assert not binding_dominates(binding, use, parents, tree)
    assert not binding_dominates(binding, use, {id(use): use}, scope)
