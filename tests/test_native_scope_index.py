"""Immutable native scope indexes reuse traversal without accepting rebinding."""

import ast
from test_runtime_audit_integrity import _JSON_TEST, _json_enum_graph


def test_scope_write_index_is_shared_across_names(tmp_path, monkeypatch):
    graph = _json_enum_graph(tmp_path)
    scope = graph.functions[tmp_path.resolve() / "test_api.py", "test_invalid_password"]
    graph.assignment_cache.clear()
    calls = []
    original = graph._walk

    def observed(node):
        if node is scope:
            calls.append(node)
        yield from original(node)

    monkeypatch.setattr(graph, "_walk", observed)
    response = graph._unique_name_assignment(scope, "response")
    data = graph._unique_name_assignment(scope, "data")
    assert isinstance(response, ast.Assign)
    assert isinstance(data, ast.Assign)
    assert graph._unique_name_assignment(scope, "response") is response
    assert graph._unique_name_assignment(scope, "missing") is None
    assert len(calls) == 1


def test_scope_index_retains_later_rebinding_veto(tmp_path):
    graph = _json_enum_graph(
        tmp_path, test_source=_JSON_TEST + "    response = supplied\n"
    )
    scope = graph.functions[tmp_path.resolve() / "test_api.py", "test_invalid_password"]
    assert graph._unique_name_assignment(scope, "response") is None
    assert not graph.witnesses()
