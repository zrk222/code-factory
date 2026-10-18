"""Adversarial controls for source-bound public credential evidence."""

from test_runtime_audit_integrity import (
    _JSON_CLIENT,
    _JSON_TEST,
    _json_enum_graph,
)


def _finding_key(tmp_path):
    return (tmp_path.resolve() / "common.py", 3, "REGISTER_INVALID_PASSWORD")


def test_json_witness_requires_unaliased_test_client(tmp_path):
    source = _JSON_TEST.replace(
        "response = await app_client.post",
        "client = app_client\n    response = await client.post",
    )
    graph = _json_enum_graph(tmp_path, test_source=source)
    assert graph.complete
    assert _finding_key(tmp_path) not in graph.witnesses()


def test_json_witness_rejects_test_client_rebinding(tmp_path):
    source = _JSON_TEST.replace(
        "response = await app_client.post",
        "app_client = supplied\n    response = await app_client.post",
    )
    graph = _json_enum_graph(tmp_path, test_source=source)
    assert graph.complete
    assert _finding_key(tmp_path) not in graph.witnesses()


def test_json_witness_rejects_mutated_httpx_provider(tmp_path):
    source = _JSON_CLIENT.replace(
        "            async with httpx.AsyncClient(",
        "            httpx.AsyncClient = supplied\n"
        "            async with httpx.AsyncClient(",
    )
    graph = _json_enum_graph(tmp_path, client_source=source)
    assert graph.complete
    assert _finding_key(tmp_path) not in graph.witnesses()


def test_closed_json_fixture_still_proves_real_client(tmp_path):
    graph = _json_enum_graph(tmp_path)
    assert graph.complete
    assert _finding_key(tmp_path) in graph.witnesses()
