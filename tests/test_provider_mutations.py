"""Provider mutation and escape controls over real native graph snapshots."""

import pytest

from test_runtime_audit_integrity import _JSON_CLIENT, _json_enum_graph


_MUTATIONS = [
    'setattr(httpx.AsyncClient, "post", replacement)\n',
    'httpx.AsyncClient.__setattr__("post", replacement)\n',
    "HTTPClient = httpx.AsyncClient\nHTTPClient.post = replacement\n",
    "HTTPClient = httpx.AsyncClient\nHTTPClient.post.__code__ = replacement\n",
    "opaque(httpx.AsyncClient)\n",
    "HTTPClient = httpx.AsyncClient\nopaque(HTTPClient)\n",
    "HTTPClient = httpx.AsyncClient\nopaque({'provider': HTTPClient})\n",
    "HTTPClient = httpx.AsyncClient\nHTTPClient = choose()\n"
    "HTTPClient.post = replacement\n",
]


@pytest.mark.parametrize("mutation", _MUTATIONS)
def test_provider_mutation_or_escape_retains_json_finding(tmp_path, mutation):
    source = _JSON_CLIENT.replace("import httpx\n", "import httpx\n" + mutation, 1)
    graph = _json_enum_graph(tmp_path, client_source=source)
    assert graph.complete
    assert not graph._provider_is_unmodified("httpx", {"AsyncClient"})
    assert (
        tmp_path.resolve() / "common.py",
        3,
        "REGISTER_INVALID_PASSWORD",
    ) not in graph.witnesses()


def test_alias_tracks_every_provider_binding(tmp_path):
    mutation = (
        "HTTPClient = httpx.AsyncClient\n"
        "HTTPClient = pytest.fixture\n"
        "HTTPClient.post = replacement\n"
    )
    source = _JSON_CLIENT.replace("import httpx\n", "import httpx\n" + mutation, 1)
    graph = _json_enum_graph(tmp_path, client_source=source)
    assert graph.complete
    assert not graph._provider_is_unmodified("httpx", {"AsyncClient"})
    assert not graph._provider_is_unmodified("pytest", {"fixture"})
    assert not graph.witnesses()


@pytest.mark.parametrize(
    "source",
    [
        _JSON_CLIENT,
        _JSON_CLIENT + "\ndef accepts(client: httpx.AsyncClient):\n    return client\n",
    ],
)
def test_canonical_construction_and_annotations_remain_source_proven(tmp_path, source):
    graph = _json_enum_graph(tmp_path, client_source=source)
    assert graph.complete
    assert graph._provider_is_unmodified("httpx", {"AsyncClient"})
    assert (
        tmp_path.resolve() / "common.py",
        3,
        "REGISTER_INVALID_PASSWORD",
    ) in graph.witnesses()


@pytest.mark.parametrize("length", [20, 100])
def test_long_alias_chain_from_provider_is_an_opaque_escape(tmp_path, length):
    assignments = ["Alias0 = httpx.AsyncClient"]
    assignments.extend(f"Alias{index} = Alias{index - 1}" for index in range(1, length))
    assignments.append(f"Alias{length - 1}.post = replacement")
    mutation = "\n".join(assignments) + "\n"
    source = _JSON_CLIENT.replace("import httpx\n", "import httpx\n" + mutation, 1)
    graph = _json_enum_graph(tmp_path, client_source=source)
    assert graph.complete
    assert not graph._provider_is_unmodified("httpx", {"AsyncClient"})
    assert not graph.witnesses()
