"""Source-only finite-input admission must reject mutable capture origins."""

import pytest
from test_runtime_audit_integrity import _json_enum_graph

_CAPTURE = (
    "import pytest\nfrom common import VALUES\n"
    "@pytest.mark.parametrize('field', sorted(VALUES))\n"
    "def test_generated(field):\n"
    "    exec(f'async def test_fn({field}: int) -> None: pass', {}, {})\n"
)


def test_canonical_capture_has_source_only_proof(tmp_path):
    graph = _json_enum_graph(
        tmp_path,
        test_source=_CAPTURE,
        client_source="",
        enum_source="VALUES = {'request', 'socket'}\n",
    )
    assert graph.snapshot_complete
    assert len(graph.finite_template_inputs()) == 1


@pytest.mark.parametrize(
    "prefix",
    [
        "from builtins import globals as ns\nns()['sorted'] = altered_sort\n",
        "def poison():\n    globals()['sorted'] = altered_sort\npoison()\n",
        "def poison():\n    globals()['sorted'] = altered_sort\nalias = poison\nalias()\n",
    ],
)
def test_namespace_capture_mutations_keep_input_unknown(tmp_path, prefix):
    graph = _json_enum_graph(
        tmp_path,
        test_source=prefix + _CAPTURE,
        client_source="",
        enum_source="VALUES = {'request', 'socket'}\n",
    )
    assert not graph.finite_template_inputs()


def test_collection_hooks_keep_input_unknown(tmp_path):
    graph = _json_enum_graph(
        tmp_path,
        test_source=_CAPTURE,
        client_source="def pytest_collection_modifyitems(items): pass\n",
        enum_source="VALUES = {'request', 'socket'}\n",
    )
    assert not graph.finite_template_inputs()
