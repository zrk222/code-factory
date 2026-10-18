"""Focused tests for local implementation-contract binding."""

import ast

from factoryline.intent_quality import bind_project_contracts


def _bind(root, base_source, implementation_source, *, write_base=True):
    base, implementation = root / "base.py", root / "impl.py"
    if write_base:
        base.write_text(base_source, encoding="utf-8")
    implementation.write_text(implementation_source, encoding="utf-8")
    snapshots = {
        base: ast.parse(base_source),
        implementation: ast.parse(implementation_source),
    }
    contexts = {path: {} for path in snapshots}
    edges = []
    bind_project_contracts(root, snapshots, contexts, edges)
    return contexts, edges


def test_missing_imported_source_does_not_create_implementation_contract(tmp_path):
    contexts, edges = _bind(
        tmp_path,
        "class Adapter:\n    def run(self):\n        raise NotImplementedError\n",
        "from base import Adapter\n"
        "class Concrete(Adapter):\n    def run(self):\n        return 1\n",
        write_base=False,
    )

    assert not contexts[tmp_path / "base.py"].get("implementation_contract_lines")
    assert edges == []


def test_imported_symbol_mismatch_does_not_create_contract_edge(tmp_path):
    contexts, edges = _bind(
        tmp_path,
        "class RenamedAdapter:\n    def run(self):\n        raise NotImplementedError\n",
        "from base import Adapter\n"
        "class Concrete(Adapter):\n    def run(self):\n        return 1\n",
    )

    assert not contexts[tmp_path / "base.py"].get("implementation_contract_lines")
    assert edges == []
