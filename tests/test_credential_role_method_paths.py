import ast
import hashlib
from types import SimpleNamespace

from factoryline.credential_role_method_paths import method_url_hop_paths
from factoryline.credential_role_sources import SourceSnapshotIndex, declaration_fact
from factoryline.review_integrity import bind_source_call


class _Audit:
    @staticmethod
    def _name(node):
        return ast.unparse(node)

    @staticmethod
    def _module_security_aliases(tree):
        return {
            item.asname or item.name.split(".")[0]: item.name
            for statement in tree.body
            if isinstance(statement, ast.Import)
            for item in statement.names
        }


def test_all_matching_callers_remain_separate_exact_paths(tmp_path, monkeypatch):
    source = """import requests
class Client:
    ENDPOINT = "https://service.example/token"
    def identity(self, value):
        alias = value
        return alias
    def dispatch(self, url):
        return requests.request("GET", url)
    def send(self):
        self.dispatch(self.identity(self.ENDPOINT))
        self.dispatch(self.ENDPOINT)
"""
    path = (tmp_path / "client.py").resolve()
    raw = source.encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(
        tmp_path.resolve(), {path: tree}, {path: raw}, {path: digest}
    )
    owner = next(node for node in tree.body if isinstance(node, ast.ClassDef))
    classes = {(path, owner.name): owner}
    imports = {path: {}}
    audit = _Audit()
    from factoryline import credential_role_method_paths as path_module
    from factoryline import credential_role_forwarding_decorator as forwarding
    from factoryline.credential_role_chain_memo import ClassChainMemo

    index.class_chain_memo = ClassChainMemo(index, imports, classes, audit)
    calls = []
    original = forwarding.method_rows

    def count_method_rows(*args):
        calls.append(1)
        return original(*args)

    monkeypatch.setattr(path_module, "method_rows", count_method_rows)
    fact = declaration_fact(index, path, owner.body[0])
    sink = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "request"
    )
    aliases = {path: audit._module_security_aliases(tree)}
    result = method_url_hop_paths(
        fact,
        path,
        sink,
        sink.args[1],
        index,
        imports,
        classes,
        aliases,
        audit,
        SimpleNamespace(bind_source_call=bind_source_call),
    )
    assert result["state"] == "BRANCH_ENUMERATION_COMPLETE"
    assert len(result["paths"]) == 2
    assert all(
        {row["role"] for row in route}.issuperset(
            {"method_argument_binding", "bound_method_parameter"}
        )
        for route in result["paths"]
    )
    spans = {
        (row["line"], row["column"])
        for route in result["paths"]
        for row in route
        if row["role"] == "method_argument_binding"
    }
    assert len(spans) >= 2
    assert len(calls) == 1
    values = iter((True, False))
    monkeypatch.setattr(index.class_chain_memo, "valid", lambda: next(values))
    stale = method_url_hop_paths(
        fact,
        path,
        sink,
        sink.args[1],
        index,
        imports,
        classes,
        aliases,
        audit,
        SimpleNamespace(bind_source_call=bind_source_call),
    )
    assert stale == {
        "state": "INCOMPLETE",
        "paths": [],
        "reason": "snapshot_revalidation_failed",
    }
