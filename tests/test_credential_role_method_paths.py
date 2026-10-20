import ast
import hashlib
from types import SimpleNamespace
from factoryline.credential_role_method_paths import method_url_hop_paths
from factoryline.credential_role_sources import SourceSnapshotIndex, declaration_fact
from factoryline.review_integrity import bind_source_call
import pytest
from factoryline.credential_role_chain_memo import ClassChainMemo
from factoryline.credential_role_method_use_audit import absolute_path


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


"""Reverse lookup preserves ambiguity and final source validation."""


def _index(root, count=3):
    raw = b"pass\n"
    digest = hashlib.sha256(raw).hexdigest()
    trees = {}
    for number in range(count):
        tree = ast.parse(raw)
        tree._oracle_source_sha256 = digest
        trees[root / f"file{number}.py"] = tree
    index = SourceSnapshotIndex(
        root, trees, dict.fromkeys(trees, raw), dict.fromkeys(trees, digest)
    )
    memo = ClassChainMemo(index, {}, {}, SimpleNamespace(_name=ast.unparse))
    index.class_chain_memo = memo
    return index, memo


def test_path_table_is_built_once_per_batch(tmp_path, monkeypatch):
    index, memo = _index(tmp_path)
    original, calls = index.relative, []

    def relative(path):
        calls.append(path)
        return original(path)

    monkeypatch.setattr(index, "relative", relative)
    with memo.analysis_batch() as batch:
        for _ in range(100):
            assert absolute_path(index, "file1.py") == tmp_path / "file1.py"
            assert absolute_path(index, "absent") is None
    assert batch.accepted and len(calls) == 3
    assert absolute_path(index, "file1.py") == tmp_path / "file1.py"
    assert len(calls) == 6


def test_duplicate_relative_paths_stay_ambiguous(tmp_path, monkeypatch):
    index, memo = _index(tmp_path)
    monkeypatch.setattr(index, "relative", lambda path: "same")
    with memo.analysis_batch() as batch:
        assert absolute_path(index, "same") is None
        assert absolute_path(index, "absent") is None
    assert batch.accepted


def test_native_bound_method_identity_is_stable(tmp_path):
    index, memo = _index(tmp_path)
    with memo.analysis_batch() as batch:
        for _ in range(100):
            assert absolute_path(index, "file1.py") == tmp_path / "file1.py"
    assert batch.accepted


def test_changed_relative_helper_rejects_batch(tmp_path, monkeypatch):
    index, memo = _index(tmp_path)
    with memo.analysis_batch() as batch:
        assert absolute_path(index, "file1.py")
        monkeypatch.setattr(index, "relative", lambda path: "changed")
        assert absolute_path(index, "file1.py") is None
    assert not batch.accepted


def test_late_source_mutation_rejects_batch(tmp_path):
    index, memo = _index(tmp_path)
    with memo.analysis_batch() as batch:
        path = absolute_path(index, "file1.py")
        index.snapshots[path].body.append(ast.Pass())
    assert not batch.accepted


@pytest.mark.parametrize("change", ["root", "keys", "inventory", "bytes"])
def test_path_cache_cannot_accept_changed_source_context(tmp_path, change):
    index, memo = _index(tmp_path)
    with memo.analysis_batch() as batch:
        path = absolute_path(index, "file1.py")
        if change == "root":
            index.root = tmp_path / "other"
        elif change == "keys":
            index.snapshots.pop(path)
        elif change == "inventory":
            index.inventory[path] = "invalid"
        else:
            index.source_bytes[path] = b"different\n"
    assert not batch.accepted


def test_none_projection_matches_old_lookup(tmp_path, monkeypatch):
    index, memo = _index(tmp_path, 1)
    monkeypatch.setattr(index, "relative", lambda path: None)
    with memo.analysis_batch() as batch:
        assert absolute_path(index, None) == tmp_path / "file0.py"
        assert absolute_path(index, "file0.py") is None
    assert batch.accepted


def test_invalid_epoch_falls_back_without_acceptance(tmp_path):
    _, memo = _index(tmp_path)
    with memo.analysis_batch() as batch:
        assert memo.source_model("bad", lambda: True, helper_epoch=lambda: None)
    assert not batch.accepted


def test_bound_epoch_replacement_cannot_reuse_cached_acceptance(tmp_path, monkeypatch):
    index, memo = _index(tmp_path)
    with memo.analysis_batch() as batch:
        assert memo.source_model(
            "bound", lambda: True, helper_epoch=lambda: (index.relative,)
        )
        monkeypatch.setattr(index, "relative", lambda path: "changed")
        assert not memo.source_model(
            "bound", lambda: False, helper_epoch=lambda: (index.relative,)
        )
    assert not batch.accepted
