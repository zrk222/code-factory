"""A producer batch must discard every derived role after source mutation."""

import ast
import hashlib
from types import SimpleNamespace

import pytest

from factoryline.credential_role_chain_memo import ClassChainMemo
from factoryline.credential_role_sources import SourceSnapshotIndex


def _memo(tmp_path):
    path = tmp_path / "client.py"
    raw = b"class Client: pass\n"
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
    index = SourceSnapshotIndex(
        tmp_path, {path: tree}, {path: raw}, {path: tree._oracle_source_sha256}
    )
    assert index.validate(path)
    imports, classes = {path: {}}, {(path, "Client"): tree.body[0]}
    audit = SimpleNamespace(_name=ast.unparse)
    return path, ClassChainMemo(index, imports, classes, audit)


@pytest.mark.parametrize("mutation", ["bytes", "ast", "inventory", "imports", "helper"])
def test_batch_exit_freshly_rejects_mutation(tmp_path, mutation):
    path, memo = _memo(tmp_path)
    with memo.analysis_batch() as batch:
        assert batch.started and not batch.accepted
        assert memo.defers_validation(
            memo.index, memo.imports, memo.classes, memo.audit
        )
        if mutation == "bytes":
            memo.index.source_bytes[path] += b"# changed\n"
        elif mutation == "ast":
            memo.index.snapshots[path].body.append(ast.Pass())
        elif mutation == "inventory":
            memo.index.inventory[path] = "0" * 64
        elif mutation == "imports":
            memo.imports[path]["Alias"] = (path, "Other")
        else:
            memo.audit._name = lambda node: "Other"
    assert not batch.accepted
    assert not memo.defers_validation(
        memo.index, memo.imports, memo.classes, memo.audit
    )


def test_batch_runs_two_fresh_checks_and_does_not_escape(tmp_path, monkeypatch):
    _, memo = _memo(tmp_path)
    calls, original = [], memo.valid

    def observed():
        calls.append(True)
        return original()

    monkeypatch.setattr(memo, "valid", observed)
    with memo.analysis_batch() as batch:
        for _ in range(20):
            assert memo.defers_validation(
                memo.index, memo.imports, memo.classes, memo.audit
            )
        with pytest.raises(ValueError, match="nested"):
            with memo.analysis_batch():
                pass
    assert batch.accepted and len(calls) == 2
    assert not memo.defers_validation(
        memo.index, memo.imports, memo.classes, memo.audit
    )


def test_relative_path_cache_is_inventory_bounded_and_tracks_root(tmp_path):
    path, memo = _memo(tmp_path)
    index = memo.index
    for _ in range(20):
        assert index.relative(path) == "client.py"
        assert index.relative(tmp_path / "uncaptured.py") == "uncaptured.py"
    assert len(index._relative_paths) == 1
    index.root = tmp_path / "different"
    assert index.relative(path) is None
    assert index._relative_paths == {}
    index.root = tmp_path
    assert index.relative(path) == "client.py"


def test_failed_batch_never_reports_acceptance(tmp_path):
    _, memo = _memo(tmp_path)
    with pytest.raises(RuntimeError, match="failed"):
        with memo.analysis_batch() as state:
            raise RuntimeError("failed")
    assert not state.accepted and memo._analysis_batch is None


def test_candidate_independent_consumer_check_is_reused(tmp_path):
    path, memo = _memo(tmp_path)
    memo.audit._module_security_aliases = lambda tree: {}
    node, calls = memo.index.snapshots[path].body[0], []

    def derive(*args):
        calls.append(args)
        return None

    for _ in range(20):
        assert memo.getter_role(node, path, memo.audit, derive) is False
    assert len(calls) == 1
    memo.audit._module_security_aliases = lambda tree: {}
    assert memo.getter_role(node, path, memo.audit, derive) is False
    assert len(calls) == 2
    memo.index.snapshots[path].body.append(ast.Pass())
    assert memo.valid() is False


def test_actual_scanner_discards_mutated_batch(tmp_path, monkeypatch):
    from factoryline import credential_endpoint_admission as admission
    from factoryline import credential_role_paths as paths
    from factoryline.review_audits import security_scan

    (tmp_path / "client.py").write_text(
        "import requests\nclass Client:\n"
        "    ACCESS_TOKEN_URL = 'https://appleid.apple.com/auth/token'\n"
        "    def send(self):\n        return requests.get(self.ACCESS_TOKEN_URL)\n"
    )
    baseline = security_scan(tmp_path, cache_enabled=False)
    assert any(
        f["code"] == "SECURITY_HARDCODED_SECRET"
        for f in baseline["primitive_observations"]
    )
    original = paths._analyze_fact

    def mutate(fact, evidence, sinks, context, publications, aliases):
        original(fact, evidence, sinks, context, publications, aliases)
        index = context[0]
        index.snapshots[index.root / fact.path].body.append(ast.Pass())

    monkeypatch.setattr(paths, "_analyze_fact", mutate)
    admission._WORKSPACES.clear()
    result = security_scan(tmp_path, cache_enabled=False)
    assert any(
        f["code"] == "SECURITY_HARDCODED_SECRET" and f["severity"] == "CRITICAL"
        for f in result["findings"]
    )
