"""Reverse lookup preserves ambiguity and final source validation."""

import ast
import hashlib
from types import SimpleNamespace

import pytest

from factoryline.credential_role_chain_memo import ClassChainMemo
from factoryline.credential_role_method_use_common import absolute_path
from factoryline.credential_role_sources import SourceSnapshotIndex


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
