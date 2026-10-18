"""Cached resolution must lose all credit if its frozen resolver changes."""

import ast
import hashlib
from types import SimpleNamespace

import pytest

from factoryline.credential_role_sources import SourceSnapshotIndex
from factoryline.credential_role_bindings import class_chain
from factoryline.credential_role_chain_memo import ClassChainMemo


def setup(tmp_path, source="class Base: pass\nclass Child(Base): pass\n"):
    path = tmp_path / "app.py"
    raw = source.encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    classes = {(path, n.name): n for n in tree.body if isinstance(n, ast.ClassDef)}
    imports = {path: {}}
    audit = SimpleNamespace(_name=ast.unparse)
    index.class_chain_memo = ClassChainMemo(index, imports, classes, audit)
    return path, index, imports, classes, audit


def test_cached_chain_is_immutable_local_and_matches_uncached(tmp_path):
    path, index, imports, classes, audit = setup(tmp_path)
    first = class_chain(index, path, "Child", imports, classes, audit)
    assert isinstance(first, tuple)
    assert len(first) == 2
    assert class_chain(index, path, "Child", imports, classes, audit) is first
    assert index.class_chain_memo.valid()
    with pytest.raises(TypeError):
        first[0] = None
    _, other, _, _, _ = setup(tmp_path)
    assert other.class_chain_memo.entries == {}


@pytest.mark.parametrize(
    "mutation",
    [
        "bytes",
        "inventory",
        "ast",
        "alias",
        "class",
        "duplicate",
        "base",
        "decorator",
        "helper",
        "membership",
    ],
)
def test_mutation_after_hit_invalidates_all_credit(tmp_path, mutation):
    path, index, imports, classes, audit = setup(tmp_path)
    assert class_chain(index, path, "Child", imports, classes, audit)
    tree = index.snapshots[path]
    if mutation == "bytes":
        index.source_bytes[path] += b"# changed"
    elif mutation == "inventory":
        index.inventory[path] = "0" * 64
    elif mutation == "ast":
        tree.body.append(ast.Pass())
    elif mutation == "alias":
        imports[path]["Other"] = (path, "Base")
    elif mutation == "class":
        classes[(path, "Child")] = ast.ClassDef(
            name="Child", bases=[], keywords=[], body=[], decorator_list=[]
        )
    elif mutation == "duplicate":
        tree.body.append(ast.parse("class Child: pass").body[0])
    elif mutation == "base":
        tree.body[1].bases = []
    elif mutation == "decorator":
        tree.body[1].decorator_list.append(ast.Name(id="opaque", ctx=ast.Load()))
    elif mutation == "helper":
        audit._name = lambda node: "Other"
    else:
        index.snapshots.pop(path)
    assert index.class_chain_memo.valid() is False


def test_different_resolver_mapping_gets_no_cached_credit(tmp_path):
    path, index, imports, classes, audit = setup(tmp_path)
    assert class_chain(index, path, "Child", imports, classes, audit)
    assert class_chain(index, path, "Child", dict(imports), classes, audit) is None
    assert class_chain(index, path, "Child", imports, dict(classes), audit) is None


@pytest.mark.parametrize(
    "source,name",
    [
        ("class A(B): pass\nclass B(A): pass\n", "A"),
        ("class A: pass\nclass A: pass\n", "A"),
        ("@opaque\nclass A: pass\n", "A"),
        ("class A(Unknown): pass\n", "A"),
    ],
)
def test_failed_resolution_stays_failed_on_repeated_queries(tmp_path, source, name):
    path, index, imports, classes, audit = setup(tmp_path, source)
    for _ in range(2):
        assert class_chain(index, path, name, imports, classes, audit) is None


def test_uncached_and_cached_resolution_agree(tmp_path):
    path, index, imports, classes, audit = setup(tmp_path)
    cached = class_chain(index, path, "Child", imports, classes, audit)
    del index.class_chain_memo
    assert tuple(class_chain(index, path, "Child", imports, classes, audit)) == cached


@pytest.mark.parametrize(
    "extra",
    [
        "",
        "    def leak(self):\n        opaque(self.ACCESS_TOKEN_URL)\n",
        "    def leak(self):\n        requests.get('https://other.example', auth=('u', self.ACCESS_TOKEN_URL))\n",
    ],
)
def test_cached_and_uncached_actual_scanner_findings_match(
    tmp_path, monkeypatch, extra
):
    from factoryline.review_audits import security_scan
    import factoryline.credential_role_chain_memo as module
    import factoryline.credential_endpoint_admission as admission

    (tmp_path / "app.py").write_text(
        "import requests\nclass Client:\n"
        "    ACCESS_TOKEN_URL = 'https://appleid.apple.com/auth/token'\n"
        "    def send(self):\n        return requests.get(self.ACCESS_TOKEN_URL)\n"
        + extra,
        encoding="utf-8",
    )
    cached = security_scan(tmp_path, cache_enabled=False)

    class Uncached(ClassChainMemo):
        def resolve(self, path, name, resolver):
            return resolver()

    monkeypatch.setattr(module, "ClassChainMemo", Uncached)
    admission._WORKSPACES.clear()
    uncached = security_scan(tmp_path, cache_enabled=False)

    def projection(report):
        return [
            (
                key,
                f["code"],
                f["path"],
                f["line"],
                f["severity"],
                f.get("facts", {}).get("disposition"),
            )
            for key in ("findings", "primitive_observations")
            for f in report.get(key, [])
        ]

    assert projection(cached) == projection(uncached)
