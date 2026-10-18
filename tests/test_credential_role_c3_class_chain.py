"""C3 resolution is source-bound, ordered, and fail-closed."""

import ast
import hashlib
from types import SimpleNamespace

import pytest

from factoryline.credential_role_bindings import class_chain
from factoryline.credential_role_chain_memo import ClassChainMemo
from factoryline.credential_role_class_binding import effective_method
from factoryline.credential_role_sources import SourceSnapshotIndex
from factoryline.review_audits import security_scan


def _index(tmp_path, sources, imports=None, *, memo=True):
    snapshots, source_bytes, inventory, classes = {}, {}, {}, {}
    for relative, source in sources.items():
        path = tmp_path / relative
        raw = source.encode()
        tree = ast.parse(raw)
        digest = hashlib.sha256(raw).hexdigest()
        tree._oracle_source_sha256 = digest
        snapshots[path], source_bytes[path], inventory[path] = tree, raw, digest
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                classes[(path, node.name)] = node
    index = SourceSnapshotIndex(tmp_path, snapshots, source_bytes, inventory)
    import_map = {path: {} for path in snapshots}
    for relative, aliases in (imports or {}).items():
        import_map[tmp_path / relative] = {
            alias: (tmp_path / target, symbol)
            for alias, (target, symbol) in aliases.items()
        }
    audit = SimpleNamespace(_name=ast.unparse)
    if memo:
        index.class_chain_memo = ClassChainMemo(index, import_map, classes, audit)
    return index, import_map, classes, audit


def _names(chain):
    return [name for _, name, _ in chain]


def test_imported_multiple_inheritance_uses_c3_order_for_getter(tmp_path):
    index, imports, classes, audit = _index(
        tmp_path,
        {
            "bases.py": """
class Root: pass
class Left(Root):
    def endpoint(self): return self.ACCESS_TOKEN_URL
class Right(Root):
    def endpoint(self): return 'other'
""",
            "client.py": """
from bases import Left as First, Right as Second
class Client(First, Second): pass
""",
        },
        {"client.py": {"First": ("bases.py", "Left"), "Second": ("bases.py", "Right")}},
    )
    chain = class_chain(
        index, tmp_path / "client.py", "Client", imports, classes, audit
    )
    assert _names(chain) == ["Client", "Left", "Right", "Root"]
    getter = effective_method(chain, "endpoint")
    assert getter[0] == tmp_path / "bases.py"
    assert getter[1].lineno == 4
    assert index.class_chain_memo.valid()


@pytest.mark.parametrize(
    "sources,imports,name",
    [
        ({"app.py": "class A: pass\nclass Child(A, A): pass\n"}, {}, "Child"),
        (
            {"app.py": "class A(B): pass\nclass B(A): pass\n"},
            {},
            "A",
        ),
        (
            {
                "app.py": """
class X: pass
class Y: pass
class A(X, Y): pass
class B(Y, X): pass
class Child(A, B): pass
"""
            },
            {},
            "Child",
        ),
        ({"app.py": "class Child(External): pass\n"}, {}, "Child"),
        (
            {"app.py": "@opaque\nclass Base: pass\nclass Child(Base): pass\n"},
            {},
            "Child",
        ),
    ],
)
def test_invalid_or_unresolved_mro_stays_unknown(tmp_path, sources, imports, name):
    index, import_map, classes, audit = _index(tmp_path, sources, imports)
    path = tmp_path / next(iter(sources))
    assert class_chain(index, path, name, import_map, classes, audit) is None


def test_import_alias_rebinding_is_rejected(tmp_path):
    index, imports, classes, audit = _index(
        tmp_path,
        {
            "bases.py": "class Base: pass\n",
            "client.py": "from bases import Base as Alias\nAlias = object\nclass Child(Alias): pass\n",
        },
        {"client.py": {"Alias": ("bases.py", "Base")}},
    )
    assert (
        class_chain(index, tmp_path / "client.py", "Child", imports, classes, audit)
        is None
    )


def test_c3_chain_is_memoized_and_source_mutation_invalidates_credit(tmp_path):
    index, imports, classes, audit = _index(
        tmp_path,
        {"app.py": "class A: pass\nclass B: pass\nclass Child(A, B): pass\n"},
    )
    path = tmp_path / "app.py"
    first = class_chain(index, path, "Child", imports, classes, audit)
    assert first is class_chain(index, path, "Child", imports, classes, audit)
    assert _names(first) == ["Child", "A", "B"]
    assert index.class_chain_memo.valid()
    index.source_bytes[path] += b"# source changed\n"
    assert not index.class_chain_memo.valid()


def test_mro_over_sixteen_unique_classes_is_rejected(tmp_path):
    source = "class C0: pass\n" + "".join(
        f"class C{number}(C{number - 1}): pass\n" for number in range(1, 17)
    )
    index, imports, classes, audit = _index(tmp_path, {"app.py": source})
    assert (
        class_chain(index, tmp_path / "app.py", "C16", imports, classes, audit) is None
    )


def _scan_inherited_getter(tmp_path, source):
    path = tmp_path / "client.py"
    path.write_text(source, encoding="utf-8")
    return security_scan(tmp_path, cache_enabled=False)


def test_scanner_retains_auth_override_before_candidate_getter(tmp_path):
    result = _scan_inherited_getter(
        tmp_path,
        "import requests\n"
        "class FieldMixin:\n"
        "    ACCESS_TOKEN_URL = 'https://appleid.apple.com/auth/token'\n"
        "class GetterMixin:\n"
        "    def endpoint(self): return self.ACCESS_TOKEN_URL\n"
        "class AuthMixin:\n"
        "    def endpoint(self):\n"
        "        return requests.request('POST', 'https://example.test/token', "
        "auth=('client', self.ACCESS_TOKEN_URL))\n"
        "class Client(AuthMixin, FieldMixin, GetterMixin):\n"
        "    def send(self): return requests.request('POST', self.endpoint())\n",
    )
    alerts = [
        item
        for item in result["findings"]
        if item["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert alerts
    assert all(item["severity"] == "CRITICAL" for item in alerts)
