import ast
import hashlib

from factoryline.credential_role_field_origin import resolve_declared_field_origin
from factoryline.credential_role_sources import SourceSnapshotIndex


def _index(tmp_path, files):
    root = tmp_path.resolve()
    snapshots, raw, inventory, paths = {}, {}, {}, {}
    for name, source in files.items():
        path = root / name
        data = source.encode()
        digest = hashlib.sha256(data).hexdigest()
        tree = ast.parse(data)
        tree._oracle_source_sha256 = digest
        snapshots[path], raw[path], inventory[path], paths[name] = (
            tree,
            data,
            digest,
            path,
        )
    return SourceSnapshotIndex(root, snapshots, raw, inventory), paths


def _chain(index, path, names):
    tree = index.snapshots[path]
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
    return [(path, name, classes[name]) for name in names]


def _origin(tmp_path, child, base, member="ENDPOINT"):
    index, paths = _index(tmp_path, {"classes.py": child + base})
    path = paths["classes.py"]
    return resolve_declared_field_origin(
        _chain(index, path, ["Child", "Base"]), member, index
    )


def test_inherited_field_returns_only_bound_declaration_identity(tmp_path):
    result = _origin(
        tmp_path,
        "class Child(Base):\n    pass\n",
        'class Base:\n    ENDPOINT = "hidden"\n',
    )
    assert result["state"] == "EXACT"
    assert result["origin"]["path"] == "classes.py"
    assert result["origin"]["span"][0] == 4
    assert len(result["origin"]["source_sha256"]) == 64
    assert "hidden" not in repr(result)


def test_child_override_has_distinct_origin(tmp_path):
    child = 'class Child(Base):\n    ENDPOINT = "child-value"\n'
    base = 'class Base:\n    ENDPOINT = "base-value"\n'
    result = _origin(tmp_path, child, base)
    assert result["state"] == "EXACT"
    assert result["origin"]["span"][0] == 2
    assert "value" not in repr(result)


def test_none_literal_has_source_identity_without_exposing_value(tmp_path):
    index, paths = _index(
        tmp_path,
        {"classes.py": "class Child:\n    ENDPOINT = None\n"},
    )
    path = paths["classes.py"]
    result = resolve_declared_field_origin(
        _chain(index, path, ["Child"]), "ENDPOINT", index
    )
    assert result["state"] == "EXACT"
    assert result["origin"]["span"][0] == 2
    assert set(result["origin"]) == {"path", "span", "source_sha256"}


def test_duplicate_conditional_or_dynamic_binding_is_unknown(tmp_path):
    cases = (
        'class Child(Base):\n    ENDPOINT = "one"\n    ENDPOINT = "two"\n',
        'class Child(Base):\n    if flag:\n        ENDPOINT = "one"\n',
        "class Child(Base):\n    ENDPOINT = make_endpoint()\n",
    )
    for child in cases:
        result = _origin(tmp_path, child, 'class Base:\n    ENDPOINT = "base"\n')
        assert result["state"] == "UNKNOWN"


def test_instance_mutation_and_reflection_block_inherited_origin(tmp_path):
    cases = (
        'class Child(Base):\n    def update(self):\n        self.ENDPOINT = "new"\n',
        'class Child(Base):\n    def update(self):\n        setattr(self, "ENDPOINT", "new")\n',
        "class Child(Base):\n    def __getattribute__(self, name):\n        return super().__getattribute__(name)\n",
    )
    for child in cases:
        result = _origin(tmp_path, child, 'class Base:\n    ENDPOINT = "base"\n')
        assert result["state"] == "UNKNOWN"


def test_stale_source_cannot_return_origin(tmp_path):
    source = 'class Child(Base):\n    pass\nclass Base:\n    ENDPOINT = "base"\n'
    index, paths = _index(tmp_path, {"classes.py": source})
    path = paths["classes.py"]
    index.source_bytes[path] += b"\n"
    result = resolve_declared_field_origin(
        _chain(index, path, ["Child", "Base"]), "ENDPOINT", index
    )
    assert result["state"] == "UNKNOWN"
    assert result["reason"] == "class_source_unbound"
