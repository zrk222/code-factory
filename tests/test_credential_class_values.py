import ast
import hashlib

import pytest

from factoryline.credential_role_constructor_provider import member_reads, source_member


def _graph(tmp_path, sources):
    from factoryline import review_audits as audit, review_integrity as integrity
    from factoryline.runtime_audit_integrity import _LiteralConsumers

    root = tmp_path.resolve()
    raw = {root / name: text.encode() for name, text in sources.items()}
    for path, data in raw.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    trees = {path: ast.parse(data) for path, data in raw.items()}
    inventory = {path: hashlib.sha256(data).hexdigest() for path, data in raw.items()}
    for path, tree in trees.items():
        tree._oracle_source_sha256 = inventory[path]
    imports = {
        path: audit._oracle_imports(root, path, tree, set(trees))
        for path, tree in trees.items()
    }
    return (
        _LiteralConsumers(
            root,
            trees,
            imports,
            audit,
            integrity,
            source_bytes=raw,
            inventory=inventory,
        ),
        trees,
        inventory,
    )


def test_source_binding_supports_imported_base_and_inherited_self_read(tmp_path):
    graph, trees, inventory = _graph(
        tmp_path,
        {
            "base.py": 'class Base:\n    ENDPOINT = "/v1"\n    def read(self):\n        return self.ENDPOINT\n',
            "child.py": "from base import Base\nclass Child(Base):\n    pass\n",
        },
    )
    child = tmp_path.resolve() / "child.py"
    source = source_member(graph, child, "Child", "ENDPOINT")
    assert source["owner_path"] == tmp_path.resolve() / "base.py"
    assert source["source_sha256"] == inventory[source["owner_path"]]
    assert source["node"] is trees[source["owner_path"]].body[0].body[0]
    result = member_reads(graph, child, "Child", "ENDPOINT")
    assert result["unresolved_reason"] is None
    assert [
        (row["owner_class"], row["method"], row["line"]) for row in result["reads"]
    ] == [("Base", "read", 4)]
    assert (
        result["reads"][0]["node"]
        is trees[source["owner_path"]].body[0].body[1].body[0].value
    )


def test_child_literal_override_and_direct_class_read_win(tmp_path):
    graph, trees, _ = _graph(
        tmp_path,
        {
            "config.py": 'class Base:\n    ENDPOINT = "/base"\nclass Child(Base):\n    ENDPOINT = "/child"\nvalue = Child.ENDPOINT\n'
        },
    )
    path = tmp_path.resolve() / "config.py"
    source = source_member(graph, path, "Child", "ENDPOINT")
    assert source["owner_class"] == "Child"
    assert source["node"] is trees[path].body[1].body[0]
    result = member_reads(graph, path, "Child", "ENDPOINT")
    assert result["unresolved_reason"] is None
    assert len(result["reads"]) == 1
    assert result["reads"][0]["node"] is trees[path].body[2].value


@pytest.mark.parametrize(
    "source",
    [
        'class Config:\n    ENDPOINT = "a"\n    ENDPOINT = "b"\n',
        'class Config:\n    ENDPOINT = "a"\nclass Config:\n    ENDPOINT = "b"\n',
        'class A:\n    ENDPOINT = "a"\nclass Config(A, A):\n    pass\n',
        'class Config(metaclass=Meta):\n    ENDPOINT = "a"\n',
        'def decorate(cls):\n    return cls\n@decorate\nclass Config:\n    ENDPOINT = "a"\n',
        'class A(B):\n    ENDPOINT = "a"\nclass B(A):\n    pass\n',
        'class Base:\n    ENDPOINT = "a"\nBase = replacement\nclass Config(Base):\n    pass\n',
        'class Config:\n    ENDPOINT = "a"\n    def __init__(self):\n        self.ENDPOINT = dynamic\n',
        'class Base:\n    ENDPOINT = "a"\n    def read(self):\n        return self.ENDPOINT\nclass Config(Base):\n    @property\n    def read(self):\n        return self.ENDPOINT\n',
    ],
)
def test_ambiguous_inheritance_or_member_binding_is_rejected(tmp_path, source):
    graph, _, _ = _graph(tmp_path, {"config.py": source})
    assert (
        source_member(graph, tmp_path.resolve() / "config.py", "Config", "ENDPOINT")
        is None
    )


def test_reflective_member_use_returns_unresolved_reason(tmp_path):
    graph, _, _ = _graph(
        tmp_path,
        {
            "config.py": 'class Config:\n    ENDPOINT = "/v1"\nsetattr(Config, dynamic_name, replacement)\n'
        },
    )
    result = member_reads(graph, tmp_path.resolve() / "config.py", "Config", "ENDPOINT")
    assert result["reads"] == []
    assert result["unresolved_reason"] is not None


@pytest.mark.parametrize("access", ["Config.__dict__['ENDPOINT']", "Config.__mro__"])
def test_class_introspection_returns_unresolved_reason(tmp_path, access):
    graph, _, _ = _graph(
        tmp_path,
        {"config.py": f'class Config:\n    ENDPOINT = "/v1"\nvalue = {access}\n'},
    )
    result = member_reads(graph, tmp_path.resolve() / "config.py", "Config", "ENDPOINT")
    assert result["reads"] == []
    assert result["unresolved_reason"] is not None


def test_assigned_dynamic_attribute_hook_rejects_source_binding(tmp_path):
    graph, _, _ = _graph(
        tmp_path,
        {
            "config.py": 'def helper(self, name):\n    return "dynamic"\nclass Config:\n    ENDPOINT = "/v1"\n    __getattribute__ = helper\n'
        },
    )
    assert (
        source_member(graph, tmp_path.resolve() / "config.py", "Config", "ENDPOINT")
        is None
    )


def test_conditional_dynamic_attribute_hook_rejects_source_binding(tmp_path):
    graph, _, _ = _graph(
        tmp_path,
        {
            "config.py": 'def helper(self, name):\n    return "dynamic"\nclass Config:\n    ENDPOINT = "/v1"\n    if condition:\n        __getattribute__ = helper\n'
        },
    )
    assert (
        source_member(graph, tmp_path.resolve() / "config.py", "Config", "ENDPOINT")
        is None
    )


@pytest.mark.parametrize(
    "shadow",
    [
        "    read: object = unsafe\n",
        "    if condition:\n        read = unsafe\n",
        "    if condition:\n        def read(self):\n            return self.ENDPOINT\n",
        "    try:\n        pass\n    except Exception as read:\n        pass\n",
        "    match value:\n        case read:\n            pass\n",
        "    pass\nChild.read = unsafe\n",
    ],
)
def test_effective_method_rebinding_blocks_inherited_member_proof(tmp_path, shadow):
    source = (
        'class Base:\n    ENDPOINT = "/v1"\n'
        "    def read(self):\n        return self.ENDPOINT\n"
        "class Child(Base):\n" + shadow
    )
    graph, _, _ = _graph(tmp_path, {"config.py": source})
    assert (
        source_member(graph, tmp_path.resolve() / "config.py", "Child", "ENDPOINT")
        is None
    )


@pytest.mark.parametrize(
    "shadow",
    [
        "    if condition:\n        ENDPOINT = dynamic\n",
        "    try:\n        pass\n    except Exception as ENDPOINT:\n        pass\n",
        "    match value:\n        case ENDPOINT:\n            pass\n",
        "    if condition:\n        def ENDPOINT(self):\n            return dynamic\n",
        "    from replacement import ENDPOINT\n",
    ],
)
def test_conditional_member_binding_blocks_literal_source_proof(tmp_path, shadow):
    source = 'class Config:\n    ENDPOINT = "/v1"\n' + shadow
    graph, _, _ = _graph(tmp_path, {"config.py": source})
    path = tmp_path.resolve() / "config.py"
    assert source_member(graph, path, "Config", "ENDPOINT") is None
    assert member_reads(graph, path, "Config", "ENDPOINT")["unresolved_reason"]


def test_imported_reflection_alias_blocks_source_member(tmp_path):
    graph, _, _ = _graph(
        tmp_path,
        {
            "config.py": 'class Config:\n    ENDPOINT = "/v1"\n',
            "consumer.py": "from builtins import setattr as write_attr\nfrom config import Config\nwrite_attr(Config, dynamic_name, replacement)\n",
        },
    )
    assert (
        source_member(graph, tmp_path.resolve() / "config.py", "Config", "ENDPOINT")
        is None
    )


def test_class_alias_escape_is_unresolved_not_a_safe_read(tmp_path):
    graph, _, _ = _graph(
        tmp_path,
        {"config.py": 'class Config:\n    ENDPOINT = "/v1"\nother = Config\n'},
    )
    result = member_reads(graph, tmp_path.resolve() / "config.py", "Config", "ENDPOINT")
    assert result["reads"] == []
    assert result["unresolved_reason"] == "class_escape_or_reflection"


def test_mixed_direct_and_transformed_member_reads_are_unresolved(tmp_path):
    graph, _, _ = _graph(
        tmp_path,
        {
            "config.py": 'class Config:\n    ENDPOINT = "/v1"\na = Config.ENDPOINT\nb = Config.ENDPOINT.strip()\n'
        },
    )
    result = member_reads(graph, tmp_path.resolve() / "config.py", "Config", "ENDPOINT")
    assert result["reads"] == []
    assert result["unresolved_reason"] == "member_transform_or_unknown_tail"


def test_ast_remains_unchanged_and_no_value_classification_is_added(tmp_path):
    graph, trees, _ = _graph(
        tmp_path,
        {
            "config.py": 'class Config:\n    ENDPOINT = "public-looking-value"\nvalue = Config.ENDPOINT\n'
        },
    )
    path = tmp_path.resolve() / "config.py"
    before = ast.dump(trees[path], include_attributes=True)
    source = source_member(graph, path, "Config", "ENDPOINT")
    reads = member_reads(graph, path, "Config", "ENDPOINT")
    assert source["node"] is trees[path].body[0].body[0]
    assert reads["reads"]
    assert "public" not in source
    assert ast.dump(trees[path], include_attributes=True) == before


_NATIVE_ENDPOINT_SOURCE = '\nimport requests\nclass Base:\n    def endpoint(self):\n        return self.ACCESS_TOKEN_URL\n    def dispatch(self, url):\n        return requests.request("GET", url)\n    def send(self):\n        return self.dispatch(self.endpoint())\nclass Child(Base):\n    ACCESS_TOKEN_URL = "https://www.arcgis.com/sharing/rest/oauth2/token"\n\nclass Other(Base):\n    ACCESS_TOKEN_URL = "https://other.example/token"\n\nclass Consumer:\n    def use_foreign(self):\n        other = Other()\n        return requests.request("GET", "https://consumer.example/resource", auth=("user", other.endpoint()))\n'


@pytest.mark.parametrize(
    "mutation, active",
    [
        ("", False),
        ("Other.ACCESS_TOKEN_URL = Child.ACCESS_TOKEN_URL\n", True),
        (
            "def mutate(typ):\n    Other.ACCESS_TOKEN_URL = typ.ACCESS_TOKEN_URL\nmutate(Child)\n",
            True,
        ),
        (
            "def steal(typ):\n    return typ.ACCESS_TOKEN_URL\nOther.ACCESS_TOKEN_URL = steal(Child)\n",
            True,
        ),
        (
            "Alias = Child\ndef steal(typ):\n    return typ.ACCESS_TOKEN_URL\nOther.ACCESS_TOKEN_URL = steal(Alias)\n",
            True,
        ),
        (
            "def steal(types):\n    return types[0].ACCESS_TOKEN_URL\nOther.ACCESS_TOKEN_URL = steal([Child])\n",
            True,
        ),
        (
            "def steal(*, typ):\n    return typ.ACCESS_TOKEN_URL\nOther.ACCESS_TOKEN_URL = steal(typ=Child)\n",
            True,
        ),
        (
            "def steal(typ=Child):\n    return typ.ACCESS_TOKEN_URL\nOther.ACCESS_TOKEN_URL = steal()\n",
            True,
        ),
        (
            "def carrier():\n    return Child\nOther.ACCESS_TOKEN_URL = carrier().ACCESS_TOKEN_URL\n",
            True,
        ),
        (
            "class Inherited(Child):\n    pass\ndef steal(typ):\n    return typ.ACCESS_TOKEN_URL\nOther.ACCESS_TOKEN_URL = steal(Inherited)\n",
            True,
        ),
        (
            'class Overridden(Child):\n    ACCESS_TOKEN_URL = "https://override.example/token"\nopaque(Overridden)\n',
            False,
        ),
        ("opaque(Base)\n", False),
        (
            'import client\ndef steal(ns):\n    return ns["Child"].ACCESS_TOKEN_URL\nOther.ACCESS_TOKEN_URL = steal(client.__dict__)\n',
            True,
        ),
        (
            'import client\ndef steal(typ):\n    return typ.ACCESS_TOKEN_URL\nOther.ACCESS_TOKEN_URL = steal(client.__getattribute__("Child"))\n',
            True,
        ),
        (
            "import client\ndef mutate(mod):\n    Other.ACCESS_TOKEN_URL = mod.Child.ACCESS_TOKEN_URL\nmutate(client)\n",
            True,
        ),
        (
            "import client\nmod = client\ndef steal(mod):\n    return mod.Child.ACCESS_TOKEN_URL\nOther.ACCESS_TOKEN_URL = steal(mod)\n",
            True,
        ),
    ],
)
def test_native_endpoint_partition_requires_closed_class_capabilities(
    tmp_path, mutation, active
):
    from factoryline.review_audits import security_scan

    source = _NATIVE_ENDPOINT_SOURCE.replace(
        "\nclass Consumer:", "\n" + mutation + "\nclass Consumer:"
    )
    (tmp_path / "client.py").write_text(source, encoding="utf-8")
    result = security_scan(tmp_path, cache_enabled=False)
    findings = [
        row
        for row in result["findings"]
        if row["code"] == "SECURITY_HARDCODED_SECRET" and row["line"] == 11
    ]
    primitives = [
        row
        for row in result.get("primitive_observations", [])
        if row["code"] == "SECURITY_HARDCODED_SECRET" and row["line"] == 11
    ]
    assert bool(findings) is active
    assert bool(primitives) is not active
    assert (findings or primitives)[0]["severity"] == "CRITICAL"


@pytest.mark.parametrize("target", ["origins", "names"])
def test_capability_memo_rejects_transitive_helper_code_mutation(
    tmp_path, monkeypatch, target
):
    from factoryline import review_audits as audit
    from factoryline import credential_role_constructor_provider as identity
    from factoryline.credential_role_constructor_provider import ClassChainMemo
    from factoryline.credential_role_constructor_provider import SourceSnapshotIndex
    from factoryline.credential_role_method_use_getter_audit import _capability_uses

    path = tmp_path / "client.py"
    data = b'class Candidate:\n    ACCESS_TOKEN_URL = "endpoint"\nopaque(Candidate)\n'
    tree = ast.parse(data)
    digest = hashlib.sha256(data).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: data}, {path: digest})
    assert index.validate(path)
    imports, classes = {path: {}}, {(path, "Candidate"): tree.body[0]}
    memo = ClassChainMemo(index, imports, classes, audit)
    index.class_chain_memo = memo

    def replacement(path, name, imports, classes):
        return set()

    def replacement_name(*args):
        return ""

    helper = identity._direct_origins if target == "origins" else audit._name
    replacement_code = (
        replacement.__code__ if target == "origins" else replacement_name.__code__
    )
    with memo.analysis_batch() as batch:
        first = _capability_uses(path, index, imports, classes, audit)
        assert first
        monkeypatch.setattr(helper, "__code__", replacement_code)
        second = _capability_uses(path, index, imports, classes, audit)
        assert second is not first
        if target == "origins":
            assert not second
    assert not batch.accepted
