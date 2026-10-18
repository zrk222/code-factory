import ast
import hashlib
from types import SimpleNamespace

import pytest

from factoryline.credential_role_method_flow import method_url_hops
from factoryline.credential_role_sources import SourceSnapshotIndex, declaration_fact
from factoryline.review_integrity import bind_source_call


class _Audit:
    @staticmethod
    def _name(node):
        return ast.unparse(node)

    @staticmethod
    def _module_security_aliases(tree):
        aliases = {}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for item in node.names:
                    aliases[item.asname or item.name.split(".")[0]] = item.name
            elif isinstance(node, ast.ImportFrom):
                for item in node.names:
                    aliases[item.asname or item.name] = f"{node.module}.{item.name}"
        return aliases


def _case(tmp_path, source, replacement=None):
    path = tmp_path / "client.py"
    raw = source.encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    snapshots, source_bytes, inventory = {path: tree}, {path: raw}, {path: digest}
    index = SourceSnapshotIndex(tmp_path, snapshots, source_bytes, inventory)
    classes = {
        (path, node.name): node for node in tree.body if isinstance(node, ast.ClassDef)
    }
    imports = {path: {}}
    aliases = {path: _Audit._module_security_aliases(tree)}
    fact_node = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and isinstance(getattr(node, "value", None), ast.Constant)
        and isinstance(node.value.value, str)
        and isinstance(
            node.targets[0] if isinstance(node, ast.Assign) else node.target, ast.Name
        )
        and (node.targets[0] if isinstance(node, ast.Assign) else node.target).id
        == "ENDPOINT"
    )
    fact = declaration_fact(index, path, fact_node)
    call = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "request"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "requests"
    )
    expression = replacement(call) if replacement else call.args[1]
    audit, integrity = _Audit(), SimpleNamespace(bind_source_call=bind_source_call)
    hops = method_url_hops(
        fact,
        path,
        call,
        expression,
        index,
        imports,
        classes,
        aliases,
        audit,
        integrity,
    )
    return hops, index, path, call, fact, imports, classes, aliases, audit, integrity


_GOOD = """
import requests
class Base:
    def endpoint(self):
        return self.ENDPOINT
    def dispatch(self, url):
        return requests.request("GET", url)
    def send(self):
        return self.dispatch(self.endpoint())
class Child(Base):
    ENDPOINT = "https://provider.example/token"
"""


def test_inherited_return_and_wrapper_parameter_reach_canonical_url(tmp_path):
    hops, *_ = _case(tmp_path, _GOOD)
    assert [row["role"] for row in hops] == [
        "declared_literal",
        "declared_member_read",
        "declared_method_return",
        "method_call",
        "method_argument_binding",
        "bound_method_parameter",
        "canonical_http_url_sink",
    ]
    assert all(len(row["source_sha256"]) == 64 for row in hops)
    assert "provider.example" not in repr(hops)


@pytest.mark.parametrize(
    "source",
    [
        _GOOD.replace(
            "self.dispatch(self.endpoint())", "self.dispatch(opaque(self.ENDPOINT))"
        ),
        _GOOD.replace(
            "def endpoint(self):\n        return self.ENDPOINT",
            "@dynamic\n    def endpoint(self):\n        return self.ENDPOINT",
        ),
        _GOOD.replace(
            "return self.ENDPOINT", 'return self.setting("URL", self.ENDPOINT)'
        ),
        _GOOD.replace(
            "self.dispatch(self.endpoint())",
            "self.dispatch(self.endpoint(), **options)",
        ),
    ],
)
def test_opaque_decorated_and_expanded_method_flows_are_unresolved(tmp_path, source):
    hops, *_ = _case(tmp_path, source)
    assert hops is None


def test_auth_slot_is_not_mistaken_for_canonical_url_argument(tmp_path):
    source = _GOOD.replace(
        'return requests.request("GET", url)',
        'return requests.request("GET", "/fixed", auth=("user", self.ENDPOINT))',
    )
    hops, *_ = _case(tmp_path, source, lambda call: call.keywords[0].value.elts[1])
    assert hops is None


def test_replaced_method_and_shadowed_parameter_do_not_flow(tmp_path):
    replaced = _GOOD.replace(
        "class Child(Base):\n    ENDPOINT",
        "class Child(Base):\n    endpoint = replacement\n    ENDPOINT",
    )
    assert _case(tmp_path / "replaced", replaced)[0] is None
    shadowed = _GOOD.replace(
        'return requests.request("GET", url)',
        'url = replacement\n        return requests.request("GET", url)',
    )
    assert _case(tmp_path / "shadowed", shadowed)[0] is None


def test_recursive_method_cycle_does_not_create_a_witness(tmp_path):
    source = _GOOD.replace(
        "return self.ENDPOINT",
        "return self.other()\n    def other(self):\n        return self.endpoint()",
    )
    assert _case(tmp_path, source)[0] is None


def test_returned_parameter_uses_the_exact_callsite_arguments(tmp_path):
    source = _GOOD.replace(
        "    def endpoint(self):\n        return self.ENDPOINT",
        "    def identity(self, value):\n        return value\n"
        "    def endpoint(self):\n        return self.ENDPOINT",
    ).replace(
        "self.dispatch(self.endpoint())",
        'self.dispatch(self.identity("https://different.example/token"))\n'
        "    def irrelevant(self):\n        return self.identity(self.ENDPOINT)",
    )
    assert _case(tmp_path, source)[0] is None


def test_cross_file_method_call_hop_keeps_callsite_source_path(tmp_path):
    root = tmp_path.resolve()
    texts = {
        "base.py": 'import requests\nclass Base:\n    def endpoint(self):\n        return self.ENDPOINT\n    def dispatch(self, url):\n        return requests.request("GET", url)\n',
        "child.py": 'from base import Base\nclass Child(Base):\n    ENDPOINT = "/token"\n    def send(self):\n        return self.dispatch(self.endpoint())\n',
    }
    snapshots, raw, inventory, paths = {}, {}, {}, {}
    for name, source in texts.items():
        path, data = root / name, source.encode()
        tree = ast.parse(data)
        digest = hashlib.sha256(data).hexdigest()
        tree._oracle_source_sha256 = digest
        snapshots[path], raw[path], inventory[path], paths[name] = (
            tree,
            data,
            digest,
            path,
        )
    index = SourceSnapshotIndex(root, snapshots, raw, inventory)
    audit = _Audit()
    classes = {
        (path, node.name): node
        for path, tree in snapshots.items()
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }
    imports = {
        paths["base.py"]: {},
        paths["child.py"]: {"Base": (paths["base.py"], "Base")},
    }
    aliases = {
        path: audit._module_security_aliases(tree) for path, tree in snapshots.items()
    }
    fact_node = snapshots[paths["child.py"]].body[1].body[0]
    fact = declaration_fact(index, paths["child.py"], fact_node)
    sink = next(
        n
        for n in ast.walk(snapshots[paths["base.py"]])
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "request"
    )
    hops = method_url_hops(
        fact,
        paths["base.py"],
        sink,
        sink.args[1],
        index,
        imports,
        classes,
        aliases,
        audit,
        SimpleNamespace(bind_source_call=bind_source_call),
    )
    method_call = next(row for row in hops if row["role"] == "method_call")
    assert method_call["path"] == "child.py"


def test_stale_source_bytes_fail_closed(tmp_path):
    state = _case(tmp_path, _GOOD)
    assert state[0]
    state[1].source_bytes[state[2]] += b"# changed after capture\n"
    assert (
        method_url_hops(
            state[4], state[2], state[3], state[3].args[1], state[1], *state[5:]
        )
        is None
    )
