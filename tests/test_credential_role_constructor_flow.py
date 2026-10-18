import ast
import hashlib
import pytest
from types import SimpleNamespace

from factoryline.credential_role_constructor_flow import constructor_url_hops
from factoryline.credential_role_sources import SourceSnapshotIndex, declaration_fact
from factoryline.review_integrity import bind_source_call


class _Audit:
    @staticmethod
    def _name(node):
        return ast.unparse(node)


def _snapshot(tmp_path, sources):
    snapshots, source_bytes, inventory, paths = {}, {}, {}, {}
    for name, source in sources.items():
        path = tmp_path / name
        raw = source.encode()
        tree = ast.parse(raw)
        digest = hashlib.sha256(raw).hexdigest()
        tree._oracle_source_sha256 = digest
        snapshots[path] = tree
        source_bytes[path] = raw
        inventory[path] = digest
        paths[name] = path
    return SourceSnapshotIndex(tmp_path, snapshots, source_bytes, inventory), paths


def _case(tmp_path, client_call, constructor):
    index, paths = _snapshot(
        tmp_path,
        {
            "adapter.py": """
from client import Client
class BaseAdapter:
    client_class = Client
    def get_client(self):
        return self.client_class(self.access_token_url)
class AppleAdapter(BaseAdapter):
    access_token_url = 'https://apple.example/token'
""",
            "client.py": f"""
class Client:
    def __init__(self, endpoint):
        {constructor}
    def send(self):
        url = self.endpoint
        with get_adapter().get_requests_session() as sess:
            {client_call}
""",
        },
    )
    adapter, client = paths["adapter.py"], paths["client.py"]
    classes = {
        (path, node.name): node
        for path, tree in index.snapshots.items()
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }
    imports = {adapter: {"Client": (client, "Client")}, client: {}}
    fact_node = next(
        node
        for node in ast.walk(index.snapshots[adapter])
        if isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "access_token_url"
    )
    fact = declaration_fact(index, adapter, fact_node)
    call = next(
        node
        for node in ast.walk(index.snapshots[client])
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "request"
    )
    expression = call.args[1]
    hops = constructor_url_hops(
        fact,
        client,
        call,
        expression,
        index,
        imports,
        classes,
        _Audit(),
        SimpleNamespace(bind_source_call=bind_source_call),
    )
    return hops


def test_inherited_provider_literal_flows_through_constructor_and_client_field(
    tmp_path,
):
    hops = _case(
        tmp_path,
        'sess.request("POST", url)',
        "self.endpoint = endpoint",
    )
    assert [hop["role"] for hop in hops] == [
        "declared_literal",
        "client_class_selection",
        "constructor_argument",
        "constructor_parameter",
        "constructor_field_binding",
        "canonical_http_url_consumer",
    ]
    assert all(len(hop["source_sha256"]) == 64 for hop in hops)
    assert all("https://" not in str(hop) for hop in hops)


def test_unsupported_constructor_assignment_does_not_create_flow(tmp_path):
    assert (
        _case(
            tmp_path,
            'sess.request("POST", url)',
            "self.endpoint = transform(endpoint)",
        )
        is None
    )


def test_duplicate_constructor_field_write_is_unresolved(tmp_path):
    assert (
        _case(
            tmp_path,
            'sess.request("POST", url)',
            "self.endpoint = endpoint\n        self.endpoint = other",
        )
        is None
    )


@pytest.mark.parametrize(
    "constructor",
    [
        "endpoint = replacement\n        self.endpoint = endpoint",
        "if condition:\n            self.endpoint = endpoint",
        "self.endpoint = endpoint\n        self.endpoint: str = replacement",
        "self.endpoint = endpoint\n        del self.endpoint",
    ],
)
def test_mutated_or_conditional_constructor_transfer_is_unresolved(
    tmp_path, constructor
):
    assert _case(tmp_path, 'sess.request("POST", url)', constructor) is None
