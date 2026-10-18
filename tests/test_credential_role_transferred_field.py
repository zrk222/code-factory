"""A constructor-renamed value retains its identity in declared descendants."""

import ast
import hashlib
import pytest

from factoryline import review_audits as audit, review_integrity as integrity
from factoryline.credential_role_paths import endpoint_role_evidence


@pytest.mark.parametrize(
    "consumer,complete", [("opaque(self.url)", False), ("requests.get(self.url)", True)]
)
def test_descendant_of_client_field_consumer_role(tmp_path, consumer, complete):
    path = tmp_path / "app.py"
    raw = (
        "import requests\n"
        "class Client:\n"
        "    def __init__(self, endpoint):\n        self.url = endpoint\n"
        "    def send(self):\n        return requests.get(self.url)\n"
        "class DerivedClient(Client):\n"
        f"    def auth(self):\n        return {consumer}\n"
        "class Adapter:\n"
        "    client_class = Client\n"
        "    ACCESS_TOKEN_URL = 'https://appleid.apple.com/auth/token'\n"
        "    def get_client(self):\n"
        "        return self.client_class(self.ACCESS_TOKEN_URL)\n"
    ).encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    integrity.bind_security_call_scopes(tree)
    rows = endpoint_role_evidence(
        tmp_path,
        {path: tree},
        {path: {}},
        {path: raw},
        {path: digest},
        audit,
        integrity,
    )
    row = next(
        r for r in rows.values() if r["declaration"]["member"] == "ACCESS_TOKEN_URL"
    )
    assert bool(row["linked_unknown_uses"]) is not complete
    assert row["value_use_audit"]["state"] == ("COMPLETE" if complete else "INCOMPLETE")


def test_selected_subclass_does_not_link_unrelated_sibling_instance(tmp_path):
    path = tmp_path / "app.py"
    raw = (
        "import requests\n"
        "class Client:\n"
        "    def __init__(self, endpoint):\n        self.url = endpoint\n"
        "    def send(self):\n        return requests.get(self.url)\n"
        "class Selected(Client):\n    pass\n"
        "class Sibling(Client):\n"
        "    def auth(self):\n        return opaque(self.url)\n"
        "class Adapter:\n    client_class = Selected\n"
        "    ACCESS_TOKEN_URL = 'https://appleid.apple.com/auth/token'\n"
        "    def get_client(self):\n"
        "        return self.client_class(self.ACCESS_TOKEN_URL)\n"
    ).encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    integrity.bind_security_call_scopes(tree)
    rows = endpoint_role_evidence(
        tmp_path,
        {path: tree},
        {path: {}},
        {path: raw},
        {path: digest},
        audit,
        integrity,
    )
    row = next(
        r for r in rows.values() if r["declaration"]["member"] == "ACCESS_TOKEN_URL"
    )
    assert row["value_use_audit"]["state"] == "COMPLETE"
    assert not row["linked_unknown_uses"]
