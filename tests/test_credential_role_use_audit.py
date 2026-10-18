"""Real AST role derivation with clean, mixed-auth and unresolved-use controls."""

import ast
import hashlib

import pytest

from factoryline import review_audits as audit, review_integrity as integrity
from factoryline.credential_role_paths import endpoint_role_evidence

ENDPOINT = "https://appleid.apple.com/auth/token"


def _roles(tmp_path, extra=""):
    path = tmp_path / "client.py"
    raw = (
        "import requests\n"
        "class Client:\n"
        f"    ACCESS_TOKEN_URL = {ENDPOINT!r}\n"
        "    def send(self):\n"
        "        return requests.get(self.ACCESS_TOKEN_URL)\n" + extra
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
    return rows["client.py", 3, "ACCESS_TOKEN_URL"]


def test_direct_endpoint_role_has_complete_declared_value_audit(tmp_path):
    row = _roles(tmp_path)
    assert row["url_witnesses"]
    assert row["value_use_audit"]["state"] == "COMPLETE"
    assert not row["linked_unknown_uses"]


def test_known_password_use_is_retained_separately(tmp_path):
    row = _roles(
        tmp_path,
        "    def login(self):\n"
        "        return requests.get('https://example.test', "
        "auth=('user', self.ACCESS_TOKEN_URL))\n",
    )
    assert row["known_auth_uses"]


@pytest.mark.parametrize(
    "statement",
    [
        "consume(self.ACCESS_TOKEN_URL)",
        "self.ACCESS_TOKEN_URL = replacement",
        "getattr(self, field_name)",
        "getattr(self, 'ACCESS_TOKEN_URL')",
        "self.__dict__['ACCESS_TOKEN_URL'] = replacement",
        "requests.get(self.ACCESS_TOKEN_URL, auth=opaque(self.ACCESS_TOKEN_URL))",
        "alias = self.ACCESS_TOKEN_URL\n        consume(alias)",
    ],
)
def test_unresolved_or_mutated_member_cannot_pass_use_audit(tmp_path, statement):
    row = _roles(tmp_path, f"    def other(self):\n        {statement}\n")
    assert row["linked_unknown_uses"]
    assert row["value_use_audit"]["state"] == "INCOMPLETE"


@pytest.mark.parametrize(
    "statement",
    [
        "getattr(Client, 'ACCESS_TOKEN_URL')",
        "vars(Client)['ACCESS_TOKEN_URL']",
        "Client.__dict__['ACCESS_TOKEN_URL']",
    ],
)
def test_external_reflection_retains_unknown_value_use(tmp_path, statement):
    row = _roles(tmp_path, f"\nconsume({statement})\n")
    assert row["linked_unknown_uses"]
    assert row["value_use_audit"]["state"] == "INCOMPLETE"


def test_descendant_credential_use_cannot_be_omitted(tmp_path):
    row = _roles(
        tmp_path,
        "class Child(Client):\n    pass\n"
        "requests.get('https://example.test', auth=('user', Child.ACCESS_TOKEN_URL))\n",
    )
    assert row["known_auth_uses"]


def test_alias_used_as_url_and_elsewhere_is_incomplete(tmp_path):
    row = _roles(
        tmp_path,
        "    def other(self):\n"
        "        url = self.ACCESS_TOKEN_URL\n"
        "        requests.request('GET', url)\n"
        "        consume(url)\n",
    )
    assert row["linked_unknown_uses"]
    assert row["value_use_audit"]["state"] == "INCOMPLETE"
