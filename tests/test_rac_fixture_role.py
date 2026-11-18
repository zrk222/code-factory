"""Prove source-only test client custody and retain unresolved controls."""

import json
import subprocess
import sys

import pytest


def test_fixture_text_model_rejects_import_identity_as_runtime_text():
    from factoryline.credential_role_identity_effects import _Value
    from factoryline.fixture_scope_values import _closed_text_binary
    import ast

    template = _Value(inert_kind="scalar", scalar_kind="text", _exact_scalar=("%s",))
    provider = _Value(
        inert_kind="scope_namespace", _exact_scalar=("unittest.TestCase",)
    )
    assert _closed_text_binary(ast.Mod(), template, provider) is None


_CLIENT = """class Client(object):
    def __init__(self, host, password):
        self.host = host
        self.password = password

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.open_session()

    def read_marker(self, record):
        return self._extract(record, "MARK")

    def _extract(self, record, field):
        if record is None:
            return
        try:
            return record.split("<%s>" % field)[1].split("</%s>" % field)[0]
        except KeyError:
            raise Exception("missing %s" % field)

    def open_session(self):
        external_authentication(self.password)
"""

_TEST = """from unittest import TestCase
from client import Client

TEST_PASSWORD = "synthetic-fixture-marker-3927"

class Checks(TestCase):
    def setUp(self):
        self.client = Client("127.0.0.1", TEST_PASSWORD)

    def test_marker(self):
        self.assertEqual(self.client.read_marker("<MARK>yes</MARK>"), "yes")
"""


@pytest.mark.parametrize(
    "counterexample",
    [
        None,
        "authentication",
        "context_manager",
        "receiver_escape",
        "fixture_field_read",
        "production_import",
        "duplicate_literal",
        "unmodeled_loader",
        "custom_dispatch",
        "descriptor",
        "missing_host_proof",
        "teardown",
    ],
)
def test_unused_unittest_client_credential_is_refuted_by_cli(tmp_path, counterexample):
    test_source = _TEST
    extra = {
        "authentication": "        self.client.open_session()\n",
        "context_manager": "        with self.client:\n            pass\n",
        "receiver_escape": "        outside_fixture(self.client)\n",
        "fixture_field_read": "        self.assertTrue(self.client.password)\n",
        "teardown": "\n    def tearDown(self):\n        self.client.open_session()\n",
        "unmodeled_loader": "\ndef load_tests(loader, tests, pattern):\n    return tests\n",
        "custom_dispatch": "\n    def doCleanups(self):\n        self.client.open_session()\n",
    }
    test_source += extra.get(counterexample, "")
    if counterexample == "missing_host_proof":
        test_source = test_source.replace("127.0.0.1", "fixture.invalid")
    if counterexample == "production_import":
        (tmp_path / "production.py").write_text(
            "import test_client\n", encoding="utf-8"
        )
    if counterexample == "duplicate_literal":
        (tmp_path / "production.py").write_text(
            'VALUE = "synthetic-fixture-marker-3927"\n', encoding="utf-8"
        )
    client = _CLIENT
    if counterexample == "descriptor":
        client = (
            "from functools import cached_property\n\n"
            + client
            + "\n    @cached_property\n    def marker(self):\n"
            + '        captured = self.password\n        return "yes"\n'
        )
        test_source = test_source.replace(
            'self.client.read_marker("<MARK>yes</MARK>")', "self.client.marker"
        )
    (tmp_path / "client.py").write_text(client, encoding="utf-8")
    (tmp_path / "test_client.py").write_text(test_source, encoding="utf-8")
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "factoryline.cli",
            "audit",
            "security",
            "--root",
            str(tmp_path),
            "--security-only",
            "--defect-policy",
            "source-role-v3",
            "--json",
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    report = json.loads(process.stdout)
    assert report["finding_conservation"]["state"] == "PASS"
    assert report["finding_conservation"]["native_rows"] == "VERIFIED"
    assert report["audit_coverage"]["complete"] is True
    assert bool(report["finding_tier_report"]["ledger"]) is bool(counterexample)
    refuted = report.get("refuted_security_observations", [])
    if counterexample is None:
        assert refuted[0]["facts"]["fixture_evidence"]["source_hypothesis"] == (
            "SOURCE_TEST_CLIENT_CREDENTIAL_UNUSED"
        )
    else:
        assert not refuted
