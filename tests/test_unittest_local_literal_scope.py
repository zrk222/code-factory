"""Local literal routing uses closed unittest consumers, never fixture spelling."""

import ast
import hashlib

import pytest

from factoryline import credential_role_identity_effects as effects
from factoryline import credential_role_method_use_getter_audit as scope
from factoryline.mock_fixture_provenance import application_test_index


def captured_scope(tmp_path, source, filename="test_scope.py"):
    path = tmp_path / filename
    raw = source.encode()
    path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = digest
    index = application_test_index(
        tmp_path,
        {path: tree},
        {path: raw},
        {path: digest},
        {"pytest.ini": b"[pytest]\n"},
    )
    assignment = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )
    return index, path, assignment


def evidence(tmp_path, source, filename="test_scope.py"):
    index, path, assignment = captured_scope(tmp_path, source, filename)
    return scope._source_test_scope_evidence(index, path, assignment, "SECRET")


def unittest_source(body, extra="", method="test_value"):
    return (
        "from unittest import TestCase\n"
        "class Checks(TestCase):\n"
        f"    def {method}(self):\n"
        + "".join("        " + line + "\n" for line in body.splitlines())
        + extra
    )


@pytest.mark.parametrize("literal", ["fixture-marker-4791", "ordinary-value-9417"])
def test_closed_unittest_local_literal_has_source_scope_only(tmp_path, literal):
    result = evidence(
        tmp_path,
        unittest_source(f"SECRET = {literal!r}\nassert SECRET == SECRET"),
    )
    assert result is not None
    assert result["profile"] == "SOURCE_BOUND_TEST_SCOPE_ONLY"
    assert result["runtime_assurance"] == "INCOMPLETE"
    assert result["isolation_assurance"] == "UNASSESSED"
    assert result["target_execution"] == "not_performed"
    assert any(
        row["role"] == "declared_test_invocation" for row in result["witness_sources"]
    )


@pytest.mark.parametrize("custom", ["run", "__getattribute__", "setUpClass"])
def test_custom_unittest_owner_cannot_obtain_local_scope_proof(tmp_path, custom):
    source = unittest_source(
        "SECRET = 'fixture-marker-4791'\nassert SECRET == SECRET",
        f"    def {custom}(self):\n        pass\n",
    )
    assert evidence(tmp_path, source) is None


@pytest.mark.parametrize("method", ["setUp", "test_value"])
def test_local_value_flows_through_setup_helper_and_teardown(tmp_path, method):
    source = unittest_source(
        "SECRET = 'ordinary-value-9417'\nself.value = self.echo(SECRET)",
        "    def echo(self, value):\n        return value\n"
        "    def tearDown(self):\n        self.value = None\n",
        method,
    )
    if method == "setUp":
        source += "    def test_value(self):\n        assert self.value == self.value\n"
    assert evidence(tmp_path, source) is not None


@pytest.mark.parametrize("filename", ["test_fixture.py", "consumer.py"])
@pytest.mark.parametrize(
    "suffix",
    [
        "        send(SECRET)\n",
        "    def tearDown(self):\n        send(self.value)\n",
    ],
)
def test_fixture_names_and_owner_do_not_close_unknown_consumers(
    tmp_path, filename, suffix
):
    source = unittest_source("SECRET = 'fixture-marker-4791'\nself.value = SECRET")
    assert evidence(tmp_path, source + suffix, filename) is None


@pytest.mark.parametrize(
    "body",
    [
        "SECRET = 'fixture-marker-4791'\nSECRET = supplied\nself.assertTrue(SECRET)",
        "SECRET = other = 'fixture-marker-4791'\nself.assertTrue(SECRET)",
        "if flag:\n    SECRET = 'fixture-marker-4791'\nself.assertTrue(SECRET)",
    ],
)
def test_unittest_route_retains_direct_single_binding_requirement(tmp_path, body):
    assert evidence(tmp_path, unittest_source(body)) is None


@pytest.mark.parametrize("method", ["helper", "setUpClass"])
def test_non_invocation_method_does_not_gain_owner_scope(tmp_path, method):
    source = unittest_source(
        "SECRET = 'fixture-marker-4791'\nassert SECRET == SECRET",
        "    def test_value(self):\n        pass\n",
        method,
    )
    assert evidence(tmp_path, source) is None


def test_existing_pytest_local_literal_route_is_preserved(tmp_path):
    source = (
        "def test_value():\n"
        "    SECRET = 'ordinary-value-9417'\n"
        "    assert SECRET == SECRET\n"
    )
    assert evidence(tmp_path, source) is not None


@pytest.mark.parametrize(
    "extra",
    [
        "    def setUp(self):\n        install_provider()\n",
        "    def tearDown(self):\n        install_provider()\n",
        "    def test_other(self):\n        install_provider()\n",
    ],
)
def test_all_owner_invocations_must_close(tmp_path, extra):
    source = unittest_source(
        "SECRET = 'ordinary-value-9417'\nassert SECRET == SECRET", extra
    )
    assert evidence(tmp_path, source) is None


def test_existing_raw_unittest_assertion_contract_is_preserved(tmp_path):
    source = unittest_source(
        "SECRET = 'ordinary-value-9417'\nself.assertEqual(SECRET, SECRET)"
    )
    assert evidence(tmp_path, source) is None


def test_stale_captured_declaration_cannot_gain_scope_proof(tmp_path):
    source = unittest_source("SECRET = 'ordinary-value-9417'\nassert SECRET == SECRET")
    index, path, assignment = captured_scope(tmp_path, source)
    index["source"].source_bytes[path] += b"\nmutate()\n"
    assert scope._source_test_scope_evidence(index, path, assignment, "SECRET") is None


def test_local_route_identity_tracks_actual_exercise_method(monkeypatch):
    original = scope._SourceTestScope.exercise
    before = effects.security_value_helper_epoch()
    assert original in before

    def replacement(self):
        return False

    monkeypatch.setattr(scope._SourceTestScope, "exercise", replacement)
    after = effects.security_value_helper_epoch()
    assert replacement in after and original not in after
