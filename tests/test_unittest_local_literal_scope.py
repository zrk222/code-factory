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


def configured_authority_scope(tmp_path, configuration, extra=None):
    configuration = {
        "requirements.txt": b"pytest-django>=4.5,<5\n",
        **configuration,
    }
    sources = {
        "support/__init__.py": "",
        "support/configuration.py": "SECRET_KEY = 'local-signing-material-847263'\n",
        "checks/__init__.py": "",
        "checks/test_feature.py": "def test_feature():\n    assert True\n",
        **(extra or {}),
    }
    modules, raw_sources, inventory = {}, {}, {}
    for relative, text in sources.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = text.encode()
        path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        tree = ast.parse(raw)
        tree._oracle_source_sha256 = digest
        modules[path], raw_sources[path], inventory[path] = tree, raw, digest
    for name, raw in configuration.items():
        (tmp_path / name).write_bytes(raw)
    index = application_test_index(
        tmp_path, modules, raw_sources, inventory, configuration
    )
    path = tmp_path / "support/configuration.py"
    assignment = modules[path].body[0]
    return index, path, assignment


@pytest.mark.parametrize(
    "name,raw",
    [
        ("pytest.ini", b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"),
        (".pytest.ini", b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"),
        ("tox.ini", b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"),
        ("setup.cfg", b"[tool:pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"),
        (
            "pyproject.toml",
            b'[tool.pytest.ini_options]\nDJANGO_SETTINGS_MODULE="support.configuration"\n',
        ),
        ("pytest.toml", b'[pytest]\nDJANGO_SETTINGS_MODULE="support.configuration"\n'),
        (".pytest.toml", b'[pytest]\nDJANGO_SETTINGS_MODULE="support.configuration"\n'),
    ],
)
def test_configured_settings_authority_uses_shared_collection_parser(
    tmp_path, name, raw
):
    index, path, assignment = configured_authority_scope(tmp_path, {name: raw})
    result = scope._source_test_scope_evidence(index, path, assignment, "SECRET_KEY")
    assert result is not None
    assert result["runtime_assurance"] == "INCOMPLETE"
    assert result["isolation_assurance"] == "UNASSESSED"
    assert {w["role"] for w in result["witness_sources"]} == {
        "configured_test_settings_binding",
        "declared_pytest_settings_invocation",
    }
    assert result["settings_selection"]["execution_status"] == "NOT_EXECUTED"
    assert result["settings_selection"]["provider_activation"] == "NOT_OBSERVED"


@pytest.mark.parametrize(
    "configuration",
    [
        {
            "pytest.ini": b"",
            "tox.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n",
        },
        {"pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=other.settings\n"},
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\naddopts=--ds=other.settings\n"
        },
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\naddopts=-cother.ini\n"
        },
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\naddopts=-o DJANGO_SETTINGS_MODULE=other.settings\n"
        },
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\naddopts=-oDJANGO_SETTINGS_MODULE=other.settings\n"
        },
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\ntestpaths=other\n"
        },
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\nDJANGO_CONFIGURATION=Custom\n"
        },
    ],
)
def test_configured_settings_authority_preserves_unknown_selection(
    tmp_path, configuration
):
    index, path, assignment = configured_authority_scope(tmp_path, configuration)
    assert (
        scope._source_test_scope_evidence(index, path, assignment, "SECRET_KEY") is None
    )


@pytest.mark.parametrize(
    "extra",
    [
        {
            "runtime.py": "import os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', 'support.configuration')\n"
        },
        {
            "runtime.py": "import os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', selected)\n"
        },
        {"runtime.py": "import os\nos.environ['DJANGO_SETTINGS_MODULE'] = selected\n"},
        {"runtime.py": "import os\nos.environ.update(selected)\n"},
        {"runtime.py": "import os\nos.putenv('DJANGO_SETTINGS_MODULE', selected)\n"},
        {
            "runtime.py": "import os\nos.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD'] = '1'\n"
        },
        {"runtime.py": "import pytest\npytest.main(['--ds=other.settings'])\n"},
        {"pytest_django.py": "plugin_enabled = False\n"},
        {
            "runtime.py": "from django.conf import settings\nsettings.SECRET_KEY = selected\n"
        },
        {
            "runtime.py": "from support.configuration import SECRET_KEY\nsend(SECRET_KEY)\n"
        },
        {
            "checks/test_feature.py": "from support.configuration import SECRET_KEY\ndef test_feature():\n    send(SECRET_KEY)\n"
        },
        {
            "support/configuration.py": "SECRET_KEY = 'local-signing-material-847263'\nSECRET_KEY = supplied\n"
        },
        {
            "checks/test_feature.py": "__test__ = False\ndef test_feature():\n    assert True\n"
        },
        {
            "checks/conftest.py": "def pytest_collection_modifyitems(items):\n    items.clear()\n"
        },
        {
            "checks/test_feature.py": "from django.test import override_settings\n@override_settings(SECRET_KEY='other-test-material')\ndef test_feature():\n    assert True\n"
        },
        {
            "checks/test_feature.py": "from django.test import override_settings\n@override_settings(SECRET_KEY_FALLBACKS=[])\ndef test_feature():\n    assert True\n"
        },
    ],
)
def test_configured_settings_authority_cannot_clear_counteredges(tmp_path, extra):
    index, path, assignment = configured_authority_scope(
        tmp_path,
        {"pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"},
        extra,
    )
    assert (
        scope._source_test_scope_evidence(index, path, assignment, "SECRET_KEY") is None
    )


def test_configured_settings_authority_reaches_scanner_primitive_endpoint(tmp_path):
    from factoryline.review_audits import security_scan

    configured_authority_scope(
        tmp_path,
        {"pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"},
    )
    result = security_scan(tmp_path, cache_enabled=False)
    assert not [
        r for r in result["findings"] if r["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    observations = [
        r
        for r in result.get("primitive_observations", [])
        if r["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert len(observations) == 1
    assert observations[0]["path"] == "support/configuration.py"
    assert (
        observations[0]["facts"]["fixture_evidence"]["profile"]
        == "SOURCE_BOUND_TEST_SCOPE_ONLY"
    )
    (tmp_path / "runtime.py").write_text(
        "import os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', 'support.configuration')\n"
    )
    changed = security_scan(tmp_path, cache_enabled=False)
    assert (
        len(
            [r for r in changed["findings"] if r["code"] == "SECURITY_HARDCODED_SECRET"]
        )
        == 1
    )


@pytest.mark.parametrize(
    "dependency",
    [b"", b"pytest-django; platform_system=='Linux'\n", b"-r unknown.txt\n"],
)
def test_configured_settings_authority_needs_captured_provider(tmp_path, dependency):
    index, path, assignment = configured_authority_scope(
        tmp_path,
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n",
            "requirements.txt": dependency,
        },
    )
    assert (
        scope._source_test_scope_evidence(index, path, assignment, "SECRET_KEY") is None
    )


def test_configured_settings_public_cli_keeps_incomplete_source_conservation(
    tmp_path, capsys
):
    import json

    from factoryline.cli import main

    configured_authority_scope(
        tmp_path,
        {"pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"},
    )
    code = main(
        [
            "audit",
            "security",
            "--root",
            str(tmp_path),
            "--security-only",
            "--defect-policy",
            "source-role-v3",
            "--json",
        ]
    )
    result = json.loads(capsys.readouterr().out)
    assert code in (0, 2)
    assert result["finding_conservation"]["state"] == "PASS"
    assert result["finding_conservation"]["native_rows"] == "VERIFIED"
    assert result["audit_coverage"]["complete"] is True
    assert not [
        r for r in result["findings"] if r["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    rows = result["finding_tier_report"]["ledger"]
    assert len(rows) == 1 and rows[0]["tier"] == "PROVEN_PRIMITIVE"
    assert result["defect_policy_decision"]["release_approved"] is False


def test_failed_configured_scope_does_not_pollute_legacy_scope(tmp_path, monkeypatch):
    def reject_with_partial_state(proof):
        proof.settings_selection = {"unaccepted": True}
        proof.witnesses[("ghost", (1, 0, 1, 1), "configured_test_settings_binding")] = {
            "role": "ghost"
        }
        proof.owners[("ghost", 1)] = ("ghost", None)
        return False

    monkeypatch.setattr(
        scope._SourceTestScope, "configured_settings_scope", reject_with_partial_state
    )
    result = evidence(
        tmp_path,
        unittest_source("SECRET = 'ordinary-value-9417'\nassert SECRET == SECRET"),
    )
    assert result is not None
    assert "settings_selection" not in result
    assert all(row["role"] != "ghost" for row in result["witness_sources"])


def test_configured_settings_cannot_credit_disabled_plugin(tmp_path):
    index, path, assignment = configured_authority_scope(
        tmp_path,
        {
            "pyproject.toml": b'[tool.pytest.ini_options]\nDJANGO_SETTINGS_MODULE="support.configuration"\naddopts="-p no:django"\n',
        },
    )
    assert (
        scope._source_test_scope_evidence(index, path, assignment, "SECRET_KEY") is None
    )


@pytest.mark.parametrize("identifier", ["ordinary", "API_TOKEN"])
@pytest.mark.parametrize("annotation", ["", ": str"])
@pytest.mark.parametrize(
    "literal",
    [
        "ghp_" + "a" * 20,
        "AKIA" + "A" * 16,
        "AIza" + "a" * 32,
        "sk-test-" + "a" * 16,
        "-----BEGIN PRIVATE KEY-----",
    ],
)
def test_detected_literal_reaches_role_evidence_without_identifier_loss(
    identifier, annotation, literal, monkeypatch
):
    from factoryline import context_efficiency as context, review_audits as audit

    tree = ast.parse(f"{identifier}{annotation} = {literal!r}")
    node = tree.body[0]
    target = node.targets[0] if isinstance(node, ast.Assign) else node.target
    assert audit._literal_assignment_diagnostic("consumer.py", node, target) is not None

    def forbidden(*args, **kwargs):
        raise AssertionError("candidate routing must not construct a finding")

    monkeypatch.setattr(audit, "_credential_role_witness", forbidden)
    demands = context._fixture_literal_candidates(tree, audit)
    assert demands == [(node, target, literal)]
    seen = []

    def unresolved(assignment, value):
        seen.append((assignment, value))
        return {"eligible": False, "reason": "external authority unresolved"}

    assert context._fixture_literal_evidence(tree, audit, unresolved) == {}
    assert seen == [(node, literal)]


def test_literal_candidate_routing_preserves_boundaries_and_epoch():
    from factoryline import context_efficiency as context, review_audits as audit

    tree = ast.parse(
        "ordinary = 'inert-data'\n"
        "ordinary = get_value()\n"
        "API_TOKEN = get_value()\n"
        "one = two = 'ghp_aaaaaaaaaaaaaaaaaaaa'\n"
        "holder.value = 'ghp_aaaaaaaaaaaaaaaaaaaa'\n"
    )
    assert context._fixture_literal_candidates(tree, audit) == []
    assert (
        audit._literal_credential_candidate
        in context.provider_context_cache_helpers(audit.contracts)
    )


@pytest.mark.parametrize("collected", [False, True])
def test_recognizable_external_credential_remains_active_after_shared_routing(
    tmp_path, collected
):
    from factoryline.review_audits import security_scan

    body = (
        "ordinary = 'ghp_aaaaaaaaaaaaaaaaaaaa'\n"
        "requests.get('https://example.invalid/private', "
        "headers={'Authorization': 'Bearer ' + ordinary})\n"
    )
    if collected:
        body = "def test_auth():\n" + "".join(
            "    " + line + "\n" for line in body.splitlines()
        )
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    (tmp_path / "test_consumer.py").write_text("import requests\n" + body)
    report = security_scan(tmp_path, cache_enabled=False)
    findings = [
        row for row in report["findings"] if row["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert len(findings) == 1 and findings[0]["facts"]["name"] == "ordinary"
    assert report["finding_conservation"]["state"] == "PASS"


@pytest.mark.parametrize("identifier", ["ordinary", "API_TOKEN"])
@pytest.mark.parametrize("annotation", ["", ": str"])
def test_test_scope_disposition_does_not_depend_on_credential_identifier(
    tmp_path, identifier, annotation
):
    from factoryline.review_audits import security_scan

    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    (tmp_path / "test_scope.py").write_text(
        unittest_source(
            f"{identifier}{annotation} = 'ghp_aaaaaaaaaaaaaaaaaaaa'\n"
            f"assert {identifier} == {identifier}"
        )
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert not [
        row for row in report["findings"] if row["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    rows = [
        row
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert len(rows) == 1 and rows[0]["tier"] == "PROVEN_PRIMITIVE"
    assert report["finding_conservation"]["state"] == "PASS"
