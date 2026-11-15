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
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    index = application_test_index(
        tmp_path, modules, raw_sources, inventory, configuration
    )
    path = tmp_path / "support/configuration.py"
    assignment = modules[path].body[0]
    return index, path, assignment


@pytest.mark.parametrize(
    "tox,config,expected",
    [
        (
            b"[testenv]\nsetenv=\n    DJANGO_SETTINGS_MODULE=environment.settings\n"
            b"commands=pytest --ds=support.configuration\n",
            b"[pytest]\nDJANGO_SETTINGS_MODULE=config.settings\n",
            "support.configuration",
        ),
        (
            b"[testenv]\nsetenv=\n    DJANGO_SETTINGS_MODULE=support.configuration\n"
            b"commands=pytest\n",
            b"[pytest]\nDJANGO_SETTINGS_MODULE=config.settings\n",
            "support.configuration",
        ),
        (
            b"[testenv]\nsetenv=\n    DJANGO_SETTINGS_MODULE=environment.settings\n"
            b"commands=pytest\n",
            b"[pytest]\nDJANGO_SETTINGS_MODULE=config.settings\n"
            b"addopts=--ds=support.configuration\n",
            "support.configuration",
        ),
    ],
)
def test_captured_tox_settings_authority_follows_effective_invocation(
    tmp_path, tox, config, expected
):
    index, path, assignment = configured_authority_scope(
        tmp_path, {"pytest.ini": config, "tox.ini": tox}
    )
    result = scope._source_test_scope_evidence(index, path, assignment, "SECRET_KEY")
    assert result is not None
    selection = result["settings_selection"]
    from factoryline.pytest_collection_audit import (
        _pytest_captured_invocation_options,
        captured_pytest_configuration,
    )

    config_selection = captured_pytest_configuration({"pytest.ini": config})
    effective = _pytest_captured_invocation_options(
        {"pytest.ini": config, "tox.ini": tox}, config_selection["options"]
    )
    assert effective["DJANGO_SETTINGS_MODULE"] == expected
    assert selection["execution_status"] == "NOT_EXECUTED"
    assert selection["provider_activation"] == "NOT_OBSERVED"
    assert selection["invocation"]["profile"] == "CAPTURED_LITERAL_COMMANDS_ONLY"


@pytest.mark.parametrize(
    "tox",
    [
        # Named testenvs with distinct authorities leave selection ambiguous.
        b"[testenv:one]\ncommands=pytest --ds=support.configuration\n"
        b"[testenv:two]\ncommands=pytest --ds=other.settings\n",
        # Pass-through selectors can change pytest's runtime environment.
        b"[testenv]\npassenv=PYTEST_ADDOPTS\ncommands=pytest\n",
        b"[testenv]\npassenv=PYTEST_*\ncommands=pytest\n",
        b"[testenv]\npassenv=DJANGO_SETTINGS_*\ncommands=pytest\n",
        # Dynamic substitution and unmodeled command targets/selectors are open.
        b"[testenv]\ncommands=pytest --ds={env:SETTINGS}\n",
        b"[testenv]\ncommands=pytest checks/test_feature.py\n",
        b"[testenv]\ncommands=pytest -k feature\n",
        b"[testenv]\ncommands=pytest -m integration\n",
        # cwd and command hooks can affect imports or execute other setup.
        b"[testenv]\nchangedir=checks\ncommands=pytest\n",
        b"[testenv]\ncommands_pre=python prepare.py\ncommands=pytest\n",
        b"[testenv]\ncommands_post=python cleanup.py\ncommands=pytest\n",
        # Unmodeled install behavior and path replacement can change authority.
        b"[testenv]\ninstall_command=python -m pip install {opts} {packages}\ncommands=pytest\n",
        b"[testenv]\nsetenv=PATH=/custom/tools\ncommands=pytest\n",
        # Malformed settings options cannot prove the selected module.
        b"[testenv]\ncommands=pytest --ds\n",
        b"[testenv]\ncommands=pytest --ds=../settings\n",
        # Default positional arguments are caller-controlled and unresolved.
        b"[testenv]\ncommands=pytest {posargs}\n",
    ],
)
def test_captured_tox_settings_authority_rejects_unmodeled_invocations(tmp_path, tox):
    index, path, assignment = configured_authority_scope(
        tmp_path,
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n",
            "tox.ini": tox,
        },
    )
    assert (
        scope._source_test_scope_evidence(index, path, assignment, "SECRET_KEY") is None
    )


@pytest.mark.parametrize(
    "name,raw",
    [
        ("pytest.ini", b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"),
        (".pytest.ini", b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"),
        (
            "tox.ini",
            b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"
            b"[testenv]\ncommands=pytest\n",
        ),
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
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\naddopts=-k selected\n"
        },
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\naddopts=-m integration\n"
        },
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\naddopts=--ignore=checks/private\n"
        },
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\naddopts=--deselect=checks/test_private.py::test_value\n"
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


def test_pytest_effect_projection_shares_general_and_tox_reporting_grammar():
    import shlex

    from factoryline.pytest_collection_audit import (
        _pytest_effective_settings_options,
        _pytest_tox_arguments_closed,
    )

    addopts = "-ra -v --strict-markers --junitxml=reports/results.xml"
    effective = _pytest_effective_settings_options(
        {"DJANGO_SETTINGS_MODULE": "support.configuration", "addopts": addopts}
    )
    assert effective["DJANGO_SETTINGS_MODULE"] == "support.configuration"
    assert _pytest_tox_arguments_closed(shlex.split(addopts))


def captured_test_profile(
    tmp_path,
    *,
    workflow,
    script=None,
    extra_sources=None,
    other_workflows=None,
    reverse_inputs=False,
    extra_configs=None,
    unbound_config=None,
):
    from factoryline.pytest_collection_audit import captured_test_invocation_profile

    workflow_path = ".github/workflows/ci.yml"
    workflow_inputs = {workflow_path: workflow.encode()}
    workflow_inputs.update(
        {name: text.encode() for name, text in (other_workflows or {}).items()}
    )
    if reverse_inputs:
        workflow_inputs = dict(reversed(list(workflow_inputs.items())))
    invocation_sources = dict(workflow_inputs)
    modules, source_bytes, inventory = {}, {}, {}
    configuration_bytes = {**workflow_inputs, **(extra_configs or {})}
    identities = {
        name: {
            "path": name,
            "state": "read",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
        for name, raw in configuration_bytes.items()
        if name != unbound_config
    }
    if script is not None:
        script_path = tmp_path / "runtests.py"
        raw = script.encode()
        script_path.write_bytes(raw)
        tree = ast.parse(raw)
        tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
        modules[script_path], source_bytes[script_path] = tree, raw
        inventory[script_path] = tree._oracle_source_sha256
        invocation_sources["runtests.py"] = raw
    if extra_sources:
        for name, text in extra_sources.items():
            path = tmp_path / name
            raw = text.encode()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            tree = ast.parse(raw)
            tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
            modules[path], source_bytes[path] = tree, raw
            inventory[path] = tree._oracle_source_sha256
    if not modules:
        path = tmp_path / "probe.py"
        raw = b""
        path.write_bytes(raw)
        tree = ast.parse(raw)
        tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
        modules[path], source_bytes[path] = tree, raw
        inventory[path] = tree._oracle_source_sha256
    index = application_test_index(
        tmp_path, modules, source_bytes, inventory, configuration_bytes
    )
    return captured_test_invocation_profile(
        index,
        configuration_bytes,
        invocation_sources,
        configuration_identities=identities,
    )


_NATIVE_RUNNER_SOURCE = (
    "import os\n"
    "import django\n"
    "from django.test.runner import DiscoverRunner\n"
    'if __name__ == "__main__":\n'
    '    os.environ["DJANGO_SETTINGS_MODULE"] = "tests.settings"\n'
    "    django.setup()\n"
    "    test_runner = DiscoverRunner(verbosity=2)\n"
    "    failures = test_runner.run_tests([])\n"
)


@pytest.mark.parametrize(
    "extra,expected",
    [
        ({}, True),
        (
            {
                "helper.py": "from django.conf import settings\nvalue = getattr(settings, 'UNRELATED_OPTION', {})\n"
            },
            True,
        ),
        ({"runtime.py": "import django\ndjango.setup()\n"}, False),
        (
            {
                "runtime.py": "from django import setup as boot\nloader = boot\nloader()\n"
            },
            False,
        ),
        (
            {
                "runtime.py": "from django.test.runner import DiscoverRunner\nDiscoverRunner.run_tests = replacement\n"
            },
            False,
        ),
        (
            {
                "runtime.py": "from django.test.runner import DiscoverRunner as Runner\nsetattr(Runner, 'run_tests', replacement)\n"
            },
            False,
        ),
        (
            {
                "runtime.py": "from django.conf import settings\nsend(settings.SECRET_KEY)\n"
            },
            False,
        ),
        (
            {
                "runtime.py": "from django.conf import settings\nsend(getattr(settings, 'SECRET_KEY'))\n"
            },
            False,
        ),
        (
            {
                "runtime.py": "from django.conf import settings\nsend(settings.SECRET_KEY_FALLBACKS)\n"
            },
            False,
        ),
        (
            {"runtime.py": "from django.conf import settings\nsend(vars(settings))\n"},
            False,
        ),
        ({"checks/test_feature.py": "def test_feature():\n    assert True\n"}, False),
        pytest.param(
            {
                "runtime.py": "from django.conf import settings\nsend(getattr(settings, '__dict__')['SECRET_KEY'])\n"
            },
            False,
            id="copied-getter-dict",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import settings\nsend(getattr(settings, '_wrapped').SECRET_KEY)\n"
            },
            False,
            id="copied-getter-wrapped",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import settings\nsend(getattr(settings, '__getattribute__')('SECRET_KEY'))\n"
            },
            False,
            id="copied-getter-protocol",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import settings\nsend(settings._wrapped.SECRET_KEY)\n"
            },
            False,
            id="copied-direct-wrapped",
        ),
        pytest.param(
            {
                "runtime.py": "from django.core.wsgi import get_wsgi_application\napplication = get_wsgi_application()\n"
            },
            False,
            id="implicit-wsgi",
        ),
        pytest.param(
            {
                "runtime.py": "from django.core.asgi import get_asgi_application\napplication = get_asgi_application()\n"
            },
            False,
            id="implicit-asgi",
        ),
        pytest.param(
            {
                "runtime.py": "from django.core.management import execute_from_command_line\nexecute_from_command_line([])\n"
            },
            False,
            id="implicit-management",
        ),
        pytest.param(
            {
                "runtime.py": "from django.core import signing\ntoken = signing.dumps({'user_id': 1})\n"
            },
            False,
            id="implicit-live-signing",
        ),
        pytest.param(
            {
                "runtime.py": "from django.core import signing\nemit = getattr(signing, 'dumps')\ntoken = emit({'user_id': 1})\n"
            },
            False,
            id="implicit-reflected-signing",
        ),
        pytest.param(
            {
                "runtime.py": "from django.core.signing import dumps as emit\ntoken = emit({'user_id': 1})\n"
            },
            False,
            id="implicit-aliased-signing",
        ),
        pytest.param(
            {
                "runtime.py": "from django.contrib.auth.tokens import default_token_generator\ntoken = default_token_generator.make_token(user)\n"
            },
            False,
            id="implicit-reset-token",
        ),
        pytest.param(
            {"runtime.py": "token = user.get_session_auth_hash()\n"},
            False,
            id="implicit-session-hash",
        ),
        pytest.param(
            {
                "runtime.py": "from django.contrib.auth import get_user_model\nUser = get_user_model()\n"
            },
            True,
            id="unrelated-user-model",
        ),
        pytest.param(
            {
                "runtime.py": "mod = __import__('django.core.signing', fromlist=['dumps'])\ntoken = mod.dumps({'user_id': 1})\n"
            },
            False,
            id="implicit-builtin-import",
        ),
        pytest.param(
            {
                "runtime.py": "from builtins import __import__ as load\nmod = load('django.core.signing', fromlist=['dumps'])\ntoken = mod.dumps({'user_id': 1})\n"
            },
            False,
            id="implicit-import-alias",
        ),
        pytest.param(
            {
                "runtime.py": "import builtins\nload = getattr(builtins, '__import__')\nmod = load('django.core.signing', fromlist=['dumps'])\ntoken = mod.dumps({'user_id': 1})\n"
            },
            False,
            id="implicit-reflected-import",
        ),
        pytest.param(
            {
                "runtime.py": "namespace = globals()['__builtins__']\nmod = namespace['__import__']('django.core.signing', fromlist=['dumps'])\ntoken = mod.dumps({'user_id': 1})\n"
            },
            False,
            id="implicit-import-from-globals",
        ),
        pytest.param(
            {
                "runtime.py": "import sys\nregistry = getattr(sys, 'modules')\nmod = registry['django.core.signing']\ntoken = mod.dumps({'user_id': 1})\n"
            },
            False,
            id="implicit-reflected-module-registry",
        ),
        pytest.param(
            {"runtime.py": "import sys\nversion = sys.version_info\n"},
            True,
            id="unrelated-version-metadata",
        ),
        pytest.param(
            {
                "runtime.py": "from django.utils.crypto import salted_hmac\ntoken = salted_hmac('scope', 'payload')\n"
            },
            False,
            id="implicit-default-hmac",
        ),
        pytest.param(
            {
                "runtime.py": "from django.utils.crypto import get_random_string\nvalue = get_random_string(12)\n"
            },
            True,
            id="unrelated-random-data",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import settings\ncfg = settings\nsend(cfg.SECRET_KEY)\n"
            },
            False,
            id="copied-namespace-alias",
        ),
        pytest.param(
            {"runtime.py": "from django.conf import settings\nconsume(settings)\n"},
            False,
            id="copied-namespace-argument",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import settings\ncfg = getattr(settings, 'MISSING_PUBLIC', settings)\nsend(cfg.SECRET_KEY)\n"
            },
            False,
            id="copied-namespace-default",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import settings\nsettings.SIGNING_BACKEND = 'external.Signer'\n"
            },
            False,
            id="copied-settings-mutation",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import LazySettings\ncfg = LazySettings()\nsend(cfg.SECRET_KEY)\n"
            },
            False,
            id="copied-lazy-settings-factory",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import Settings\ncfg = Settings('support.configuration')\nsend(cfg.SECRET_KEY)\n"
            },
            False,
            id="copied-explicit-settings-factory",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import settings\ndef getattr(obj, name, default=None):\n    send(obj.SECRET_KEY)\nvalue = getattr(settings, 'PUBLIC_OPTION', {})\n"
            },
            False,
            id="shadowed-settings-getter",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import settings\ndef consume(getattr):\n    return getattr(settings, 'PUBLIC_OPTION', {})\n"
            },
            False,
            id="parameter-settings-getter",
        ),
        pytest.param(
            {
                "runtime.py": "from builtins import getattr as read\nfrom django.conf import settings\nvalue = read(settings, 'PUBLIC_OPTION', {})\n"
            },
            True,
            id="qualified-settings-getter",
        ),
        pytest.param(
            {
                "runtime.py": "from django.contrib.auth import get_user_model\nnamespace = getattr(get_user_model, '__globals__')\nsend(namespace['settings'].SECRET_KEY)\n"
            },
            False,
            id="implicit-function-namespace",
        ),
        pytest.param(
            {
                "runtime.py": "from builtins import getattr as read\nfrom django.contrib.auth import get_user_model\nnamespace = read(get_user_model, '__globals__')\nsend(namespace['settings'].SECRET_KEY)\n"
            },
            False,
            id="implicit-aliased-function-namespace",
        ),
        pytest.param(
            {
                "poison.py": "import builtins\nbuiltins.getattr = replacement\n",
                "runtime.py": "import poison\nfrom django.conf import settings\nvalue = getattr(settings, 'PUBLIC_OPTION', {})\n",
            },
            False,
            id="cross-source-builtin-mutation",
        ),
    ],
)
def test_native_settings_scope_closes_all_captured_provider_effects(
    tmp_path, extra, expected
):
    index, path, assignment = configured_authority_scope(
        tmp_path,
        {
            "requirements.txt": b"Django>=4.2\n",
            ".github/workflows/ci.yml": b"jobs:\n  test:\n    steps:\n      - run: python runtests.py\n",
        },
        {
            "runtests.py": _NATIVE_RUNNER_SOURCE.replace(
                "tests.settings", "support.configuration"
            ),
            "checks/test_feature.py": "from unittest import TestCase\nclass Checks(TestCase):\n    def test_feature(self):\n        assert True\n",
            **extra,
        },
    )
    result = scope._source_test_scope_evidence(index, path, assignment, "SECRET_KEY")
    assert (result is not None) is expected
    if expected:
        assert (
            result["settings_selection"]["invocation"]["runner"]
            == "django.DiscoverRunner"
        )
        assert any(
            w["role"] == "modeled_implicit_settings_load"
            for w in result["witness_sources"]
        )


@pytest.mark.parametrize(
    "ending", ["", "    sys.exit(failures)\n", "    sys.exit(bool(failures))\n"]
)
def test_captured_invocation_profile_binds_native_django_bootstrap(tmp_path, ending):
    workflow = (
        "jobs:\n  test:\n    steps:\n      - run: |\n          python runtests.py\n"
    )
    script = "import sys\n" + _NATIVE_RUNNER_SOURCE + ending
    profile = captured_test_profile(tmp_path, workflow=workflow, script=script)
    assert profile["status"] == "DECLARED"
    assert profile["execution_status"] == "NOT_EXECUTED"
    assert profile["runner"] == "django.DiscoverRunner"
    assert profile["selector"]["settings_module"] == "tests.settings"
    assert profile["selector"]["bootstrap_effect"] == "MODELED_IMPLICIT_SETTINGS_LOAD"
    assert profile["selector"]["setup_span"][0] < profile["selector"]["runner_span"][0]
    assert (
        profile["sources"]["runtests.py"]["sha256"]
        == hashlib.sha256(script.encode()).hexdigest()
    )
    profile = captured_test_profile(
        tmp_path,
        workflow=workflow,
        script=script,
        other_workflows={
            ".github/workflows/dependabot-auto-merge.yml": "jobs:\n  update:\n    steps:\n      - run: gh pr view\n",
            ".github/workflows/update-hooks.yml": "jobs:\n  update:\n    steps:\n      - run: prek run --all-files\n",
        },
    )
    assert profile["status"] == "DECLARED"
    assert len(profile["sources"]) == 4
    assert [item["status"] for item in profile["workflow_dispositions"]] == [
        "DECLARED",
        "NO_TEST_INVOCATION",
        "NO_TEST_INVOCATION",
    ]


@pytest.mark.parametrize(
    "workflow,script,extra_sources",
    [
        (
            "jobs:\n  test:\n    steps:\n      - run: python runtests.py --tag smoke\n",
            _NATIVE_RUNNER_SOURCE,
            None,
        ),
        (
            "jobs:\n  test:\n    steps:\n      - working-directory: tests\n        run: python runtests.py\n",
            _NATIVE_RUNNER_SOURCE,
            None,
        ),
        (
            "jobs:\n  test:\n    steps:\n      - run: python runtests.py\n",
            _NATIVE_RUNNER_SOURCE.replace(
                "    django.setup()\n", "    if False:\n        django.setup()\n"
            ),
            None,
        ),
        (
            "jobs:\n  test:\n    steps:\n      - run: python runtests.py\n",
            _NATIVE_RUNNER_SOURCE,
            {"django.py": "# shadow provider\n"},
        ),
    ],
)
def test_captured_native_invocation_refuses_unbound_argv_cwd_or_bootstrap(
    tmp_path, workflow, script, extra_sources
):
    assert (
        captured_test_profile(
            tmp_path,
            workflow=workflow,
            script=script,
            extra_sources=extra_sources,
        )["status"]
        == "UNRESOLVED"
    )


@pytest.mark.parametrize(
    "workflow",
    [
        "jobs:\n  test:\n    steps:\n      - run: |\n          cd tests\n          python runtests.py\n",
        "jobs:\n  test:\n    steps:\n      - run: |\n          if false; then\n            echo skip\n          fi\n          python runtests.py\n",
        "jobs:\n  test:\n    steps:\n      - run: |\n          export PYTHONPATH=/outside && echo ready\n          python runtests.py\n",
        "jobs:\n  test:\n    steps:\n      - run: echo 'PYTHONPATH=/outside' >> $GITHUB_ENV\n"
        "      - run: python runtests.py\n",
        "jobs:\n  test:\n    steps:\n      - working-directory: C:\\\\outside\n        run: python runtests.py\n",
    ],
)
def test_captured_native_invocation_refuses_shell_selection_or_path_mutations(
    tmp_path, workflow
):
    assert (
        captured_test_profile(
            tmp_path, workflow=workflow, script=_NATIVE_RUNNER_SOURCE
        )["status"]
        == "UNRESOLVED"
    )


def test_captured_pytest_invocation_needs_bound_selector_or_absence(tmp_path):
    workflow = "jobs:\n  test:\n    steps:\n      - run: pytest -ra\n"
    assert captured_test_profile(tmp_path, workflow=workflow)["status"] == "UNRESOLVED"


@pytest.mark.parametrize(
    "config_in_tox,unbound",
    [(False, False), (True, False), (False, True)],
)
def test_captured_pytest_invocation_binds_config_without_borrowing_tox(
    tmp_path, config_in_tox, unbound
):
    workflow = "jobs:\n  test:\n    steps:\n      - run: pytest -ra\n"
    selector = b"[pytest]\nDJANGO_SETTINGS_MODULE = direct.settings\n"
    tox = b"[testenv]\ncommands = pytest --ds=tox.settings\n"
    configs = (
        {"tox.ini": selector + tox}
        if config_in_tox
        else {"pytest.ini": selector, "tox.ini": tox}
    )
    profile = captured_test_profile(
        tmp_path,
        workflow=workflow,
        extra_configs=configs,
        unbound_config="tox.ini" if unbound else None,
    )
    if unbound:
        assert profile["status"] == "UNRESOLVED"
    else:
        assert profile["status"] == "DECLARED"
        assert profile["selector"]["settings_module"] == "direct.settings"
        assert profile["selector"]["configuration"]["path"] == (
            "tox.ini" if config_in_tox else "pytest.ini"
        )
        assert profile["configuration_identities"]["tox.ini"]["sha256"] == (
            hashlib.sha256(configs["tox.ini"]).hexdigest()
        )


@pytest.mark.parametrize("direct_matches", [True, False])
def test_source_settings_role_uses_workflow_selector_and_receipt(
    tmp_path, direct_matches
):
    direct, tox = (
        ("support.configuration", "alternate.settings")
        if direct_matches
        else ("alternate.settings", "support.configuration")
    )
    index, path, assignment = configured_authority_scope(
        tmp_path,
        {
            "pytest.ini": f"[pytest]\nDJANGO_SETTINGS_MODULE={direct}\n".encode(),
            "tox.ini": f"[testenv]\ncommands=pytest --ds={tox}\n".encode(),
            ".github/workflows/ci.yml": b"jobs:\n  test:\n    steps:\n      - run: pytest -ra\n",
        },
    )
    from factoryline.review_audits import security_scan

    result = scope._source_test_scope_evidence(index, path, assignment, "SECRET_KEY")
    report = security_scan(
        tmp_path, cache_enabled=False, defect_policy="source-role-v3"
    )
    assert report["finding_conservation"]["state"] == "PASS"
    assert report["audit_coverage"]["complete"] is True
    rows = [
        row
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert (
        len(rows) == 1 and rows[0]["raw_finding"]["path"] == "support/configuration.py"
    )
    assert rows[0]["tier"] == (
        "PROVEN_PRIMITIVE" if direct_matches else "NEEDS_CONTEXT"
    )
    if not direct_matches:
        assert result is None
        return
    assert result is not None
    invocation = result["settings_selection"]["invocation"]
    assert invocation["runner"] == "pytest"
    assert invocation["execution_status"] == "NOT_EXECUTED"
    assert invocation["selector"]["settings_module"] == direct
    assert invocation["invocations"][0]["argv"] == ["pytest", "-ra"]
    assert "sources" not in invocation
    workflow = index["configuration_bytes"][".github/workflows/ci.yml"]
    assert (
        invocation["configuration_identities"][".github/workflows/ci.yml"]["sha256"]
        == hashlib.sha256(workflow).hexdigest()
    )
    proved = next(
        row
        for row in report["primitive_observations"]
        if row["path"] == "support/configuration.py"
    )
    assert (
        proved["facts"]["fixture_evidence"]["settings_selection"]["invocation"]
        == invocation
    )


def test_captured_workflows_without_test_entry_are_explicit_noncontributors(tmp_path):
    profile = captured_test_profile(
        tmp_path,
        workflow="jobs:\n  update:\n    steps:\n      - run: gh pr view\n",
    )
    assert profile["status"] == "NO_TEST_INVOCATION"
    assert profile["workflows"] == [
        {"path": ".github/workflows/ci.yml", "status": "NO_TEST_INVOCATION"}
    ]


def test_captured_native_profile_is_independent_of_input_mapping_order(tmp_path):
    workflow = "jobs:\n  test:\n    steps:\n      - run: python runtests.py\n"
    extras = {
        ".github/workflows/z.yml": "jobs:\n  update:\n    steps:\n      - run: gh pr view\n",
        ".github/workflows/a.yml": "jobs:\n  update:\n    steps:\n      - run: echo update\n",
    }
    expected = captured_test_profile(
        tmp_path,
        workflow=workflow,
        script=_NATIVE_RUNNER_SOURCE,
        other_workflows=extras,
    )
    actual = captured_test_profile(
        tmp_path,
        workflow=workflow,
        script=_NATIVE_RUNNER_SOURCE,
        other_workflows=extras,
        reverse_inputs=True,
    )
    assert actual == expected


def test_captured_distribution_provider_binds_django_requirement_bytes():
    import hashlib

    from factoryline.pytest_collection_audit import captured_distribution_provider

    raw = b"Django>=3.2,<5\n"
    result = captured_distribution_provider({"requirements.txt": raw}, "Django")
    assert result == {
        "path": "requirements.txt",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "provider": "django",
        "declaration_only": True,
        "declarations": [
            {"group": "requirements.txt", "requirement": "Django>=3.2,<5"}
        ],
    }


@pytest.mark.parametrize(
    "raw",
    [
        b"Django-extra>=3.2\n",
        b"Django[postgres]>=3.2\n",
        b"Django>=3.2; python_version<'3.12'\n",
        b"Django @ https://example.invalid/django.whl\n",
        b"Django>=3.2\n-r base.txt\n",
    ],
)
def test_captured_distribution_provider_rejects_non_exact_or_included_requirements(raw):
    from factoryline.pytest_collection_audit import captured_distribution_provider

    assert captured_distribution_provider({"requirements.txt": raw}, "django") is None


def test_captured_distribution_provider_reads_required_project_dependency_only():
    from factoryline.pytest_collection_audit import captured_distribution_provider

    raw = b'[project]\ndependencies = ["Django>=4,<6"]\n'
    result = captured_distribution_provider({"pyproject.toml": raw}, "django")
    assert result["provider"] == "django"
    assert result["declarations"] == [
        {"group": "project.dependencies", "requirement": "Django>=4,<6"}
    ]
    optional = (
        b"[project]\ndependencies = []\n"
        b'[project.optional-dependencies]\ntest = ["Django>=4"]\n'
    )
    assert (
        captured_distribution_provider({"pyproject.toml": optional}, "django") is None
    )


def test_generic_provider_keeps_legacy_pytest_django_receipt_shape():
    from factoryline.pytest_collection_audit import captured_pytest_django_provider

    result = captured_pytest_django_provider(
        {"requirements.txt": b"pytest_django>=4.5\n"}
    )
    assert result["provider"] == "pytest_django"
    assert result["declaration_only"] is True
    assert "declarations" not in result


@pytest.mark.parametrize("flag", ["-q", "-v", "-vv"])
def test_captured_tox_selection_accepts_legacy_report_flags(flag):
    from factoryline.pytest_collection_audit import (
        _pytest_captured_invocation_options,
    )

    tox = (
        "[testenv]\nsetenv=\n    DJANGO_SETTINGS_MODULE=environment.settings\n"
        f"commands=pytest {flag}\n"
    ).encode()
    selected = _pytest_captured_invocation_options(
        {"tox.ini": tox}, {"DJANGO_SETTINGS_MODULE": "config.settings"}
    )
    assert selected["DJANGO_SETTINGS_MODULE"] == "environment.settings"
    assert selected["captured_invocations"]["commands"] == [
        ("testenv", f"pytest {flag}")
    ]


def test_pytest_coverage_flags_require_same_profile_provider():
    from factoryline.pytest_collection_audit import captured_pytest_configuration

    config = (
        b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"
        b"addopts=--cov=package --cov-report=term-missing\n"
    )
    selected = captured_pytest_configuration(
        {"pytest.ini": config, "requirements.txt": b"pytest-cov>=5\n"}
    )
    assert selected["options"]["DJANGO_SETTINGS_MODULE"] == "support.configuration"
    assert (
        captured_pytest_configuration(
            {
                "pytest.ini": config,
                "pyproject.toml": b'[project.optional-dependencies]\ntest=["pytest-cov"]\n',
            }
        )
        is None
    )
    assert (
        captured_pytest_configuration(
            {
                "pytest.ini": config,
                "pyproject.toml": b'[dependency-groups]\ntest=["pytest-cov"]\n',
            }
        )
        is None
    )


def test_malformed_project_dependencies_refuse_captured_provider_selection():
    from factoryline.pytest_collection_audit import (
        captured_pytest_configuration,
        captured_pytest_django_provider,
    )

    captured = {
        "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"
        b"addopts=--cov=package\n",
        "pyproject.toml": b"[project]\ndependencies=1\n",
    }
    assert captured_pytest_configuration(captured) is None
    assert captured_pytest_django_provider(captured) is None


def test_pytest_coverage_accepts_default_poetry_dependency():
    from factoryline.pytest_collection_audit import captured_pytest_configuration

    raw = (
        b'[tool.poetry.dependencies]\npytest-cov="^5"\n'
        b"[tool.pytest.ini_options]\n"
        b'DJANGO_SETTINGS_MODULE="support.configuration"\n'
        b'addopts="--junitxml=report.xml --cov=package --cov-report=term-missing"\n'
    )
    selected = captured_pytest_configuration({"pyproject.toml": raw})
    assert selected["options"]["DJANGO_SETTINGS_MODULE"] == "support.configuration"


def test_pytest_coverage_accepts_provider_in_same_tox_profile():
    from factoryline.pytest_collection_audit import captured_pytest_configuration

    selected = captured_pytest_configuration(
        {
            "pytest.ini": b"[pytest]\n"
            b"DJANGO_SETTINGS_MODULE=support.configuration\n"
            b"addopts=--cov=package\n",
            "tox.ini": b"[testenv]\ndeps=pytest-cov\ncommands=pytest\n",
        }
    )
    assert selected["options"]["DJANGO_SETTINGS_MODULE"] == "support.configuration"


def test_pytest_coverage_provider_cannot_be_borrowed_from_tox_sibling():
    from factoryline.pytest_collection_audit import captured_pytest_configuration

    config = b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\naddopts=--cov=package\n"
    tox = (
        b"[testenv:fast]\ndeps=pytest\ncommands=pytest\n"
        b"[testenv:coverage]\ndeps=pytest-cov\ncommands=pytest\n"
    )
    assert (
        captured_pytest_configuration(
            {
                "pytest.ini": config,
                "tox.ini": tox,
                "pyproject.toml": b'[project.optional-dependencies]\ntest=["pytest-cov"]\n',
            }
        )
        is None
    )


@pytest.mark.parametrize(
    "addopts,coverage_provider",
    [
        ("--junitxml --ds=production.settings", False),
        ("--cov-report --ds=production.settings", True),
        ("--reuse-db", False),
        ("--nomigrations", False),
        ("--autocheck", False),
        ("-o DJANGO_SETTINGS_MODULE=other.settings", False),
    ],
)
def test_pytest_effect_projection_rejects_swallowed_and_unknown_effects(
    addopts, coverage_provider
):
    from factoryline.pytest_collection_audit import _pytest_effective_settings_options

    assert (
        _pytest_effective_settings_options(
            {"DJANGO_SETTINGS_MODULE": "support.configuration", "addopts": addopts},
            coverage_provider=coverage_provider,
        )
        is None
    )


@pytest.mark.parametrize(
    "step,tier",
    [
        ("", "PROVEN_PRIMITIVE"),
        ("- run: pytest -ra", "PROVEN_PRIMITIVE"),
        ("- run: python -m pytest -ra", "PROVEN_PRIMITIVE"),
        ("- run: pytest --ds=other.settings", "NEEDS_CONTEXT"),
        ("- run: python -m pytest --ds=other.settings", "NEEDS_CONTEXT"),
        ("- run: python -m pytest --ds=support.configuration", "PROVEN_PRIMITIVE"),
        ("- run: pytest\n        working-directory: checks", "NEEDS_CONTEXT"),
    ],
)
def test_configured_settings_public_cli_keeps_incomplete_source_conservation(
    tmp_path, capsys, step, tier
):
    import json

    from factoryline.cli import main

    configuration = {
        "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"
    }
    if step:
        configuration[".github/workflows/ci.yml"] = (
            f"jobs:\n  test:\n    steps:\n      {step}\n"
        ).encode()
    configured_authority_scope(tmp_path, configuration)
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
    alerts = [r for r in result["findings"] if r["code"] == "SECURITY_HARDCODED_SECRET"]
    assert len(alerts) == (tier == "NEEDS_CONTEXT")
    rows = result["finding_tier_report"]["ledger"]
    assert len(rows) == 1 and rows[0]["tier"] == tier
    assert rows[0]["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"
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
