"""Operative Django defaults require selected, unmodified runtime consumers."""

import ast
import copy
from hashlib import sha256
import json
from pathlib import Path

import pytest

from factoryline import review_audits as audit
from factoryline.primitive_observation_binding import build_finding_tier_report

SETTINGS = (
    'SECRET_KEY = "published-signing-material"\n'
    'INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions"]\n'
    'MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware", '
    '"django.contrib.auth.middleware.AuthenticationMiddleware"]\n'
)
START = (
    "import os\nfrom django.core.wsgi import get_wsgi_application\n"
    'os.environ.setdefault("DJANGO_SETTINGS_MODULE", "service.settings")\n'
    "application = get_wsgi_application()\n"
)


def _recovery_sources(settings=SETTINGS, startup=START, extra=None):
    return {
        "service/__init__.py": "",
        "service/settings.py": settings,
        "start.py": startup,
        **(extra or {}),
    }


def _recovery_row(files, name="SECRET_KEY"):
    sources = {path: source.encode() for path, source in files.items()}
    findings = audit._security_scan_tree(
        Path("."), Path("service/settings.py"), ast.parse(files["service/settings.py"])
    )
    finding = next(item for item in findings if item["facts"].get("name") == name)
    report = build_finding_tier_report(
        [finding],
        [],
        [
            {"path": path, "sha256": sha256(raw).hexdigest()}
            for path, raw in sources.items()
        ],
        sources,
        coverage_state=True,
        partition_state="VALIDATED",
    )
    return report["ledger"][0]


@pytest.mark.parametrize("material", ["your_key", "YOUR SECRET KEY", "change-this-key"])
def test_local_signing_default_spelling_does_not_negate_selected_authority(material):
    files = _recovery_sources(SETTINGS.replace("published-signing-material", material))
    row = _recovery_row(files)
    assert row["tier"] == "SUPPORTED_DEFECT"
    proof = row["credential_authority_observation"]
    assert proof["consumer_role"] == "configured_authentication_session_signing"
    assert proof["runtime_execution"] == "not_performed"
    assert proof["deployment"] == "UNASSESSED"
    for transfer in proof["transfers"]:
        assert (
            transfer["sha256"] == sha256(files[transfer["path"]].encode()).hexdigest()
        )


@pytest.mark.parametrize(
    "read",
    [
        'getattr(settings, "FEATURE_FLAG", False)',
        'hasattr(settings, "FEATURE_FLAG")',
        'getattr(settings, "STATIC_URL", getattr(settings, "MEDIA_URL", "/"))',
    ],
)
def test_readonly_unrelated_framework_settings_preserve_signing_authority(read):
    row = _recovery_row(
        _recovery_sources(
            extra={
                "reader.py": "from django.conf import settings\nvalue = " + read + "\n",
            }
        )
    )
    assert row["tier"] == "SUPPORTED_DEFECT"


@pytest.mark.parametrize("middleware", ["MIDDLEWARE", "MIDDLEWARE_CLASSES"])
def test_selected_main_management_startup_preserves_legacy_session_authority(
    middleware,
):
    startup = (
        "import os\nimport sys\n"
        'if __name__ == "__main__":\n'
        '    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "service.settings")\n'
        "    from django.core.management import execute_from_command_line\n"
        "    execute_from_command_line(sys.argv)\n"
    )
    row = _recovery_row(
        _recovery_sources(SETTINGS.replace("MIDDLEWARE =", middleware + " ="), startup)
    )
    assert row["tier"] == "SUPPORTED_DEFECT"
    proof = row["credential_authority_observation"]
    assert len(proof["transfers"]) == 5
    assert any(item["path"] == "start.py" for item in proof["transfers"])


@pytest.mark.parametrize(
    "mutation",
    [
        'getattr(settings, "MIDDLEWARE").clear()',
        "getattr(settings, dynamic_name)",
        'hasattr(settings, "FEATURE_FLAG", False)',
        'getattr(settings, "__dict__")["MIDDLEWARE"] = []',
        'setattr(settings, "MIDDLEWARE", [])',
        "settings.MIDDLEWARE.clear()",
        "escape(settings)",
        'getattr = replacement\ngetattr(settings, "FEATURE_FLAG", False)',
        'def inspect(getattr):\n    return getattr(settings, "FEATURE_FLAG", False)',
    ],
)
def test_selected_container_or_unknown_reflection_still_vetoes_authority(mutation):
    row = _recovery_row(
        _recovery_sources(
            extra={
                "reader.py": "from django.conf import settings\n" + mutation + "\n",
            }
        )
    )
    assert row["tier"] == "NEEDS_CONTEXT"
    assert "credential_authority_observation" not in row


@pytest.mark.parametrize(
    "startup",
    [
        START.replace("service.settings", "elsewhere.settings"),
        START.replace(
            "application =", "get_wsgi_application = replacement\napplication ="
        ),
        "def test_only():\n"
        + "".join("    " + line + "\n" for line in START.splitlines()),
        "if False:\n" + "".join("    " + line + "\n" for line in START.splitlines()),
        START.replace(
            "application =",
            'os.environ["DJANGO_SETTINGS_MODULE"] = "other.settings"\napplication =',
        ),
    ],
)
def test_unselected_dead_test_only_or_replaced_startup_gets_no_authority(startup):
    assert _recovery_row(_recovery_sources(startup=startup))["tier"] == "NEEDS_CONTEXT"


def test_external_provider_placeholder_remains_unadmitted_with_selected_runtime():
    files = _recovery_sources(
        SETTINGS + 'SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = "your_key"\n'
    )
    assert (
        _recovery_row(files, "SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET")["tier"]
        == "NEEDS_CONTEXT"
    )


@pytest.mark.parametrize(
    "metadata",
    [
        {"setup.py": "from setuptools import setup\nsetup(packages=['library'])\n"},
        {"pyproject.toml": "[project]\nname='library'\n"},
    ],
)
def test_packaging_does_not_negate_captured_settings_loader(metadata):
    row = _recovery_row(_recovery_sources(extra=metadata))
    assert row["tier"] == "SUPPORTED_DEFECT"
    assert row["credential_authority_observation"]["deployment"] == "UNASSESSED"
    assert (
        row["credential_authority_observation"]["distribution_runtime_selection"]
        == "captured_settings_loader"
    )
    assert (
        _recovery_row(_recovery_sources(startup="", extra=metadata))["tier"]
        == "NEEDS_CONTEXT"
    )
    metadata = {
        **metadata,
        "reader.py": "import service.settings as cfg\nmutate(cfg)\n",
    }
    assert _recovery_row(_recovery_sources(extra=metadata))["tier"] == "NEEDS_CONTEXT"


@pytest.mark.parametrize(
    "extra",
    [
        {
            "reader.py": "from django.conf import settings\ncount = len(settings.INSTALLED_APPS)\n"
        },
        {
            "reader.py": "from service.settings import MIDDLEWARE as layers\ncount = len(layers)\n"
        },
    ],
)
def test_selected_consumer_container_length_is_readonly(extra):
    assert (
        _recovery_row(
            _recovery_sources(SETTINGS + "count = len(MIDDLEWARE)\n", extra=extra)
        )["tier"]
        == "SUPPORTED_DEFECT"
    )
    for change in (
        "layers.clear()",
        "mutate(layers)",
        "copy = layers",
        "len = mutate\nlen(layers)",
    ):
        changed = {
            "reader.py": "from service.settings import MIDDLEWARE as layers\n"
            + change
            + "\n"
        }
        assert (
            _recovery_row(_recovery_sources(extra=changed))["tier"] == "NEEDS_CONTEXT"
        )


@pytest.mark.parametrize(
    ("operation", "expected"),
    [
        ('os.environ["GEOS_LIBRARY_PATH"] = "/opt/lib/geos"', "SUPPORTED_DEFECT"),
        (
            'os.environ["DJANGO_SETTINGS_MODULE"] = "elsewhere.settings"',
            "NEEDS_CONTEXT",
        ),
        ("os.environ[key] = value", "NEEDS_CONTEXT"),
        (
            'os.environ.update({"DJANGO_SETTINGS_MODULE": "elsewhere.settings"})',
            "NEEDS_CONTEXT",
        ),
        ("escaped = os.environ\nmutate(escaped)", "NEEDS_CONTEXT"),
    ],
)
def test_environment_key_selection_keeps_loader_mutation_controls(operation, expected):
    files = _recovery_sources("import os\n" + SETTINGS + operation + "\n")
    assert _recovery_row(files)["tier"] == expected


def test_recovered_local_default_native_cli_receipt_and_independent_regeneration(
    tmp_path, capsys
):
    from factoryline.cli import main
    from factoryline import mission_control_status as receipts

    files = _recovery_sources(
        SETTINGS.replace("published-signing-material", "your_key")
    )
    for name, source in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
    assert (
        main(
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
        == 1
    )
    output = capsys.readouterr()
    assert not output.err
    report = json.loads(output.out)
    (row,) = report["finding_tier_report"]["ledger"]
    assert row["tier"] == "SUPPORTED_DEFECT"
    assert report["defect_policy_decision"]["supported_defect_count"] == 1
    assert report["defect_policy_decision"]["passed"] is False
    assert any(
        action["finding_context"]["code"] == "SECURITY_HARDCODED_SECRET"
        for action in report["agent_actions"]
    )
    envelope, truncated = receipts._security_scan_read_receipt(tmp_path)
    assert not truncated
    persisted, _, error = receipts._security_scan_receipt_report(envelope)
    assert error is None and persisted == report
    rebuilt = copy.deepcopy(report)
    # Prior serialized source evidence must remain replayable when its facts did
    # not change. This is the legacy no-distribution observation, not a bypass.
    rebuilt["finding_tier_report"]["ledger"][0]["credential_authority_observation"][
        "distribution_runtime_selection"
    ] = "no_captured_distribution_declaration"
    rebuilt["_primitive_source_bytes"] = {
        name: (tmp_path / name).read_bytes() for name in files
    }
    resealed = audit._seal_security_scan(rebuilt)
    assert resealed["finding_tier_report"] == report["finding_tier_report"]
    assert resealed["defect_policy_decision"]["state"] != "BLOCKED"
    rebuilt = copy.deepcopy(report)
    rebuilt["_primitive_source_bytes"] = {
        name: (tmp_path / name).read_bytes() for name in files
    }
    rebuilt["_primitive_source_bytes"]["start.py"] = b"application = unknown()\n"
    assert (
        audit._seal_security_scan(rebuilt)["finding_tier_report"]["tier_counts"][
            "SUPPORTED_DEFECT"
        ]
        == 0
    )


def test_literal_key_hash_read_preserves_selected_signing_authority():
    row = _recovery_row(
        _recovery_sources(
            extra={
                "consumer.py": "import hashlib\nfrom django.conf import settings\n"
                "def derive(value):\n    return hashlib.sha1(value + settings.SECRET_KEY).hexdigest()\n"
            }
        )
    )
    assert row["tier"] == "SUPPORTED_DEFECT"


def test_unrendered_key_and_runtime_module_scaffold_is_not_authority():
    settings = SETTINGS.replace('"published-signing-material"', '"{{ fresh_key }}"')
    settings += 'ROOT_URLCONF = "{{ app_name }}.urls"\n'
    assert _recovery_row(_recovery_sources(settings))["tier"] == "NEEDS_CONTEXT"
    # A literal spelling alone cannot negate a real selected signing consumer.
    assert (
        _recovery_row(
            _recovery_sources(
                settings.replace(
                    'ROOT_URLCONF = "{{ app_name }}.urls"',
                    'ROOT_URLCONF = "service.urls"',
                )
            )
        )["tier"]
        == "SUPPORTED_DEFECT"
    )


def test_package_exclusion_and_unrelated_test_do_not_isolate_active_runtime():
    files = _recovery_sources(
        extra={
            "setup.py": "from setuptools import setup, find_packages\n"
            "setup(packages=find_packages(exclude=['service']))\n",
            "service/test_example.py": "from django.test import TestCase\n"
            "from django.contrib.auth.models import User\nfrom django.conf import settings\n"
            "class Example(TestCase):\n    def setUp(self):\n"
            "        User.objects.create_user(settings.EXAMPLE_NAME, settings.EXAMPLE_EMAIL, settings.EXAMPLE_PASSWORD)\n",
        }
    )
    assert _recovery_row(files)["tier"] == "SUPPORTED_DEFECT"


@pytest.mark.parametrize(
    "extra_target",
    ["live", "unknown_target", "include(dynamic_urls)", "'missing.views.login'"],
)
def test_fixture_route_cannot_hide_an_additional_selected_runtime_target(extra_target):
    files = _recovery_sources(
        SETTINGS + 'ROOT_URLCONF = "service.urls"\n',
        extra={
            "setup.py": "from setuptools import setup, find_packages\n"
            "setup(packages=find_packages(exclude=['service']))\n",
            "service/test_example.py": "from django.test import TestCase\n"
            "from django.contrib.auth.models import User\nfrom django.conf import settings\n"
            "class Example(TestCase):\n    def setUp(self):\n"
            "        User.objects.create_user(settings.TEST_USERNAME, settings.TEST_EMAIL, settings.TEST_PASSWORD)\n",
            "service/urls.py": "from django.conf.urls import url, include\n"
            "from service.views import live\n"
            "urlpatterns = [url('/fixture', 'service.views.fixture'), "
            f"url('/login', {extra_target})]\n",
            "service/views.py": "from django.conf import settings\n"
            "from django.contrib.auth import authenticate, login\n"
            "def fixture(request):\n"
            "    return authenticate(username=settings.TEST_USERNAME, password=settings.TEST_PASSWORD)\n"
            "def live(request):\n"
            "    user = authenticate(username=request.POST['username'], password=request.POST['password'])\n"
            "    login(request, user)\n",
        },
    )
    assert _recovery_row(files)["tier"] == "SUPPORTED_DEFECT"


@pytest.mark.parametrize(
    "mutation",
    [
        "@replacement\nclass Config:",
        "class Config(metaclass=Replacement):",
        "class Config(DynamicBase):",
        "Config.SECRET_KEY = secure_runtime_key",
        "del Config.SECRET_KEY",
    ],
)
def test_selected_config_class_requires_closed_provider_and_field(mutation):
    from test_semantic_credential_sensor import (
        _flask_login_config_sources,
        _captured_secret_tiers,
    )

    files = _flask_login_config_sources(target="config.Config")
    original = 'class Config:\n    SECRET_KEY = "source-bound-login-signing-key"\n'
    files["config.py"] = original
    assert (
        _captured_secret_tiers(files, "config.py")["ledger"][0]["tier"]
        == "SUPPORTED_DEFECT"
    )
    files["config.py"] = (
        original.replace("class Config:", mutation)
        if "class Config" in mutation
        else original + mutation + "\n"
    )
    assert (
        _captured_secret_tiers(files, "config.py")["ledger"][0]["tier"]
        == "NEEDS_CONTEXT"
    )


@pytest.mark.parametrize(
    "provider", ['PUBLIC = "value"\n', "__all__ = dynamic_names\n"]
)
def test_finite_import_cache_memoizes_success_and_refusal(monkeypatch, provider):
    from factoryline import semantic_credential_sensor as sensor

    sources = {
        "reader.py": b"from provider import *\n",
        "provider.py": provider.encode(),
    }
    context = sensor.signing_configuration_inventory(
        sources, {name: sha256(raw).hexdigest() for name, raw in sources.items()}
    )
    original = sensor._signing_module_imports
    calls = []

    def derive(context, path):
        calls.append(path)
        return original(context, path)

    monkeypatch.setattr(sensor, "_signing_module_imports", derive)
    first = sensor._signing_source_symbols(context)
    count = len(calls)
    assert count == 1
    assert (first["imports"][Path("reader.py")] is None) == (
        "dynamic_names" in provider
    )
    for _ in range(4):
        assert sensor._signing_source_symbols(context) is first
    assert len(calls) == count


def test_finite_import_cache_invalidates_snapshot_inventory_and_helper_epoch(
    monkeypatch,
):
    from factoryline import semantic_credential_sensor as sensor

    sources = {
        "reader.py": b"from provider import *\n",
        "provider.py": b'PUBLIC = "value"\n',
    }
    context = sensor.signing_configuration_inventory(
        sources, {name: sha256(raw).hexdigest() for name, raw in sources.items()}
    )
    index = context["index"]
    first = sensor._signing_source_symbols(context)
    assert first["imports"][Path("reader.py")] is not None
    original_code = sensor._flask_module_exports_dynamic.__code__

    def opaque(_tree):
        return True

    with monkeypatch.context() as patch:
        patch.setattr(sensor._flask_module_exports_dynamic, "__code__", opaque.__code__)
        refused = sensor._signing_source_symbols(context)
        assert refused is not first
        assert refused["imports"][Path("reader.py")] is None
        assert sensor._signing_source_symbols(context) is refused
    assert sensor._flask_module_exports_dynamic.__code__ is original_code
    rebuilt = sensor._signing_source_symbols(context)
    assert rebuilt["imports"][Path("reader.py")] is not None
    path = Path("provider.py")
    tree = ast.parse(sources["provider.py"])
    tree._oracle_source_sha256 = index.inventory[path]
    index.snapshots[path] = tree
    assert sensor._signing_source_symbols(context) is not rebuilt
    digest = index.inventory[path]
    index.inventory[path] = "0" * 64
    assert sensor._signing_source_symbols(context) is None
    assert sensor._signing_source_symbols(context) is None
    index.inventory[path] = digest
    assert (
        sensor._signing_source_symbols(context)["imports"][Path("reader.py")]
        is not None
    )
    raw = b"__all__ = dynamic_names\n"
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = sha256(raw).hexdigest()
    index.snapshots[path], index.source_bytes[path], index.inventory[path] = (
        tree,
        raw,
        tree._oracle_source_sha256,
    )
    final = sensor._signing_source_symbols(context)
    assert final["imports"][Path("reader.py")] is None
