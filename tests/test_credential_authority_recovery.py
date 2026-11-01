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


@pytest.mark.parametrize(
    "source",
    [
        'f"prefix:{value}"',
        'f"{value}:{17}:{True}"',
        '"{}".format(value)',
        'f"{value}" + ":suffix"',
    ],
)
def test_primitive_interpolation_preserves_origin_without_an_exact_value(source):
    from factoryline.credential_role_identity_effects import _Value
    from factoryline.finite_capture import security_structural_value

    incoming = _Value(
        roots=frozenset({"source:" + "a" * 64}),
        inert_kind="scalar",
        scalar_kind="text",
        trace=(("REQUEST_SOURCE", (1, 0, 1, 5), "a" * 64),),
    )
    assert incoming._exact_scalar == ()
    value = security_structural_value(
        ast.parse(source, mode="eval").body, {"value": incoming}
    )
    assert value.roots == incoming.roots and value.scalar_kind == "text"
    assert not value.unknown and not value.content_unknown
    assert any(step[0] == "TEXT_INTERPOLATION" for step in value.trace)


@pytest.mark.parametrize(
    "source",
    [
        'f"{value!r}"',
        'f"{value!s}"',
        'f"{value:>10}"',
        'f"{value:{spec}}"',
        'f"{opaque}"',
        'f"{value.strip()}"',
        "f\"{value if flag else 'fixed'}\"",
    ],
)
def test_interpolation_keeps_unclosed_formatting_and_origins_unproved(source):
    from factoryline.credential_role_identity_effects import _Value
    from factoryline.finite_capture import security_structural_value
    from factoryline.semantic_credential_sensor import _security_input_flow_evidence

    incoming = _Value(
        roots=frozenset({"source:known"}), inert_kind="scalar", scalar_kind="text"
    )
    env = {
        "value": incoming,
        "opaque": _Value(
            roots=incoming.roots, class_roots=frozenset({"custom"}), unknown=True
        ),
    }
    value = security_structural_value(ast.parse(source, mode="eval").body, env)
    assert _security_input_flow_evidence(value, value_type=_Value) is None


def test_legacy_taint_bit_cannot_become_interpolated_source_proof():
    from factoryline.credential_role_identity_effects import _Value
    from factoryline.finite_capture import security_structural_value
    from factoryline.semantic_credential_sensor import _security_input_flow_evidence

    value = security_structural_value(
        ast.parse('f"{value}"', mode="eval").body, {"value": True}
    )
    assert _security_input_flow_evidence(value, value_type=_Value) is None


@pytest.mark.parametrize(
    "source", ['"fixed".format(value)', '"{0}".format("fixed", value)']
)
def test_unused_format_argument_is_not_an_output_origin(source):
    from factoryline.credential_role_identity_effects import _Value
    from factoryline.finite_capture import security_structural_value

    incoming = _Value(
        roots=frozenset({"source:known"}), inert_kind="scalar", scalar_kind="text"
    )
    result = security_structural_value(
        ast.parse(source, mode="eval").body, {"value": incoming}
    )
    assert not result.unknown and not result.roots


@pytest.mark.parametrize(
    "mutation",
    [
        "none",
        "bound_parameter",
        "fixed_overwrite",
        "opaque_result",
        "custom_format",
        "provider_replaced",
        "dead_sink",
    ],
)
def test_source_model_interpolation_reaches_only_proved_unsafe_sink(tmp_path, mutation):
    from test_semantic_credential_sensor import _captured_log_scan

    source = (
        "import sqlite3\nfrom flask import request\n"
        "def view():\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    cursor = conn.cursor()\n"
        "    value = request.args.get('key', '')\n"
        "    query = f\"SELECT * FROM records WHERE key = '{value}'\"\n"
        "    cursor.execute(query)\n"
    )
    transforms = {
        "bound_parameter": (
            "cursor.execute(query)",
            "cursor.execute('SELECT * FROM records WHERE key=?', (query,))",
        ),
        "fixed_overwrite": ("    query =", "    value = 'fixed'\n    query ="),
        "opaque_result": ("    query =", "    value = unknown(value)\n    query ="),
        "custom_format": ("'{value}'", "'{value:{spec}}'"),
        "provider_replaced": (
            "def view():",
            "sqlite3.connect = replacement\ndef view():",
        ),
        "dead_sink": (
            "    cursor.execute(query)",
            "    if False:\n        cursor.execute(query)",
        ),
    }
    if mutation != "none":
        source = source.replace(*transforms[mutation])
    selected = [
        row
        for row in _captured_log_scan(tmp_path, source, startup=False)
        if row["code"] == "SECURITY_SQL_INJECTION"
        and row.get("facts", {}).get("security_precondition", {}).get("status")
        == "SUPPORTED"
    ]
    assert bool(selected) is (mutation == "none")
    if selected:
        assert "TEXT_INTERPOLATION" in str(selected[0]["facts"])


def _closed_star_projection(files):
    from factoryline.credential_role_constructor_provider import SourceSnapshotIndex
    from factoryline.credential_role_method_use_getter_audit import (
        CapturedOriginProjection,
    )
    from factoryline.review_integrity import bind_security_call_scopes

    raw = {Path(name): text.encode() for name, text in files.items()}
    trees = {path: ast.parse(data) for path, data in raw.items()}
    inventory = {path: sha256(data).hexdigest() for path, data in raw.items()}
    for path, tree in trees.items():
        tree._oracle_source_sha256 = inventory[path]
        bind_security_call_scopes(tree)
    index = SourceSnapshotIndex(Path("."), trees, raw, inventory)
    return CapturedOriginProjection(index, lambda *args: (False, None))


@pytest.mark.parametrize(
    "module,alias", [("exports", "Service"), ("renamed_exports", "RenamedService")]
)
def test_common_provider_closure_preserves_closed_renamed_star_exports(module, alias):
    from factoryline.credential_role_identity_effects import _Value

    projection = _closed_star_projection(
        {
            module
            + ".py": f"from external import Widget as {alias}\n__all__ = ['{alias}']\n",
            "consumer.py": f"from {module} import *\n",
        }
    )
    assert projection._symbol_closed([("external.Widget", None, None)], _Value())


def test_closed_star_exports_allow_uninitialized_keyword_only_defaults():
    from factoryline.credential_role_identity_effects import _Value

    projection = _closed_star_projection(
        {
            "exports.py": "from external import Widget as Service\ndef marker(*, option):\n    return None\n__all__ = ['Service']\n",
            "consumer.py": "from exports import *\n",
        }
    )
    assert projection._symbol_closed([("external.Widget", None, None)], _Value())


@pytest.mark.parametrize(
    "mutation",
    [
        "dynamic_exports",
        "dynamic_getattr",
        "missing_export",
        "shadow",
        "field_write",
        "escape",
        "ambiguous_import",
        "conditional_star",
        "export_mutation",
    ],
)
def test_common_provider_star_closure_retains_source_and_effect_barriers(mutation):
    from factoryline.credential_role_identity_effects import _Value

    files = {
        "exports.py": "from external import Widget as Service\n__all__ = ['Service']\n",
        "consumer.py": "from exports import *\n",
    }
    changes = {
        "dynamic_exports": (
            "exports.py",
            "__all__ = ['Service']",
            "__all__ = dynamic_names",
        ),
        "dynamic_getattr": (
            "exports.py",
            "__all__ = ['Service']",
            "def __getattr__(name):\n    return unknown()",
        ),
        "missing_export": ("exports.py", "['Service']", "['Missing']"),
        "shadow": (
            "consumer.py",
            "from exports import *",
            "from exports import *\nService = replacement",
        ),
        "field_write": (
            "consumer.py",
            "from exports import *",
            "from exports import *\nService.run = replacement",
        ),
        "escape": (
            "consumer.py",
            "from exports import *",
            "from exports import *\nmutate(Service)",
        ),
        "ambiguous_import": (
            "consumer.py",
            "from exports import *",
            "from alternate import Widget as Service\nfrom exports import *",
        ),
        "conditional_star": (
            "consumer.py",
            "from exports import *",
            "if condition:\n    from exports import *",
        ),
        "export_mutation": (
            "exports.py",
            "__all__ = ['Service']",
            "__all__ = ['Service']\n__all__.append(dynamic_name)",
        ),
    }
    path, old, new = changes[mutation]
    files[path] = files[path].replace(old, new)
    projection = _closed_star_projection(files)
    assert not projection._symbol_closed([("external.Widget", None, None)], _Value())


def test_common_star_inventory_invalidates_helper_source_and_inventory_changes(
    monkeypatch,
):
    from factoryline import semantic_credential_sensor as sensor
    from factoryline.credential_role_identity_effects import _Value

    projection = _closed_star_projection(
        {
            "exports.py": "from external import Widget as Service\n__all__ = ['Service']\n",
            "consumer.py": "from exports import *\n",
        }
    )

    def closed():
        return projection._symbol_closed([("external.Widget", None, None)], _Value())

    assert closed()
    with monkeypatch.context() as patch:
        patch.setattr(sensor, "_flask_static_module_exports", lambda *args: None)
        assert not closed()
    assert closed()
    index = projection.index
    digest = index.inventory[Path("exports.py")]
    index.inventory[Path("exports.py")] = "0" * 64
    assert not closed()
    index.inventory[Path("exports.py")] = digest
    assert closed()
    index.snapshots[Path("consumer.py")].body.extend(
        ast.parse("Service.run = replacement").body
    )
    assert not closed()


@pytest.mark.parametrize(
    "provider",
    [
        "from external import Widget\nService = Widget\n__all__ = ['Service']\n",
        "from external import Widget\ndef create():\n    return Widget\nService = create()\n__all__ = ['Service']\n",
        "from external import Widget as Service\n__all__ = ['Service']\nimport sys\nsys.modules[__name__].__class__ = Replacement\n",
    ],
)
def test_star_provider_aliases_and_namespace_replacement_do_not_hide_writes(provider):
    from factoryline.credential_role_identity_effects import _Value

    projection = _closed_star_projection(
        {
            "exports.py": provider,
            "consumer.py": "from exports import *\nService.run = replacement\n",
        }
    )
    assert not projection._symbol_closed([("external.Widget", None, None)], _Value())


def _optional_configuration_sources():
    settings = SETTINGS.replace("MIDDLEWARE =", "MIDDLEWARE_CLASSES =")
    settings += (
        "import os\n"
        "BASE = os.path.dirname(os.path.abspath(__file__))\n"
        "optional = BASE + '/private_settings.py'\n"
        "if os.path.isfile(optional):\n"
        "    from .private_settings import *\n"
    )
    return _recovery_sources(settings)


def test_absent_optional_configuration_preserves_feasible_default_authority():
    files = _optional_configuration_sources()
    row = _recovery_row(files)
    assert row["tier"] == "SUPPORTED_DEFECT"
    evidence = row["credential_authority_observation"]
    assert any(
        transfer["path"] == "service/settings.py"
        and transfer["span"][0]
        == next(
            line
            for line, text in enumerate(files["service/settings.py"].splitlines(), 1)
            if text.startswith("if os.path.isfile")
        )
        for transfer in evidence["transfers"]
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "captured_file",
        "current_file",
        "unknown_path",
        "replaced_predicate",
        "shadowed_os",
        "opaque_namespace",
        "foreign_predicate_mutation",
        "missing_import",
        "forward_path_binding",
        "windows_separator",
        "windows_drive",
    ],
)
def test_optional_configuration_requires_closed_absence_profile(mutation):
    files = _optional_configuration_sources()
    if mutation == "captured_file":
        files["service/private_settings.py"] = (
            "INSTALLED_APPS = []\nMIDDLEWARE_CLASSES = []\n"
        )
    elif mutation == "current_file":
        files["service/settings.py"] = files["service/settings.py"].replace(
            "os.path.isfile(optional)", "os.path.isfile(__file__)"
        )
    elif mutation == "unknown_path":
        files["service/settings.py"] = files["service/settings.py"].replace(
            "os.path.isfile(optional)", "os.path.isfile(dynamic_path())"
        )
    elif mutation == "replaced_predicate":
        files["service/settings.py"] = files["service/settings.py"].replace(
            "if os.path.isfile",
            "os.path.isfile = lambda value: True\nif os.path.isfile",
        )
    elif mutation == "shadowed_os":
        files["os.py"] = "path = unknown_path_provider\n"
    elif mutation == "foreign_predicate_mutation":
        files["other.py"] = "import os\nos.path.isfile = replacement\n"
    elif mutation == "missing_import":
        files["service/settings.py"] = files["service/settings.py"].replace(
            "import os\n", ""
        )
    elif mutation == "forward_path_binding":
        files["service/settings.py"] = files["service/settings.py"].replace(
            "BASE = os.path.dirname(os.path.abspath(__file__))\noptional = BASE + '/private_settings.py'",
            "optional = BASE + '/private_settings.py'\nBASE = os.path.dirname(os.path.abspath(__file__))",
        )
    elif mutation in {"windows_separator", "windows_drive"}:
        files["service/private_settings.py"] = (
            "INSTALLED_APPS = []\nMIDDLEWARE_CLASSES = []\n"
        )
        suffix = (
            "r'\\private_settings.py'"
            if mutation == "windows_separator"
            else "'C:/private_settings.py'"
        )
        files["service/settings.py"] = files["service/settings.py"].replace(
            "BASE + '/private_settings.py'", "os.path.join(BASE, " + suffix + ")"
        )
    else:
        files["service/settings.py"] += "configure(locals())\n"
    assert _recovery_row(files)["tier"] == "NEEDS_CONTEXT"


@pytest.mark.parametrize(
    "mutation",
    [
        "prior_file_creation",
        "prior_opaque_helper",
        "prior_local_import",
        "loader_file_creation",
        "loader_local_import",
    ],
)
def test_optional_configuration_requires_closed_initialization_effects(mutation):
    files = _optional_configuration_sources()
    if mutation in {
        "prior_file_creation",
        "prior_opaque_helper",
        "prior_local_import",
    }:
        effect = {
            "prior_file_creation": "open(optional, 'w').write('INSTALLED_APPS = []\\nMIDDLEWARE_CLASSES = []\\n')",
            "prior_opaque_helper": "prepare(optional)",
            "prior_local_import": "import service.side_effects",
        }[mutation]
        files["service/settings.py"] = files["service/settings.py"].replace(
            "if os.path.isfile", effect + "\nif os.path.isfile"
        )
        files["service/side_effects.py"] = (
            "open('service/private_settings.py', 'w').write('INSTALLED_APPS = []\\n')\n"
        )
    elif mutation == "loader_file_creation":
        files["start.py"] = (
            "open('service/private_settings.py', 'w').write('INSTALLED_APPS = []\\n')\n"
            + START
        )
    elif mutation == "loader_local_import":
        files["start.py"] = "import service.side_effects\n" + START
        files["service/side_effects.py"] = (
            "open('service/private_settings.py', 'w').write('INSTALLED_APPS = []\\n')\n"
        )
    assert _recovery_row(files)["tier"] == "NEEDS_CONTEXT"


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


@pytest.mark.parametrize("selector", ["Choice", "selected", "config_object"])
@pytest.mark.parametrize("snapshot", ["valid", "missing", "digest", "bytes", "ast"])
def test_name_configuration_validates_consumer_before_lazy_parents(selector, snapshot):
    from factoryline import semantic_credential_sensor as sensor

    raw = (
        "from policy import Policy as Choice\n"
        "def create(config_object):\n"
        "    selected = Choice\n"
        f"    app.config.from_object({selector})\n"
    ).encode()
    sources = {
        "consumer.py": raw,
        "policy.py": b"class Policy:\n    SECRET_KEY = 'published-material'\n",
    }
    context = sensor.signing_configuration_inventory(
        sources, {name: sha256(value).hexdigest() for name, value in sources.items()}
    )
    index, path = context["index"], Path("consumer.py")
    original_tree = index.snapshots[path]
    expression = next(
        node.args[0]
        for node in ast.walk(index.snapshots[path])
        if isinstance(node, ast.Call)
    )
    assert path not in index.parents
    if snapshot == "missing":
        del index.snapshots[path]
    elif snapshot == "digest":
        index.inventory[path] = "0" * 64
    elif snapshot == "bytes":
        index.source_bytes[path] = b"replacement = True\n"
    elif snapshot == "ast":
        replacement = ast.parse("replacement = True\n")
        replacement._oracle_source_sha256 = index.inventory[path]
        index.snapshots[path] = replacement
    selected = sensor._flask_selected_config(context, expression, path)
    if snapshot == "valid":
        assert index.validated[path] and path in index.parents
        assert (selected is not None) == (selector != "config_object")
        if selected is not None:
            assert selected[0] == Path("policy.py") and isinstance(
                selected[1], ast.ClassDef
            )
        parents = index.parents[path]
        assert sensor._flask_selected_config(context, expression, path) == selected
        assert index.parents[path] is parents
    else:
        assert (
            selected is None and not index.validated[path] and path not in index.parents
        )
        index.snapshots[path] = original_tree
        index.source_bytes[path] = raw
        index.inventory[path] = sha256(raw).hexdigest()
        restored = sensor._flask_selected_config(context, expression, path)
        assert index.validated[path] and (restored is not None) == (
            selector != "config_object"
        )


@pytest.mark.parametrize("target", ["config", "config.Policy"])
def test_literal_selected_configuration_keeps_existing_signing_authority(target):
    from test_semantic_credential_sensor import (
        _flask_login_config_sources,
        _captured_secret_tiers,
    )

    files = _flask_login_config_sources(target=target)
    if target.endswith("Policy"):
        files["config.py"] = (
            "class Policy:\n    SECRET_KEY = 'source-bound-login-signing-key'\n"
        )
    assert (
        _captured_secret_tiers(files, "config.py")["ledger"][0]["tier"]
        == "SUPPORTED_DEFECT"
    )


def test_literal_module_resolution_does_not_add_consumer_validation(monkeypatch):
    from factoryline import semantic_credential_sensor as sensor

    sources = {"consumer.py": b"import policy\n", "policy.py": b"VALUE = 1\n"}
    context = sensor.signing_configuration_inventory(
        sources, {name: sha256(raw).hexdigest() for name, raw in sources.items()}
    )
    index, original, calls = context["index"], context["index"].validate, []

    def validate(path):
        calls.append(path)
        return original(path)

    monkeypatch.setattr(index, "validate", validate)
    literal = ast.Constant(value="policy")
    first = sensor._flask_selected_config(context, literal, Path("consumer.py"))
    assert first == (Path("policy.py"), index.snapshots[Path("policy.py")])
    assert sensor._flask_selected_config(context, literal, Path("consumer.py")) == first
    assert Path("consumer.py") not in calls
