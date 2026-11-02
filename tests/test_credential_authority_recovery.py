"""Operative Django defaults require selected, unmodified runtime consumers."""

import ast
import copy
from hashlib import sha256
import json
from pathlib import Path

import pytest

from factoryline import review_audits as audit
from factoryline.primitive_observation_binding import build_finding_tier_report


@pytest.mark.parametrize(
    "change",
    [
        "bare",
        "overwrite",
        "clear",
        "shadow",
        "escape",
        "missing_include",
        "recursive_include",
        "provider",
        "storage",
        "signer",
    ],
)
def test_selected_feedback_counterexamples_respect_selected_source_scope(change):
    files = _recovery_sources(
        SETTINGS + 'ROOT_URLCONF = "service.urls"\n',
        extra={"service/urls.py": FEEDBACK_URLS},
    )
    _apply_source_mutations(files, FEEDBACK_COUNTEREXAMPLE_EDITS[change])
    row = _recovery_row(files)
    if change == "provider":
        # This sibling is not imported by Python or selected by Django settings.
        assert row["tier"] == "SUPPORTED_DEFECT"
        proof = row["credential_authority_observation"]
        assert (
            proof["proof_scope"] == "source_bound_selected_framework_feedback_default"
        )
        assert "mutation.py" not in {p["path"] for p in proof["supporting_sources"]}
    else:
        assert row["tier"] == "NEEDS_CONTEXT"
        assert "credential_authority_observation" not in row
    assert row["raw_finding"]["facts"]["name"] == "SECRET_KEY"
    assert row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"


SETTINGS = (
    'SECRET_KEY = "published-signing-material"\n'
    'INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "django.contrib.messages"]\n'
    'MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware", '
    '"django.contrib.auth.middleware.AuthenticationMiddleware", '
    '"django.contrib.messages.middleware.MessageMiddleware"]\n'
)
START = (
    "import os\nfrom django.core.wsgi import get_wsgi_application\n"
    'os.environ.setdefault("DJANGO_SETTINGS_MODULE", "service.settings")\n'
    "application = get_wsgi_application()\n"
)


def _recovery_sources(settings=SETTINGS, startup=START, extra=None):
    return {
        "service/__init__.py": "",
        "service/settings.py": settings
        + ('ROOT_URLCONF = "service.urls"\n' if "ROOT_URLCONF" not in settings else ""),
        "service/urls.py": 'from django.contrib import admin\nfrom django.urls import path\nurlpatterns = [path("admin/", admin.site.urls)]\n',
        "start.py": startup,
        **(extra or {}),
    }


FEEDBACK_URLS = (
    "from django.contrib import admin\n"
    "from django.urls import path, include\n"
    'urlpatterns = [path("admin/", admin.site.urls)]\n'
)


def _apply_source_mutations(files, mutations):
    """Apply compact replace, append, set, copy, and remove fixture edits."""
    for operation, path, *values in mutations:
        if operation == "replace":
            files[path] = files[path].replace(*values)
        elif operation == "append":
            files[path] += values[0]
        elif operation == "set":
            files[path] = values[0]
        elif operation == "copy":
            files[path] = files[values[0]]
        else:
            files.pop(path)


FEEDBACK_COUNTEREXAMPLE_EDITS = {
    "bare": (
        ("set", "service/settings.py", SETTINGS),
        ("remove", "service/urls.py"),
    ),
    "overwrite": (("append", "service/urls.py", "urlpatterns = []\n"),),
    "clear": (("append", "service/urls.py", "urlpatterns.clear()\n"),),
    "shadow": (
        ("replace", "service/urls.py", "[path(", '[path("admin/", replacement), path('),
    ),
    "escape": (("append", "service/urls.py", "escape(urlpatterns)\n"),),
    "missing_include": (
        ("replace", "service/urls.py", "admin.site.urls", 'include("missing.urls")'),
    ),
    "recursive_include": (
        ("replace", "service/urls.py", "admin.site.urls", 'include("service.urls")'),
    ),
    "provider": (
        (
            "set",
            "mutation.py",
            "from django.contrib import admin\nadmin.site.urls = replacement\n",
        ),
    ),
    "storage": (
        ("append", "service/settings.py", 'MESSAGE_STORAGE = "custom.Storage"\n'),
    ),
    "signer": (
        ("append", "service/settings.py", 'SIGNING_BACKEND = "custom.Signer"\n'),
    ),
}


def _nested_project_sources():
    files = _recovery_sources()
    files.pop("start.py")
    files.update({"service/asgi.py": START, "service/__init__.py": ""})
    for path, source in list(files.items()):
        files["service/" + path] = source
    script = (
        "import os\nimport sys\n"
        "def main():\n"
        '    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "service.settings")\n'
        "    from django.core.management import execute_from_command_line\n"
        "    execute_from_command_line(sys.argv)\n"
        'if __name__ == "__main__":\n    main()\n'
    )
    files["manage.py"] = script
    files["service/manage.py"] = script
    return files


def test_captured_script_module_direct_selection_and_sys_path_rejection():
    from factoryline import semantic_credential_sensor as sensor
    from factoryline.import_context import captured_script_module

    files = _nested_project_sources()
    raw = {name: source.encode() for name, source in files.items()}
    context = sensor.signing_configuration_inventory(
        raw, {name: sha256(value).hexdigest() for name, value in raw.items()}
    )
    assert context is not None
    parts, origin = ["service", "settings"], Path("service/service/settings.py")
    assert captured_script_module(context, parts, origin) == origin

    files["service/manage.py"] = files["service/manage.py"].replace(
        "def main():", 'sys.path.insert(0, "other")\ndef main():'
    )
    raw = {name: source.encode() for name, source in files.items()}
    context = sensor.signing_configuration_inventory(
        raw, {name: sha256(value).hexdigest() for name, value in raw.items()}
    )
    assert context is not None
    assert captured_script_module(context, parts, origin) is None


def test_eager_import_closure_directly_reports_sources_and_unresolved_imports():
    from factoryline import semantic_credential_sensor as sensor
    from factoryline.import_context import eager_import_closure

    sources = {
        "consumer.py": b"from provider import VALUE\n",
        "provider.py": b"VALUE = 1\n",
    }
    context = sensor.signing_configuration_inventory(
        sources, {name: sha256(value).hexdigest() for name, value in sources.items()}
    )
    proof = eager_import_closure(context["index"], (Path("consumer.py"),), set())
    assert proof["closed"]
    assert {row["path"] for row in proof["sources"]} == {"consumer.py", "provider.py"}
    assert proof["unresolved"] == []

    sources["consumer.py"] = b"from missing_provider import VALUE\n"
    context = sensor.signing_configuration_inventory(
        sources, {name: sha256(value).hexdigest() for name, value in sources.items()}
    )
    blocked = eager_import_closure(context["index"], (Path("consumer.py"),), set())
    assert not blocked["closed"]
    assert blocked["unresolved"][0]["reason"] == "unmodeled_eager_import_effects"


def test_close_selected_import_sources_records_closed_and_open_contracts():
    from factoryline import semantic_credential_sensor as sensor
    from factoryline.import_context import close_selected_import_sources

    sources = {
        "consumer.py": b"from provider import VALUE\n",
        "provider.py": b"VALUE = 1\n",
    }
    context = sensor.signing_configuration_inventory(
        sources, {name: sha256(value).hexdigest() for name, value in sources.items()}
    )
    selection, sites = Path("consumer.py"), (Path("consumer.py"),)
    assert close_selected_import_sources(context, selection, sites, set()) is sites
    assert context["selected_import_closures"][selection.as_posix()]["closed"]

    sources["consumer.py"] = b"from missing_provider import VALUE\n"
    context = sensor.signing_configuration_inventory(
        sources, {name: sha256(value).hexdigest() for name, value in sources.items()}
    )
    assert close_selected_import_sources(context, selection, sites, set()) is None
    blocked = context["selected_import_closures"][selection.as_posix()]
    assert not blocked["closed"]
    assert blocked["unresolved"][0]["reason"] == "unmodeled_eager_import_effects"


@pytest.mark.parametrize(
    "target", ["service/settings.py", "service/service/settings.py"]
)
def test_explicit_script_launch_disambiguates_nested_project_roots(target):
    row = _recovery_row(_nested_project_sources(), path=target)
    assert row["tier"] == "SUPPORTED_DEFECT"
    assert (
        row["credential_authority_observation"]["consumer_role"]
        == "signed_feedback_integrity"
    )


NESTED_MANAGE = "service/manage.py"
DORMANT_MANAGE_LAYOUTS = {
    "dormant_function": ("    def dormant():\n", "", "\n"),
    "dormant_class": ("    class Dormant:\n", "", "\n"),
    "dormant_lambda": ("    dormant = lambda: (\n", "    )\n", ",\n"),
    "dormant_comprehension": (
        "    dormant = [(\n",
        "    ) for item in []]\n",
        ",\n",
    ),
}


def _dormant_nested_manage_source(mutation):
    prefix, suffix, separator = DORMANT_MANAGE_LAYOUTS[mutation]
    statements = (
        'os.environ.setdefault("DJANGO_SETTINGS_MODULE", "service.settings")',
        "execute_from_command_line(sys.argv)",
    )
    body = separator.join("        " + statement for statement in statements) + "\n"
    return (
        "import os\nimport sys\nfrom django.core.management import execute_from_command_line\n"
        "def main():\n"
        + prefix
        + body
        + suffix
        + 'if __name__ == "__main__":\n    main()\n'
    )


NESTED_ROOT_EDITS = {
    "missing_launch": (("remove", NESTED_MANAGE),),
    "main_rebound": (
        ("replace", NESTED_MANAGE, "if __name__", "main = replacement\nif __name__"),
    ),
    "os_rebound": (
        ("replace", NESTED_MANAGE, "def main():", "os = replacement\ndef main():"),
    ),
    "sys_path": (
        (
            "replace",
            NESTED_MANAGE,
            "def main():",
            'sys.path.insert(0, "other")\ndef main():',
        ),
    ),
    "sys_modules": (
        (
            "replace",
            NESTED_MANAGE,
            "def main():",
            'sys.modules["service"] = other\ndef main():',
        ),
    ),
    "env_before": (
        (
            "replace",
            NESTED_MANAGE,
            "    os.environ.setdefault",
            '    os.environ["DJANGO_SETTINGS_MODULE"] = "other.settings"\n    os.environ.setdefault',
        ),
    ),
    "env_after": (
        (
            "replace",
            NESTED_MANAGE,
            "    execute_from_command_line(sys.argv)",
            '    os.environ["DJANGO_SETTINGS_MODULE"] = "other.settings"\n    execute_from_command_line(sys.argv)',
        ),
    ),
    "env_delete": (
        (
            "replace",
            NESTED_MANAGE,
            "    execute_from_command_line(sys.argv)",
            '    del os.environ["DJANGO_SETTINGS_MODULE"]\n    execute_from_command_line(sys.argv)',
        ),
    ),
    "env_update": (
        (
            "replace",
            NESTED_MANAGE,
            "    execute_from_command_line(sys.argv)",
            '    os.environ.update({"DJANGO_SETTINGS_MODULE": "other.settings"})\n    execute_from_command_line(sys.argv)',
        ),
    ),
    "env_pop": (
        (
            "replace",
            NESTED_MANAGE,
            "    execute_from_command_line(sys.argv)",
            '    os.environ.pop("DJANGO_SETTINGS_MODULE", None)\n    execute_from_command_line(sys.argv)',
        ),
    ),
    "env_clear": (
        (
            "replace",
            NESTED_MANAGE,
            "    execute_from_command_line(sys.argv)",
            "    os.environ.clear()\n    execute_from_command_line(sys.argv)",
        ),
    ),
    "env_alias": (
        (
            "replace",
            NESTED_MANAGE,
            "    execute_from_command_line(sys.argv)",
            '    env = os.environ\n    env["DJANGO_SETTINGS_MODULE"] = "other.settings"\n    execute_from_command_line(sys.argv)',
        ),
    ),
    "env_reassign": (
        (
            "replace",
            NESTED_MANAGE,
            "    execute_from_command_line(sys.argv)",
            "    os.environ = other_environment\n    execute_from_command_line(sys.argv)",
        ),
    ),
    "other_module": (
        ("replace", NESTED_MANAGE, '"service.settings"', '"other.settings"'),
    ),
    "sibling_module": (
        ("copy", "service/service/other.py", "service/service/settings.py"),
        ("replace", NESTED_MANAGE, '"service.settings"', '"service.other"'),
    ),
    "guarded_launch": (
        ("replace", NESTED_MANAGE, "    main()\n", "    if enabled:\n        main()\n"),
    ),
    "unknown_call": (
        ("replace", NESTED_MANAGE, "def main():", "mutate_environment()\ndef main():"),
    ),
    "sys_rebound": (
        ("replace", NESTED_MANAGE, "def main():", "sys = replacement\ndef main():"),
    ),
    "argv_rebound": (
        (
            "replace",
            NESTED_MANAGE,
            "def main():",
            "sys.argv = replacement\ndef main():",
        ),
    ),
    "arg_default": (
        (
            "replace",
            NESTED_MANAGE,
            "def main():",
            'def main(flag=os.environ.setdefault("DJANGO_SETTINGS_MODULE", "service.other")):',
        ),
    ),
    "kw_default": (
        (
            "replace",
            NESTED_MANAGE,
            "def main():",
            'def main(*, flag=os.environ.setdefault("DJANGO_SETTINGS_MODULE", "service.other")):',
        ),
    ),
    "extra_import": (
        (
            "replace",
            NESTED_MANAGE,
            "def main():",
            "import unknown_eager_effect\ndef main():",
        ),
    ),
    "second_default": (
        (
            "replace",
            NESTED_MANAGE,
            "    execute_from_command_line(sys.argv)",
            '    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "service.other")\n    execute_from_command_line(sys.argv)',
        ),
    ),
    "captured_import": (
        ("replace", NESTED_MANAGE, "def main():", "import poison\ndef main():"),
        (
            "set",
            "poison.py",
            'import os\nos.environ["DJANGO_SETTINGS_MODULE"] = "other.settings"\n',
        ),
    ),
    "os_shadow": (("set", "service/os.py", "environ = other_environment\n"),),
    "package_initializer": (
        (
            "set",
            "service/service/__init__.py",
            'import os\nos.environ["DJANGO_SETTINGS_MODULE"] = "service.other"\n',
        ),
    ),
    "module_definition_effect": (
        (
            "replace",
            NESTED_MANAGE,
            "def main():",
            'def unused(flag=os.environ.setdefault("DJANGO_SETTINGS_MODULE", "service.other")):\n    pass\ndef main():',
        ),
    ),
    "prior_raise": (
        (
            "replace",
            NESTED_MANAGE,
            "    os.environ.setdefault",
            '    raise ImportError("blocked startup")\n    os.environ.setdefault',
        ),
    ),
    "recursive_entry": (
        (
            "replace",
            NESTED_MANAGE,
            "    os.environ.setdefault",
            "    main()\n    os.environ.setdefault",
        ),
    ),
    "dormant_function": (
        ("set", NESTED_MANAGE, _dormant_nested_manage_source("dormant_function")),
    ),
    "dormant_class": (
        ("set", NESTED_MANAGE, _dormant_nested_manage_source("dormant_class")),
    ),
    "dormant_lambda": (
        ("set", NESTED_MANAGE, _dormant_nested_manage_source("dormant_lambda")),
    ),
    "dormant_comprehension": (
        ("set", NESTED_MANAGE, _dormant_nested_manage_source("dormant_comprehension")),
    ),
    "computed_default": (
        (
            "replace",
            NESTED_MANAGE,
            "    os.environ.setdefault",
            '    os.environ.setdefault("DJANGO_" + "SETTINGS_MODULE", "service.other")\n    os.environ.setdefault',
        ),
    ),
    "unknown_default": (
        (
            "replace",
            NESTED_MANAGE,
            "    os.environ.setdefault",
            '    os.environ.setdefault(unknown_key, "service.other")\n    os.environ.setdefault',
        ),
    ),
    "catch_and_continue": (
        (
            "replace",
            NESTED_MANAGE,
            "    from django.core.management import execute_from_command_line",
            "    try:\n        from django.core.management import execute_from_command_line\n    except ImportError:\n        pass",
        ),
    ),
    "late_module_import": (
        ("replace", NESTED_MANAGE, "import os\n", ""),
        ("append", NESTED_MANAGE, "import os\n"),
    ),
    "late_local_import": (
        ("replace", NESTED_MANAGE, "import os\n", ""),
        (
            "replace",
            NESTED_MANAGE,
            "    from django.core.management",
            "    import os\n    from django.core.management",
        ),
    ),
    "unrelated_env": (
        (
            "replace",
            NESTED_MANAGE,
            "    execute_from_command_line(sys.argv)",
            '    os.environ["FEATURE_FLAG"] = "enabled"\n    execute_from_command_line(sys.argv)',
        ),
    ),
    "entry_provider_shadow": (("replace", NESTED_MANAGE, "main()", "os()"),),
}


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_launch",
        "main_rebound",
        "os_rebound",
        "sys_path",
        "sys_modules",
        "env_before",
        "env_after",
        "env_delete",
        "env_update",
        "env_pop",
        "env_clear",
        "env_alias",
        "env_reassign",
        "other_module",
        "sibling_module",
        "guarded_launch",
        "unknown_call",
        "sys_rebound",
        "argv_rebound",
        "arg_default",
        "kw_default",
        "extra_import",
        "second_default",
        "captured_import",
        "os_shadow",
        "package_initializer",
        "module_definition_effect",
        "prior_raise",
        "recursive_entry",
        "dormant_function",
        "dormant_class",
        "dormant_lambda",
        "dormant_comprehension",
        "computed_default",
        "unknown_default",
        "catch_and_continue",
        "late_module_import",
        "late_local_import",
        "unrelated_env",
        "entry_provider_shadow",
    ],
)
def test_nested_root_requires_closed_explicit_script_selection(mutation):
    files = _nested_project_sources()
    _apply_source_mutations(files, NESTED_ROOT_EDITS[mutation])
    for source in files.values():
        ast.parse(source)
    assert (
        _recovery_row(files, path="service/service/settings.py")["tier"]
        == "NEEDS_CONTEXT"
    )


@pytest.mark.parametrize("startup", ["direct_import", "module_import", "import_try"])
def test_canonical_startup_and_docstring_packages_select_script_module(startup):
    files = _nested_project_sources()
    files["service/__init__.py"] = '"Package documentation only"\n'
    files["service/service/__init__.py"] = '"Nested package documentation only"\n'
    script = files["service/manage.py"]
    provider = "from django.core.management import execute_from_command_line"
    if startup == "module_import":
        script = script.replace("    " + provider + "\n", "")
        script = script.replace("def main():", provider + "\ndef main():")
    elif startup == "import_try":
        script = script.replace(
            "    " + provider,
            "    try:\n        "
            + provider
            + '\n    except ImportError as exc:\n        raise ImportError("Missing Django") from exc',
        )
    files["service/manage.py"] = script
    assert (
        _recovery_row(files, path="service/service/settings.py")["tier"]
        == "SUPPORTED_DEFECT"
    )


def test_nested_script_root_public_cli_and_source_bound_reseal(tmp_path, capsys):
    from factoryline.cli import main

    files = _nested_project_sources()
    for name, source in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.encode())
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
    report = json.loads(capsys.readouterr().out)
    assert report["audit_coverage"]["complete"]
    assert report["finding_tier_report"]["tier_counts"]["SUPPORTED_DEFECT"] == 2
    assert len(report["agent_actions"]) == 2
    assert all(
        (tmp_path / name).read_bytes() == source.encode()
        for name, source in files.items()
    )
    rebuilt = copy.deepcopy(report)
    rebuilt["_primitive_source_bytes"] = {
        name: source.encode() for name, source in files.items()
    }
    assert (
        audit._seal_security_scan(rebuilt)["finding_tier_report"]
        == report["finding_tier_report"]
    )
    rebuilt = copy.deepcopy(report)
    rebuilt["_primitive_source_bytes"] = {
        name: source.encode() for name, source in files.items()
    }
    rebuilt["_primitive_source_bytes"]["service/manage.py"] = (
        b"different_selected_source\n"
    )
    changed = audit._seal_security_scan(rebuilt)
    assert changed["defect_policy_decision"]["state"] == "BLOCKED"


@pytest.mark.parametrize(
    "dependency,expected",
    [
        ("missing", "NEEDS_CONTEXT"),
        ("closed", "SUPPORTED_DEFECT"),
        ("mutating", "NEEDS_CONTEXT"),
        ("transitive_missing", "NEEDS_CONTEXT"),
        ("standard_parent_shadow", "NEEDS_CONTEXT"),
    ],
)
def test_selected_provider_import_requires_eager_dependency_closure(
    dependency, expected
):
    files = _provider_configuration_sources()
    files["widget/views.py"] = (
        "from extension_transport import VALUE\n" + files["widget/views.py"]
    )
    if dependency == "closed":
        files["extension_transport.py"] = "VALUE = 1\n"
    elif dependency == "mutating":
        files["extension_transport.py"] = (
            "from django.conf import settings\nsettings.SECRET_KEY = 'replacement'\nVALUE = 1\n"
        )
    elif dependency == "transitive_missing":
        files["extension_transport.py"] = "from absent_transport import VALUE\n"
    elif dependency == "standard_parent_shadow":
        files["extension_transport.py"] = "import unittest.mock\nVALUE = 1\n"
        files["unittest/__init__.py"] = "pass\n"
    row = _recovery_row(files)
    assert row["tier"] == expected
    assert row["raw_finding"]["facts"] == {"name": "SECRET_KEY"}
    if dependency == "missing":
        evidence = row["unresolved_provider_imports"]
        assert any(
            item["module"] == "extension_transport"
            and item["reason"] == "unmodeled_eager_import_effects"
            and item["path"] == "widget/views.py"
            and item["sha256"] == sha256(files["widget/views.py"].encode()).hexdigest()
            for item in evidence
        )
        assert "source_bound_eager_provider_import_closure" in row["missing_premises"]


def _provider_configuration_sources():
    return _recovery_sources(
        extra={
            "widget/__init__.py": 'from django.conf import settings\n_DEFAULTS = {"EXTENSION_FLAG": True, "EXTENSION_LABEL": "x"}\nfor key, value in list(_DEFAULTS.items()):\n    try:\n        getattr(settings, key)\n    except AttributeError:\n        setattr(settings, key, value)\n',
            "widget/views.py": "from importlib import import_module\nfrom django.conf import settings\nfrom django.views import View\nSessionStore = import_module(settings.SESSION_ENGINE).SessionStore\nclass Callback(View):\n    pass\n",
            "service/urls.py": 'from django.contrib import admin\nfrom django.urls import path\nfrom widget.views import Callback\nurlpatterns = [path("admin/", admin.site.urls), path("extension/", Callback.as_view())]\n',
        }
    )


NATIVE_SELECTED_SETTING_EDITS = {
    "secret_key": (("replace", "widget/__init__.py", "EXTENSION_FLAG", "SECRET_KEY"),),
    "wrapped": (("replace", "widget/__init__.py", "EXTENSION_FLAG", "_wrapped"),),
    "dunder": (("replace", "widget/__init__.py", "EXTENSION_FLAG", "__dict__"),),
    "explicit": (
        (
            "append",
            "service/settings.py",
            'SESSION_ENGINE = "django.contrib.sessions.backends.db"\n',
        ),
    ),
    "importer_alias": (
        (
            "replace",
            "widget/views.py",
            "import import_module",
            "import import_module as load",
        ),
        ("replace", "widget/views.py", "= import_module(", "= load("),
    ),
    "dict_alias": (
        ("replace", "widget/__init__.py", "for key,", "copy = _DEFAULTS\nfor key,"),
    ),
    "dict_update": (
        (
            "replace",
            "widget/__init__.py",
            "for key,",
            '_DEFAULTS.update({"SECRET_KEY": "replacement"})\nfor key,',
        ),
    ),
    "dict_escape": (
        ("replace", "widget/__init__.py", "for key,", "escape(_DEFAULTS)\nfor key,"),
    ),
    "foreign_dict": (
        (
            "set",
            "mutation.py",
            'from widget import _DEFAULTS\n_DEFAULTS["SECRET_KEY"] = "replacement"\n',
        ),
    ),
    "mutated_builtin": (
        ("set", "mutation.py", "import builtins\nbuiltins.setattr = replacement\n"),
    ),
    "mutated_importer": (
        (
            "set",
            "mutation.py",
            "import importlib\nimportlib.import_module = replacement\n",
        ),
    ),
    "importer_rebound": (
        (
            "replace",
            "widget/views.py",
            "SessionStore =",
            "import_module = replacement\nSessionStore =",
        ),
    ),
    "backend_override": (
        (
            "set",
            "mutation.py",
            'from django.conf import settings\nsettings.SESSION_ENGINE = "unknown.backend"\n',
        ),
    ),
    "dynamic_module": (
        ("replace", "widget/views.py", "settings.SESSION_ENGINE", "choose_module()"),
    ),
    "reflected_module": (
        (
            "replace",
            "widget/views.py",
            "settings.SESSION_ENGINE",
            'getattr(settings, "SESSION_ENGINE")',
        ),
    ),
    "backend_member": (
        (
            "set",
            "mutation.py",
            "import django.contrib.sessions.backends.db as backend\nbackend.SessionStore = replacement\n",
        ),
    ),
    "importlib_file": (
        ("set", "importlib.py", "def import_module(name):\n    return unknown\n"),
    ),
    "importlib_package": (
        (
            "set",
            "importlib/__init__.py",
            "def import_module(name):\n    return unknown\n",
        ),
    ),
    "importer_escape": (
        ("set", "mutation.py", "import importlib\nescape(importlib)\n"),
    ),
    "literal_selected": (
        (
            "replace",
            "widget/views.py",
            "settings.SESSION_ENGINE",
            '"django.contrib.sessions.backends.db"',
        ),
    ),
    "plain_explicit": (
        (
            "replace",
            "widget/views.py",
            "from django.conf import settings",
            "import service.settings as settings",
        ),
        (
            "append",
            "service/settings.py",
            'SESSION_ENGINE = "django.contrib.sessions.backends.db"\n',
        ),
    ),
    "missing_plain_setting": (
        (
            "replace",
            "widget/views.py",
            "from django.conf import settings",
            "import service.settings as settings",
        ),
    ),
    "key_rebound": (
        (
            "replace",
            "widget/__init__.py",
            "        getattr",
            '        key = "SECRET_KEY"\n        getattr',
        ),
    ),
    "dict_chained_alias": (
        ("replace", "widget/__init__.py", "_DEFAULTS =", "copy = _DEFAULTS ="),
    ),
    "relative_foreign_dict": (
        (
            "set",
            "widget/peer.py",
            'from . import _DEFAULTS\n_DEFAULTS["SECRET_KEY"] = "replacement"\n',
        ),
    ),
    "dict_module_escape": (("set", "mutation.py", "import widget\nescape(widget)\n"),),
    "dict_peer_alias_only": (
        ("set", "mutation.py", "from widget import _DEFAULTS as copied\n"),
    ),
    "backend_dynamic_setting": (
        ("append", "service/settings.py", "SESSION_ENGINE = choose_backend()\n"),
    ),
    "backend_global_rebind": (
        (
            "append",
            "service/settings.py",
            'def change_engine():\n    global SESSION_ENGINE\n    SESSION_ENGINE = "unknown.backend"\n',
        ),
    ),
    "loader_namespace_escape": (
        ("set", "mutation.py", "import sys\nescape(sys.modules)\n"),
    ),
    "wrong_module_literal": (
        (
            "replace",
            "widget/views.py",
            "settings.SESSION_ENGINE",
            '"unexpected.plugin"',
        ),
    ),
    "wrong_terminal_member": (
        ("replace", "widget/views.py", ").SessionStore", ").Unknown"),
    ),
    "backend_store_alias_mutation": (
        (
            "set",
            "mutation.py",
            "from widget.views import SessionStore as Store\nStore.attribute = replacement\n",
        ),
    ),
    "importlib_ambiguous": (
        ("set", "importlib.py", "pass\n"),
        ("set", "importlib/__init__.py", "pass\n"),
    ),
}


@pytest.mark.parametrize(
    "change,expected",
    [
        ("default", "SUPPORTED_DEFECT"),
        ("explicit", "SUPPORTED_DEFECT"),
        ("importer_alias", "SUPPORTED_DEFECT"),
        ("secret_key", "NEEDS_CONTEXT"),
        ("wrapped", "NEEDS_CONTEXT"),
        ("dunder", "NEEDS_CONTEXT"),
        ("dict_alias", "NEEDS_CONTEXT"),
        ("dict_update", "NEEDS_CONTEXT"),
        ("dict_escape", "NEEDS_CONTEXT"),
        ("foreign_dict", "NEEDS_CONTEXT"),
        ("mutated_builtin", "NEEDS_CONTEXT"),
        ("mutated_importer", "NEEDS_CONTEXT"),
        ("importer_rebound", "NEEDS_CONTEXT"),
        ("backend_override", "NEEDS_CONTEXT"),
        ("dynamic_module", "NEEDS_CONTEXT"),
        ("reflected_module", "NEEDS_CONTEXT"),
        ("backend_member", "NEEDS_CONTEXT"),
        ("importlib_file", "NEEDS_CONTEXT"),
        ("importlib_package", "NEEDS_CONTEXT"),
        ("importer_escape", "NEEDS_CONTEXT"),
        ("literal_selected", "SUPPORTED_DEFECT"),
        ("plain_explicit", "SUPPORTED_DEFECT"),
        ("missing_plain_setting", "NEEDS_CONTEXT"),
        ("key_rebound", "NEEDS_CONTEXT"),
        ("dict_chained_alias", "NEEDS_CONTEXT"),
        ("relative_foreign_dict", "NEEDS_CONTEXT"),
        ("dict_module_escape", "NEEDS_CONTEXT"),
        ("dict_peer_alias_only", "NEEDS_CONTEXT"),
        ("backend_dynamic_setting", "NEEDS_CONTEXT"),
        ("backend_global_rebind", "NEEDS_CONTEXT"),
        ("loader_namespace_escape", "NEEDS_CONTEXT"),
        ("wrong_module_literal", "NEEDS_CONTEXT"),
        ("wrong_terminal_member", "NEEDS_CONTEXT"),
        ("backend_store_alias_mutation", "NEEDS_CONTEXT"),
        ("importlib_ambiguous", "NEEDS_CONTEXT"),
    ],
)
def test_native_selected_setting_import_requires_closed_finite_source(change, expected):
    files = _provider_configuration_sources()
    _apply_source_mutations(files, NATIVE_SELECTED_SETTING_EDITS.get(change, ()))
    row = _recovery_row(files)
    assert row["tier"] == expected
    assert row["raw_finding"]["facts"] == {"name": "SECRET_KEY"}
    if expected == "SUPPORTED_DEFECT":
        proof = row["credential_authority_observation"]["selected_consumer"]
        assert (
            proof["configuration_imports"][0]["module"]
            == "django.contrib.sessions.backends.db"
        )
        assert proof["configuration_imports"][0]["source"]["path"] == "widget/views.py"
        assert proof["finite_configuration_fields"][0]["fields"] == [
            "EXTENSION_FLAG",
            "EXTENSION_LABEL",
        ]


def _recovery_row(files, name="SECRET_KEY", path="service/settings.py"):
    sources = {path: source.encode() for path, source in files.items()}
    findings = audit._security_scan_tree(Path("."), Path(path), ast.parse(files[path]))
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


@pytest.mark.parametrize(
    "helper", ["finite_keys", "import_operand", "scalar_owner", "scalar_capability"]
)
def test_primed_native_provider_proof_rechecks_selected_helper_dependencies(
    tmp_path, monkeypatch, helper
):
    from factoryline import (
        import_context,
        credential_endpoint_admission,
        context_efficiency,
        mock_fixture_provenance,
    )

    files = _provider_configuration_sources()
    if helper in {"scalar_owner", "scalar_capability"}:
        files["consumer.py"] = (
            "from django.conf import settings\nvalue = settings.SECRET_KEY.encode()\n"
        )
    for name, source in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
    options = {
        "security_only": True,
        "defect_policy": "source-role-v3",
        "cache_enabled": True,
    }
    before = audit.security_scan(tmp_path, **options)
    assert before["finding_tier_report"]["ledger"][0]["tier"] == "SUPPORTED_DEFECT"
    if helper == "finite_keys":
        monkeypatch.setattr(
            import_context, "finite_key_reflection_reads", lambda *args, **kwargs: set()
        )
    elif helper == "import_operand":
        monkeypatch.setattr(
            credential_endpoint_admission,
            "_django_setting_import_operand",
            lambda *args: False,
        )
    elif helper == "scalar_owner":
        monkeypatch.setattr(
            context_efficiency, "_informed_unshadowed", lambda *args: False
        )
    else:
        monkeypatch.setattr(
            mock_fixture_provenance,
            "_jwt_module_has_dynamic_execution",
            lambda *args: True,
        )
    after = audit.security_scan(tmp_path, **options)
    row = after["finding_tier_report"]["ledger"][0]
    if helper in {"scalar_owner", "scalar_capability"}:
        # The unselected consumer does not participate in the framework witness.
        assert row["tier"] == "SUPPORTED_DEFECT"
        proof = row["credential_authority_observation"]
        assert (
            proof["proof_scope"] == "source_bound_selected_framework_feedback_default"
        )
        assert "consumer.py" not in {p["path"] for p in proof["supporting_sources"]}
    else:
        assert row["tier"] == "NEEDS_CONTEXT"
    assert before["findings"] == after["findings"]


@pytest.mark.parametrize(
    "route_style", ["alias", "legacy", "nested", "overwrite_selected"]
)
def test_selected_feedback_routes_bind_effective_consumers(route_style):
    files = _recovery_sources()
    if route_style == "alias":
        files["service/urls.py"] = (
            'from django.contrib import admin as staff\nfrom django.urls import path as route\nurlpatterns = [route("staff/", staff.site.urls)]\n'
        )
    elif route_style == "legacy":
        files["service/urls.py"] = (
            'from django.contrib import admin\nfrom django.conf.urls import url\nurlpatterns = [url(r"^admin/", admin.site.urls)]\n'
        )
    elif route_style == "nested":
        files["service/urls.py"] = (
            'from django.urls import include, path\nurlpatterns = [path("staff/", include("service.staff"))]\n'
        )
        files["service/staff.py"] = (
            'from django.contrib import admin\nfrom django.urls import path\nurlpatterns = [path("admin/", admin.site.urls)]\n'
        )
    else:
        files["service/urls.py"] = files["service/urls.py"].replace(
            "urlpatterns =", "urlpatterns = []\nurlpatterns ="
        )
    row = _recovery_row(files)
    assert row["tier"] == "SUPPORTED_DEFECT"
    assert (
        row["credential_authority_observation"]["selected_consumer"]["model"]
        == "django.admin.feedback.v1"
    )
    assert row["raw_finding"]["facts"] == {"name": "SECRET_KEY"}


@pytest.mark.parametrize(
    "target", ["factory()", "mutate(admin.site)", "unknown", "missing"]
)
def test_unknown_handler_or_factory_cannot_be_innocuous_admin_sibling(target):
    files = _recovery_sources()
    files["service/urls.py"] = (
        "from django.contrib import admin\nfrom django.urls import path\nfrom .missing import missing\n"
        f'urlpatterns = [path("other/", {target}), path("admin/", admin.site.urls)]\n'
    )
    assert _recovery_row(files)["tier"] == "NEEDS_CONTEXT"


@pytest.mark.parametrize(
    "pattern,expected", [("^", "NEEDS_CONTEXT"), ("^$", "SUPPORTED_DEFECT")]
)
def test_legacy_regex_prefix_and_terminal_route_precedence(pattern, expected):
    files = _recovery_sources(
        extra={
            "service/views.py": "def home(request):\n    return None\n",
            "service/urls.py": "from django.contrib import admin\nfrom django.conf.urls import url\nfrom .views import home\n"
            f'urlpatterns = [url({pattern!r}, home), url(r"^admin/", admin.site.urls)]\n',
        }
    )
    assert _recovery_row(files)["tier"] == expected


@pytest.mark.parametrize(
    "configuration",
    [
        'SESSION_ENGINE = "custom.sessions"',
        'SESSION_SERIALIZER = "custom.Serializer"',
        'SECRET_KEY_FALLBACKS = ["different-key"]',
        "MESSAGE_LEVEL = 50",
        'ROOT_URLCONF = "missing.urls"',
    ],
)
def test_selected_feedback_requires_closed_key_storage_and_backend(configuration):
    row = _recovery_row(
        _recovery_sources(
            SETTINGS + 'ROOT_URLCONF = "service.urls"\n' + configuration + "\n"
        )
    )
    assert row["tier"] == "NEEDS_CONTEXT"
    assert row["raw_finding"]["facts"] == {"name": "SECRET_KEY"}


@pytest.mark.parametrize(
    "sequence,expected",
    [
        (
            'urlpatterns = []\nurlpatterns += [path("admin/", admin.site.urls)]',
            "SUPPORTED_DEFECT",
        ),
        (
            'more = [path("admin/", admin.site.urls)]\nurlpatterns = []\nurlpatterns += more',
            "SUPPORTED_DEFECT",
        ),
        (
            'urlpatterns = patterns("", url(r"^admin/", include(admin.site.urls)))',
            "SUPPORTED_DEFECT",
        ),
        (
            'urlpatterns = [path("admin/", admin.site.urls)]\nif False:\n    urlpatterns.clear()',
            "SUPPORTED_DEFECT",
        ),
        (
            'urlpatterns = []\nif unknown:\n    urlpatterns += [path("admin/", admin.site.urls)]',
            "NEEDS_CONTEXT",
        ),
        (
            'more = [path("admin/", admin.site.urls)]\nurlpatterns = []\nmore.clear()\nurlpatterns += more',
            "NEEDS_CONTEXT",
        ),
        (
            'more = [path("admin/", admin.site.urls)]\nurlpatterns = more',
            "NEEDS_CONTEXT",
        ),
    ],
)
def test_effective_feedback_sequence_composition_and_unknown_mutation(
    sequence, expected
):
    files = _recovery_sources(
        extra={
            "service/urls.py": "from django.contrib import admin\nfrom django.urls import path, include\nfrom django.conf.urls import patterns, url\n"
            + sequence
            + "\n"
        }
    )
    row = _recovery_row(files)
    assert row["tier"] == expected
    assert row["raw_finding"]["facts"] == {"name": "SECRET_KEY"}


@pytest.mark.parametrize(
    "prefix,before,expected",
    [
        ("/assets/", True, "SUPPORTED_DEFECT"),
        ("/", True, "NEEDS_CONTEXT"),
        ("/", False, "SUPPORTED_DEFECT"),
    ],
)
def test_registered_static_routes_preserve_real_order_and_prefix(
    prefix, before, expected
):
    files = _recovery_sources(
        SETTINGS + f'DEBUG = True\nSTATIC_URL = {prefix!r}\nSTATIC_ROOT = "files"\n'
    )
    start = (
        "from django.conf import settings\nfrom django.conf.urls.static import static\n"
    )
    addition = "static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)"
    admin = '[path("admin/", admin.site.urls)]'
    files["service/urls.py"] = (
        start
        + "from django.contrib import admin\nfrom django.urls import path\nurlpatterns = "
        + (addition + " + " + admin if before else admin + " + " + addition)
        + "\n"
    )
    assert _recovery_row(files)["tier"] == expected
    files["mutation.py"] = 'from service import settings\nsettings.STATIC_URL = "/"\n'
    assert _recovery_row(files)["tier"] == "NEEDS_CONTEXT"


@pytest.mark.parametrize(
    "pattern,expected",
    [(r"^p/(?P<pk>[0-9]+)/$", "SUPPORTED_DEFECT"), (r"^p/|admin/", "NEEDS_CONTEXT")],
)
def test_compiled_regex_sibling_prefix_is_conservative(pattern, expected):
    files = _recovery_sources(
        extra={
            "service/views.py": "def home(request):\n    return None\n",
            "service/urls.py": "from django.contrib import admin\nfrom django.conf.urls import url\nfrom .views import home\n"
            + f'urlpatterns = [url({pattern!r}, home), url(r"^admin/", admin.site.urls)]\n',
        }
    )
    assert _recovery_row(files)["tier"] == expected


def test_impossible_regex_cannot_create_selected_feedback_consumer():
    files = _recovery_sources(
        extra={
            "service/urls.py": 'from django.contrib import admin\nfrom django.conf.urls import url\nurlpatterns = [url(r"^admin(?!)", admin.site.urls)]\n'
        }
    )
    assert _recovery_row(files)["tier"] == "NEEDS_CONTEXT"


@pytest.mark.parametrize(
    "change,expected",
    [
        ("closed", "SUPPORTED_DEFECT"),
        ("override", "NEEDS_CONTEXT"),
        ("unknown_base", "NEEDS_CONTEXT"),
        ("provider", "NEEDS_CONTEXT"),
        ("nonexistent_builtin", "NEEDS_CONTEXT"),
    ],
)
def test_framework_cbv_callback_binds_selected_as_view_provider(change, expected):
    cls = "from django.views.generic import TemplateView\nclass Home(TemplateView):\n    pass\n"
    if change == "override":
        cls = cls.replace("    pass", "    def as_view(cls):\n        return unknown()")
    elif change == "unknown_base":
        cls = cls.replace("class Home(TemplateView)", "class Home(UnknownBase)")
    elif change == "nonexistent_builtin":
        cls = cls.replace("TemplateView", "ImaginaryView")
    files = _recovery_sources(
        extra={
            "service/views.py": cls,
            "service/urls.py": 'from django.contrib import admin\nfrom django.urls import path\nfrom .views import Home\nurlpatterns = [path("", Home.as_view()), path("admin/", admin.site.urls)]\n',
        }
    )
    if change == "provider":
        files["mutation.py"] = (
            "from django.views.generic import TemplateView\nTemplateView.as_view = unknown\n"
        )
    row = _recovery_row(files)
    assert row["tier"] == ("SUPPORTED_DEFECT" if change == "provider" else expected)
    if change == "provider":
        proof = row["credential_authority_observation"]
        assert (
            proof["proof_scope"] == "source_bound_selected_framework_feedback_default"
        )
        assert "mutation.py" not in {p["path"] for p in proof["supporting_sources"]}
        assert row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"


@pytest.mark.parametrize(
    "change,expected",
    [
        ("wildcard_before", "SUPPORTED_DEFECT"),
        ("wildcard_after", "NEEDS_CONTEXT"),
        ("foreign_replacement", "NEEDS_CONTEXT"),
    ],
)
def test_callback_declaration_epoch_and_provider_remain_closed(change, expected):
    function = "def home(request):\n    return None\n"
    source = (
        ("from decimal import *\n" + function)
        if change != "wildcard_after"
        else (function + "from decimal import *\n")
    )
    files = _recovery_sources(
        extra={
            "service/views.py": source,
            "service/urls.py": 'from django.contrib import admin\nfrom django.urls import path\nfrom .views import home\nurlpatterns = [path("other/", home), path("admin/", admin.site.urls)]\n',
        }
    )
    if change == "foreign_replacement":
        files["mutation.py"] = "from service import views\nviews.home = unknown\n"
    assert _recovery_row(files)["tier"] == expected


def test_feedback_signer_does_not_depend_on_authentication_backend_value():
    row = _recovery_row(
        _recovery_sources(SETTINGS + 'AUTHENTICATION_BACKENDS = ["custom.Backend"]\n')
    )
    assert row["tier"] == "SUPPORTED_DEFECT"
    assert (
        row["credential_authority_observation"]["consumer_role"]
        == "signed_feedback_integrity"
    )


@pytest.mark.parametrize("mutation", ["authority", "settings_model"])
def test_cached_native_feedback_admission_rechecks_current_helper_contract(
    tmp_path, monkeypatch, mutation
):
    from factoryline import credential_endpoint_admission as admission

    for name, source in _recovery_sources().items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
    options = {
        "security_only": True,
        "defect_policy": "source-role-v3",
        "cache_enabled": True,
    }
    before = audit.security_scan(tmp_path, **options)
    assert before["finding_tier_report"]["ledger"][0]["tier"] == "SUPPORTED_DEFECT"
    if mutation == "authority":
        monkeypatch.setattr(admission, "_django_default_authority", lambda *args: None)
    else:
        monkeypatch.setattr(
            admission._CredentialHandlerIndex,
            "_django_feedback_settings",
            staticmethod(lambda: {"SECRET_KEY": set()}),
        )
    after = audit.security_scan(tmp_path, **options)
    assert after["finding_tier_report"]["ledger"][0]["tier"] == "NEEDS_CONTEXT"
    assert before["findings"] == after["findings"]


@pytest.mark.parametrize(
    "change",
    [
        "selected",
        "unguarded",
        "no_operation",
        "wrong_order",
        "receiver_replaced",
        "effect_provider_replaced",
    ],
)
def test_authenticated_operation_feedback_binds_selected_effect_source(change):
    files = _recovery_sources(
        extra={
            "service/urls.py": 'from django.urls import path\nfrom .views import change\nurlpatterns = [path("change/", change)]\n',
            "service/forms.py": "from django import forms\nclass ChangeForm(forms.ModelForm):\n    pass\n",
            "service/views.py": 'from django.contrib.auth.decorators import login_required\nfrom django.contrib import messages\nfrom .forms import ChangeForm\n@login_required\ndef change(request):\n    form = ChangeForm(request.POST)\n    form.save()\n    messages.success(request, "Record saved")\n',
        }
    )
    if change == "unguarded":
        files["service/views.py"] = files["service/views.py"].replace(
            "@login_required\n", ""
        )
    elif change == "no_operation":
        files["service/views.py"] = files["service/views.py"].replace(
            "    form.save()\n", ""
        )
    elif change == "wrong_order":
        files["service/views.py"] = files["service/views.py"].replace(
            '    form.save()\n    messages.success(request, "Record saved")',
            '    messages.success(request, "Record saved")\n    form.save()',
        )
    elif change == "receiver_replaced":
        files["service/views.py"] = files["service/views.py"].replace(
            "    form.save()", "    form = replacement\n    form.save()"
        )
    elif change == "effect_provider_replaced":
        files["mutation.py"] = (
            "from django.contrib import messages\nmessages.success = replacement\n"
        )
    row = _recovery_row(files)
    assert row["tier"] == (
        "SUPPORTED_DEFECT"
        if change in {"selected", "effect_provider_replaced"}
        else "NEEDS_CONTEXT"
    )
    assert row["raw_finding"]["facts"] == {"name": "SECRET_KEY"}
    if change in {"selected", "effect_provider_replaced"}:
        proof = row["credential_authority_observation"]
        assert (
            proof["proof_scope"] == "source_bound_selected_framework_feedback_default"
        )
        assert (
            proof["selected_consumer"]["model"]
            == "django.authenticated-operation.feedback.v1"
        )
        assert {r["path"] for r in proof["transfers"]} >= {
            "service/forms.py",
            "service/views.py",
            "service/urls.py",
        }
        assert "mutation.py" not in {p["path"] for p in proof["supporting_sources"]}


@pytest.mark.parametrize("material", ["your_key", "YOUR SECRET KEY", "change-this-key"])
def test_local_signing_default_spelling_does_not_negate_selected_authority(material):
    files = _recovery_sources(SETTINGS.replace("published-signing-material", material))
    row = _recovery_row(files)
    assert row["tier"] == "SUPPORTED_DEFECT"
    proof = row["credential_authority_observation"]
    assert proof["consumer_role"] == "signed_feedback_integrity"
    assert proof["selected_consumer"]["model"] == "django.admin.feedback.v1"
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
    assert len(proof["transfers"]) >= 7
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
def test_unselected_reflection_module_does_not_negate_framework_feedback(mutation):
    row = _recovery_row(
        _recovery_sources(
            extra={
                "reader.py": "from django.conf import settings\n" + mutation + "\n",
            }
        )
    )
    # No startup, app, middleware, URL or backend selection executes reader.py.
    assert row["tier"] == "SUPPORTED_DEFECT"
    proof = row["credential_authority_observation"]
    assert proof["proof_scope"] == "source_bound_selected_framework_feedback_default"
    assert "reader.py" not in {p["path"] for p in proof["supporting_sources"]}
    assert row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"


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
def test_selected_container_reads_and_unselected_mutations_preserve_feedback(extra):
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
        row = _recovery_row(_recovery_sources(extra=changed))
        assert row["tier"] == "SUPPORTED_DEFECT"
        proof = row["credential_authority_observation"]
        assert (
            proof["proof_scope"] == "source_bound_selected_framework_feedback_default"
        )
        assert "reader.py" not in {p["path"] for p in proof["supporting_sources"]}
        assert row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"


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
    "alias,prelude",
    [
        ("settings", ""),
        ("runtime_settings", ""),
        ("settings", "import operator\nunrelated = operator.add(1, 2)\n"),
    ],
)
def test_selected_literal_scalar_encoding_preserves_native_authority(alias, prelude):
    row = _recovery_row(
        _recovery_sources(
            extra={
                "consumer.py": f"from django.conf import settings as {alias}\n"
                + prelude
                + f"def derive():\n    return {alias}.SECRET_KEY.encode()\n"
            }
        )
    )
    assert row["tier"] == "SUPPORTED_DEFECT"
    assert row["raw_finding"]["facts"] == {"name": "SECRET_KEY"}
    assert (
        row["credential_authority_observation"]["runtime_execution"] == "not_performed"
    )


def test_unselected_scalar_module_does_not_trigger_capability_scan(monkeypatch):
    import sys
    from factoryline import mock_fixture_provenance as fixture

    consumer = (
        "from django.conf import settings\n"
        + "\n".join(f"ordinary_{i} = len('value')" for i in range(40))
        + "\nfirst = settings.SECRET_KEY.encode()\n"
        "second = settings.SECRET_KEY.encode()\n"
    )
    unrelated = "\n".join(f"ordinary_{i} = len('value')" for i in range(40)) + "\n"
    original = fixture._jwt_module_has_dynamic_execution
    observed = []

    def observe(module):
        frame = sys._getframe(1)
        while (
            frame is not None
            and frame.f_code.co_name != "_django_selected_consumers_closed"
        ):
            frame = frame.f_back
        if frame is not None:
            observed.append((frame, module))
        return original(module)

    monkeypatch.setattr(fixture, "_jwt_module_has_dynamic_execution", observe)
    row = _recovery_row(
        _recovery_sources(extra={"consumer.py": consumer, "unrelated.py": unrelated})
    )
    assert row["tier"] == "SUPPORTED_DEFECT"
    proof = row["credential_authority_observation"]
    assert proof["proof_scope"] == "source_bound_selected_framework_feedback_default"
    assert {p["path"] for p in proof["supporting_sources"]}.isdisjoint(
        {"consumer.py", "unrelated.py"}
    )
    assert observed == []
    assert row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"


@pytest.mark.parametrize(
    "source",
    [
        'value = settings.SECRET_KEY.encode("utf8")',
        'value = settings.SECRET_KEY.encode(encoding="utf8")',
        "value = settings.SECRET_KEY.encode(*())",
        "value = settings.SECRET_KEY.encode(**{})",
        "value = settings.SECRET_KEY.lower()",
        "value = settings.SECRET_KEY.decode()",
        "value = settings.SECRET_KEY.__class__().encode()",
        "def derive(settings):\n    return settings.SECRET_KEY.encode()",
        "def derive():\n    settings = replacement\n    return settings.SECRET_KEY.encode()",
        "settings = replacement\nvalue = settings.SECRET_KEY.encode()",
        "escape([settings])\nvalue = settings.SECRET_KEY.encode()",
        "settings.__dict__['SECRET_KEY'] = replacement\nvalue = settings.SECRET_KEY.encode()",
        "setattr(settings, 'SECRET_KEY', replacement)\nvalue = settings.SECRET_KEY.encode()",
        "value = replace(settings).SECRET_KEY.encode()",
        "value = [settings.SECRET_KEY.encode() for settings in replacements]",
        "class Receiver:\n    settings = replacement\n    value = settings.SECRET_KEY.encode()",
        "def outer(settings):\n    def inner():\n        return settings.SECRET_KEY.encode()\n    return inner()",
        "namespace = settings.__dict__\nvalue = settings.SECRET_KEY.encode()",
        "value = vars(settings)\nencoded = settings.SECRET_KEY.encode()",
        "settings.SECRET_KEY = replacement\nvalue = settings.SECRET_KEY.encode()",
        "globals()['settings'] = replacement\nvalue = settings.SECRET_KEY.encode()",
        "from builtins import globals as namespace\nnamespace()['settings'] = replacement\n"
        "value = settings.SECRET_KEY.encode()",
        "def helper():\n    pass\nhelper.__globals__['settings'] = replacement\n"
        "value = settings.SECRET_KEY.encode()",
        "from builtins import getattr as lookup\ndef helper():\n    pass\n"
        "lookup(helper, '__globals__').update({'settings': replacement})\n"
        "value = settings.SECRET_KEY.encode()",
        "import sys\nsys._getframe().f_globals['settings'] = replacement\n"
        "value = settings.SECRET_KEY.encode()",
        "from operator import attrgetter as lookup\ndef helper():\n    pass\n"
        "namespace = lookup('__globals__')(helper)\nnamespace['settings'] = replacement\n"
        "value = settings.SECRET_KEY.encode()",
        "import operator as capability\ndef helper():\n    pass\n"
        "capability.methodcaller('__getattribute__', '__globals__')(helper)['settings'] = replacement\n"
        "value = settings.SECRET_KEY.encode()",
    ],
)
def test_unselected_scalar_receivers_do_not_replace_framework_feedback_proof(
    source,
):
    row = _recovery_row(
        _recovery_sources(
            extra={"consumer.py": "from django.conf import settings\n" + source + "\n"}
        )
    )
    # This proves framework feedback, not the sibling's scalar receiver/calls.
    assert row["tier"] == "SUPPORTED_DEFECT"
    proof = row["credential_authority_observation"]
    assert proof["proof_scope"] == "source_bound_selected_framework_feedback_default"
    assert proof["consumer_role"] == "signed_feedback_integrity"
    assert "consumer.py" not in {p["path"] for p in proof["supporting_sources"]}
    assert row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"


@pytest.mark.parametrize(
    "replacement",
    [
        'SECRET_KEY = "second-literal"',
        "SECRET_KEY = replacement",
        "class Custom(str):\n    def encode(self):\n        mutate()\n"
        "SECRET_KEY = Custom(SECRET_KEY)",
    ],
)
def test_selected_scalar_encoding_requires_one_unchanged_literal_declaration(
    replacement,
):
    row = _recovery_row(
        _recovery_sources(
            SETTINGS + replacement + "\n",
            extra={
                "consumer.py": "from django.conf import settings\n"
                "value = settings.SECRET_KEY.encode()\n"
            },
        )
    )
    assert row["tier"] == "NEEDS_CONTEXT"
    assert "credential_authority_observation" not in row


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
def test_authentication_route_without_signed_feedback_has_no_selected_authority(
    extra_target,
):
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
    row = _recovery_row(files)
    assert row["tier"] == "NEEDS_CONTEXT"
    assert row["raw_finding"]["facts"]["name"] == "SECRET_KEY"


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


@pytest.mark.parametrize(
    "mutation", ["urlpatterns.clear()", "alias = urlpatterns\nalias.clear()"]
)
def test_selected_admin_route_rejects_later_container_mutation(mutation):
    files = _recovery_sources()
    files["service/urls.py"] += mutation + "\n"
    row = _recovery_row(files)
    assert row["tier"] == "NEEDS_CONTEXT"
    assert "credential_authority_observation" not in row
    assert row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"


@pytest.mark.parametrize("container", ["list", "concat"])
@pytest.mark.parametrize("suffix", ["path()", "missing_value", "disturb()"])
def test_selected_admin_route_requires_complete_eager_construction(container, suffix):
    files = _recovery_sources()
    first = 'path("admin/", admin.site.urls)'
    expression = (
        f"[{first}, {suffix}]" if container == "list" else f"[{first}] + [{suffix}]"
    )
    files["service/urls.py"] = (
        "from django.contrib import admin\nfrom django.urls import path\n"
        'def disturb():\n    raise RuntimeError("URL construction failed")\n'
        f"urlpatterns = {expression}\n"
    )
    row = _recovery_row(files)
    assert row["tier"] == "NEEDS_CONTEXT"
    assert "credential_authority_observation" not in row


@pytest.mark.parametrize("container", ["list", "concat"])
def test_selected_admin_route_allows_closed_unrelated_later_handler(container):
    files = _recovery_sources()
    first = 'path("admin/", admin.site.urls)'
    later = 'path("plain/", plain)'
    expression = (
        f"[{first}, {later}]" if container == "list" else f"[{first}] + [{later}]"
    )
    files["service/urls.py"] = (
        "from django.contrib import admin\nfrom django.urls import path\n"
        "def plain(request):\n    return None\n"
        f"urlpatterns = {expression}\n"
    )
    assert _recovery_row(files)["tier"] == "SUPPORTED_DEFECT"


@pytest.mark.parametrize(
    "replacement",
    [
        "import django.core.wsgi as loader\nloader.get_wsgi_application = lambda: None",
        "from django.core import wsgi as loader\nloader.get_wsgi_application = lambda: None",
        "get_wsgi_application = lambda: None",
        'from django.conf import settings\nsettings.SECRET_KEY = "replacement-key"',
        'import service.settings as cfg\ncfg.SECRET_KEY = "replacement-key"',
        "import django.contrib.sessions.middleware as layers\nlayers.SessionMiddleware = lambda: None",
    ],
)
def test_selected_startup_rejects_loader_and_configuration_replacement(replacement):
    from factoryline import semantic_credential_sensor as sensor

    files = _recovery_sources(
        startup=START.replace("application =", replacement + "\napplication =")
    )
    sources = {name: source.encode() for name, source in files.items()}
    context = sensor.signing_configuration_inventory(
        sources, {name: sha256(raw).hexdigest() for name, raw in sources.items()}
    )
    finding = _recovery_row(files)["raw_finding"]
    assert sensor.signing_configuration_evidence(finding, context) is None


@pytest.mark.parametrize("snapshot", ["valid", "missing", "bytes", "digest", "ast"])
def test_selected_signing_closure_transports_hashes_and_rejects_stale_dependency(
    snapshot,
):
    from factoryline import semantic_credential_sensor as sensor

    files = _recovery_sources(
        startup="import helper\n" + START, extra={"helper.py": 'LABEL = "support"\n'}
    )
    sources = {name: source.encode() for name, source in files.items()}
    context = sensor.signing_configuration_inventory(
        sources, {name: sha256(raw).hexdigest() for name, raw in sources.items()}
    )
    finding = _recovery_row(files)["raw_finding"]
    evidence = sensor.signing_configuration_evidence(finding, context)
    assert evidence is not None
    assert {row["path"]: row["sha256"] for row in evidence["supporting_sources"]}[
        "helper.py"
    ] == sha256(sources["helper.py"]).hexdigest()
    index, path = context["index"], Path("helper.py")
    if snapshot == "missing":
        del index.snapshots[path]
    elif snapshot == "bytes":
        index.source_bytes[path] = b'LABEL = "changed"\n'
    elif snapshot == "digest":
        index.inventory[path] = "0" * 64
    elif snapshot == "ast":
        index.snapshots[path].body.append(ast.parse("replacement = True").body[0])
    regenerated = sensor.signing_configuration_evidence(finding, context)
    assert (regenerated is not None) == (snapshot == "valid")
    if regenerated is not None:
        assert regenerated == evidence


@pytest.mark.parametrize("container", ["list", "concat"])
@pytest.mark.parametrize("effect", ["harmless", "key_replacement"])
@pytest.mark.parametrize("suffix_routes", ["empty", "nonempty"])
def test_selected_admin_suffix_include_closes_eager_import_effects(
    container, effect, suffix_routes
):
    files = _recovery_sources()
    first = 'path("admin/", admin.site.urls)'
    later = 'path("tail/", include("service.tail"))'
    expression = (
        f"[{first}, {later}]" if container == "list" else f"[{first}] + [{later}]"
    )
    files["service/urls.py"] = (
        "from django.contrib import admin\nfrom django.urls import path, include\n"
        f"urlpatterns = {expression}\n"
    )
    files["service/tail.py"] = "import mutator\n" + (
        "urlpatterns = []\n"
        if suffix_routes == "empty"
        else "from django.urls import path\n"
        "def plain(request):\n    return None\n"
        'urlpatterns = [path("plain/", plain)]\n'
    )
    files["mutator.py"] = (
        'from django.conf import settings\nsettings.SECRET_KEY = "replacement-key"\n'
        if effect == "key_replacement"
        else 'LABEL = "harmless"\n'
    )
    row = _recovery_row(files)
    assert row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"
    if effect == "key_replacement":
        assert row["tier"] == "NEEDS_CONTEXT"
        assert "credential_authority_observation" not in row
    else:
        assert row["tier"] == "SUPPORTED_DEFECT"
        proof = row["credential_authority_observation"]
        assert proof["selected_consumer"]["model"] == "django.admin.feedback.v1"
        assert {
            item["path"]: item["sha256"] for item in proof["supporting_sources"]
        } == {
            name: sha256(source.encode()).hexdigest() for name, source in files.items()
        }


@pytest.mark.parametrize(
    "reachable", [False, True], ids=["unimported", "startup_import"]
)
@pytest.mark.parametrize(
    "hazard",
    ["admin_provider", "cbv_provider", "feedback_provider", "middleware", "secret_key"],
)
def test_framework_feedback_authority_binds_hazard_execution_scope(hazard, reachable):
    files = _recovery_sources()
    mutations = {
        "admin_provider": "from django.contrib import admin\nadmin.site.urls = replacement\n",
        "cbv_provider": "from django.views.generic import TemplateView\nTemplateView.as_view = unknown\n",
        "feedback_provider": "from django.contrib import messages\nmessages.success = replacement\n",
        "middleware": "from django.conf import settings\nsettings.MIDDLEWARE.clear()\n",
        "secret_key": 'from django.conf import settings\nsettings.SECRET_KEY = "replacement-key"\n',
    }
    files["mutation.py"] = mutations[hazard]
    if hazard == "cbv_provider":
        files["service/views.py"] = (
            "from django.views.generic import TemplateView\n"
            "class Home(TemplateView):\n    pass\n"
        )
        files["service/urls.py"] = (
            "from django.contrib import admin\nfrom django.urls import path\n"
            "from .views import Home\n"
            'urlpatterns = [path("", Home.as_view()), path("admin/", admin.site.urls)]\n'
        )
    elif hazard == "feedback_provider":
        files["service/urls.py"] = (
            "from django.urls import path\nfrom .views import change\n"
            'urlpatterns = [path("change/", change)]\n'
        )
        files["service/forms.py"] = (
            "from django import forms\nclass ChangeForm(forms.ModelForm):\n    pass\n"
        )
        files["service/views.py"] = (
            "from django.contrib.auth.decorators import login_required\n"
            "from django.contrib import messages\nfrom .forms import ChangeForm\n"
            "@login_required\ndef change(request):\n"
            "    form = ChangeForm(request.POST)\n    form.save()\n"
            '    messages.success(request, "Record saved")\n'
        )
    if reachable:
        files["start.py"] = START.replace(
            "application =", "import mutation\napplication ="
        )
    row = _recovery_row(files)
    assert row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"
    assert row["raw_finding"]["facts"] == {"name": "SECRET_KEY"}
    if reachable:
        assert row["tier"] == "NEEDS_CONTEXT"
        assert "credential_authority_observation" not in row
    else:
        assert row["tier"] == "SUPPORTED_DEFECT"
        proof = row["credential_authority_observation"]
        assert (
            proof["proof_scope"] == "source_bound_selected_framework_feedback_default"
        )
        assert proof["consumer_role"] == "signed_feedback_integrity"
        assert proof["selected_consumer"]["model"] == (
            "django.authenticated-operation.feedback.v1"
            if hazard == "feedback_provider"
            else "django.admin.feedback.v1"
        )
        assert "mutation.py" not in {p["path"] for p in proof["supporting_sources"]}
        assert proof["runtime_execution"] == "not_performed"
        assert proof["deployment"] == "UNASSESSED"
