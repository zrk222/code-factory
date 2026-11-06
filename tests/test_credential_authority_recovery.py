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


@pytest.mark.parametrize(
    "first,second,supported",
    [
        ("service.other", "service.settings", False),
        ("service.settings", "service.other", True),
        ("service.settings", "service.settings", True),
        ("missing.settings", "service.settings", False),
    ],
)
def test_django_startup_defaults_preserve_first_settings_selection(
    first, second, supported
):
    startup = (
        "import os\nfrom django.core.wsgi import get_wsgi_application\n"
        "os.environ.setdefault('UNRELATED', 'service.other')\n"
        f"os.environ.setdefault('DJANGO_SETTINGS_MODULE', {first!r})\n"
        f"os.environ.setdefault('DJANGO_SETTINGS_MODULE', {second!r})\n"
        "application = get_wsgi_application()\n"
    )
    row = _recovery_row(
        _recovery_sources(startup=startup, extra={"service/other.py": SETTINGS})
    )
    assert row["tier"] == ("SUPPORTED_DEFECT" if supported else "NEEDS_CONTEXT")
    assert row["raw_finding"]["facts"]["name"] == "SECRET_KEY"
    if supported:
        proof = row["credential_authority_observation"]
        assert proof["selected_consumer"]["model"] == "django.admin.feedback.v1"
        assert any(
            edge["path"] == "start.py" and edge["span"][0] == 4
            for edge in proof["transfers"]
        )


@pytest.mark.parametrize(
    "prefix",
    [
        "os.environ.setdefault(unknown_key, 'service.other')\n",
        "os.environ.setdefault('DJANGO_' + 'SETTINGS_MODULE', 'service.other')\n",
        "os.environ.setdefault('DJANGO_SETTINGS_MODULE', value='service.other')\n",
        "os.environ.setdefault(*selection)\n",
        "selected: str = os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'service.other')\n",
        "os.environ.setdefault('UNRELATED', mutate_environment())\n",
        "if os.getenv('MODE') == 'other':\n"
        "    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'service.other')\n",
        "if os.getenv('MODE') == 'other':\n"
        "    from os import environ as selected_env\n"
        "    selected_env.setdefault('DJANGO_SETTINGS_MODULE', 'service.other')\n",
        "try:\n    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'service.other')\n"
        "except Exception:\n    pass\n",
    ],
)
@pytest.mark.parametrize("interface", ["wsgi", "asgi"])
def test_django_startup_defaults_refuse_unresolved_prior_selection(prefix, interface):
    startup = START.replace(
        "os.environ.setdefault", prefix + "os.environ.setdefault", 1
    )
    startup = startup.replace("wsgi", interface)
    row = _recovery_row(
        _recovery_sources(startup=startup, extra={"service/other.py": SETTINGS})
    )
    assert row["tier"] == "NEEDS_CONTEXT"
    assert row["raw_finding"]["facts"]["name"] == "SECRET_KEY"


@pytest.mark.parametrize("local_provider", [False, True])
def test_django_family_guarded_management_loader_reaches_selected_consumer(
    local_provider,
):
    provider = "from django.core.management import execute_from_command_line\n"
    body = (
        "    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'service.settings')\n"
        + (
            "    try:\n        "
            + provider
            + "    except ImportError as exc:\n        raise ImportError('Django required') from exc\n"
            if local_provider
            else ""
        )
        + "    execute_from_command_line(sys.argv)\n"
    )
    startup = (
        "import os\nimport sys\n"
        + ("" if local_provider else provider)
        + "def main():\n"
        + body
        + "if __name__ == '__main__':\n    main()\n"
    )
    row = _recovery_row(_recovery_sources(startup=startup))
    assert row["tier"] == "SUPPORTED_DEFECT"
    proof = row["credential_authority_observation"]
    assert proof["selected_consumer"]["model"] == "django.admin.feedback.v1"
    assert any(edge["path"] == "start.py" for edge in proof["transfers"])


@pytest.mark.parametrize(
    "mutation", ["uncalled", "shadowed", "extra_argument", "conditional"]
)
def test_django_family_management_loader_requires_closed_invocation(mutation):
    startup = (
        "import os\nimport sys\n"
        "from django.core.management import execute_from_command_line\n"
        "def main():\n"
        "    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'service.settings')\n"
        "    execute_from_command_line(sys.argv)\n"
        "if __name__ == '__main__':\n    main()\n"
    )
    if mutation == "uncalled":
        startup = startup.replace("    main()\n", "    pass\n")
    elif mutation == "shadowed":
        startup = startup.replace("if __name__", "main = lambda: None\nif __name__")
    elif mutation == "extra_argument":
        startup = startup.replace("    main()\n", "    main('unproved')\n")
    else:
        startup = startup.replace("    main()\n", "    if enabled:\n        main()\n")
    row = _recovery_row(_recovery_sources(startup=startup))
    assert row["tier"] == "NEEDS_CONTEXT"
    assert row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"


@pytest.mark.parametrize(
    "helper",
    ["captured_django_management_contract", "captured_django_startup_statements"],
)
def test_django_family_changed_loader_invalidates_retained_proof_epoch(
    monkeypatch, helper
):
    from factoryline import import_context
    from factoryline.credential_role_constructor_provider import (
        _helper_snapshot,
        helper_epochs_valid,
    )
    from factoryline.credential_role_identity_effects import security_value_helper_epoch

    snapshot = _helper_snapshot(security_value_helper_epoch)
    epochs = {"proof": (security_value_helper_epoch, snapshot)}
    assert helper_epochs_valid(epochs)

    def replaced(_context, _path):
        return None

    monkeypatch.setattr(getattr(import_context, helper), "__code__", replaced.__code__)
    assert not helper_epochs_valid(epochs)


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
    "metadata",
    [
        {},
        {"pyproject.toml": '[project]\nname="library"\n'},
        {"setup.cfg": "[metadata]\nname = library\n"},
        {"setup.py": 'from setuptools import setup\nsetup(packages=["library"])\n'},
        {
            "pyproject.toml": '[build-system]\nbuild-backend="setuptools.build_meta"\n'
            '[tool.setuptools]\npackages=["library"]\n'
            '[tool.pytest.ini_options]\nDJANGO_SETTINGS_MODULE="service.settings"\n'
        },
    ],
)
def test_authority_domain_unshipped_runnable_signer_preserves_authority(metadata):
    files = _recovery_sources(
        SETTINGS + 'DEBUG = True\nALLOWED_HOSTS = ["localhost"]\n',
        extra={"README.md": "This is only a demo and its key is fake.", **metadata},
    )
    row = _recovery_row(files)
    assert row["tier"] == "SUPPORTED_DEFECT"
    assert row["raw_finding"]["facts"] == {"name": "SECRET_KEY"}
    proof = row["credential_authority_observation"]
    assert proof["distribution_runtime_selection"] == (
        "UNASSESSED" if metadata else "no_captured_distribution_declaration"
    )
    assert proof["settings_runtime_selection"] == "captured_settings_loader"
    assert proof["consumer_effect_phase"] == "signed_feedback_cookie_acceptance"
    assert proof["rendered_output"] == "UNASSESSED"
    assert {ref["path"] for ref in proof["transfers"]} >= {
        "start.py",
        "service/urls.py",
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("distribution_runtime_selection", "shipped_application"),
        ("settings_runtime_selection", "environment_deployment"),
        ("rendered_output", "PROVEN"),
        ("consumer_effect_phase", "rendered_security_feedback"),
    ],
)
def test_authority_domain_native_admission_rejects_forged_assurance(field, value):
    from factoryline import primitive_observation_binding as binding
    from factoryline import semantic_credential_sensor as sensor

    files = _recovery_sources()
    row = _recovery_row(files)
    finding = row["raw_finding"]
    proof = copy.deepcopy(row["credential_authority_observation"])
    proof[field] = value
    raw = {name: source.encode() for name, source in files.items()}
    hashes = {name: sha256(source).hexdigest() for name, source in raw.items()}
    context = sensor.signing_configuration_inventory(raw, hashes)
    result = binding._decide_finding_tier(
        finding,
        True,
        [finding],
        [],
        proof,
        source_bindings=hashes,
        credential_context=context,
    )
    assert result[0] == "NEEDS_CONTEXT"


def _configured_test_domain_sources(mode="model", namespace="verification"):
    project = (
        '[build-system]\nbuild-backend="flit_core.buildapi"\n'
        '[tool.flit.module]\nname="library"\n'
        '[project.optional-dependencies]\ncheck=["pytest", "pytest-django"]\n'
        "[tool.pytest.ini_options]\ndjango_find_project=false\n"
        f'DJANGO_SETTINGS_MODULE="{namespace}.config"\ntestpaths=["{namespace}"]\n'
    )
    settings = SETTINGS.replace(
        '"django.contrib.messages"]',
        f'"django.contrib.messages", "{namespace}.resource"]',
    ) + (
        f'ROOT_URLCONF="{namespace}.urls"\n'
        f'WSGI_APPLICATION="{namespace}.wsgi.application"\n'
        'DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}\n'
    )
    consumer = (
        f"from django.test import TestCase\nfrom {namespace}.resource.models import Item\n"
        "class TestExercise(TestCase):\n"
        "    def setUp(self):\n        self.obj = Item.objects.create(label='fixture')\n"
        "    def test_roundtrip(self):\n        self.assertEqual(self.obj.label, 'fixture')\n"
        if mode == "model"
        else "import pytest\nfrom django.core.management import call_command\n"
        "@pytest.mark.django_db\ndef test_database():\n    call_command('migrate', 'resource', 'zero')\n"
    )
    return {
        "pyproject.toml": project,
        "library/__init__.py": "",
        f"{namespace}/__init__.py": "",
        f"{namespace}/config.py": settings,
        f"{namespace}/urls.py": FEEDBACK_URLS,
        f"{namespace}/wsgi.py": START.replace(
            "service.settings", namespace + ".config"
        ),
        f"{namespace}/resource/__init__.py": "",
        f"{namespace}/resource/models.py": "from django.db import models\n"
        "class Item(models.Model):\n    label = models.CharField(max_length=32)\n",
        f"{namespace}/test_flow.py": consumer,
    }


@pytest.mark.parametrize("mode", ["model", "migration"])
@pytest.mark.parametrize("namespace", ["verification", "neutral_resources"])
def test_authority_domain_requires_configured_transactional_consumers(mode, namespace):
    files = _configured_test_domain_sources(mode, namespace)
    row = _recovery_row(files, path=namespace + "/config.py")
    assert row["tier"] == "NEEDS_CONTEXT"
    assert row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"
    proof = row["credential_authority_observation"]
    domain = proof["authority_domain"]
    assert proof["proof_scope"] == "source_bound_configured_test_feedback"
    assert domain["role"] == "CONFIGURED_TEST_INVOCATION_SIGNER"
    assert domain["application_authority"] == "UNKNOWN"
    assert domain["isolation_assurance"] == "UNASSESSED"
    assert domain["consumer"]["effect_span"]
    assert len(domain["source_inventory_sha256"]) == 64


@pytest.mark.parametrize("mode", ["model", "migration"])
def test_django_family_management_bootstrap_keeps_configured_test_ownership(mode):
    files = _configured_test_domain_sources(mode)
    files["manage.py"] = (
        "import os\nimport sys\n"
        "from django.core.management import execute_from_command_line\n"
        "def main():\n"
        "    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'verification.config')\n"
        "    execute_from_command_line(sys.argv)\n"
        "if __name__ == '__main__':\n    main()\n"
    )
    row = _recovery_row(files, path="verification/config.py")
    assert row["tier"] == "NEEDS_CONTEXT"
    domain = row["credential_authority_observation"]["authority_domain"]
    assert domain["role"] == "CONFIGURED_TEST_INVOCATION_SIGNER"
    assert any(edge["path"] == "manage.py" for edge in domain["management_loaders"])


@pytest.mark.parametrize(
    "escape", ["none", "construct", "globals", "module_getattr", "receiver"]
)
def test_django_family_inherited_fixture_effects_share_transactional_owner(escape):
    files = _configured_test_domain_sources()
    files["verification/support.py"] = (
        "from verification.resource.models import Item\n"
        "class SeedMixin:\n"
        "    def setUp(self):\n        self.obj = Item.objects.create(label='fixture')\n"
        "class AlternateMixin:\n"
        "    def setUp(self):\n        self.obj = Item.objects.create(label='other')\n"
    )
    files["verification/test_flow.py"] = (
        "from django.test import TestCase\n"
        "from verification.support import SeedMixin, AlternateMixin\n"
        "class TestFirst(SeedMixin, TestCase):\n"
        "    def test_roundtrip(self):\n        self.assertEqual(self.obj.label, 'fixture')\n"
        "class TestSecond(AlternateMixin, TestCase):\n"
        "    def test_roundtrip(self):\n        self.assertEqual(self.obj.label, 'other')\n"
    )
    if escape == "construct":
        files["live.py"] = (
            "from verification.support import SeedMixin\n"
            "live = SeedMixin()\nlive.setUp()\n"
        )
    elif escape == "globals":
        files["live.py"] = (
            "from verification.support import SeedMixin\n"
            "live = globals()['SeedMixin']()\nlive.setUp()\n"
        )
    elif escape == "module_getattr":
        files["live.py"] = (
            "import verification.support as helpers\n"
            "live = getattr(helpers, 'SeedMixin')()\nlive.setUp()\n"
        )
    elif escape == "receiver":
        files["verification/support.py"] = files["verification/support.py"].replace(
            "        self.obj =",
            "        global retained\n        retained = self\n        self.obj =",
            1,
        )
    row = _recovery_row(files, path="verification/config.py")
    escaped = escape != "none"
    assert row["tier"] == ("SUPPORTED_DEFECT" if escaped else "NEEDS_CONTEXT")
    domain = row["credential_authority_observation"]["authority_domain"]
    assert (domain is None) is escaped


def test_shared_class_collection_is_independent_of_first_skipped_method():
    files = _configured_test_domain_sources()
    files["verification/test_flow.py"] = (
        files["verification/test_flow.py"]
        .replace(
            "from django.test import TestCase",
            "import unittest\nfrom django.test import TestCase",
        )
        .replace(
            "    def setUp(self):",
            "    @unittest.skip('optional')\n    def test_optional(self):\n        pass\n    def setUp(self):",
        )
    )
    row = _recovery_row(files, path="verification/config.py")
    assert row["tier"] == "NEEDS_CONTEXT"
    assert row["credential_authority_observation"]["authority_domain"] is not None


@pytest.mark.parametrize("escape", [False, True])
def test_shared_decorated_method_does_not_hide_another_class_lifecycle(escape):
    files = _configured_test_domain_sources()
    files["verification/support.py"] = (
        "from verification.resource.models import Item\n"
        "class SeedMixin:\n"
        "    def setUp(self):\n        self.obj = Item.objects.create(label='fixture')\n"
    )
    files["verification/test_flow.py"] = (
        "from django.test import TestCase\n"
        "from verification.support import SeedMixin\n"
        "class TestFirst(SeedMixin, TestCase):\n"
        "    def test_roundtrip(self):\n        self.assertEqual(self.obj.label, 'fixture')\n"
        "class TestSecond(SeedMixin, TestCase):\n"
        "    @unknown_wrapper\n"
        "    def test_optional(self):\n        pass\n"
    )
    if escape:
        files["verification/test_flow.py"] = (
            "from verification.resource.models import Item\n"
            + files["verification/test_flow.py"]
        ).replace("        pass", "        Item.objects.create(label='unowned')")
    row = _recovery_row(files, path="verification/config.py")
    domain = row.get("credential_authority_observation", {}).get("authority_domain")
    assert bool(domain) is not escape


@pytest.mark.parametrize(
    "wrapper", ["@opaque\n", "@opaque()\n", "@pytest.mark.django_db(unknown())\n"]
)
def test_shared_transactional_free_test_requires_closed_metadata_decorators(wrapper):
    files = _configured_test_domain_sources("migration")
    files["verification/test_flow.py"] = files["verification/test_flow.py"].replace(
        "@pytest.mark.django_db\n", wrapper + "@pytest.mark.django_db\n"
    )
    row = _recovery_row(files, path="verification/config.py")
    assert (
        row.get("credential_authority_observation", {}).get("authority_domain") is None
    )


def test_shared_test_invocation_context_does_not_claim_unmarked_transaction():
    files = _configured_test_domain_sources("migration")
    files["verification/test_other.py"] = (
        "from verification.resource.models import Item\n"
        "def test_unmarked():\n    Item.objects.create(label='unmarked-test')\n"
    )
    row = _recovery_row(files, path="verification/config.py")
    assert row["tier"] == "NEEDS_CONTEXT"
    domain = row["credential_authority_observation"]["authority_domain"]
    assert domain["role"] == "CONFIGURED_TEST_INVOCATION_SIGNER"
    assert (
        domain["ownership_scope"]
        == "captured_pytest_invocation_not_transaction_isolation"
    )
    assert domain["transactional_consumer_phase"] == "witness_only"
    assert domain["isolation_assurance"] == "UNASSESSED"
    assert domain["application_authority"] == "UNKNOWN"
    assert "transactional_owners" not in domain
    assert "verification/test_other.py" in {
        owner["path"] for owner in domain["test_invocation_owners"]
    }
    assert domain["consumer"]["source"]["path"] != "verification/test_other.py"


@pytest.mark.parametrize("escape", ["none", "return", "callback", "shadow"])
def test_shared_lexical_test_helpers_require_closed_call_ownership(escape):
    files = _configured_test_domain_sources()
    body = (
        "        def create_pair():\n            return Item.objects.create(label='nested')\n"
        "        def consume_pair():\n            return create_pair()\n"
        "        consume_pair()\n"
    )
    if escape == "return":
        body += "        return create_pair\n"
    elif escape == "callback":
        body += "        pending.append(lambda: create_pair())\n"
    elif escape == "shadow":
        body = body.replace(
            "def consume_pair():", "def consume_pair(create_pair=unknown):"
        )
    files["verification/test_flow.py"] += body
    row = _recovery_row(files, path="verification/config.py")
    assert bool(
        row.get("credential_authority_observation", {}).get("authority_domain")
    ) is (escape == "none")


@pytest.mark.parametrize(
    "expression,eager",
    [
        ("[Item.objects.create(label='eager') for _ in range(2)]", True),
        ("(Item.objects.create(label='deferred') for _ in range(2))", False),
    ],
)
def test_shared_transactional_comprehension_phase_preserves_deferral(expression, eager):
    files = _configured_test_domain_sources()
    files["verification/test_flow.py"] += "        values = " + expression + "\n"
    row = _recovery_row(files, path="verification/config.py")
    assert (
        bool(row.get("credential_authority_observation", {}).get("authority_domain"))
        is eager
    )


@pytest.mark.parametrize("mutation", ["none", "source", "helper", "inventory"])
def test_shared_terminal_batch_reuses_only_fresh_provider_derivations(
    monkeypatch, mutation
):
    from factoryline import credential_role_constructor_provider as provider
    from factoryline import mock_fixture_provenance as fixture
    from factoryline import semantic_credential_sensor as sensor

    files = _configured_test_domain_sources()
    files["verification/test_flow.py"] += (
        "class TestSecond(TestCase):\n    def test_other(self):\n        pass\n"
    )
    raw = {name: text.encode() for name, text in files.items()}
    context = sensor.signing_configuration_inventory(
        raw, {name: sha256(data).hexdigest() for name, data in raw.items()}
    )
    source = context["index"]
    index = fixture.application_test_index(
        source.root,
        source.snapshots,
        source.source_bytes,
        source.inventory,
        raw,
        source_index=source,
    )
    roots, _apps, _project, patterns = __import__(
        "factoryline.credential_identity_audit",
        fromlist=["_django_test_domain_profile"],
    )._django_test_domain_profile(index, Path("verification/config.py"))
    original = provider._captured_terminal_provider_mutation
    seen = []

    def counted(*args, **kwargs):
        seen.append(args[2])
        result = original(*args, **kwargs)
        if mutation == "source":
            source.snapshots[Path("verification/test_flow.py")].body.append(
                ast.parse("tamper = 1").body[0]
            )
        elif mutation == "inventory":
            source.inventory[Path("verification/test_flow.py")] = "0" * 64
        elif mutation == "helper":
            monkeypatch.setattr(
                provider, "_terminal_provider_mutated", lambda *a, **k: False
            )
        return result

    monkeypatch.setattr(provider, "_captured_terminal_provider_mutation", counted)
    from factoryline import credential_identity_audit as authority

    ownership = authority._django_transactional_owners(index, roots, patterns)
    assert (ownership is not None) is (mutation == "none")
    assert seen.count("django.test.TestCase") == (2 if mutation == "helper" else 1)


@pytest.mark.parametrize("decorator", ["skipIf", "skipUnless"])
@pytest.mark.parametrize(
    "mutation",
    ["none", "provider", "shadow", "effect", "object", "rebound", "conditional"],
)
def test_shared_transactional_class_decorators_preserve_only_closed_identity(
    decorator, mutation
):
    files = _configured_test_domain_sources()
    files["verification/support.py"] = (
        "from verification.resource.models import Item\n"
        "class SeedMixin:\n"
        "    def setUp(self):\n        self.obj = Item.objects.create(label='fixture')\n"
    )
    args = "'optional'" if decorator == "skip" else "ENABLED, 'optional'"
    prefix = (
        "import unittest\nENABLED = "
        + ("False" if decorator == "skipIf" else "True")
        + "\n"
    )
    if mutation == "provider":
        prefix += f"unittest.{decorator} = replacement\n"
    elif mutation == "shadow":
        files["unittest.py"] = "def skip(*args):\n    return replacement\n"
    elif mutation == "effect":
        args = "unknown()" if decorator == "skip" else "unknown(), 'optional'"
    elif mutation == "rebound":
        prefix += "ENABLED = " + ("True" if decorator == "skipIf" else "False") + "\n"
    elif mutation == "conditional":
        prefix = "import unittest\nif external:\n    ENABLED = True\nelse:\n    ENABLED = False\n"
    elif mutation == "object":
        prefix = "import unittest\nENABLED = unknown()\n"
        if decorator == "skip":
            args = "ENABLED"
    files["verification/test_flow.py"] = (
        prefix + "from django.test import TestCase\n"
        "from verification.support import SeedMixin\n"
        f"@unittest.{decorator}({args})\n"
        "class TestFirst(SeedMixin, TestCase):\n"
        "    def test_roundtrip(self):\n        self.assertEqual(self.obj.label, 'fixture')\n"
    )
    row = _recovery_row(files, path="verification/config.py")
    domain = row.get("credential_authority_observation", {}).get("authority_domain")
    assert bool(domain) is (mutation == "none")
    assert row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"


@pytest.mark.parametrize(
    "counteredge",
    [
        "outside_wsgi",
        "imported_secret",
        "entrypoint",
        "root_management",
        "module_model",
        "class_model",
    ],
)
def test_authority_domain_independent_application_edge_defeats_test_discharge(
    counteredge,
):
    files = _configured_test_domain_sources()
    if counteredge == "outside_wsgi":
        files["live.py"] = START.replace("service.settings", "verification.config")
    elif counteredge == "root_management":
        files = {
            name.replace("config.py", "settings.py"): value.replace(
                "verification.config", "verification.settings"
            )
            for name, value in files.items()
        }
        files["manage.py"] = (
            "import os\nfrom django.core.management import execute_from_command_line\n"
            "os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'verification.settings')\n"
            "execute_from_command_line([])\n"
        )
    elif counteredge in {"module_model", "class_model"}:
        operation = "Item.objects.create(label='live')"
        body = (
            operation
            if counteredge == "module_model"
            else "class Live:\n    value = " + operation
        )
        files["live.py"] = (
            "from verification.resource.models import Item\n" + body + "\n"
        )
    elif counteredge == "imported_secret":
        files["live.py"] = (
            "from verification.config import SECRET_KEY\nvalue=SECRET_KEY\n"
        )
    else:
        files["pyproject.toml"] += '[project.scripts]\nserve="live:application"\n'
    selected = (
        "verification/settings.py"
        if counteredge == "root_management"
        else "verification/config.py"
    )
    row = _recovery_row(files, path=selected)
    assert row["tier"] == "SUPPORTED_DEFECT"
    assert row["credential_authority_observation"]["authority_domain"] is None


@pytest.mark.parametrize(
    "rewrite",
    [
        lambda files: files.__setitem__(
            "verification/live.py",
            START.replace("service.settings", "verification.config"),
        ),
        lambda files: files.__setitem__(
            "verification/test_helper.py",
            "from verification.resource.models import Item\ndef helper():\n    return Item.objects.create(label='outside')\n",
        ),
        lambda files: files["verification/test_flow.py"].replace(
            "class TestExercise(TestCase)", "class Exercise(object)"
        ),
        lambda files: files["verification/test_flow.py"].replace(
            "    def test_roundtrip", "    def helper_roundtrip"
        ),
        lambda files: files.__setitem__(
            "conftest.py", "pytest_plugins = ['external.plugin']\n"
        ),
        lambda files: files.__setitem__("pytest.ini", "[pytest]\ntestpaths = other\n"),
        lambda files: files.__delitem__("pyproject.toml"),
        lambda files: files.__setitem__("pyproject.toml", "[tool.other]\nflag=true\n"),
    ],
)
def test_authority_domain_rejects_uncollected_or_competing_test_ownership(rewrite):
    files = _configured_test_domain_sources()
    value = rewrite(files)
    if isinstance(value, str):
        files["verification/test_flow.py"] = value
    row = _recovery_row(files, path="verification/config.py")
    assert row["tier"] == "SUPPORTED_DEFECT"
    assert row["credential_authority_observation"]["authority_domain"] is None


@pytest.mark.parametrize("missing", ["ownership", "data", "plugin", "provider"])
def test_authority_domain_hints_without_closed_fixture_role_preserve_signer(missing):
    files = _configured_test_domain_sources()
    if missing == "ownership":
        files["pyproject.toml"] = files["pyproject.toml"].replace(
            'testpaths=["verification"]', 'testpaths=["other"]'
        )
    elif missing == "data":
        files["verification/test_flow.py"] = "from django.test import TestCase\n"
    elif missing == "plugin":
        files["pyproject.toml"] = files["pyproject.toml"].replace(
            '"pytest-django"', '"pytest"'
        )
    else:
        files["verification/test_flow.py"] += "TestCase._fixture_setup = replacement\n"
    row = _recovery_row(files, path="verification/config.py")
    assert row["tier"] == "SUPPORTED_DEFECT"
    assert row["credential_authority_observation"]["authority_domain"] is None


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
        == "UNASSESSED"
    )
    assert (
        row["credential_authority_observation"]["settings_runtime_selection"]
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


@pytest.mark.parametrize(
    "deferred",
    [
        "lambda: Item.objects.create(label='fixture')",
        "(Item.objects.create(label='fixture') for _ in [])",
    ],
)
def test_authority_domain_deferred_fixture_is_not_transactional_witness(deferred):
    files = _configured_test_domain_sources()
    files["verification/test_flow.py"] = files["verification/test_flow.py"].replace(
        "Item.objects.create(label='fixture')", deferred
    )
    row = _recovery_row(files, path="verification/config.py")
    assert row["tier"] == "SUPPORTED_DEFECT"
    assert row["credential_authority_observation"]["authority_domain"] is None


def test_authority_domain_nested_uncalled_test_is_not_collected():
    files = _configured_test_domain_sources("migration")
    original = files["verification/test_flow.py"]
    imports, function = original.split("@pytest.mark.django_db", 1)
    files["verification/test_flow.py"] = (
        imports
        + "def helper():\n"
        + "".join(
            "    " + line + "\n"
            for line in ("@pytest.mark.django_db" + function).splitlines()
        )
    )
    row = _recovery_row(files, path="verification/config.py")
    assert row["tier"] == "SUPPORTED_DEFECT"
    assert row["credential_authority_observation"]["authority_domain"] is None


@pytest.mark.parametrize("lookup", ["static", "registry", "dynamic", "appconfig"])
def test_authority_domain_independent_second_app_effect_vetoes_context(lookup):
    files = _configured_test_domain_sources()
    files["verification/config.py"] = files["verification/config.py"].replace(
        '"verification.resource"]', '"verification.resource", "application"]'
    )
    files["application/__init__.py"] = ""
    files["application/models.py"] = (
        "from django.db import models\n"
        "class Other(models.Model):\n    label = models.CharField(max_length=32)\n"
    )
    operations = {
        "static": "from application.models import Other\nOther.objects.create(label='live')\n",
        "registry": "from django.apps import apps\nOther = apps.get_model('application', 'Other')\n"
        "Other.objects.create(label='live')\n",
        "dynamic": "from importlib import import_module\n"
        "Other = import_module('application.models').Other\n"
        "Other.objects.create(label='live')\n",
    }
    if lookup == "appconfig":
        files["verification/config.py"] = files["verification/config.py"].replace(
            '"application"]', '"application.apps.ApplicationConfig"]'
        )
        files["application/apps.py"] = (
            "from django.apps import AppConfig\n"
            "class ApplicationConfig(AppConfig):\n    name = 'application'\n"
        )
    files["live.py"] = operations["static" if lookup == "appconfig" else lookup]
    row = _recovery_row(files, path="verification/config.py")
    if lookup == "dynamic":
        assert row["tier"] == "NEEDS_CONTEXT"
        assert row["evidence"] is None
    else:
        assert row["tier"] == "SUPPORTED_DEFECT"
    assert (
        row.get("credential_authority_observation", {}).get("authority_domain") is None
    )


def test_authority_domain_escaping_deferred_test_effect_vetoes_context():
    files = _configured_test_domain_sources()
    files["callbacks.py"] = "pending = []\n"
    files["verification/test_flow.py"] = (
        "from callbacks import pending\n" + files["verification/test_flow.py"]
    ).replace(
        "self.assertEqual(self.obj.label, 'fixture')",
        "pending.append(lambda: Item.objects.create(label='outside'))",
    )
    files["live.py"] = (
        "from callbacks import pending\n"
        "def start():\n    return [callback() for callback in pending]\n"
    )
    row = _recovery_row(files, path="verification/config.py")
    assert row["tier"] == "SUPPORTED_DEFECT"
    assert row["credential_authority_observation"]["authority_domain"] is None


_REQUEST_USER_SETTINGS = (
    "SECRET_KEY = 'captured-test-only-key'\n"
    "INSTALLED_APPS = ['django.contrib.auth', 'django.contrib.contenttypes']\n"
    "DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}}\n"
)
_REQUEST_USER_PROJECT = (
    '[project]\nname = "request-user-controls"\n'
    'dependencies = ["Django", "pytest", "pytest-django"]\n'
    "[tool.pytest.ini_options]\n"
    'DJANGO_SETTINGS_MODULE = "app.settings"\n'
)
_REQUEST_USER_EXTRA_ONLY = (
    '[project]\nname = "request-user-controls"\n'
    '[project.optional-dependencies]\ntest = ["Django", "pytest", "pytest-django"]\n'
    "[tool.pytest.ini_options]\n"
    'DJANGO_SETTINGS_MODULE = "app.settings"\n'
)
_REQUEST_USER_TEST = """
from app.views import profile

def test_created_user(rf, django_user_model):
    username = "created-user"
    password = "fictional-request-password"
    user = django_user_model.objects.create_user(username=username, password=password)
    request = rf.get("/profile")
    request.user = user
    response = profile(request)
    assert response == username
"""


def _request_user_role_projection(
    tmp_path,
    test_source,
    *,
    settings=None,
    conftest=None,
    project=None,
    extra_sources=None,
):
    from factoryline.mock_fixture_provenance import (
        application_test_index,
        application_test_secret_evidence,
    )

    files = {
        "app/__init__.py": "",
        "app/settings.py": (_REQUEST_USER_SETTINGS if settings is None else settings),
        "app/views.py": (
            "def profile(request):\n    return request.user.get_username()\n"
        ),
        "tests/__init__.py": "",
        "tests/test_user_flow.py": test_source,
    }
    if conftest is not None:
        files["tests/conftest.py"] = conftest
    files.update(extra_sources or {})
    modules, source_bytes, inventory = {}, {}, {}
    for relative, text in files.items():
        path = tmp_path / relative
        raw = text.encode()
        digest = sha256(raw).hexdigest()
        tree = ast.parse(raw, filename=relative)
        tree._oracle_source_sha256 = digest
        modules[path], source_bytes[path], inventory[path] = tree, raw, digest
    test_path = tmp_path / "tests/test_user_flow.py"
    declaration = next(
        node
        for node in ast.walk(modules[test_path])
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "password"
    )
    project = _REQUEST_USER_PROJECT if project is None else project
    configuration = {"pyproject.toml": project.encode()}
    index = application_test_index(
        tmp_path,
        modules,
        source_bytes,
        inventory,
        configuration,
    )
    return (
        application_test_secret_evidence(
            index, test_path, declaration.value.lineno, declaration.value.value
        ),
        declaration,
        source_bytes[test_path],
        source_bytes,
        inventory,
        configuration,
        project.encode(),
    )


@pytest.mark.parametrize("settings_drift", [False, True])
def test_captured_pytest_django_user_fixture_binds_settings_bytes(
    tmp_path, settings_drift
):
    from factoryline.mock_fixture_provenance import (
        _app_has_dynamic_scope,
        application_test_index,
    )
    from factoryline.pytest_collection_audit import captured_pytest_django_user_fixture

    _, _, _, source_bytes, inventory, configuration, _ = _request_user_role_projection(
        tmp_path, _REQUEST_USER_TEST
    )
    modules = {path: ast.parse(raw) for path, raw in source_bytes.items()}
    for path, tree in modules.items():
        tree._oracle_source_sha256 = inventory[path]
    settings_path = tmp_path / "app/settings.py"
    if settings_drift:
        source_bytes[settings_path] += b"\nAUTH_USER_MODEL = 'accounts.CustomUser'\n"
    index = application_test_index(
        tmp_path, modules, source_bytes, inventory, configuration
    )
    assert index is not None
    path = tmp_path / "tests/test_user_flow.py"
    function = next(n for n in modules[path].body if isinstance(n, ast.FunctionDef))
    proof = captured_pytest_django_user_fixture(
        index, path, function, "password", _app_has_dynamic_scope
    )
    if settings_drift:
        assert proof is None
    else:
        assert (
            proof["fixture_provider"]["settings"]["sha256"] == inventory[settings_path]
        )
        assert proof["profile"] == "SOURCE_BOUND_TEST_ACCOUNT_ENROLLMENT"


def test_captured_django_user_fixture_and_request_role_is_source_bound(tmp_path):
    evidence, declaration, raw, source_bytes, *_ = _request_user_role_projection(
        tmp_path, _REQUEST_USER_TEST
    )
    assert evidence["eligible"] is True
    assert evidence["classification"] == "APPLICATION_TEST_CREDENTIAL_ROLE"
    assert evidence["source_sha256"] == sha256(raw).hexdigest()
    assert evidence["declaration_span"][0] == declaration.lineno
    assert evidence["consumer_use_closure"]["complete"] is True
    assert isinstance(evidence["consumer_use_closure"], dict)
    assert evidence["witness_sources"]
    assert all(
        len(item["sha256"]) == 64 for item in evidence["witness_sources"].values()
    )
    receipt = evidence["test_fixture_provider"]
    captured = {
        path.relative_to(tmp_path).as_posix(): data
        for path, data in source_bytes.items()
    }
    assert receipt["schema"] == "factory.pytest-django-user-fixture.v1"
    assert (
        receipt["test"]["sha256"]
        == sha256(captured[receipt["test"]["path"]]).hexdigest()
    )
    assert (
        receipt["settings"]["sha256"]
        == sha256(captured[receipt["settings"]["path"]]).hexdigest()
    )
    assert evidence["runtime_assurance"] == "INCOMPLETE"
    assert evidence["transport_role"] == "UNASSESSED"
    assert evidence["isolation_assurance"] == "UNASSESSED"
    assert evidence["target_execution"] == "not_performed"


@pytest.mark.parametrize(
    "external,eligible",
    [
        ("callback = lambda value: value\n", True),
        (
            "def operate():\n"
            "    from tests.test_user_flow import test_created_user as invoke\n"
            "    return lambda: invoke(None, None)\n",
            False,
        ),
        (
            "class Operations:\n"
            "    from tests.test_user_flow import test_created_user as invoke\n"
            "    result = invoke(None, None)\n",
            False,
        ),
        (
            "class Operations:\n"
            "    import tests.test_user_flow\n"
            "    result = tests.test_user_flow.test_created_user(None, None)\n",
            False,
        ),
    ],
)
def test_django_user_role_preserves_nested_import_escape_controls(
    tmp_path, external, eligible
):
    evidence, *_ = _request_user_role_projection(
        tmp_path, _REQUEST_USER_TEST, extra_sources={"operations.py": external}
    )
    assert evidence["eligible"] is eligible, evidence


@pytest.mark.parametrize("flag", ["--reuse-db", "--pdbcls=pudb.debugger:Debugger"])
def test_django_user_role_runtime_options_do_not_relax_generic_settings(tmp_path, flag):
    from factoryline.pytest_collection_audit import _pytest_effective_settings_options

    assert _pytest_effective_settings_options({"addopts": flag}) is None
    evidence, *_ = _request_user_role_projection(
        tmp_path,
        _REQUEST_USER_TEST,
        project=_REQUEST_USER_PROJECT + f'addopts = "{flag}"\n',
    )
    assert evidence["eligible"] is True, evidence
    receipt = evidence["test_fixture_provider"]
    assert receipt["runtime_effects_unassessed"] == [flag.partition("=")[0]]
    assert receipt["runtime_assurance"] == "UNASSESSED"
    assert evidence["isolation_assurance"] == "UNASSESSED"


@pytest.mark.parametrize(
    ("parameters", "eligible"),
    [
        ("rf, *, django_user_model", True),
        ("rf, django_user_model=ForeignUser", False),
        ("rf, *, django_user_model=ForeignUser", False),
        ("rf, django_user_model, /", False),
    ],
)
def test_captured_django_user_role_requires_injected_fixture(
    tmp_path, parameters, eligible
):
    source = _REQUEST_USER_TEST.replace(
        "def test_created_user(rf, django_user_model):",
        f"def test_created_user({parameters}):",
    )
    evidence, *_ = _request_user_role_projection(tmp_path, source)
    assert evidence["eligible"] is eligible, evidence


def test_captured_django_user_role_does_not_require_request_exercise(tmp_path):
    source = _REQUEST_USER_TEST.replace(
        "def test_created_user(rf, django_user_model):",
        "def test_created_user(django_user_model):",
    ).replace(
        '    request = rf.get("/profile")\n'
        "    request.user = user\n"
        "    response = profile(request)\n"
        "    assert response == username\n",
        "    assert user.get_username() == username\n",
    )
    evidence, *_ = _request_user_role_projection(tmp_path, source)
    assert evidence["eligible"] is True
    assert evidence["classification"] == "APPLICATION_TEST_CREDENTIAL_ROLE"


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {
                "source": _REQUEST_USER_TEST.replace(
                    "    assert response == username\n",
                    "    assert response == username\n    requests.post('https://example.invalid', data=password)\n",
                )
            },
            id="outbound",
        ),
        pytest.param(
            {
                "conftest": "import pytest\n@pytest.fixture\ndef django_user_model():\n    return FakeUserProvider()\n"
            },
            id="fixture_override",
        ),
        pytest.param(
            {
                "conftest": "_name = 'pytest_' + 'plugins'\nglobals()[_name] = ['tests.override_plugin']\n",
                "extra_sources": {
                    "tests/override_plugin.py": "import pytest\n@pytest.fixture\ndef django_user_model():\n    return ForeignManager()\n"
                },
            },
            id="dynamic_plugin_namespace",
        ),
        pytest.param(
            {
                "conftest": "from .override_plugin import django_user_model\n",
                "extra_sources": {
                    "tests/override_plugin.py": "import pytest\n@pytest.fixture\ndef django_user_model():\n    return ForeignManager()\n"
                },
            },
            id="imported_fixture_override",
        ),
        pytest.param(
            {
                "conftest": "from app.plugin_config import pytest_plugins\n",
                "extra_sources": {
                    "app/plugin_config.py": 'pytest_plugins = ["app.fixture_plugin"]\n',
                    "app/fixture_plugin.py": "import pytest\n@pytest.fixture\ndef django_user_model():\n    return FakeUserProvider()\n",
                },
            },
            id="plugin_fixture_override",
        ),
        pytest.param(
            {
                "conftest": "import pytest\n@pytest.fixture(autouse=True)\ndef change_model(settings):\n    settings.AUTH_USER_MODEL = choose_model()\n"
            },
            id="autouse_model_mutation",
        ),
        pytest.param(
            {
                "conftest": "import pytest\n@pytest.fixture(autouse=True)\ndef patch_create_user(monkeypatch, django_user_model):\n    monkeypatch.setattr(\n        django_user_model.objects, 'create_user', foreign_factory\n    )\n"
            },
            id="create_user_monkeypatch",
        ),
        pytest.param(
            {
                "source": _REQUEST_USER_TEST.replace(
                    "def test_created_user(rf, django_user_model):",
                    "def test_created_user(rf, django_user_model, monkeypatch):",
                ).replace(
                    "    user = django_user_model.objects.create_user(",
                    "    monkeypatch.setattr(\n        django_user_model, 'objects', ExfiltratingManager()\n    )\n    user = django_user_model.objects.create_user(",
                )
            },
            id="manager_monkeypatch",
        ),
        pytest.param(
            {
                "source": _REQUEST_USER_TEST.replace(
                    '    username = "created-user"\n',
                    '    django_user_model = supplied_provider\n    username = "created-user"\n',
                )
            },
            id="local_shadow",
        ),
        pytest.param(
            {
                "source": _REQUEST_USER_TEST.replace(
                    "username=username, password=password",
                    'username=username, **{"password": password}',
                )
            },
            id="kwargs_expansion",
        ),
        pytest.param(
            {
                "source": _REQUEST_USER_TEST.replace(
                    "def test_created_user(", "def create_operational_user("
                )
            },
            id="operational",
        ),
        pytest.param(
            {
                "extra_sources": {
                    "app/operations.py": "from tests.test_user_flow import test_created_user\ntest_created_user(None, None)\n"
                }
            },
            id="operational_caller",
        ),
        pytest.param(
            {
                "extra_sources": {
                    "app/operations.py": "from tests.test_user_flow import test_created_user as run_fixture_test\ndef dispatch():\n    run_fixture_test(None, None)\ndef export():\n    return run_fixture_test\n"
                }
            },
            id="operational_alias_export",
        ),
        pytest.param(
            {
                "extra_sources": {
                    "app/operations.py": "import tests.test_user_flow as m\ngetattr(m, 'test_created_user')(None, User)\n"
                }
            },
            id="operational_module_reflection",
        ),
        pytest.param(
            {
                "settings": _REQUEST_USER_SETTINGS
                + "AUTH_USER_MODEL = 'app.CustomUser'\n"
            },
            id="custom_user_model",
        ),
        pytest.param(
            {
                "settings": _REQUEST_USER_SETTINGS
                + "DATABASE_ROUTERS = ['app.ProductionRouter']\n"
            },
            id="database_router",
        ),
        pytest.param(
            {
                "settings": "from .base import AUTH_USER_MODEL\n"
                + _REQUEST_USER_SETTINGS,
                "extra_sources": {
                    "app/base.py": "AUTH_USER_MODEL = 'app.CustomUser'\n"
                },
            },
            id="imported_user_model",
        ),
        pytest.param(
            {
                "settings": _REQUEST_USER_SETTINGS
                + "import os\nAUTH_USER_MODEL = os.getenv('USER_MODEL')\n"
            },
            id="dynamic_user_model",
        ),
        pytest.param(
            {
                "settings": _REQUEST_USER_SETTINGS
                + "setting_name = 'AUTH_USER_' + 'MODEL'\nglobals()[setting_name] = 'accounts.CustomUser'\n"
            },
            id="dynamic_globals_user_model",
        ),
        pytest.param(
            {
                "settings": "from builtins import globals as namespace\n"
                + (
                    _REQUEST_USER_SETTINGS
                    + "setting_name = 'AUTH_USER_' + 'MODEL'\nglobals()[setting_name] = 'accounts.CustomUser'\n"
                ).replace("globals()[", "namespace()[")
            },
            id="aliased_globals_user_model",
        ),
        pytest.param({"project": _REQUEST_USER_EXTRA_ONLY}, id="optional_extra_only"),
        pytest.param(
            {
                "extra_sources": {
                    "app/operations.py": "from tests.test_user_flow import *\ntest_created_user(None, User)\n"
                }
            },
            id="star_import_operational_caller",
        ),
    ],
)
def test_django_user_role_rejects_unclosed_creation_context(tmp_path, case):
    source = case.get("source", _REQUEST_USER_TEST)
    options = {key: value for key, value in case.items() if key != "source"}
    evidence, *_ = _request_user_role_projection(tmp_path, source, **options)
    assert evidence["eligible"] is False, evidence


@pytest.mark.parametrize(
    "tamper", ["profile", "closure", "provider_source", "fixture_provider"]
)
def test_django_user_role_verifier_rejects_tampered_evidence(tmp_path, tamper):
    from factoryline.primitive_observation_binding import _application_fixture_use_proof

    evidence, _, _, source_bytes, inventory, configuration, project_bytes = (
        _request_user_role_projection(tmp_path, _REQUEST_USER_TEST)
    )
    assert evidence["eligible"] is True
    evidence = copy.deepcopy(evidence)
    bindings = {
        path.relative_to(tmp_path).as_posix(): digest
        for path, digest in inventory.items()
    }
    captured = {
        path.relative_to(tmp_path).as_posix(): raw for path, raw in source_bytes.items()
    }
    captured["pyproject.toml"] = project_bytes
    configuration_hashes = {
        name: sha256(raw).hexdigest() for name, raw in configuration.items()
    }
    bindings.update(configuration_hashes)
    evidence.update(
        inventory_sha256="captured-inventory",
        configuration_sha256=configuration_hashes,
    )
    facts = {"name": "password"}
    assert _application_fixture_use_proof(evidence, bindings, facts, captured)
    altered = copy.deepcopy(evidence)
    if tamper == "profile":
        altered["profile"] = "UNSUPPORTED_TEST_ACCOUNT_PROFILE"
    elif tamper == "provider_source":
        provider_source = next(iter(altered["witness_sources"].values()))
        provider_source["sha256"] = "0" * 64
    elif tamper == "fixture_provider":
        altered["test_fixture_provider"]["settings"]["sha256"] = "0" * 64
    else:
        altered["consumer_use_closure"]["complete"] = False
    assert not _application_fixture_use_proof(altered, bindings, facts, captured)
