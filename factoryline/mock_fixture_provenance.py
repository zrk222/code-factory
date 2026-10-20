"""Bind mock fixture credit to retained source snapshots."""

from __future__ import annotations

import ast
import configparser
import hashlib
import re
from pathlib import Path


_ASSERTION_METHODS = frozenset(
    "assert_called_with assert_called_once_with assert_called assert_called_once "
    "assert_any_call assert_has_calls assert_not_called assert_awaited_with "
    "assert_awaited_once_with assert_any_await assert_has_awaits "
    "assert_not_awaited assert_awaited assert_awaited_once".split()
)

_DJANGO_CANONICAL_PROVIDER_ROOTS = frozenset({"django", "urllib"})

_JWT_TEST_FIXTURE_TYPES = {
    "jwt": "jwt.api_jwt.PyJWT",
    "jws": "jwt.api_jws.PyJWS",
}


def _closed_method_signature(method):
    if method.decorator_list:
        return False
    arguments = method.args
    defaults = [
        *arguments.defaults,
        *(item for item in arguments.kw_defaults if item is not None),
    ]
    if any(not isinstance(item, ast.Constant) for item in defaults):
        return False
    annotated = [
        item.annotation
        for item in [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
        ]
        if item.annotation is not None
    ]
    if arguments.vararg and arguments.vararg.annotation is not None:
        annotated.append(arguments.vararg.annotation)
    if arguments.kwarg and arguments.kwarg.annotation is not None:
        annotated.append(arguments.kwarg.annotation)
    if method.returns is not None:
        annotated.append(method.returns)
    return all(isinstance(item, ast.Constant) for item in annotated)


def _class_is_unmutated(module, spec, name):
    for node in ast.walk(module):
        if isinstance(node, ast.Name) and node.id == name and node is not spec:
            return False
    return True


def _has_wildcard_import(module):
    return any(
        isinstance(node, ast.ImportFrom)
        and any(alias.name == "*" for alias in node.names)
        for node in ast.walk(module)
    )


def _source_closed_class_spec(module, fixture, spec, audit):
    if (
        not isinstance(spec, ast.Name)
        or spec.id in audit._scope_parameters(fixture)
        or any(
            isinstance(node, ast.Name)
            and node.id == spec.id
            and isinstance(node.ctx, (ast.Store, ast.Del))
            for node in ast.walk(fixture)
        )
    ):
        return False
    classes = [
        node
        for node in module.body
        if isinstance(node, ast.ClassDef) and node.name == spec.id
    ]
    if len(classes) != 1:
        return False
    cls = classes[0]
    if (
        cls.bases
        or cls.keywords
        or cls.decorator_list
        or _has_wildcard_import(module)
        or not _class_is_unmutated(module, spec, spec.id)
        or any(
            statement is not cls and spec.id in audit._bound_names(statement)
            for statement in module.body
        )
    ):
        return False
    for statement in cls.body:
        if isinstance(statement, ast.Pass):
            continue
        if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        if not _closed_method_signature(statement):
            return False
    return True


def direct_mock_return(module, fixture, aliases, audit):
    body = fixture.body
    if len(body) != 1 or not isinstance(body[0], ast.Return):
        return False
    value = body[0].value
    local_aliases = audit._scope_security_aliases(aliases, fixture)
    if not isinstance(value, ast.Call):
        return False
    constructor = audit._normalized_call_name(value, local_aliases)
    if constructor not in audit._UNITTEST_MOCK_CONSTRUCTORS:
        return False
    if constructor == "unittest.mock.create_autospec":
        return (
            isinstance(fixture, ast.FunctionDef)
            and not audit._scope_parameters(fixture)
            and len(value.args) == 1
            and not value.keywords
            and _source_closed_class_spec(module, fixture, value.args[0], audit)
        )
    return not value.args and not value.keywords


def inert_assertion_methods(module, fixture, audit):
    body = fixture.body
    value = (
        body[0].value if len(body) == 1 and isinstance(body[0], ast.Return) else None
    )
    if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Name):
        return []
    classes = [
        n
        for n in module.body
        if isinstance(n, ast.ClassDef) and n.name == value.func.id
    ]
    if len(classes) != 1 or classes[0].bases or classes[0].keywords:
        return []
    cls = classes[0]
    if cls.decorator_list or any(
        s is not cls and cls.name in audit._bound_names(s) for s in module.body
    ):
        return []
    if any(
        not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in cls.body
    ):
        return []
    if any(
        n.decorator_list
        or len(n.body) != 1
        or not isinstance(n.body[0], (ast.Pass, ast.Return))
        or isinstance(n.body[0], ast.Return)
        and n.body[0].value is not None
        for n in cls.body
    ):
        return []
    return [n.name for n in cls.body if n.name in _ASSERTION_METHODS]


def fixture_registration(decorator, function_name, aliases, audit):
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if audit._resolved_ast_name(target, aliases) != "pytest.fixture":
        return None, False
    names = (
        [keyword.value for keyword in decorator.keywords if keyword.arg == "name"]
        if isinstance(decorator, ast.Call)
        else []
    )
    if not names:
        return function_name, True
    value = names[0]
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value, False
    return None, False


def fixture_bindings_for_source(tree):
    from . import review_audits as audit

    aliases = audit._scope_security_aliases(audit._module_security_aliases(tree), tree)
    fixtures = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for item in node.decorator_list:
                name, supported = fixture_registration(item, node.name, aliases, audit)
                if name is not None:
                    fixtures.setdefault(name, []).append((node, supported))
    if not fixtures:
        return {}
    mock_provider_safe = _mock_providers_are_closed(tree, aliases, audit)
    pytest_provider_safe = _pytest_fixture_provider_safe(tree, audit)
    result = {}
    for name, items in fixtures.items():
        fixture, supported_name = items[0] if len(items) == 1 else (None, False)
        controlled = bool(
            fixture
            and supported_name
            and len(fixture.decorator_list) == 1
            and not any(
                s is not fixture and name in audit._bound_names(s) for s in tree.body
            )
            and pytest_provider_safe
        )
        result[name] = {
            "mock": bool(
                controlled
                and mock_provider_safe
                and direct_mock_return(tree, fixture, aliases, audit)
            ),
            "inert_methods": (
                inert_assertion_methods(tree, fixture, audit) if controlled else []
            ),
        }
    return result


def fixtures_for_file(path: Path, sources: dict[Path, dict[str, dict]]):
    parents = sorted(
        (
            p
            for p in sources
            if p.name == "conftest.py" and path.parent.is_relative_to(p.parent)
        ),
        key=lambda p: len(p.parts),
    )
    result = {}
    for parent in parents:
        result.update(sources[parent])
    result.update(sources.get(path, {}))
    return result


def fixture_is_mock(module, name):
    mapping = getattr(module, "_oracle_mock_fixture_provenance", {})
    profile = mapping.get(name, {}) if isinstance(mapping, dict) else {}
    return isinstance(profile, dict) and profile.get("mock") is True


def inert_fixture_assertion_reason(call, aliases):
    if (
        not isinstance(call, ast.Call)
        or not isinstance(call.func, ast.Attribute)
        or not isinstance(call.func.value, ast.Name)
    ):
        return None
    scope = getattr(call, "_oracle_scope", None)
    module = getattr(scope, "_oracle_module", None)
    profiles = getattr(module, "_oracle_mock_fixture_provenance", {})
    from . import review_audits as audit

    receiver = audit._mock_root_name(call.func.value, scope, aliases)
    profile = profiles.get(receiver, {}) if isinstance(profiles, dict) else {}
    return (
        "assertion method is source-proven to have an inert implementation"
        if call.func.attr in profile.get("inert_methods", ())
        else None
    )


def inert_fixture_assertions(nodes, aliases):
    return [
        (node, reason)
        for node in nodes
        if isinstance(node, ast.Call)
        and (reason := inert_fixture_assertion_reason(node, aliases)) is not None
    ]


def _mock_providers_are_closed(module, aliases, audit):
    imports = [n for n in module.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    providers = {
        n
        for n, target in audit._security_aliases(imports).items()
        if target == "unittest" or target.startswith("unittest.mock")
    }
    if not providers or any(
        p in audit._bound_names(s)
        for s in module.body
        if not isinstance(s, (ast.Import, ast.ImportFrom))
        for p in providers
    ):
        return False
    allowed = {
        id(child)
        for call in ast.walk(module)
        if isinstance(call, ast.Call)
        and audit._normalized_call_name(call, aliases)
        in audit._UNITTEST_MOCK_CONSTRUCTORS
        for child in ast.walk(call.func)
    }
    allowed.update(
        id(child)
        for item in ast.walk(module)
        if isinstance(item, ast.arg) and item.annotation
        for child in ast.walk(item.annotation)
    )
    for node in ast.walk(module):
        if (
            isinstance(node, (ast.Name, ast.Attribute))
            and _root_name(node) in providers
        ):
            if (
                isinstance(node.ctx, (ast.Store, ast.Del))
                or isinstance(node.ctx, ast.Load)
                and id(node) not in allowed
            ):
                return False
        if isinstance(node, ast.Call) and any(
            isinstance(a, ast.Constant)
            and isinstance(a.value, str)
            and a.value.startswith("unittest.mock.")
            for a in [*node.args, *(k.value for k in node.keywords)]
        ):
            return False
    return True


def _root_name(node):
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else ""


def _pytest_fixture_provider_safe(module, audit):
    imports = [n for n in module.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    roots = {
        n
        for n, target in audit._security_aliases(imports).items()
        if target == "pytest"
    }
    parents = {id(c): p for p in ast.walk(module) for c in ast.iter_child_nodes(p)}
    for node in ast.walk(module):
        if (
            isinstance(node, ast.Name)
            and node.id in roots
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            return False
        if isinstance(node, ast.Attribute) and _root_name(node.value) in roots:
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                return False
            if node.attr == "fixture" and isinstance(node.ctx, ast.Load):
                parent = parents.get(id(node))
                if not (
                    isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node in parent.decorator_list
                    or isinstance(parent, ast.Call)
                    and parent.func is node
                ):
                    return False
    return True


def _django_unknown(reason):
    return {"eligible": False, "classification": "UNPROVEN", "reason": reason}


def django_test_secret_index(root, modules, configs, *, source_bytes=None, inventory=None):
    """Build a bounded index from the producer's captured Python and config bytes."""
    if not isinstance(source_bytes, dict) or not isinstance(inventory, dict):
        return None
    from .credential_role_sources import SourceSnapshotIndex

    source = SourceSnapshotIndex(root, modules, source_bytes, inventory)
    if not source.bounded or set(configs) != {"pyproject.toml", "tox.ini"}:
        return None
    if any(not isinstance(raw, bytes) for raw in configs.values()):
        return None
    try:
        import tomllib
        pyproject = tomllib.loads(configs["pyproject.toml"].decode("utf-8"))
        tox = configparser.ConfigParser()
        tox.read_string(configs["tox.ini"].decode("utf-8"))
    except (ImportError, UnicodeError, ValueError, configparser.Error):
        return None
    testenv = tox["testenv"] if tox.has_section("testenv") else None
    if testenv is None or not re.search(r"\bpytest(?:\s|$)", testenv.get("commands", "")):
        return None
    if not _django_runner_plugins_safe(pyproject, testenv):
        return None
    extras = set(testenv.get("extras", "").replace(",", " ").split())
    optional = pyproject.get("project", {}).get("optional-dependencies", {})
    test_deps = {
        re.split(r"[<>=!~\[]", str(item).lower(), maxsplit=1)[0].strip()
        for key in extras
        for item in optional.get(key, [])
    }
    if "pytest" not in test_deps or "pytest-django" not in test_deps:
        return None
    setting_match = re.search(
        r"(?m)^\s*DJANGO_SETTINGS_MODULE\s*=\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*$",
        testenv.get("setenv", ""),
    )
    if setting_match is None:
        return None
    runner = setting_match.group(1)
    configs_sha = {name: hashlib.sha256(raw).hexdigest() for name, raw in configs.items()}
    rows = {
        source.relative(path): digest
        for path, digest in inventory.items()
        if source.relative(path) is not None
    }
    module_paths = {source.relative(path): path for path in modules if source.relative(path)}
    if len(rows) != len(inventory) or any(
        _django_provider_root_shadowed(module_paths, root)
        for root in _DJANGO_CANONICAL_PROVIDER_ROOTS
    ):
        return None
    combined = dict(rows)
    combined.update(configs_sha)
    inventory_sha = hashlib.sha256(
        "\n".join(sorted(f"{name}\0{digest}" for name, digest in combined.items())).encode()
    ).hexdigest()
    return {
        "root": source.root,
        "source": source,
        "modules": modules,
        "module_paths": module_paths,
        "configs": configs,
        "config_hashes": configs_sha,
        "inventory_sha256": inventory_sha,
        "runner": runner,
        "runner_valid": True,
        "imports": {},
        "model_cache": {},
        "signal_cache": {},
    }


def _django_runner_plugins_safe(pyproject, testenv):
    options = pyproject.get("tool", {}).get("pytest", {}).get("ini_options", {})
    if any(key in options for key in ("plugins", "pytest_plugins")):
        return False
    addopts = str(options.get("addopts", ""))
    commands = testenv.get("commands", "")
    setenv = testenv.get("setenv", "")
    return not (
        re.search(r"(?:^|\s)-p(?:\s|=|\w)", addopts)
        or re.search(r"(?:^|\s)-p(?:\s|=|\w)", commands)
        or re.search(r"(?m)^\s*PYTEST_PLUGINS\s*=", setenv)
    )


def _django_mod(index, name):
    root = name.partition(".")[0]
    if root in _DJANGO_CANONICAL_PROVIDER_ROOTS and _django_provider_root_shadowed(index["module_paths"], root):
        return None, None
    for suffix in (".py", "/__init__.py"):
        path = index["module_paths"].get(name.replace(".", "/") + suffix)
        if path is not None and index["source"].validate(path):
            return path, index["modules"][path]
    return None, None


def _django_provider_root_shadowed(module_paths, root):
    prefix = root.replace(".", "/")
    return any(
        relative == prefix + ".py" or relative.startswith(prefix + "/")
        for relative in module_paths
    )


def _django_local_import_path(index, target):
    parts = target.split(".")
    for end in range(len(parts), 0, -1):
        path, tree = _django_mod(index, ".".join(parts[:end]))
        if path is not None and tree is not None:
            return path
    return None


def _django_test_conftests(index, test_path):
    relative = index["source"].relative(test_path)
    if relative is None:
        return []
    parts = relative.split("/")[:-1]
    directories = [""] + ["/".join(parts[:end]) for end in range(1, len(parts) + 1)]
    return [
        path
        for directory in directories
        if (path := index["module_paths"].get(f"{directory + '/' if directory else ''}conftest.py")) is not None
    ]


def _django_signal_scan_paths(index, test_path, app_label):
    package = app_label.replace(".", "/")
    package_paths = {
        path
        for relative, path in index["module_paths"].items()
        if relative == package + ".py" or relative.startswith(package + "/")
    }
    seeds = {test_path, *package_paths}
    seeds.update(_django_test_conftests(index, test_path))
    seeds.update(
        path
        for name in (app_label, app_label + ".apps", app_label + ".models")
        if (path := _django_mod(index, name)[0]) is not None
    )
    pending = list(seeds)
    seen = set()
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        if len(seen) >= 512 or not index["source"].validate(path):
            return None
        seen.add(path)
        imports = _django_imports(index, path)
        if imports is None:
            relative = index["source"].relative(path)
            if relative == package + ".py" or (relative and relative.startswith(package + "/")):
                continue
            return None
        for target in imports.values():
            imported = _django_local_import_path(index, target)
            if imported is not None and imported not in seen:
                pending.append(imported)
    return seen


def _django_ambiguous_signal_calls_clear(tree):
    return not any(
        isinstance(node, ast.Call)
        and (
            isinstance(node.func, ast.Attribute) and node.func.attr in {"connect", "connect_via"}
            or isinstance(node.func, ast.Name) and node.func.id == "receiver"
            or isinstance(node.func, ast.Name) and node.func.id in {"connect", "connect_via"}
            or isinstance(node.func, ast.Attribute) and node.func.attr == "receiver"
            or isinstance(node.func, ast.Name) and node.func.id in {"pre_save", "post_save", "pre_init", "post_init"}
        )
        for node in ast.walk(tree)
    )


def _django_model_signal_provider(canonical):
    return canonical == "django.db.models.signals" or (
        isinstance(canonical, str) and canonical.startswith("django.db.models.signals.")
    )


def _django_model_signal_registration_clear(index, path):
    tree = index["modules"].get(path)
    if tree is None:
        return False
    imports = _django_imports(index, path)
    if imports is None:
        return _django_ambiguous_signal_calls_clear(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if _django_model_signal_provider(imports.get(node.id)):
                return False
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
            if _django_model_signal_provider(_django_expr(index, path, node)):
                return False
        if isinstance(node, ast.Call) and _django_signal_import_call(index, path, node):
            return False
    return True


def _django_signal_import_call(index, path, call):
    canonical = _django_expr(index, path, call.func)
    if canonical not in {"importlib.import_module", "__import__", "builtins.__import__"}:
        return False
    return bool(
        call.args
        and isinstance(call.args[0], ast.Constant)
        and _django_model_signal_provider(call.args[0].value)
    )


def _django_model_signal_hooks_closed(index, test_path, app_label):
    key = (test_path, app_label)
    if key in index["signal_cache"]:
        return index["signal_cache"][key]
    paths = _django_signal_scan_paths(index, test_path, app_label)
    closed = paths is not None and all(
        _django_model_signal_registration_clear(index, path) for path in paths
    )
    index["signal_cache"][key] = closed
    return closed


def _django_name(index, path):
    relative = index["source"].relative(path)
    if relative is None or not relative.endswith(".py"):
        return None
    parts = relative[:-3].split("/")
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _django_import_targets(index, path, tree):
    from .credential_role_scope_bindings import binding_occurrences

    current = _django_name(index, path)
    package = current.rpartition(".")[0]
    result = {}
    for statement in tree.body:
        rows = _django_import_rows(statement, package)
        if rows is None:
            return None
        for bound, target in rows:
            occurrences = binding_occurrences(tree.body, bound)
            if len(occurrences) != 1 or occurrences[0] is not statement or bound in result:
                return None
            result[bound] = target
    return result


def _django_import_rows(statement, package):
    if isinstance(statement, ast.Import):
        return [
            (alias.asname or alias.name.split(".")[0], alias.name if alias.asname else alias.name.split(".")[0])
            for alias in statement.names
        ]
    if not isinstance(statement, ast.ImportFrom):
        return []
    if any(alias.name == "*" for alias in statement.names):
        return None
    if statement.level:
        base_parts = package.split(".") if package else []
        keep = max(0, len(base_parts) - statement.level + 1)
        base = ".".join(base_parts[:keep])
        module = ".".join(part for part in (base, statement.module or "") if part)
    else:
        module = statement.module or ""
    return [
        (alias.asname or alias.name, f"{module}.{alias.name}" if module else alias.name)
        for alias in statement.names
    ]


def _django_imports(index, path):
    if path in index["imports"]:
        return index["imports"][path]
    tree = index["modules"].get(path)
    if tree is None or not index["source"].validate(path):
        return None
    answer = _django_import_targets(index, path, tree)
    index["imports"][path] = answer
    return answer


def _django_expr(index, path, node, function=None):
    if isinstance(node, ast.Name):
        imports = _django_imports(index, path)
        if imports is None:
            return None
        if node.id in imports:
            if function is not None:
                from .credential_role_scope_bindings import binding_occurrences
                if binding_occurrences(function.body, node.id):
                    return None
                args = [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]
                if any(arg.arg == node.id for arg in args) or (function.args.vararg and function.args.vararg.arg == node.id) or (function.args.kwarg and function.args.kwarg.arg == node.id):
                    return None
            return imports[node.id]
        return None
    if isinstance(node, ast.Attribute):
        base = _django_expr(index, path, node.value, function)
        return f"{base}.{node.attr}" if base else None
    return None


def _django_source_function(index, path, expression, function=None):
    canonical = _django_expr(index, path, expression, function)
    if not canonical:
        return None
    module, _, name = canonical.rpartition(".")
    if not module:
        module, name = _django_name(index, path), canonical
    target_path, tree = _django_mod(index, module)
    if tree is None:
        return None
    from .credential_role_scope_bindings import binding_occurrences
    rows = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name]
    bindings = binding_occurrences(tree.body, name)
    if len(rows) != 1 or len(bindings) != 1 or bindings[0] is not rows[0]:
        return None
    return target_path, rows[0]


def _django_assignment(tree, name):
    from .credential_role_scope_bindings import binding_occurrences
    bindings = binding_occurrences(tree.body, name)
    rows = []
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name) and statement.targets[0].id == name:
            rows.append((statement, statement.value))
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name) and statement.target.id == name:
            rows.append((statement, statement.value))
    return rows if len(rows) == len(bindings) else []


def _django_builtins_unshadowed(index, path, names):
    tree = index["modules"].get(path)
    if tree is None:
        return False
    from .credential_role_scope_bindings import binding_occurrences

    return not any(binding_occurrences(tree.body, name) for name in names)


def _django_dict_value(node, key):
    if not isinstance(node, ast.Dict):
        return None
    found = [value for item, value in zip(node.keys, node.values) if isinstance(item, ast.Constant) and item.value == key]
    return found[0] if len(found) == 1 else None


def _django_setting_facts(index):
    settings_path, settings_tree = _django_mod(index, index["runner"])
    if settings_tree is None:
        return None
    db_rows = _django_assignment(settings_tree, "DATABASES")
    app_rows = _django_assignment(settings_tree, "OAUTH2_PROVIDER_APPLICATION_MODEL")
    installed_rows = _django_assignment(settings_tree, "INSTALLED_APPS")
    from .credential_role_scope_bindings import binding_occurrences
    if len(db_rows) != 1 or len(app_rows) < 1 or not installed_rows or binding_occurrences(settings_tree.body, "OAUTH2_PROVIDER"):
        return None
    db = db_rows[0][1]
    default = _django_dict_value(db, "default")
    engine = _django_dict_value(default, "ENGINE")
    name = _django_dict_value(default, "NAME")
    if not (isinstance(db, ast.Dict) and len(db.keys) == 1 and isinstance(engine, ast.Constant) and engine.value == "django.db.backends.sqlite3" and isinstance(name, ast.Constant) and name.value == ":memory:"):
        return None
    configured = []
    for _, value in app_rows:
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return None
        configured.append(value.value)
    if not configured or len(set(configured)) != 1 or "." not in configured[0]:
        return None
    app_label, model_name = configured[0].split(".", 1)
    apps = installed_rows[0][1]
    installed = {item.value for item in ast.walk(apps) if isinstance(item, ast.Constant) and isinstance(item.value, str)}
    if app_label not in installed:
        return None
    if _django_settings_mutated(settings_tree):
        return None
    return settings_path, settings_tree, app_label, model_name


def _django_settings_mutated(tree):
    protected = {"DATABASES", "OAUTH2_PROVIDER_APPLICATION_MODEL", "INSTALLED_APPS", "OAUTH2_PROVIDER"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.attr in protected:
            return True
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if _django_settings_reference(node.value, protected):
                return True
        if isinstance(node, ast.Call):
            if any(
                _django_settings_reference(argument, protected)
                for argument in [*node.args, *(item.value for item in node.keywords)]
            ) or _django_settings_reference(node.func, protected):
                return True
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            if _django_settings_reference(getattr(node, "value", None), protected):
                return True
    return False


def _django_settings_reference(node, protected):
    return isinstance(node, ast.AST) and (
        _root_name(node) in protected
        or any(
            isinstance(part, ast.Attribute) and part.attr in protected
            or isinstance(part, ast.Name) and part.id in protected
            for part in ast.walk(node)
        )
    )


def _django_factory_resolves(index, path, function, expected_model):
    call = _django_factory_model_call(index, path, function)
    if call is None:
        return False
    model_arg = call.args[0]
    imports = _django_imports(index, path)
    settings_target = imports.get(model_arg.value.id) if imports else None
    if not settings_target or not settings_target.endswith(".oauth2_settings"):
        return False
    provider_path, provider = _django_mod(index, settings_target.rsplit(".", 1)[0])
    if provider is None:
        return False
    configured = _django_setting_facts(index)
    if configured is None or ".".join(configured[2:]) != expected_model:
        return False
    return _django_provider_settings(index, provider_path, provider) and _django_provider_object(index, provider_path, provider)


def _django_factory_model_call(index, path, function):
    body = list(function.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body.pop(0)
    if len(body) != 1 or not isinstance(body[0], ast.Return) or not isinstance(body[0].value, ast.Call):
        return None
    call = body[0].value
    if len(call.args) != 1 or call.keywords or _django_expr(index, path, call.func, function) != "django.apps.apps.get_model":
        return None
    model_arg = call.args[0]
    if not isinstance(model_arg, ast.Attribute) or model_arg.attr != "APPLICATION_MODEL" or not isinstance(model_arg.value, ast.Name):
        return None
    return call


def _django_provider_settings(index, path, provider):
    if not _django_builtins_unshadowed(index, path, {"getattr"}):
        return False
    configured = _django_assignment(provider, "APPLICATION_MODEL")
    defaults = _django_assignment(provider, "DEFAULTS")
    user = _django_assignment(provider, "USER_SETTINGS")
    if len(configured) != 1 or len(defaults) != 1 or len(user) != 1:
        return False
    call = configured[0][1]
    if not _django_getattr(call, "OAUTH2_PROVIDER_APPLICATION_MODEL", required_type=str):
        return False
    if _django_expr(index, path, call.args[0]) != "django.conf.settings":
        return False
    fallback = _django_dict_value(defaults[0][1], "APPLICATION_MODEL")
    if not isinstance(fallback, ast.Name) or fallback.id != "APPLICATION_MODEL":
        return False
    user_call = user[0][1]
    if not _django_getattr(user_call, "OAUTH2_PROVIDER", required_type=type(None)):
        return False
    if _django_expr(index, path, user_call.args[0]) != "django.conf.settings":
        return False
    return True


def _django_getattr(node, setting, *, required_type):
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "getattr" or len(node.args) != 3:
        return False
    key, fallback = node.args[1:]
    return (
        isinstance(key, ast.Constant)
        and key.value == setting
        and isinstance(fallback, ast.Constant)
        and type(fallback.value) is required_type
    )


def _django_provider_object(index, path, provider):
    instance = _django_assignment(provider, "oauth2_settings")
    if len(instance) != 1 or not isinstance(instance[0][1], ast.Call) or not isinstance(instance[0][1].func, ast.Name):
        return False
    args = instance[0][1].args
    if len(args) < 2 or not all(isinstance(arg, ast.Name) for arg in args[:2]) or [arg.id for arg in args[:2]] != ["USER_SETTINGS", "DEFAULTS"]:
        return False
    provider_class = _django_class(index, path, instance[0][1].func.id)
    if provider_class is None or provider_class.bases or _class_has_binding(provider_class, "__setattr__"):
        return False
    from .credential_role_class_binding import effective_method
    chain = [(path, provider_class.name, provider_class)]
    getter = effective_method(chain, "__getattr__")
    constructor = effective_method(chain, "__init__")
    return (
        constructor is not None
        and getter is not None
        and any(isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name) and node.value.value.id == "self" and node.value.attr == "defaults" for node in ast.walk(getter[1]))
        and any(isinstance(node, ast.Attribute) and node.attr == "defaults" and isinstance(node.value, ast.Name) and node.value.id == "self" and isinstance(node.ctx, ast.Store) for node in ast.walk(constructor[1]))
    )


def _django_class(index, path, name):
    tree = index["modules"].get(path)
    if tree is None or not index["source"].validate(path):
        return None
    from .credential_role_scope_bindings import binding_occurrences
    rows = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == name]
    bindings = binding_occurrences(tree.body, name)
    return rows[0] if len(rows) == 1 and len(bindings) == 1 and bindings[0] is rows[0] else None


def _django_model_authority(index, app_label, model_name):
    cache_key = (app_label, model_name)
    if cache_key in index["model_cache"]:
        return index["model_cache"][cache_key]
    model_path, tree = _django_mod(index, app_label + ".models")
    if tree is None:
        return _django_cache_model(index, cache_key, None)
    if not _django_builtins_unshadowed(index, model_path, {"getattr", "setattr", "super"}):
        return _django_cache_model(index, cache_key, None)
    resolved = _django_model_classes(index, model_path, model_name)
    result = None if resolved is None else _django_model_field(index, model_path, *resolved)
    if result is not None:
        result = {"model": model_name, **result}
    return _django_cache_model(index, cache_key, result)


def _django_cache_model(index, cache_key, result):
    index["model_cache"][cache_key] = result
    return result


def _django_model_classes(index, path, name):
    cls = _django_class(index, path, name)
    chain = _django_class_chain(index, path, cls, "django.db.models.Model") if cls else None
    if chain is None or not _django_hooks_unbound(chain, _MODEL_AUTHORITY_HOOKS):
        return None
    manager_data = _django_model_manager(index, path, cls)
    if manager_data is None:
        return None
    manager, manager_chain = manager_data
    if not _django_hooks_unbound(manager_chain, _MANAGER_AUTHORITY_HOOKS):
        return None
    return chain, manager


def _django_model_manager(index, path, cls):
    assignments = _django_assignment_from_class(cls, "objects")
    if len(assignments) != 1 or not isinstance(assignments[0], ast.Call) or not isinstance(assignments[0].func, ast.Name):
        return None
    manager = _django_class(index, path, assignments[0].func.id)
    chain = _django_class_chain(index, path, manager, "django.db.models.Manager") if manager else None
    if chain is None:
        return None
    return manager, chain


_MODEL_AUTHORITY_HOOKS = frozenset({
    "save", "save_base", "from_db", "__init__", "__new__", "__getattribute__",
    "__getattr__", "__setattr__", "__delattr__",
})
_MANAGER_AUTHORITY_HOOKS = frozenset({
    "create", "get_queryset", "get_query_set", "bulk_create", "__init__", "__new__",
    "__getattribute__", "__getattr__", "__setattr__", "__delattr__",
})
_FIELD_AUTHORITY_HOOKS = frozenset({
    "__init__", "__new__", "__getattribute__", "__getattr__", "__setattr__",
    "__delattr__", "get_prep_value", "get_db_prep_save",
})


def _django_class_chain(index, path, cls, terminal):
    chain, current_path, current, seen = [], path, cls, set()
    while current is not None and len(chain) < 16:
        key = (current_path, current.name)
        if key in seen or len(current.bases) != 1:
            return None
        seen.add(key)
        chain.append((current_path, current.name, current))
        base = current.bases[0]
        canonical = _django_expr(index, current_path, base)
        if canonical == terminal:
            return chain
        resolved = _django_base_class(index, current_path, base, canonical)
        if resolved is None:
            return None
        current_path, current = resolved
    return None


def _django_base_class(index, path, base, canonical):
    if isinstance(base, ast.Name):
        local = _django_class(index, path, base.id)
        if local is not None:
            return path, local
    if not canonical:
        return None
    module, _, name = canonical.rpartition(".")
    target_path, _ = _django_mod(index, module)
    owner = _django_class(index, target_path, name) if target_path else None
    return (target_path, owner) if owner is not None else None


def _django_hooks_unbound(chain, names):
    from .credential_role_scope_bindings import binding_occurrences

    return all(
        not binding_occurrences(owner.body, name)
        for _, _, owner in chain
        for name in names
    )


def _django_model_field(index, path, model_chain, manager):
    field_value = _django_effective_class_attribute(model_chain, "client_secret")
    if len(field_value) != 1 or not isinstance(field_value[0], ast.Call) or not isinstance(field_value[0].func, ast.Name):
        return None
    field_class = _django_class(index, path, field_value[0].func.id)
    field_chain = _django_class_chain(index, path, field_class, "django.db.models.CharField") if field_class else None
    if field_chain is None or not _django_hooks_unbound(field_chain, _FIELD_AUTHORITY_HOOKS):
        return None
    from .credential_role_class_binding import effective_method
    method = effective_method(field_chain, "pre_save")
    if any(_class_has_binding(owner, "pre_save") for _, _, owner in field_chain) and method is None:
        return None
    hook = method[1] if method is not None else None
    if hook is not None and not _django_secret_field_hook(index, path, hook):
        return None
    return {"manager": manager.name, "field": field_class.name, "field_hook": "source-bound hash-or-pass-through" if hook else "Django CharField pre_save"}


def _django_effective_class_attribute(chain, name):
    from .credential_role_scope_bindings import binding_occurrences

    for _, _, owner in chain:
        bindings = binding_occurrences(owner.body, name)
        if not bindings:
            continue
        if len(bindings) != 1:
            return []
        return _django_assignment_from_class(owner, name)
    return []


def _class_has_binding(owner, name):
    from .credential_role_scope_bindings import binding_occurrences

    return bool(binding_occurrences(owner.body, name))


def _django_assignment_from_class(cls, name):
    rows = []
    for statement in cls.body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name) and statement.targets[0].id == name:
            rows.append(statement.value)
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name) and statement.target.id == name:
            rows.append(statement.value)
    return rows


def _django_secret_field_hook(index, path, method):
    imports = _django_imports(index, path)
    if not imports:
        return False
    if not _django_builtins_unshadowed(index, path, {"getattr", "setattr", "super"}):
        return False
    if not _django_hash_imports(index, path, imports):
        return False
    return _django_hash_calls(method) and _django_secret_uses_are_modeled(index, path, method)


def _django_hash_imports(index, path, imports):
    from .credential_role_scope_bindings import binding_occurrences
    for name, canonical in (("identify_hasher", "django.contrib.auth.hashers.identify_hasher"), ("make_password", "django.contrib.auth.hashers.make_password")):
        if imports.get(name) != canonical or len(binding_occurrences(index["modules"][path].body, name)) != 1:
            return False
    return True


def _django_hash_calls(method):
    allowed = {"getattr", "identify_hasher", "make_password", "setattr", "super"}
    for node in ast.walk(method):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in allowed:
                continue
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"debug", "pre_save"}:
                continue
            return False
    names = {
        node.func.id
        for node in ast.walk(method)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    return {"identify_hasher", "make_password", "setattr"}.issubset(names)


def _django_secret_uses_are_modeled(index, path, method):
    parents = index["source"].parents[path]
    for node in ast.walk(method):
        if not isinstance(node, ast.Name) or node.id != "secret" or not isinstance(node.ctx, ast.Load):
            continue
        parent = parents.get(id(node))
        if not isinstance(parent, ast.Call):
            return False
        accepted = (
            isinstance(parent.func, ast.Name) and parent.func.id in {"identify_hasher", "make_password"}
            or isinstance(parent.func, ast.Attribute) and parent.func.attr == "debug"
        )
        if not accepted:
            return False
    return True


def _django_test_function(index, path, assignment):
    parents = index["source"].parents[path]
    current = parents.get(id(assignment))
    while current is not None and not isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
        current = parents.get(id(current))
    if current is None or parents.get(id(current)) is not index["modules"][path] or not current.name.startswith("test_"):
        return None
    if any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) and node is not current for stmt in current.body for node in ast.walk(stmt)):
        return None
    args = [*current.args.posonlyargs, *current.args.args]
    if not any(arg.arg == "client" for arg in args):
        return None
    if any(arg.arg == "client" and arg is not args[0] for arg in current.args.kwonlyargs):
        return None
    from .credential_role_scope_bindings import binding_occurrences
    if binding_occurrences(current.body, "client"):
        return None
    imports = _django_imports(index, path)
    if not imports or any(_django_expr(index, path, (item.func if isinstance(item, ast.Call) else item)) == "pytest.mark.django_db" for item in current.decorator_list) is False:
        return None
    if not _django_test_module_client_fixture_safe(index, path):
        return None
    return current


def _django_test_module_client_fixture_safe(index, path):
    tree = index["modules"].get(path)
    return tree is not None and all(
        _django_fixture_decorators_safe(index, path, statement)
        for statement in tree.body
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
    )


def _django_client_fixture(index):
    return _django_plugins_unmodified(index) and _django_no_client_override(index)


def _django_plugins_unmodified(index):
    for path, tree in index["modules"].items():
        if not index["source"].validate(path):
            continue
        for statement in tree.body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                if any(isinstance(node, ast.Name) and node.id == "pytest_plugins" for target in targets for node in ast.walk(target)):
                    return False
    return True


def _django_no_client_override(index):
    for path, tree in index["modules"].items():
        if not (index["source"].relative(path) or "").endswith("conftest.py"):
            continue
        imports = _django_imports(index, path)
        if imports is None:
            return False
        for statement in tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and not _django_fixture_decorators_safe(index, path, statement):
                return False
    return True


def _django_fixture_decorators_safe(index, path, function):
    for decorator in function.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if _django_expr(index, path, target) != "pytest.fixture":
            continue
        fixture_name = function.name
        if isinstance(decorator, ast.Call):
            names = [keyword.value for keyword in decorator.keywords if keyword.arg == "name"]
            if names and (len(names) != 1 or not isinstance(names[0], ast.Constant) or not isinstance(names[0].value, str)):
                return False
            if names:
                fixture_name = names[0].value
        if fixture_name == "client":
            return False
    return True


def _django_form_request(index, path, function, secret, client_name="client"):
    calls = [node for statement in function.body for node in ast.walk(statement) if isinstance(node, ast.Call)]
    for call in calls:
        direct = _django_direct_form_request(call, secret, client_name)
        if direct:
            return direct, call
        helper = _django_source_function(index, path, call.func, function)
        if helper is not None and _django_form_helper_call(index, call, helper, secret, client_name):
            return "source-resolved form helper to local test-client post", call
    return None


def _django_direct_form_request(call, secret, client_name):
    func = call.func
    if not isinstance(func, ast.Attribute) or func.attr != "post" or not isinstance(func.value, ast.Name) or func.value.id != client_name:
        return None
    data = next((kw.value for kw in call.keywords if kw.arg == "data"), None)
    return "direct test-client post" if _django_form_dict(data, secret) else None


def _django_form_helper_call(index, call, helper, secret, client_name):
    helper_path, function = helper
    signature = [*function.args.posonlyargs, *function.args.args]
    if len(signature) < 2 or not call.args or not isinstance(call.args[0], ast.Name) or call.args[0].id != client_name:
        return False
    if any(isinstance(arg, ast.Starred) for arg in call.args) or any(keyword.arg is None for keyword in call.keywords):
        return False
    param = _django_form_helper_data_parameter(index, helper_path, function, signature)
    if param is None:
        return False
    actual = _django_call_argument(call, signature, param)
    return _django_form_dict(actual, secret)


def _django_form_helper_data_parameter(index, path, function, signature):
    imports = _django_imports(index, path)
    posts = [node for node in ast.walk(function) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "post" and isinstance(node.func.value, ast.Name) and node.func.value.id == signature[0].arg]
    if len(posts) != 1 or not imports:
        return None
    data = next((kw.value for kw in posts[0].keywords if kw.arg == "data"), None)
    if not isinstance(data, ast.Call) or _django_expr(index, path, data.func, function) != "urllib.parse.urlencode" or not data.args:
        return None
    candidate = data.args[0]
    param = candidate.values[0].id if isinstance(candidate, ast.BoolOp) and isinstance(candidate.op, ast.Or) and candidate.values and isinstance(candidate.values[0], ast.Name) else candidate.id if isinstance(candidate, ast.Name) else None
    if param is None or any(isinstance(node, ast.Name) and node.id == param and isinstance(node.ctx, (ast.Store, ast.Del)) for node in ast.walk(function)):
        return None
    return param if any(item.arg == param for item in signature) else None


def _django_call_argument(call, signature, param):
    position = next((i for i, arg in enumerate(signature) if arg.arg == param), None)
    if position is None:
        return None
    if position < len(call.args):
        return call.args[position]
    return next((kw.value for kw in call.keywords if kw.arg == param), None)


def _django_form_dict(node, secret):
    value = _django_dict_value(node, "client_secret")
    return isinstance(value, ast.Name) and value.id == secret


def _django_before(node, target):
    return (getattr(node, "lineno", 0), getattr(node, "col_offset", 0)) < (
        getattr(target, "lineno", 0), getattr(target, "col_offset", 0)
    )


def _django_mutated_before(function, name, target):
    return any(
        isinstance(node, ast.Call)
        and _django_before(node, target)
        and any(
            isinstance(value, ast.Name) and value.id == name
            for argument in [*node.args, *(item.value for item in node.keywords)]
            for value in ast.walk(argument)
        )
        for statement in function.body
        for node in ast.walk(statement)
    )


def _django_receiver_written_before(function, name, target):
    for node in ast.walk(function):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete, ast.NamedExpr)):
            continue
        targets = node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target]
        if _django_before(node, target) and any(
            isinstance(part, (ast.Attribute, ast.Subscript))
            and _root_name(part) == name
            for item in targets
            for part in ast.walk(item)
        ):
            return True
    return False


def _django_model_binding_rebound(function, name, binding):
    for node in ast.walk(function):
        if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, (ast.Store, ast.Del)) and node is not binding:
            return True
        if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)) and _root_name(node) == name:
            return True
    return False


def django_test_secret_evidence(index, path, line, value):
    if not isinstance(index, dict) or not index.get("runner_valid"):
        return _django_unknown("captured runner/source index unavailable")
    candidate, reason = _django_candidate_binding(index, path, line, value)
    if candidate is None:
        return _django_unknown(reason)
    literal, assignment, secret = candidate
    function = _django_test_function(index, path, assignment)
    if function is None:
        return _django_unknown("declaration is not inside a resolved pytest-django test with canonical client fixture")
    from .credential_role_scope_bindings import binding_occurrences
    if binding_occurrences(function.body, secret) != [assignment.targets[0]]:
        return _django_unknown("credential binding is reassigned or shadowed")
    witness, reason = _django_fixture_role_witness(index, path, function, secret)
    if witness is None:
        return _django_unknown(reason)
    return _django_evidence_record(index, path, value, literal, witness)


def _django_candidate_binding(index, path, line, value):
    source = index["source"]
    tree = index["modules"].get(path)
    if tree is None or not source.validate(path):
        return None, "source bytes and captured AST did not validate"
    candidates = [node for node in ast.walk(tree) if isinstance(node, ast.Constant) and node.lineno == line and isinstance(node.value, str) and node.value == value]
    if len(candidates) != 1:
        return None, "literal does not identify one captured declaration"
    literal = candidates[0]
    assignment = source.parents[path].get(id(literal))
    targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target] if isinstance(assignment, ast.AnnAssign) else []
    if len(targets) != 1 or not isinstance(targets[0], ast.Name) or assignment.value is not literal:
        return None, "only direct function-local string bindings are in scope"
    return (literal, assignment, targets[0].id), None


def _django_fixture_role_witness(index, path, function, secret):
    settings = _django_setting_facts(index)
    if settings is None or not _django_client_fixture(index):
        return None, "runner settings, isolated database, model default, or client fixture is unresolved"
    _, _, app_label, model_name = settings
    imports = _django_imports(index, path)
    if not imports:
        return None, "test imports are ambiguous or rebound"
    factory, factory_call = _django_factory_call(index, path, function)
    if factory is None:
        return None, "no source-resolved active application-model factory call"
    factory_path, factory_function = factory
    factory_name = _django_name(index, factory_path)
    if factory_name != app_label + ".models" or not _django_factory_resolves(index, factory_path, factory_function, f"{app_label}.{model_name}"):
        return None, "application-model factory or provider setting resolution is not closed"
    if not _django_model_signal_hooks_closed(index, path, app_label):
        return None, "registered model authority signal is unresolved"
    model, reason = _django_model_witness(index, path, function, secret, factory_call, app_label, model_name)
    if model is None:
        return None, reason
    request, reason = _django_request_witness(index, path, function, secret)
    if request is None:
        return None, reason
    if _django_settings_mutated(function) or any(isinstance(node, ast.Constant) and node.value in {"APPLICATION_MODEL", "OAUTH2_PROVIDER_APPLICATION_MODEL"} for node in ast.walk(function)):
        return None, "test mutates or overrides the active application-model setting"
    return {
        "model_facts": model["facts"],
        "factory_name": factory_name,
        "configured_model": f"{app_label}.{model_name}",
        "request_kind": request[0],
    }, None


def _django_factory_call(index, path, function):
    for statement in function.body:
        for node in ast.walk(statement):
            if not isinstance(node, ast.Call):
                continue
            resolved = _django_source_function(index, path, node.func, function)
            if resolved is not None and resolved[1].name == "get_application_model":
                return resolved, node
    return None, None


def _django_model_witness(index, path, function, secret, factory_call, app_label, model_name):
    from .credential_role_scope_bindings import binding_occurrences

    app_binding = next((node for stmt in function.body for node in ast.walk(stmt) if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Call) and node.value is factory_call), None)
    if app_binding is None or binding_occurrences(function.body, app_binding.targets[0].id) != [app_binding.targets[0]]:
        return None, "active model class is not held by one stable local binding"
    model_name_local = app_binding.targets[0].id
    model_facts = _django_model_authority(index, app_label, model_name)
    if model_facts is None:
        return None, "resolved model, manager, or client-secret field hook is unproven"
    create = next((node for stmt in function.body for node in ast.walk(stmt) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "create" and isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "objects" and isinstance(node.func.value.value, ast.Name) and node.func.value.value.id == model_name_local), None)
    if create is None or not any(keyword.arg == "client_secret" and isinstance(keyword.value, ast.Name) and keyword.value.id == secret for keyword in create.keywords):
        return None, "same local binding does not create the resolved model client_secret"
    if not _django_model_capability_uses_closed(index, path, function, model_name_local, create, app_label, model_name):
        return None, "model capability escapes the witnessed authority creation"
    if _django_model_binding_rebound(function, model_name_local, app_binding.targets[0]):
        return None, "resolved model provider is mutated"
    return {"name": model_name_local, "facts": model_facts}, None


def _django_model_capability_uses_closed(index, path, function, name, create, app_label, model_name):
    model_receiver = (
        create.func.value.value
        if isinstance(create.func, ast.Attribute)
        and isinstance(create.func.value, ast.Attribute)
        else None
    )
    if not isinstance(model_receiver, ast.Name) or model_receiver.id != name:
        return False
    loads = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, ast.Load)
    ]
    if model_receiver not in loads:
        return False
    model_path, _ = _django_mod(index, app_label + ".models")
    cls = _django_class(index, model_path, model_name) if model_path else None
    chain = _django_class_chain(index, model_path, cls, "django.db.models.Model") if cls else None
    if chain is None:
        return False
    return all(
        node is model_receiver or _django_literal_class_projection(index, path, chain, node)
        for node in loads
    )


def _django_literal_class_projection(index, path, chain, node):
    parent = index["source"].parents[path].get(id(node))
    if not isinstance(parent, ast.Attribute) or parent.value is not node:
        return False
    from .credential_role_scope_bindings import binding_occurrences

    for _, _, owner in chain:
        bindings = binding_occurrences(owner.body, parent.attr)
        if not bindings:
            continue
        if len(bindings) != 1:
            return False
        values = _django_assignment_from_class(owner, parent.attr)
        return len(values) == 1 and isinstance(values[0], ast.Constant) and type(values[0].value) in {str, int, float, bool, bytes, type(None)}
    return False


def _django_request_witness(index, path, function, secret):
    request = _django_form_request(index, path, function, secret)
    if request is None:
        return None, "same local binding is not exercised through a source-resolved local test client"
    request_kind, request_call = request
    if _django_mutated_before(function, "client", request_call) or _django_receiver_written_before(function, "client", request_call):
        return None, "test client is passed to an opaque operation before the local request"
    return (request_kind, request_call), None


def _django_evidence_record(index, path, value, literal, witness):
    raw = index["source"].source_bytes[path]
    relative = index["source"].relative(path)
    return {
        "eligible": True,
        "classification": "TEST_OWNED_LOCAL_FIXTURE",
        "source": relative,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "value_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        "declaration_span": [literal.lineno, literal.col_offset, getattr(literal, "end_lineno", literal.lineno), getattr(literal, "end_col_offset", literal.col_offset)],
        "inventory_sha256": index["inventory_sha256"],
        "runner_config_sha256": index["config_hashes"],
        "settings_module": index["runner"],
        "witness_count": 2,
        "modeled_effects": ["pytest-django test marked for database access", "SQLite in-memory test database", "resolved configured Django model created with this local credential binding", "same binding placed in a source-resolved local test-client form request"],
        "authority": {"kind": "synthetic Django test model", **witness["model_facts"], "factory": witness["factory_name"], "configured_model": witness["configured_model"]},
        "origin": "function-local fixed string literal",
        "transport": {"local_exercise": witness["request_kind"], "other_transports": "UNASSESSED", "exclusivity": "UNASSESSED"},
        "runtime_assurance": "INCOMPLETE",
        "captured_repo_only": True,
    }


def _review_audit():
    from . import review_audits

    return review_audits


def _jwt_test_owner(
    node: ast.AST, target: ast.expr
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    if not isinstance(target, ast.Name):
        return None
    owner = node
    while (
        parent := _review_audit()._security_parent(owner)
    ) is not None and not isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
        owner = parent
    if not isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    owner = parent
    if not owner.name.startswith("test_"):
        return None
    owner_parent = _review_audit()._security_parent(owner)
    if not isinstance(owner_parent, (ast.Module, ast.ClassDef)):
        return None
    if isinstance(owner_parent, ast.ClassDef) and (
        owner_parent.name.startswith("Test") is False
        or _review_audit()._security_parent(owner_parent) is not module_for(owner)
    ):
        return None
    if any(
        isinstance(statement, (ast.Global, ast.Nonlocal))
        and target.id in statement.names
        for statement in ast.walk(owner)
    ):
        return None
    class_node = _review_audit()._security_parent(owner)
    if isinstance(class_node, ast.ClassDef) and not class_node.name.startswith("Test"):
        return None
    return owner


def module_for(node):
    owner = node
    while (parent := _review_audit()._security_parent(owner)) is not None:
        owner = parent
    return owner if isinstance(owner, ast.Module) else None


def _jwt_fixture_is_exact(
    fixture: ast.FunctionDef | ast.AsyncFunctionDef,
    module_aliases: dict[str, str],
) -> bool:
    fixture_type = _JWT_TEST_FIXTURE_TYPES[fixture.name]
    if (
        len(fixture.decorator_list) != 1
        or _review_audit()._resolved_ast_name(fixture.decorator_list[0], module_aliases)
        != "pytest.fixture"
    ):
        return False
    args = fixture.args
    if (
        args.posonlyargs
        or args.args
        or args.vararg
        or args.kwonlyargs
        or args.kwarg
        or args.defaults
        or any(value is not None for value in args.kw_defaults)
    ):
        return False
    if (
        fixture.returns is None
        or _review_audit()._resolved_ast_name(fixture.returns, module_aliases)
        != fixture_type
    ):
        return False
    if len(fixture.body) != 1 or not isinstance(fixture.body[0], ast.Return):
        return False
    returned = fixture.body[0].value
    if not isinstance(returned, ast.Call):
        return False
    if (
        _review_audit()._resolved_ast_name(returned.func, module_aliases)
        != fixture_type
        or returned.args
        or returned.keywords
    ):
        return False
    provider_name = "PyJWT" if fixture.name == "jwt" else "PyJWS"
    return module_aliases.get(provider_name) == fixture_type


def _jwt_module_fixture(
    module: ast.Module, module_aliases: dict[str, str]
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    fixture_candidates = [
        statement
        for statement in module.body
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
        and statement.name in _JWT_TEST_FIXTURE_TYPES
    ]
    if len(fixture_candidates) != 1:
        return None
    fixture = fixture_candidates[0]
    if not _jwt_fixture_is_exact(fixture, module_aliases):
        return None
    if any(
        statement is not fixture
        and fixture.name in _review_audit()._bound_names(statement)
        for statement in module.body
    ):
        return None
    provider_name = "PyJWT" if fixture.name == "jwt" else "PyJWS"
    if _jwt_provider_is_mutated(module, provider_name, module_aliases, fixture):
        return None
    if _jwt_nearer_fixture_override(module, fixture):
        return None
    if not _jwt_provider_source_safe(module, fixture, module_aliases):
        return None
    return fixture


def _jwt_nearer_fixture_override(
    module: ast.Module, fixture: ast.FunctionDef | ast.AsyncFunctionDef
) -> bool:
    return any(
        isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.name == fixture.name
        and any(
            _review_audit()._resolved_ast_name(
                decorator.func if isinstance(decorator, ast.Call) else decorator,
                _review_audit()._scope_security_aliases(
                    _review_audit()._module_security_aliases(module), item
                ),
            )
            == "pytest.fixture"
            for decorator in item.decorator_list
        )
        for owner in ast.walk(module)
        if isinstance(owner, ast.ClassDef)
        for item in owner.body
    )


def _jwt_provider_source_safe(
    module: ast.Module,
    fixture: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str],
) -> bool:
    """Require the imported provider's captured source and reject external effects."""
    import hashlib

    source_context = getattr(module, "_security_source_context", None)
    if not isinstance(source_context, tuple) or len(source_context) != 2:
        return False
    root, sources = source_context
    type_name = _JWT_TEST_FIXTURE_TYPES[fixture.name]
    provider_module, provider_class = type_name.rsplit(".", 1)
    captured = getattr(module, "_security_oracle_context", {}).get(
        "captured_imports", {}
    )
    relative = Path(*provider_module.split(".")).with_suffix(".py")
    import_bindings = [
        alias.asname or alias.name
        for item in module.body
        if isinstance(item, ast.ImportFrom) and item.module == provider_module
        for alias in item.names
        if alias.name == provider_class
    ]
    if (
        import_bindings != [provider_class]
        or aliases.get(provider_class) != type_name
        or captured.get(provider_class) != (relative.as_posix(), provider_class)
    ):
        return False
    candidates = [path for path in sources if path == root / relative]
    if len(candidates) != 1:
        return False
    raw = sources[candidates[0]]
    if not isinstance(raw, bytes) or len(raw) > _review_audit().MAX_BYTES:
        return False
    try:
        provider = ast.parse(raw, filename=str(relative))
    except (SyntaxError, ValueError):
        return False
    provider_classes = [
        item
        for item in provider.body
        if isinstance(item, ast.ClassDef) and item.name == provider_class
    ]
    provider_aliases = _jwt_provider_aliases(
        provider, provider_class, {provider_class: type_name}
    )
    provider_safe = (
        len(provider_classes) == 1
        and not provider_classes[0].bases
        and not provider_classes[0].keywords
        and not provider_classes[0].decorator_list
        and not any(
            _jwt_provider_write(item, provider_class, {provider_class: type_name}, provider_aliases)
            for item in ast.walk(provider)
        )
        and _jwt_provider_api_profile_safe(provider_classes[0], provider_class)
        and bool(hashlib.sha256(raw).hexdigest())
    )
    if not provider_safe:
        return False
    if provider_class != "PyJWT":
        return True
    return _jwt_pyjws_source_safe(provider, root, sources)


def _jwt_pyjws_source_safe(provider, root, sources):
    imports_jws = [
        alias.name
        for item in provider.body
        if isinstance(item, ast.ImportFrom)
        and item.module == "api_jws"
        and item.level == 1
        for alias in item.names
        if alias.name == "PyJWS"
    ]
    jws_relative = Path("jwt/api_jws.py")
    if imports_jws != ["PyJWS"] or root / jws_relative not in sources:
        return False
    jws_raw = sources[root / jws_relative]
    if not isinstance(jws_raw, bytes) or len(jws_raw) > _review_audit().MAX_BYTES:
        return False
    try:
        jws_module = ast.parse(jws_raw, filename=jws_relative.as_posix())
    except (SyntaxError, ValueError):
        return False
    jws_classes = [
        item
        for item in jws_module.body
        if isinstance(item, ast.ClassDef) and item.name == "PyJWS"
    ]
    jws_aliases = _jwt_provider_aliases(
        jws_module, "PyJWS", {"PyJWS": "jwt.api_jws.PyJWS"}
    )
    return bool(
        len(jws_classes) == 1
        and not any(
            _jwt_provider_write(
                item,
                "PyJWS",
                {"PyJWS": "jwt.api_jws.PyJWS"},
                jws_aliases,
            )
            for item in ast.walk(jws_module)
        )
        and _jwt_provider_api_profile_safe(jws_classes[0], "PyJWS")
    )


def _jwt_attribute_path(node):
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, ast.Attribute):
        return (*_jwt_attribute_path(node.value), node.attr)
    return ()


def _jwt_method_has_call(method, attribute_path):
    return any(
        isinstance(node, ast.Call)
        and _jwt_attribute_path(node.func) == attribute_path
        for node in ast.walk(method)
    )


def _jwt_provider_api_profile_safe(provider_class, provider_class_name):
    """Recognize the captured PyJWT API flow without asserting provider purity."""
    methods = {
        item.name: item
        for item in provider_class.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if provider_class_name == "PyJWT":
        initializer = methods.get("__init__")
        encode = methods.get("encode")
        decode = methods.get("decode")
        decode_complete = methods.get("decode_complete")
        return bool(
            encode
            and decode
            and decode_complete
            and initializer
            and not encode.decorator_list
            and not decode.decorator_list
            and not decode_complete.decorator_list
            and _jwt_initializer_binds_jws(initializer)
            and any(
                isinstance(statement, ast.Return)
                and isinstance(statement.value, ast.Call)
                and _jwt_attribute_path(statement.value.func)
                == ("self", "_jws", "encode")
                for statement in encode.body
            )
            and _jwt_method_has_call(
                decode_complete, ("self", "_jws", "decode_complete")
            )
            and _jwt_direct_assignment_from_call(
                decode_complete, "decoded", ("self", "_jws", "decode_complete")
            )
            and _jwt_direct_assignment_from_call(
                decode, "decoded", ("self", "decode_complete")
            )
            and _jwt_method_has_call(decode, ("self", "decode_complete"))
            and _jwt_returns_payload(decode)
        )
    if provider_class_name == "PyJWS":
        encode = methods.get("encode")
        decode = methods.get("decode")
        decode_complete = methods.get("decode_complete")
        verify = methods.get("_verify_signature")
        return bool(
            encode
            and decode
            and decode_complete
            and verify
            and not encode.decorator_list
            and not decode.decorator_list
            and not decode_complete.decorator_list
            and not verify.decorator_list
            and _jwt_method_has_call(encode, ("self", "get_algorithm_by_name"))
            and any(
                isinstance(statement, ast.Assign)
                and isinstance(statement.value, ast.Call)
                and isinstance(statement.value.func, ast.Attribute)
                and statement.value.func.attr == "sign"
                and any(isinstance(target, ast.Name) and target.id == "signature" for target in statement.targets)
                for statement in encode.body
            )
            and _jwt_signed_result_is_encoded(encode)
            and any(
                isinstance(statement, ast.Return)
                and isinstance(statement.value, ast.Call)
                and isinstance(statement.value.func, ast.Attribute)
                and statement.value.func.attr == "decode"
                and isinstance(statement.value.func.value, ast.Name)
                and statement.value.func.value.id == "encoded_string"
                for statement in encode.body
            )
            and _jwt_active_verify_call(decode_complete)
            and _jwt_method_has_call(verify, ("self", "get_algorithm_by_name"))
            and _jwt_verify_failure_is_active(verify)
            and _jwt_direct_assignment_from_call(
                decode, "decoded", ("self", "decode_complete")
            )
            and _jwt_returns_payload(decode)
            and _jwt_method_has_call(decode, ("self", "decode_complete"))
        )


def _jwt_direct_assignment_from_call(method, target_name, attribute_path):
    return any(
        isinstance(statement, ast.Assign)
        and isinstance(statement.value, ast.Call)
        and _jwt_attribute_path(statement.value.func) == attribute_path
        and any(
            isinstance(target, ast.Name) and target.id == target_name
            for target in statement.targets
        )
        for statement in method.body
    )


def _jwt_returns_payload(method):
    return any(
        isinstance(statement, ast.Return)
        and any(
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id == "decoded"
            for node in ast.walk(statement.value)
        )
        for statement in method.body
    )


def _jwt_initializer_binds_jws(method):
    return any(
        isinstance(statement, (ast.Assign, ast.AnnAssign))
        and isinstance(statement.value, ast.Call)
        and isinstance(statement.value.func, ast.Name)
        and statement.value.func.id == "PyJWS"
        and any(
            isinstance(target, ast.Attribute)
            and target.attr == "_jws"
            and isinstance(target.value, ast.Name)
            and target.value.id == "self"
            for target in (
                statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            )
        )
        for statement in method.body
    )


def _jwt_active_verify_call(method):
    return any(
        isinstance(statement, ast.If)
        and isinstance(statement.test, ast.Name)
        and statement.test.id == "verify_signature"
        and any(
            isinstance(node, ast.Call)
            and _jwt_attribute_path(node.func) == ("self", "_verify_signature")
            for child in statement.body
            for node in ast.walk(child)
        )
        for statement in method.body
    )


def _jwt_verify_failure_is_active(method):
    return any(
        isinstance(statement, ast.If)
        and isinstance(statement.test, ast.UnaryOp)
        and isinstance(statement.test.op, ast.Not)
        and isinstance(statement.test.operand, ast.Call)
        and isinstance(statement.test.operand.func, ast.Attribute)
        and statement.test.operand.func.attr == "verify"
        and any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "InvalidSignatureError"
            for child in statement.body
            for node in ast.walk(child)
        )
        for statement in method.body
    )


def _jwt_method_returns_call(method, attribute_path):
    return any(
        isinstance(node, ast.Return)
        and isinstance(node.value, ast.Call)
        and _jwt_attribute_path(node.value.func) == attribute_path
        for node in ast.walk(method)
    )


def _jwt_signed_result_is_encoded(method):
    signature_names = {
        target.id
        for node in method.body
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute)
        and node.value.func.attr == "sign"
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    return bool(signature_names) and any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "append"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "segments"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Call)
        and isinstance(node.args[0].func, ast.Name)
        and node.args[0].func.id == "base64url_encode"
        and any(
            isinstance(argument, ast.Name) and argument.id in signature_names
            for argument in node.args[0].args
        )
        for node in (statement.value for statement in method.body if isinstance(statement, ast.Expr))
    )


def _jwt_test_has_typed_fixture_parameter(
    owner: ast.FunctionDef | ast.AsyncFunctionDef,
    fixture: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str],
) -> bool:
    fixture_type = _JWT_TEST_FIXTURE_TYPES[fixture.name]
    parameters = [
        argument
        for argument in [
            *owner.args.posonlyargs,
            *owner.args.args,
            *owner.args.kwonlyargs,
        ]
        if argument.arg == fixture.name
        and argument.annotation is not None
        and _review_audit()._resolved_ast_name(argument.annotation, aliases)
        == fixture_type
    ]
    return len(parameters) == 1


def _jwt_provider_is_mutated(
    module: ast.Module,
    provider_name: str,
    aliases: dict[str, str],
    fixture: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    provider_aliases = _jwt_provider_aliases(module, provider_name, aliases)
    for item in ast.walk(module):
        if _jwt_provider_write(item, provider_name, aliases, provider_aliases) or (
            isinstance(item, ast.Name)
            and item.id in provider_aliases
            and isinstance(item.ctx, ast.Load)
            and not _jwt_provider_use_is_closed(item, fixture, provider_aliases)
        ):
            return True
    return False


def _jwt_provider_aliases(module, provider_name, aliases):
    fixture_name = "jwt" if provider_name == "PyJWT" else "jws"
    canonical = _JWT_TEST_FIXTURE_TYPES[fixture_name]
    provider_aliases = {
        name for name, resolved in aliases.items() if resolved == canonical
    }
    provider_aliases.add(provider_name)
    changed = True
    while changed:
        changed = False
        for item in ast.walk(module):
            if not isinstance(item, (ast.Assign, ast.AnnAssign)):
                continue
            value = item.value
            if not isinstance(value, ast.Name) or value.id not in provider_aliases:
                continue
            targets = item.targets if isinstance(item, ast.Assign) else [item.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id not in provider_aliases:
                    provider_aliases.add(target.id)
                    changed = True
    return provider_aliases


def _jwt_provider_write(item, provider_name, aliases, provider_aliases):
    if isinstance(item, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
        targets = (
            item.targets
            if isinstance(item, ast.Assign)
            else (item.targets if isinstance(item, ast.Delete) else [item.target])
        )
        if any(
            _jwt_provider_write_target(target, provider_aliases) for target in targets
        ):
            return True
        for target in targets:
            if not isinstance(target, ast.Name) or target.id not in provider_aliases:
                continue
            if (
                isinstance(item, ast.Assign)
                and target.id not in aliases
                and isinstance(item.value, ast.Name)
                and item.value.id in provider_aliases
            ):
                continue
            return True
    return isinstance(item, ast.Call) and _jwt_provider_mutation_call(
        item, provider_name, aliases, provider_aliases
    )


def _jwt_provider_use_is_closed(name, fixture, provider_aliases):
    parent = _review_audit()._security_parent(name)
    if isinstance(parent, ast.arg) and parent.annotation is name:
        return True
    if (
        isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
        and parent.returns is name
    ):
        return True
    if isinstance(parent, ast.Assign) and parent.value is name:
        return any(
            isinstance(target, ast.Name) and target.id not in provider_aliases
            for target in parent.targets
        )
    # A constructor reference creates an instance; it does not mutate or export
    # the provider class. Other test cases in the same module may construct the
    # real provider independently of this fixture.
    if isinstance(parent, ast.Call) and parent.func is name:
        return True
    return bool(
        isinstance(parent, ast.Call)
        and parent.func is name
        and isinstance(fixture.body[0], ast.Return)
        and parent is fixture.body[0].value
    )


def _jwt_provider_write_target(target: ast.AST, provider_aliases: set[str]) -> bool:
    return (
        isinstance(target, ast.Attribute)
        and target.attr in {"encode", "decode"}
        and isinstance(target.value, ast.Name)
        and target.value.id in provider_aliases
    )


def _jwt_provider_mutation_call(
    call: ast.Call,
    provider_name: str,
    aliases: dict[str, str],
    provider_aliases: set[str],
) -> bool:
    if not call.args:
        return False
    fixture_name = "jwt" if provider_name == "PyJWT" else "jws"
    canonical = _JWT_TEST_FIXTURE_TYPES[fixture_name]
    name = _review_audit()._resolved_ast_name(call.func, aliases)
    if name.endswith(".patch"):
        mutation = call.args[0]
        if isinstance(mutation, ast.Constant) and isinstance(mutation.value, str):
            return mutation.value in {
                f"{canonical}.encode",
                f"{canonical}.decode",
            }
    if not (isinstance(call.args[0], ast.Name) and call.args[0].id in provider_aliases):
        return False
    if name == "setattr":
        return True
    if not (name.endswith(".setattr") or name.endswith(".patch.object")):
        return False
    return (
        len(call.args) < 2
        or not isinstance(call.args[1], ast.Constant)
        or call.args[1].value in {"encode", "decode"}
    )


def _jwt_load_is_closed_call(
    name: ast.Name, receiver: str, parent_map: dict[ast.AST, ast.AST]
) -> ast.Call | None:
    call = parent_map.get(name)
    if not isinstance(call, ast.Call):
        return None
    direct_argument = name in call.args or any(
        keyword.value is name for keyword in call.keywords
    )
    if not direct_argument or not isinstance(call.func, ast.Attribute):
        return None
    if not isinstance(call.func.value, ast.Name) or call.func.value.id != receiver:
        return None
    return call if call.func.attr in {"encode", "decode"} else None


def _jwt_call_escapes(
    call: ast.Call,
    owner: ast.FunctionDef | ast.AsyncFunctionDef,
    parent_map: dict[ast.AST, ast.AST],
) -> bool:
    ancestor = parent_map.get(call)
    while ancestor is not None and ancestor is not owner:
        if isinstance(ancestor, (ast.Return, ast.Yield, ast.YieldFrom, ast.Call)):
            return True
        ancestor = parent_map.get(ancestor)
    return False


def _jwt_local_literal_uses(
    node: ast.AST,
    target: ast.Name,
    owner: ast.FunctionDef | ast.AsyncFunctionDef,
    receiver: str,
    module: ast.Module,
) -> bool:
    if _jwt_receiver_is_rebound(owner, receiver):
        return False
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    literal_targets = {item for item in targets if isinstance(item, ast.Name)}
    if target not in literal_targets:
        return False
    key_stores = [
        item
        for item in ast.walk(owner)
        if isinstance(item, ast.Name)
        and item.id == target.id
        and isinstance(item.ctx, (ast.Store, ast.Del))
    ]
    if key_stores != [target]:
        return False
    parent_map = {
        child: parent
        for parent in ast.walk(module)
        for child in ast.iter_child_nodes(parent)
    }
    if not _jwt_receiver_uses_are_closed(owner, receiver, parent_map):
        return False
    if not _jwt_derived_results_are_closed(owner, receiver, parent_map):
        return False
    if _jwt_literal_has_nested_use(owner, target, literal_targets):
        return False
    return _jwt_literal_loads_closed(
        owner, target, literal_targets, receiver, parent_map
    )


def _jwt_local_data_expression(value):
    if isinstance(value, ast.Constant):
        return value.value is None or type(value.value) in {str, bytes, int, float, bool}
    if isinstance(value, ast.Dict):
        return all(
            key is not None
            and _jwt_local_data_expression(key)
            and _jwt_local_data_expression(item)
            for key, item in zip(value.keys, value.values)
        )
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return all(_jwt_local_data_expression(item) for item in value.elts)
    return False


def _jwt_payload_source_span(value, owner, module, aliases, encode_statement):
    if _jwt_local_data_expression(value):
        return [value.lineno, value.col_offset, value.end_lineno, value.end_col_offset]
    if not isinstance(value, ast.Name):
        return None
    local_definition = next(
        (
            statement
            for statement in ast.walk(owner)
            if isinstance(statement, (ast.Assign, ast.AnnAssign))
            and any(
                isinstance(target, ast.Name) and target.id == value.id
                for target in (
                    statement.targets
                    if isinstance(statement, ast.Assign)
                    else [statement.target]
                )
            )
        ),
        None,
    )
    definitions = [
        statement
        for statement in ast.walk(owner)
        if isinstance(statement, (ast.Assign, ast.AnnAssign))
        and any(
            isinstance(target, ast.Name) and target.id == value.id
            for target in (
                statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            )
        )
    ]
    if (
        len(definitions) == 1
        and local_definition is not None
        and _jwt_local_data_expression(local_definition.value)
        and _jwt_payload_root_is_stable(
            value.id, owner, encode_statement, module, aliases
        )
    ):
        return [
            local_definition.value.lineno,
            local_definition.value.col_offset,
            local_definition.value.end_lineno,
            local_definition.value.end_col_offset,
        ]
    if value.id not in {
        argument.arg
        for argument in [
            *owner.args.posonlyargs,
            *owner.args.args,
            *owner.args.kwonlyargs,
        ]
    }:
        return None
    candidates = [
        item
        for item in module.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.name == value.id
    ]
    if len(candidates) != 1:
        return None
    fixture = candidates[0]
    fixture_body = [
        statement
        for statement in fixture.body
        if not (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        )
    ]
    if (
        len(fixture.decorator_list) != 1
        or _review_audit()._resolved_ast_name(
            fixture.decorator_list[0], aliases
        )
        != "pytest.fixture"
        or fixture.args.posonlyargs
        or fixture.args.args
        or fixture.args.vararg
        or fixture.args.kwonlyargs
        or fixture.args.kwarg
        or len(fixture_body) != 1
        or not isinstance(fixture_body[0], ast.Return)
        or not _jwt_fixture_payload_expression_safe(
            fixture_body[0].value, module, aliases
        )
        or any(
            statement is not fixture and fixture.name in _review_audit()._bound_names(statement)
            for statement in module.body
        )
        or not _jwt_payload_root_is_stable(
            value.id,
            owner,
            encode_statement,
            module,
            aliases,
            fixture_owned=True,
        )
    ):
        return None
    returned = fixture_body[0].value
    return [returned.lineno, returned.col_offset, returned.end_lineno, returned.end_col_offset]


def _jwt_fixture_payload_expression_safe(value, module, aliases):
    if _jwt_local_data_expression(value):
        return True
    if isinstance(value, ast.Dict):
        return all(
            key is not None
            and _jwt_local_data_expression(key)
            and _jwt_fixture_payload_expression_safe(item, module, aliases)
            for key, item in zip(value.keys, value.values)
        )
    if (
        isinstance(value, ast.BinOp)
        and isinstance(value.op, (ast.Add, ast.Sub))
    ):
        return (
            _jwt_captured_test_timestamp_call(value.left, module, aliases)
            and isinstance(value.right, ast.Constant)
            and type(value.right.value) is int
            or isinstance(value.left, ast.Constant)
            and type(value.left.value) is int
            and isinstance(value.op, ast.Add)
            and _jwt_captured_test_timestamp_call(value.right, module, aliases)
        )
    return False


def _jwt_captured_test_timestamp_call(value, module, aliases):
    if (
        not isinstance(value, ast.Call)
        or not isinstance(value.func, ast.Name)
        or value.args
        or value.keywords
    ):
        return False
    binding = getattr(module, "_security_oracle_context", {}).get(
        "captured_imports", {}
    ).get(value.func.id)
    if (
        not isinstance(binding, tuple)
        or len(binding) != 2
        or not isinstance(binding[1], str)
        or aliases.get(value.func.id, "").split(".")[-1] != binding[1]
    ):
        return False
    imports = [
        alias.name
        for item in module.body
        if isinstance(item, ast.ImportFrom)
        for alias in item.names
        if (alias.asname or alias.name) == value.func.id
    ]
    if imports != [binding[1]] or _jwt_module_name_is_rebound(module, value.func.id):
        return False
    source_context = getattr(module, "_security_source_context", None)
    if not isinstance(source_context, tuple) or len(source_context) != 2:
        return False
    root, sources = source_context
    relative = Path(binding[0])
    if relative.is_absolute() or ".." in relative.parts:
        return False
    source_path = root / relative
    if not source_path.resolve().is_relative_to(root.resolve()):
        return False
    raw = sources.get(source_path)
    if not isinstance(raw, bytes) or len(raw) > _review_audit().MAX_BYTES:
        return False
    try:
        source = ast.parse(raw, filename=binding[0])
    except (SyntaxError, ValueError):
        return False
    helpers = [
        item
        for item in source.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)
        ) and item.name == binding[1]
    ]
    if len(helpers) != 1:
        return False
    return _jwt_timestamp_helper_is_source_bound(helpers[0], source)


def _jwt_module_name_is_rebound(module, name):
    for statement in module.body:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(
            statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            if statement.name == name:
                return True
            continue
        if any(
            isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, (ast.Store, ast.Del))
            for node in ast.walk(statement)
        ):
            return True
    return False


def _jwt_timestamp_helper_is_source_bound(helper, source):
    body = [
        item
        for item in helper.body
        if not (
            isinstance(item, ast.Expr)
            and isinstance(item.value, ast.Constant)
            and isinstance(item.value.value, str)
        )
    ]
    if (
        helper.decorator_list
        or helper.args.posonlyargs
        or helper.args.args
        or helper.args.vararg
        or helper.args.kwonlyargs
        or helper.args.kwarg
        or helper.args.defaults
        or helper.args.kw_defaults
        or len(body) != 1
        or not isinstance(body[0], ast.Return)
    ):
        return False
    aliases = _review_audit()._module_security_aliases(source)
    dependencies = {
        name: canonical
        for name, canonical in aliases.items()
        if canonical
        in {
            "calendar.timegm",
            "datetime.datetime",
            "datetime.timezone",
        }
        and any(
            isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, ast.Load)
            for node in ast.walk(helper)
        )
    }
    if len(dependencies) != 3 or any(
        not _jwt_captured_import_binding_is_stable(source, name)
        for name in dependencies
    ):
        return False
    result = body[0].value
    if not (
        isinstance(result, ast.Call)
        and _review_audit()._resolved_ast_name(
            result.func, aliases
        )
        == "calendar.timegm"
        and len(result.args) == 1
        and not result.keywords
    ):
        return False
    timestamp = result.args[0]
    if not (
        isinstance(timestamp, ast.Call)
        and isinstance(timestamp.func, ast.Attribute)
        and timestamp.func.attr == "utctimetuple"
        and not timestamp.args
        and not timestamp.keywords
        and isinstance(timestamp.func.value, ast.Call)
        and _review_audit()._resolved_ast_name(
            timestamp.func.value.func,
            aliases,
        )
        == "datetime.datetime.now"
        and not timestamp.func.value.args
        and len(timestamp.func.value.keywords) == 1
        and timestamp.func.value.keywords[0].arg == "tz"
        and isinstance(
            timestamp.func.value.keywords[0].value, (ast.Name, ast.Attribute)
        )
        and _review_audit()._resolved_ast_name(
            timestamp.func.value.keywords[0].value,
            aliases,
        )
        == "datetime.timezone.utc"
    ):
        return False
    return True


def _jwt_captured_import_binding_is_stable(source, name):
    from .credential_role_scope_bindings import binding_occurrences

    imports = [
        item
        for item in source.body
        if isinstance(item, (ast.Import, ast.ImportFrom))
        and any(
            (alias.asname or alias.name.split(".")[0]) == name
            for alias in item.names
        )
    ]
    if len(imports) != 1 or binding_occurrences(source.body, name) != imports:
        return False
    for statement in source.body:
        if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
            targets = (
                statement.targets
                if isinstance(statement, (ast.Assign, ast.Delete))
                else [statement.target]
            )
            if any(_root_name(target) == name for target in targets):
                return False
        expression = statement.value if isinstance(statement, ast.Expr) else statement
        if (
            isinstance(expression, ast.Call)
            and isinstance(expression.func, ast.Name)
            and expression.func.id in {"setattr", "delattr"}
        ):
            if expression.args and _root_name(expression.args[0]) == name:
                return False
    return True


def _jwt_payload_root_is_stable(
    name, owner, encode_statement, module, aliases, fixture_owned=False
):
    definition_index = _jwt_payload_initial_index(name, owner, fixture_owned)
    if definition_index is None:
        return False
    try:
        encode_index = owner.body.index(encode_statement)
    except ValueError:
        return False
    if definition_index >= encode_index:
        return False
    parents = {
        child: parent
        for statement in owner.body[definition_index + 1 : encode_index]
        for parent in ast.walk(statement)
        for child in ast.iter_child_nodes(parent)
    }
    for statement in owner.body[definition_index + 1 : encode_index]:
        loads = [
            node
            for node in ast.walk(statement)
            if isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, ast.Load)
        ]
        if loads and not _jwt_is_literal_payload_update(
            statement, name, loads, parents, module, aliases
        ):
            return False
    return True


def _jwt_payload_initial_index(name, owner, fixture_owned):
    stores = [
        node
        for node in ast.walk(owner)
        if isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    if fixture_owned:
        if stores:
            return None
        definition_index = -1
    elif len(stores) != 1:
        return None
    definitions = [
        (index, statement)
        for index, statement in enumerate(owner.body)
        if isinstance(statement, (ast.Assign, ast.AnnAssign))
        and any(
            isinstance(target, ast.Name) and target.id == name
            for target in (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
        )
    ]
    if not fixture_owned:
        if len(definitions) != 1:
            return None
        definition_index, definition = definitions[0]
        definition_targets = (
            definition.targets
            if isinstance(definition, ast.Assign)
            else [definition.target]
        )
        if stores[0] not in definition_targets or not _jwt_local_data_expression(
            definition.value
        ):
            return None
    return definition_index


def _jwt_is_literal_payload_update(statement, name, loads, parents, module, aliases):
    if (
        not isinstance(statement, ast.Assign)
        or len(statement.targets) != 1
        or not isinstance(statement.targets[0], ast.Subscript)
        or not isinstance(statement.targets[0].value, ast.Name)
        or statement.targets[0].value.id != name
        or not isinstance(statement.targets[0].ctx, ast.Store)
        or not _jwt_local_data_expression(statement.targets[0].slice)
        or not _jwt_fixture_payload_expression_safe(statement.value, module, aliases)
        or loads != [statement.targets[0].value]
    ):
        return False
    return parents.get(statement.targets[0].value) is statement.targets[0]


def _jwt_roundtrip_witness(owner, key_name, receiver, module, aliases):
    parent_map = {
        child: parent
        for parent in ast.walk(module)
        for child in ast.iter_child_nodes(parent)
    }
    pairs = []
    for statement in ast.walk(owner):
        if (
            not isinstance(statement, ast.Assign)
            or len(statement.targets) != 1
            or not isinstance(statement.targets[0], ast.Name)
            or not isinstance(statement.value, ast.Call)
        ):
            continue
        encode = statement.value
        if not (
            isinstance(encode.func, ast.Attribute)
            and encode.func.attr == "encode"
            and isinstance(encode.func.value, ast.Name)
            and encode.func.value.id == receiver
        ):
            continue
        key_bound = _jwt_argument_is_bound(encode, key_name, 1, "key")
        payload = (
            encode.args[0]
            if encode.args
            else next(
                (kw.value for kw in encode.keywords if kw.arg == "payload"), None
            )
        )
        payload_span = (
            _jwt_payload_source_span(payload, owner, module, aliases, statement)
            if payload is not None
            else None
        )
        if not key_bound or payload_span is None:
            continue
        token_name = statement.targets[0].id
        token_stores = [
            item
            for item in ast.walk(owner)
            if isinstance(item, ast.Name)
            and item.id == token_name
            and isinstance(item.ctx, (ast.Store, ast.Del))
        ]
        if token_stores != [statement.targets[0]]:
            continue
        for decode in ast.walk(owner):
            if not (
                isinstance(decode, ast.Call)
                and isinstance(decode.func, ast.Attribute)
                and decode.func.attr == "decode"
                and isinstance(decode.func.value, ast.Name)
                and decode.func.value.id == receiver
            ):
                continue
            has_token = _jwt_argument_is_bound(
                decode, token_name, 0, "jwt", "msg"
            )
            has_same_key = _jwt_argument_is_bound(decode, key_name, 1, "key")
            token_arguments = (
                ([decode.args[0]] if decode.args else [])
                + [
                    item.value
                    for item in decode.keywords
                    if item.arg in {"jwt", "msg"}
                ]
            )
            token_decodes = _jwt_token_loads_have_closed_decodes(
                owner,
                token_name,
                receiver,
                key_name,
                parent_map,
            )
            if (
                has_token
                and has_same_key
                and token_decodes
                and decode is token_decodes[0]
                and token_arguments
            ):
                pairs.append(
                    {
                        "encode": encode,
                        "decode": decode,
                        "token_target": statement.targets[0],
                        "payload_span": payload_span,
                    }
                )
    return pairs[0] if len(pairs) == 1 else None


def _jwt_token_loads_have_closed_decodes(owner, token_name, receiver, key_name, parents):
    loads = [
        item
        for item in ast.walk(owner)
        if isinstance(item, ast.Name)
        and item.id == token_name
        and isinstance(item.ctx, ast.Load)
    ]
    if not loads:
        return ()
    decodes = []
    for item in loads:
        call = parents.get(item)
        if not (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "decode"
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == receiver
            and _jwt_argument_is_bound(call, token_name, 0, "jwt", "msg")
            and _jwt_argument_is_bound(call, key_name, 1, "key")
        ):
            return ()
        token_arguments = (
            ([call.args[0]] if call.args else [])
            + [item.value for item in call.keywords if item.arg in {"jwt", "msg"}]
        )
        if item not in token_arguments:
            return ()
        decodes.append(call)
    return tuple(decodes)


def _jwt_argument_is_bound(call, name, position, *keyword_names):
    positional = call.args[position] if len(call.args) > position else None
    keyword_values = [
        item.value for item in call.keywords if item.arg in keyword_names
    ]
    return any(
        isinstance(item, ast.Name) and item.id == name
        for item in ([positional] if positional is not None else []) + keyword_values
    )


def _jwt_literal_loads_closed(owner, target, literal_targets, receiver, parent_map):
    loads = []
    for scoped_node in ast.walk(owner):
        if not isinstance(scoped_node, ast.Name) or scoped_node.id != target.id:
            continue
        if scoped_node in literal_targets and isinstance(scoped_node.ctx, ast.Store):
            continue
        if not isinstance(scoped_node.ctx, ast.Load):
            return False
        call = _jwt_load_is_closed_call(scoped_node, receiver, parent_map)
        if call is None or _jwt_call_escapes(call, owner, parent_map):
            return False
        loads.append(scoped_node)
    return bool(loads)


def _jwt_receiver_uses_are_closed(owner, receiver, parent_map) -> bool:
    for name in ast.walk(owner):
        if not isinstance(name, ast.Name) or name.id != receiver:
            continue
        if isinstance(name.ctx, (ast.Store, ast.Del)):
            return False
        parent = parent_map.get(name)
        if isinstance(parent, ast.Attribute) and parent.value is name:
            if isinstance(parent.ctx, ast.Store) or parent.attr not in {
                "encode",
                "decode",
            }:
                return False
            call = parent_map.get(parent)
            if not isinstance(call, ast.Call) or call.func is not parent:
                return False
        elif parent is not None and isinstance(parent, (ast.arg, ast.keyword)):
            continue
        else:
            return False
    return True


def _jwt_derived_results_are_closed(owner, receiver, parent_map) -> bool:
    derived = _jwt_result_assignments(owner, receiver)
    return all(
        _jwt_result_load_is_closed(name, derived[name.id], receiver, parent_map)
        for name in ast.walk(owner)
        if isinstance(name, ast.Name) and name.id in derived
    )


def _jwt_result_assignments(owner, receiver):
    derived = {}
    for item in ast.walk(owner):
        if not isinstance(item, ast.Assign) or len(item.targets) != 1:
            continue
        target = item.targets[0]
        value = item.value
        if (
            isinstance(target, ast.Name)
            and isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and isinstance(value.func.value, ast.Name)
            and value.func.value.id == receiver
            and value.func.attr in {"encode", "decode"}
        ):
            derived[target.id] = value.func.attr
    return derived


def _jwt_result_load_is_closed(name, role, receiver, parent_map):
    if isinstance(name.ctx, ast.Store):
        return isinstance(parent_map.get(name), ast.Assign)
    if not isinstance(name.ctx, ast.Load):
        return False
    parent = parent_map.get(name)
    if role == "encode":
        return bool(
            isinstance(parent, ast.Call)
            and isinstance(parent.func, ast.Attribute)
            and isinstance(parent.func.value, ast.Name)
            and parent.func.value.id == receiver
            and parent.func.attr == "decode"
            and name in parent.args
        )
    ancestor = parent
    while ancestor is not None and not isinstance(ancestor, ast.Assert):
        if isinstance(ancestor, (ast.Return, ast.Yield, ast.YieldFrom, ast.Call)):
            return False
        ancestor = parent_map.get(ancestor)
    return isinstance(ancestor, ast.Assert)


def _jwt_receiver_is_rebound(
    owner: ast.FunctionDef | ast.AsyncFunctionDef, receiver: str
) -> bool:
    return any(
        isinstance(item, ast.Name)
        and item.id == receiver
        and isinstance(item.ctx, (ast.Store, ast.Del))
        for item in ast.walk(owner)
    )


def _jwt_literal_has_nested_use(
    owner: ast.FunctionDef | ast.AsyncFunctionDef,
    target: ast.Name,
    literal_targets: set[ast.Name],
) -> bool:
    for statement in owner.body:
        for scoped_node in ast.walk(statement):
            if not isinstance(
                scoped_node,
                (*_review_audit()._FUNCTION_NODES, ast.ClassDef, ast.Lambda),
            ):
                continue
            if scoped_node is statement:
                continue
            if any(
                isinstance(child, ast.Name)
                and child.id == target.id
                and child not in literal_targets
                for child in ast.walk(scoped_node)
            ):
                return True
    return False


def closed_jwt_test_literal(
    relative: str, node: ast.AST, target: ast.expr
) -> dict | None:
    """Prove a local test literal is used only by its in-process JWT fixture."""
    if not isinstance(target, ast.Name):
        return None
    owner = _jwt_test_owner(node, target)
    if owner is None:
        return None
    module = _review_audit()._module_for_security_node(owner)
    if module is None:
        return None
    module_aliases = _review_audit()._scope_security_aliases(
        _review_audit()._module_security_aliases(module), module
    )
    fixture = _jwt_module_fixture(module, module_aliases)
    if fixture is None or not _jwt_test_has_typed_fixture_parameter(
        owner, fixture, module_aliases
    ):
        return None
    if not _jwt_local_literal_uses(node, target, owner, fixture.name, module):
        return None
    witness = _jwt_roundtrip_witness(
        owner, target.id, fixture.name, module, module_aliases
    )
    if witness is None:
        return None
    import hashlib
    import json

    source_context = module._security_source_context
    root, sources = source_context
    source_sha = getattr(module, "_oracle_source_sha256", None)
    provider_module = _JWT_TEST_FIXTURE_TYPES[fixture.name].rsplit(".", 1)[0]
    provider_path = Path(*provider_module.split(".")).with_suffix(".py")
    provider_source = root / provider_path
    provider_sha = hashlib.sha256(sources[provider_source]).hexdigest()
    source_rows = sorted(
        (path.relative_to(root).as_posix(), hashlib.sha256(raw).hexdigest())
        for path, raw in sources.items()
        if isinstance(raw, bytes)
    )
    workspace_sha = hashlib.sha256(
        json.dumps(source_rows, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "schema": "factory.jwt-local-crypto-test-primitive.v1",
        "disposition": "PROVEN_LOCAL_CRYPTO_TEST_PRIMITIVE",
        "source_path": relative,
        "source_sha256": source_sha,
        "workspace_sources_sha256": workspace_sha,
        "provider_path": provider_path.as_posix(),
        "provider_sha256": provider_sha,
        "declaration_span": [
            node.lineno,
            node.col_offset,
            node.end_lineno,
            node.end_col_offset,
        ],
        "test_owner": owner.name,
        "fixture_provider": fixture.name,
        "operation_role": "test_owned_local_sign_and_verify_roundtrip",
        "authority_role": "TEST_OWNED_SYNTHETIC_SIGNING_AUTHORITY",
        "transport_role": "UNASSESSED",
        "runtime_assurance": "INCOMPLETE",
        "test_owner_span": [
            owner.lineno,
            owner.col_offset,
            owner.end_lineno,
            owner.end_col_offset,
        ],
        "provider_allocation_span": [
            fixture.body[0].value.lineno,
            fixture.body[0].value.col_offset,
            fixture.body[0].value.end_lineno,
            fixture.body[0].value.end_col_offset,
        ],
        "encode_call_span": [
            witness["encode"].lineno,
            witness["encode"].col_offset,
            witness["encode"].end_lineno,
            witness["encode"].end_col_offset,
        ],
        "decode_call_span": [
            witness["decode"].lineno,
            witness["decode"].col_offset,
            witness["decode"].end_lineno,
            witness["decode"].end_col_offset,
        ],
        "token_result_span": [
            witness["token_target"].lineno,
            witness["token_target"].col_offset,
            witness["token_target"].end_lineno,
            witness["token_target"].end_col_offset,
        ],
        "payload_source_span": witness["payload_span"],
        "runtime_executed": False,
    }


CACHE_HELPERS = tuple(
    value
    for name, value in sorted(globals().items())
    if callable(value) and getattr(value, "__module__", None) == __name__
)
