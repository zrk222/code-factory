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


CACHE_HELPERS = tuple(
    value
    for name, value in sorted(globals().items())
    if callable(value) and getattr(value, "__module__", None) == __name__
)
