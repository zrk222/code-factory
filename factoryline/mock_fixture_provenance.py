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
    """Confirm a fixture directly returns a supported mock constructor with a closed autospec class when required."""
    body = fixture.body
    if len(body) != 1 or not isinstance(body[0], ast.Return):
        return False
    value = body[0].value
    local_aliases = audit._scope_security_aliases(aliases, fixture)
    if not isinstance(value, ast.Call):
        return False
    return _direct_mock_call_is_supported(module, fixture, value, local_aliases, audit)


def _direct_mock_call_is_supported(module, fixture, value, local_aliases, audit):
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
    """Return assertion method names only for a source-closed local class whose methods do nothing."""
    body = fixture.body
    value = (
        body[0].value if len(body) == 1 and isinstance(body[0], ast.Return) else None
    )
    cls = _inert_assertion_class(module, value, audit)
    if cls is None:
        return []
    return [n.name for n in cls.body if n.name in _ASSERTION_METHODS]


def _inert_assertion_class(module, value, audit):
    if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Name):
        return None
    classes = [
        n
        for n in module.body
        if isinstance(n, ast.ClassDef) and n.name == value.func.id
    ]
    if len(classes) != 1 or classes[0].bases or classes[0].keywords:
        return None
    cls = classes[0]
    if cls.decorator_list or any(
        s is not cls and cls.name in audit._bound_names(s) for s in module.body
    ):
        return None
    if not all(
        isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in cls.body
    ):
        return None
    return cls if all(_inert_method_body(method) for method in cls.body) else None


def _inert_method_body(method):
    return (
        not method.decorator_list
        and len(method.body) == 1
        and isinstance(method.body[0], (ast.Pass, ast.Return))
        and not (
            isinstance(method.body[0], ast.Return) and method.body[0].value is not None
        )
    )


def fixture_registration(decorator, function_name, aliases, audit):
    """Resolve a pytest.fixture decorator to its literal name, marking dynamic or unsupported names as unproven."""
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
    """Index source fixtures and record closed mock-provider and inert-assertion evidence for each fixture name."""
    from . import review_audits as audit

    aliases = audit._scope_security_aliases(audit._module_security_aliases(tree), tree)
    fixtures = _source_fixture_declarations(tree, aliases, audit)
    if not fixtures:
        return {}
    mock_provider_safe = _mock_providers_are_closed(tree, aliases, audit)
    pytest_provider_safe = _pytest_fixture_provider_safe(tree, audit)
    return {
        name: _source_fixture_binding(
            tree, name, items, aliases, audit, mock_provider_safe, pytest_provider_safe
        )
        for name, items in fixtures.items()
    }


def _source_fixture_declarations(tree, aliases, audit):
    fixtures = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for item in node.decorator_list:
                name, supported = fixture_registration(item, node.name, aliases, audit)
                if name is not None:
                    fixtures.setdefault(name, []).append((node, supported))
    return fixtures


def _source_fixture_binding(tree, name, items, aliases, audit, mock_safe, pytest_safe):
    fixture, supported_name = items[0] if len(items) == 1 else (None, False)
    controlled = bool(
        fixture
        and supported_name
        and len(fixture.decorator_list) == 1
        and not any(
            s is not fixture and name in audit._bound_names(s) for s in tree.body
        )
        and pytest_safe
    )
    return {
        "mock": bool(
            controlled
            and mock_safe
            and direct_mock_return(tree, fixture, aliases, audit)
        ),
        "inert_methods": inert_assertion_methods(tree, fixture, audit)
        if controlled
        else [],
    }


def fixtures_for_file(path: Path, sources: dict[Path, dict[str, dict]]):
    """Combine applicable ancestor conftest fixtures with the file's own fixtures, letting the nearer file entries override."""
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
    """Report whether the source-bound fixture profile marks the named fixture as a mock."""
    mapping = getattr(module, "_oracle_mock_fixture_provenance", {})
    profile = mapping.get(name, {}) if isinstance(mapping, dict) else {}
    return isinstance(profile, dict) and profile.get("mock") is True


def inert_fixture_assertion_reason(call, aliases):
    """Explain an assertion call as inert only when its fixture's source-proven profile lists that method."""
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
    """Return the fixture assertion calls whose source-bound implementations are inert."""
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


def _evidence_node_span(node):
    """Project complete parsed-source coordinates without defaulting missing fields."""
    return [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset]


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


def django_test_secret_index(
    root, modules, configs, *, source_bytes=None, inventory=None
):
    """Build a bounded index from the producer's captured Python and config bytes."""
    if not isinstance(source_bytes, dict) or not isinstance(inventory, dict):
        return None
    from .credential_role_constructor_provider import SourceSnapshotIndex

    source = SourceSnapshotIndex(root, modules, source_bytes, inventory)
    if not _django_snapshot_inputs_valid(source, configs):
        return None
    try:
        from .review_audits import tomllib

        pyproject = tomllib.loads(configs["pyproject.toml"].decode("utf-8"))
        tox = configparser.ConfigParser()
        tox.read_string(configs["tox.ini"].decode("utf-8"))
    except (ImportError, UnicodeError, ValueError, configparser.Error):
        return None
    testenv = _django_test_environment(pyproject, tox)
    if testenv is None:
        return None
    runner = _django_settings_module(testenv)
    if runner is None:
        return None
    configs_sha = {
        name: hashlib.sha256(raw).hexdigest() for name, raw in configs.items()
    }
    rows, module_paths = _django_source_paths(source, modules, inventory)
    if rows is None or any(
        _django_provider_root_shadowed(module_paths, root)
        for root in _DJANGO_CANONICAL_PROVIDER_ROOTS
    ):
        return None
    combined = dict(rows)
    combined.update(configs_sha)
    inventory_sha = hashlib.sha256(
        "\n".join(
            sorted(f"{name}\0{digest}" for name, digest in combined.items())
        ).encode()
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


def _django_snapshot_inputs_valid(source, configs):
    return (
        source.bounded
        and set(configs) == {"pyproject.toml", "tox.ini"}
        and all(isinstance(raw, bytes) for raw in configs.values())
    )


def _django_test_environment(pyproject, tox):
    testenv = tox["testenv"] if tox.has_section("testenv") else None
    if testenv is None or not re.search(
        r"\bpytest(?:\s|$)", testenv.get("commands", "")
    ):
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
    return testenv if {"pytest", "pytest-django"} <= test_deps else None


def _django_settings_module(testenv):
    match = re.search(
        r"(?m)^\s*DJANGO_SETTINGS_MODULE\s*=\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*$",
        testenv.get("setenv", ""),
    )
    return match.group(1) if match is not None else None


def _django_source_paths(source, modules, inventory):
    rows = {
        source.relative(path): digest
        for path, digest in inventory.items()
        if source.relative(path) is not None
    }
    module_paths = {
        source.relative(path): path for path in modules if source.relative(path)
    }
    return (rows if len(rows) == len(inventory) else None), module_paths


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
    if root in _DJANGO_CANONICAL_PROVIDER_ROOTS and _django_provider_root_shadowed(
        index["module_paths"], root
    ):
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
        if (
            path := index["module_paths"].get(
                f"{directory + '/' if directory else ''}conftest.py"
            )
        )
        is not None
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
            if relative == package + ".py" or (
                relative and relative.startswith(package + "/")
            ):
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
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"connect", "connect_via"}
            or isinstance(node.func, ast.Name)
            and node.func.id == "receiver"
            or isinstance(node.func, ast.Name)
            and node.func.id in {"connect", "connect_via"}
            or isinstance(node.func, ast.Attribute)
            and node.func.attr == "receiver"
            or isinstance(node.func, ast.Name)
            and node.func.id in {"pre_save", "post_save", "pre_init", "post_init"}
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
    if canonical not in {
        "importlib.import_module",
        "__import__",
        "builtins.__import__",
    }:
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
    from .credential_role_constructor_provider import binding_occurrences

    current = _django_name(index, path)
    package = current.rpartition(".")[0]
    result = {}
    for statement in tree.body:
        rows = _django_import_rows(statement, package)
        if rows is None:
            return None
        for bound, target in rows:
            occurrences = binding_occurrences(tree.body, bound)
            if (
                len(occurrences) != 1
                or occurrences[0] is not statement
                or bound in result
            ):
                return None
            result[bound] = target
    return result


def _django_import_rows(statement, package):
    if isinstance(statement, ast.Import):
        return [
            (
                alias.asname or alias.name.split(".")[0],
                alias.name if alias.asname else alias.name.split(".")[0],
            )
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
                from .credential_role_constructor_provider import binding_occurrences

                if binding_occurrences(function.body, node.id):
                    return None
                args = [
                    *function.args.posonlyargs,
                    *function.args.args,
                    *function.args.kwonlyargs,
                ]
                if (
                    any(arg.arg == node.id for arg in args)
                    or (function.args.vararg and function.args.vararg.arg == node.id)
                    or (function.args.kwarg and function.args.kwarg.arg == node.id)
                ):
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
    from .credential_role_constructor_provider import binding_occurrences

    rows = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    ]
    bindings = binding_occurrences(tree.body, name)
    if len(rows) != 1 or len(bindings) != 1 or bindings[0] is not rows[0]:
        return None
    return target_path, rows[0]


def _direct_named_assignments(owner, name):
    rows = []
    for statement in owner.body:
        target = None
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
        elif isinstance(statement, ast.AnnAssign):
            target = statement.target
        if isinstance(target, ast.Name) and target.id == name:
            rows.append((statement, statement.value))
    return rows


def _django_assignment(tree, name):
    from .credential_role_constructor_provider import binding_occurrences

    bindings = binding_occurrences(tree.body, name)
    rows = _direct_named_assignments(tree, name)
    return rows if len(rows) == len(bindings) else []


def _django_builtins_unshadowed(index, path, names):
    tree = index["modules"].get(path)
    if tree is None:
        return False
    from .credential_role_constructor_provider import binding_occurrences

    return not any(binding_occurrences(tree.body, name) for name in names)


def _django_dict_value(node, key):
    if not isinstance(node, ast.Dict):
        return None
    found = [
        value
        for item, value in zip(node.keys, node.values)
        if isinstance(item, ast.Constant) and item.value == key
    ]
    return found[0] if len(found) == 1 else None


def _django_setting_facts(index):
    settings_path, settings_tree = _django_mod(index, index["runner"])
    if settings_tree is None:
        return None
    db_rows = _django_assignment(settings_tree, "DATABASES")
    app_rows = _django_assignment(settings_tree, "OAUTH2_PROVIDER_APPLICATION_MODEL")
    installed_rows = _django_assignment(settings_tree, "INSTALLED_APPS")
    from .credential_role_constructor_provider import binding_occurrences

    if (
        len(db_rows) != 1
        or len(app_rows) < 1
        or not installed_rows
        or binding_occurrences(settings_tree.body, "OAUTH2_PROVIDER")
    ):
        return None
    db = db_rows[0][1]
    default = _django_dict_value(db, "default")
    engine = _django_dict_value(default, "ENGINE")
    name = _django_dict_value(default, "NAME")
    if not (
        isinstance(db, ast.Dict)
        and len(db.keys) == 1
        and isinstance(engine, ast.Constant)
        and engine.value == "django.db.backends.sqlite3"
        and isinstance(name, ast.Constant)
        and name.value == ":memory:"
    ):
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
    installed = {
        item.value
        for item in ast.walk(apps)
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    }
    if app_label not in installed:
        return None
    if _django_settings_mutated(settings_tree):
        return None
    return settings_path, settings_tree, app_label, model_name


def _django_settings_mutated(tree):
    protected = {
        "DATABASES",
        "OAUTH2_PROVIDER_APPLICATION_MODEL",
        "INSTALLED_APPS",
        "OAUTH2_PROVIDER",
    }
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.attr in protected
        ):
            return True
        if isinstance(node, ast.Subscript) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
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
            isinstance(part, ast.Attribute)
            and part.attr in protected
            or isinstance(part, ast.Name)
            and part.id in protected
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
    return _django_provider_settings(
        index, provider_path, provider
    ) and _django_provider_object(index, provider_path, provider)


def _django_factory_model_call(index, path, function):
    body = list(function.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body.pop(0)
    if (
        len(body) != 1
        or not isinstance(body[0], ast.Return)
        or not isinstance(body[0].value, ast.Call)
    ):
        return None
    call = body[0].value
    if (
        len(call.args) != 1
        or call.keywords
        or _django_expr(index, path, call.func, function)
        != "django.apps.apps.get_model"
    ):
        return None
    model_arg = call.args[0]
    if (
        not isinstance(model_arg, ast.Attribute)
        or model_arg.attr != "APPLICATION_MODEL"
        or not isinstance(model_arg.value, ast.Name)
    ):
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
    if not _django_getattr(
        call, "OAUTH2_PROVIDER_APPLICATION_MODEL", required_type=str
    ):
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
    if (
        not isinstance(node, ast.Call)
        or not isinstance(node.func, ast.Name)
        or node.func.id != "getattr"
        or len(node.args) != 3
    ):
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
    if (
        len(instance) != 1
        or not isinstance(instance[0][1], ast.Call)
        or not isinstance(instance[0][1].func, ast.Name)
    ):
        return False
    args = instance[0][1].args
    if (
        len(args) < 2
        or not all(isinstance(arg, ast.Name) for arg in args[:2])
        or [arg.id for arg in args[:2]] != ["USER_SETTINGS", "DEFAULTS"]
    ):
        return False
    provider_class = _django_class(index, path, instance[0][1].func.id)
    if (
        provider_class is None
        or provider_class.bases
        or _class_has_binding(provider_class, "__setattr__")
    ):
        return False
    from .credential_role_constructor_provider import effective_method

    chain = [(path, provider_class.name, provider_class)]
    getter = effective_method(chain, "__getattr__")
    constructor = effective_method(chain, "__init__")
    return (
        constructor is not None
        and getter is not None
        and any(
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "self"
            and node.value.attr == "defaults"
            for node in ast.walk(getter[1])
        )
        and any(
            isinstance(node, ast.Attribute)
            and node.attr == "defaults"
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
            and isinstance(node.ctx, ast.Store)
            for node in ast.walk(constructor[1])
        )
    )


def _django_class(index, path, name):
    tree = index["modules"].get(path)
    if tree is None or not index["source"].validate(path):
        return None
    from .credential_role_constructor_provider import binding_occurrences

    rows = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == name
    ]
    bindings = binding_occurrences(tree.body, name)
    return (
        rows[0]
        if len(rows) == 1 and len(bindings) == 1 and bindings[0] is rows[0]
        else None
    )


def _django_model_authority(index, app_label, model_name):
    cache_key = (app_label, model_name)
    if cache_key in index["model_cache"]:
        return index["model_cache"][cache_key]
    model_path, tree = _django_mod(index, app_label + ".models")
    if tree is None:
        return _django_cache_model(index, cache_key, None)
    if not _django_builtins_unshadowed(
        index, model_path, {"getattr", "setattr", "super"}
    ):
        return _django_cache_model(index, cache_key, None)
    resolved = _django_model_classes(index, model_path, model_name)
    result = (
        None if resolved is None else _django_model_field(index, model_path, *resolved)
    )
    if result is not None:
        result = {"model": model_name, **result}
    return _django_cache_model(index, cache_key, result)


def _django_cache_model(index, cache_key, result):
    index["model_cache"][cache_key] = result
    return result


def _django_model_classes(index, path, name):
    cls = _django_class(index, path, name)
    chain = (
        _django_class_chain(index, path, cls, "django.db.models.Model") if cls else None
    )
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
    if (
        len(assignments) != 1
        or not isinstance(assignments[0], ast.Call)
        or not isinstance(assignments[0].func, ast.Name)
    ):
        return None
    manager = _django_class(index, path, assignments[0].func.id)
    chain = (
        _django_class_chain(index, path, manager, "django.db.models.Manager")
        if manager
        else None
    )
    if chain is None:
        return None
    return manager, chain


_MODEL_AUTHORITY_HOOKS = frozenset(
    {
        "save",
        "save_base",
        "from_db",
        "__init__",
        "__new__",
        "__getattribute__",
        "__getattr__",
        "__setattr__",
        "__delattr__",
    }
)
_MANAGER_AUTHORITY_HOOKS = frozenset(
    {
        "create",
        "get_queryset",
        "get_query_set",
        "bulk_create",
        "__init__",
        "__new__",
        "__getattribute__",
        "__getattr__",
        "__setattr__",
        "__delattr__",
    }
)
_FIELD_AUTHORITY_HOOKS = frozenset(
    {
        "__init__",
        "__new__",
        "__getattribute__",
        "__getattr__",
        "__setattr__",
        "__delattr__",
        "get_prep_value",
        "get_db_prep_save",
    }
)


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
    from .credential_role_constructor_provider import binding_occurrences

    return all(
        not binding_occurrences(owner.body, name)
        for _, _, owner in chain
        for name in names
    )


def _django_model_field(index, path, model_chain, manager):
    field_value = _django_effective_class_attribute(model_chain, "client_secret")
    if (
        len(field_value) != 1
        or not isinstance(field_value[0], ast.Call)
        or not isinstance(field_value[0].func, ast.Name)
    ):
        return None
    field_class = _django_class(index, path, field_value[0].func.id)
    field_chain = (
        _django_class_chain(index, path, field_class, "django.db.models.CharField")
        if field_class
        else None
    )
    if field_chain is None or not _django_hooks_unbound(
        field_chain, _FIELD_AUTHORITY_HOOKS
    ):
        return None
    from .credential_role_constructor_provider import effective_method

    method = effective_method(field_chain, "pre_save")
    if (
        any(_class_has_binding(owner, "pre_save") for _, _, owner in field_chain)
        and method is None
    ):
        return None
    hook = method[1] if method is not None else None
    if hook is not None and not _django_secret_field_hook(index, path, hook):
        return None
    return {
        "manager": manager.name,
        "field": field_class.name,
        "field_hook": "source-bound hash-or-pass-through"
        if hook
        else "Django CharField pre_save",
    }


def _django_effective_class_attribute(chain, name):
    from .credential_role_constructor_provider import binding_occurrences

    for _, _, owner in chain:
        bindings = binding_occurrences(owner.body, name)
        if not bindings:
            continue
        if len(bindings) != 1:
            return []
        return _django_assignment_from_class(owner, name)
    return []


def _class_has_binding(owner, name):
    from .credential_role_constructor_provider import binding_occurrences

    return bool(binding_occurrences(owner.body, name))


def _django_assignment_from_class(cls, name):
    return [value for _, value in _direct_named_assignments(cls, name)]


def _django_secret_field_hook(index, path, method):
    imports = _django_imports(index, path)
    if not imports:
        return False
    if not _django_builtins_unshadowed(index, path, {"getattr", "setattr", "super"}):
        return False
    if not _django_hash_imports(index, path, imports):
        return False
    return _django_hash_calls(method) and _django_secret_uses_are_modeled(
        index, path, method
    )


def _django_hash_imports(index, path, imports):
    from .credential_role_constructor_provider import binding_occurrences

    for name, canonical in (
        ("identify_hasher", "django.contrib.auth.hashers.identify_hasher"),
        ("make_password", "django.contrib.auth.hashers.make_password"),
    ):
        if (
            imports.get(name) != canonical
            or len(binding_occurrences(index["modules"][path].body, name)) != 1
        ):
            return False
    return True


def _django_hash_calls(method):
    allowed = {"getattr", "identify_hasher", "make_password", "setattr", "super"}
    for node in ast.walk(method):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in allowed:
                continue
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "debug",
                "pre_save",
            }:
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
        if (
            not isinstance(node, ast.Name)
            or node.id != "secret"
            or not isinstance(node.ctx, ast.Load)
        ):
            continue
        parent = parents.get(id(node))
        if not isinstance(parent, ast.Call):
            return False
        accepted = (
            isinstance(parent.func, ast.Name)
            and parent.func.id in {"identify_hasher", "make_password"}
            or isinstance(parent.func, ast.Attribute)
            and parent.func.attr == "debug"
        )
        if not accepted:
            return False
    return True


def _django_test_function(index, path, assignment):
    parents = index["source"].parents[path]
    current = parents.get(id(assignment))
    while current is not None and not isinstance(
        current, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        current = parents.get(id(current))
    if (
        current is None
        or parents.get(id(current)) is not index["modules"][path]
        or not current.name.startswith("test_")
    ):
        return None
    if any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
        and node is not current
        for stmt in current.body
        for node in ast.walk(stmt)
    ):
        return None
    args = [*current.args.posonlyargs, *current.args.args]
    if not any(arg.arg == "client" for arg in args):
        return None
    if any(
        arg.arg == "client" and arg is not args[0] for arg in current.args.kwonlyargs
    ):
        return None
    from .credential_role_constructor_provider import binding_occurrences

    if binding_occurrences(current.body, "client"):
        return None
    imports = _django_imports(index, path)
    if (
        not imports
        or any(
            _django_expr(
                index, path, (item.func if isinstance(item, ast.Call) else item)
            )
            == "pytest.mark.django_db"
            for item in current.decorator_list
        )
        is False
    ):
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
                targets = (
                    statement.targets
                    if isinstance(statement, ast.Assign)
                    else [statement.target]
                )
                if any(
                    isinstance(node, ast.Name) and node.id == "pytest_plugins"
                    for target in targets
                    for node in ast.walk(target)
                ):
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
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and not _django_fixture_decorators_safe(index, path, statement):
                return False
    return True


def _django_fixture_decorators_safe(index, path, function):
    for decorator in function.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if _django_expr(index, path, target) != "pytest.fixture":
            continue
        fixture_name = function.name
        if isinstance(decorator, ast.Call):
            names = [
                keyword.value for keyword in decorator.keywords if keyword.arg == "name"
            ]
            if names and (
                len(names) != 1
                or not isinstance(names[0], ast.Constant)
                or not isinstance(names[0].value, str)
            ):
                return False
            if names:
                fixture_name = names[0].value
        if fixture_name == "client":
            return False
    return True


def _django_form_request(index, path, function, secret, client_name="client"):
    calls = [
        node
        for statement in function.body
        for node in ast.walk(statement)
        if isinstance(node, ast.Call)
    ]
    for call in calls:
        direct = _django_direct_form_request(call, secret, client_name)
        if direct:
            return direct, call
        helper = _django_source_function(index, path, call.func, function)
        if helper is not None and _django_form_helper_call(
            index, call, helper, secret, client_name
        ):
            return "source-resolved form helper to local test-client post", call
    return None


def _django_direct_form_request(call, secret, client_name):
    func = call.func
    if (
        not isinstance(func, ast.Attribute)
        or func.attr != "post"
        or not isinstance(func.value, ast.Name)
        or func.value.id != client_name
    ):
        return None
    data = next((kw.value for kw in call.keywords if kw.arg == "data"), None)
    return "direct test-client post" if _django_form_dict(data, secret) else None


def _django_form_helper_call(index, call, helper, secret, client_name):
    helper_path, function = helper
    signature = [*function.args.posonlyargs, *function.args.args]
    if (
        len(signature) < 2
        or not call.args
        or not isinstance(call.args[0], ast.Name)
        or call.args[0].id != client_name
    ):
        return False
    if any(isinstance(arg, ast.Starred) for arg in call.args) or any(
        keyword.arg is None for keyword in call.keywords
    ):
        return False
    param = _django_form_helper_data_parameter(index, helper_path, function, signature)
    if param is None:
        return False
    actual = _django_call_argument(call, signature, param)
    return _django_form_dict(actual, secret)


def _django_form_helper_data_parameter(index, path, function, signature):
    imports = _django_imports(index, path)
    posts = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "post"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == signature[0].arg
    ]
    if len(posts) != 1 or not imports:
        return None
    data = next((kw.value for kw in posts[0].keywords if kw.arg == "data"), None)
    if (
        not isinstance(data, ast.Call)
        or _django_expr(index, path, data.func, function) != "urllib.parse.urlencode"
        or not data.args
    ):
        return None
    candidate = data.args[0]
    param = (
        candidate.values[0].id
        if isinstance(candidate, ast.BoolOp)
        and isinstance(candidate.op, ast.Or)
        and candidate.values
        and isinstance(candidate.values[0], ast.Name)
        else candidate.id
        if isinstance(candidate, ast.Name)
        else None
    )
    if param is None or any(
        isinstance(node, ast.Name)
        and node.id == param
        and isinstance(node.ctx, (ast.Store, ast.Del))
        for node in ast.walk(function)
    ):
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
        getattr(target, "lineno", 0),
        getattr(target, "col_offset", 0),
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
        if not isinstance(
            node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete, ast.NamedExpr)
        ):
            continue
        targets = (
            node.targets
            if isinstance(node, (ast.Assign, ast.Delete))
            else [node.target]
        )
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
        if (
            isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node is not binding
        ):
            return True
        if (
            isinstance(node, (ast.Attribute, ast.Subscript))
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and _root_name(node) == name
        ):
            return True
    return False


def django_test_secret_evidence(index, path, line, value):
    """Build Django test-secret evidence only from a closed runner, canonical client fixture, stable credential binding, and fixture-role witness."""
    if not isinstance(index, dict) or not index.get("runner_valid"):
        return _django_unknown("captured runner/source index unavailable")
    candidate, reason = _django_candidate_binding(index, path, line, value)
    if candidate is None:
        return _django_unknown(reason)
    literal, assignment, secret = candidate
    function = _django_test_function(index, path, assignment)
    if function is None:
        return _django_unknown(
            "declaration is not inside a resolved pytest-django test with canonical client fixture"
        )
    from .credential_role_constructor_provider import binding_occurrences

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
    candidates = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and node.lineno == line
        and isinstance(node.value, str)
        and node.value == value
    ]
    if len(candidates) != 1:
        return None, "literal does not identify one captured declaration"
    literal = candidates[0]
    assignment = source.parents[path].get(id(literal))
    targets = (
        assignment.targets
        if isinstance(assignment, ast.Assign)
        else [assignment.target]
        if isinstance(assignment, ast.AnnAssign)
        else []
    )
    if (
        len(targets) != 1
        or not isinstance(targets[0], ast.Name)
        or assignment.value is not literal
    ):
        return None, "only direct function-local string bindings are in scope"
    return (literal, assignment, targets[0].id), None


def _django_fixture_role_witness(index, path, function, secret):
    settings = _django_setting_facts(index)
    if settings is None or not _django_client_fixture(index):
        return (
            None,
            "runner settings, isolated database, model default, or client fixture is unresolved",
        )
    _, _, app_label, model_name = settings
    imports = _django_imports(index, path)
    if not imports:
        return None, "test imports are ambiguous or rebound"
    factory, factory_call = _django_factory_call(index, path, function)
    if factory is None:
        return None, "no source-resolved active application-model factory call"
    factory_path, factory_function = factory
    factory_name = _django_name(index, factory_path)
    if factory_name != app_label + ".models" or not _django_factory_resolves(
        index, factory_path, factory_function, f"{app_label}.{model_name}"
    ):
        return (
            None,
            "application-model factory or provider setting resolution is not closed",
        )
    if not _django_model_signal_hooks_closed(index, path, app_label):
        return None, "registered model authority signal is unresolved"
    model, reason = _django_model_witness(
        index, path, function, secret, factory_call, app_label, model_name
    )
    if model is None:
        return None, reason
    request, reason = _django_request_witness(index, path, function, secret)
    if request is None:
        return None, reason
    if _django_settings_mutated(function) or any(
        isinstance(node, ast.Constant)
        and node.value in {"APPLICATION_MODEL", "OAUTH2_PROVIDER_APPLICATION_MODEL"}
        for node in ast.walk(function)
    ):
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


def _django_model_witness(
    index, path, function, secret, factory_call, app_label, model_name
):
    from .credential_role_constructor_provider import binding_occurrences

    app_binding = next(
        (
            node
            for stmt in function.body
            for node in ast.walk(stmt)
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Call)
            and node.value is factory_call
        ),
        None,
    )
    if app_binding is None or binding_occurrences(
        function.body, app_binding.targets[0].id
    ) != [app_binding.targets[0]]:
        return None, "active model class is not held by one stable local binding"
    model_name_local = app_binding.targets[0].id
    model_facts = _django_model_authority(index, app_label, model_name)
    if model_facts is None:
        return None, "resolved model, manager, or client-secret field hook is unproven"
    create = next(
        (
            node
            for stmt in function.body
            for node in ast.walk(stmt)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "create"
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == "objects"
            and isinstance(node.func.value.value, ast.Name)
            and node.func.value.value.id == model_name_local
        ),
        None,
    )
    if create is None or not any(
        keyword.arg == "client_secret"
        and isinstance(keyword.value, ast.Name)
        and keyword.value.id == secret
        for keyword in create.keywords
    ):
        return (
            None,
            "same local binding does not create the resolved model client_secret",
        )
    if not _django_model_capability_uses_closed(
        index, path, function, model_name_local, create, app_label, model_name
    ):
        return None, "model capability escapes the witnessed authority creation"
    if _django_model_binding_rebound(
        function, model_name_local, app_binding.targets[0]
    ):
        return None, "resolved model provider is mutated"
    return {"name": model_name_local, "facts": model_facts}, None


def _django_model_capability_uses_closed(
    index, path, function, name, create, app_label, model_name
):
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
    chain = (
        _django_class_chain(index, model_path, cls, "django.db.models.Model")
        if cls
        else None
    )
    if chain is None:
        return False
    return all(
        node is model_receiver
        or _django_literal_class_projection(index, path, chain, node)
        for node in loads
    )


def _django_literal_class_projection(index, path, chain, node):
    parent = index["source"].parents[path].get(id(node))
    if not isinstance(parent, ast.Attribute) or parent.value is not node:
        return False
    from .credential_role_constructor_provider import binding_occurrences

    for _, _, owner in chain:
        bindings = binding_occurrences(owner.body, parent.attr)
        if not bindings:
            continue
        if len(bindings) != 1:
            return False
        values = _django_assignment_from_class(owner, parent.attr)
        return (
            len(values) == 1
            and isinstance(values[0], ast.Constant)
            and type(values[0].value) in {str, int, float, bool, bytes, type(None)}
        )
    return False


def _django_request_witness(index, path, function, secret):
    request = _django_form_request(index, path, function, secret)
    if request is None:
        return (
            None,
            "same local binding is not exercised through a source-resolved local test client",
        )
    request_kind, request_call = request
    if _django_mutated_before(
        function, "client", request_call
    ) or _django_receiver_written_before(function, "client", request_call):
        return (
            None,
            "test client is passed to an opaque operation before the local request",
        )
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
        "declaration_span": [
            literal.lineno,
            literal.col_offset,
            getattr(literal, "end_lineno", literal.lineno),
            getattr(literal, "end_col_offset", literal.col_offset),
        ],
        "inventory_sha256": index["inventory_sha256"],
        "runner_config_sha256": index["config_hashes"],
        "settings_module": index["runner"],
        "witness_count": 2,
        "modeled_effects": [
            "pytest-django test marked for database access",
            "SQLite in-memory test database",
            "resolved configured Django model created with this local credential binding",
            "same binding placed in a source-resolved local test-client form request",
        ],
        "authority": {
            "kind": "synthetic Django test model",
            **witness["model_facts"],
            "factory": witness["factory_name"],
            "configured_model": witness["configured_model"],
        },
        "origin": "function-local fixed string literal",
        "transport": {
            "local_exercise": witness["request_kind"],
            "other_transports": "UNASSESSED",
            "exclusivity": "UNASSESSED",
        },
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
    """Find the owning AST module by following the review-audit parent chain."""
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
    module: ast.Module, module_aliases: dict[str, str], relative: str
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
    if not _jwt_provider_source_safe(module, fixture, module_aliases, relative):
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
    relative: str,
) -> bool:
    """Admit only the captured PyJWT source profile with closed test consumers."""
    source_context = getattr(module, "_security_source_context", None)
    if not isinstance(source_context, tuple) or len(source_context) != 2:
        return False
    root, sources = source_context
    type_name = _JWT_TEST_FIXTURE_TYPES[fixture.name]
    provider_module, provider_class = type_name.rsplit(".", 1)
    test_relative = relative
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
    if not _jwt_captured_provider_sources_safe(root, sources):
        return False
    if _jwt_provider_sources_mutated(
        root, sources, module, test_relative, provider_class
    ):
        return False
    return True


def _jwt_captured_provider_sources_safe(root, sources):
    expected = {
        "jwt/__init__.py": "f8f61e8d4e05e471fe7be86232fe31f12032a936ce429ae12c03d03ab68b32e6",
        "jwt/api_jwt.py": "976ed8585007e68083dd2acbcc415960e4b17ce8514fb7b5bf90ec297d3ca55b",
        "jwt/api_jws.py": "ebc79619623c88bbd9776afc592a990ae1d4c89ec2ea60f4037ac5b36abd2a53",
        "jwt/algorithms.py": "1b90a461c6ca7b3e8d62b53742d7c411c4d1146ef8bd6ee5286774ff9cac112b",
        "jwt/api_jwk.py": "1533a7fdc34aa23db7c649af87559424d8398223c65ecd3bf7d29761330f62b9",
        "jwt/exceptions.py": "d4541ff6f736aad49a42412955b8f24e31e018cdb62bc0cbc31a0e8caad12b80",
        "jwt/help.py": "83c1677b6abdfee51e2ade8105cfe5cf38e1b14ef8bdba42d10701a31e19e45f",
        "jwt/jwk_set_cache.py": "3d21e96bc1601e79db8dad50edac410babcaeec934151b11ceb3482a0b727eb1",
        "jwt/jwks_client.py": "0857af89523afe69d988044d0aefcd8f562cda0d2692001e4d6a4fa9dbd818d0",
        "jwt/types.py": "0b78d477efe2475213796919badb73f022b70518f5f4404f43532289f4781a26",
        "jwt/utils.py": "014e2080681802aa360efed7ccaccbe41d57bc54b5b6dd5676f010aade6cb9e9",
        "jwt/warnings.py": "3822ccb2edff125525f5a5b74ecfb83c5d81c82802a910d3a976abec4ddaba10",
    }
    package_paths = {
        path.relative_to(root).as_posix()
        for path in sources
        if path.is_relative_to(root / "jwt") and path.suffix == ".py"
    }
    if package_paths != set(expected):
        return False
    for relative, expected_hash in expected.items():
        raw = sources.get(root / relative)
        if not isinstance(raw, bytes) or len(raw) > _review_audit().MAX_BYTES:
            return False
        try:
            source = ast.parse(raw, filename=relative)
            actual = hashlib.sha256(
                ast.dump(source, include_attributes=False).encode()
            ).hexdigest()
        except (SyntaxError, ValueError):
            return False
        if actual != expected_hash:
            return False
        for item in ast.walk(source):
            names = (
                [alias.name.split(".", 1)[0] for alias in item.names]
                if isinstance(item, ast.Import)
                else [item.module.split(".", 1)[0]]
                if isinstance(item, ast.ImportFrom) and item.level == 0 and item.module
                else []
            )
            if any(
                root / f"{name}.py" in sources or root / name / "__init__.py" in sources
                for name in names
            ):
                return False
    return True


def _jwt_provider_sources_mutated(root, sources, module, relative, provider_class):
    providers = ("PyJWT", "PyJWS") if provider_class == "PyJWT" else ("PyJWS",)
    pending = [(root / relative, module)]
    test_parent = Path(relative).parent
    pending.extend(
        (path, None)
        for path in sources
        if path.name == "conftest.py"
        and path.relative_to(root).parent
        in (*test_parent.parents, test_parent, Path("."))
    )
    visited = set()
    while pending:
        path, known_source = pending.pop()
        if path in visited:
            continue
        visited.add(path)
        raw = sources.get(path)
        if not isinstance(raw, bytes):
            return True
        try:
            source = known_source or ast.parse(raw, filename=str(path))
        except (SyntaxError, ValueError):
            return True
        if path.relative_to(root).as_posix().startswith("jwt/"):
            continue
        if path != root / relative and _jwt_module_has_dynamic_execution(source):
            return True
        if _jwt_source_mutates_provider(source, providers):
            return True
        names = _jwt_imported_local_module_names(source, path, root, sources)
        if names is None:
            return True
        pending.extend(
            (candidate, None)
            for name in names
            for candidate in _jwt_local_module_paths(name, root, sources)
            if candidate not in visited
        )
    return False


def _jwt_source_mutates_provider(source, providers):
    aliases = _review_audit()._module_security_aliases(source)
    nodes = list(ast.walk(source))
    for name in providers:
        provider_aliases = _jwt_provider_aliases(source, name, aliases)
        if any(
            _jwt_provider_write(node, name, aliases, provider_aliases) for node in nodes
        ):
            return True
        if any(
            isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete))
            and any(
                isinstance(target, ast.Attribute)
                and target.attr in {"encode", "decode"}
                for target in (
                    node.targets
                    if isinstance(node, (ast.Assign, ast.Delete))
                    else [node.target]
                )
            )
            or isinstance(node, ast.Call)
            and _review_audit()
            ._resolved_ast_name(node.func, aliases)
            .endswith(("setattr", "patch.object"))
            and len(node.args) > 1
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in {"encode", "decode"}
            for node in nodes
        ):
            return True
    return False


def _jwt_imported_local_module_names(source, path, root, sources):
    names = []
    for item in ast.walk(source):
        if isinstance(item, ast.Import):
            names.extend(alias.name for alias in item.names)
        elif isinstance(item, ast.ImportFrom):
            relative = path.relative_to(root)
            package = list(relative.parent.parts)
            if path.name != "__init__.py":
                package = (
                    package if root / Path(*package) / "__init__.py" in sources else []
                )
            if item.level:
                if item.level > len(package) + 1:
                    return None
                package = package[: len(package) - item.level + 1]
            base = [
                *(package if item.level else []),
                *(item.module.split(".") if item.module else []),
            ]
            if base:
                names.append(".".join(base))
                names.extend(".".join([*base, alias.name]) for alias in item.names)
    return names


def _jwt_local_module_paths(name, root, sources):
    if name is None:
        return []
    parts = name.split(".")
    candidates = []
    for index in range(1, len(parts) + 1):
        prefix = Path(*parts[:index])
        candidates.extend(
            (root / prefix.with_suffix(".py"), root / prefix / "__init__.py")
        )
    return [path for path in candidates if path in sources]


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
    binding_cache = {}
    for item in ast.walk(module):
        if _jwt_provider_write(item, provider_name, aliases, provider_aliases) or (
            isinstance(item, ast.Name)
            and item.id in provider_aliases
            and isinstance(item.ctx, ast.Load)
            and not _jwt_provider_use_is_closed(
                item, fixture, provider_aliases, binding_cache
            )
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
        canonical = _JWT_TEST_FIXTURE_TYPES[
            "jwt" if provider_name == "PyJWT" else "jws"
        ]
        if any(
            _jwt_provider_write_target(target, provider_aliases)
            or isinstance(target, ast.Attribute)
            and target.attr in {"encode", "decode"}
            and _review_audit()._resolved_ast_name(target.value, aliases) == canonical
            for target in targets
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


def _jwt_provider_use_is_closed(name, fixture, provider_aliases, binding_cache=None):
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
    if _jwt_provider_is_exception_callback(name, parent, binding_cache):
        return True
    if _jwt_provider_static_call_is_closed(
        name, parent, fixture, provider_aliases, binding_cache
    ):
        return True
    return bool(
        isinstance(parent, ast.Call)
        and parent.func is name
        and isinstance(fixture.body[0], ast.Return)
        and parent is fixture.body[0].value
    )


def _jwt_provider_is_exception_callback(name, call, binding_cache=None):
    """pytest's callable raises form invokes a constructor without exporting it."""
    if not (
        isinstance(call, ast.Call)
        and len(call.args) >= 2
        and call.args[1] is name
        and not any(isinstance(item, ast.Starred) for item in call.args)
        and all(item.arg is not None for item in call.keywords)
    ):
        return False
    module = module_for(name)
    if module is None:
        return False
    audit = _review_audit()
    aliases = audit._scope_security_aliases(
        audit._module_security_aliases(module), module
    )
    scopes = []
    owner = audit._security_parent(call)
    while owner is not None and owner is not module:
        if isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scopes.append(owner)
        owner = audit._security_parent(owner)
    for scope in reversed(scopes):
        aliases = audit._scope_security_aliases(aliases, scope)
    head = audit._call_name(call).split(".", 1)[0]
    return (
        head in aliases
        and audit._normalized_call_name(call, aliases) == "pytest.raises"
        and _jwt_exception_callback_binding_stable(module, head, binding_cache)
    )


def _jwt_exception_callback_binding_stable(module, head, binding_cache=None):
    if binding_cache is not None and head in binding_cache:
        return binding_cache[head]
    stable = not _jwt_module_has_dynamic_execution(
        module
    ) and _jwt_captured_import_binding_is_stable(module, head)
    if stable:
        for node in ast.walk(module):
            if (
                isinstance(node, ast.Name)
                and node.id == head
                and isinstance(node.ctx, ast.Load)
                and not _jwt_namespace_reference_is_closed(node)
            ):
                stable = False
                break
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
                targets = (
                    node.targets
                    if isinstance(node, (ast.Assign, ast.Delete))
                    else [node.target]
                )
                if any(
                    not isinstance(target, ast.Name) and _root_name(target) == head
                    for target in targets
                ):
                    stable = False
                    break
            if (
                isinstance(node, ast.Call)
                and node.args
                and _root_name(node.args[0]) == head
            ):
                stable = False
                break
    if binding_cache is not None:
        binding_cache[head] = stable
    return stable


def _jwt_module_has_dynamic_execution(module):
    names = {
        "exec",
        "eval",
        "compile",
        "getattr",
        "setattr",
        "delattr",
        "vars",
        "globals",
        "locals",
        "__import__",
        "__builtins__",
    }
    canonical = {f"builtins.{name}" for name in names}
    namespaces = {"builtins", "sys", "inspect", "importlib"}
    frames = {
        "f_locals",
        "f_globals",
        "f_builtins",
        "gi_frame",
        "cr_frame",
        "ag_frame",
        "tb_frame",
    }
    imports = ast.Module(
        body=[
            item
            for item in ast.walk(module)
            if isinstance(item, (ast.Import, ast.ImportFrom))
        ],
        type_ignores=[],
    )
    aliases = _review_audit()._module_security_aliases(imports)
    return any(
        isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and (
            node.id in names
            or aliases.get(node.id) in canonical
            or aliases.get(node.id, "").split(".", 1)[0] in namespaces
        )
        or isinstance(node, ast.Attribute)
        and (node.attr in names | frames or node.attr.startswith("__"))
        for node in ast.walk(module)
    )


def _jwt_namespace_reference_is_closed(node):
    """A namespace or callable captured as data can be mutated through aliases."""
    parent = _review_audit()._security_parent(node)
    while isinstance(parent, ast.Attribute) and parent.value is node:
        node, parent = parent, _review_audit()._security_parent(parent)
    if isinstance(parent, ast.Call):
        return parent.func is node
    if isinstance(parent, ast.arg):
        return parent.annotation is node
    if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return node in parent.decorator_list or parent.returns is node
    return False


def _jwt_provider_static_call_is_closed(
    name, parent, fixture, provider_aliases, binding_cache=None
):
    call = _jwt_provider_static_call_shape(
        name, parent, fixture, provider_aliases, binding_cache
    )
    module = module_for(name)
    if call is None or module is None:
        return False
    audit = _review_audit()
    aliases = audit._module_security_aliases(module)
    scopes = []
    owner = audit._security_parent(name)
    while owner is not None and owner is not module:
        if isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scopes.append(owner)
        owner = audit._security_parent(owner)
    for scope in reversed(scopes):
        aliases = audit._scope_security_aliases(aliases, scope)
    return (
        aliases.get("PyJWS") == "jwt.api_jws.PyJWS"
        and _jwt_captured_import_binding_is_stable(module, "PyJWS")
        and _jwt_static_source_profile(module)
    )


def _jwt_provider_static_call_shape(
    name, parent, fixture, provider_aliases, binding_cache=None
):
    if not (
        fixture.name == "jws"
        and isinstance(name, ast.Name)
        and name.id == "PyJWS"
        and name.id in provider_aliases
        and isinstance(parent, ast.Attribute)
        and parent.value is name
        and parent.attr == "_decode_base64url_segment"
    ):
        return None
    call = _review_audit()._security_parent(parent)
    if not (
        isinstance(call, ast.Call)
        and call.func is parent
        and len(call.args) == 2
        and not call.keywords
        and isinstance(call.args[1], ast.Constant)
        and type(call.args[1].value) is str
    ):
        return None
    first = call.args[0]
    if isinstance(first, ast.Constant) and type(first.value) is bytes:
        return call
    if isinstance(first, ast.Name) and _jwt_static_bytes_parameter_is_finite(
        first, call, binding_cache
    ):
        return call
    return None


def _jwt_static_bytes_parameter_is_finite(name, call, binding_cache=None):
    audit = _review_audit()
    owner = audit._security_parent(call)
    while owner is not None and not isinstance(
        owner, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        owner = audit._security_parent(owner)
    params = (
        [
            arg
            for arg in [
                *owner.args.posonlyargs,
                *owner.args.args,
                *owner.args.kwonlyargs,
            ]
            if arg.arg == name.id
        ]
        if owner
        else []
    )
    loads = (
        [
            node
            for stmt in owner.body
            for node in ast.walk(stmt)
            if isinstance(node, ast.Name)
            and node.id == name.id
            and isinstance(node.ctx, ast.Load)
        ]
        if owner
        else []
    )
    return bool(
        owner
        and len(params) == 1
        and isinstance(params[0].annotation, ast.Name)
        and params[0].annotation.id == "bytes"
        and not owner.args.vararg
        and not owner.args.kwarg
        and not owner.args.defaults
        and not any(owner.args.kw_defaults)
        and not any(
            isinstance(node, ast.Name)
            and node.id == name.id
            and isinstance(node.ctx, (ast.Store, ast.Del))
            for stmt in owner.body
            for node in ast.walk(stmt)
        )
        and loads == [name]
        and not _jwt_provider_builtin_is_shadowed(module_for(name), "bytes")
        and _jwt_static_parametrize_domain_is_literal(
            module_for(name), owner, name.id, binding_cache
        )
    )


def _jwt_static_parametrize_domain_is_literal(
    module, owner, parameter, binding_cache=None
):
    decorator = _jwt_static_parametrize_decorator(module, owner, binding_cache)
    if decorator is None or len(decorator.args) != 2 or decorator.keywords:
        return False
    names, values = decorator.args
    if isinstance(names, ast.Constant):
        names = [names.value] if type(names.value) is str else []
    elif isinstance(names, (ast.Tuple, ast.List)) and all(
        isinstance(item, ast.Constant) and type(item.value) is str
        for item in names.elts
    ):
        names = [item.value for item in names.elts]
    else:
        names = []
    return (
        len(names) == len(set(names))
        and parameter in names
        and _jwt_static_parameter_values_are_bytes(values, len(names))
    )


def _jwt_static_parametrize_decorator(module, owner, binding_cache=None):
    aliases = _review_audit()._scope_security_aliases(
        _review_audit()._module_security_aliases(module), module
    )
    if len(owner.decorator_list) != 1:
        return None
    item = owner.decorator_list[0]
    if (
        not isinstance(item, ast.Call)
        or item.keywords
        or any(isinstance(arg, ast.Starred) for arg in item.args)
    ):
        return None
    head = _review_audit()._call_name(item).split(".", 1)[0]
    return (
        item
        if _review_audit()._normalized_call_name(item, aliases)
        == "pytest.mark.parametrize"
        and _jwt_exception_callback_binding_stable(module, head, binding_cache)
        else None
    )


def _jwt_static_parameter_values_are_bytes(values, parameter_count):
    return bool(isinstance(values, (ast.Tuple, ast.List)) and values.elts) and all(
        isinstance(case, ast.Constant) and type(case.value) is bytes
        if parameter_count == 1
        else isinstance(case, (ast.Tuple, ast.List))
        and len(case.elts) == parameter_count
        and all(
            isinstance(value, ast.Constant) and type(value.value) is bytes
            for value in case.elts
        )
        for case in values.elts
    )


def _jwt_static_source_profile(module):
    context = getattr(module, "_security_source_context", None)
    captured = getattr(module, "_security_oracle_context", {}).get(
        "captured_imports", {}
    )
    return bool(
        isinstance(context, tuple)
        and len(context) == 2
        and captured.get("PyJWS") == ("jwt/api_jws.py", "PyJWS")
        and _jwt_captured_provider_sources_safe(*context)
    )


def _jwt_provider_builtin_is_shadowed(module, name):
    return any(
        isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, ast.Store)
        or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.name == name
        or isinstance(node, (ast.Import, ast.ImportFrom))
        and name in _review_audit()._bound_names(node)
        for node in ast.walk(module)
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
    if (
        not (isinstance(call.args[0], ast.Name) and call.args[0].id in provider_aliases)
        and _review_audit()._resolved_ast_name(call.args[0], aliases) != canonical
    ):
        return False
    if name in {"setattr", "builtins.setattr"}:
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
    if isinstance(call, ast.keyword):
        call = parent_map.get(call)
    if (
        not isinstance(call, ast.Call)
        or any(isinstance(arg, ast.Starred) for arg in call.args)
        or any(keyword.arg is None for keyword in call.keywords)
    ):
        return None
    if not isinstance(call.func, ast.Attribute):
        return None
    if not isinstance(call.func.value, ast.Name) or call.func.value.id != receiver:
        return None
    if call.func.attr not in {"encode", "decode"}:
        return None
    positional_key = call.args[1] if len(call.args) > 1 else None
    keyword_keys = [keyword.value for keyword in call.keywords if keyword.arg == "key"]
    if len(keyword_keys) > 1 or positional_key is not None and keyword_keys:
        return None
    key = (
        positional_key if positional_key is not None else next(iter(keyword_keys), None)
    )
    return call if key is name else None


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


def _jwt_local_namespace_scope(module, owner):
    definitions = {}
    for item in ast.walk(module):
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            definitions.setdefault(item.name, []).append(item)
    for item in module.body:
        if isinstance(item, (ast.Assign, ast.AnnAssign)):
            for name in _review_audit()._bound_names(item):
                definitions.setdefault(name, []).append(item)
    pending, visited = [owner], set()
    while pending:
        item = pending.pop()
        if item in visited:
            continue
        visited.add(item)
        for reference in ast.walk(item):
            name = (
                reference.id
                if isinstance(reference, ast.Name)
                else getattr(reference, "attr", None)
            )
            pending.extend(definitions.get(name, []))
    return ast.Module(
        body=[
            *visited,
            *(
                item
                for item in module.body
                if isinstance(item, (ast.Import, ast.ImportFrom))
            ),
        ],
        type_ignores=[],
    )


def _jwt_local_literal_uses(node, target, owner, receiver, module) -> bool:
    if _jwt_receiver_is_rebound(owner, receiver):
        return False
    if _jwt_module_has_dynamic_execution(_jwt_local_namespace_scope(module, owner)):
        return False
    if not _jwt_local_data_expression(node.value):
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
        return value.value is None or type(value.value) in {
            str,
            bytes,
            int,
            float,
            bool,
        }
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


def _jwt_local_definitions(owner, name):
    return [
        statement
        for statement in ast.walk(owner)
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


def _jwt_payload_source_span(value, owner, module, aliases, encode_statement):
    if _jwt_local_data_expression(value):
        return _evidence_node_span(value)
    if not isinstance(value, ast.Name):
        return None
    definitions = _jwt_local_definitions(owner, value.id)
    if (
        len(definitions) == 1
        and _jwt_local_data_expression(definitions[0].value)
        and _jwt_payload_root_is_stable(
            value.id, owner, encode_statement, module, aliases
        )
    ):
        return _evidence_node_span(definitions[0].value)
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
        or _review_audit()._resolved_ast_name(fixture.decorator_list[0], aliases)
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
            statement is not fixture
            and fixture.name in _review_audit()._bound_names(statement)
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
    return _evidence_node_span(returned)


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
    if isinstance(value, ast.BinOp) and isinstance(value.op, (ast.Add, ast.Sub)):
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
    binding = (
        getattr(module, "_security_oracle_context", {})
        .get("captured_imports", {})
        .get(value.func.id)
    )
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
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.name == binding[1]
    ]
    if len(helpers) != 1:
        return False
    return _jwt_timestamp_helper_is_source_bound(helpers[0], source)


def _jwt_module_name_is_rebound(module, name):
    for statement in module.body:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
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
        and _review_audit()._resolved_ast_name(result.func, aliases)
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
    from .credential_role_constructor_provider import binding_occurrences

    imports = [
        item
        for item in source.body
        if isinstance(item, (ast.Import, ast.ImportFrom))
        and any(
            (alias.asname or alias.name.split(".")[0]) == name for alias in item.names
        )
    ]
    if len(imports) != 1 or binding_occurrences(source.body, name) != imports:
        return False
    for statement in source.body:
        if isinstance(
            statement, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)
        ):
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
            fixtures = [
                item
                for item in module.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                and item.name in _JWT_TEST_FIXTURE_TYPES
                and _jwt_fixture_is_exact(item, aliases)
            ]
            fixture = fixtures[0] if len(fixtures) == 1 else None
            if (
                len(loads) != 1
                or fixture is None
                or not _jwt_test_has_typed_fixture_parameter(owner, fixture, aliases)
                or not isinstance(statement, ast.Assign)
                or len(statement.targets) != 1
                or not isinstance(statement.targets[0], ast.Name)
                or not isinstance(statement.value, ast.Call)
                or _jwt_bound_argument(statement.value, 0, {"payload"}) is not loads[0]
                or _jwt_encoded_input_span(
                    statement.targets[0], owner, fixture.name, module, aliases
                )
                is None
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


def _jwt_bound_argument(call, position, names):
    values = ([call.args[position]] if len(call.args) > position else []) + [
        item.value for item in call.keywords if item.arg in names
    ]
    return values[0] if len(values) == 1 else None


def _jwt_owner_statement(node, owner, parents):
    while node is not None and parents.get(node) is not owner:
        node = parents.get(node)
    return node


def _jwt_crypto_operation_witness(owner, key_name, receiver, module, aliases):
    parents = {
        child: parent
        for parent in ast.walk(module)
        for child in ast.iter_child_nodes(parent)
    }
    if not _jwt_receiver_crypto_calls_are_closed(
        owner, receiver, key_name, module, aliases, parents
    ):
        return None
    calls, inputs, kinds = [], [], set()
    for item in ast.walk(owner):
        if not (
            isinstance(item, ast.Name)
            and item.id == key_name
            and isinstance(item.ctx, ast.Load)
        ):
            continue
        call = _jwt_load_is_closed_call(item, receiver, parents)
        if (
            call is None
            or _jwt_call_escapes(call, owner, parents)
            or not _jwt_crypto_result_is_closed(call, owner, parents)
        ):
            return None
        kind = call.func.attr
        value = _jwt_bound_argument(
            call, 0, {"payload"} if kind == "encode" else {"jwt", "msg"}
        )
        statement = _jwt_owner_statement(call, owner, parents)
        if statement is None:
            return None
        span = _jwt_payload_source_span(value, owner, module, aliases, statement)
        if span is None and kind == "decode":
            span = _jwt_encoded_input_span(value, owner, receiver, module, aliases)
        if span is None:
            return None
        calls.append(call)
        inputs.append(span)
        kinds.add(kind)
    if not calls:
        return None
    if len(kinds) > 1:
        kind = "roundtrip"
    else:
        kind = kinds.pop()
    return {"kind": kind, "calls": calls, "inputs": inputs}


def _jwt_receiver_crypto_calls_are_closed(
    owner, receiver, key_name, module, aliases, parents
):
    calls = [
        item
        for item in ast.walk(owner)
        if isinstance(item, ast.Call)
        and isinstance(item.func, ast.Attribute)
        and isinstance(item.func.value, ast.Name)
        and item.func.value.id == receiver
        and item.func.attr in {"encode", "decode"}
    ]
    if not calls:
        return False
    for call in calls:
        kind = call.func.attr
        key = _jwt_bound_argument(call, 1, {"key"})
        if (
            any(isinstance(item, ast.Starred) for item in call.args)
            or any(item.arg is None for item in call.keywords)
            or not _jwt_crypto_result_is_closed(call, owner, parents)
            or key is not None
            and not _jwt_key_value_is_local(
                key, key_name, owner, receiver, module, parents
            )
            or not _jwt_crypto_arguments_are_local(
                call, kind, key, owner, module, aliases
            )
        ):
            return False
    return True


def _jwt_key_value_is_local(value, key_name, owner, receiver, module, parents):
    if _jwt_local_data_expression(value):
        return True
    if not isinstance(value, ast.Name):
        return False
    definitions = _jwt_local_definitions(owner, value.id)
    if len(definitions) != 1 or not _jwt_local_data_expression(definitions[0].value):
        return False
    definition = definitions[0]
    target = next(
        (
            item
            for item in (
                definition.targets
                if isinstance(definition, ast.Assign)
                else [definition.target]
            )
            if isinstance(item, ast.Name) and item.id == value.id
        ),
        None,
    )
    if target is None:
        return False
    if value.id == key_name:
        return _jwt_local_literal_uses(definition, target, owner, receiver, module)
    stores = [
        item
        for item in ast.walk(owner)
        if isinstance(item, ast.Name)
        and item.id == value.id
        and isinstance(item.ctx, (ast.Store, ast.Del))
    ]
    if stores != [target] or _jwt_literal_has_nested_use(owner, target, {target}):
        return False
    return all(
        isinstance(parent := parents.get(item), ast.Call)
        and isinstance(parent.func, ast.Attribute)
        and isinstance(parent.func.value, ast.Name)
        and parent.func.value.id == receiver
        and parent.func.attr in {"encode", "decode"}
        and _jwt_bound_argument(parent, 1, {"key"}) is item
        for item in ast.walk(owner)
        if isinstance(item, ast.Name)
        and item.id == value.id
        and isinstance(item.ctx, ast.Load)
    )


def _jwt_crypto_arguments_are_local(call, kind, key, owner, module, aliases):
    parents = {
        child: parent
        for parent in ast.walk(owner)
        for child in ast.iter_child_nodes(parent)
    }
    statement = _jwt_owner_statement(call, owner, parents)
    positional, input_name, allowed = (
        (
            ("payload", "key", "algorithm", "headers", "json_encoder"),
            "payload",
            {"payload", "key", "algorithm", "headers", "json_encoder"},
        )
        if kind == "encode"
        else (
            ("jwt", "key", "algorithms", "options"),
            "jwt",
            {
                "jwt",
                "key",
                "algorithms",
                "options",
                "audience",
                "issuer",
                "leeway",
                "subject",
                "jti",
                "nonce",
                "detached_payload",
            },
        )
    )
    if len(call.args) > len(positional) or any(
        item.arg not in allowed and not _jwt_local_data_expression(item.value)
        for item in call.keywords
    ):
        return False
    bound = dict(zip(positional, call.args))
    for item in call.keywords:
        if item.arg in bound:
            return False
        bound[item.arg] = item.value
    if key is not None and bound.get("key") is not key:
        return False
    if (
        kind == "encode"
        and "json_encoder" in bound
        and not (
            isinstance(bound["json_encoder"], ast.Constant)
            and bound["json_encoder"].value is None
        )
    ):
        return False
    input_value = bound.get(input_name)
    if kind == "decode" and isinstance(input_value, ast.Name):
        source_span = _jwt_payload_source_span(
            input_value, owner, module, aliases, statement
        ) or _jwt_encoded_input_span(
            input_value, owner, call.func.value.id, module, aliases
        )
    else:
        source_span = _jwt_payload_source_span(
            input_value, owner, module, aliases, statement
        )
    if source_span is None:
        return False
    return all(
        name in {input_name, "key", "json_encoder"}
        or _jwt_local_data_expression(value)
        or name == "detached_payload"
        and _jwt_payload_source_span(value, owner, module, aliases, statement)
        is not None
        for name, value in bound.items()
    )


def _jwt_crypto_result_is_closed(call, owner, parents):
    parent = parents.get(call)
    if isinstance(parent, ast.Assign) and parent.value is call:
        return len(parent.targets) == 1 and isinstance(parent.targets[0], ast.Name)
    if isinstance(parent, ast.AnnAssign) and parent.value is call:
        return isinstance(parent.target, ast.Name)
    if isinstance(parent, ast.Expr) and parent.value is call:
        return True
    while parent is not None and parent is not owner:
        if isinstance(
            parent,
            (
                ast.Return,
                ast.Yield,
                ast.YieldFrom,
                ast.Call,
                ast.Attribute,
                ast.Subscript,
                ast.Dict,
                ast.List,
                ast.Tuple,
                ast.Set,
            ),
        ):
            return False
        if isinstance(parent, ast.Assert):
            return True
        if not isinstance(parent, (ast.Compare, ast.BoolOp, ast.UnaryOp)):
            return False
        parent = parents.get(parent)
    return False


def _jwt_encoded_input_span(value, owner, receiver, module, aliases):
    if not isinstance(value, ast.Name):
        return None
    definitions = _jwt_local_definitions(owner, value.id)
    if len(definitions) != 1:
        return None
    definition = definitions[0]
    token = definition.value
    if not (
        isinstance(token, ast.Call)
        and isinstance(token.func, ast.Attribute)
        and token.func.attr == "encode"
        and isinstance(token.func.value, ast.Name)
        and token.func.value.id == receiver
    ):
        return None
    key = _jwt_bound_argument(token, 1, {"key"})
    parents = {
        child: parent
        for parent in ast.walk(owner)
        for child in ast.iter_child_nodes(parent)
    }
    if not _jwt_key_value_is_local(key, "", owner, receiver, module, parents):
        return None
    payload = _jwt_bound_argument(token, 0, {"payload"})
    if _jwt_payload_source_span(payload, owner, module, aliases, definition) is None:
        return None
    return _evidence_node_span(token)


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
    for item in ast.walk(owner):
        targets = (
            item.targets
            if isinstance(item, ast.Assign)
            else [item.target]
            if isinstance(item, ast.AnnAssign)
            else []
        )
        value = getattr(item, "value", None)
        if not (
            len(targets) == 1
            and isinstance(targets[0], ast.Name)
            and isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and isinstance(value.func.value, ast.Name)
            and value.func.value.id == receiver
            and value.func.attr in {"encode", "decode"}
        ):
            continue
        target = targets[0]
        uses = [
            node
            for node in ast.walk(owner)
            if isinstance(node, ast.Name) and node.id == target.id
        ]
        if [node for node in uses if isinstance(node.ctx, (ast.Store, ast.Del))] != [
            target
        ]:
            return False
        if not all(
            _jwt_derived_load_is_closed(name, value.func.attr, receiver, parent_map)
            for name in uses
            if not isinstance(name.ctx, ast.Store)
        ):
            return False

    return True


def _jwt_derived_load_is_closed(name, role, receiver, parent_map):
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
            and _jwt_bound_argument(parent, 0, {"jwt", "msg"}) is name
        )
    while parent is not None and not isinstance(parent, ast.Assert):
        if isinstance(parent, (ast.Return, ast.Yield, ast.YieldFrom, ast.Call)):
            return False
        parent = parent_map.get(parent)
    return isinstance(parent, ast.Assert)


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
    parents = {
        child: parent
        for parent in ast.walk(owner)
        for child in ast.iter_child_nodes(parent)
    }
    scopes = (*_review_audit()._FUNCTION_NODES, ast.ClassDef, ast.Lambda)
    for item in ast.walk(owner):
        if not isinstance(item, ast.Name) or item.id != target.id:
            continue
        parent = parents.get(item)
        while parent is not None and parent is not owner:
            if isinstance(parent, scopes):
                return True
            parent = parents.get(parent)
    return False


def closed_jwt_test_literal(
    relative: str, node: ast.AST, target: ast.expr
) -> dict | None:
    """Prove a local test literal is used only by its in-process JWT fixture."""
    context = _closed_jwt_test_context(relative, node, target)
    if context is None:
        return None
    return _closed_jwt_test_evidence(relative, node, *context)


def _closed_jwt_test_context(relative, node, target):
    value = getattr(node, "value", None)
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        if _app_known_credential_format(value.value):
            return None
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
    fixture = _jwt_module_fixture(module, module_aliases, relative)
    if fixture is None or not _jwt_test_has_typed_fixture_parameter(
        owner, fixture, module_aliases
    ):
        return None
    if not _jwt_local_literal_uses(node, target, owner, fixture.name, module):
        return None
    operation = _jwt_crypto_operation_witness(
        owner, target.id, fixture.name, module, module_aliases
    )
    if operation is None:
        return None
    return target, owner, module, fixture, operation


def _closed_jwt_test_evidence(
    relative, node, target, owner, module, fixture, operation
):
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
    workspace_sha = getattr(module, "_security_workspace_sources_sha256", None)
    if not isinstance(workspace_sha, str):
        workspace_sha = hashlib.sha256(
            json.dumps(source_rows, separators=(",", ":")).encode()
        ).hexdigest()
    evidence = {
        "schema": "factory.jwt-local-crypto-test-primitive.v1",
        "disposition": "PROVEN_LOCAL_CRYPTO_TEST_PRIMITIVE",
        "source_path": relative,
        "source_sha256": source_sha,
        "workspace_sources_sha256": workspace_sha,
        "provider_path": provider_path.as_posix(),
        "provider_sha256": provider_sha,
        "declaration_span": _evidence_node_span(node),
        "test_owner": owner.name,
        "fixture_provider": fixture.name,
        "authority_role": "TEST_OWNED_SYNTHETIC_SIGNING_AUTHORITY",
        "transport_role": "UNASSESSED",
        "runtime_assurance": "INCOMPLETE",
        "test_owner_span": _evidence_node_span(owner),
        "provider_allocation_span": _evidence_node_span(fixture.body[0].value),
        "runtime_executed": False,
    }
    evidence.update(
        operation_role="test_owned_local_crypto_operation",
        operation_kind=operation["kind"],
        crypto_call_spans=[_evidence_node_span(call) for call in operation["calls"]],
        input_source_spans=operation["inputs"],
    )
    return evidence


def application_test_index(
    root, modules, source_bytes, inventory, configuration_bytes=None
):
    """Reuse the captured snapshot graph for application credential role slices."""
    from .credential_role_constructor_provider import SourceSnapshotIndex

    source = SourceSnapshotIndex(root, modules, source_bytes, inventory)
    if not source.bounded:
        return None
    paths = {source.relative(path): path for path in modules}
    if None in paths or len(paths) != len(modules):
        return None
    if any(
        _django_provider_root_shadowed(paths, name)
        for name in (
            "pytest",
            "flask",
            "django",
            "rest_framework",
            "hashlib",
            "base64",
            "json",
            "itsdangerous",
            "passlib",
            "unittest",
        )
    ):
        return None
    return {
        "source": source,
        "modules": modules,
        "module_paths": paths,
        "imports": {},
        "profiles": {},
        "configuration_bytes": configuration_bytes or {},
    }


def _app_expression_name(index, path, node, function=None):
    """Resolve only the requested binding; unrelated shadowing is irrelevant."""
    from .credential_role_constructor_provider import binding_occurrences
    from .credential_role_identity_effects import _argument_names

    if isinstance(node, ast.Attribute):
        base = _app_expression_name(index, path, node.value, function)
        return base + "." + node.attr if base else None
    if not isinstance(node, ast.Name) or not index["source"].validate(path):
        return None
    tree = index["modules"][path]
    module = _django_name(index, path)
    package = (
        module
        if index["source"].relative(path).endswith("/__init__.py")
        else module.rpartition(".")[0]
    )
    scope = (
        function
        if function is not None and binding_occurrences(function.body, node.id)
        else tree
    )
    bindings = binding_occurrences(scope.body, node.id)
    if len(bindings) != 1 or not isinstance(bindings[0], (ast.Import, ast.ImportFrom)):
        return None
    if isinstance(
        function, (ast.FunctionDef, ast.AsyncFunctionDef)
    ) and node.id in _argument_names(function):
        return None
    rows = _django_import_rows(bindings[0], package)
    return next((target for name, target in rows or () if name == node.id), None)


def _app_local_assignment(function, name):
    rows = _django_assignment(function, name)
    if len(rows) != 1:
        return None
    statement, _ = rows[0]
    return statement if isinstance(statement, ast.Assign) else None


def _app_literal_encoding(index, path, function, call):
    return (
        not call.keywords
        and len(call.args) <= 2
        and all(
            isinstance(arg, ast.Constant)
            and isinstance(arg.value, str)
            or _app_expression_name(index, path, arg, function)
            == "rest_framework.HTTP_HEADER_ENCODING"
            for arg in call.args
        )
    )


def _app_credential_lineage(index, path, function, expression, secret, seen=()):
    """Only explicit value-preserving encodings and cryptographic input edges."""
    if id(expression) in seen or len(seen) >= 24:
        return False
    seen = (*seen, id(expression))
    if isinstance(expression, ast.Name):
        if expression.id == secret:
            return True
        row = _app_local_assignment(function, expression.id)
        return bool(
            row
            and row.lineno < expression.lineno
            and _app_credential_lineage(index, path, function, row.value, secret, seen)
        )
    if isinstance(expression, ast.BinOp):
        return isinstance(expression.op, ast.Add) and any(
            _app_hash_derived(index, path, function, child, secret, seen)
            for child in (expression.left, expression.right)
        )
    if isinstance(expression, (ast.JoinedStr, ast.FormattedValue)):
        return any(
            _app_credential_lineage(index, path, function, child, secret, seen)
            for child in ast.iter_child_nodes(expression)
        )
    if not isinstance(expression, ast.Call):
        return False
    if isinstance(expression.func, ast.Attribute) and expression.func.attr in {
        "encode",
        "decode",
    }:
        return _app_literal_encoding(
            index, path, function, expression
        ) and _app_credential_lineage(
            index, path, function, expression.func.value, secret, seen
        )
    canonical = _app_expression_name(index, path, expression.func, function)
    if canonical in {"base64.b64encode", "base64.b64decode"}:
        return (
            len(expression.args) == 1
            and not expression.keywords
            and _app_credential_lineage(
                index, path, function, expression.args[0], secret, seen
            )
        )
    if canonical == "hashlib.pbkdf2_hmac":
        return (
            len(expression.args) == 4
            and not expression.keywords
            and _app_exact_raw_credential(
                index, path, function, expression.args[1], secret, seen
            )
        )
    return False


def _app_consumer_aliases(index, path, function, secret):
    candidates, assignments = {secret}, {}
    for _ in range(9):
        changed = False
        for statement in function.body:
            if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
                continue
            target = statement.targets[0]
            if not isinstance(target, ast.Name) or target.id in candidates:
                continue
            if _app_local_assignment(function, target.id) is not statement:
                continue
            if not _app_credential_lineage(
                index, path, function, statement.value, secret
            ):
                continue
            candidates.add(target.id)
            assignments[target.id] = statement
            changed = True
            if len(candidates) > 9:
                return None
        if not changed:
            return candidates, assignments
    return None


def _app_consumer_roots(index, path, function, secret, witness):
    roots = []
    for role, operation in witness.items():
        if role in {"additional_requests", "verified_password_calls"}:
            continue
        if isinstance(operation, (ast.Assign, ast.AnnAssign)):
            expression = operation.value
            if _app_credential_lineage(index, path, function, expression, secret):
                roots.append((role, expression))
            continue
        if not isinstance(operation, ast.Call):
            continue
        if role == "header":
            expressions = [
                keyword.value
                for keyword in operation.keywords
                if keyword.arg == "HTTP_AUTHORIZATION"
            ]
        elif role == "request":
            expressions = _app_request_secret_values(operation)
        else:
            expressions = [
                *operation.args,
                *(item.value for item in operation.keywords),
            ]
        roots.extend(
            (role, expression)
            for expression in expressions
            if _app_credential_lineage(index, path, function, expression, secret)
        )
    for operation in witness.get("additional_requests", ()):
        roots.extend(
            ("request", expression)
            for expression in _app_request_secret_values(operation)
            if _app_credential_lineage(index, path, function, expression, secret)
        )
    for operation in witness.get("verified_password_calls", ()):
        roots.extend(
            ("verification", expression)
            for expression in operation.args[:1]
            if _app_credential_lineage(index, path, function, expression, secret)
        )
    return roots


def _app_request_secret_values(operation):
    return [
        value
        for keyword in operation.keywords
        if keyword.arg in {"data", "json"} and isinstance(keyword.value, ast.Dict)
        for key, value in zip(keyword.value.keys, keyword.value.values)
        if isinstance(key, ast.Constant)
        and key.value in {"password", "old_password", "new_password"}
    ]


def _app_consumer_reached_assignments(candidates, assignments, secret, roots):
    pending = {
        node.id
        for _, expression in roots
        for node in ast.walk(expression)
        if isinstance(node, ast.Name) and node.id in candidates
    }
    reached, used = {secret}, {}
    while pending:
        name = pending.pop()
        if name in reached:
            continue
        statement = assignments.get(name)
        if statement is None:
            return None
        reached.add(name)
        used[name] = statement
        pending.update(
            node.id
            for node in ast.walk(statement.value)
            if isinstance(node, ast.Name)
            and node.id in candidates
            and node.id not in reached
        )
    return used


def _app_consumer_stores_closed(nodes, function, secret, candidates, used):
    for node in nodes:
        if not isinstance(node, ast.Name) or node.id not in candidates:
            continue
        if not isinstance(node.ctx, (ast.Store, ast.Del)):
            continue
        assignment = _app_local_assignment(function, node.id)
        permitted = assignment is not None and node is assignment.targets[0]
        permitted = permitted and (
            node.id == secret or node.id in used and used[node.id] is assignment
        )
        if not permitted:
            return False
    return True


def _app_consumer_allowed_loads(nodes, function, secret, candidates, used, roots):
    if not _app_consumer_stores_closed(nodes, function, secret, candidates, used):
        return None
    allowed = {}
    for statement in used.values():
        for node in ast.walk(statement.value):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                allowed[id(node)] = "derived_value"
    for role, expression in roots:
        for node in ast.walk(expression):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                allowed[id(node)] = role
    loads = [
        node
        for node in nodes
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id in candidates
    ]
    return (
        (loads, allowed)
        if loads and all(id(node) in allowed for node in loads)
        else None
    )


def _app_closed_consumer_uses(index, path, function, secret, secret_value, witness):
    """Bind every local secret use to the supported enrollment and exercise path."""
    nodes = list(ast.walk(function))
    if len(nodes) > 512:
        return None
    source_path = index["source"].relative(path)
    source_hash = index["source"].inventory.get(path)
    if source_path is None or not isinstance(source_hash, str):
        return None
    if _app_known_credential_format(secret_value) or _app_has_dynamic_scope(
        index, path, function, nodes
    ):
        return None
    aliases = _app_consumer_aliases(index, path, function, secret)
    if aliases is None:
        return None
    candidates, assignments = aliases
    roots = _app_consumer_roots(index, path, function, secret, witness)
    if not roots:
        return None
    used = _app_consumer_reached_assignments(candidates, assignments, secret, roots)
    if used is None:
        return None
    closure = _app_consumer_allowed_loads(
        nodes, function, secret, candidates, used, roots
    )
    if closure is None:
        return None
    loads, allowed = closure

    def source_row(node, name, role):
        return {
            "path": source_path,
            "sha256": source_hash,
            "span": _evidence_node_span(node),
            "name": name,
            "role": role,
        }

    operations = _app_consumer_operation_rows(index, witness, source_row)
    if operations is None:
        return None
    return {
        "schema": "factory.application-consumer-use-closure.v1",
        "complete": True,
        "source": source_path,
        "source_sha256": source_hash,
        "assignments": [
            source_row(statement, name, "credential_lineage_assignment")
            for name, statement in sorted(used.items())
        ],
        "uses": [
            source_row(node, node.id, allowed[id(node)])
            for node in sorted(loads, key=lambda item: (item.lineno, item.col_offset))
        ],
        "operations": operations,
    }


def _app_consumer_operation_rows(index, witness, source_row):
    operations = [
        source_row(node, "", role)
        for role, rows in (
            ("request", witness.get("additional_requests", ())),
            ("verification", witness.get("verified_password_calls", ())),
        )
        for node in rows
    ]
    for selected in witness.get("verified_password_implementations", ()):
        if not isinstance(selected, tuple) or len(selected) != 2:
            return None
        implementation_path, implementation = selected
        relative = index["source"].relative(implementation_path)
        implementation_hash = index["source"].inventory.get(implementation_path)
        if relative is None or not isinstance(implementation_hash, str):
            return None
        operations.append(
            {
                "path": relative,
                "sha256": implementation_hash,
                "span": _evidence_node_span(implementation),
                "name": "",
                "role": "verification_implementation",
            }
        )
    return operations


def _app_has_dynamic_scope(index, path, function, nodes):
    dynamic_calls = {
        "globals",
        "locals",
        "vars",
        "eval",
        "exec",
        "compile",
        "getattr",
        "setattr",
        "delattr",
        "_getframe",
        "currentframe",
        "stack",
        "walk_stack",
    }
    namespace_names = {
        "__builtins__",
        "__globals__",
        "__dict__",
        "_getframe",
        "currentframe",
        "f_locals",
        "f_globals",
        "f_builtins",
        "gi_frame",
        "cr_frame",
        "ag_frame",
        "tb_frame",
    }
    return (
        any(isinstance(node, (ast.Global, ast.Nonlocal)) for node in nodes)
        or any(
            isinstance(node, ast.Attribute)
            and (node.attr.startswith("_") or node.attr in namespace_names)
            for node in nodes
        )
        or any(
            isinstance(node, ast.Name) and node.id in namespace_names for node in nodes
        )
        or any(
            isinstance(node, ast.Call)
            and _app_dynamic_callable(index, path, function, node.func, dynamic_calls)
            for node in nodes
        )
    )


def _app_dynamic_callable(index, path, function, expression, dynamic_calls, seen=()):
    if id(expression) in seen or len(seen) >= 8:
        return False
    seen = (*seen, id(expression))
    if isinstance(expression, (ast.Call, ast.Subscript)):
        return True
    if isinstance(expression, ast.Attribute):
        canonical = _app_expression_name(index, path, expression, function)
        return expression.attr in dynamic_calls or canonical in {
            *(f"builtins.{name}" for name in dynamic_calls),
            "sys._getframe",
            "inspect.currentframe",
            "inspect.stack",
            "traceback.walk_stack",
        }
    if not isinstance(expression, ast.Name):
        return False
    if expression.id in dynamic_calls:
        return True
    canonical = _app_expression_name(index, path, expression, function)
    if canonical in {
        *(f"builtins.{name}" for name in dynamic_calls),
        "sys._getframe",
        "inspect.currentframe",
        "inspect.stack",
        "traceback.walk_stack",
    }:
        return True
    assignment = _app_local_assignment(function, expression.id)
    return bool(
        assignment
        and _app_dynamic_callable(
            index, path, function, assignment.value, dynamic_calls, seen
        )
    )


def _app_known_credential_format(value):
    from .context_efficiency import _SECRET_BYTES
    from .intent_quality import _looks_like_known_credential

    if value.startswith("sk_") and _looks_like_known_credential(value):
        return True
    encoded = value.encode("utf-8", "ignore")
    return any(pattern.search(encoded) for pattern in _SECRET_BYTES)


def _app_exact_raw_credential(index, path, function, expression, secret, seen=()):
    if id(expression) in seen or len(seen) >= 24:
        return False
    seen = (*seen, id(expression))
    if isinstance(expression, ast.Name):
        if expression.id == secret:
            return True
        row = _app_local_assignment(function, expression.id)
        return bool(
            row
            and _app_exact_raw_credential(
                index, path, function, row.value, secret, seen
            )
        )
    return bool(
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Attribute)
        and expression.func.attr in {"encode", "decode"}
        and _app_literal_encoding(index, path, function, expression)
        and _app_exact_raw_credential(
            index, path, function, expression.func.value, secret, seen
        )
    )


def _app_hash_derived(index, path, function, expression, secret, seen=()):
    if id(expression) in seen or len(seen) >= 24:
        return False
    seen = (*seen, id(expression))
    if isinstance(expression, ast.Name):
        row = _app_local_assignment(function, expression.id)
        return bool(
            row and _app_hash_derived(index, path, function, row.value, secret, seen)
        )
    return bool(
        isinstance(expression, ast.Call)
        and _app_expression_name(index, path, expression.func, function)
        == "hashlib.pbkdf2_hmac"
        and len(expression.args) == 4
        and not expression.keywords
        and _app_exact_raw_credential(
            index, path, function, expression.args[1], secret, seen
        )
    )


def _app_active_call(index, path, function, call):
    parent = call
    parents = index["source"].parents[path]
    while not isinstance(parent, ast.stmt):
        if isinstance(
            parent,
            (
                ast.BoolOp,
                ast.IfExp,
                ast.Lambda,
                ast.ListComp,
                ast.SetComp,
                ast.DictComp,
                ast.GeneratorExp,
            ),
        ):
            return False
        parent = parents.get(id(parent))
        if parent is None:
            return False
    if parent not in function.body:
        return False
    position = function.body.index(parent)
    return not any(
        isinstance(node, ast.Return)
        for statement in function.body[:position]
        for node in ast.walk(statement)
    )


def _app_subscript_chain(node):
    keys = []
    while isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
        keys.insert(0, node.slice.value)
        node = node.value
    return node, keys


def _app_member_chain(node):
    members = []
    while isinstance(node, ast.Attribute):
        members.insert(0, node.attr)
        node = node.value
    return [node.id, *members] if isinstance(node, ast.Name) else None


def _app_client_requests(function, receiver):
    return [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"post", "put", "patch"}
        and _app_member_chain(node.func.value) == receiver
    ]


def _app_request_credential(index, path, function, call, secret):
    data = next((kw.value for kw in call.keywords if kw.arg in {"data", "json"}), None)
    if not isinstance(data, ast.Dict):
        return False
    return any(
        isinstance(key, ast.Constant)
        and key.value == "password"
        and _app_credential_lineage(index, path, function, value, secret)
        for key, value in zip(data.keys, data.values)
    )


def _app_provider_unchanged(index, path, function, canonical):
    """Related module/attribute writes and reflective replacement invalidate roles."""
    for node in ast.walk(function):
        if isinstance(node, ast.Attribute) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            value = _app_expression_name(index, path, node.value, function)
            if value and (
                canonical == value
                or canonical.startswith(value + ".")
                or value.startswith(canonical + ".")
            ):
                return False
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"setattr", "delattr"}
        ):
            if node.args and _app_expression_name(index, path, node.args[0], function):
                return False
    return True


def _app_capability_interval(index, path, function, before):
    """Reject explicit replacement/escape of the selected client/factory roots."""
    protected = (["client"], ["self", "client"], ["self", "factory"], ["self", "app"])
    for node in ast.walk(function):
        if getattr(node, "lineno", before + 1) >= before:
            continue
        if isinstance(node, (ast.Name, ast.Attribute)) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            chain = _app_member_chain(node)
            if chain and any(chain[: len(root)] == root for root in protected):
                return False
        if isinstance(node, ast.Call) and _app_capability_call_escapes(
            index, path, function, node, protected
        ):
            return False
    return True


def _app_capability_call_escapes(index, path, function, call, protected):
    arguments = [*call.args, *(kw.value for kw in call.keywords)]
    if (
        isinstance(call.func, ast.Name)
        and call.func.id in {"setattr", "delattr"}
        and call.args
    ):
        chain = _app_member_chain(call.args[0])
        return chain == ["self"] or any(chain == root for root in protected)
    tracked = [
        arg
        for arg in arguments
        if any(_app_member_chain(arg) == root for root in protected)
    ]
    return bool(tracked) and not _app_captured_call_preserves(
        index, path, function, call, tracked
    )


def _app_captured_call_preserves(index, path, function, call, tracked):
    selected = _app_source_function(index, path, call.func, function)
    if selected is None or selected[1].decorator_list:
        return False
    callee_path, callee = selected
    parameters = [arg.arg for arg in [*callee.args.posonlyargs, *callee.args.args]]
    if callee.args.vararg or callee.args.kwarg or len(call.args) > len(parameters):
        return False
    mapping = dict(zip(parameters, call.args))
    mapping.update({kw.arg: kw.value for kw in call.keywords if kw.arg})
    roots = {
        name: "selected-capability"
        for name, value in mapping.items()
        if value in tracked
    }
    if len(roots) != len(tracked):
        return False
    from .credential_role_identity_effects import summarize_identity_effect

    effect = summarize_identity_effect(callee, callee_path, index["source"], roots)
    return effect.preserves_class_identity and not effect.field_writes


def _app_direct_returns(index, path, function):
    from .credential_role_identity_effects import own_function_nodes

    if not index["source"].validate(path):
        return []
    rows = [
        node
        for node in own_function_nodes(function, path, index["source"])
        if isinstance(node, ast.Return)
    ]
    return rows if all(node in function.body for node in rows) else []


def _app_exact_formatted_member(node, member):
    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(value, ast.FormattedValue)
            and value.format_spec is None
            and value.conversion == -1
            and _app_member_chain(value.value) == member
            for value in node.values
        )
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
        and len(node.args) == 1
        and not node.keywords
    ):
        return False
    import string

    try:
        fields = [
            (name, spec, conversion)
            for _, name, spec, conversion in string.Formatter().parse(
                node.func.value.value
            )
            if name is not None
        ]
    except ValueError:
        return False
    return (
        fields in [[("", "", None)], [("0", "", None)]]
        and _app_member_chain(node.args[0]) == member
    )


def _app_signed_user_id(index, path, function):
    returns = _app_direct_returns(index, path, function)
    parameters = function.args.args
    if len(returns) != 1 or len(parameters) != 1:
        return False
    call = returns[0].value
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "dumps"
        and isinstance(call.func.value, ast.Name)
        and len(call.args) == 1
        and not call.keywords
    ):
        return False
    rows = _django_assignment(index["modules"][path], call.func.value.id)
    if len(rows) != 1 or not isinstance(rows[0][1], ast.Call):
        return False
    if (
        _app_expression_name(index, path, rows[0][1].func)
        != "itsdangerous.URLSafeTimedSerializer"
    ):
        return False
    argument = call.args[0]
    return bool(
        isinstance(argument, ast.Call)
        and isinstance(argument.func, ast.Name)
        and argument.func.id == "str"
        and len(argument.args) == 1
        and _app_member_chain(argument.args[0]) == [parameters[0].arg, "id"]
    )


def _app_basic_pair(function, expression, seen=()):
    if id(expression) in seen or len(seen) >= 24:
        return None
    seen = (*seen, id(expression))
    if isinstance(expression, ast.Name):
        row = _app_local_assignment(function, expression.id)
        return _app_basic_pair(function, row.value, seen) if row else None
    if isinstance(expression, ast.Call):
        if isinstance(expression.func, ast.Attribute) and expression.func.attr in {
            "encode",
            "decode",
        }:
            return _app_basic_pair(function, expression.func.value, seen)
        return (
            _app_basic_pair(function, expression.args[0], seen)
            if expression.args
            else None
        )
    if not isinstance(expression, ast.JoinedStr):
        return None
    values = expression.values
    if (
        len(values) == 3
        and isinstance(values[0], ast.FormattedValue)
        and isinstance(values[1], ast.Constant)
        and values[1].value == ":"
        and isinstance(values[2], ast.FormattedValue)
    ):
        if all(
            isinstance(values[n].value, ast.Name)
            and values[n].format_spec is None
            and values[n].conversion == -1
            for n in (0, 2)
        ):
            return values[0].value.id, values[2].value.id
    pairs = [
        _app_basic_pair(function, value.value, seen)
        for value in values
        if isinstance(value, ast.FormattedValue)
    ]
    pairs = [pair for pair in pairs if pair is not None]
    return pairs[0] if len(pairs) == 1 else None


def _app_drf_same_credentials(function, creation, header, secret):
    username = next(
        (kw.value for kw in creation.keywords if kw.arg == "username"), None
    )
    if (
        not isinstance(username, ast.Name)
        or _app_local_assignment(function, username.id) is None
    ):
        return False
    expression = next(
        (kw.value for kw in header.keywords if kw.arg == "HTTP_AUTHORIZATION"), None
    )
    return _app_basic_pair(function, expression) == (username.id, secret)


def _app_provider_scopes_clear(index, path, function):
    providers = (
        "django.contrib.auth.models.User",
        "rest_framework.test.APITestCase",
        "base64.b64encode",
        "hashlib.pbkdf2_hmac",
    )
    return all(
        _app_provider_unchanged(index, path, function, name) for name in providers
    )


def _app_drf_enrollment(index, path, function, owner, secret):
    if not isinstance(owner, ast.ClassDef) or owner.decorator_list or owner.keywords:
        return None
    if (
        len(owner.bases) != 1
        or _app_expression_name(index, path, owner.bases[0])
        != "rest_framework.test.APITestCase"
    ):
        return None
    from .credential_role_constructor_provider import binding_occurrences

    if any(
        binding_occurrences(owner.body, name)
        for name in (
            "client",
            "client_class",
            "__init__",
            "__new__",
            "__getattribute__",
            "__getattr__",
            "run",
        )
    ):
        return None
    creates = [
        call
        for call in ast.walk(function)
        if isinstance(call, ast.Call)
        and _app_expression_name(index, path, call.func, function)
        == "django.contrib.auth.models.User.objects.create_user"
        and any(
            kw.arg == "password"
            and isinstance(kw.value, ast.Name)
            and kw.value.id == secret
            for kw in call.keywords
        )
    ]
    creates = [
        call for call in creates if _app_active_call(index, path, function, call)
    ]
    if len(creates) != 1 or not _app_provider_unchanged(
        index, path, function, "django.contrib.auth.models.User"
    ):
        return None
    # The Basic header must descend from this same password binding.
    headers = [
        call
        for call in ast.walk(function)
        if isinstance(call, ast.Call)
        and _app_member_chain(call.func) == ["self", "client", "credentials"]
        and any(
            kw.arg == "HTTP_AUTHORIZATION"
            and _app_credential_lineage(index, path, function, kw.value, secret)
            for kw in call.keywords
        )
    ]
    requests = _app_client_requests(function, ["self", "client"])
    if len(headers) != 1 or not requests or creates[0].lineno >= headers[0].lineno:
        return None
    requests = [call for call in requests if call.lineno > headers[0].lineno]
    if not requests or not _app_active_call(index, path, function, headers[0]):
        return None
    if not _app_drf_same_credentials(function, creates[0], headers[0], secret):
        return None
    return {
        "profile": "DRF_TEST_USER_ENROLLMENT",
        "creation": creates[0],
        "request": requests[0],
        "header": headers[0],
    }


def _app_source_function(index, path, expression, function=None):
    canonical = _app_expression_name(index, path, expression, function)
    if canonical is None:
        return None
    module, _, name = canonical.rpartition(".")
    target, tree = _django_mod(index, module)
    if tree is None:
        return None
    from .credential_role_constructor_provider import binding_occurrences

    rows = binding_occurrences(tree.body, name)
    return (
        (target, rows[0])
        if len(rows) == 1 and isinstance(rows[0], ast.FunctionDef)
        else None
    )


def _app_fixture_provider(index, path, name):
    """Nearest fixture binding, with declared pytest-Flask plugin as API boundary."""
    declared = index["configuration_bytes"].get("requirements.txt", b"")
    if re.search(rb"(?m)^\s*pytest[-_]flask\s*(?:[<>=!~\[]|$)", declared) is None:
        return None
    cursor = Path(path).parent
    while cursor.is_relative_to(index["source"].root):
        provider = cursor / "conftest.py"
        tree = index["modules"].get(provider)
        if tree is not None:
            if not index["source"].validate(
                provider
            ) or "client" in fixture_bindings_for_source(tree):
                return None
            if any(
                isinstance(node, (ast.FunctionDef, ast.Assign))
                and (
                    getattr(node, "name", None) in {"client", "pytest_plugins"}
                    or any(
                        isinstance(t, ast.Name) and t.id in {"client", "pytest_plugins"}
                        for t in getattr(node, "targets", [])
                    )
                )
                for node in tree.body
            ):
                return None
            rows = [
                node
                for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == name
            ]
            if rows:
                if len(rows) != 1 or len(rows[0].decorator_list) != 1:
                    return None
                decorator = rows[0].decorator_list[0]
                expr = decorator.func if isinstance(decorator, ast.Call) else decorator
                if _app_expression_name(index, provider, expr) != "pytest.fixture":
                    return None
                return provider, rows[0]
        if cursor == index["source"].root:
            break
        cursor = cursor.parent
    return None


def _app_flask_datastore_factory(index, path, function):
    """Resolve the returned Flask app and the parameter installed in its store slot."""
    returns = [node for node in function.body if isinstance(node, ast.Return)]
    if len(returns) != 1 or not isinstance(returns[0].value, ast.Name):
        return None
    name = returns[0].value.id
    rows = _django_assignment(index["modules"][path], name)
    if len(rows) != 1 or not isinstance(rows[0][1], ast.Call):
        return None
    if _app_expression_name(index, path, rows[0][1].func) != "flask.Flask":
        return None
    stores = []
    for node in function.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        root, keys = _app_subscript_chain(node.targets[0])
        if _app_member_chain(root) == [name, "config"] and keys == ["DATASTORE"]:
            stores.append(node.value)
    if len(stores) != 1 or not isinstance(stores[0], ast.Name):
        return None
    parameters = [arg.arg for arg in [*function.args.posonlyargs, *function.args.args]]
    return parameters.index(stores[0].id) if stores[0].id in parameters else None


def _app_pytest_store_profile(index, path, function):
    if not any(arg.arg == "client" for arg in function.args.args):
        return None
    if "client" in fixture_bindings_for_source(index["modules"][path]):
        return None
    provider = _app_fixture_provider(index, path, "app")
    if provider is None:
        return None
    return _app_fixture_store_profile(index, *provider)


def _app_fixture_store_profile(index, fixture_path, fixture):
    yields = [
        node.value.value
        for node in fixture.body
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Yield)
    ]
    if len(yields) != 1 or not isinstance(yields[0], ast.Name):
        return None
    allocation = _app_local_assignment(fixture, yields[0].id)
    if allocation is None or not isinstance(allocation.value, ast.Call):
        return None
    factory = _app_source_function(index, fixture_path, allocation.value.func, fixture)
    if factory is None:
        return None
    position = _app_flask_datastore_factory(index, *factory)
    if position is None or len(allocation.value.args) <= position:
        return None
    selected_store = allocation.value.args[position]
    if not isinstance(selected_store, ast.Name):
        return None
    store = _app_local_assignment(fixture, selected_store.id)
    if store is None or not isinstance(store.value, ast.Call):
        return None
    canonical = _app_expression_name(index, fixture_path, store.value.func, fixture)
    module, _, cls_name = (canonical or "").rpartition(".")
    cls_path, tree = _django_mod(index, module)
    if tree is None or _django_class(index, cls_path, cls_name) is None:
        return None
    return {
        "profile": "PYTEST_FLASK_TEST_STORE_ENROLLMENT",
        "creation": store,
        "provider_path": index["source"].relative(fixture_path),
        "factory_path": index["source"].relative(factory[0]),
    }


def _app_pytest_store_enrollment(index, path, function, secret):
    profile = _app_pytest_store_profile(index, path, function)
    if profile is None:
        return None
    installs = []
    for statement in function.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        root, tail = _app_subscript_chain(statement.targets[0])
        # .data is a member between the app configuration and its nested store keys.
        if not isinstance(root, ast.Attribute) or root.attr != "data":
            continue
        app, prefix = _app_subscript_chain(root.value)
        if (
            _app_member_chain(app) == ["client", "application", "config"]
            and prefix == ["DATASTORE"]
            and tail == ["settings", "application", "password"]
            and _app_credential_lineage(index, path, function, statement.value, secret)
        ):
            installs.append(statement)
    requests = [
        call
        for call in _app_client_requests(function, ["client"])
        if _app_request_credential(index, path, function, call, secret)
        and _app_active_call(index, path, function, call)
    ]
    if len(installs) != 1 or not requests or installs[0].lineno >= requests[0].lineno:
        return None
    return {
        **profile,
        "enrollment": installs[0],
        "request": requests[0],
        "additional_requests": requests[1:],
    }


def _app_source_symbol(index, path, expression, function=None, seen=()):
    """Resolve captured imports/reexports to one exact module declaration."""
    canonical = _app_expression_name(index, path, expression, function)
    if canonical is None and isinstance(expression, ast.Name):
        from .credential_role_constructor_provider import binding_occurrences

        if function is not None and binding_occurrences(function.body, expression.id):
            return None
        canonical = _django_name(index, path) + "." + expression.id
    if not canonical or canonical in seen or len(seen) >= 12:
        return None
    module, _, name = canonical.rpartition(".")
    target, tree = _django_mod(index, module)
    if tree is None:
        return None
    from .credential_role_constructor_provider import binding_occurrences

    rows = binding_occurrences(tree.body, name)
    if len(rows) != 1:
        return None
    if isinstance(rows[0], (ast.Import, ast.ImportFrom)):
        return _app_source_symbol(
            index, target, ast.Name(id=name, ctx=ast.Load()), seen=(*seen, canonical)
        )
    binding = rows[0]
    if isinstance(binding, ast.Name):
        binding = index["source"].parents[target].get(id(binding))
    return target, binding


def _app_effective_method(chain, name, decorators=()):
    from .credential_role_constructor_provider import effective_method

    return effective_method(chain, name, allowed_decorators=decorators)


def _app_direct_field_assignment(function, field):
    rows = [
        node
        for node in function.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and _app_member_chain(node.targets[0]) == ["self", field]
    ]
    return rows[0] if len(rows) == 1 else None


def _app_flask_constructor(index, path, call, function=None):
    selected = _app_source_symbol(index, path, call.func, function)
    if selected is None:
        return None
    owner_path, owner = selected
    if isinstance(owner, ast.FunctionDef):
        returns = _app_direct_returns(index, owner_path, owner)
        if len(returns) != 1 or not isinstance(returns[0].value, ast.Name):
            return None
        allocation = _app_local_assignment(owner, returns[0].value.id)
        if allocation is None or not isinstance(allocation.value, ast.Call):
            return None
        selected = _app_source_symbol(index, owner_path, allocation.value.func, owner)
        if selected is None:
            return None
        owner_path, owner = selected
    if not isinstance(owner, ast.ClassDef):
        return None
    return (
        selected
        if _django_class_chain(index, owner_path, owner, "flask.Flask")
        else None
    )


def _app_unittest_profile(index, path, owner):
    if not isinstance(owner, ast.ClassDef):
        return None
    chain = _django_class_chain(index, path, owner, "unittest.TestCase")
    if chain is None:
        return None
    setup = _app_effective_method(chain, "setUp")
    if setup is None:
        return None
    setup_path, method = setup
    app = _app_direct_field_assignment(method, "app")
    client = _app_direct_field_assignment(method, "client")
    factory = _app_direct_field_assignment(method, "factory")
    if app is None or client is None or factory is None:
        return None
    if not all(isinstance(node.value, ast.Call) for node in (app, client, factory)):
        return None
    if _app_member_chain(client.value.func) != ["self", "app", "test_client"]:
        return None
    if _app_flask_constructor(index, setup_path, app.value, method) is None:
        return None
    selected = _app_source_symbol(index, setup_path, factory.value.func, method)
    if selected is None or not isinstance(selected[1], ast.ClassDef):
        return None
    return {
        "chain": chain,
        "setup": setup,
        "factory": selected,
        "client_creation": client,
    }


def _app_factory_return(index, path, owner, method):
    """Resolve source factory -> constructor field -> model construction return."""
    returns = _app_direct_returns(index, path, method)
    if len(returns) != 1 or not isinstance(returns[0].value, ast.Call):
        return None
    call = returns[0].value
    if not isinstance(call.func, ast.Attribute) or not isinstance(
        call.func.value, ast.Name
    ):
        return None
    selected = _app_source_symbol(index, path, call.func.value, method)
    if (
        selected is None
        or not isinstance(selected[1], ast.Assign)
        or not isinstance(selected[1].value, ast.Call)
    ):
        return None
    factory_path, declaration = selected
    creator = _app_source_symbol(index, factory_path, declaration.value.func)
    if creator is None or not isinstance(creator[1], ast.ClassDef) or creator[1].bases:
        return None
    chain = [(creator[0], creator[1].name, creator[1])]
    constructor = _app_effective_method(chain, "__init__")
    create = _app_effective_method(chain, call.func.attr)
    if constructor is None or create is None:
        return None
    row = _app_fresh_model_return(index, create[0], create[1])
    if row is None:
        return None
    model_field, allocation = row
    field = _app_direct_field_assignment(constructor[1], model_field)
    if field is None or not isinstance(field.value, ast.Name):
        return None
    params = [arg.arg for arg in constructor[1].args.args][1:]
    if field.value.id not in params:
        return None
    return _app_bound_model_argument(
        index, factory_path, declaration, params.index(field.value.id), allocation
    )


def _app_bound_model_argument(index, path, declaration, position, allocation):
    if len(declaration.value.args) <= position:
        return None
    model = _app_source_symbol(index, path, declaration.value.args[position])
    if model is None or not isinstance(model[1], ast.ClassDef):
        return None
    return {
        "model": model,
        "allocation": allocation,
        "factory_declaration": declaration,
    }


def _app_fresh_model_return(index, path, method):
    returns = _app_direct_returns(index, path, method)
    if len(returns) != 1 or not isinstance(returns[0].value, ast.Name):
        return None
    row = _app_local_assignment(method, returns[0].value.id)
    if row is None or not isinstance(row.value, ast.Call):
        return None
    chain = _app_member_chain(row.value.func)
    return (
        (chain[1], row.value)
        if chain and len(chain) == 2 and chain[0] == "self"
        else None
    )


def _app_factory_user(index, profile, expression, function, path):
    factory_path, owner = profile["factory"]
    parts = _app_member_chain(expression)
    if parts is None or len(parts) != 3 or parts[:2] != ["self", "factory"]:
        return None
    chain = [(factory_path, owner.name, owner)]
    if isinstance(expression.ctx, ast.Load):
        getter = _app_effective_method(chain, parts[2], ("property",))
        if getter is not None:
            return _app_lazy_user_return(index, factory_path, owner, getter[1])
    return None


def _app_lazy_user_return(index, path, owner, getter):
    returns = _app_direct_returns(index, path, getter)
    if len(returns) != 1:
        return None
    member = _app_member_chain(returns[0].value)
    if member is None or len(member) != 2 or member[0] != "self":
        return None
    chain = [(path, owner.name, owner)]
    constructor = _app_effective_method(chain, "__init__")
    initial = (
        _app_direct_field_assignment(constructor[1], member[1]) if constructor else None
    )
    if (
        initial is None
        or not isinstance(initial.value, ast.Constant)
        or initial.value.value is not None
    ):
        return None
    assignments = [
        node
        for node in ast.walk(getter)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and _app_member_chain(node.targets[0]) == member
    ]
    if len(assignments) != 1 or not isinstance(assignments[0].value, ast.Call):
        return None
    guards = [
        node
        for node in getter.body
        if isinstance(node, ast.If) and assignments[0] in node.body
    ]
    if len(guards) != 1 or not _app_none_guard(guards[0].test, member):
        return None
    selected = _app_member_chain(assignments[0].value.func)
    if selected is None or len(selected) != 2 or selected[0] != "self":
        return None
    creator = _app_effective_method(chain, selected[1])
    return _app_factory_return(index, path, owner, creator[1]) if creator else None


def _app_none_guard(node, member):
    return (
        isinstance(node, ast.Compare)
        and len(node.ops) == len(node.comparators) == 1
        and isinstance(node.ops[0], ast.Is)
        and _app_member_chain(node.left) == member
        and isinstance(node.comparators[0], ast.Constant)
        and node.comparators[0].value is None
    )


def _app_factory_call_user(index, profile, expression):
    if not isinstance(expression, ast.Call):
        return None
    parts = _app_member_chain(expression.func)
    if parts is None or len(parts) != 3 or parts[:2] != ["self", "factory"]:
        return None
    path, owner = profile["factory"]
    method = _app_effective_method([(path, owner.name, owner)], parts[2])
    return _app_factory_return(index, path, owner, method[1]) if method else None


def _app_wrapper_data_projection(index, path, method):
    from .credential_role_identity_effects import own_function_nodes

    parents = index["source"].parents[path]
    for node in own_function_nodes(method, path, index["source"]):
        if isinstance(node, ast.Name) and node.id == "data":
            parent = parents.get(id(node))
            if not _app_payload_name_use(index, path, method, node, parent):
                return False
        if isinstance(node, ast.Subscript) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            if isinstance(node.value, ast.Name) and node.value.id == "data":
                return False
    return True


def _app_payload_name_use(index, path, method, node, parent):
    if isinstance(node.ctx, (ast.Store, ast.Del)):
        return bool(
            isinstance(parent, ast.Assign)
            and len(parent.targets) == 1
            and _app_json_string_map(index, path, method, parent.value)
        )
    if isinstance(parent, ast.Assign):
        return False  # Unmodeled mutable aliases cannot retain a payload proof.
    if isinstance(parent, ast.Attribute):
        return False  # A dict method may mutate or leak the selected payload.
    if isinstance(parent, (ast.Call, ast.keyword)):
        call = (
            parent
            if isinstance(parent, ast.Call)
            else index["source"].parents[path].get(id(parent))
        )
        return bool(
            isinstance(call, ast.Call)
            and (
                _app_wrapper_dispatch(index, path, method, call)
                or _app_json_string_map(index, path, method, call)
            )
        )
    return True


def _app_wrapper_dispatch(index, path, method, call):
    chain = _app_member_chain(call.func)
    if chain and chain[:2] == ["self", "client"] and len(chain) == 3:
        return chain[2] in {"post", "put", "patch"}
    if not isinstance(call.func, ast.Name):
        return False
    row = _app_local_assignment(method, call.func.id)
    return bool(
        row
        and isinstance(row.value, ast.Call)
        and isinstance(row.value.func, ast.Name)
        and row.value.func.id == "getattr"
        and row.value.args
        and _app_member_chain(row.value.args[0]) == ["self", "client"]
    )


def _app_json_string_map(index, path, wrapper, call):
    if not (
        isinstance(call, ast.Call)
        and len(call.args) == 1
        and not call.keywords
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == "data"
    ):
        return False
    selected = _app_source_function(index, path, call.func, wrapper)
    if selected is None:
        return False
    helper_path, helper = selected
    if not _app_provider_unchanged(
        index, helper_path, index["modules"][helper_path], "json.dumps"
    ):
        return False
    returns = _app_direct_returns(index, helper_path, helper)
    if len(helper.args.args) != 1 or len(returns) != 1:
        return False
    parameter = helper.args.args[0].arg
    expression = returns[0].value
    if (
        not isinstance(expression, ast.Call)
        or _app_expression_name(index, helper_path, expression.func, helper)
        != "json.dumps"
    ):
        return False
    if not expression.args or not _app_json_normalizer(
        index, helper_path, helper, expression.args[0], parameter
    ):
        return False
    return all(
        _app_json_helper_statement(index, helper_path, helper, node)
        for node in helper.body
        if node is not returns[0]
    )


def _app_json_helper_statement(index, path, function, statement):
    if (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    ):
        return True
    call = statement.value if isinstance(statement, ast.Expr) else None
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and _app_member_chain(call.func.value)
        == [function.args.kwarg.arg if function.args.kwarg else None]
        and call.func.attr == "setdefault"
        and len(call.args) == 2
        and not call.keywords
        and isinstance(call.args[0], ast.Constant)
    ):
        return False
    if call.args[0].value in {"allow_nan", "ensure_ascii"}:
        return (
            isinstance(call.args[1], ast.Constant) and type(call.args[1].value) is bool
        )
    if call.args[0].value != "cls":
        return False
    selected = _app_source_symbol(index, path, call.args[1], function)
    return selected is not None and _app_default_only_json_encoder(index, *selected)


def _app_default_only_json_encoder(index, path, owner):
    if (
        not isinstance(owner, ast.ClassDef)
        or owner.decorator_list
        or owner.keywords
        or len(owner.bases) != 1
    ):
        return False
    if _app_expression_name(index, path, owner.bases[0]) != "json.JSONEncoder":
        return False
    body = [
        node
        for node in owner.body
        if not (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        )
    ]
    return all(
        isinstance(node, ast.FunctionDef)
        and not node.decorator_list
        and (
            node.name == "default"
            or node.name == "__init__"
            and _app_json_encoder_init(node)
        )
        for node in body
    )


def _app_json_encoder_init(function):
    """Custom default handlers may register codecs without changing base encoding."""
    if function.args.kwarg is None:
        return False
    kwargs = function.args.kwarg.arg
    from .credential_role_constructor_provider import binding_occurrences

    if binding_occurrences(function.body, kwargs):
        return False
    forwards = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "__init__"
        and isinstance(node.func.value, ast.Call)
        and isinstance(node.func.value.func, ast.Name)
        and node.func.value.func.id == "super"
    ]
    if len(forwards) != 1:
        return False
    forward = forwards[0]
    if (
        forward.args
        or len(forward.keywords) != 1
        or forward.keywords[0].arg is not None
    ):
        return False
    if (
        not isinstance(forward.keywords[0].value, ast.Name)
        or forward.keywords[0].value.id != kwargs
    ):
        return False
    return _app_json_initializer_fields(function, forward.func.value)


def _app_json_initializer_fields(function, super_call):
    protected = {
        "encode",
        "iterencode",
        "__dict__",
        "__class__",
        "skipkeys",
        "sort_keys",
        "ensure_ascii",
        "allow_nan",
        "item_separator",
        "key_separator",
        "check_circular",
    }
    for node in ast.walk(function):
        if isinstance(node, ast.Attribute) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            if _app_member_chain(node.value) == ["self"] and node.attr in protected:
                return False
        if isinstance(node, ast.Call) and node is not super_call:
            if any(isinstance(arg, ast.Name) and arg.id == "self" for arg in node.args):
                return False
    return True


def _app_type_guard(expression, parameter, types):
    if isinstance(expression, ast.BoolOp) and isinstance(expression.op, ast.And):
        expression = expression.values[0]
    return (
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Name)
        and expression.func.id == "isinstance"
        and len(expression.args) == 2
        and isinstance(expression.args[0], ast.Name)
        and expression.args[0].id == parameter
        and isinstance(expression.args[1], ast.Name)
        and expression.args[1].id in types
    )


def _app_json_normalizer(index, path, function, node, parameter):
    if isinstance(node, ast.Name) and node.id == parameter:
        return True
    if (
        not isinstance(node, ast.Call)
        or len(node.args) != 1
        or not isinstance(node.args[0], ast.Name)
        or node.args[0].id != parameter
    ):
        return False
    selected = _app_source_symbol(index, path, node.func, function)
    if selected is None or not isinstance(selected[1], ast.FunctionDef):
        return False
    helper = selected[1]
    if len(helper.args.args) != 1 or len(helper.body) < 2:
        return False
    name = helper.args.args[0].arg
    first, last = helper.body[0], helper.body[-1]
    if not (
        isinstance(first, ast.If)
        and not first.orelse
        and _app_type_guard(first.test, name, {"dict"})
        and isinstance(last, ast.Return)
        and isinstance(last.value, ast.Name)
        and last.value.id == name
    ):
        return False
    if not all(
        isinstance(item, ast.If)
        and not item.orelse
        and _app_type_guard(item.test, name, {"list", "float"})
        for item in helper.body[1:-1]
    ):
        return False
    return _app_recursive_string_map(first.body, helper, name)


def _app_recursive_string_map(body, function, parameter):
    if (
        len(body) != 1
        or not isinstance(body[0], ast.Return)
        or not isinstance(body[0].value, ast.DictComp)
    ):
        return False
    comp = body[0].value
    if len(comp.generators) != 1:
        return False
    generator = comp.generators[0]
    if (
        not isinstance(generator.target, ast.Tuple)
        or len(generator.target.elts) != 2
        or generator.ifs
        or generator.is_async
    ):
        return False
    if not all(isinstance(part, ast.Name) for part in generator.target.elts):
        return False
    key, value = [part.id for part in generator.target.elts]
    return (
        isinstance(comp.key, ast.Name)
        and comp.key.id == key
        and isinstance(generator.iter, ast.Call)
        and not generator.iter.args
        and not generator.iter.keywords
        and _app_member_chain(generator.iter.func) == [parameter, "items"]
        and isinstance(comp.value, ast.Call)
        and isinstance(comp.value.func, ast.Name)
        and comp.value.func.id == function.name
        and len(comp.value.args) == 1
        and not comp.value.keywords
        and isinstance(comp.value.args[0], ast.Name)
        and comp.value.args[0].id == value
    )


def _app_request_wrapper(index, profile, call):
    chain = _app_member_chain(call.func)
    if chain is None or len(chain) != 2 or chain[0] != "self":
        return None
    selected = _app_effective_method(profile["chain"], chain[1])
    if selected is None:
        return None
    path, method = selected
    if not _app_wrapper_data_projection(index, path, method):
        return None
    direct = [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and _app_member_chain(node.func) == ["self", "client", "post"]
        and any(
            kw.arg == "data"
            and isinstance(kw.value, ast.Name)
            and kw.value.id == "data"
            for kw in node.keywords
        )
    ]
    if len(direct) == 1:
        return direct[0] if _app_active_call(index, path, method, direct[0]) else None
    # The dynamic method selector is still bound to this same captured client.
    selectors = [
        node
        for node in method.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "getattr"
        and len(node.value.args) == 2
        and _app_member_chain(node.value.args[0]) == ["self", "client"]
    ]
    if len(selectors) != 1:
        return None
    name = selectors[0].targets[0].id
    calls = [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == name
        and any(
            kw.arg == "data"
            and isinstance(kw.value, ast.Name)
            and kw.value.id == "data"
            for kw in node.keywords
        )
    ]
    return (
        calls[0]
        if len(calls) == 1 and _app_active_call(index, path, method, calls[0])
        else None
    )


def _app_password_operation(index, model, method_name, kind):
    path, owner = model
    selected = _app_password_method(index, model, method_name)
    if selected is None:
        return None
    function = selected[1]
    params = [arg.arg for arg in function.args.args][1:]
    if len(params) != 1 or len(function.body) != 1:
        return None
    statement = function.body[0]
    if kind == "hash":
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            return None
        member, call = _app_member_chain(statement.targets[0]), statement.value
    else:
        if not isinstance(statement, ast.Return) or not isinstance(
            statement.value, ast.BoolOp
        ):
            return None
        if (
            not isinstance(statement.value.op, ast.And)
            or len(statement.value.values) != 2
        ):
            return None
        member = _app_member_chain(statement.value.values[0])
        call = statement.value.values[1]
    return _app_password_call_field(
        index, path, function, member, call, params[0], kind
    )


def _app_password_method(index, model, method_name):
    path, owner = model
    return _app_effective_method([(path, owner.name, owner)], method_name)


def _app_password_call_field(index, path, function, member, call, parameter, kind):
    if (
        not member
        or len(member) != 2
        or member[0] != "self"
        or not isinstance(call, ast.Call)
    ):
        return None
    if (
        _app_expression_name(index, path, call.func, function)
        != "passlib.apps.custom_app_context." + kind
    ):
        return None
    if (
        not call.args
        or not isinstance(call.args[0], ast.Name)
        or call.args[0].id != parameter
    ):
        return None
    if kind == "verify" and (
        len(call.args) != 2 or _app_member_chain(call.args[1]) != member
    ):
        return None
    return member[1]


def _app_selected_user(index, path, function, expression, owner, model):
    if _app_member_chain(expression) == owner:
        return True
    if not isinstance(expression, ast.Name):
        return False
    row = _app_local_assignment(function, expression.id)
    if row is None or not isinstance(row.value, ast.Call):
        return False
    call = row.value
    if not (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "get"
        and isinstance(call.func.value, ast.Attribute)
        and call.func.value.attr == "query"
        and len(call.args) == 1
        and not call.keywords
        and _app_member_chain(call.args[0]) == [*owner, "id"]
    ):
        return False
    return _app_source_symbol(index, path, call.func.value.value, function) == model


def _app_credential_operations(index, path, function, model, owner, request):
    installed, verified = [], []
    for node in ast.walk(function):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if len(node.args) != 1 or not isinstance(node.args[0], ast.Name):
            continue
        if not _app_selected_user(index, path, function, node.func.value, owner, model):
            continue
        if node.lineno < request.lineno and _app_password_operation(
            index, model, node.func.attr, "hash"
        ):
            installed.append(node)
        if node.lineno > request.lineno and _app_password_operation(
            index, model, node.func.attr, "verify"
        ):
            verified.append(node)
    return installed, verified


def _app_user_credential_witness(index, path, function, profile, request, secret):
    owner = ["self", "factory", "user"]
    if not any(
        _app_exact_formatted_member(arg, [*owner, "id"]) for arg in request.args
    ):
        return None
    user = _app_factory_user(
        index, profile, ast.parse("self.factory.user", mode="eval").body, function, path
    )
    if user is None:
        return None
    installed, verified = _app_credential_operations(
        index, path, function, user["model"], owner, request
    )
    if len(installed) != 1 or not verified:
        return None
    data = next((kw.value for kw in request.keywords if kw.arg == "data"), None)
    if not isinstance(data, ast.Dict):
        return None
    values = {
        key.value: value
        for key, value in zip(data.keys, data.values)
        if isinstance(key, ast.Constant)
    }
    old, new = values.get("old_password"), values.get("password")
    if (
        not isinstance(old, ast.Name)
        or old.id != installed[0].args[0].id
        or not isinstance(new, ast.Name)
    ):
        return None
    if not any(node.args[0].id == new.id for node in verified) or secret not in {
        old.id,
        new.id,
    }:
        return None
    return {
        "creation": user["allocation"],
        "enrollment": installed[0],
        "request": request,
        "verified_password_calls": [
            node for node in verified if _app_active_call(index, path, function, node)
        ],
        "verified_password_implementations": [
            _app_password_method(index, user["model"], node.func.attr)
            for node in verified
            if _app_active_call(index, path, function, node)
        ],
    }


def _app_invitation_credential_witness(index, path, function, profile, request, secret):
    verifies = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == secret
        and node.lineno > request.lineno
    ]
    for verify in verifies:
        # A postcondition may re-query the same ID; construction before request owns it.
        assignments = [
            node
            for node in function.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == verify.func.value.id
            and node.lineno < request.lineno
        ]
        if len(assignments) != 1:
            continue
        user = _app_factory_call_user(index, profile, assignments[0].value)
        if user is None or not _app_password_operation(
            index, user["model"], verify.func.attr, "verify"
        ):
            continue
        tokens = _app_invitation_tokens(
            index, path, function, verify.func.value.id, request
        )
        if tokens:
            return {
                "creation": user["allocation"],
                "enrollment": request,
                "request": request,
                "token": tokens[0],
                "verified_password_calls": [verify],
                "verified_password_implementations": [
                    _app_password_method(index, user["model"], verify.func.attr)
                ],
            }
    return None


def _app_invitation_tokens(index, path, function, user, request):
    results = []
    for statement in function.body:
        if (
            not isinstance(statement, ast.Assign)
            or len(statement.targets) != 1
            or not isinstance(statement.targets[0], ast.Name)
        ):
            continue
        call = statement.value
        if (
            not isinstance(call, ast.Call)
            or len(call.args) != 1
            or not isinstance(call.args[0], ast.Name)
            or call.args[0].id != user
        ):
            continue
        selected = _app_source_function(index, path, call.func, function)
        if selected is None or not request.args:
            continue
        body = selected[1]
        if not _app_signed_user_id(index, selected[0], body):
            continue
        if any(
            _app_exact_formatted_member(arg, [statement.targets[0].id])
            for arg in request.args
        ):
            results.append(statement)
    return results


def _app_unittest_witness(witness):
    return {
        "profile": (
            "UNITTEST_FACTORY_INVITATION_ENROLLMENT"
            if "token" in witness
            else "UNITTEST_FACTORY_USER_ENROLLMENT"
        ),
        **witness,
    }


def _app_unittest_enrollment(index, path, function, owner, secret):
    profile = _app_unittest_profile(index, path, owner)
    if profile is None:
        return None
    calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and _app_request_credential(index, path, function, node, secret)
    ]
    for call in calls:
        if _app_request_wrapper(index, profile, call) is None:
            continue
        witness = _app_user_credential_witness(
            index, path, function, profile, call, secret
        ) or _app_invitation_credential_witness(
            index, path, function, profile, call, secret
        )
        if witness is not None:
            return _app_unittest_witness(witness)
    # An old-password input is paired with the same owned user's new password.
    for call in ast.walk(function):
        if (
            not isinstance(call, ast.Call)
            or _app_request_wrapper(index, profile, call) is None
        ):
            continue
        witness = _app_user_credential_witness(
            index, path, function, profile, call, secret
        )
        if witness is not None:
            return _app_unittest_witness(witness)
    return None


def application_test_secret_evidence(index, path, line, value):
    """Project a local test credential's captured creation and request witnesses."""
    if index is None:
        return _django_unknown("captured application source index is unavailable")
    candidate, reason = _django_candidate_binding(index, path, line, value)
    if candidate is None:
        return _django_unknown(reason)
    literal, assignment, secret = candidate
    from .credential_role_identity_effects import module_fixture_evidence_for_binding

    result = module_fixture_evidence_for_binding(index, path, assignment, secret)
    if result is not None:
        return result
    return _application_test_secret_from_local_binding(
        index, path, literal, assignment, secret
    )


def _application_test_secret_from_local_binding(
    index, path, literal, assignment, secret
):
    parents = index["source"].parents[path]
    function = parents.get(id(assignment))
    if (
        not isinstance(function, ast.FunctionDef)
        or not function.name.startswith("test_")
        or function.decorator_list
    ):
        return _django_unknown("literal is not a direct test-function declaration")
    if _app_local_assignment(function, secret) is not assignment:
        return _django_unknown("credential is rebound or not a unique local binding")
    owner = parents.get(id(function))
    witness = (
        _app_drf_enrollment(index, path, function, owner, secret)
        or _app_pytest_store_enrollment(index, path, function, secret)
        or _app_unittest_enrollment(index, path, function, owner, secret)
    )
    if witness is None:
        return _django_unknown(
            "captured framework authority creation and same-client exercise are unresolved"
        )
    return _application_test_secret_witness(
        index, path, literal, assignment, function, secret, witness
    )


def _application_test_secret_witness(
    index, path, literal, assignment, function, secret, witness
):
    use_closure = _app_closed_consumer_uses(
        index, path, function, secret, literal.value, witness
    )
    if use_closure is None:
        return _django_unknown(
            "credential has an unresolved, unbound, or credential-shaped use"
        )
    if not all(
        _app_active_call(index, path, function, witness[key])
        for key in ("enrollment", "request", "header", "token")
        if key in witness
    ):
        return _django_unknown(
            "selected enrollment or exercise is not on a supported active statement path"
        )
    if not _app_capability_interval(
        index, path, function, witness["request"].lineno
    ) or not _app_provider_scopes_clear(index, path, function):
        return _django_unknown(
            "selected client, authority or encoder capability was replaced or escaped"
        )
    return {
        "eligible": True,
        "classification": "APPLICATION_TEST_CREDENTIAL_ROLE",
        "source": index["source"].relative(path),
        "source_sha256": hashlib.sha256(index["source"].source_bytes[path]).hexdigest(),
        "declaration_span": _evidence_node_span(assignment),
        "profile": witness["profile"],
        "witness_spans": {
            key: _evidence_node_span(node)
            for key, node in witness.items()
            if isinstance(node, ast.AST)
        },
        "runtime_assurance": "INCOMPLETE",
        "transport_role": "UNASSESSED",
        "target_execution": "not_performed",
        "isolation_assurance": "UNASSESSED",
        "witness_sources": _app_witness_sources(index, witness),
        "consumer_use_closure": use_closure,
    }


def _app_witness_sources(index, witness):
    result = {}
    for key, node in witness.items():
        if not isinstance(node, ast.AST):
            continue
        paths = [
            path
            for path, parents in index["source"].parents.items()
            if id(node) in parents
        ]
        if len(paths) != 1:
            return {}
        path = paths[0]
        result[key] = {
            "path": index["source"].relative(path),
            "sha256": index["source"].inventory[path],
            "span": _evidence_node_span(node),
        }
    return result


def _app_known_credential_cache_dependencies():
    from .intent_quality import _looks_like_known_credential as looks
    from .credential_role_identity_effects import module_fixture_helper_epoch as epoch

    return looks, _APP_SECRET_INVENTORY_CACHE_TOKEN, *epoch()


class _AppSecretInventoryCacheToken:
    """Expose the live immutable token inventory identity to the native cache epoch."""

    __name__ = "_APP_SECRET_INVENTORY_CACHE_TOKEN"

    @property
    def __code__(self):
        from .context_efficiency import _SECRET_BYTES

        return _SECRET_BYTES

    def __call__(self):
        return self.__code__


_APP_SECRET_INVENTORY_CACHE_TOKEN = _AppSecretInventoryCacheToken()


CACHE_HELPERS = (
    tuple(
        value
        for name, value in sorted(globals().items())
        if callable(value) and getattr(value, "__module__", None) == __name__
    )
    + _app_known_credential_cache_dependencies()
)
