"""Pytest collection configuration and source-bound collection-hook admission."""

from __future__ import annotations

import configparser
import hashlib
import re
import shlex
from contextlib import contextmanager
from contextvars import ContextVar
from fnmatch import fnmatchcase

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

_ADVISORY_COLLECTION = ContextVar("advisory_pytest_collection", default=False)


@contextmanager
def advisory_collection_context(enabled=True):
    """Let repository scans retain static results when collection is unknown."""
    token = _ADVISORY_COLLECTION.set(enabled is True)
    try:
        yield
    finally:
        _ADVISORY_COLLECTION.reset(token)


def _pytest_collection_settings(value=None):
    """Normalize captured pytest file, function, and class patterns."""
    from .review_audits import (
        _TEST_CLASS_PATTERNS,
        _TEST_FILE_PATTERNS,
        _TEST_FUNCTION_PATTERNS,
    )

    if isinstance(value, dict):
        return {
            "python_files": list(value.get("python_files", _TEST_FILE_PATTERNS)),
            "python_functions": list(
                value.get("python_functions", _TEST_FUNCTION_PATTERNS)
            ),
            "python_classes": list(value.get("python_classes", _TEST_CLASS_PATTERNS)),
        }
    files = (
        sorted(value)
        if isinstance(value, (set, frozenset))
        else list(_pytest_pattern_list(value))
        if value is not None
        else list(_TEST_FILE_PATTERNS)
    )
    return {
        "python_files": files,
        "python_functions": list(_TEST_FUNCTION_PATTERNS),
        "python_classes": list(_TEST_CLASS_PATTERNS),
    }


def _pytest_name_matches(name, patterns):
    """Apply pytest's prefix-or-glob rule used for function and class names."""
    return any(
        name.startswith(pattern)
        or (any(marker in pattern for marker in "*?[") and fnmatchcase(name, pattern))
        for pattern in patterns
    )


def _pytest_file_matches(relative, patterns):
    """Match basename globs and slash-containing globs against full paths."""
    from .review_audits import (
        Path,
    )

    path = Path(relative)
    normalized = path.as_posix()
    return any(
        fnmatchcase(normalized, pattern.replace("\\", "/"))
        if "/" in pattern or "\\" in pattern
        else fnmatchcase(path.name, pattern)
        for pattern in patterns
    )


def _pytest_test_disabled(node, parents, nodes):
    """Honor statically false module/class/function __test__ markers."""
    from .review_audits import (
        ast,
    )

    scopes = [
        nodes[0],
        *(
            parent
            for parent, _child in parents.get(id(node), ())
            if isinstance(parent, ast.ClassDef)
        ),
    ]
    return any(_pytest_scope_test_disabled(scope) for scope in scopes) or any(
        _pytest_function_test_disabled(statement, node.name)
        for scope in scopes
        for statement in getattr(scope, "body", ())
    )


def _pytest_scope_test_disabled(scope):
    from .review_audits import (
        ast,
    )

    for statement in getattr(scope, "body", ()):
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
            if isinstance(statement, ast.AnnAssign)
            else []
        )
        value = getattr(statement, "value", None)
        if (
            isinstance(value, ast.Constant)
            and value.value is False
            and any(
                isinstance(target, ast.Name) and target.id == "__test__"
                for target in targets
            )
        ):
            return True
    return False


def _pytest_function_test_disabled(statement, function_name):
    from .review_audits import (
        ast,
    )

    if not isinstance(statement, ast.Assign) or not (
        isinstance(statement.value, ast.Constant) and statement.value.value is False
    ):
        return False
    return any(
        isinstance(target, ast.Attribute)
        and target.attr == "__test__"
        and isinstance(target.value, ast.Name)
        and target.value.id == function_name
        for target in statement.targets
    )


def _pytest_collection_config(root, source_files=None, *, allow_unknown=False):
    """Read pytest selected root config; malformed config is incomplete."""
    from .review_audits import (
        ReviewAuditError,
        _TEST_CLASS_PATTERNS,
        _TEST_FILE_PATTERNS,
        _TEST_FUNCTION_PATTERNS,
    )

    allow_unknown = allow_unknown or _ADVISORY_COLLECTION.get()
    defaults = set(_TEST_FILE_PATTERNS)
    candidates = (
        ("pytest.toml", "toml-pytest"),
        (".pytest.toml", "toml-pytest"),
        ("pytest.ini", "pytest"),
        (".pytest.ini", "pytest"),
        ("pyproject.toml", "pyproject"),
        ("tox.ini", "pytest"),
        ("setup.cfg", "tool:pytest"),
    )
    for relative, section in candidates:
        result = _pytest_config_file(root, relative, section, defaults)
        if result is not None and result[1].get("state") != "absent-section":
            unmodeled = result[1].get("state") == "unmodeled-builtin-collection"
            if result[1].get("state") in {
                "invalid",
                "oversized",
                "unreadable",
            } or (
                (unmodeled or result[1].get("state") == "unsupported")
                and not allow_unknown
            ):
                raise ReviewAuditError(
                    f"Cannot determine pytest test collection from {relative}: "
                    f"{'unsupported' if unmodeled else result[1]['state']} configuration."
                )
            patterns, identity = result
            identity = _pytest_collection_source_identity(
                root, identity, source_files, allow_unknown=allow_unknown
            )
            if identity.get("collection_state") == "UNKNOWN":
                patterns = set()
            return patterns, identity
    patterns, identity = (
        defaults,
        {
            "path": None,
            "state": "missing",
            "python_files": sorted(defaults),
            "python_functions": list(_TEST_FUNCTION_PATTERNS),
            "python_classes": list(_TEST_CLASS_PATTERNS),
        },
    )
    identity = _pytest_collection_source_identity(
        root, identity, source_files, allow_unknown=allow_unknown
    )
    return (
        set() if identity.get("collection_state") == "UNKNOWN" else patterns
    ), identity


def _pytest_collection_source_identity(
    root, identity, source_files=None, *, allow_unknown=False
):
    """Bind project-local collection hooks; reject them unless explicitly unknown."""
    from .review_audits import (
        ReviewAuditError,
        RuntimeAuditError,
        MAX_BYTES,
        _security_source_bytes,
        _security_source_files,
        ast,
        sha256,
    )

    sources = []
    hooks = []
    settings = _pytest_collection_settings(identity)
    files = _security_source_files(root) if source_files is None else source_files
    for path in files:
        relative = path.relative_to(root).as_posix()
        is_conftest = path.name == "conftest.py"
        is_test_module = _pytest_file_matches(relative, settings["python_files"])
        if not is_conftest and not is_test_module:
            continue
        try:
            data = _security_source_bytes(root, relative)
            if len(data) > MAX_BYTES:
                raise OSError("oversized hook source")
            tree = ast.parse(data, filename=relative)
        except (
            SyntaxError,
            OSError,
            UnicodeError,
            RuntimeAuditError,
            RecursionError,
        ) as exc:
            syntax_error = isinstance(exc, SyntaxError)
            if syntax_error and allow_unknown:
                hooks.append(
                    {
                        "path": relative,
                        "sha256": sha256(data).hexdigest(),
                        "bytes": len(data),
                        "names": [],
                        "pytest_plugins": False,
                        "state": "unparseable_source",
                    }
                )
                continue
            if is_conftest or (allow_unknown and not syntax_error):
                raise ReviewAuditError(
                    f"Cannot determine pytest test collection from {relative}: "
                    "unreadable or invalid hook source."
                )
            continue
        found = _pytest_collection_hook_names(tree, is_conftest, is_test_module)
        plugin_assignment = (is_conftest or is_test_module) and any(
            _pytest_plugin_declaration_active(node) for node in tree.body
        )
        hooks.extend(
            [
                {
                    "path": relative,
                    "sha256": sha256(data).hexdigest(),
                    "bytes": len(data),
                    "names": sorted(set(found)),
                    "pytest_plugins": plugin_assignment,
                }
            ]
            if found or plugin_assignment
            else []
        )
        sources.extend(
            [
                {
                    "path": relative,
                    "sha256": sha256(data).hexdigest(),
                    "bytes": len(data),
                }
            ]
            if is_conftest
            else []
        )
    if hooks and not allow_unknown:
        raise ReviewAuditError(
            "Cannot determine pytest test collection: custom collection hooks "
            "or pytest plugins are unsupported."
        )
    unmodeled = identity.get("state") in {"unmodeled-builtin-collection", "unsupported"}
    unknown = bool(hooks or unmodeled)
    reason = {
        "unmodeled-builtin-collection": "unmodeled_builtin_collection_options",
        "unsupported": "unsupported_collection_configuration",
    }.get(
        identity.get("state"),
        "unparseable_collection_source"
        if any(hook.get("state") == "unparseable_source" for hook in hooks)
        else "custom_collection_hooks_or_pytest_plugins",
    )
    return {
        **identity,
        **(
            {
                "state": "unsupported",
                "collection_state": "UNKNOWN",
                "mode": {
                    True: "static_without_collection",
                    False: "security_only",
                }[bool(_ADVISORY_COLLECTION.get())],
                "reason": reason,
                "python_files": [],
                "python_functions": [],
                "python_classes": [],
                "collection_hook_sources": hooks,
            }
            if unknown
            else {}
        ),
        "conftest_sources": sources,
    }


def _pytest_collection_hook_names(tree, is_conftest, is_test_module):
    from .review_audits import ast, _FUNCTION_NODES, _PYTEST_COLLECTION_HOOKS

    found = []
    for node in ast.walk(tree):
        if not isinstance(node, _FUNCTION_NODES):
            continue
        if (is_conftest and node.name in _PYTEST_COLLECTION_HOOKS) or (
            is_test_module and node.name == "pytest_generate_tests"
        ):
            found.append(node.name)
    return found


def _pytest_plugin_declaration_active(node):
    from .review_audits import (
        ast,
    )

    if not isinstance(node, (ast.Assign, ast.AnnAssign)):
        return False
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    if not any(
        isinstance(target, ast.Name) and target.id == "pytest_plugins"
        for target in targets
    ):
        return False
    try:
        value = ast.literal_eval(node.value)
    except (ValueError, TypeError):
        return True
    return not (type(value) in {list, tuple} and len(value) == 0)


def _pytest_config_file(root, relative, section, defaults):
    from .review_audits import (
        MAX_BYTES,
        RuntimeAuditError,
        local_file,
    )

    try:
        path = local_file(root, relative)
        size = path.stat().st_size
        if size > MAX_BYTES:
            return set(), {"path": relative, "state": "oversized", "bytes": size}
        data = path.read_bytes()
    except RuntimeAuditError as exc:
        if exc.code == "E_SOURCE_MISSING":
            return None
        return set(), {"path": relative, "state": "unreadable"}
    except OSError:
        return set(), {"path": relative, "state": "unreadable"}
    return _pytest_config_data(data, relative, section, defaults)


def _pytest_config_data(data, relative, section, defaults):
    from .review_audits import (
        MAX_BYTES,
        _TEST_CLASS_PATTERNS,
        _TEST_FUNCTION_PATTERNS,
        sha256,
    )

    identity = {
        "path": relative,
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
        "state": "read",
    }
    if len(data) > MAX_BYTES:
        return set(), {**identity, "state": "oversized"}
    try:
        text = data.decode("utf-8")
        configured = _pytest_pattern_value(text, section)
    except (UnicodeError, ValueError, configparser.Error):
        return set(), {**identity, "state": "invalid"}
    if configured is _INVALID_PYTEST_CONFIG:
        return set(), {**identity, "state": "invalid"}
    if configured is _UNSUPPORTED_PYTEST_CONFIG:
        return defaults, {**identity, "state": "unsupported"}
    if configured is _UNMODELED_BUILTIN_COLLECTION:
        return defaults, {**identity, "state": "unmodeled-builtin-collection"}
    if configured is _ABSENT_PYTEST_SECTION:
        if relative in {"pytest.toml", ".pytest.toml", "pytest.ini", ".pytest.ini"}:
            identity.update(
                {
                    "python_files": sorted(defaults),
                    "python_functions": list(_TEST_FUNCTION_PATTERNS),
                    "python_classes": list(_TEST_CLASS_PATTERNS),
                }
            )
            return defaults, identity
        return defaults, {**identity, "state": "absent-section"}
    settings = (
        configured
        if configured is not None
        else {
            "python_files": sorted(defaults),
            "python_functions": list(_TEST_FUNCTION_PATTERNS),
            "python_classes": list(_TEST_CLASS_PATTERNS),
        }
    )
    return set(settings["python_files"]), {**identity, **settings}


def _pytest_pattern_value(text, section):
    options = _pytest_configuration_options(text, section)
    if not isinstance(options, dict):
        return options
    if not _supported_pytest_function_patterns(options):
        return _INVALID_PYTEST_CONFIG
    if _pytest_config_uses_custom_collection(options):
        return _pytest_custom_collection_state(options)
    return _pytest_patterns_from_options(options)


def _pytest_configuration_options(text, section):
    """Use the same raw option parser for collection and captured authority roles."""
    if section in {"pyproject", "toml-pytest"}:
        document = tomllib.loads(text)
        options = (
            document.get("pytest")
            if section == "toml-pytest"
            else document.get("tool", {}).get("pytest")
        )
        if options is None:
            return _ABSENT_PYTEST_SECTION
        if not isinstance(options, dict):
            return _INVALID_PYTEST_CONFIG
        options = options.get("ini_options", options)
        return options if isinstance(options, dict) else _INVALID_PYTEST_CONFIG
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read_string(text)
    if section not in parser:
        return _ABSENT_PYTEST_SECTION
    parser.defaults().clear()
    return dict(parser.items(section))


def _toml_pytest_pattern_value(text, section):
    return _pytest_pattern_value(text, section)


def captured_pytest_configuration(captured):
    """Select captured root configuration with collection's exact precedence."""
    from .review_audits import _TEST_FILE_PATTERNS

    if not isinstance(captured, dict):
        return None
    for name, section in (
        ("pytest.toml", "toml-pytest"),
        (".pytest.toml", "toml-pytest"),
        ("pytest.ini", "pytest"),
        (".pytest.ini", "pytest"),
        ("pyproject.toml", "pyproject"),
        ("tox.ini", "pytest"),
        ("setup.cfg", "tool:pytest"),
    ):
        if name not in captured:
            continue
        raw = captured[name]
        if not isinstance(raw, bytes):
            return None
        _files, identity = _pytest_config_data(
            raw, name, section, set(_TEST_FILE_PATTERNS)
        )
        if identity["state"] == "absent-section":
            continue
        if identity["state"] != "read":
            return None
        try:
            options = _pytest_configuration_options(raw.decode("utf-8"), section)
        except (UnicodeError, ValueError, configparser.Error):
            return None
        if options is _ABSENT_PYTEST_SECTION:
            options = {}
        effective = _pytest_effective_settings_options(options)
        if effective is None:
            return None
        return {"identity": identity, "options": effective}
    return None


def _pytest_settings_selection_overridden(options):
    """Do not credit a config default when captured argv selects another source."""
    return _pytest_effective_settings_options(options) is None


def _pytest_effective_settings_options(options):
    """Apply exact captured --ds selection; other source overrides stay unknown."""
    if not isinstance(options, dict):
        return None
    value = options.get("addopts", "")
    try:
        tokens = shlex.split(value) if isinstance(value, str) else value
    except ValueError:
        return None
    if not isinstance(tokens, list) or not all(isinstance(t, str) for t in tokens):
        return None
    if any(
        token == "--"
        or token.startswith("--ds")
        and token != "--ds"
        and not token.startswith("--ds=")
        or token.split("=", 1)[0]
        in {"--dc", "--rootdir", "-c", "--config-file", "-o", "--override-ini"}
        or token.startswith(("-c", "-o"))
        for token in tokens
    ):
        return None
    effective = dict(options)
    arguments = iter(tokens)
    for token in arguments:
        if token == "--ds" or token.startswith("--ds="):
            module = next(arguments, None) if token == "--ds" else token[5:]
            if not isinstance(module, str) or not all(
                part.isidentifier() for part in module.split(".")
            ):
                return None
            effective["DJANGO_SETTINGS_MODULE"] = module
    return effective


def captured_pytest_django_provider(captured):
    """Bind a declared plugin dependency; activation and execution stay unobserved."""
    for name, raw in captured.items():
        if not isinstance(raw, bytes):
            return None
        try:
            text = raw.decode("utf-8")
            if name == "pyproject.toml":
                declarations = _pytest_django_project_declarations(tomllib.loads(text))
                declared = bool(declarations)
            elif name == "requirements.txt":
                declared = any(
                    _pytest_django_requirement(line) for line in text.splitlines()
                )
            elif name == "tox.ini":
                parser = configparser.ConfigParser(interpolation=None)
                parser.read_string(text)
                dependencies = parser.get("testenv", "deps", fallback="")
                commands = parser.get("testenv", "commands", fallback="")
                declared = any(
                    _pytest_django_requirement(line)
                    for line in dependencies.splitlines()
                ) and any(
                    re.match(r"^(?:python\s+-m\s+)?pytest(?:\s|$)", line.strip())
                    for line in commands.splitlines()
                )
            else:
                continue
        except (UnicodeError, ValueError, configparser.Error):
            return None
        if declared:
            return {
                "path": name,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "provider": "pytest_django",
                "declaration_only": True,
                **({"declarations": declarations} if name == "pyproject.toml" else {}),
            }
    return None


def _pytest_django_project_declarations(project):
    """Retain dependency-group premises without claiming installation/activation."""
    metadata = project.get("project", {})
    if not isinstance(metadata, dict):
        return []
    groups = {"project.dependencies": metadata.get("dependencies", [])}
    for prefix, collection in (
        ("project.optional-dependencies", metadata.get("optional-dependencies", {})),
        ("dependency-groups", project.get("dependency-groups", {})),
    ):
        if not isinstance(collection, dict):
            return []
        groups.update(
            {prefix + "." + name: value for name, value in collection.items()}
        )
    declarations = [
        {"group": group, "requirement": item}
        for group, values in groups.items()
        if isinstance(values, list)
        for item in values
        if isinstance(item, str) and _pytest_django_requirement(item)
    ]
    tools = project.get("tool", {})
    if not isinstance(tools, dict):
        return []
    poetry = tools.get("poetry", {})
    if not isinstance(poetry, dict) or not isinstance(poetry.get("group", {}), dict):
        return []
    poetry_groups = {
        "tool.poetry.dependencies": poetry.get("dependencies", {}),
        "tool.poetry.dev-dependencies": poetry.get("dev-dependencies", {}),
        **{
            "tool.poetry.group." + name + ".dependencies": group.get("dependencies", {})
            for name, group in poetry.get("group", {}).items()
            if isinstance(group, dict) and group.get("optional", False) is False
        },
    }
    for group, values in poetry_groups.items():
        if not isinstance(values, dict):
            return []
        # Tables may select markers, sources, extras or optional installation.
        declarations.extend(
            {"group": group, "requirement": "pytest-django " + constraint}
            for name, constraint in values.items()
            if name.lower().replace("_", "-") == "pytest-django"
            and isinstance(constraint, str)
            and re.fullmatch(
                r"(?:\*|[\^~<>=!0-9][0-9.*,+<>=!~^| -]*)", constraint.strip()
            )
        )
    return declarations


def _pytest_django_requirement(line):
    """Unresolved requirement markers/includes never establish a plugin contract."""
    return bool(
        re.fullmatch(
            r"\s*pytest[-_]django(?:\s*[<>=!~][A-Za-z0-9.*,+<>=!~ -]+)?\s*",
            line,
            re.IGNORECASE,
        )
    )


def _supported_pytest_function_patterns(options):
    for option in ("python_files", "python_functions", "python_classes"):
        if option not in options:
            continue
        patterns = _pytest_pattern_list(options[option])
        if not isinstance(patterns, list) or any(
            not isinstance(pattern, str)
            or not pattern.strip()
            or len(pattern) > 256
            or any(ord(character) < 32 for character in pattern)
            for pattern in patterns
        ):
            return False
        if len(patterns) > 64:
            return False
    return True


def _pytest_patterns_from_options(options):
    from .review_audits import (
        _TEST_CLASS_PATTERNS,
        _TEST_FILE_PATTERNS,
        _TEST_FUNCTION_PATTERNS,
    )

    defaults = {
        "python_files": list(_TEST_FILE_PATTERNS),
        "python_functions": list(_TEST_FUNCTION_PATTERNS),
        "python_classes": list(_TEST_CLASS_PATTERNS),
    }
    return {
        name: _pytest_pattern_list(options[name]) if name in options else values
        for name, values in defaults.items()
    }


def _pytest_config_uses_custom_collection(options):
    if "pytest_plugins" in options:
        return True
    addopts = options.get("addopts", "")
    if isinstance(addopts, list) and all(isinstance(value, str) for value in addopts):
        addopts = " ".join(addopts)
    if not isinstance(addopts, str):
        return True
    tokens = addopts.split()
    return any(
        token == "-p"
        or token.startswith("-p")
        or token.split("=", 1)[0]
        in {
            "--ignore",
            "--ignore-glob",
            "--deselect",
            "--doctest-modules",
            "--pyargs",
            "--confcutdir",
            "--noconftest",
            "--collect-in-virtualenv",
            "--import-mode",
            "--override-ini",
        }
        for token in tokens
    )


def _pytest_custom_collection_state(options):
    """Distinguish builtin collector modes from invalid/external configuration."""
    addopts = options.get("addopts", "")
    if isinstance(addopts, list) and all(isinstance(value, str) for value in addopts):
        addopts = " ".join(addopts)
    if not isinstance(addopts, str):
        return _INVALID_PYTEST_CONFIG
    tokens = iter(addopts.split())
    remaining = []
    for token in tokens:
        if token == "--doctest-modules":
            continue
        if token == "--import-mode" or token.startswith("--import-mode="):
            mode = (
                next(tokens, None)
                if token == "--import-mode"
                else token.partition("=")[2]
            )
            if mode not in {"prepend", "append", "importlib"}:
                return _INVALID_PYTEST_CONFIG
            continue
        remaining.append(token)
    if _pytest_config_uses_custom_collection({**options, "addopts": remaining}):
        return _UNSUPPORTED_PYTEST_CONFIG
    return _UNMODELED_BUILTIN_COLLECTION


def _pytest_pattern_list(value):
    return value.split() if isinstance(value, str) else value


_ABSENT_PYTEST_SECTION = object()


_INVALID_PYTEST_CONFIG = object()


_UNSUPPORTED_PYTEST_CONFIG = object()


_UNMODELED_BUILTIN_COLLECTION = object()
