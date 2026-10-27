"""Pytest collection configuration and source-bound collection-hook admission."""

from __future__ import annotations

import configparser
from fnmatch import fnmatchcase

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


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


def _pytest_collection_config(root, source_files=None):
    """Read pytest selected root config; malformed config is incomplete."""
    from .review_audits import (
        ReviewAuditError,
        _TEST_CLASS_PATTERNS,
        _TEST_FILE_PATTERNS,
        _TEST_FUNCTION_PATTERNS,
    )

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
            if result[1].get("state") in {
                "invalid",
                "oversized",
                "unreadable",
                "unsupported",
            }:
                raise ReviewAuditError(
                    f"Cannot determine pytest test collection from {relative}: "
                    f"{result[1]['state']} configuration."
                )
            patterns, identity = result
            identity = _pytest_collection_source_identity(root, identity, source_files)
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
    return patterns, _pytest_collection_source_identity(root, identity, source_files)


def _pytest_collection_source_identity(root, identity, source_files=None):
    """Bind and reject project-local hooks that can change pytest collection."""
    from .review_audits import (
        ReviewAuditError,
        RuntimeAuditError,
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
            tree = ast.parse(data, filename=relative)
        except (OSError, UnicodeError, SyntaxError, RuntimeAuditError, RecursionError):
            if is_conftest:
                raise ReviewAuditError(
                    f"Cannot determine pytest test collection from {relative}: "
                    "unreadable or invalid hook source."
                )
            continue
        found = _pytest_collection_hook_names(tree, is_conftest, is_test_module)
        plugin_assignment = (is_conftest or is_test_module) and any(
            _pytest_plugin_declaration_active(node) for node in tree.body
        )
        if found or plugin_assignment:
            hooks.append(
                {
                    "path": relative,
                    "names": sorted(set(found)),
                    "pytest_plugins": plugin_assignment,
                }
            )
        if is_conftest:
            sources.append(
                {
                    "path": relative,
                    "sha256": sha256(data).hexdigest(),
                    "bytes": len(data),
                }
            )
    if hooks:
        raise ReviewAuditError(
            "Cannot determine pytest test collection: custom collection hooks "
            "or pytest plugins are unsupported."
        )
    return {**identity, "conftest_sources": sources}


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
    if section in {"pyproject", "toml-pytest"}:
        return _toml_pytest_pattern_value(text, section)
    parser = configparser.ConfigParser()
    parser.read_string(text)
    if section not in parser:
        return _ABSENT_PYTEST_SECTION
    options = dict(parser.items(section))
    if not _supported_pytest_function_patterns(options):
        return _UNSUPPORTED_PYTEST_CONFIG
    if _pytest_config_uses_custom_collection(options):
        return _UNSUPPORTED_PYTEST_CONFIG
    return _pytest_patterns_from_options(options)


def _toml_pytest_pattern_value(text, section):
    document = tomllib.loads(text)
    pytest = (
        document.get("pytest")
        if section == "toml-pytest"
        else document.get("tool", {}).get("pytest")
    )
    if pytest is None:
        return _ABSENT_PYTEST_SECTION
    options = pytest.get("ini_options", pytest)
    if not isinstance(options, dict):
        return _INVALID_PYTEST_CONFIG
    if not _supported_pytest_function_patterns(options):
        return _UNSUPPORTED_PYTEST_CONFIG
    if _pytest_config_uses_custom_collection(options):
        return _UNSUPPORTED_PYTEST_CONFIG
    return _pytest_patterns_from_options(options)


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


def _pytest_pattern_list(value):
    return value.split() if isinstance(value, str) else value


_ABSENT_PYTEST_SECTION = object()


_INVALID_PYTEST_CONFIG = object()


_UNSUPPORTED_PYTEST_CONFIG = object()
