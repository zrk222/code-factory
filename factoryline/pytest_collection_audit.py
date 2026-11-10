"""Pytest collection configuration and source-bound collection-hook admission."""

from __future__ import annotations

import configparser
import ast
import hashlib
import re
import shlex
from contextlib import contextmanager
from contextvars import ContextVar
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import PurePosixPath
import yaml

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


def captured_pytest_configuration(captured, *, source_role_only=False):
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
        effective = _pytest_captured_invocation_options(
            captured, options, source_role_only=source_role_only
        )
        if effective is None:
            return None
        return {"identity": identity, "options": effective}
    return None


def captured_test_invocation_profile(
    index, configuration_bytes, invocation_sources, *, configuration_identities
):
    """Return DECLARED, NO_TEST_INVOCATION or UNRESOLVED for all captured workflows."""
    result = _captured_test_invocation_profile(
        index,
        configuration_bytes,
        invocation_sources,
        configuration_identities=configuration_identities,
    )
    if result is not None:
        return result
    return {
        "schema": "factory.captured-test-invocation-profile.v1",
        "status": "UNRESOLVED",
        "reason": "capture-or-invocation-closure-failed",
        "execution_status": "NOT_EXECUTED",
        "runner": None,
        "selector": None,
        "workflows": [],
        "invocations": [],
        "workflow_dispositions": [],
        "sources": {
            name: {
                "path": name,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw),
                "verification": "UNRESOLVED",
            }
            for name, raw in invocation_sources.items()
            if isinstance(name, str) and isinstance(raw, bytes)
        }
        if isinstance(invocation_sources, dict)
        else {},
        "deployment_assurance": "UNASSESSED",
    }


def _captured_test_invocation_profile(
    index, configuration_bytes, invocation_sources, *, configuration_identities
):
    """Bind captured workflow argv to one pytest or native Django test runner."""
    source_rows = _captured_profile_source_rows(
        index, configuration_bytes, invocation_sources, configuration_identities
    )
    if source_rows is None:
        return None
    source = index["source"]
    projected = _captured_workflow_projection(
        index, invocation_sources, configuration_identities, source
    )
    if projected is None:
        return None
    workflows, workflow_dispositions = projected
    if not workflows:
        return {
            "schema": "factory.captured-test-invocation-profile.v1",
            "status": "NO_TEST_INVOCATION",
            "reason": "all-captured-workflows-are-valid-noncontributors",
            "execution_status": "NOT_EXECUTED",
            "runner": None,
            "selector": None,
            "workflows": workflow_dispositions,
            "invocations": [],
            "workflow_dispositions": workflow_dispositions,
            "sources": source_rows,
            "configuration_identities": {
                name: {
                    key: identity[key]
                    for key in ("path", "state", "sha256", "bytes")
                    if key in identity
                }
                for name, identity in configuration_identities.items()
                if identity["state"] == "read"
            },
            "environment": "SOURCE_DECLARED_HASHES_ONLY",
            "deployment_assurance": "UNASSESSED",
        }
    if (
        len(
            {
                row["runner"]["kind"]
                if isinstance(row["runner"], dict)
                else row["runner"]
                for row in workflows
            }
        )
        != 1
    ):
        return None
    runner = (
        workflows[0]["runner"]["kind"]
        if isinstance(workflows[0]["runner"], dict)
        else workflows[0]["runner"]
    )
    if runner == "pytest":
        selection = captured_pytest_configuration(configuration_bytes)
        if selection is None:
            return None
        for row in workflows:
            args = (
                row["argv"][3:]
                if row["argv"][:2] == ["python", "-m"]
                else row["argv"][1:]
            )
            projection = _pytest_argument_projection(args)
            if projection is None:
                return None
            row["selector_effects"] = projection
        identity = selection["identity"]
        selector = {
            "configuration": {
                key: identity[key]
                for key in ("path", "sha256", "bytes", "state")
                if key in identity
            },
            "settings_module": selection["options"].get("DJANGO_SETTINGS_MODULE"),
            "python_files": _pytest_collection_settings(identity)["python_files"],
            "python_functions": _pytest_collection_settings(identity)[
                "python_functions"
            ],
            "python_classes": _pytest_collection_settings(identity)["python_classes"],
        }
    else:
        selector = workflows[0]["runner"]
        if len({row["runner"]["settings_module"] for row in workflows}) != 1:
            return None
    return {
        "schema": "factory.captured-test-invocation-profile.v1",
        "status": "DECLARED",
        "execution_status": "NOT_EXECUTED",
        "runner": runner,
        "selector": selector,
        "workflows": workflows,
        "invocations": workflows,
        "workflow_dispositions": workflow_dispositions,
        "configuration_identities": {
            name: {
                key: configuration_identities[name][key]
                for key in ("path", "state", "sha256", "bytes")
                if key in configuration_identities[name]
            }
            for name in sorted(configuration_identities)
            if configuration_identities[name]["state"] == "read"
            and (
                name in {row["workflow"] for row in workflows}
                or runner == "pytest"
                and name in configuration_bytes
            )
        },
        "sources": source_rows,
        "environment": "SOURCE_DECLARED_HASHES_ONLY",
        "deployment_assurance": "UNASSESSED",
        "coordinate_units": {
            "workflow_span": "1-based-line, 0-based-unicode-column",
            "python_span": "1-based-line, 0-based-UTF8-byte-column",
        },
    }


def _captured_profile_source_rows(
    index, configuration_bytes, invocation_sources, configuration_identities
):
    if not all(
        isinstance(value, dict)
        for value in (
            index,
            configuration_bytes,
            invocation_sources,
            configuration_identities,
        )
    ):
        return None
    source = index.get("source")
    if not source or not isinstance(getattr(source, "inventory", None), dict):
        return None
    if not _captured_configuration_identities_valid(
        configuration_bytes, configuration_identities
    ):
        return None
    rows = {}
    for name, raw in sorted(invocation_sources.items()):
        row = _captured_invocation_source_row(
            name, raw, source, configuration_identities
        )
        if row is None:
            return None
        rows[name] = row
    return rows


def _captured_configuration_identities_valid(configuration_bytes, identities):
    for name, identity in sorted(identities.items()):
        if (
            not isinstance(identity, dict)
            or identity.get("path") != name
            or identity.get("state") not in {"read", "missing"}
        ):
            return False
        raw = configuration_bytes.get(name)
        if identity["state"] == "read" and (
            not isinstance(raw, bytes)
            or identity.get("sha256") != hashlib.sha256(raw).hexdigest()
            or identity.get("bytes") != len(raw)
        ):
            return False
        if identity["state"] == "missing" and raw is not None:
            return False
    return True


def _captured_invocation_source_row(name, raw, source, identities):
    from pathlib import PurePosixPath

    path = PurePosixPath(name)
    if (
        not isinstance(raw, bytes)
        or path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != name
    ):
        return None
    digest = hashlib.sha256(raw).hexdigest()
    if path.suffix == ".py":
        selected = source.root.joinpath(*path.parts)
        if (
            selected not in source.snapshots
            or source.inventory.get(selected) != digest
            or source.source_bytes.get(selected) != raw
            or not source.validate(selected)
        ):
            return None
    elif path.suffix in {".yaml", ".yml"}:
        identity = identities.get(name)
        if (
            not name.startswith(".github/workflows/")
            or not isinstance(identity, dict)
            or identity.get("state") != "read"
            or identity.get("sha256") != digest
            or identity.get("bytes") != len(raw)
        ):
            return None
    else:
        return None
    return {"path": name, "sha256": digest, "bytes": len(raw)}


def _captured_workflow_projection(
    index, invocation_sources, configuration_identities, source
):
    from .mock_fixture_provenance import _django_imports

    workflows, dispositions = [], []
    try:
        for name, raw in sorted(invocation_sources.items()):
            if name.endswith((".yaml", ".yml")):
                found = _captured_workflow_rows(
                    name,
                    raw,
                    invocation_sources,
                    configuration_identities,
                    index,
                    source,
                    _django_imports,
                )
                if found is None:
                    return None
                rows, disposition = found
                workflows.extend(rows)
                dispositions.append(disposition)
    except (UnicodeError, ValueError, TypeError, yaml.YAMLError):
        return None
    return workflows, dispositions


def _captured_workflow_rows(
    name, raw, invocation_sources, identities, index, source, django_imports
):
    from pathlib import PurePosixPath

    document = yaml.compose(raw.decode("utf-8"))
    jobs = _captured_yaml_mapping_value(document, "jobs")
    if not isinstance(jobs, yaml.MappingNode):
        return None
    context = {
        "workflow": name,
        "workflow_if": _captured_yaml_mapping_value(document, "if"),
        "workflow_env": _captured_yaml_mapping_value(document, "env"),
        "workflow_cwd": _captured_yaml_mapping_value(
            _captured_yaml_mapping_value(document, "defaults"), "run"
        ),
        "yaml_lines": raw.decode("utf-8").splitlines(),
    }
    if isinstance(context["workflow_cwd"], yaml.MappingNode):
        context["workflow_cwd"] = _captured_yaml_mapping_value(
            context["workflow_cwd"], "working-directory"
        )
    if context["workflow_cwd"] is not None and not isinstance(
        context["workflow_cwd"], yaml.ScalarNode
    ):
        return None
    rows = []
    for _, job in jobs.value:
        found = _captured_job_rows(
            job,
            context,
            invocation_sources,
            identities,
            index,
            source,
            django_imports,
            PurePosixPath,
        )
        if found is None:
            return None
        rows.extend(found)
    return rows, {"path": name, "status": "DECLARED" if rows else "NO_TEST_INVOCATION"}


def _captured_job_rows(
    job,
    context,
    invocation_sources,
    identities,
    index,
    source,
    django_imports,
    posix_path,
):
    steps = _captured_yaml_mapping_value(job, "steps")
    if not isinstance(steps, yaml.SequenceNode):
        return []
    defaults = _captured_yaml_mapping_value(
        _captured_yaml_mapping_value(job, "defaults"), "run"
    )
    job_cwd = (
        _captured_yaml_mapping_value(defaults, "working-directory")
        if defaults
        else None
    )
    if job_cwd is not None and not isinstance(job_cwd, yaml.ScalarNode):
        return None
    job_context = {
        **context,
        "job_if": _captured_yaml_mapping_value(job, "if"),
        "job_env": _captured_yaml_mapping_value(job, "env"),
        "job_cwd": job_cwd,
    }
    effects, rows = [], []
    for step in steps.value:
        found = _captured_step_rows(
            step,
            job_context,
            effects,
            invocation_sources,
            identities,
            index,
            source,
            django_imports,
            posix_path,
        )
        if found is None:
            return None
        step_rows, step_effects = found
        rows.extend(step_rows)
        effects.extend(
            row for row in step_effects if row["scope"] == "workflow-next-step"
        )
    return rows


def _captured_step_rows(
    step,
    context,
    prior_effects,
    invocation_sources,
    identities,
    index,
    source,
    django_imports,
    posix_path,
):
    run = _captured_yaml_mapping_value(step, "run")
    if not isinstance(run, yaml.ScalarNode) or run.tag != "tag:yaml.org,2002:str":
        return [], []
    step_cwd = _captured_yaml_mapping_value(step, "working-directory")
    if step_cwd is not None and not isinstance(step_cwd, yaml.ScalarNode):
        return None
    cwd = (
        step_cwd.value
        if step_cwd
        else context["job_cwd"].value
        if context["job_cwd"]
        else context["workflow_cwd"].value
        if context["workflow_cwd"]
        else "."
    )
    if not _captured_repository_relative(cwd):
        return None
    env = _captured_yaml_environment(
        ("workflow", context["workflow_env"]),
        ("job", context["job_env"]),
        ("step", _captured_yaml_mapping_value(step, "env")),
    )
    if env is None:
        return None
    return _captured_step_commands(
        run,
        step,
        context,
        prior_effects,
        invocation_sources,
        index,
        source,
        django_imports,
        posix_path,
        cwd,
        env,
    )


def _captured_step_commands(
    run,
    step,
    context,
    prior_effects,
    invocation_sources,
    index,
    source,
    django_imports,
    posix_path,
    cwd,
    env,
):
    rows, effects, shell_env = [], [], []
    for start, end, command in _captured_shell_commands(run.value):
        found = _captured_step_command(
            command,
            start,
            end,
            run,
            step,
            context,
            prior_effects,
            invocation_sources,
            index,
            source,
            django_imports,
            posix_path,
            cwd,
            env,
            shell_env,
            effects,
        )
        if found is None:
            return None
        row, row_effects, row_env = found
        effects.extend(row_effects)
        shell_env.extend(row_env)
        if row:
            rows.append(row)
    return rows, effects


def _captured_step_command(
    command,
    start,
    end,
    run,
    step,
    context,
    prior_effects,
    invocation_sources,
    index,
    source,
    django_imports,
    posix_path,
    cwd,
    env,
    shell_env,
    effects,
):
    try:
        argv = shlex.split(command, comments=True)
    except ValueError:
        return None
    if not argv:
        return [], [], []
    row_effects = _captured_shell_effects(argv, command, start)
    if _captured_shell_target_unresolved(argv, command):
        return None
    if "${{" in command or _captured_shell_compound(command):
        return [], row_effects, []
    row_env = _captured_shell_environment(argv, command, start)
    row = _captured_invocation_row(
        argv,
        context,
        run,
        start,
        end,
        context["yaml_lines"],
        cwd,
        env,
        [*shell_env, *row_env],
        [*effects, *row_effects],
        prior_effects,
        step,
    )
    if row is None:
        return None
    if not row:
        return row, row_effects, row_env
    if argv[0].rsplit("/", 1)[-1] not in {"python", "python3", "python.exe"}:
        return row, row_effects, row_env
    runner_path = (posix_path(cwd) / argv[1]).as_posix()
    if (
        not _captured_repository_relative(argv[1])
        or runner_path not in invocation_sources
    ):
        return None
    path = source.root.joinpath(*posix_path(runner_path).parts)
    runner = _captured_django_runner(
        index, path, source.snapshots.get(path), django_imports(index, path)
    )
    if runner is None:
        return None
    row.update(script=runner_path, runner=runner)
    return row, row_effects, row_env


def _captured_shell_target_unresolved(argv, command):
    if "${{" in command:
        return _captured_test_like_command(argv) or _captured_unknown_python_command(
            argv
        )
    return _captured_shell_compound(command) and (
        _captured_test_like_command(argv) or any(arg.endswith(".py") for arg in argv)
    )


def _captured_shell_compound(command):
    return any(token in command for token in ("&&", "||", ";", "|", ">", "<"))


def _captured_invocation_row(
    argv,
    context,
    run,
    start,
    end,
    lines,
    cwd,
    env,
    shell_env,
    effects,
    prior_effects,
    step,
):
    python_script = (
        argv[0].rsplit("/", 1)[-1] in {"python", "python3", "python.exe"}
        and len(argv) == 2
        and argv[1].endswith(".py")
    )
    pytest = (
        argv[0] == "pytest"
        or argv[:2] == ["python", "-m"]
        and len(argv) >= 3
        and argv[2] == "pytest"
    )
    if not (python_script or pytest):
        return (
            None
            if _captured_test_like_command(argv)
            or _captured_unknown_python_command(argv)
            else {}
        )
    conditions = _captured_workflow_conditions(
        context["workflow_if"],
        context["job_if"],
        _captured_yaml_mapping_value(step, "if"),
    )
    if conditions is None or _captured_environment_conflict(
        env, shell_env, effects, prior_effects
    ):
        return None
    row_line = run.start_mark.line + start + 1
    row_end = run.start_mark.line + end + 1
    row = {
        "workflow": context["workflow"],
        "argv": argv,
        "cwd": cwd,
        "span": [
            row_line,
            len(lines[row_line - 1]) - len(lines[row_line - 1].lstrip()),
            row_end,
            len(lines[row_end - 1]),
        ],
        "condition": conditions,
        "declared_environment": [*env, *shell_env],
    }
    if pytest:
        row["runner"] = "pytest"
    return row


def _captured_test_like_command(argv):
    tokens = [str(value).lower().replace("\\", "/") for value in argv]
    return any(
        token in {"pytest", "tox", "nox", "unittest", "manage.py", "discoverrunner"}
        or token.endswith("/manage.py")
        or token.endswith("/pytest")
        or token.endswith(".py")
        and "test" in token.rsplit("/", 1)[-1]
        for token in tokens
    )


def _captured_shell_commands(script):
    lines = script.splitlines()
    start, parts = 0, []
    for index, line in enumerate(lines):
        if not parts:
            start = index
        continued = line.rstrip().endswith("\\")
        parts.append(line.rstrip()[:-1] if continued else line)
        if not continued:
            yield start, index, " ".join(parts)
            parts = []
    if parts:
        yield start, len(lines) - 1, " ".join(parts)


def _captured_unknown_python_command(argv):
    tokens = [str(value).lower().replace("\\", "/") for value in argv]
    if tokens[0].rsplit("/", 1)[-1] in {"python", "python3", "python.exe"}:
        if len(tokens) > 1 and tokens[1] == "-m":
            return len(tokens) < 3 or tokens[2] not in {
                "pip",
                "sphinx",
                "build",
                "setuptools",
                "twine",
                "compileall",
                "ensurepip",
            }
        return len(tokens) > 1 and (tokens[1].endswith(".py") or tokens[1] == "-c")
    return any(
        token.endswith(".py") or token in {"python", "python3", "pytest", "tox", "nox"}
        for token in tokens
    )


def _captured_yaml_mapping_value(node, key):
    if not isinstance(node, yaml.MappingNode):
        return None
    matches = [value for name, value in node.value if name.value == key]
    if len(matches) > 1:
        raise ValueError("duplicate workflow key")
    return matches[0] if len(matches) == 1 else None


def _captured_repository_relative(value):
    from pathlib import PurePosixPath

    return bool(
        isinstance(value, str)
        and value
        and "${{" not in value
        and "\\" not in value
        and ":" not in value
        and not PurePosixPath(value).is_absolute()
        and ".." not in PurePosixPath(value).parts
        and PurePosixPath(value).as_posix() == value
    )


def _captured_workflow_conditions(*nodes):
    conditions = []
    for node in nodes:
        if node is None:
            continue
        if (
            not isinstance(node, yaml.ScalarNode)
            or node.tag != "tag:yaml.org,2002:bool"
            or node.value.lower() != "true"
        ):
            return None
        conditions.append(
            {
                "state": "literal-true",
                "span": [
                    node.start_mark.line + 1,
                    node.start_mark.column,
                    node.end_mark.line + 1,
                    node.end_mark.column,
                ],
            }
        )
    return conditions or [{"state": "unconditional"}]


def _captured_yaml_environment(*scopes):
    rows = []
    for scope, node in scopes:
        if node is None:
            continue
        if not isinstance(node, yaml.MappingNode):
            return None
        for key, value in node.value:
            if key.tag != "tag:yaml.org,2002:str" or not isinstance(
                value, yaml.ScalarNode
            ):
                return None
            raw = value.value.encode("utf-8")
            rows.append(
                {
                    "name": key.value,
                    "scope": scope,
                    "value_sha256": hashlib.sha256(raw).hexdigest(),
                    "span": [
                        key.start_mark.line + 1,
                        key.start_mark.column,
                        value.end_mark.line + 1,
                        value.end_mark.column,
                    ],
                }
            )
    return rows


def _captured_shell_environment(argv, command, start):
    rows = []
    if argv[0] in {".", "source", "eval", "exec", "env"}:
        return [
            {
                "name": "<dynamic-shell-environment>",
                "scope": "workflow-shell",
                "value_sha256": hashlib.sha256(command.encode()).hexdigest(),
                "line_offset": start,
            }
        ]
    assignments = argv[1:] if argv[0] == "export" else argv
    for token in assignments:
        match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", token)
        if match:
            rows.append(
                {
                    "name": match.group(1),
                    "scope": "workflow-shell",
                    "value_sha256": hashlib.sha256(match.group(2).encode()).hexdigest(),
                    "line_offset": start,
                }
            )
        elif argv[0] != "export":
            break
    return rows


def _captured_shell_effects(argv, command, start):
    """Find shell effects that can change later command selection or reachability."""
    rows = []
    dynamic = any(token in command for token in ("&&", "||", ";", "|", ">", "<"))
    control = re.search(
        r"\b(?:if|then|elif|else|fi|for|while|until|case|function|do|done)\b", command
    )
    if dynamic or control or any(arg in {"cd", "pushd", "popd"} for arg in argv):
        rows.append(
            {
                "name": "<unmodeled-shell-effect>",
                "scope": "workflow-shell",
                "value_sha256": hashlib.sha256(command.encode()).hexdigest(),
                "line_offset": start,
            }
        )
    env_write = re.search(
        r"(?:>>?|\|)\s*\$\{?GITHUB_(?:ENV|PATH)\}?\b", command, re.IGNORECASE
    )
    if env_write:
        names = re.findall(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", command, re.MULTILINE)
        for name in names or ["<dynamic-github-env>"]:
            rows.append(
                {
                    "name": name,
                    "scope": "workflow-next-step",
                    "value_sha256": hashlib.sha256(command.encode()).hexdigest(),
                    "line_offset": start,
                }
            )
    return rows


def _captured_environment_conflict(*rows):
    selector_names = {
        "PATH",
        "PYTHONPATH",
        "PYTHONHOME",
        "VIRTUAL_ENV",
        "DJANGO_SETTINGS_MODULE",
        "DJANGO_CONFIGURATION",
        "GITHUB_PATH",
        "GITHUB_ENV",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
        "PYTEST_CONFIG",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
        "TOX_ENV",
        "NOX_CURRENT_SESSION",
    }
    return any(
        row["name"] == "<dynamic-shell-environment>"
        or row["name"] in {"<unmodeled-shell-effect>", "<dynamic-github-env>"}
        or row["name"].upper() in selector_names
        or row["name"].upper().startswith(("PYTEST_", "TOX_", "NOX_"))
        for collection in rows
        for row in collection
    )


# These APIs may consume configured settings or hide unmodeled consumers.
# A catalog hit is an unresolved effect, never proof that the key was used.
# Model basis: https://docs.djangoproject.com/en/5.2/ref/settings/#secret-key
DJANGO_IMPLICIT_KEY_EFFECTS = frozenset(
    {
        "__import__",
        "builtins.__import__",
        "__builtins__",
        "sys.modules",
        "builtins.__dict__",
        "django.utils.module_loading.import_string",
        "pkgutil.resolve_name",
        *(
            prefix + name
            for prefix in ("", "builtins.")
            for name in ("globals", "locals", "vars", "dir", "eval", "exec", "compile")
        ),
        "django.setup",
        "django.conf.LazySettings",
        "django.conf.Settings",
        "django.utils.crypto.salted_hmac",
        "django.core.wsgi.get_wsgi_application",
        "django.core.asgi.get_asgi_application",
        "django.core.management.execute_from_command_line",
        *(
            "django.core.signing." + name
            for name in (
                "dumps",
                "loads",
                "Signer",
                "TimestampSigner",
                "get_cookie_signer",
            )
        ),
        "django.contrib.auth.tokens.default_token_generator",
        "django.contrib.auth.tokens.PasswordResetTokenGenerator",
        *(
            "django.contrib.auth." + name
            for name in ("login", "get_user", "update_session_auth_hash")
        ),
        *(
            "django.contrib.sessions.backends." + name
            for name in (
                "base.SessionBase",
                "db.SessionStore",
                "cached_db.SessionStore",
                "cache.SessionStore",
                "file.SessionStore",
                "signed_cookies.SessionStore",
            )
        ),
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "django.contrib.messages.storage.cookie.CookieStorage",
        "django.contrib.messages.storage.fallback.FallbackStorage",
        *(
            prefix + name
            for prefix in ("django.contrib.messages.", "django.contrib.messages.api.")
            for name in ("add_message", "debug", "info", "success", "warning", "error")
        ),
    }
)
DJANGO_IMPLICIT_KEY_METHODS = frozenset(
    {
        "__dict__",
        "__class__",
        "__globals__",
        "__getattribute__",
        "__subclasses__",
        "__mro__",
        "__base__",
        "__bases__",
        "__builtins__",
        "_wrapped",
        "set_signed_cookie",
        "get_signed_cookie",
        "get_session_auth_hash",
        "get_session_auth_fallback_hash",
    }
)


def _captured_django_runner(index, path, tree, aliases):
    """Bind a captured Django setup and DiscoverRunner invocation by imports."""
    if not isinstance(tree, ast.Module) or not isinstance(aliases, dict):
        return None
    from .import_context import captured_django_startup_statements
    from .intent_quality import _canary_main_guard_test

    statements = _captured_native_guard_body(tree, _canary_main_guard_test)
    if statements is None or len(statements) not in {4, 5}:
        return None
    startup = captured_django_startup_statements(
        {"index": index["source"], "aliases": {path: aliases}}, path
    )
    if startup[-len(statements) :] != statements:
        return None
    selector, setup, allocation, invocation, *exit_statements = statements
    if not _captured_selector_assignment(selector, aliases):
        return None
    if not _captured_setup_call(setup, aliases) or not _captured_runner_allocation(
        allocation, aliases
    ):
        return None
    variable = allocation.targets[0].id
    if (
        not isinstance(invocation, ast.Assign)
        or len(invocation.targets) != 1
        or not isinstance(invocation.targets[0], ast.Name)
    ):
        return None
    call = invocation.value
    if (
        not isinstance(call, ast.Call)
        or not isinstance(call.func, ast.Attribute)
        or call.func.attr != "run_tests"
        or not isinstance(call.func.value, ast.Name)
        or call.func.value.id != variable
        or len(call.args) != 1
        or not isinstance(call.args[0], ast.List)
        or call.args[0].elts
        or call.keywords
    ):
        return None
    if exit_statements and not _captured_system_exit(
        exit_statements[0], aliases, invocation.targets[0].id
    ):
        return None
    settings_module = _captured_selector_assignment(selector, aliases)
    return {
        "kind": "django.DiscoverRunner",
        "settings_module": settings_module,
        "bootstrap_effect": "MODELED_IMPLICIT_SETTINGS_LOAD",
        "settings_selector_span": [
            selector.lineno,
            selector.col_offset,
            selector.end_lineno,
            selector.end_col_offset,
        ],
        "effect_model": "django.settings-module-import-uppercase-attributes.v1",
        "setup_span": [
            setup.lineno,
            setup.col_offset,
            setup.end_lineno,
            setup.end_col_offset,
        ],
        "runner_allocation_span": [
            allocation.lineno,
            allocation.col_offset,
            allocation.end_lineno,
            allocation.end_col_offset,
        ],
        "runner_span": [
            invocation.lineno,
            invocation.col_offset,
            invocation.end_lineno,
            invocation.end_col_offset,
        ],
        "settings_selector": "SOURCE_BOUND_LITERAL",
    }


def _captured_native_guard_body(tree, main_guard_test):
    body = [
        node
        for node in tree.body
        if not (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        )
    ]
    guards = [
        node for node in body if isinstance(node, ast.If) and main_guard_test(node.test)
    ]
    if len(guards) != 1 or body[-1] is not guards[0] or guards[0].orelse:
        return None
    if any(not isinstance(node, (ast.Import, ast.ImportFrom)) for node in body[:-1]):
        return None
    return guards[0].body


def _captured_setup_call(node, aliases):
    from .review_audits import _resolved_ast_name

    return bool(
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and _resolved_ast_name(node.value.func, aliases) == "django.setup"
        and not node.value.args
        and not node.value.keywords
    )


def _captured_runner_allocation(node, aliases):
    from .review_audits import _resolved_ast_name

    if (
        not isinstance(node, ast.Assign)
        or len(node.targets) != 1
        or not isinstance(node.targets[0], ast.Name)
    ):
        return False
    call = node.value
    if (
        not isinstance(call, ast.Call)
        or _resolved_ast_name(call.func, aliases) != "django.test.runner.DiscoverRunner"
        or call.args
        or len(call.keywords) != 1
    ):
        return False
    keyword = call.keywords[0]
    return (
        keyword.arg == "verbosity"
        and isinstance(keyword.value, ast.Constant)
        and type(keyword.value.value) is int
    )


def _captured_selector_assignment(node, aliases):
    from .review_audits import _resolved_ast_name

    if not isinstance(node, ast.Assign) or len(node.targets) != 1:
        return None
    target = node.targets[0]
    if (
        not isinstance(target, ast.Subscript)
        or not isinstance(target.slice, ast.Constant)
        or target.slice.value != "DJANGO_SETTINGS_MODULE"
        or _resolved_ast_name(target.value, aliases) != "os.environ"
    ):
        return None
    value = node.value
    return (
        value.value
        if isinstance(value, ast.Constant)
        and isinstance(value.value, str)
        and value.value
        else None
    )


def _captured_system_exit(node, aliases, result_name):
    from .review_audits import _resolved_ast_name

    if not (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and _resolved_ast_name(node.value.func, aliases) == "sys.exit"
        and len(node.value.args) == 1
        and not node.value.keywords
    ):
        return False
    argument = node.value.args[0]
    if isinstance(argument, ast.Call):
        return (
            _resolved_ast_name(argument.func, aliases) in {"bool", "builtins.bool"}
            and len(argument.args) == 1
            and not argument.keywords
            and isinstance(argument.args[0], ast.Name)
            and argument.args[0].id == result_name
        )
    allowed = (
        ast.Expression,
        ast.Name,
        ast.Load,
        ast.Constant,
        ast.BoolOp,
        ast.And,
        ast.Or,
        ast.UnaryOp,
        ast.Not,
        ast.Compare,
        ast.Eq,
        ast.NotEq,
        ast.Gt,
        ast.GtE,
        ast.Lt,
        ast.LtE,
    )
    return all(
        isinstance(child, allowed)
        and (not isinstance(child, ast.Name) or child.id == result_name)
        for child in ast.walk(ast.Expression(argument))
    )


def _pytest_settings_selection_overridden(options):
    """Do not credit a config default when captured argv selects another source."""
    return _pytest_effective_settings_options(options) is None


def _pytest_effective_settings_options(
    options, *, coverage_provider=False, source_role_only=False
):
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
    projection = _pytest_argument_projection(
        tokens, coverage_provider=coverage_provider, source_role_only=source_role_only
    )
    if projection is None:
        return None
    effective = dict(options)
    effective.update(projection)
    return effective


def _pytest_captured_invocation_options(captured, options, *, source_role_only=False):
    """Reconcile captured tox argv/environment with the selected config defaults."""
    coverage_provider = _pytest_cov_provider(captured)
    effective = _pytest_effective_settings_options(
        options, coverage_provider=coverage_provider, source_role_only=source_role_only
    )
    if effective is None or "tox.ini" not in captured:
        return effective
    try:
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(captured["tox.ini"].decode("utf-8"))
        invocations = [
            (
                section,
                parser.get(
                    section,
                    "commands",
                    fallback=parser.get("testenv", "commands", fallback=""),
                ),
            )
            for section in parser.sections()
            if section == "testenv" or section.startswith("testenv:")
        ]
        selections = [
            selection
            for section, commands in invocations
            for line in commands.splitlines()
            if line.strip()
            for selection in [
                _pytest_tox_selection(
                    parser,
                    section,
                    line,
                    options,
                    coverage_provider=coverage_provider,
                )
            ]
        ]
    except (AttributeError, UnicodeError, ValueError, configparser.Error):
        return None
    if not selections:
        return None
    if any(selection is None for selection in selections) or any(
        selection != selections[0] for selection in selections[1:]
    ):
        return None
    result = selections[0]
    result["captured_invocations"] = {
        "path": "tox.ini",
        "sha256": hashlib.sha256(captured["tox.ini"]).hexdigest(),
        "commands": invocations,
        "profile": "CAPTURED_LITERAL_COMMANDS_ONLY",
        "execution_status": "NOT_EXECUTED",
    }
    return result


def _pytest_tox_selection(parser, section, line, options, *, coverage_provider=False):
    """Bind a literal default pytest invocation; unknown wrappers stay unresolved."""
    tokens = shlex.split(line)
    prefix = 3 if tokens[:3] == ["python", "-m", "pytest"] else 1
    if not tokens or (prefix == 1 and tokens[0] != "pytest"):
        return None
    args = tokens[prefix:]
    if not _pytest_tox_context_closed(parser, section) or any(
        "{" in token or "}" in token for token in args
    ):
        return None
    environment = _pytest_tox_environment(parser, section)
    if environment is None:
        return None
    effective = dict(options)
    if "DJANGO_SETTINGS_MODULE" in environment:
        effective["DJANGO_SETTINGS_MODULE"] = environment["DJANGO_SETTINGS_MODULE"]
    # Configuration addopts precede command arguments, but their --ds still
    # outranks the environment; apply them together in argparse order.
    configured = effective.get("addopts", "")
    configured = shlex.split(configured) if isinstance(configured, str) else configured
    if not isinstance(configured, list):
        return None
    selected = _pytest_effective_settings_options(
        {**effective, "addopts": configured + args},
        coverage_provider=coverage_provider,
    )
    if selected is None or not _pytest_tox_arguments_closed(
        args, coverage_provider=coverage_provider
    ):
        return None
    selected["addopts"] = options.get("addopts", "")
    return selected


def _pytest_tox_context_closed(parser, section):
    """Only this literal INI command subset is modeled, not arbitrary Tox execution."""
    supported = {"commands", "setenv", "passenv", "deps", "description"}
    return not any(
        key not in supported
        for owner in {"testenv", section}
        if parser.has_section(owner)
        for key in parser.options(owner)
    )


def _pytest_tox_environment(parser, section):
    """Only literal environment assignments with closed selector inheritance count."""
    selectors = {
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
        "DJANGO_SETTINGS_MODULE",
        "DJANGO_CONFIGURATION",
        "PYTHONPATH",
        "PYTHONHOME",
        "PATH",
        "VIRTUAL_ENV",
    }
    passthrough = parser.get(
        section, "passenv", fallback=parser.get("testenv", "passenv", fallback="")
    )
    if any(
        fnmatchcase(name, pattern.upper())
        for pattern in re.split(r"[\s,]+", passthrough)
        for name in selectors
    ):
        return None
    environment = {}
    configured = parser.get(
        section, "setenv", fallback=parser.get("testenv", "setenv", fallback="")
    )
    for item in configured.splitlines():
        if not item.strip() or item.lstrip().startswith("#"):
            continue
        name, separator, value = item.strip().partition("=")
        name, value = name.strip().upper(), value.strip()
        if not separator or not name.isidentifier() or "{" in value or "}" in value:
            return None
        if name in selectors - {"DJANGO_SETTINGS_MODULE"}:
            return None
        environment[name] = value
    module = environment.get("DJANGO_SETTINGS_MODULE", "unused")
    return (
        environment if all(part.isidentifier() for part in module.split(".")) else None
    )


_PYTEST_ARGUMENT_EFFECTS = (
    ("-q", (0, "report")),
    ("-v", (0, "report")),
    ("-vv", (0, "report")),
    ("-ra", (0, "report")),
    ("--strict-markers", (0, "validation")),
    ("--junitxml", (1, "report-output")),
    ("--cov", ("optional", "coverage")),
    ("--cov-report", (1, "coverage")),
    ("--reuse-db", (0, "database-reuse")),
    ("--pdbcls", (1, "debugger-class")),
)


def _pytest_argument_projection(
    tokens, *, coverage_provider=False, source_role_only=False
):
    """Project one allowlisted argument grammar onto settings selection."""
    if not isinstance(tokens, list) or not all(isinstance(t, str) for t in tokens):
        return None
    projection = {}
    arguments = iter(tokens)
    for token in arguments:
        effect = _pytest_argument_effect(
            token,
            arguments,
            coverage_provider=coverage_provider,
            source_role_only=source_role_only,
        )
        if effect is None:
            return None
        projection.update(effect)
    return projection


def _pytest_argument_effect(
    token, arguments, *, coverage_provider, source_role_only=False
):
    """Project one recognized argument or refuse its missing/unknown effect."""
    if token == "--":
        return None
    flag, separator, inline_value = token.partition("=")
    if token == "--ds" or flag == "--ds" and separator:
        module = next(arguments, None) if token == "--ds" else inline_value
        if (
            not isinstance(module, str)
            or not module
            or not all(part.isidentifier() for part in module.split("."))
        ):
            return None
        return {"DJANGO_SETTINGS_MODULE": module}
    effect = dict(_PYTEST_ARGUMENT_EFFECTS).get(flag)
    if effect is None or effect[1] == "coverage" and not coverage_provider:
        return None
    if effect[1] in {"database-reuse", "debugger-class"} and not source_role_only:
        return None
    arity = effect[0]
    if arity == 0:
        return {} if not separator else None
    if arity == "optional":
        return (
            {} if not separator or _pytest_argument_value_valid(inline_value) else None
        )
    value = inline_value if separator else next(arguments, None)
    if not separator and isinstance(value, str) and value.startswith("-"):
        return None
    if (
        flag == "--pdbcls"
        and re.fullmatch(
            r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*",
            value or "",
        )
        is None
    ):
        return None
    return {} if _pytest_argument_value_valid(value) else None


def _pytest_argument_value_valid(value):
    return (
        isinstance(value, str) and bool(value) and "{" not in value and "}" not in value
    )


def _pytest_tox_arguments_closed(args, *, coverage_provider=False):
    """Use the same selector and effect grammar for literal Tox argv."""
    return (
        _pytest_argument_projection(args, coverage_provider=coverage_provider)
        is not None
    )


def _pytest_cov_provider(captured):
    """Require coverage to be declared in the selected captured test profile."""
    if not isinstance(captured, dict) or any(
        not isinstance(value, bytes) for value in captured.values()
    ):
        return False
    if "tox.ini" in captured:
        try:
            profiles = _pytest_cov_tox_profiles(captured["tox.ini"])
            if profiles:
                return all(profiles)
        except (UnicodeError, configparser.Error):
            return False
    try:
        project = (
            tomllib.loads(captured["pyproject.toml"].decode())
            if "pyproject.toml" in captured
            else {}
        )
        if _pytest_cov_project(project):
            return True
        requirements = captured.get("requirements.txt", b"").decode()
    except (UnicodeError, ValueError):
        return False
    return any(_pytest_cov_requirement(line) for line in requirements.splitlines())


def _pytest_cov_tox_profiles(raw):
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(raw.decode())
    profiles = []
    for section in parser.sections():
        if section != "testenv" and not section.startswith("testenv:"):
            continue
        commands = parser.get(
            section, "commands", fallback=parser.get("testenv", "commands", fallback="")
        )
        if not any(
            re.match(r"^(?:python\s+-m\s+)?pytest(?:\s|$)", line.strip())
            for line in commands.splitlines()
        ):
            continue
        dependencies = parser.get(
            section, "deps", fallback=parser.get("testenv", "deps", fallback="")
        )
        profiles.append(
            any(_pytest_cov_requirement(line) for line in dependencies.splitlines())
        )
    return profiles


def _pytest_cov_project(project):
    metadata = project.get("project", {})
    dependencies = (
        metadata.get("dependencies", []) if isinstance(metadata, dict) else []
    )
    if not isinstance(dependencies, list) or not all(
        isinstance(line, str) for line in dependencies
    ):
        return False
    if any(_pytest_cov_requirement(line) for line in dependencies):
        return True
    tools = project.get("tool", {})
    poetry = tools.get("poetry", {}) if isinstance(tools, dict) else {}
    if not isinstance(poetry, dict):
        return False
    groups = [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})]
    named = poetry.get("group", {})
    if isinstance(named, dict):
        groups.extend(
            group.get("dependencies", {})
            for group in named.values()
            if isinstance(group, dict) and group.get("optional", False) is False
        )
    return any(
        isinstance(dependencies, dict)
        and any(
            name.lower().replace("_", "-") == "pytest-cov" and isinstance(value, str)
            for name, value in dependencies.items()
        )
        for dependencies in groups
    )


def _pytest_cov_requirement(line):
    return (
        re.fullmatch(
            r"\s*pytest[-_]cov(?:\s*[<>=!~][A-Za-z0-9.*,+<>=!~ -]+)?\s*",
            line,
            re.IGNORECASE,
        )
        is not None
    )


def captured_distribution_provider(captured, distribution, *, include_optional=False):
    """Bind an exact captured distribution declaration, never installation or activation."""
    canonical = _distribution_name(distribution)
    if (
        canonical is None
        or not isinstance(captured, dict)
        or any(not isinstance(name, str) for name in captured)
    ):
        return None
    matches = []
    for name in ("requirements.txt", "pyproject.toml", "tox.ini"):
        if name not in captured:
            continue
        resolved = _captured_provider_file(
            name, captured[name], canonical, include_optional
        )
        if resolved is None:
            return None
        raw, declarations = resolved
        if declarations:
            matches.append((name, raw, declarations))
    if not matches:
        return None
    name, raw, declarations = matches[0]
    return {
        "path": name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "provider": canonical,
        "declaration_only": True,
        "declarations": declarations,
    }


def _captured_provider_file(name, raw, canonical, include_optional):
    if not isinstance(raw, bytes):
        return None
    try:
        decoded = raw.decode("utf-8")
        if name == "requirements.txt":
            declarations = _distribution_requirement_file(decoded, canonical)
        elif name == "pyproject.toml":
            declarations = _distribution_project_declarations(
                tomllib.loads(decoded), canonical, include_optional=include_optional
            )
        else:
            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(decoded)
            commands = parser.get("testenv", "commands", fallback="")
            declarations = (
                _distribution_requirement_file(
                    parser.get("testenv", "deps", fallback=""), canonical
                )
                if commands.strip()
                else None
            )
            if canonical == "pytest-django" and not any(
                re.match(r"^(?:python\s+-m\s+)?pytest(?:\s|$)", line.strip())
                for line in commands.splitlines()
            ):
                declarations = []
    except (UnicodeError, ValueError, configparser.Error):
        return None
    return (raw, declarations) if declarations is not None else None


def captured_pytest_django_provider(captured):
    """Preserve the legacy pytest plugin declaration receipt and provider spelling."""
    result = captured_distribution_provider(
        captured, "pytest-django", include_optional=True
    )
    if result is None:
        return None
    return {
        "path": result["path"],
        "sha256": result["sha256"],
        "provider": "pytest_django",
        "declaration_only": True,
        **(
            {"declarations": result["declarations"]}
            if result["path"] == "pyproject.toml"
            else {}
        ),
    }


def captured_pytest_django_user_fixture(index, path, function, secret, scope_dynamic):
    """Bind a unique local password to the builtin database-backed user fixture."""
    if not _pytest_django_user_owner(index, path, function):
        return None
    call = _pytest_django_user_enrollment(index, path, function, secret)
    binding = _pytest_django_user_configuration(index, path, function)
    if call is None or binding is None:
        return None
    provider, selected, settings = binding
    settings_path = (
        index["source"].root.joinpath(*settings.split(".")).with_suffix(".py")
    )
    if not _pytest_django_user_settings(index, settings_path, scope_dynamic):
        return None
    if not _pytest_django_fixture_namespace_closed(index, path, scope_dynamic):
        return None
    fixture_provider = _pytest_django_user_receipt(
        index, path, settings_path, provider, selected, settings
    )
    return {
        **fixture_provider,
        "fixture_provider": fixture_provider,
        "profile": "SOURCE_BOUND_TEST_ACCOUNT_ENROLLMENT",
        "enrollment": call,
    }


def _pytest_django_user_owner(index, path, function):
    """Require an ordinary collected function with a required fixture argument."""
    if not isinstance(index["configuration_bytes"], dict):
        return False
    match function:
        case ast.FunctionDef(
            decorator_list=[],
            args=ast.arguments(posonlyargs=[], vararg=None, kwarg=None),
        ):
            pass
        case _:
            return False
    required = function.args.args[
        : len(function.args.args) - len(function.args.defaults)
    ]
    required += [
        arg
        for arg, default in zip(function.args.kwonlyargs, function.args.kw_defaults)
        if default is None
    ]
    source = index["source"]
    return (
        source.validate(path)
        and source.parents[path].get(id(function)) is index["modules"].get(path)
        and any(item.arg == "django_user_model" for item in required)
    )


def _pytest_django_user_enrollment(index, path, function, secret):
    """Locate one unpatched, direct enrollment using only the fixture provider."""
    calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "create_user"
    ]
    if len(calls) != 1:
        return None
    call = calls[0]
    if not _pytest_django_user_enrollment_arguments(call, secret):
        return None
    model = call.func.value.value
    provider_names = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Name) and node.id == "django_user_model"
    ]
    parent = index["source"].parents[path].get(id(call))
    if (
        provider_names != [model]
        or parent not in function.body
        or _pytest_django_user_provider_patched(function)
    ):
        return None
    return call


def _pytest_django_user_enrollment_arguments(call, secret):
    match call:
        case ast.Call(
            func=ast.Attribute(
                value=ast.Attribute(
                    value=ast.Name(id="django_user_model"), attr="objects"
                ),
                attr="create_user",
            ),
            args=[],
        ):
            pass
        case _:
            return False
    passwords = [item.value for item in call.keywords if item.arg == "password"]
    return (
        len(passwords) == 1
        and isinstance(passwords[0], ast.Name)
        and passwords[0].id == secret
    )


def _pytest_django_user_configuration(index, path, function):
    """Co-select the declared fixture provider, pytest configuration and settings."""
    captured = index["configuration_bytes"]
    provider = captured_pytest_django_provider(captured)
    active_groups = {
        "project.dependencies",
        "tool.poetry.dependencies",
        "tool.poetry.group.dev.dependencies",
        "dependency-groups.dev",
    }
    if not provider or not any(
        item.get("group") in active_groups
        for item in provider.get("declarations", ())
        if isinstance(item, dict)
    ):
        return None
    config_names = {
        "pytest.toml",
        ".pytest.toml",
        "pytest.ini",
        ".pytest.ini",
        "pyproject.toml",
        "setup.cfg",
    }
    selected = captured_pytest_configuration(
        {name: raw for name, raw in captured.items() if name in config_names},
        source_role_only=True,
    )
    if selected is None:
        return None
    settings = selected["options"].get("DJANGO_SETTINGS_MODULE")
    if not isinstance(settings, str):
        return None
    if not all(part.isidentifier() for part in settings.split(".")):
        return None
    if not _pytest_django_user_collection_selected(index, path, function, selected):
        return None
    return provider, selected, settings


def _pytest_django_user_collection_selected(index, path, function, selected):
    source = index["source"]
    relative = source.relative(path)
    options = selected["options"] if selected is not None else {}
    if (
        not isinstance(relative, str)
        or not _pytest_name_matches(
            relative.rsplit("/", 1)[-1],
            _pytest_patterns_from_options(options)["python_files"],
        )
        or not _pytest_name_matches(
            function.name, _pytest_patterns_from_options(options)["python_functions"]
        )
        or any(
            name == "pytest_django.py" or name.startswith("pytest_django/")
            for name in (source.relative(item) for item in index["modules"])
        )
    ):
        return False
    return True


def _pytest_django_user_settings(index, settings_path, scope_dynamic):
    """Close the captured settings namespace around Django's default user model."""
    settings_tree = index["modules"].get(settings_path)
    if settings_tree is None or not index["source"].validate(settings_path):
        return False
    installed_apps = _pytest_django_installed_apps(settings_tree)
    return (
        installed_apps is not None
        and "django.contrib.auth" in installed_apps
        and _pytest_django_default_user_closed(settings_tree)
        and not scope_dynamic(
            index, settings_path, settings_tree, tuple(ast.walk(settings_tree))
        )
    )


def _pytest_django_installed_apps(settings_tree):
    installed_rows = (
        [
            node
            for node in settings_tree.body
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            and any(
                isinstance(target, ast.Name) and target.id == "INSTALLED_APPS"
                for target in (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
            )
        ]
        if settings_tree is not None
        else []
    )
    return (
        _pytest_literal_setting_values(
            settings_tree,
            installed_rows[0].value,
        )
        if len(installed_rows) == 1 and isinstance(installed_rows[0], ast.Assign)
        else None
    )


def _pytest_django_user_receipt(
    index, path, settings_path, provider, selected, settings
):
    source = index["source"]
    return {
        "schema": "factory.pytest-django-user-fixture.v1",
        "fixture": "django_user_model",
        "provider": "pytest-django",
        "provider_declaration": {
            key: provider[key] for key in ("path", "sha256", "provider")
        },
        "configuration": {
            key: selected["identity"][key] for key in ("path", "sha256", "bytes")
        },
        "test": {"path": source.relative(path), "sha256": source.inventory[path]},
        "settings_module": settings,
        "settings": {
            "path": source.relative(settings_path),
            "sha256": source.inventory[settings_path],
        },
        "database_semantics": "pytest-django-django_user_model-requires-db",
        "runtime_effects_unassessed": [
            option
            for option in ("--reuse-db", "--pdbcls")
            if option in str(selected["options"].get("addopts", ""))
        ],
        "execution_status": "NOT_EXECUTED",
        "runtime_assurance": "UNASSESSED",
    }


def _pytest_literal_setting_values(tree, expression, seen=()):
    """Resolve only stable module-local string collections and concatenations."""
    if isinstance(expression, ast.Constant) and isinstance(expression.value, str):
        return (expression.value,)
    if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
        values = [
            _pytest_literal_setting_values(tree, item, seen) for item in expression.elts
        ]
        return (
            tuple(value for group in values for value in group)
            if all(group is not None for group in values)
            else None
        )
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Add):
        left = _pytest_literal_setting_values(tree, expression.left, seen)
        right = _pytest_literal_setting_values(tree, expression.right, seen)
        return left + right if left is not None and right is not None else None
    if not isinstance(expression, ast.Name) or expression.id in seen:
        return None
    name = expression.id
    rows = [
        statement
        for statement in tree.body
        if isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and statement.targets[0].id == name
    ]
    stores = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    if len(rows) != 1 or stores != [rows[0].targets[0]]:
        return None
    return _pytest_literal_setting_values(tree, rows[0].value, (*seen, name))


def _pytest_django_user_provider_patched(function):
    for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
        if getattr(call.func, "attr", None) not in {"patch", "setattr"}:
            continue
        values = [
            node.value
            for node in ast.walk(call)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        ]
        if not values or any(
            "django.contrib.auth" in value or "create_user" in value for value in values
        ):
            return True
    return False


def _pytest_django_fixture_namespace_closed(index, path, scope_dynamic):
    """Reject applicable fixture replacement, autouse effects and plugin injection."""
    source, modules = index["source"], index["modules"]
    parts = source.relative(path).split("/")
    for offset in range(len(parts) + 1):
        selected = (
            path
            if offset == len(parts)
            else source.root.joinpath(*parts[:offset], "conftest.py")
        )
        if selected in modules and (
            any(
                scope_dynamic(index, selected, owner, tuple(ast.walk(owner)))
                for owner in ast.walk(modules[selected])
                if isinstance(
                    owner, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)
                )
            )
            or not _pytest_django_fixture_scope_closed(source, modules, selected, path)
        ):
            return False
    return True


def _pytest_django_fixture_scope_closed(source, modules, selected, path):
    from .credential_role_constructor_provider import binding_occurrences

    tree = modules[selected]
    protected = {
        "django_user_model",
        "db",
        "django_db",
        "django_db_setup",
        "django_db_modify_db_settings",
        "django_db_blocker",
    }
    if any(
        binding_occurrences(tree.body, name) for name in protected | {"pytest_plugins"}
    ):
        return False
    aliases = {}
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom):
            if any(item.name in {"*", "pytest_plugins"} for item in statement.names):
                return False
            if statement.module == "pytest":
                aliases.update(
                    (item.asname or item.name, "pytest." + item.name)
                    for item in statement.names
                    if item.name == "fixture"
                )
        elif isinstance(statement, ast.Import):
            aliases.update(
                (item.asname or item.name.split(".")[0], "pytest")
                for item in statement.names
                if item.name == "pytest"
            )
    return _pytest_django_fixture_definitions_closed(
        tree, selected, path, protected, aliases
    )


def _pytest_django_fixture_definitions_closed(tree, selected, path, protected, aliases):
    for statement in tree.body:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)) and any(
            isinstance(node, ast.Name) and node.id == "pytest_plugins"
            for node in ast.walk(statement)
        ):
            return False
        if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if statement.name in protected and selected != path:
            return False
        for decorator in statement.decorator_list:
            if not _pytest_protected_fixture(statement, decorator, aliases, protected):
                continue
            return False
    return True


def _pytest_protected_fixture(statement, decorator, aliases, protected):
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    canonical = (
        aliases.get(target.id)
        if isinstance(target, ast.Name)
        else aliases.get(target.value.id) + "." + target.attr
        if isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Name)
        and target.value.id in aliases
        else None
    )
    if canonical != "pytest.fixture":
        return False
    name = statement.name
    if isinstance(decorator, ast.Call):
        for keyword in decorator.keywords:
            if keyword.arg == "name":
                if not isinstance(keyword.value, ast.Constant) or not isinstance(
                    keyword.value.value, str
                ):
                    return True
                name = keyword.value.value
            if keyword.arg == "autouse" and keyword.value is not None:
                if (
                    not isinstance(keyword.value, ast.Constant)
                    or type(keyword.value.value) is not bool
                    or keyword.value.value
                ):
                    return True
    return name in protected


def _pytest_django_default_user_closed(tree):
    protected = {"AUTH_USER_MODEL", "DATABASE_ROUTERS"}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and node.id in protected
            or isinstance(node, ast.Attribute)
            and node.attr in protected
            or isinstance(node, ast.Constant)
            and node.value in protected
            or isinstance(node, ast.ImportFrom)
            and any(item.name == "*" or item.name in protected for item in node.names)
        ):
            return False
    return True


def _distribution_project_declarations(
    project, distribution, *, include_optional=False
):
    """Read required project/Poetry declarations; optional groups cannot supply providers."""
    if not isinstance(project, dict):
        return None
    declarations = _distribution_project_metadata(
        project.get("project", {}), distribution, include_optional
    )
    tools = project.get("tool", {})
    if declarations is None or not isinstance(tools, dict):
        return None
    dependency_groups = _distribution_dependency_groups(
        project.get("dependency-groups", {}), distribution, include_optional
    )
    if dependency_groups is None:
        return None
    poetry = _distribution_poetry_declarations(tools.get("poetry", {}), distribution)
    if poetry is None:
        return None
    return declarations + dependency_groups + poetry


def _distribution_dependency_groups(groups, distribution, include_optional):
    if not isinstance(groups, dict):
        return None
    declarations = []
    for group, values in groups.items():
        found = _distribution_declarations(
            values, "dependency-groups." + group, distribution
        )
        if found is None:
            return None
        if include_optional:
            declarations.extend(found)
    return declarations


def _distribution_project_metadata(metadata, distribution, include_optional):
    if not isinstance(metadata, dict):
        return None
    declarations = []
    for field, group in (
        ("dependencies", "project.dependencies"),
        ("optional-dependencies", "project.optional-dependencies"),
    ):
        values = metadata.get(field, [] if field == "dependencies" else {})
        if field == "dependencies":
            if not isinstance(values, list) or not all(
                isinstance(item, str) for item in values
            ):
                return None
            found = _distribution_declarations(values, group, distribution)
            if found is None:
                return None
            declarations.extend(found)
            continue
        if not isinstance(values, dict):
            return None
        for subgroup, items in values.items():
            found = _distribution_declarations(
                items, group + "." + subgroup, distribution
            )
            if found is None:
                return None
            if include_optional:
                declarations.extend(found)
    return declarations


def _distribution_poetry_declarations(poetry, distribution):
    groups = _distribution_poetry_groups(poetry, distribution)
    if groups is None:
        return None
    declarations = []
    for group, values in groups:
        if not isinstance(values, dict):
            return None
        for name, constraint in values.items():
            if not isinstance(name, str) or _distribution_name(name) != distribution:
                continue
            if not isinstance(constraint, str) or not re.fullmatch(
                r"(?:\*|[\^~<>=!0-9][0-9.*,+<>=!~^| -]*)", constraint.strip()
            ):
                return None
            declarations.append(
                {"group": group, "requirement": f"{distribution} {constraint}"}
            )
    return declarations


def _distribution_poetry_groups(poetry, distribution):
    if not isinstance(poetry, dict) or not isinstance(poetry.get("group", {}), dict):
        return None
    groups = [
        ("tool.poetry.dependencies", poetry.get("dependencies", {})),
        ("tool.poetry.dev-dependencies", poetry.get("dev-dependencies", {})),
    ]
    for name, group in poetry.get("group", {}).items():
        if (
            not isinstance(group, dict)
            or type(group.get("optional", False)) is not bool
        ):
            return None
        dependencies = group.get("dependencies", {})
        if not isinstance(dependencies, dict):
            return None
        if group.get("optional", False) is False:
            groups.append(("tool.poetry.group." + name + ".dependencies", dependencies))
        elif distribution in {
            _distribution_name(key) for key in dependencies if isinstance(key, str)
        }:
            return None
    return groups


def _distribution_name(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]*", value
    ):
        return None
    return re.sub(r"[-_.]+", "-", value).lower()


def _distribution_candidate(line):
    match = (
        re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if isinstance(line, str)
        else None
    )
    return _distribution_name(match.group(1)) if match else None


def _distribution_requirement(line, distribution):
    match = (
        re.fullmatch(
            r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\s*([<>=!~][A-Za-z0-9.*,+<>=!~ -]*))?\s*",
            line,
        )
        if isinstance(line, str)
        else None
    )
    return bool(match and _distribution_name(match.group(1)) == distribution)


def _distribution_declarations(lines, group, distribution):
    declarations = []
    for line in lines:
        candidate = _distribution_candidate(line)
        if candidate == distribution:
            if not _distribution_requirement(line, distribution):
                return None
            declarations.append({"group": group, "requirement": line.strip()})
    return declarations


def _distribution_requirement_file(text, distribution):
    lines = text.splitlines()
    if any(
        line.strip().startswith(
            ("-r", "--requirement", "-c", "--constraint", "-e", "--editable")
        )
        for line in lines
    ):
        return None
    return _distribution_declarations(lines, "requirements.txt", distribution)


def _pytest_django_project_declarations(project):
    return _distribution_project_declarations(project, "pytest-django") or []


def _pytest_django_requirement(line):
    return _distribution_requirement(line, "pytest-django")


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


def captured_pytest_helpers():
    """Bind live parser predicates and immutable policies into cache epochs."""
    return tuple(
        value
        for name, value in globals().items()
        if callable(value) and getattr(value, "__module__", None) == __name__
    ) + (
        _PYTEST_ARGUMENT_EFFECTS,
        DJANGO_IMPLICIT_KEY_EFFECTS,
        DJANGO_IMPLICIT_KEY_METHODS,
        yaml.compose,
        yaml.Loader,
        yaml.MappingNode,
        yaml.SequenceNode,
        yaml.ScalarNode,
        shlex.split,
        shlex.shlex,
    )


def _setup_cfg_allows_static_selection(captured):
    setup_cfg = captured.get("setup.cfg")
    if setup_cfg is not None:
        if not isinstance(setup_cfg, bytes):
            return False
        sections = _distribution_setup_cfg_sections(setup_cfg)
        if sections is None:
            return False
        if any(
            section in sections
            for section in ("options", "options.packages", "options.packages.find")
        ):
            return False
    return True


def _distribution_selection_excludes_source(captured, path):
    """Resolve an exclusion only from a supported captured build configuration."""
    if not _setup_cfg_allows_static_selection(captured):
        return None
    raw = captured.get("pyproject.toml")
    if raw is not None and not isinstance(raw, bytes):
        return None
    document = _distribution_toml_document(raw) if raw is not None else {}
    if document is None:
        return None
    build_system = document.get("build-system", {})
    if not isinstance(build_system, dict):
        return None
    backend = build_system.get("build-backend")
    if backend == "hatchling.build":
        if "hatch.toml" in captured:
            return None
        return _hatch_default_wheel_scope(captured, document, raw, path)
    if backend not in {
        "setuptools.build_meta",
        "setuptools.build_meta:__legacy__",
        None,
    }:
        return None
    if raw is None:
        setup_py = captured.get("setup.py")
        return _package_scope_proof(
            "setup.py", setup_py, _literal_setup_packages(setup_py), path.parts
        )
    if backend is None or "setup.py" in captured:
        return None
    return _setuptools_distribution_exclusion(document, raw, path)


def _setuptools_distribution_exclusion(document, raw, path):
    tool = document.get("tool")
    if not isinstance(tool, dict):
        return None
    setuptools = tool.get("setuptools")
    if not isinstance(setuptools, dict):
        return None
    if not _setuptools_package_data_is_bounded(setuptools):
        return None
    if "packages" in setuptools and isinstance(setuptools["packages"], list):
        packages = setuptools["packages"]
        if "package-dir" in setuptools or not all(
            isinstance(item, str) and item for item in packages
        ):
            return None
        return _package_scope_proof(
            "pyproject.toml", raw, packages, path.parts, "setuptools_static_packages"
        )
    packages = setuptools.get("packages")
    if isinstance(packages, dict) and set(packages) - {"find"}:
        return None
    find = packages.get("find") if isinstance(packages, dict) else None
    if not isinstance(find, dict):
        return None
    if (
        set(find) - {"include", "exclude", "where", "namespaces"}
        or type(find.get("namespaces", True)) is not bool
    ):
        return None
    if "package-dir" in setuptools:
        return _setuptools_mapped_root_exclusion(
            setuptools["package-dir"], find, path, raw
        )
    return _setuptools_find_exclusion(find, path, raw)


def _setuptools_mapped_root_exclusion(mapping, find, path, raw):
    if not isinstance(mapping, dict) or set(mapping) != {""}:
        return None
    root = mapping[""]
    if not (
        isinstance(root, str)
        and re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", root) is not None
        and find.get("where") == [root]
        and _setuptools_find_inputs(find) is not None
    ):
        return None
    # Inside the source root, an omitted package can still ship as package data.
    if PurePosixPath(path.as_posix().casefold()).is_relative_to(root.casefold()):
        return None
    return _manifest_scope_proof("pyproject.toml", raw, "setuptools_mapped_source_root")


def _setuptools_find_inputs(find):
    include = find.get("include", ["*"])
    exclude = find.get("exclude", [])
    where = find.get("where", ["."])
    if not all(
        isinstance(items, list) and all(isinstance(x, str) for x in items)
        for items in (include, exclude, where)
    ):
        return None
    roots = [PurePosixPath(root.replace("\\", "/")) for root in where]
    if any(
        root.is_absolute()
        or ".." in root.parts
        or root.as_posix().startswith("/")
        or re.match(r"^[A-Za-z]:", root.as_posix())
        for root in roots
    ):
        return None
    return roots, include, exclude


def _setuptools_find_exclusion(find, path, raw):
    inputs = _setuptools_find_inputs(find)
    if inputs is None:
        return None
    roots, include, exclude = inputs
    matched_root = False
    for root in roots:
        try:
            relative = path if root == PurePosixPath(".") else path.relative_to(root)
        except ValueError:
            continue
        package_parts = relative.parts[:-1]
        if not package_parts:
            return None
        matched_root = True
        package = ".".join(package_parts)
        if any(fnmatchcase(package, pattern) for pattern in exclude):
            continue
        if include and not any(fnmatchcase(package, pattern) for pattern in include):
            continue
        return None
    basis = (
        "setuptools_package_name_filter" if matched_root else "setuptools_find_roots"
    )
    return _manifest_scope_proof("pyproject.toml", raw, basis)


@lru_cache(maxsize=32)
def _distribution_toml_document(raw):
    if not isinstance(raw, bytes):
        return None
    try:
        return tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, TypeError):
        return None


@lru_cache(maxsize=32)
def _distribution_setup_cfg_sections(raw):
    if not isinstance(raw, bytes):
        return None
    parser = configparser.ConfigParser()
    try:
        parser.read_string(raw.decode("utf-8"))
    except (UnicodeError, configparser.Error):
        return None
    return frozenset(parser.sections())


def captured_hatch_wheel_roots(raw):
    """Read explicit Hatch wheel package roots, with no file or hook overrides."""
    document = _distribution_toml_document(raw) or {}
    system = document.get("build-system")
    if not isinstance(system, dict) or system.get("build-backend") != "hatchling.build":
        return ()
    if set(system) != {"requires", "build-backend"} or system.get("requires") != [
        "hatchling"
    ]:
        return ()
    settings = document
    for key in ("tool", "hatch", "build", "targets", "wheel"):
        settings = settings.get(key)
        if not isinstance(settings, dict):
            return ()
        next_key = {
            "hatch": "build",
            "build": "targets",
            "targets": "wheel",
            "wheel": "packages",
        }.get(key)
        if next_key and set(settings) != {next_key}:
            return ()
    packages = settings["packages"]
    if (
        not isinstance(packages, list)
        or not packages
        or not all(
            isinstance(p, str)
            and re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", p)
            for p in packages
        )
    ):
        return ()
    return tuple(PurePosixPath(package) for package in packages)


def captured_unpacked_consumer(root_raw, consumer_raw):
    root = _distribution_toml_document(root_raw) or {}
    consumer = _distribution_toml_document(consumer_raw) or {}
    project, local = root.get("project"), consumer.get("project")
    tools = consumer.get("tool")
    uv = tools.get("uv") if isinstance(tools, dict) else None
    if not all(isinstance(row, dict) for row in (project, local, uv)):
        return False
    name = _distribution_name(project.get("name"))
    if (
        not name
        or not _distribution_name(local.get("name"))
        or name == _distribution_name(local.get("name"))
    ):
        return False
    return uv.get("package") is False and bool(
        captured_distribution_provider({"pyproject.toml": consumer_raw}, name)
    )


def _hatch_default_wheel_scope(captured, document, raw, path):
    project = document.get("project")
    name = project.get("name") if isinstance(project, dict) else None
    if not isinstance(name, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]*", name
    ):
        return None
    tool = document.get("tool")
    hatch = tool.get("hatch") if isinstance(tool, dict) else None
    build = hatch.get("build", {}) if isinstance(hatch, dict) else None
    targets = build.get("targets", {}) if isinstance(build, dict) else None
    sdist = targets.get("sdist", {}) if isinstance(targets, dict) else None
    if (
        not isinstance(build, dict)
        or set(build) - {"targets"}
        or not isinstance(targets, dict)
        or set(targets) - {"sdist"}
        or not isinstance(sdist, dict)
    ):
        return None
    package = re.sub(r"[-_.]+", "_", name).lower()
    selected = next(
        (
            candidate
            for candidate in (
                PurePosixPath(package, "__init__.py"),
                PurePosixPath("src", package, "__init__.py"),
                PurePosixPath(package + ".py"),
            )
            if isinstance(captured.get(candidate.as_posix()), bytes)
        ),
        None,
    )
    if selected is not None:
        selected_roots = [selected.parent] if selected.name == "__init__.py" else []
        selected_files = {selected}
    else:
        selected_roots = sorted(
            {
                candidate.parent
                for candidate in (
                    PurePosixPath(relative.replace("\\", "/"))
                    for relative in captured
                    if isinstance(relative, str)
                )
                if candidate.name == "__init__.py"
                and candidate.parent.name == package
                and len(candidate.parent.parts) > 1
                and isinstance(captured.get(candidate.as_posix()), bytes)
            }
        )
        selected_files = set()
    if not selected_roots and not selected_files:
        return None
    if any(path == root or root in path.parents for root in selected_roots):
        return None
    if path in selected_files:
        return None
    return _manifest_scope_proof(
        "pyproject.toml", raw, "hatch_default_project_name_wheel_heuristic"
    )


def _literal_setup_packages(raw):
    if not isinstance(raw, bytes):
        return None
    try:
        tree = ast.parse(raw.decode("utf-8"))
    except (UnicodeError, SyntaxError, ValueError):
        return None
    imported = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module in {"setuptools", "distutils.core"}
        for alias in node.names
        if alias.name == "setup"
    }
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in imported
    ]
    if (
        len(calls) != 1
        or not any(
            isinstance(statement, ast.Expr) and statement.value is calls[0]
            for statement in tree.body
        )
        or any(
            keyword.arg is None
            or keyword.arg
            in {
                "package_dir",
                "py_modules",
                "data_files",
                "scripts",
                "script_files",
                "package_data",
                "include_package_data",
            }
            for keyword in calls[0].keywords
        )
        or any(
            isinstance(node, ast.Name)
            and node.id in imported
            and isinstance(node.ctx, (ast.Store, ast.Del))
            for node in ast.walk(tree)
        )
    ):
        return None
    values = [
        keyword.value for keyword in calls[0].keywords if keyword.arg == "packages"
    ]
    if len(values) != 1 or not isinstance(values[0], ast.List):
        return None
    packages = [item.value for item in values[0].elts if isinstance(item, ast.Constant)]
    return (
        packages
        if len(packages) == len(values[0].elts)
        and all(isinstance(item, str) for item in packages)
        else None
    )


def _setuptools_package_data_is_bounded(setuptools):
    """Validate data options without treating them as package-selection inputs."""
    allowed = {
        "packages",
        "package-dir",
        "include-package-data",
        "package-data",
        "exclude-package-data",
    }
    if set(setuptools) - allowed:
        return False
    include_data = setuptools.get("include-package-data")
    if include_data is not None and type(include_data) is not bool:
        return False
    for key in ("package-data", "exclude-package-data"):
        mapping = setuptools.get(key, {})
        if not isinstance(mapping, dict):
            return False
        for package, patterns in mapping.items():
            if (
                not isinstance(package, str)
                or not isinstance(patterns, list)
                or not all(isinstance(pattern, str) for pattern in patterns)
            ):
                return False
            for pattern in patterns:
                normalized = pattern.replace("\\", "/")
                path = PurePosixPath(normalized)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or re.match(r"^[A-Za-z]:", normalized)
                ):
                    return False
    # These options affect files in selected packages; they do not add package
    # names. Other distribution inputs remain unsupported.
    return True


def _package_scope_proof(
    path, raw, packages, parts, basis="setuptools_static_packages"
):
    if packages is None or not all(
        isinstance(package, str)
        and package
        and all(part.isidentifier() for part in package.split("."))
        for package in packages
    ):
        return None
    candidate = ".".join(parts[:-1])
    if any(
        candidate == package or candidate.startswith(package + ".")
        for package in packages
    ):
        return None
    return _manifest_scope_proof(path, raw, basis)


def _manifest_scope_proof(path, raw, basis):
    if not isinstance(raw, bytes):
        return None
    return {"path": path, "sha256": hashlib.sha256(raw).hexdigest(), "basis": basis}
