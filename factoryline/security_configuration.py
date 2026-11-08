"""Read bounded Python AST evidence for selected security configurations."""

from __future__ import annotations

import ast
import hashlib
import json
import re
from functools import lru_cache
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath


_SCOPE_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_CONTROL_TYPES = tuple(
    getattr(ast, n) for n in "If For AsyncFor While Try With AsyncWith Match".split()
)
_DEFERRED_TYPES = tuple(
    getattr(ast, n) for n in "Lambda ListComp SetComp DictComp GeneratorExp".split()
)


def _canonical(node, aliases, expression=None):
    from .review_integrity import (
        _security_flow_bindings,
        _security_scope_request_aliases,
    )
    from .review_audits import _name

    if expression is None:
        resolved, _ = _security_flow_bindings(node, aliases)
    else:
        resolved = _security_scope_request_aliases(
            getattr(node, "_security_lexical_scope", None),
            aliases,
            getattr(node, "_security_flow_statement", None),
        )
    raw = _name(node.func if expression is None else expression)
    head, _, tail = raw.partition(".")
    if head not in resolved or _relative_binding(node, head):
        return ""
    reference = resolved[head]
    return (
        raw
        if raw == reference or raw.startswith(reference + ".")
        else reference + ("." + tail if tail else "")
    )


def _relative_binding(node, head):
    from .review_integrity import _security_module_scope, _security_scope_body
    from .review_audits import _bound_names

    scope = getattr(node, "_security_lexical_scope", None)
    module = _security_module_scope(scope)
    for owner in (scope, module):
        relative = None
        for statement in _security_scope_body(owner):
            if owner is scope and statement is getattr(
                node, "_security_flow_statement", None
            ):
                break
            if isinstance(
                statement, (ast.Import, ast.ImportFrom)
            ) and head in _bound_names(statement):
                relative = bool(getattr(statement, "level", 0))
        if relative is not None:
            return relative
    return False


def _expanded(node):
    return any(isinstance(arg, ast.Starred) for arg in node.args) or any(
        kw.arg is None for kw in node.keywords
    )


def _keyword(call, name, position=None):
    value = next((item.value for item in call.keywords if item.arg == name), None)
    if value is None and position is not None and len(call.args) > position:
        return call.args[position]
    return value


def _literal_bool(node):
    value = getattr(node, "value", None)
    return value if type(value) is bool else None


_SOURCE_ROLE_COMPONENTS = frozenset(
    {
        "test",
        "tests",
        "example",
        "examples",
        "example_projects",
        "demo",
        "demo_project",
        "demos",
        "archive",
    }
)


def source_role_distribution_domain(
    captured, relative, *, line=None, credential_name=None
):
    """Resolve source-role authority from bound package or archive evidence."""
    if not isinstance(captured, dict) or not isinstance(relative, str):
        return None
    normalized = relative.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        return None
    path = PurePosixPath(normalized)
    parts = path.parts
    if path.is_absolute() or ".." in parts or path.suffix.lower() != ".py":
        return None
    role = next(
        (
            part.lower()
            for part in parts[:-1]
            if part.lower() in _SOURCE_ROLE_COMPONENTS
        ),
        None,
    )
    if role is None:
        return None
    if role == "archive":
        redaction = _archive_redaction_domain(
            captured, path, line=line, credential_name=credential_name
        )
        if redaction is not None:
            return redaction
    proof = _distribution_selection_excludes_source(captured, path)
    if proof is None:
        return None
    return {
        "schema": "factory.security.source-role-package-scope.v1",
        "role": role,
        "application_authority": "UNKNOWN",
        "proof_scope": "source_bound_distribution_package_selection",
        "package_scope": "EXCLUDED_FROM_CAPTURED_STATIC_PACKAGE_SELECTION",
        "selection_basis": proof["basis"],
        "claim_boundary": "Package selection only; repository source may still be runnable.",
        "candidate_path": path.as_posix(),
        "manifest_path": proof["path"],
        "manifest_sha256": proof["sha256"],
        "supporting_sources": {proof["path"]: proof["sha256"]},
    }


def selected_django_credential_domain(
    identity, context, path, observation, selected, finding, index
):
    domain = identity.django_test_domain_evidence(context, path, observation, selected)
    return domain or source_role_distribution_domain(
        context.get("captured", {}),
        index.relative(path),
        line=finding.get("line"),
        credential_name=(finding.get("facts") or {}).get("name"),
    )


def source_role_context_fallback(
    finding, bound, credential_evidence, generated, context, source_bindings
):
    if not (
        (
            (generated is None and credential_evidence is None)
            or (
                isinstance(generated, dict)
                and generated.get("authority_domain") is None
            )
        )
        and bound
        and finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and isinstance(finding.get("facts"), dict)
        and isinstance(finding["facts"].get("name"), str)
        and isinstance(context, dict)
        and isinstance(source_bindings, dict)
    ):
        return None
    index = context.get("index")
    path = Path(finding.get("path", ""))
    if index is None or not index.validate(path):
        return None
    domain = source_role_distribution_domain(
        context.get("captured", {}),
        index.relative(path),
        line=finding.get("line"),
        credential_name=finding["facts"]["name"],
    )
    supporting = domain.get("supporting_sources") if isinstance(domain, dict) else None
    if (
        not isinstance(supporting, dict)
        or not supporting
        or any(
            source_bindings.get(source) != digest
            for source, digest in supporting.items()
        )
    ):
        return None
    observation = {
        "schema": "factory.security.source-role-context-observation.v1",
        "proof_scope": domain["proof_scope"],
        "credential_key": finding["facts"]["name"],
        "source_role": domain["role"],
        "authority_domain": domain,
        "supporting_sources": [
            {"path": source, "sha256": digest}
            for source, digest in sorted(supporting.items())
        ],
    }
    if generated is not None:
        observation["selected_framework_observation"] = generated
    return (
        "NEEDS_CONTEXT",
        domain["proof_scope"],
        {"credential_authority_observation": observation},
    )


def source_role_tier_override(
    finding, bound, credential_evidence, context, source_bindings
):
    from .credential_endpoint_admission import operative_signing_default_evidence

    generated = (
        operative_signing_default_evidence(finding, context)
        if bound and credential_evidence is None and context is not None
        else None
    )
    fallback = source_role_context_fallback(
        finding, bound, credential_evidence, generated, context, source_bindings
    )
    return generated, fallback


def source_role_capture_context(source_bytes, bindings, context):
    support = getattr(source_bytes, "source_role_sources", {})
    if not (
        isinstance(support, dict)
        and all(
            isinstance(path, str)
            and isinstance(raw, bytes)
            and len(raw) <= 1_000_000
            and (
                path not in bindings
                or hashlib.sha256(raw).hexdigest() == bindings[path]
            )
            for path, raw in support.items()
        )
    ):
        support = {}
    role_bindings = dict(bindings)
    role_bindings.update(
        {path: hashlib.sha256(raw).hexdigest() for path, raw in support.items()}
    )
    role_context = context
    if (
        support
        and isinstance(context, dict)
        and isinstance(context.get("captured"), dict)
    ):
        role_context = {
            **context,
            "captured": {**context["captured"], **support},
        }
    return role_context, role_bindings


def _archive_redaction_domain(captured, path, *, line, credential_name):
    if (
        not isinstance(line, int)
        or not isinstance(credential_name, str)
        or not re.search(
            r"secret|password|token|credential|api[_-]?key|private[_-]?key",
            credential_name,
            re.IGNORECASE,
        )
    ):
        return None
    candidate_path = path.as_posix()
    source = captured.get(candidate_path)
    manifest = captured.get("archive/manifest.json")
    readme = captured.get("archive/README.md")
    if not all(isinstance(raw, bytes) for raw in (source, manifest, readme)):
        return None
    try:
        source_hash = hashlib.sha256(source).hexdigest()
        manifest_rows = json.loads(manifest)
        document = ast.parse(source.decode("utf-8"))
        readme_text = readme.decode("utf-8").lower()
    except (UnicodeDecodeError, SyntaxError, ValueError, TypeError):
        return None
    if not isinstance(manifest_rows, list) or not all(
        phrase in readme_text
        for phrase in ("historical source archive", "sanitized", "secret")
    ):
        return None
    manifest_row = next(
        (
            row
            for row in manifest_rows
            if isinstance(row, dict)
            and row.get("published") == candidate_path
            and row.get("published_sha256") == source_hash
            and isinstance(row.get("transformations"), list)
            and any(
                isinstance(item, str)
                and "secret" in item.lower()
                and re.search(r"(?:removed|redacted|sanitized)", item, re.I)
                for item in row["transformations"]
            )
        ),
        None,
    )
    if manifest_row is None:
        return None
    for node in ast.walk(document):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.lineno != line:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = {
            target.id if isinstance(target, ast.Name) else target.attr
            for root in targets
            for target in ast.walk(root)
            if isinstance(target, ast.Name | ast.Attribute)
        }
        value = node.value
        if (
            credential_name in names
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and re.fullmatch(
                r"[\[({<]\s*(?:removed|redacted|sanitized)"
                r"(?:[-_\s]+[A-Za-z][A-Za-z0-9]{0,23}){1,4}\s*[\])}>]",
                value.value,
                re.I,
            )
        ):
            return {
                "schema": "factory.security.source-role-archive-redaction.v1",
                "role": "archive",
                "application_authority": "UNKNOWN",
                "proof_scope": "source_bound_archive_redaction_manifest",
                "redaction": "DECLARED_SECRET_REMOVAL",
                "candidate_path": candidate_path,
                "candidate_sha256": source_hash,
                "credential_name": credential_name,
                "assignment_line": line,
                "manifest_path": "archive/manifest.json",
                "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                "documentation_path": "archive/README.md",
                "documentation_sha256": hashlib.sha256(readme).hexdigest(),
                "claim_boundary": (
                    "The captured archive manifest identifies this exact credential "
                    "assignment as sanitized; the raw finding remains and runtime "
                    "or deployment safety is unassessed."
                ),
                "supporting_sources": {
                    candidate_path: source_hash,
                    "archive/manifest.json": hashlib.sha256(manifest).hexdigest(),
                    "archive/README.md": hashlib.sha256(readme).hexdigest(),
                },
            }
    return None


def _distribution_selection_excludes_source(captured, path):
    setup_cfg = captured.get("setup.cfg")
    if setup_cfg is not None:
        if not isinstance(setup_cfg, bytes):
            return None
        sections = _distribution_setup_cfg_sections(setup_cfg)
        if sections is None:
            return None
        if any(
            section in sections
            for section in ("options", "options.packages", "options.packages.find")
        ):
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
    tool = document.get("tool")
    if not isinstance(tool, dict) or "setup.py" in captured:
        return None
    setuptools = tool.get("setuptools")
    if backend not in {
        "setuptools.build_meta",
        "setuptools.build_meta:__legacy__",
    } or not isinstance(setuptools, dict):
        return None
    if not _setuptools_package_data_is_bounded(setuptools):
        return None
    if "packages" in setuptools and isinstance(setuptools["packages"], list):
        packages = setuptools["packages"]
        if not all(isinstance(item, str) and item for item in packages):
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
    if set(find) - {"include", "exclude", "where", "namespaces"}:
        return None
    if "namespaces" in find and type(find["namespaces"]) is not bool:
        return None
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
    from .pytest_collection_audit import tomllib

    if not isinstance(raw, bytes):
        return None
    try:
        return tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, TypeError):
        return None


@lru_cache(maxsize=32)
def _distribution_setup_cfg_sections(raw):
    from .pytest_collection_audit import configparser

    if not isinstance(raw, bytes):
        return None
    parser = configparser.ConfigParser()
    try:
        parser.read_string(raw.decode("utf-8"))
    except (UnicodeError, configparser.Error):
        return None
    return frozenset(parser.sections())


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


def yaml_safe_loader(call, aliases):
    """Credit only an unmutated canonical safe loader in an exact argument slot."""
    from .semantic_credential_sensor import yaml_load_call_signature

    if not yaml_load_call_signature(call):
        return False
    loader = _keyword(call, "Loader", 1)
    if loader is None:
        return False
    selected = _canonical(call, aliases, loader)
    if selected not in {
        "yaml.SafeLoader",
        "yaml.CSafeLoader",
        "yaml.BaseLoader",
        "yaml.CBaseLoader",
        "yaml.loader.SafeLoader",
        "yaml.loader.BaseLoader",
        "yaml.cyaml.CSafeLoader",
        "yaml.cyaml.CBaseLoader",
    }:
        return False
    from .review_integrity import _security_module_scope
    from .semantic_credential_sensor import yaml_loader_provider_uncertain

    module = _security_module_scope(getattr(call, "_security_lexical_scope", None))
    if module is None:
        return False
    provider_nodes = tuple(ast.walk(module))
    if any(
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and _canonical(call, aliases, n.func.value) == selected
        for n in provider_nodes
    ):
        return False
    return not yaml_loader_provider_uncertain(module, aliases, selected)


def _environment_autoescape(call):
    if _expanded(call):
        return "dynamic"
    value = _keyword(call, "autoescape")
    if value is None and len(call.args) > 16:
        value = call.args[16]
    if value is None:
        return "omitted"
    if _literal_bool(value) is False:
        return "explicit_false"
    if _literal_bool(value) is True:
        return "explicit_true"
    return "dynamic"


def _record(code, node, message, **facts):
    return code, node, "MEDIUM", message, facts


def _jinja_assignment(node, environments, aliases):
    from .review_audits import _bound_names

    if not isinstance(node, (ast.Assign, ast.AnnAssign)):
        return
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    value = node.value
    for target in targets:
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            if target.attr == "autoescape" and target.value.id in environments:
                environments[target.value.id] = {
                    False: "explicit_false",
                    True: "explicit_true",
                }.get(_literal_bool(value), "dynamic")
    for target in _bound_names(node):
        environments.pop(target, None)
    if (
        isinstance(value, ast.Call)
        and _canonical(value, aliases) == "jinja2.Environment"
    ):
        for target in targets:
            if isinstance(target, ast.Name):
                environments[target.id] = _environment_autoescape(value)


def _jinja_load(node, environments):
    if not isinstance(node.func, ast.Attribute) or not isinstance(
        node.func.value, ast.Name
    ):
        return None
    setting = environments.get(node.func.value.id)
    if (
        node.func.attr != "get_template"
        or setting not in {"omitted", "explicit_false"}
        or not node.args
    ):
        return None
    template = node.args[0]
    if not isinstance(template, ast.Constant) or not isinstance(template.value, str):
        return None
    if not template.value.lower().endswith((".html", ".htm", ".xhtml")):
        return None
    return _record(
        "SECURITY_JINJA_AUTOESCAPE_DISABLED",
        node,
        "An HTML template is loaded with autoescape disabled; output context and input trust are unknown.",
        template=template.value,
        configuration=setting,
        input_trust="unknown",
        output_context="unknown",
        exploitability="not_established",
    )


def _jinja_records(tree, aliases):
    records = []
    for scope in [tree] + [n for n in ast.walk(tree) if isinstance(n, _SCOPE_TYPES)]:
        environments = {}
        for statement in scope.body:
            if isinstance(statement, _CONTROL_TYPES):
                environments.clear()
                continue
            if isinstance(statement, _SCOPE_TYPES):
                environments.pop(statement.name, None)
                continue
            if any(isinstance(n, _DEFERRED_TYPES) for n in ast.walk(statement)):
                environments.clear()
                continue
            for node in ast.walk(statement):
                if isinstance(node, ast.Call):
                    record = _jinja_load(node, environments)
                    if record:
                        records.append(record)
            _jinja_assignment(statement, environments, aliases)
    return records


def _xml_records(tree, passed_aliases):
    records = []
    aliases = passed_aliases
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _canonical(node, aliases)
        if name == "lxml.etree.XMLParser":
            if _literal_bool(_keyword(node, "resolve_entities")) is True:
                records.append(
                    _record(
                        "SECURITY_XML_ENTITY_RESOLUTION",
                        node,
                        "XML entity resolution is explicitly enabled; local input and exploitability are unknown.",
                        capability="resolve_entities",
                        configuration="explicit_true",
                        parser_no_network=_literal_bool(_keyword(node, "no_network")),
                        input_trust="unknown",
                        exploitability="not_established",
                    )
                )
        elif name == "lxml.etree.XSLTAccessControl":
            unknown_kwargs = _expanded(node)
            if unknown_kwargs:
                continue
            for index, capability in ((0, "read_file"), (3, "read_network")):
                value = _keyword(node, capability)
                if value is None and len(node.args) > index:
                    value = node.args[index]
                enabled = _literal_bool(value)
                defaulted = value is None and not unknown_kwargs
                if enabled is not True and not defaulted:
                    continue
                setting = (
                    "explicit_true" if enabled is True else "documented_default_enabled"
                )
                records.append(
                    _record(
                        "SECURITY_XSLT_EXTERNAL_ACCESS",
                        node,
                        "XSLT external resource access is enabled by configuration; stylesheet trust and runtime availability are unknown.",
                        capability=capability,
                        configuration=setting,
                        runtime_default_version_dependent=defaulted,
                        input_trust="unknown",
                        exploitability="not_established",
                    )
                )
    return records


def configuration_findings(tree, aliases, relative="<source>"):
    """Return conditional Jinja and lxml configuration findings for one AST."""
    from .review_audits import _security_finding

    from .review_integrity import bind_security_call_scopes

    if not any(v.startswith(("jinja2", "lxml")) for v in aliases.values()):
        return []
    if not hasattr(tree, "_security_scope_kind"):
        bind_security_call_scopes(tree)
    messages = _jinja_records(tree, aliases) + _xml_records(tree, aliases)
    return [
        _security_finding(code, relative, node, message, severity, **facts)
        for code, node, severity, message, facts in messages
    ]


def legacy_tls_verification_risk(call, node, aliases=None):
    """Delegate canonical client TLS configuration analysis to the semantic lane."""
    from .semantic_credential_sensor import legacy_tls_verification_risk as analyze

    return analyze(call, node, aliases)


def tls_finding(call, relative, node, aliases=None):
    """Preserve the existing TLS finding entry point and live helper identity."""
    from .semantic_credential_sensor import tls_finding as analyze

    return analyze(call, relative, node, aliases)
