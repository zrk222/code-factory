"""Deterministic quality checks for natural-language intent boundaries.

AI-authored text is untrusted input even when it appears in a signed or
hash-bound artifact.  A digest proves that text was not changed after it was
captured; it does not prove that the text was specific enough to test.  This
module supplies a small, dependency-free lexical guard for the places where
FactoryLine accepts intent, promises, requirements, or acceptance evidence.

The lexical guard is deliberately conservative and explainable: it rejects
known placeholders/vague phrases and statements that lack an action or (when
requested) an observable evidence signal. AST implementation contracts and
SQL provenance helpers remain available here through their established APIs.
A human still owns confirmation and an independent verifier still owns results.
"""

from __future__ import annotations

import ast
import configparser
from dataclasses import dataclass
from fnmatch import fnmatchcase
from hashlib import sha256
import os
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

from .implementation_audit import (  # noqa: F401
    _BoundSourceBytes,
    _bind_file_contracts,
    _bind_imported_base,
    _concrete_contract_method,
    _contract_body_nodes,
    _declared_stub_method,
    _function_rebinds_module_getattr,
    _group_decorator,
    _literal_method,
    _local_override,
    _method_contract,
    _null_io_contract,
    _placeholder_statement,
    _recognized_group,
    _scope_binds_name,
    _scope_statement_binds_name,
    _shadowed_error,
    _stable_api_origin,
    _stable_base_contract,
    _stable_import_index,
    _stable_import_contract,
    _track_import_binding,
    _stable_scope,
    _typing_io_base,
    _unsafe_project_bases,
    _walk_scope_nodes,
    bind_project_contracts,
    bound_snapshots,
    click_group_container,
    intentional_implementation_contract,
)


_PLACEHOLDER_RE = re.compile(
    r"\b(?:todo|tbd|n/?a|unknown|unspecified|fill\s+in|your\s+choice)\b|\?{2,}", re.I
)
_VAGUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("make_it_better", re.compile(r"\bmake\s+(?:it|this)\s+better\b", re.I)),
    ("do_something", re.compile(r"\bdo\s+something\b", re.I)),
    (
        "as_needed",
        re.compile(r"\bas\s+needed\b|\bas\s+appropriate\b|\bas\s+necessary\b", re.I),
    ),
    ("works", re.compile(r"\b(?:it|this|that)\s+works\b|\bshould\s+work\b", re.I)),
    ("fix_it", re.compile(r"\bfix\s+(?:it|this|that)\b", re.I)),
    ("etcetera", re.compile(r"\betc\.?\b|\band\s+so\s+on\b", re.I)),
    ("whatever", re.compile(r"\bwhatever\b|\banyhow\b", re.I)),
    ("stuff", re.compile(r"\bstuff\b|\bsomething\s+like\s+that\b", re.I)),
)

# These are deliberately words, not a parser.  They identify an action or a
# state transition without claiming that the sentence is semantically true.
_ACTION_RE = re.compile(
    r"\b(?:allow|approve|assert|block|build|call|capture|change|check|consume|"
    r"contain|create|delete|deny|detect|disable|display|emit|enable|equal|"
    r"fail|fetch|finish|generate|has|have|is|are|keep|list|measure|migrate|"
    r"must|never|notify|open|pass|prevent|produce|publish|record|reject|"
    r"release|remove|report|respond|return|run|save|show|start|stop|store|"
    r"succeed|succeeds|test|tests|update|updates|use|uses|validate|validates|"
    r"verify|verifies|visible|write|writes|work|works|fail|fails|reject|rejects|"
    r"record|records|recorded|produce|produces|receive|receives|receiving|"
    r"duplicate|release|releases|approve|approves|approval|run|runs|can|cannot|shall|will)\b",
    re.I,
)
_OBSERVABLE_RE = re.compile(
    r"\b(?:accept(?:ed|ance)?|actual|artifact|assert(?:ion)?|bound|check|"
    r"code|count|digest|error|event|exit|fail(?:ed|ure)?|file|hash|latency|"
    r"metric|output|pass(?:ed)?|proof|receipt|record(?:ed|ing|s)?|response|result|status|"
    r"timestamp|url|visible|within|under|over|equals?|contains?|rejected|"
    r"denied|created|updated|deleted|approved|approve|approval|rejected|visible)\b|sha-?256|given/when/then|\b\d+\b",
    re.I,
)


@dataclass(frozen=True)
class IntentFinding:
    """One deterministic reason a statement should not cross a gate."""

    code: str
    message: str

    def as_dict(self) -> dict[str, str]:
        """Return the stable code and human-readable explanation for a receipt."""
        return {"code": self.code, "message": self.message}


class IntentQualityError(ValueError):
    """Raised when a statement is too vague to bind to a proof gate."""

    def __init__(self, finding: IntentFinding):
        super().__init__(f"{finding.code}: {finding.message}")
        self.code = finding.code
        self.message = finding.message


def normalize(value: Any) -> str:
    """Normalize whitespace without changing the author's words."""
    return " ".join(value.split()) if isinstance(value, str) else ""


def assess(
    value: Any,
    *,
    field: str,
    require_action: bool = True,
    require_observable: bool = False,
) -> tuple[str, list[IntentFinding]]:
    """Return normalized text and deterministic clarity findings.

    This function intentionally returns findings instead of deciding whether a
    mission is safe.  Callers map the findings to their own stable error type
    and retain their existing human/authority boundaries.
    """
    text = normalize(value)
    findings: list[IntentFinding] = []
    if _PLACEHOLDER_RE.search(text):
        findings.append(
            IntentFinding(
                "INTENT_PLACEHOLDER",
                f"{field} contains a placeholder or unresolved value",
            )
        )
    for name, pattern in _VAGUE_PATTERNS:
        if pattern.search(text):
            findings.append(
                IntentFinding(
                    "INTENT_VAGUE_LANGUAGE", f"{field} contains vague phrase: {name}"
                )
            )
            break
    if require_action and not _ACTION_RE.search(text):
        findings.append(
            IntentFinding(
                "INTENT_NO_ACTION",
                f"{field} does not state an observable action or state transition",
            )
        )
    if require_observable and not _OBSERVABLE_RE.search(text):
        findings.append(
            IntentFinding(
                "INTENT_NOT_OBSERVABLE",
                f"{field} does not name observable evidence or an outcome boundary",
            )
        )
    return text, findings


def require_clear(
    value: Any,
    *,
    field: str,
    require_action: bool = True,
    require_observable: bool = False,
) -> str:
    """Normalize and fail closed on the first clarity finding."""
    text, findings = assess(
        value,
        field=field,
        require_action=require_action,
        require_observable=require_observable,
    )
    if findings:
        raise IntentQualityError(findings[0])
    return text


def findings_as_dict(
    value: Any,
    *,
    field: str,
    require_action: bool = True,
    require_observable: bool = False,
) -> list[dict[str, str]]:
    """Expose stable findings for receipts and diagnostics without raising."""
    _text, findings = assess(
        value,
        field=field,
        require_action=require_action,
        require_observable=require_observable,
    )
    return [finding.as_dict() for finding in findings]


# Static source contracts supplement the natural-language boundary checks.


def implementation_findings(relative, tree, data, context):
    """Apply project contracts only to empty-body findings, never other rules."""
    from .review_integrity import implementation_completeness_findings

    lines = (context or {}).get("implementation_contract_lines", ())
    return [
        f
        for f in implementation_completeness_findings(relative, tree, data)
        if f["code"] != "QUALITY_EMPTY_IMPLEMENTATION" or f["line"] not in lines
    ]


_SQL_CONNECTORS = {
    "mysql.connector.connect": "mysql.connector",
    "psycopg.connect": "psycopg",
    "sqlite3.connect": "sqlite3",
}


def sql_connection_driver(node, aliases, connections, scope_aliases, resolve_call):
    """Return a narrowly proven SQL connection driver for a call or name."""
    if isinstance(node, ast.Call):
        return _SQL_CONNECTORS.get(resolve_call(node, aliases))
    if not isinstance(node, ast.Name):
        return None
    for binding in connections:
        if (
            isinstance(binding, tuple)
            and len(binding) == 3
            and binding[0] == "sql-connection"
            and binding[2] == node.id
        ):
            return binding[1]
    if scope_aliases.get(node.id) == "django.db.connection":
        return "django"
    return None


def scoped_sql_connection_driver(
    node, aliases, connections, scope_aliases_for, resolve_call
):
    """Resolve a SQL connection after applying lexical import aliases."""
    scope = getattr(node, "_security_lexical_scope", None)
    statement = getattr(node, "_security_flow_statement", None)
    return sql_connection_driver(
        node,
        aliases,
        connections,
        scope_aliases_for(scope, aliases, statement),
        resolve_call,
    )


def sql_cursor_driver(node, aliases, connections, scope_aliases, resolve_call):
    """Return the proven driver for a cursor expression or tracked cursor name."""
    if isinstance(node, ast.Name):
        for binding in connections:
            if (
                isinstance(binding, tuple)
                and len(binding) == 3
                and binding[0] == "sql-cursor"
                and binding[2] == node.id
            ):
                return binding[1]
        return None
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return None
    if node.func.attr != "cursor":
        return None
    return sql_connection_driver(
        node.func.value, aliases, connections, scope_aliases, resolve_call
    )


def scoped_sql_driver(
    node,
    aliases,
    connections,
    cursors,
    helpers,
    scope_aliases_for,
    resolve_call,
    helper_call,
    call_leaf,
):
    """Resolve driver provenance for a SQL connection or cursor expression."""
    scope = getattr(node, "_security_lexical_scope", None)
    statement = getattr(node, "_security_flow_statement", None)
    scoped_aliases = scope_aliases_for(scope, aliases, statement)
    driver = sql_cursor_driver(node, aliases, cursors, scoped_aliases, resolve_call)
    if driver is None and helper_call(node, "cursor", aliases, helpers):
        return "mysql.connector"
    if driver is None and isinstance(node, ast.Call) and call_leaf(node) == "cursor":
        return sql_connection_driver(
            node.func.value, aliases, connections, scoped_aliases, resolve_call
        )
    return driver


def sql_return_kind(
    statement,
    aliases,
    helpers,
    connections,
    cursors,
    connection_driver,
    cursor_driver,
    helper_call,
):
    """Classify returned SQL connections and cursors using proven provenance."""
    if not isinstance(statement, ast.Return):
        return ""
    value = statement.value
    if isinstance(value, ast.Name):
        if value.id in connections:
            return "connection"
        if value.id in cursors:
            return "cursor"
    if connection_driver(value, aliases, connections) or helper_call(
        value, "connection", aliases, helpers
    ):
        return "connection"
    return (
        "cursor" if cursor_driver(value, aliases, connections, cursors, helpers) else ""
    )


def clear_sql_provenance(connection_names, cursor_names, bound_names):
    """Remove driver tags when ordinary flow rebinds a connection or cursor."""
    for names, tag in (
        (connection_names, "sql-connection"),
        (cursor_names, "sql-cursor"),
    ):
        names.difference_update(bound_names)
        names.difference_update(
            binding
            for binding in tuple(names)
            if isinstance(binding, tuple)
            and len(binding) == 3
            and binding[0] == tag
            and binding[2] in bound_names
        )


def bind_sql_provenance(
    connection_names, cursor_names, name, connection_driver, cursor_driver
):
    """Bind only the SQL object kinds proven by the current assignment."""
    if connection_driver:
        connection_names.update({name, ("sql-connection", connection_driver, name)})
    if cursor_driver:
        cursor_names.update({name, ("sql-cursor", cursor_driver, name)})


def track_sql_assignment(
    statement,
    aliases,
    helpers,
    connections,
    cursors,
    connection_driver,
    cursor_driver,
    helper_call,
):
    """Track a straight-line SQL connection/cursor assignment with rebinds."""
    if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
        return
    value = getattr(statement, "value", None)
    driver = connection_driver(value)
    cursor = cursor_driver(value)
    is_connection, is_cursor = _sql_assignment_kinds(
        value, aliases, helpers, driver, cursor, helper_call
    )
    driver = driver or ("mysql.connector" if is_connection else None)
    cursor = cursor or ("mysql.connector" if is_cursor else None)
    for name in _sql_assignment_names(statement):
        clear_sql_provenance(connections, cursors, {name})
        bind_sql_provenance(connections, cursors, name, driver, cursor)


def credential_password_request_value(
    node,
    password_fields,
    aliases,
    scope,
    flow_statement,
    flask_collection,
    django_request,
):
    """Recognize password fields read from proven Flask or Django request sources."""
    if isinstance(node, ast.Call):
        parts = _credential_get_source_key(node)
    elif isinstance(node, ast.Subscript):
        parts = node.value, node.slice
    else:
        return False
    if parts is None:
        return False
    request_value, key = parts
    if (
        not isinstance(key, ast.Constant)
        or not isinstance(key.value, str)
        or key.value.casefold() != "password"
    ):
        return False
    return _credential_request_collection(
        request_value,
        password_fields,
        flask_collection,
        aliases,
        scope,
        flow_statement,
    ) or django_request(request_value, aliases, scope, flow_statement)


def _credential_get_source_key(call):
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "get":
        return None
    if not 1 <= len(call.args) <= 2 or len(call.keywords) > 1:
        return None
    if any(keyword.arg != "default" for keyword in call.keywords):
        return None
    if len(call.args) == 2 and call.keywords:
        return None
    return call.func.value, call.args[0]


def _credential_request_collection(
    node, password_fields, resolve_flask_collection, aliases, scope, flow_statement
):
    if isinstance(node, ast.Name):
        marker = f"request-collection:{node.id}:"
        return any(
            isinstance(item, str) and item.startswith(marker)
            for item in password_fields
        )
    return resolve_flask_collection(node, aliases, scope, flow_statement)


def _track_credential_request_collection(
    bindings, statement, password_fields, collection
):
    password_fields.difference_update(
        item
        for item in tuple(password_fields)
        if isinstance(item, str)
        and item.startswith("request-collection:")
        and item.split(":", 2)[1] in bindings
    )
    if collection:
        targets = getattr(statement, "targets", None) or [statement.target]
        password_fields.update(
            f"request-collection:{target.id}:source"
            for target in targets
            if isinstance(target, ast.Name)
        )


def _sql_assignment_kinds(value, aliases, helpers, driver, cursor, helper_call):
    receiver = _sql_call_receiver(value)
    connection = bool(driver) or helper_call(value, "connection", aliases, helpers)
    is_cursor = (
        bool(cursor)
        or helper_call(value, "cursor", aliases, helpers)
        or (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "cursor"
            and helper_call(receiver, "connection", aliases, helpers)
        )
    )
    return connection, is_cursor


def _sql_call_receiver(value):
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute):
        return value.func.value
    return None


def _sql_assignment_names(statement):
    targets = (
        statement.targets if isinstance(statement, ast.Assign) else [statement.target]
    )
    return [target.id for target in targets if isinstance(target, ast.Name)]


def sqlalchemy_with_findings(
    statement, aliases, scope, connections, cursors, resolve_call, analyze_body
):
    """Analyze only SQLAlchemy engine contexts proven from create_engine."""
    targets = sqlalchemy_with_connection_targets(
        statement, aliases, scope, resolve_call
    )
    if not targets:
        return None
    old_connections, old_cursors = connections.copy(), cursors.copy()
    try:
        for target in targets:
            bind_sql_provenance(connections, cursors, target, "sqlalchemy", None)
        return analyze_body(statement.body)
    finally:
        connections.clear()
        connections.update(old_connections)
        cursors.clear()
        cursors.update(old_cursors)


def unsafe_sql_driver(
    call,
    requests,
    parameters,
    aliases,
    connection_names,
    cursor_names,
    scoped_aliases,
    resolve_call,
    proven_cursor,
    is_tainted,
):
    """Return the proven driver only when its SQL statement is request-tainted."""
    driver = sql_sink_driver(
        call,
        aliases,
        connection_names,
        cursor_names,
        scoped_aliases,
        resolve_call,
    )
    if (
        driver is None
        and isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "execute"
        and call.args
        and proven_cursor(call.func.value)
    ):
        driver = "mysql.connector"
    if driver is None:
        return None
    query = sql_statement_argument(call, driver, aliases, resolve_call)
    return driver if is_tainted(query, requests, parameters, aliases) else None


def scoped_unsafe_sql_driver(
    call,
    requests,
    parameters,
    aliases,
    connection_names,
    cursor_names,
    scope_aliases_for,
    resolve_call,
    helpers,
    cursor_driver,
    helper_call,
    is_tainted,
):
    """Apply scoped aliases before resolving a request-tainted SQL sink."""
    scope = getattr(call, "_security_lexical_scope", None)
    statement = getattr(call, "_security_flow_statement", None)
    return unsafe_sql_driver(
        call,
        requests,
        parameters,
        aliases,
        connection_names,
        cursor_names,
        scope_aliases_for(scope, aliases, statement),
        resolve_call,
        lambda receiver: _proven_sql_cursor(
            receiver,
            aliases,
            connection_names,
            cursor_names,
            helpers,
            cursor_driver,
            helper_call,
        ),
        is_tainted,
    )


def _proven_sql_cursor(
    receiver,
    aliases,
    connection_names,
    cursor_names,
    helpers,
    cursor_driver,
    helper_call,
):
    if isinstance(receiver, ast.Name):
        return receiver.id in cursor_names
    return bool(
        cursor_driver(receiver, aliases, connection_names, cursor_names, helpers)
    ) or helper_call(receiver, "cursor", aliases, helpers)


def sql_sink_driver(
    call, aliases, connection_names, cursor_names, scope_aliases, resolve_call
):
    """Resolve a supported execute receiver to its proven SQL driver."""
    if (
        not isinstance(call, ast.Call)
        or not isinstance(call.func, ast.Attribute)
        or call.func.attr != "execute"
        or not call.args
    ):
        return None
    receiver = call.func.value
    driver = sql_cursor_driver(
        receiver, aliases, cursor_names, scope_aliases, resolve_call
    )
    if driver:
        return driver
    driver = sql_connection_driver(
        receiver, aliases, connection_names, scope_aliases, resolve_call
    )
    if driver in {"sqlite3", "psycopg", "sqlalchemy"}:
        return driver
    if isinstance(receiver, ast.Call) and isinstance(receiver.func, ast.Attribute):
        if receiver.func.attr == "cursor":
            return sql_connection_driver(
                receiver.func.value,
                aliases,
                connection_names,
                scope_aliases,
                resolve_call,
            )
    return None


def sql_statement_argument(call, driver, aliases, resolve_call):
    """Unwrap only SQLAlchemy text() around the SQL statement argument."""
    statement = call.args[0]
    if (
        driver == "sqlalchemy"
        and isinstance(statement, ast.Call)
        and resolve_call(statement, aliases) == "sqlalchemy.text"
        and statement.args
    ):
        return statement.args[0]
    return statement


def sqlalchemy_with_connection_targets(statement, aliases, scope, resolve_call):
    """Return `with engine.connect() as conn` targets backed by create_engine."""
    if not isinstance(statement, (ast.With, ast.AsyncWith)):
        return ()
    targets = []
    for item in statement.items:
        expression = item.context_expr
        target = item.optional_vars
        if (
            not isinstance(expression, ast.Call)
            or not isinstance(expression.func, ast.Attribute)
            or expression.func.attr != "connect"
            or not isinstance(expression.func.value, ast.Name)
            or not isinstance(target, ast.Name)
            or not _sqlalchemy_engine_bound(
                expression.func.value.id, scope, statement, aliases, resolve_call
            )
        ):
            continue
        targets.append(target.id)
    return tuple(targets)


def _sqlalchemy_engine_bound(name, scope, before, aliases, resolve_call):
    """Prove a straight-line create_engine assignment visible at this with."""
    from .review_audits import _bound_names

    current = scope
    anchor = before
    while isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if name in getattr(current, "_security_parameter_names", set()):
                return False
            local = set(getattr(current, "_security_local_names", set()))
            if name in local:
                if anchor not in current.body:
                    return False
                return _sqlalchemy_assignment_before(
                    name, current.body, anchor, aliases, resolve_call
                )
            if anchor not in current.body or any(
                name in _bound_names(statement)
                for statement in current.body[: current.body.index(anchor)]
            ):
                return False
            anchor = current
        else:
            if anchor not in current.body:
                return False
            return _sqlalchemy_assignment_before(
                name, current.body, anchor, aliases, resolve_call
            )
        current = getattr(current, "_security_parent_scope", None)
    return False


def _sqlalchemy_assignment_before(name, body, stop, aliases, resolve_call):
    from .review_audits import _bound_names

    proven = False
    for statement in body:
        if statement is stop:
            break
        value = getattr(statement, "value", None)
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
            if isinstance(statement, ast.AnnAssign)
            else []
        )
        direct_binding = (
            len(targets) == 1
            and isinstance(targets[0], ast.Name)
            and targets[0].id == name
        )
        if direct_binding:
            proven = (
                isinstance(value, ast.Call)
                and resolve_call(value, aliases) == "sqlalchemy.create_engine"
            )
            continue
        if name in _bound_names(statement):
            proven = False
    return proven


def sql_sink_label(call, driver):
    """Return descriptive, driver-specific SQL sink facts."""
    return f"{driver}.execute"


def sql_injection_finding(make_finding, relative, call, driver):
    """Build a driver-specific SQL injection finding."""
    return make_finding(
        "SECURITY_SQL_INJECTION",
        relative,
        call,
        f"Interpolated SQL reaches a proven {driver} sink without parameter binding.",
        "HIGH",
        call=sql_sink_label(call, driver),
    )


def project_contract_helpers():
    """Include every contract resolver in process-local cache identity."""
    return (
        bind_project_contracts,
        _capture_project_imports,
        _project_import_views,
        _bind_file_contracts,
        _bind_imported_base,
        _stable_import_index,
        _stable_import_contract,
        _track_import_binding,
        _declared_stub_method,
        _concrete_contract_method,
        _shadowed_error,
        _stable_base_contract,
        _contract_body_nodes,
        _placeholder_statement,
        _unsafe_project_bases,
        _function_rebinds_module_getattr,
        _scope_binds_name,
        _scope_statement_binds_name,
        _walk_scope_nodes,
        bound_snapshots,
        _BoundSourceBytes.get,
        _BoundSourceBytes.__init__,
    )


def _declared_typecheck_sources(
    root,
    files,
    read_bytes,
    local_file,
    relative_path,
    source_error,
    max_bytes,
    max_paths,
):
    """Bind supported declared type-check scopes; unknown ty inputs earn no credit."""
    identity = {
        "path": "pyproject.toml",
        "state": "missing",
        "ty": {"state": "missing"},
    }
    bindings = []
    try:
        config = local_file(root, "pyproject.toml")
        size = config.stat().st_size
        if size > max_bytes:
            identity["state"] = "oversized"
            identity["bytes"] = size
            return set(), [], identity, False
        data = read_bytes(root, "pyproject.toml")
        digest = sha256(data).hexdigest()
        identity.update(state="read", bytes=len(data), sha256=digest)
        bindings = [{"path": "pyproject.toml", "sha256": digest, "bytes": len(data)}]
        tools = tomllib.loads(data.decode("utf-8")).get("tool", {})
        declared, pyright = (
            tools.get("mypy", {}).get("files", []),
            tools.get("pyright", {}).get("include", []),
        )
        if not isinstance(pyright, list):
            return set(), bindings, identity, True
        declared = declared + pyright if isinstance(declared, list) else declared
        if not isinstance(declared, list) or len(declared) > max_paths:
            return set(), bindings, identity, True
        roots = [root / relative_path(item) for item in declared]
        if any(not target.resolve().is_relative_to(root.resolve()) for target in roots):
            return set(), bindings, identity, False
        ty_sources, ty_identity, cacheable = _ty_sources(
            root,
            files,
            tools.get("ty"),
            read_bytes,
            local_file,
            source_error,
            max_bytes,
            max_paths,
        )
        identity["ty"] = ty_identity
        if ty_identity.get("invocation"):
            bindings.append(ty_identity["invocation"])
        bindings.extend(ty_identity.get("ignore_files", []))
        selected = {
            path
            for path in files
            if (
                path in roots
                or not (path.name.startswith("test_") or path.name.endswith("_test.py"))
            )
            and any(path == target or path.is_relative_to(target) for target in roots)
        }
        return selected, bindings, identity, cacheable
    except source_error as exc:
        if getattr(exc, "code", None) == "E_SOURCE_MISSING":
            identity["ty"] = {"state": "missing"}
            return set(), [], identity, True
        identity.update(state="unreadable", ty={"state": "unknown"})
        return set(), [], identity, False
    except (OSError, ValueError, UnicodeError, AttributeError, TypeError):
        identity.update(state="unreadable", ty={"state": "unknown"})
        return set(), bindings, identity, False


def _ty_sources(
    root, files, config, read_bytes, local_file, source_error, limit, max_paths
):
    if config is None:
        return set(), {"state": "missing"}, True
    state = {"state": "unknown"}
    try:
        override = _ty_external_config_state(root)
        if override:
            return set(), override, False
        invocation = _ty_invocation_profile(
            root, read_bytes, local_file, source_error, limit
        )
        if invocation is None:
            return set(), state, True
        git_identity, global_ignore_safe = _ty_global_git_configuration(limit)
        if not global_ignore_safe:
            return set(), {"state": "unknown", "git_config": git_identity}, False
        scope = _ty_config_scope(root, config, max_paths)
        if scope is None:
            return set(), state, True
        includes, excludes, rules, include_paths, exclude_paths = scope
        rule_state = _ty_assertion_rules(rules)
        if rule_state is None:
            return set(), state, True
        if not rule_state:
            return set(), {"state": "disabled", "rules": rules}, True
        ignore_identity, ignored = _ty_ignored_paths(
            root, files, read_bytes, local_file, source_error, limit
        )
        if ignored is None:
            return set(), {**state, "ignore_files": ignore_identity}, False
        selected = _ty_selected_paths(
            root, files, include_paths, exclude_paths, ignored
        )
        return (
            selected,
            {
                "state": "selected",
                "selected": sorted(
                    path.relative_to(root).as_posix() for path in selected
                ),
                "include": [
                    path.relative_to(root).as_posix() for path in include_paths
                ],
                "exclude": [
                    path.relative_to(root).as_posix() for path in exclude_paths
                ],
                "rules": rules,
                "invocation": invocation,
                "ignore_files": ignore_identity,
                "git_config": git_identity,
            },
            True,
        )
    except (OSError, ValueError, UnicodeError, TypeError, configparser.Error):
        return set(), state, False


def _ty_invocation_profile(root, read_bytes, local_file, source_error, limit):
    try:
        path = local_file(root, "tox.ini")
        if path.stat().st_size > limit:
            return None
        data = read_bytes(root, "tox.ini")
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        parser.read_string(data.decode("utf-8"))
        if any(
            parser.has_option(section, option)
            for section in parser.sections()
            for option in (
                "changedir",
                "setenv",
                "commands_pre",
                "commands_post",
            )
        ):
            return None
        if not _ty_safe_passenv(parser):
            return None
        commands = [
            command.strip()
            for section in parser.sections()
            for command in parser.get(section, "commands", fallback="").splitlines()
            if re.search(r"\bty\s+check\b", command)
        ]
        if not commands or any(command != "ty check" for command in commands):
            return None
        return {
            "path": "tox.ini",
            "sha256": sha256(data).hexdigest(),
            "bytes": len(data),
            "command": "ty check",
        }
    except source_error:
        return None
    except (OSError, UnicodeError, configparser.Error):
        return None


def _ty_safe_passenv(parser):
    """Accept only explicitly named non-checker environment passthroughs."""
    return all(
        name in {"PYTEST_ADDOPTS", "FORCE_COLOR", "CI"}
        for section in parser.sections()
        for line in parser.get(section, "passenv", fallback="").splitlines()
        for name in line.split()
        if not line.lstrip().startswith("#")
    )


def _ty_external_config_state(root):
    user = Path(os.environ.get("APPDATA", Path.home() / ".config")) / "ty" / "ty.toml"
    if (
        os.environ.get("TY_CONFIG_FILE")
        or user.is_file()
        or (root / "ty.toml").exists()
    ):
        return {"state": "unknown", "config_override": True}
    return None


def _ty_config_scope(root, config, limit):
    if not isinstance(config, dict) or set(config) - {"src", "rules", "terminal"}:
        return None
    src = config.get("src")
    if not isinstance(src, dict) or set(src) - {
        "include",
        "exclude",
        "respect-ignore-files",
    }:
        return None
    if src.get("respect-ignore-files", True) is not True:
        return None
    includes, excludes = src.get("include"), src.get("exclude", [])
    include_paths, exclude_paths = (
        _ty_paths(root, includes, limit),
        _ty_paths(root, excludes, limit),
    )
    rules = config.get("rules", {})
    if include_paths is None or exclude_paths is None or not include_paths:
        return None
    if not isinstance(rules, dict):
        return None
    return includes, excludes, rules, include_paths, exclude_paths


def _ty_assertion_rules(rules):
    known = {
        "missing-type-argument",
        "missing-override-decorator",
        "type-assertion-failure",
        "assert-type-unspellable-subtype",
    }
    names = ("type-assertion-failure", "assert-type-unspellable-subtype")
    if set(rules) - known:
        return None
    if any(rules.get(name) == "ignore" for name in names):
        return False
    if any(rules.get(name) not in (None, "error", "warn") for name in names):
        return None
    return True


def _ty_selected_paths(root, files, includes, excludes, ignored):
    return {
        path
        for path in files
        if any(path == target or path.is_relative_to(target) for target in includes)
        and not any(
            path == target or path.is_relative_to(target) for target in excludes
        )
        and not _ty_default_excluded(path.relative_to(root))
        and not ignored.get(path, False)
    }


def _static_type_edges(root, sources, config_bindings, ty_sources=None):
    """Describe declared static-type scopes without implying checker execution."""
    ty_sources = ty_sources or set()
    return [
        {
            "caller": path.relative_to(root).as_posix(),
            "target": binding["path"],
            "kind": "static_type_configuration",
            "symbol": "type_checker.sources",
            "strength": "declared",
            "execution_state": "NOT_VERIFIED",
            **({"checker": "ty"} if path in ty_sources else {}),
            "sha256": binding["sha256"],
        }
        for path in sorted(sources)
        for binding in config_bindings
    ]


def _ty_paths(root, values, limit):
    if not isinstance(values, list) or len(values) > limit:
        return None
    result = []
    for value in values:
        if (
            not isinstance(value, str)
            or not value
            or any(char in value for char in "*?[]!")
        ):
            return None
        path = Path(value)
        if path.is_absolute() or ".." in path.parts:
            return None
        target = (root / path).resolve()
        if not target.is_relative_to(root.resolve()):
            return None
        result.append(target)
    return result


def _ty_default_excluded(path):
    return any(
        part
        in {".git", ".venv", "venv", "__pycache__", "site-packages", "dist-packages"}
        for part in path.parts
    )


def _ty_global_git_configuration(limit):
    names = (
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
    )
    if any(os.environ.get(name) for name in names):
        return {"state": "environment_override"}, False
    home = Path.home()
    xdg = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
    program_files = Path(os.environ.get("ProgramFiles", "C:/Program Files"))
    paths = (
        home / ".gitconfig",
        xdg / "git" / "config",
        program_files / "Git" / "etc" / "gitconfig",
    )
    rows = []
    for path in dict.fromkeys(paths):
        if not path.is_file():
            continue
        if path.is_symlink() or path.stat().st_size > limit:
            return {"state": "unknown"}, False
        data = path.read_bytes()
        parser = configparser.RawConfigParser(strict=False, interpolation=None)
        parser.read_string(data.decode("utf-8"))
        if any(
            section == "include" or section.startswith("include ")
            for section in parser.sections()
        ):
            return {"state": "include"}, False
        if parser.has_option("core", "excludesfile"):
            return {"state": "global_ignore_configured"}, False
        rows.append({"source": "git_config", "sha256": sha256(data).hexdigest()})
    return {"state": "read", "files": rows}, True


def _ty_ignored_paths(root, files, read_bytes, local_file, source_error, limit):
    parsed, hashes, ignored = {}, {}, {}
    for path in files:
        ignored[path] = _ty_path_is_ignored(
            path, root, parsed, hashes, read_bytes, local_file, source_error, limit
        )
        if ignored[path] is None:
            return [], None
    return [hashes[name] for name in sorted(hashes)], ignored


def _ty_path_is_ignored(
    path, root, parsed, hashes, read_bytes, local_file, source_error, limit
):
    relative = path.relative_to(root)
    directories = [
        Path(*relative.parts[:index]) for index in range(len(relative.parts))
    ]
    directories.append(Path(*relative.parts[:-1]))
    for directory in directories:
        names = [directory / name for name in (".ignore", ".gitignore")]
        if not directory.parts:
            names.append(Path(".git/info/exclude"))
        for candidate in names:
            name = candidate.as_posix()
            if name not in parsed:
                parsed[name] = _ty_ignore_file_patterns(
                    root, name, read_bytes, local_file, source_error, limit, hashes
                )
            patterns = parsed[name]
            if patterns is None:
                return None
            if _ty_matches_ignore(path.relative_to(root / directory), patterns):
                return True
    return False


def _ty_ignore_file_patterns(
    root, name, read_bytes, local_file, source_error, limit, hashes
):
    try:
        path = local_file(root, name)
        if path.stat().st_size > limit:
            return None
        data = read_bytes(root, name)
    except source_error as exc:
        return [] if getattr(exc, "code", None) == "E_SOURCE_MISSING" else None
    except OSError:
        return None
    patterns = _ty_parse_ignore_lines(data)
    if patterns is not None:
        hashes[name] = {
            "path": name,
            "sha256": sha256(data).hexdigest(),
            "bytes": len(data),
        }
    return patterns


def _ty_parse_ignore_lines(data):
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError:
        return None
    patterns = []
    for line in lines:
        pattern = line.strip()
        if not pattern or pattern.startswith("#"):
            continue
        if (
            pattern.startswith("!")
            or "\\" in pattern
            or any(c in pattern for c in "?[]")
        ):
            return None
        value = pattern.lstrip("/").rstrip("/")
        if not value or (
            "*" in value
            and not (
                value.count("*") == 1
                and "/" not in value
                and (value.startswith("*.") or value.endswith("*"))
            )
        ):
            return None
        patterns.append(pattern)
    return patterns


def _ty_matches_ignore(relative, patterns):
    for pattern in patterns:
        anchored, directory = pattern.startswith("/"), pattern.endswith("/")
        value = pattern.strip("/")
        parts = relative.parts[:-1] if directory else relative.parts
        if not anchored and "/" not in value:
            matched = any(fnmatchcase(part, value) for part in parts)
        else:
            prefix = value.split("/")
            matched = len(parts) >= len(prefix) and all(
                fnmatchcase(part, expected) for part, expected in zip(parts, prefix)
            )
        if matched:
            return True
    return False


def _ty_assertion_provider_mutated(module, aliases):
    """Reject writes to canonical assertion-provider attributes anywhere in scope."""
    return (
        any(
            isinstance(item, ast.Attribute)
            and isinstance(item.ctx, (ast.Store, ast.Del))
            and item.attr == "assert_type"
            and isinstance(item.value, ast.Name)
            and aliases.get(item.value.id) in {"typing", "typing_extensions"}
            for item in ast.walk(module)
        )
        if module is not None
        else True
    )


def _capture_project_imports(views, path, imports, eligible):
    """Retain bounded, immutable maps only for the current context build."""
    if not views:
        return
    views.setdefault("eligible", MappingProxyType(eligible))
    views["bindings"] += len(imports)
    views["characters"] += sum(
        len(alias) + len(str(source)) + len(symbol or "")
        for alias, (source, symbol) in imports.items()
    )
    if views["bindings"] > 4096 or views["characters"] > 1048576:
        views.clear()
        return
    views["resolved"][path] = MappingProxyType(dict(imports))


def _project_import_views(views, snapshots):
    """Select a whole captured view only for the identical resolver inventory."""
    if (
        views
        and views.get("eligible") == {p.resolve(): p for p in snapshots}
        and views["resolved"].keys() == snapshots.keys()
    ):
        return MappingProxyType(dict(views["resolved"]))
    return None
