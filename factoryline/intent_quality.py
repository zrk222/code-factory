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
from dataclasses import dataclass
import re
from typing import Any

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
    _stable_import_contract,
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
        _bind_file_contracts,
        _bind_imported_base,
        _stable_import_contract,
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
