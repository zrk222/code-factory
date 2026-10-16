"""Deterministic quality checks for natural-language intent boundaries.

AI-authored text is untrusted input even when it appears in a signed or
hash-bound artifact.  A digest proves that text was not changed after it was
captured; it does not prove that the text was specific enough to test.  This
module supplies a small, dependency-free lexical guard for the places where
FactoryLine accepts intent, promises, requirements, or acceptance evidence.

The guard is deliberately conservative and explainable.  It does not infer a
product meaning or call a model.  It only rejects known placeholders/vague
phrases and statements that lack an action or (when requested) an observable
evidence signal.  A human still owns confirmation and an independent verifier
still owns the result.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from hashlib import sha256
import re
from typing import Any


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
def intentional_implementation_contract(node, parents, aliases):
    """Recognize explicit container or locally evidenced extension contracts."""
    return (
        click_group_container(node, parents, aliases)
        or _method_contract(node, parents)
        or _null_io_contract(node, parents, aliases)
    )


def _null_io_contract(node, parents, aliases):
    """Recognize an inert IO implementation by its complete local behavior.

    Neither the class name nor an isolated pass/zero return is sufficient.
    """
    owner = parents.get(node)
    if not isinstance(owner, ast.ClassDef) or owner.decorator_list:
        return False
    if node.decorator_list or not _stable_api_origin(
        owner, parents, aliases, {"typing", "typing.IO"}
    ):
        return False
    if node.name not in {"close", "flush", "writelines", "__exit__"}:
        return False
    body = node.body[1:] if ast.get_docstring(node) is not None else node.body
    if len(body) != 1 or not isinstance(body[0], ast.Pass):
        return False
    bases = [
        base.value if isinstance(base, ast.Subscript) else base for base in owner.bases
    ]
    if len(bases) != 1 or not _typing_io_base(bases[0], aliases):
        return False
    methods = [n for n in owner.body if isinstance(n, ast.FunctionDef)]
    names = {n.name: n for n in methods}
    if len(names) != len(methods) or "__init__" in names:
        return False
    if any(
        isinstance(n, ast.Attribute) and isinstance(n.ctx, (ast.Store, ast.Del))
        for n in ast.walk(owner)
    ):
        return False
    required = {
        "readable": False,
        "writable": False,
        "seekable": False,
        "read": "",
        "readline": "",
        "write": 0,
    }
    return all(
        _literal_method(names.get(name), value) for name, value in required.items()
    )


def _typing_io_base(base, aliases):
    if isinstance(base, ast.Name):
        return aliases.get(base.id) == "typing.IO"
    return (
        isinstance(base, ast.Attribute)
        and base.attr == "IO"
        and isinstance(base.value, ast.Name)
        and aliases.get(base.value.id) == "typing"
    )


def _literal_method(node, expected):
    if node is None or node.decorator_list:
        return False
    body = node.body[1:] if ast.get_docstring(node) is not None else node.body
    return (
        len(body) == 1
        and isinstance(body[0], ast.Return)
        and isinstance(body[0].value, ast.Constant)
        and type(body[0].value.value) is type(expected)
        and body[0].value.value == expected
    )


def _method_contract(node, parents):
    owner = parents.get(node)
    if not isinstance(owner, ast.ClassDef):
        return False
    body = node.body[1:] if ast.get_docstring(node) is not None else node.body
    if len(body) != 1:
        return False
    documentation = " ".join((ast.get_docstring(node) or "").lower().split())
    if isinstance(body[0], ast.Pass):
        return "nothing by default" in documentation and "overrid" in documentation
    if not isinstance(body[0], ast.Raise):
        return False
    error = body[0].exc
    error = error.func if isinstance(error, ast.Call) else error
    if not isinstance(error, ast.Name) or error.id != "NotImplementedError":
        return False
    scope = parents.get(owner)
    if (
        not isinstance(scope, ast.Module)
        or _shadowed_error(scope)
        or owner.decorator_list
    ):
        return False
    if any(
        isinstance(item, ast.Call)
        and isinstance(item.func, ast.Name)
        and item.func.id == owner.name
        for item in ast.walk(scope)
    ):
        return False
    if "subclasses must override" in documentation or (
        "must be implemented" in documentation and "subclasses" in documentation
    ):
        return True
    return _local_override(owner, node.name, scope)


def _shadowed_error(scope):
    return any(
        (
            isinstance(item, ast.Name)
            and isinstance(item.ctx, (ast.Store, ast.Del))
            and item.id == "NotImplementedError"
        )
        or (
            isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and item.name == "NotImplementedError"
        )
        or (
            isinstance(item, ast.alias)
            and (item.asname or item.name.split(".")[0]) == "NotImplementedError"
        )
        or (isinstance(item, ast.arg) and item.arg == "NotImplementedError")
        for item in ast.walk(scope)
    )


def _local_override(owner, method, scope):
    # Require an unambiguous local base binding and a non-stub override.
    if (
        sum(isinstance(n, ast.ClassDef) and n.name == owner.name for n in scope.body)
        != 1
    ):
        return False
    if any(
        isinstance(n, ast.Name)
        and isinstance(n.ctx, (ast.Store, ast.Del))
        and n.id == owner.name
        for n in ast.walk(scope)
    ):
        return False
    return any(
        isinstance(child, ast.ClassDef)
        and any(
            isinstance(base, ast.Name) and base.id == owner.name for base in child.bases
        )
        and any(
            isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
            and function.name == method
            and _concrete_contract_method(function)
            for function in child.body
        )
        for child in scope.body
    )


def click_group_container(node, parents, aliases):
    """Recognize a default Click group with a statically registered child.

    This proves a container role, not that callbacks execute or commands work.
    Custom group implementations and invocation modes remain unverified.
    """
    if not node.decorator_list:
        return False
    if not _stable_api_origin(node, parents, aliases, {"click", "click.group"}):
        return False
    scope = parents.get(node)
    if not isinstance(scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    definitions = {
        item.name: item
        for item in scope.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if not _stable_scope(scope, {node.name, *aliases, *definitions}, definitions):
        return False
    if not _recognized_group(node, definitions, aliases, set()):
        return False
    return any(
        isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and isinstance(decorator.func.value, ast.Name)
        and decorator.func.value.id == node.name
        and decorator.func.attr in {"command", "group"}
        for function in definitions.values()
        if function is not node
        for decorator in function.decorator_list
    )


def _stable_scope(scope, names, definitions):
    # A redefinition or assignment makes decorator ownership ambiguous.
    for statement in scope.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if (
                statement.name in names
                and definitions.get(statement.name) is not statement
            ):
                return False
            continue
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            continue
        if any(
            isinstance(item, (ast.Name, ast.Attribute))
            and isinstance(item.ctx, (ast.Store, ast.Del))
            and (
                item.id
                if isinstance(item, ast.Name)
                else ast.unparse(item).split(".")[0]
            )
            in names
            for item in ast.walk(statement)
        ):
            return False
    return True


def _recognized_group(function, definitions, aliases, visiting):
    if function.name in visiting or len(function.decorator_list) != 1:
        return False
    visiting = visiting | {function.name}
    return any(
        _group_decorator(d, definitions, aliases, visiting)
        for d in function.decorator_list
    )


def _group_decorator(decorator, definitions, aliases, visiting):
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(decorator, ast.Call) and (
        decorator.args
        or any(
            keyword.arg not in {"help", "short_help"}
            or not isinstance(keyword.value, ast.Constant)
            or not isinstance(keyword.value.value, str)
            for keyword in decorator.keywords
        )
    ):
        return False
    if isinstance(target, ast.Name):
        return aliases.get(target.id) == "click.group"
    if not isinstance(target, ast.Attribute) or target.attr != "group":
        return False
    if not isinstance(target.value, ast.Name):
        return False
    owner = target.value.id
    if aliases.get(owner) == "click":
        return True
    return owner in definitions and _recognized_group(
        definitions[owner], definitions, aliases, visiting
    )


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
        and isinstance(call.func, ast.Attribute)
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
            local = set(getattr(current, "_security_local_names", set()))
            if name in local:
                if name in {argument.arg for argument in current.args.args}:
                    return False
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
        bound_snapshots,
        _BoundSourceBytes.get,
        _BoundSourceBytes.__init__,
    )


def bind_project_contracts(root, snapshots, contexts, edges):
    """Resolve direct local imported bases from the already hash-bound snapshots."""
    from .review_audits import _oracle_imports

    eligible = {p.resolve(): p for p in snapshots}
    resolved = {
        path: _oracle_imports(root, path, tree, eligible)
        for path, tree in snapshots.items()
    }
    blocked = _unsafe_project_bases(snapshots, resolved)
    for path, tree in snapshots.items():
        _bind_file_contracts(
            root, path, tree, resolved[path], snapshots, contexts, edges, blocked
        )


def _bind_file_contracts(
    root, path, tree, imports, snapshots, contexts, edges, blocked
):
    for child in (n for n in tree.body if isinstance(n, ast.ClassDef)):
        if child.decorator_list:
            continue
        for base in child.bases:
            if not isinstance(base, ast.Name) or base.id not in imports:
                continue
            if not _stable_import_contract(tree, base.id, child.lineno):
                continue
            source, symbol = imports[base.id]
            if (
                symbol is not None
                and source in snapshots
                and (source, symbol) not in blocked
            ):
                _bind_imported_base(
                    root,
                    path,
                    child,
                    source,
                    symbol,
                    snapshots[source],
                    contexts,
                    edges,
                )


def _bind_imported_base(root, path, child, source, symbol, tree, contexts, edges):
    bases = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == symbol]
    if len(bases) != 1 or bases[0].decorator_list or _shadowed_error(tree):
        return
    if not _stable_base_contract(tree, bases[0]):
        return
    if any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == symbol
        for n in ast.walk(tree)
    ):
        return
    if any(
        isinstance(n, ast.Name)
        and isinstance(n.ctx, (ast.Store, ast.Del))
        and n.id == symbol
        for n in ast.walk(tree)
    ):
        return
    methods = {
        n.name: n
        for n in child.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for method in bases[0].body:
        if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        override = methods.get(method.name)
        if not _declared_stub_method(method) or not _concrete_contract_method(override):
            continue
        if type(method) is not type(override):
            continue
        contexts[source].setdefault("implementation_contract_lines", set()).add(
            method.lineno
        )
        edges.append(
            {
                "caller": path.relative_to(root).as_posix(),
                "target": source.relative_to(root).as_posix(),
                "kind": "implementation_contract",
                "symbol": symbol + "." + method.name,
                "strength": "declared_override",
            }
        )


def _stable_import_contract(tree, local, before):
    imports = [
        statement.lineno
        for statement in tree.body
        if isinstance(statement, (ast.Import, ast.ImportFrom))
        for alias in statement.names
        if (alias.asname or alias.name.split(".")[0]) == local
    ]
    if len(imports) != 1 or imports[0] >= before:
        return False
    return not any(
        (
            isinstance(n, ast.Name)
            and isinstance(n.ctx, (ast.Store, ast.Del))
            and n.id == local
        )
        or (
            isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and n.name == local
        )
        or (
            isinstance(n, ast.Attribute)
            and isinstance(n.ctx, (ast.Store, ast.Del))
            and isinstance(n.value, ast.Name)
            and n.value.id == local
        )
        or (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == local
        )
        for n in ast.walk(tree)
    )


def _stable_base_contract(tree, owner):
    return not any(
        (
            isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == owner.name
            and node is not owner
        )
        or (
            isinstance(node, ast.alias)
            and (node.asname or node.name.split(".")[0]) == owner.name
        )
        for node in ast.walk(tree)
    )


def _declared_stub_method(node):
    body = node.body[1:] if ast.get_docstring(node) is not None else node.body
    if len(body) != 1:
        return False
    statement = body[0]
    if isinstance(statement, ast.Raise):
        error = (
            statement.exc.func if isinstance(statement.exc, ast.Call) else statement.exc
        )
        return isinstance(error, ast.Name) and error.id == "NotImplementedError"
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and statement.value.value is Ellipsis
        and node.returns is not None
    )


def _concrete_contract_method(node):
    if node is None or node.decorator_list:
        return False
    body = node.body[1:] if ast.get_docstring(node) is not None else node.body
    if not body or _declared_stub_method(node):
        return False
    nodes = list(_contract_body_nodes(body))
    if any(_placeholder_statement(n) for n in nodes):
        return False
    return any(
        isinstance(n, (ast.Return, ast.Assign, ast.AnnAssign))
        or (isinstance(n, ast.Expr) and isinstance(n.value, (ast.Call, ast.Await)))
        for n in nodes
    )


def _contract_body_nodes(statements):
    for statement in statements:
        if isinstance(
            statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        yield statement
        yield from _contract_body_nodes(ast.iter_child_nodes(statement))


def _placeholder_statement(node):
    if isinstance(node, ast.Raise):
        error = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
        return isinstance(error, ast.Name) and error.id == "NotImplementedError"
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and node.value.value is Ellipsis
    )


def _stable_api_origin(node, parents, aliases, targets):
    roots = {name for name, target in aliases.items() if target in targets}
    if not roots:
        return False
    scopes = []
    parent = parents.get(node)
    while parent is not None:
        if isinstance(
            parent, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            scopes.append(parent)
        parent = parents.get(parent)
    for name in roots:
        imports = [
            statement
            for scope in scopes
            for statement in scope.body
            if isinstance(statement, (ast.Import, ast.ImportFrom))
            for alias in statement.names
            if (alias.asname or alias.name.split(".")[0]) == name
        ]
        if len(imports) != 1 or imports[0].lineno >= node.lineno:
            return False
    return not any(
        isinstance(item, ast.Attribute)
        and isinstance(item.ctx, (ast.Store, ast.Del))
        and ast.unparse(item).split(".")[0] in roots
        for scope in scopes
        for item in ast.walk(scope)
    )


def _unsafe_project_bases(snapshots, resolved):
    blocked = set()
    for path, tree in snapshots.items():
        for local, (source, symbol) in resolved[path].items():
            if symbol is not None:
                if not _stable_import_contract(tree, local, float("inf")):
                    blocked.add((source, symbol))
                continue
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == local
                ):
                    blocked.add((source, node.func.attr))
    return blocked


class _BoundSourceBytes:
    def __init__(self, root, data, bindings):
        self.root, self.data = root, data
        self.expected = {row["path"]: row["sha256"] for row in bindings}

    def get(self, path):
        """Read source bytes only when they match the original scan identity."""
        from .review_audits import _security_source_bytes, ReviewAuditError, MAX_BYTES
        from .runtime_audit_common import RuntimeAuditError
        from .deep_audit_io import local_file

        relative = path.relative_to(self.root).as_posix()
        expected = self.expected.get(relative)
        if expected is None:
            raise RuntimeAuditError(
                "SOURCE_IDENTITY_MISSING", "Snapshot has no original source identity"
            )
        data = self.data.get(path)
        if data is None:
            if (
                path.is_symlink()
                or local_file(self.root, relative).stat().st_size > MAX_BYTES
            ):
                raise RuntimeAuditError(
                    "SOURCE_BOUNDARY_INVALID", "Snapshot exceeds source boundary"
                )
            data = _security_source_bytes(self.root, relative)
        if len(data) > MAX_BYTES or sha256(data).hexdigest() != expected:
            raise ReviewAuditError(
                "Source changed before snapshot parsing: " + relative
            )
        return data


def bound_snapshots(root, files, data, bindings):
    """Parse only byte snapshots bound to the original source manifest."""
    from .review_audits import _oracle_snapshots

    return _oracle_snapshots(root, files, _BoundSourceBytes(root, data, bindings))
