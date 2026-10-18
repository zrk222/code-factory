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
from contextvars import ContextVar
from bisect import bisect_left
import configparser
from collections import Counter
from dataclasses import dataclass
from fnmatch import fnmatchcase
from hashlib import sha256
import os
from pathlib import Path
import re
import json
import logging
import threading
from typing import Any

from .import_context import (
    capture_project_imports as _capture_project_imports,
    project_import_views as _project_import_views,
    import_configuration as import_configuration,
    new_import_views as new_import_views,
    import_context_metadata as import_context_metadata,
    native_import_profile as native_import_profile,
)


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


_SECURITY_REQUEST_ALIAS_MEMO = ContextVar("security_request_alias_memo", default=None)
_SECURITY_REQUEST_ALIAS_MAX_ENTRIES = 512
_SECURITY_REQUEST_ALIAS_MAX_PAIRS = 8192
_SECURITY_REQUEST_ALIAS_MAX_BYTES = 524288


def _new_security_request_alias_memo(tree):
    """Create bounded, invocation-local request alias caches for one AST."""
    return {"tree": tree, "values": {}, "pairs": 0, "bytes": 0}


def _security_scope_request_aliases(scope, aliases, flow_statement=None):
    """Resolve request aliases, reusing only exact-prefix results in one scan."""
    from . import review_integrity
    from . import review_audits as audit

    memo = _SECURITY_REQUEST_ALIAS_MEMO.get()
    module = review_integrity._security_module_scope(scope) if scope else None
    if not memo or module is None or module is not memo["tree"]:
        return _security_scope_request_aliases_uncached(scope, aliases, flow_statement)
    alias_items = tuple(sorted(aliases.items()))
    key = (module, scope, flow_statement, alias_items)
    cached = memo["values"].get(key)
    if cached is not None:
        return dict(cached)
    if isinstance(scope, ast.Module):
        resolved = _security_request_alias_module_bindings(
            module, alias_items, flow_statement
        )
    elif isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        resolved = _security_request_alias_module_bindings(module, alias_items, None)
        local_names = set(getattr(scope, "_security_local_names", set()))
        local_names.update(getattr(scope, "_security_parameter_names", set()))
        for name in local_names:
            resolved.pop(name, None)
        resolved = review_integrity._security_apply_import_bindings(
            scope.body, resolved, flow_statement, audit
        )
    else:
        resolved = _security_scope_request_aliases_uncached(
            scope, aliases, flow_statement
        )
    _security_store_request_alias_bindings(memo, key, alias_items, resolved)
    return dict(resolved)


def _security_scope_request_aliases_uncached(scope, aliases, flow_statement):
    """Run the compatibility alias walk without consulting an invocation memo."""
    from . import review_audits as audit
    from .review_integrity import (
        _security_apply_import_bindings,
        _security_module_scope,
    )

    module = _security_module_scope(scope) if scope is not None else None
    if module is None:
        resolved = dict(aliases)
    else:
        module_stop = flow_statement if scope is module else None
        resolved = _security_apply_import_bindings(module.body, {}, module_stop, audit)
    if isinstance(scope, ast.Module):
        return resolved
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return resolved
    local_names = set(getattr(scope, "_security_local_names", set()))
    local_names.update(getattr(scope, "_security_parameter_names", set()))
    for name in local_names:
        resolved.pop(name, None)
    return _security_apply_import_bindings(scope.body, resolved, flow_statement, audit)


def _security_request_alias_module_bindings(module, alias_items, stop):
    """Return full or exact-prefix module bindings in the active invocation."""
    from . import review_audits as audit
    from .review_integrity import _security_apply_import_bindings

    memo = _SECURITY_REQUEST_ALIAS_MEMO.get()
    key = (module, module, stop, alias_items)
    cached = memo["values"].get(key)
    if cached is not None:
        return dict(cached)
    resolved = _security_apply_import_bindings(module.body, {}, stop, audit)
    _security_store_request_alias_bindings(memo, key, alias_items, resolved)
    return dict(resolved)


def _security_store_request_alias_bindings(memo, key, alias_items, resolved):
    """Store a defensive alias copy only while all invocation budgets allow it."""
    if key in memo["values"]:
        return
    value = dict(resolved)
    pair_count = len(alias_items) + len(value)
    byte_count = sum(
        len(str(k).encode("utf-8")) + len(str(v).encode("utf-8"))
        for k, v in alias_items
    )
    byte_count += sum(
        len(str(k).encode("utf-8")) + len(str(v).encode("utf-8"))
        for k, v in value.items()
    )
    if len(memo["values"]) >= _SECURITY_REQUEST_ALIAS_MAX_ENTRIES:
        return
    if memo["pairs"] + pair_count > _SECURITY_REQUEST_ALIAS_MAX_PAIRS:
        return
    if memo["bytes"] + byte_count > _SECURITY_REQUEST_ALIAS_MAX_BYTES:
        return
    memo["values"][key] = value
    memo["pairs"] += pair_count
    memo["bytes"] += byte_count


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


def _literal_assignment_diagnostics(relative, node, aliases, diagnostics):
    """Keep ordinary literal findings unless a closed test canary is proven."""
    if not any(
        item.get("code") == "SECURITY_HARDCODED_SECRET"
        and item.get("facts", {}).get("name") == "secret"
        for item in diagnostics
    ):
        return diagnostics
    if not _is_closed_command_canary(relative, node, aliases):
        return diagnostics
    return [
        finding
        for finding in diagnostics
        if not (
            finding.get("code") == "SECURITY_HARDCODED_SECRET"
            and finding.get("facts", {}).get("name") == "secret"
        )
    ]


def _is_closed_command_canary(relative, node, aliases):
    """Accept only a source-resolved local consumer with linked output proof."""
    context = _canary_context(relative, node, aliases)
    if context is None:
        return False
    scope, secret_loads = context
    absence = _canary_absence_assertion(scope, secret_loads)
    if absence is None:
        return False
    output_name, assertion_line = absence
    read = _canary_output_read_call(scope, output_name)
    if read is None:
        return False
    run = _canary_single_secret_run(scope, node, secret_loads, aliases)
    if run is None:
        return False
    return _canary_run_output_is_closed(
        relative, scope, run, secret_loads, read, assertion_line, aliases
    )


def _canary_single_secret_run(scope, node, secret_loads, aliases):
    """Find one later JSON subprocess carrying the exact marker binding."""
    runs = [
        call
        for call in _canary_nodes(scope, ast.Call)
        if _canary_call_name(call, aliases) == "subprocess.run"
        and _canary_run_payload_contract(call, secret_loads, aliases) is not None
    ]
    return runs[0] if len(runs) == 1 and runs[0].lineno > node.lineno else None


def _canary_run_output_is_closed(
    relative, scope, run, secret_loads, read, assertion_line, aliases
):
    """Prove the subprocess writer and assertion read share a local root."""
    source_context = _canary_source_context(scope)
    if source_context is None:
        return False
    contract = _canary_run_payload_contract(run, secret_loads, aliases)
    if contract is None:
        return False
    root = _canary_run_project_root(run, scope, aliases)
    if root is None:
        return False
    workspace, sources = source_context
    consumer = _canary_local_python_consumer(
        run, scope, relative, aliases, workspace, sources, root[1], contract
    )
    if consumer is None:
        return False
    tree, consumer_aliases = consumer
    writer = _canary_digest_only_output(tree, consumer_aliases, root[1], contract)
    reader = _canary_readback_prefix(scope, read)
    return _canary_linked_prefixes(
        writer, reader, root, scope, run, read, assertion_line
    )


def _canary_linked_prefixes(writer, reader, root, scope, run, read, assertion_line):
    """Join exact reader/writer roots and preserve execution order."""
    return bool(
        writer is not None
        and reader is not None
        and reader == writer
        and writer[0] == root[0]
        and _canary_tmp_path_is_closed(scope, run, read)
        and read.lineno > run.lineno
        and assertion_line > read.lineno
    )


def _canary_context(relative, node, aliases):
    """Return the test scope and closed literal's two uses, or no context."""
    if not _canary_assignment(relative, node):
        return None
    scope = _canary_test_scope(node, aliases)
    if scope is None:
        return None
    if not _canary_index(scope).get("complete"):
        return None
    names = _canary_nodes(scope, ast.Name)
    secret_names = [item for item in names if item.id == "secret"]
    if (
        len(secret_names) != 3
        or sum(isinstance(item.ctx, ast.Store) for item in secret_names) != 1
    ):
        return None
    secret_loads = [item for item in secret_names if isinstance(item.ctx, ast.Load)]
    if len(secret_loads) != 2:
        return None
    return scope, secret_loads


def _canary_test_scope(node, aliases):
    """Return only a direct test-function scope with no outer secret binding."""
    scope = getattr(node, "_security_lexical_scope", None)
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    if not _canary_is_direct_test(scope, node):
        return None
    if not _canary_has_tmp_path_fixture(scope) or not _canary_has_no_secret_parameter(
        scope
    ):
        return None
    if not _canary_scope_has_no_rebindings(scope, aliases):
        return None
    return scope


def _canary_is_direct_test(scope, node):
    """Require the literal assignment directly in one test-function body."""
    return scope.name.startswith("test_") and node in scope.body


def _canary_scope_parameters(scope):
    """Return all positional, keyword-only, and variadic parameters."""
    return (
        *scope.args.posonlyargs,
        *scope.args.args,
        *scope.args.kwonlyargs,
        scope.args.vararg,
        scope.args.kwarg,
    )


def _canary_has_tmp_path_fixture(scope):
    """Require pytest's temporary-directory fixture by parameter name."""
    return any(
        argument is not None and argument.arg == "tmp_path"
        for argument in _canary_scope_parameters(scope)
    )


def _canary_has_no_secret_parameter(scope):
    """Reject parameter shadowing of the generic literal name."""
    return not any(
        argument is not None and argument.arg == "secret"
        for argument in _canary_scope_parameters(scope)
    )


def _canary_scope_has_no_rebindings(scope, aliases):
    """Reject global, nonlocal, or dynamic module mutation in the test source."""
    index = _canary_index(scope)
    if any(
        "secret" in item.names
        for kind in (ast.Global, ast.Nonlocal)
        for item in _canary_nodes(scope, kind)
    ):
        return False
    return (
        index.get("complete", False)
        and not index["attribute_writes"]
        and not index["subscript_writes"]
        and not any(
            isinstance(item.ctx, (ast.Store, ast.Del))
            for item in _canary_nodes(scope, ast.Name)
            if item.id == "tmp_path"
        )
        and not any(
            _canary_call_name(item, aliases).rsplit(".", 1)[-1]
            in {"setattr", "delattr", "__setattr__", "__delattr__"}
            or (
                isinstance(item.func, ast.Attribute)
                and item.func.attr
                in {"setattr", "delattr", "__setattr__", "__delattr__"}
            )
            for item in _canary_nodes(scope, ast.Call)
        )
    )


def _canary_assignment(relative, node):
    """Restrict filtering to generic string literals in test sources."""
    if not isinstance(node, ast.Assign) or len(node.targets) != 1:
        return False
    target, value = node.targets[0], node.value
    if not (
        isinstance(target, ast.Name)
        and target.id == "secret"
        and isinstance(value, ast.Constant)
        and isinstance(value.value, str)
    ):
        return False
    path = Path(relative)
    return (
        "tests" in path.parts or path.name.startswith("test_")
    ) and not _looks_like_known_credential(value.value)


def _canary_output_read_call(scope, output_name):
    """Return the sole direct read whose bound value is asserted."""
    reads = [
        call
        for call in _canary_nodes(scope, ast.Call)
        if isinstance(call.func, ast.Attribute) and call.func.attr == "read_text"
    ]
    if len(reads) != 1:
        return None
    read = reads[0]
    if not _canary_read_assigned_to(scope, read, output_name):
        return None
    if not _canary_output_name_is_closed(scope, output_name):
        return None
    return read


def _canary_read_assigned_to(scope, read, output_name):
    """Require the sole file read to be a direct function-body assignment."""
    parent = _canary_parent(scope, read)
    return (
        isinstance(parent, ast.Assign)
        and parent.value is read
        and len(parent.targets) == 1
        and isinstance(parent.targets[0], ast.Name)
        and parent.targets[0].id == output_name
        and parent in scope.body
    )


def _canary_output_name_is_closed(scope, output_name):
    """Require a single output assignment and reject deletion or rebinding."""
    names = _canary_nodes(scope, ast.Name)
    output_names = [item for item in names if item.id == output_name]
    if (
        sum(isinstance(item.ctx, ast.Store) for item in output_names) != 1
        or any(isinstance(item.ctx, ast.Del) for item in output_names)
        or not any(isinstance(item.ctx, ast.Load) for item in output_names)
    ):
        return False
    return True


def _looks_like_known_credential(value):
    """Keep known token formats and credential-shaped strings reportable."""
    from .context_efficiency import _SECRET_BYTES

    encoded = value.encode("utf-8", "ignore")
    return bool(
        re.search(r"\bsk_(?:live|test|prod)_[A-Za-z0-9]{16,}\b", value)
        or re.search(
            r"(?i)\b(?:api[_ -]?key|access[_ -]?token|bearer|credential|"
            r"password|passwd|private[_ -]?key|secret[_ -]?key)\b",
            value,
        )
        or re.fullmatch(r"(?i)[a-z]{4,16}[0-9]{1,4}", value.strip())
        or any(pattern.search(encoded) for pattern in _SECRET_BYTES)
    )


def _canary_run_payload_contract(run, secret_loads, aliases):
    """Return top-level JSON fields and the field carrying the literal marker."""
    serialized = _canary_json_input(run, aliases)
    if serialized is None or not isinstance(serialized.args[0], ast.Dict):
        return None
    payload = serialized.args[0]
    fields = {}
    for key, value in zip(payload.keys, payload.values):
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
            return None
        if key.value in fields:
            return None
        fields[key.value] = value
    marked = [
        key
        for key, value in fields.items()
        if any(item in secret_loads for item in _canary_nodes(value))
    ]
    if len(marked) != 1:
        return None
    return marked[0], frozenset(fields)


def _canary_json_input(run, aliases):
    """Return a single proven json.dumps input when shell expansion is absent."""
    input_value = _canary_run_input_value(run)
    if input_value is None:
        return None
    serialized = input_value
    if (
        not isinstance(serialized, ast.Call)
        or _canary_call_name(serialized, aliases) != "json.dumps"
    ):
        return None
    if len(serialized.args) != 1 or serialized.keywords:
        return None
    return serialized


def _canary_run_input_value(run):
    """Return a unique input keyword with explicit shell expansion disabled."""
    inputs = [keyword.value for keyword in run.keywords if keyword.arg == "input"]
    shell = [keyword.value for keyword in run.keywords if keyword.arg == "shell"]
    if len(inputs) != 1 or len(shell) > 1:
        return None
    if any(keyword.arg is None for keyword in run.keywords):
        return None
    if shell and not (isinstance(shell[0], ast.Constant) and shell[0].value is False):
        return None
    return inputs[0]


def _canary_absence_assertion(scope, secret_loads):
    """Find a direct assert that the marker is absent from one output name."""
    assertions = []
    for statement in scope.body:
        match = _canary_absence_assertion_line(statement, secret_loads)
        if match is not None:
            assertions.append(match)
    if len(assertions) != 1:
        return None
    return assertions[0][0], assertions[0][1]


def _canary_absence_assertion_line(statement, secret_loads):
    """Recognize one direct secret-not-in-output comparison statement."""
    if not isinstance(statement, ast.Assert) or not isinstance(
        statement.test, ast.Compare
    ):
        return None
    test = statement.test
    if not _canary_secret_not_in_output(test, secret_loads):
        return None
    return test.comparators[0].id, statement.lineno


def _canary_secret_not_in_output(test, secret_loads):
    """Check the exact two-name `secret not in output` predicate shape."""
    return (
        len(test.ops) == 1
        and isinstance(test.ops[0], ast.NotIn)
        and len(test.comparators) == 1
        and isinstance(test.left, ast.Name)
        and isinstance(test.left.ctx, ast.Load)
        and test.left in secret_loads
        and isinstance(test.comparators[0], ast.Name)
        and isinstance(test.comparators[0].ctx, ast.Load)
    )


def _canary_call_name(call, aliases):
    """Resolve imported call aliases through the shared config provenance."""
    index = _canary_index(call)
    if not index.get("complete"):
        return "<incomplete-index>"
    signature = tuple(sorted(aliases.items()))
    if index.get("call_alias_signature") != signature:
        index["call_alias_signature"] = signature
        index["resolved_call_names"] = {}
    resolved = index["resolved_call_names"]
    if id(call) not in resolved:
        resolved[id(call)] = _canary_resolve_call_name(call, aliases)
        index["call_resolution_count"] += 1
    return resolved[id(call)]


def _canary_resolve_call_name(call, aliases):
    """Resolve one uncached call after the source AST has passed its bound."""
    from .security_configuration import _canonical
    from .review_audits import _name

    resolved = _canonical(call, aliases)
    if resolved:
        return resolved
    raw = _name(call.func)
    head = raw.split(".", 1)[0]
    if head in aliases:
        from .review_integrity import _security_flow_bindings

        flow, _ = _security_flow_bindings(call, aliases)
        if head in getattr(call, "_security_shadowed_names", ()) or head not in flow:
            return "<unresolved-import>"
    if not isinstance(call.func, ast.Name):
        return ""
    if call.func.id in getattr(call, "_security_shadowed_names", ()):
        return "<unresolved-name>"
    return call.func.id


def _canary_source_context(scope):
    """Return the scan root and retained source blobs attached by the scanner."""
    module = getattr(scope, "_oracle_module", None)
    context = getattr(module, "_security_source_context", None)
    if not isinstance(context, tuple) or len(context) != 2:
        return None
    workspace, sources = context
    return (workspace, sources) if isinstance(sources, dict) else None


def _canary_local_python_consumer(
    run, scope, relative, aliases, workspace, sources, env_key, payload_contract
):
    """Parse only a statically located local Python consumer from scan bytes."""
    script_name = _canary_local_argv(run, scope, aliases)
    if script_name is None:
        return None
    candidate = _canary_script_path(scope, relative, aliases, workspace, script_name)
    if candidate is None or candidate not in sources or candidate.is_symlink():
        return None
    data = sources[candidate]
    if not isinstance(data, bytes) or len(data) > 1_000_000:
        return None
    return _canary_parse_consumer(candidate, data)


def _canary_parse_consumer(candidate, data):
    """Parse, bind and index one retained consumer source blob."""
    try:
        tree = ast.parse(data, filename=str(candidate))
    except (RecursionError, SyntaxError, UnicodeError, ValueError):
        return None
    index = _canary_index(tree)
    if not index.get("complete"):
        return None
    from .review_audits import _security_aliases
    from .review_integrity import bind_security_call_scopes

    try:
        bind_security_call_scopes(tree)
    except RecursionError:
        return None
    return tree, _security_aliases(index["nodes"])


def _canary_local_argv(run, scope, aliases):
    """Require one explicit interpreter, assigned script, and fixed event arg."""
    items = _canary_local_argv_items(run, aliases)
    if items is None:
        return None
    script_name = _canary_script_argument(items[1], aliases)
    if script_name is None or not _canary_script_binding(
        scope, script_name, run, items, aliases
    ):
        return None

    return script_name


def _canary_local_argv_items(run, aliases):
    """Accept only interpreter, local script path, and one fixed event arg."""
    if len(run.args) != 1 or not isinstance(run.args[0], ast.List):
        return None
    items = run.args[0].elts
    valid = len(items) == 3 and _canary_reference(items[0], aliases) == "sys.executable"
    return items if valid else None


def _canary_script_argument(script, aliases):
    """Return a named script value passed through ``str``."""
    if not isinstance(script, ast.Call) or _canary_call_name(script, aliases) != "str":
        return None
    if (
        len(script.args) != 1
        or script.keywords
        or not isinstance(script.args[0], ast.Name)
    ):
        return None
    return script.args[0].id


def _canary_script_binding(scope, script_name, run, items, aliases):
    """Require one earlier path assignment and safe run options."""
    assigned = [
        statement
        for statement in scope.body
        if isinstance(statement, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == script_name
            for target in statement.targets
        )
    ]
    env_key = _canary_run_environment(run, aliases, scope)
    return (
        len(assigned) == 1
        and assigned[0].lineno < run.lineno
        and isinstance(items[2], ast.Constant)
        and isinstance(items[2].value, str)
        and env_key is not None
        and _canary_run_options(run)
    )


def _canary_run_environment(run, aliases, scope):
    """Bind the subprocess project root directly to the fresh fixture path."""
    values = [item.value for item in run.keywords if item.arg == "env"]
    if len(values) != 1:
        return None
    environment = values[0]
    if isinstance(environment, ast.Name):
        environment = _canary_environment_binding(scope, environment.id, run.lineno)
    return _canary_environment_key(environment, aliases)


def _canary_environment_binding(scope, name, run_line):
    """Resolve one earlier environment dictionary assignment."""
    assignment = _canary_name_assignment(scope, name)
    if assignment is None or assignment.lineno >= run_line:
        return None
    return assignment.value


def _canary_environment_key(environment, aliases):
    """Find one project-root key in a copied environment dictionary."""
    if not isinstance(environment, ast.Dict):
        return None
    if not environment.keys or environment.keys[0] is not None:
        return None
    if _canary_reference(environment.values[0], aliases) != "os.environ":
        return None
    matches = [
        key.value
        for key, value in zip(environment.keys[1:], environment.values[1:])
        if isinstance(key, ast.Constant)
        and isinstance(key.value, str)
        and _canary_call_is(value, "str", aliases, "tmp_path")
    ]
    if len(environment.keys) != len(environment.values) or len(matches) != 1:
        return None
    return matches[0]


def _canary_run_options(run):
    """Reject shell expansion and unsupported subprocess input/output options."""
    values = {item.arg: item.value for item in run.keywords if item.arg is not None}
    if len(values) != len(run.keywords) or set(values) - {
        "input",
        "text",
        "capture_output",
        "env",
        "check",
        "shell",
    }:
        return False
    shell = values.get("shell", ast.Constant(False))
    return isinstance(shell, ast.Constant) and shell.value is False


def _canary_script_path(scope, relative, aliases, workspace, script_name):
    """Resolve a Path(__file__).parents[n] expression without using cwd."""
    statements = [
        statement
        for statement in scope.body
        if isinstance(statement, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == script_name
            for target in statement.targets
        )
    ]
    if len(statements) != 1:
        return None
    expression = _canary_path_expression(statements[0].value, aliases)
    if expression is None:
        return None
    parent_index, suffix = expression
    test_path = workspace / relative
    try:
        base = test_path.parents[parent_index]
        candidate = base.joinpath(*suffix)
        root = workspace.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except (OSError, IndexError, RuntimeError):
        return None
    if not resolved.is_relative_to(root) or resolved.suffix != ".py":
        return None
    return resolved


def _canary_path_expression(node, aliases):
    """Return the __file__ parent index and constant path suffix, if exact."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _canary_path_join(node, aliases)
    return _canary_path_parent_index(node, aliases)


def _canary_path_join(node, aliases):
    """Append one safe constant segment to a Path parent expression."""
    left = _canary_path_expression(node.left, aliases)
    right = node.right
    if left is None or not isinstance(right, ast.Constant):
        return None
    if not isinstance(right.value, str) or not right.value:
        return None
    return left[0], (*left[1], right.value)


def _canary_path_parent_index(node, aliases):
    """Recognize Path(__file__).parents[index] as the expression root."""
    if not isinstance(node, ast.Subscript):
        return None
    if not _canary_file_parents(node.value, aliases):
        return None
    index = node.slice.value if isinstance(node.slice, ast.Constant) else None
    return (index, ()) if isinstance(index, int) and index >= 0 else None


def _canary_file_parents(node, aliases):
    """Require the path parent expression to be rooted at __file__."""
    if not isinstance(node, ast.Attribute) or node.attr != "parents":
        return False
    call = node.value
    if (
        not isinstance(call, ast.Call)
        or _canary_call_name(call, aliases) != "pathlib.Path"
    ):
        return False
    return (
        len(call.args) == 1
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == "__file__"
        and not call.keywords
    )


def _canary_readback_prefix(scope, read):
    """Resolve the unique JSON rglob directory from the test's tmp_path."""
    iterator = _canary_readback_iterator(scope, read)
    if iterator is None:
        return None
    return _canary_tmp_path_parts(iterator.func.value)


def _canary_rglob_directory(iterator):
    """Accept only a single '*.json' rglob below a constant local directory."""
    return (
        isinstance(iterator, ast.Call)
        and isinstance(iterator.func, ast.Attribute)
        and iterator.func.attr == "rglob"
        and len(iterator.args) == 1
        and isinstance(iterator.args[0], ast.Constant)
        and iterator.args[0].value == "*.json"
        and not iterator.keywords
        and _canary_tmp_path_parts(iterator.func.value) is not None
    )


def _canary_tmp_path_is_closed(scope, run, read):
    """Require tmp_path only at the writer root and matching readback prefix."""
    env_names = _canary_environment_tmp_references(scope, run)
    iterator = _canary_readback_iterator(scope, read)
    if len(env_names) != 1 or iterator is None:
        return False
    read_root = _canary_tmp_path_root(iterator.func.value)
    if read_root is None:
        return False
    names = [
        node
        for node in _canary_nodes(scope, ast.Name)
        if node.id == "tmp_path" and isinstance(node.ctx, ast.Load)
    ]
    return len(names) == 2 and set(map(id, names)) == {id(env_names[0]), id(read_root)}


def _canary_environment_tmp_references(scope, run):
    """Return fixture references in the subprocess environment expression."""
    env = next((item.value for item in run.keywords if item.arg == "env"), None)
    if isinstance(env, ast.Name):
        assignment = _canary_name_assignment(scope, env.id)
        env = assignment.value if assignment is not None else None
    return (
        [
            node
            for node in _canary_nodes(env, ast.Name)
            if node.id == "tmp_path" and isinstance(node.ctx, ast.Load)
        ]
        if env is not None
        else []
    )


def _canary_readback_iterator(scope, read):
    """Return the exact rglob iterator used by the asserted read_text value."""
    if not _canary_read_text_call(read):
        return None
    record = read.func.value
    if not isinstance(record, ast.Name):
        return None
    assignment = _canary_name_assignment(scope, record.id)
    iterator = _canary_next_iterator(assignment)
    return iterator if _canary_rglob_directory(iterator) else None


def _canary_read_text_call(read):
    """Require one UTF-8 text read with no extra arguments."""
    if not isinstance(read.func, ast.Attribute) or read.func.attr != "read_text":
        return False
    if read.args or len(read.keywords) != 1 or read.keywords[0].arg != "encoding":
        return False
    value = read.keywords[0].value
    return isinstance(value, ast.Constant) and value.value == "utf-8"


def _canary_next_iterator(assignment):
    """Resolve one direct or generator-backed next() expression."""
    if assignment is None or not isinstance(assignment.value, ast.Call):
        return None
    parent = assignment.value
    if (
        not isinstance(parent.func, ast.Name)
        or parent.func.id != "next"
        or len(parent.args) != 1
    ):
        return None
    generator = parent.args[0]
    if not isinstance(generator, ast.GeneratorExp):
        return generator
    if len(generator.generators) != 1:
        return None
    return generator.generators[0].iter


def _canary_tmp_path_root(node):
    """Return the root fixture name in a constant-only Path expression."""
    if isinstance(node, ast.Name) and node.id == "tmp_path":
        return node
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _canary_tmp_path_root(node.left)
    return None


def _canary_tmp_path_parts(node):
    """Return a constant suffix rooted directly at the pytest tmp_path fixture."""
    if isinstance(node, ast.Name) and node.id == "tmp_path":
        return "tmp_path", ()
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        base = _canary_tmp_path_parts(node.left)
        if base is None or not isinstance(node.right, ast.Constant):
            return None
        if not isinstance(node.right.value, str) or not node.right.value:
            return None
        return base[0], (*base[1], node.right.value)
    return None


def _canary_run_project_root(run, scope, aliases):
    """Return the tmp_path fixture and environment key bound to the consumer."""
    env_key = _canary_run_environment(run, aliases, scope)
    if env_key is None:
        return None
    return "tmp_path", env_key


def _canary_digest_only_output(tree, aliases, env_key, payload_contract):
    """Recognize a narrow local JSON digest recorder with a linked output root."""
    helpers = _canary_digest_helpers(tree, aliases)
    if helpers is None:
        return None
    canonical_name, digest_name = helpers
    entrypoint = _canary_entrypoint(tree, aliases)
    if entrypoint is None or not _canary_consumer_call_inventory(
        tree, aliases, {canonical_name, digest_name, entrypoint}
    ):
        return None
    input_name = _canary_payload_is_digest_only(
        tree, aliases, digest_name, payload_contract
    )
    if input_name is None:
        return None
    prefix = _canary_writer_is_local(
        tree, aliases, canonical_name, digest_name, env_key, input_name
    )
    if prefix is None:
        return None
    return prefix


def _canary_consumer_call_inventory(tree, aliases, local_helpers):
    """Fail closed on extra call families that could export or retain payloads."""
    calls = _canary_nodes(tree, ast.Call)
    counts = Counter(_canary_call_name(node, aliases) for node in calls)
    names = set(counts)
    attributes = {
        node.func.attr for node in calls if isinstance(node.func, ast.Attribute)
    }
    index = _canary_index(tree)
    allowed = (
        names
        <= {
            "datetime.datetime.now",
            "hashlib.sha256",
            "json.dumps",
            "json.load",
            "json.loads",
            "os.environ.get",
            "os.getcwd",
            "pathlib.Path",
            "re.sub",
            "str",
            "isinstance",
            "len",
            "sorted",
            "SystemExit",
            "",
        }
        | local_helpers
        and attributes
        <= {
            "now",
            "sha256",
            "dumps",
            "load",
            "loads",
            "get",
            "getcwd",
            "Path",
            "sub",
            "hexdigest",
            "encode",
            "resolve",
            "mkdir",
            "glob",
            "read_text",
            "lower",
            "write_bytes",
            "isoformat",
            "replace",
        }
        and _canary_import_inventory(tree)
    )
    return (
        allowed
        and all(
            counts.get(name, 0) == count
            for name, count in {
                "json.load": 1,
                "json.loads": 1,
                "os.environ.get": 1,
            }.items()
        )
        and sum(
            isinstance(node.func, ast.Attribute) and node.func.attr == "write_bytes"
            for node in calls
        )
        == 1
        and not index["attribute_writes"]
        and not index["subscript_writes"]
        and _canary_prior_output_read(tree, aliases)
    )


def _canary_import_inventory(tree):
    """Reject relative or nonstandard imports with unreviewed import-time code."""
    allowed = {
        "__future__",
        "hashlib",
        "json",
        "os",
        "pathlib",
        "re",
        "sys",
        "datetime",
    }
    for node in (
        *_canary_nodes(tree, ast.Import),
        *_canary_nodes(tree, ast.ImportFrom),
    ):
        if isinstance(node, ast.Import):
            if any(item.name.split(".", 1)[0] not in allowed for item in node.names):
                return False
        elif isinstance(node, ast.ImportFrom):
            if node.level or node.module not in allowed:
                return False
    return True


def _canary_digest_helpers(tree, aliases):
    """Discover the local canonical JSON and SHA256 helper names structurally."""
    functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    canonical = [
        node
        for node in functions
        if len(node.args.args) == 1
        and len(node.body) == 1
        and isinstance(node.body[0], ast.Return)
        and _canary_canonical_return(node.body[0].value, node, aliases)
    ]
    if len(canonical) != 1:
        return None
    digest = [
        node
        for node in functions
        if len(node.args.args) == 1
        and len(node.body) == 1
        and isinstance(node.body[0], ast.Return)
        and _canary_digest_return(node.body[0].value, node, aliases, canonical[0].name)
    ]
    if len(digest) != 1:
        return None
    names = (canonical[0].name, digest[0].name)
    if any(
        not _canary_helper_unrebound(tree, name, function)
        for name, function in zip(names, (canonical[0], digest[0]))
    ):
        return None
    return names


def _canary_entrypoint(tree, aliases):
    """Find the sole main function reached by a guarded SystemExit call."""
    index = _canary_index(tree)
    if not index.get("complete") or any(
        index["writes"].get(name) for name in ("SystemExit", "__name__")
    ):
        return None
    functions = _canary_functions(tree)
    if functions is None:
        return None
    matches = [
        entry
        for guard in tree.body
        if isinstance(guard, ast.If)
        and (entry := _canary_guard_entry(guard, aliases, functions, index))
    ]
    return matches[0] if len(matches) == 1 else None


def _canary_functions(tree):
    """Index unique top-level sync and async function bindings."""
    definitions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    functions = {node.name: node for node in definitions}
    return functions if len(functions) == len(definitions) else None


def _canary_guard_entry(guard, aliases, functions, index):
    """Resolve one exact guarded call to an unchanged synchronous function."""
    name = _canary_guard_call_name(guard, aliases)
    function = functions.get(name) if name is not None else None
    if not isinstance(function, ast.FunctionDef) or index["writes"].get(name) != [
        function
    ]:
        return None
    return name


def _canary_guard_call_name(guard, aliases):
    """Return the call target only for one exact module entry guard."""
    if not _canary_main_guard_test(guard.test) or len(guard.body) != 1 or guard.orelse:
        return None
    statement = guard.body[0]
    if not isinstance(statement, ast.Raise):
        return None
    return _canary_exit_target(statement.exc, aliases)


def _canary_exit_target(call, aliases):
    """Extract an unshadowed function name from one SystemExit invocation."""
    if (
        not isinstance(call, ast.Call)
        or _canary_call_name(call, aliases) != "SystemExit"
    ):
        return None
    if len(call.args) != 1 or call.keywords or not isinstance(call.args[0], ast.Call):
        return None
    entry = call.args[0]
    if (
        not isinstance(entry.func, ast.Name)
        or entry.args
        or entry.keywords
        or getattr(entry, "_security_shadowed_names", ())
    ):
        return None
    return entry.func.id


def _canary_main_guard_test(test):
    """Require the exact module-name equals-main guard without extra tests."""
    return (
        isinstance(test, ast.Compare)
        and len(test.ops) == len(test.comparators) == 1
        and isinstance(test.ops[0], ast.Eq)
        and _canary_main_name_constant(test.left, test.comparators[0])
    )


def _canary_main_name_constant(left, right):
    """Match __name__ and __main__ on either side of one equality."""
    return (
        isinstance(left, ast.Name)
        and left.id == "__name__"
        and isinstance(right, ast.Constant)
        and right.value == "__main__"
    ) or (
        isinstance(right, ast.Name)
        and right.id == "__name__"
        and isinstance(left, ast.Constant)
        and left.value == "__main__"
    )


def _canary_canonical_return(value, function, aliases):
    """Match canonical JSON serialization with deterministic compact options."""
    if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Attribute):
        return False
    if value.func.attr != "encode" or len(value.args) != 1:
        return False
    serialized = value.func.value
    if not _canary_canonical_serialization(serialized, function, aliases):
        return False
    return _canary_canonical_encoding(value, serialized)


def _canary_canonical_serialization(serialized, function, aliases):
    """Require json.dumps of the sole canonicalizer argument."""
    if (
        not isinstance(serialized, ast.Call)
        or _canary_call_name(serialized, aliases) != "json.dumps"
    ):
        return False
    return (
        len(serialized.args) == 1
        and isinstance(serialized.args[0], ast.Name)
        and serialized.args[0].id == function.args.args[0].arg
    )


def _canary_canonical_encoding(value, serialized):
    """Check compact deterministic JSON options and UTF-8 output encoding."""
    options = {item.arg: item.value for item in serialized.keywords}
    return (
        len(options) == len(serialized.keywords)
        and set(options) == {"sort_keys", "separators", "ensure_ascii"}
        and isinstance(options.get("sort_keys"), ast.Constant)
        and options["sort_keys"].value is True
        and isinstance(options.get("separators"), ast.Tuple)
        and [
            item.value
            for item in options["separators"].elts
            if isinstance(item, ast.Constant)
        ]
        == [",", ":"]
        and isinstance(options.get("ensure_ascii"), ast.Constant)
        and options["ensure_ascii"].value is False
        and isinstance(value.args[0], ast.Constant)
        and value.args[0].value == "utf-8"
    )


def _canary_digest_return(value, function, aliases, canonical_name):
    """Match SHA256 over the canonical serialization of one function argument."""
    if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Attribute):
        return False
    if value.func.attr != "hexdigest" or value.args or value.keywords:
        return False
    hashed = value.func.value
    return (
        isinstance(hashed, ast.Call)
        and _canary_call_name(hashed, aliases) == "hashlib.sha256"
        and len(hashed.args) == 1
        and not hashed.keywords
        and _canary_call_is(
            hashed.args[0], canonical_name, aliases, function.args.args[0].arg
        )
    )


def _canary_payload_is_digest_only(tree, aliases, digest_name, payload_contract):
    """Ensure the only read of command-bearing JSON is the discovered digest call."""
    payload_name = _canary_stdin_payload_name(tree, aliases)
    if payload_name is None:
        return None
    return _canary_digest_input_name(
        tree, aliases, digest_name, payload_name, payload_contract
    )


def _canary_stdin_payload_name(tree, aliases):
    """Find one direct JSON stdin load assigned to a local name."""
    loads = [
        node
        for node in _canary_nodes(tree, ast.Call)
        if _canary_call_name(node, aliases) == "json.load"
    ]
    if len(loads) != 1 or len(loads[0].args) != 1:
        return None
    if _canary_reference(loads[0].args[0], aliases) != "sys.stdin":
        return None
    assignment = _canary_parent(tree, loads[0])
    if not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1:
        return None
    return (
        assignment.targets[0].id
        if isinstance(assignment.targets[0], ast.Name)
        else None
    )


def _canary_digest_input_name(tree, aliases, digest_name, payload_name, contract):
    """Validate payload field reads and the sole digest call input use."""
    payload_key, allowed_keys = contract
    names = [node for node in _canary_nodes(tree, ast.Name)]
    payload = [node for node in names if node.id == payload_name]
    stores = [node for node in payload if isinstance(node.ctx, ast.Store)]
    if not stores or any(
        not _canary_payload_store(tree, node, aliases) for node in stores
    ):
        return None
    payload_reads = [node for node in payload if isinstance(node.ctx, ast.Load)]
    if not _canary_payload_fields(tree, payload_reads, allowed_keys, payload_key):
        return None
    extracted = _canary_payload_extraction(tree, payload_name, payload_key)
    if extracted is None:
        return None
    input_name, extraction = extracted
    uses = [
        node
        for node in names
        if node.id == input_name and isinstance(node.ctx, ast.Load)
    ]
    if len(uses) != 1:
        return None
    if not _canary_call_is(
        _canary_parent(tree, uses[0]), digest_name, aliases, input_name
    ):
        return None
    if (
        sum(isinstance(node.ctx, ast.Store) for node in names if node.id == input_name)
        != 1
    ):
        return None
    return input_name


def _canary_payload_fields(tree, payload_reads, allowed_keys, payload_key):
    """Reject JSON fields outside the caller's literal input object."""
    accessed = [
        key
        for node in payload_reads
        if (key := _canary_payload_field_key(tree, node)) is not None
    ]
    return _canary_allowed_payload_keys(accessed, allowed_keys, payload_key)


def _canary_payload_field_key(tree, node):
    """Return a literal field key or a sentinel for the dict type check."""
    attribute = _canary_parent(tree, node)
    if _canary_is_dict_check_use(attribute, node):
        return None
    call = _canary_parent(tree, attribute) if attribute is not None else None
    return _canary_payload_get_key(attribute, call, node)


def _canary_payload_get_key(attribute, call, node):
    """Return a literal get() key, rejecting defaults on marked input fields."""
    if not _canary_payload_get_call(attribute, call, node):
        return False
    key = call.args[0]
    return key.value if _canary_payload_key_argument(call, key) else False


def _canary_payload_get_call(attribute, call, node):
    """Check that the payload name is the receiver of a direct get() call."""
    return (
        isinstance(attribute, ast.Attribute)
        and isinstance(call, ast.Call)
        and attribute.attr == "get"
        and attribute.value is node
        and call.func is attribute
        and 1 <= len(call.args) <= 2
        and not call.keywords
    )


def _canary_payload_key_argument(call, key):
    """Validate a literal field key and reject a default for command input."""
    return isinstance(key, ast.Constant) and not (
        len(call.args) == 2 and key.value == "tool_input"
    )


def _canary_is_dict_check_use(attribute, node):
    """Recognize the payload mapping type guard, not an input data read."""
    return (
        isinstance(attribute, ast.Call)
        and isinstance(attribute.func, ast.Name)
        and attribute.func.id == "isinstance"
        and len(attribute.args) == 2
        and attribute.args[0] is node
        and isinstance(attribute.args[1], ast.Name)
        and attribute.args[1].id == "dict"
    )


def _canary_allowed_payload_keys(accessed, allowed_keys, payload_key):
    """Allow only caller-supplied fields and exactly two input-key reads."""
    return (
        set(accessed) <= set(allowed_keys)
        and accessed.count(payload_key) == 2
        and all(isinstance(key, str) for key in accessed)
    )


def _canary_payload_store(tree, node, aliases):
    """Permit JSON input binding and empty-object error fallbacks only."""
    assignment = _canary_parent(tree, node)
    if not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1:
        return False
    value = assignment.value
    if isinstance(value, ast.Dict) and not value.keys:
        return True
    return (
        isinstance(value, ast.Call) and _canary_call_name(value, aliases) == "json.load"
    )


def _canary_payload_extraction(tree, payload_name, payload_key):
    """Find one dict-checked extraction binding for the marker-bearing field."""
    matches = [
        result
        for node in _canary_nodes(tree, ast.Assign)
        if (result := _canary_extraction_assignment(node, payload_name, payload_key))
    ]
    return matches[0] if len(matches) == 1 else None


def _canary_extraction_assignment(node, payload_name, payload_key):
    """Return one assignment guarded by a dict check and empty fallback."""
    if not isinstance(node, ast.Assign) or len(node.targets) != 1:
        return None
    if not isinstance(node.targets[0], ast.Name) or not isinstance(
        node.value, ast.IfExp
    ):
        return None
    if not _canary_dict_guard(node.value.test, payload_name, payload_key):
        return None
    if not _canary_is_payload_get(node.value.body, payload_name, payload_key):
        return None
    fallback = node.value.orelse
    return (
        (node.targets[0].id, node.value)
        if isinstance(fallback, ast.Dict) and not fallback.keys
        else None
    )


def _canary_dict_guard(test, payload_name, payload_key):
    """Require at least one matching isinstance(field, dict) check."""
    return any(
        _canary_is_dict_type_check(item, payload_name, payload_key)
        for item in _canary_nodes(test, ast.Call)
    )


def _canary_is_payload_get(node, payload_name, payload_key):
    """Match one named JSON field access without inspecting its contents."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == payload_name
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == payload_key
    )


def _canary_is_dict_type_check(node, payload_name, payload_key):
    """Require isinstance(field, dict) before hashing the extracted value."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "isinstance"
        and len(node.args) == 2
        and _canary_is_payload_get(node.args[0], payload_name, payload_key)
        and isinstance(node.args[1], ast.Name)
        and node.args[1].id == "dict"
    )


def _canary_writer_is_local(
    tree, aliases, canonical_name, digest_name, env_key, input_name
):
    """Require one local writer to serialize the digest-bearing record."""
    write = _canary_unique_write_call(tree)
    record_name = _canary_write_record_name(write, aliases, canonical_name)
    if write is None or record_name is None:
        return None
    directory = _canary_writer_directory(tree, write)
    if not _canary_prior_output_read(tree, aliases, directory):
        return None
    prefix = _canary_writer_path(tree, write.func.value, aliases, env_key)
    linked = _canary_record_contains_digest(
        tree, aliases, digest_name, input_name, record_name
    )
    return prefix if prefix and linked else None


def _canary_unique_write_call(tree):
    """Find exactly one byte writer among all file-output methods."""
    writes = [
        node
        for node in _canary_nodes(tree, ast.Call)
        if isinstance(node.func, ast.Attribute)
        and node.func.attr in {"write_bytes", "write_text"}
    ]
    return (
        writes[0] if len(writes) == 1 and writes[0].func.attr == "write_bytes" else None
    )


def _canary_write_record_name(write, aliases, canonical_name):
    """Return the record variable passed through canonical serialization."""
    if write is None or len(write.args) != 1 or write.keywords:
        return None
    payload = write.args[0]
    if not isinstance(payload, ast.BinOp) or not isinstance(payload.op, ast.Add):
        return None
    if not isinstance(payload.right, ast.Constant) or payload.right.value != b"\n":
        return None
    return _canary_encoded_record_name(payload.left, aliases, canonical_name)


def _canary_encoded_record_name(encoded, aliases, canonical_name):
    """Return a local record name serialized by the canonical helper."""
    if (
        not isinstance(encoded, ast.Call)
        or _canary_call_name(encoded, aliases) != canonical_name
    ):
        return None
    if (
        len(encoded.args) != 1
        or encoded.keywords
        or not isinstance(encoded.args[0], ast.Name)
    ):
        return None
    return encoded.args[0].id


def _canary_writer_directory(tree, write):
    """Return the parent directory variable for the written path."""
    if write is None or not isinstance(write.func.value, ast.Name):
        return None
    output = _canary_name_assignment(tree, write.func.value.id)
    if output is None or not isinstance(output.value, ast.BinOp):
        return None
    return output.value.left if isinstance(output.value.left, ast.Name) else None


def _canary_prior_output_read(tree, aliases, target=None):
    """Bind prior-record reads to the same writer directory and digest field."""
    prior = _canary_previous_read(tree)
    if prior is None:
        return False
    read, record_name = prior
    directory = _canary_previous_record_directory(tree, record_name)
    if directory is None or not _canary_same_name(directory, target):
        return False
    return _canary_previous_record_digest(tree, read, aliases)


def _canary_previous_read(tree):
    """Find one UTF-8 read of the latest record file in a local list."""
    reads = [
        node
        for node in _canary_nodes(tree, ast.Call)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "read_text"
    ]
    if len(reads) != 1 or not _canary_read_text_call(reads[0]):
        return None
    name = _canary_latest_record_name(reads[0].func.value)
    return (reads[0], name) if name is not None else None


def _canary_latest_record_name(latest):
    """Return the name holding the final sorted record, if exact."""
    if not isinstance(latest, ast.Subscript) or not isinstance(latest.value, ast.Name):
        return None
    if not isinstance(latest.slice, ast.UnaryOp) or not isinstance(
        latest.slice.op, ast.USub
    ):
        return None
    if (
        not isinstance(latest.slice.operand, ast.Constant)
        or latest.slice.operand.value != 1
    ):
        return None
    return latest.value.id


def _canary_previous_record_directory(tree, record_name):
    """Resolve sorted JSON record names to their producing directory."""
    records = _canary_name_assignment(tree, record_name)
    if records is None or not isinstance(records.value, ast.Call):
        return None
    glob = _canary_sorted_json_glob(records.value)
    if glob is None:
        return None
    return glob.func.value


def _canary_sorted_json_glob(ordered):
    """Return a single *.json glob passed directly through sorted()."""
    if not _canary_sorted_one_arg(ordered):
        return None
    glob = ordered.args[0]
    return glob if _canary_json_glob(glob) else None


def _canary_sorted_one_arg(node):
    """Require a direct one-argument call to sorted()."""
    return (
        isinstance(node.func, ast.Name)
        and node.func.id == "sorted"
        and len(node.args) == 1
        and not node.keywords
    )


def _canary_json_glob(glob):
    """Require one literal JSON glob on a directory receiver."""
    if not isinstance(glob, ast.Call) or not isinstance(glob.func, ast.Attribute):
        return False
    if glob.func.attr != "glob" or len(glob.args) != 1 or glob.keywords:
        return False
    return isinstance(glob.args[0], ast.Constant) and glob.args[0].value == "*.json"


def _canary_same_name(first, second):
    """Require equivalent local path variable identities when supplied."""
    return second is None or (
        isinstance(first, ast.Name)
        and isinstance(second, ast.Name)
        and first.id == second.id
    )


def _canary_previous_record_digest(tree, read, aliases):
    """Require the prior JSON file to contribute only its event digest."""
    loaded = _canary_parent(tree, read)
    if (
        not isinstance(loaded, ast.Call)
        or _canary_call_name(loaded, aliases) != "json.loads"
    ):
        return False
    if len(loaded.args) != 1 or loaded.args[0] is not read or loaded.keywords:
        return False
    prior_name = _canary_loaded_record_name(tree, loaded)
    return prior_name is not None and _canary_prior_digest_field(tree, prior_name)


def _canary_loaded_record_name(tree, loaded):
    """Return the sole name bound to the parsed prior event record."""
    assignment = _canary_parent(tree, loaded)
    if not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1:
        return None
    target = assignment.targets[0]
    return target.id if isinstance(target, ast.Name) else None


def _canary_prior_digest_field(tree, prior_name):
    """Require the prior record's sole read to select event_sha256."""
    reads = [
        node
        for node in _canary_nodes(tree, ast.Name)
        if node.id == prior_name and isinstance(node.ctx, ast.Load)
    ]
    if len(reads) != 1:
        return False
    attribute = _canary_parent(tree, reads[0])
    digest_field = _canary_parent(tree, attribute) if attribute is not None else None
    return _canary_event_digest_get(digest_field, reads[0])


def _canary_event_digest_get(call, prior_read):
    """Recognize one literal event_sha256 lookup with no fallback value."""
    return (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "get"
        and call.func.value is prior_read
        and len(call.args) == 1
        and isinstance(call.args[0], ast.Constant)
        and call.args[0].value == "event_sha256"
        and not call.keywords
    )


def _canary_writer_path(tree, receiver, aliases, env_key):
    """Derive the output prefix from an environment-rooted local path."""
    target = _canary_writer_target(tree, receiver, aliases)
    if target is None:
        return None
    rooted = _canary_rooted_path_parts(target.value)
    if rooted is None:
        return None
    root_name, segments = rooted
    prefix = _canary_constant_prefix(segments)
    if not _canary_path_segments_safe(tree, segments, len(prefix), aliases):
        return None
    root = _canary_name_assignment(tree, root_name)
    return (
        ("tmp_path", prefix)
        if root and _canary_root_env_expression(root.value, aliases, env_key)
        else None
    )


def _canary_writer_target(tree, receiver, aliases):
    """Resolve the output file variable to its directory and safe filename."""
    if not isinstance(receiver, ast.Name):
        return None
    assignment = _canary_name_assignment(tree, receiver.id)
    if assignment is None or not isinstance(assignment.value, ast.BinOp):
        return None
    output = assignment.value
    if not isinstance(output.op, ast.Div) or not isinstance(output.left, ast.Name):
        return None
    if not _canary_safe_path_value(tree, output.right, aliases):
        return None
    return _canary_name_assignment(tree, output.left.id)


def _canary_path_segments_safe(tree, segments, prefix_length, aliases):
    """Validate each dynamic component following the constant directory prefix."""
    suffix = segments[prefix_length:]
    return bool(
        prefix_length
        and all(_canary_safe_path_value(tree, item, aliases) for item in suffix)
    )


def _canary_rooted_path_parts(node):
    """Separate the root variable from ordered literal or dynamic components."""
    if isinstance(node, ast.Name):
        return node.id, ()
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left = _canary_rooted_path_parts(node.left)
        return (left[0], (*left[1], node.right)) if left else None
    return None


def _canary_constant_prefix(segments):
    """Return a safe directory prefix before the first dynamic component."""
    result = []
    for node in segments:
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            break
        if node.value in {"", ".", ".."} or "/" in node.value or "\\" in node.value:
            return ()
        result.append(node.value)
    return tuple(result)


def _canary_safe_path_value(tree, node, aliases):
    """Accept hash-derived names and separator-sanitized filename components."""
    if isinstance(node, ast.Name):
        return _canary_safe_path_name(tree, node, aliases)
    if isinstance(node, ast.JoinedStr):
        return _canary_safe_fstring(tree, node, aliases)
    if isinstance(node, ast.Call) and _canary_call_name(node, aliases) == "re.sub":
        return _canary_sanitized_component(node)
    return False


def _canary_safe_path_name(tree, node, aliases):
    """Validate a variable as a digest slice or nonnegative index."""
    binding = _canary_name_assignment(tree, node.id)
    return binding is not None and (
        _canary_hash_path_value(binding.value, aliases)
        or _canary_nonnegative_integer(binding.value)
    )


def _canary_safe_fstring(tree, node, aliases):
    """Reject separators in literals and recursively check formatted parts."""
    return all(_canary_safe_fstring_part(tree, item, aliases) for item in node.values)


def _canary_safe_fstring_part(tree, item, aliases):
    """Check one constant or formatted component of a path filename."""
    if isinstance(item, ast.Constant) and isinstance(item.value, str):
        return "/" not in item.value and "\\" not in item.value
    return isinstance(item, ast.FormattedValue) and _canary_safe_path_value(
        tree, item.value, aliases
    )


def _canary_hash_path_value(value, aliases):
    """Recognize a SHA256 hexadecimal slice as a safe path segment."""
    return (
        isinstance(value, ast.Subscript)
        and isinstance(value.value, ast.Call)
        and isinstance(value.value.func, ast.Attribute)
        and value.value.func.attr == "hexdigest"
        and isinstance(value.value.func.value, ast.Call)
        and _canary_call_name(value.value.func.value, aliases) == "hashlib.sha256"
    )


def _canary_sanitized_component(call):
    """Recognize a slug replacement whose pattern excludes path separators."""
    return (
        len(call.args) == 3
        and _canary_slug_pattern(call.args[0])
        and _canary_slug_replacement(call.args[1])
        and _canary_lowered_slug(call.args[2])
    )


def _canary_slug_pattern(node):
    """Require a character class restricted to letters, digits, and hyphens."""
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return False
    pattern = node.value
    allowed = (
        pattern[2:-2] if pattern.startswith("[^") and pattern.endswith("]+") else ""
    )
    return (
        bool(allowed)
        and all(char.isalnum() or char == "-" for char in allowed)
        and ("a-z" in allowed and "0-9" in allowed)
    )


def _canary_slug_replacement(node):
    """Require a dotless, separator-free replacement string."""
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and "/" not in node.value
        and "\\" not in node.value
        and "." not in node.value
    )


def _canary_lowered_slug(node):
    """Require a lower() source call for the slug input."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "lower"
    )


def _canary_nonnegative_integer(value):
    """Recognize a list length plus a nonnegative integer for filenames."""
    return (
        isinstance(value, ast.BinOp)
        and isinstance(value.op, ast.Add)
        and isinstance(value.left, ast.Call)
        and isinstance(value.left.func, ast.Name)
        and value.left.func.id == "len"
        and len(value.left.args) == 1
        and not value.left.keywords
        and isinstance(value.right, ast.Constant)
        and isinstance(value.right.value, int)
        and value.right.value >= 0
    )


def _canary_helper_unrebound(tree, name, definition):
    """Reject competing bindings and mutations of a discovered module helper."""
    index = _canary_index(tree)
    if not index.get("complete") or index["writes"].get(name) != [definition]:
        return False
    if index["subscript_writes"] or any(
        _canary_attribute_mentions(node, name) for node in index["attribute_writes"]
    ):
        return False
    return all(
        isinstance(parent := _canary_parent(tree, node), ast.Call)
        and parent.func is node
        for node in _canary_nodes(tree, ast.Name)
        if node.id == name and isinstance(node.ctx, ast.Load)
    )


def _canary_attribute_mentions(node, name):
    """Detect writes through a helper name or an attribute named for it."""
    if node.attr == name:
        return True
    receiver = node.value
    while isinstance(receiver, ast.Attribute):
        if receiver.attr == name:
            return True
        receiver = receiver.value
    return isinstance(receiver, ast.Name) and receiver.id == name


def _canary_root_env_expression(value, aliases, env_key):
    """Require Path(env root).resolve() with no fallback to an unrelated root."""
    environment = _canary_resolved_path_input(value, aliases)
    return environment is not None and _canary_environment_root_matches(
        environment, aliases, env_key
    )


def _canary_resolved_path_input(value, aliases):
    """Return the argument to one Path(...).resolve() call."""
    if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Attribute):
        return None
    if value.func.attr != "resolve" or value.args or value.keywords:
        return None
    path = value.func.value
    if (
        not isinstance(path, ast.Call)
        or _canary_call_name(path, aliases) != "pathlib.Path"
    ):
        return None
    if len(path.args) != 1 or path.keywords:
        return None
    return path.args[0]


def _canary_environment_root_matches(env, aliases, env_key):
    """Require the discovered environment key and cwd fallback exactly."""
    if (
        not isinstance(env, ast.Call)
        or _canary_call_name(env, aliases) != "os.environ.get"
    ):
        return False
    return (
        len(env.args) == 2
        and isinstance(env.args[0], ast.Constant)
        and env.args[0].value == env_key
        and not env.keywords
        and isinstance(env.args[1], ast.Call)
        and _canary_call_name(env.args[1], aliases) == "os.getcwd"
    )


def _canary_root_env_key(tree, aliases, env_key):
    """Require the consumer's only environment-root lookup to match the caller."""
    lookups = [
        node
        for node in _canary_nodes(tree, ast.Call)
        if _canary_call_name(node, aliases) == "os.environ.get"
    ]
    return (
        len(lookups) == 1
        and len(lookups[0].args) == 2
        and isinstance(lookups[0].args[0], ast.Constant)
        and lookups[0].args[0].value == env_key
    )


def _canary_record_contains_digest(tree, aliases, digest_name, input_name, record_name):
    """Link the raw-input digest mapping to the serialized record."""
    mappings = [
        node
        for node in _canary_nodes(tree, ast.Dict)
        if any(
            _canary_call_is(value, digest_name, aliases, input_name)
            for value in node.values
        )
    ]
    if len(mappings) != 1:
        return False
    assignment = _canary_parent(tree, mappings[0])
    if not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1:
        return False
    if not isinstance(assignment.targets[0], ast.Name):
        return False
    record = _canary_name_assignment(tree, record_name)
    core_name = assignment.targets[0].id
    return bool(
        record
        and isinstance(record.value, ast.Dict)
        and any(
            key is None and isinstance(value, ast.Name) and value.id == core_name
            for key, value in zip(record.value.keys, record.value.values)
        )
    )


def _canary_call_is(node, name, aliases, argument):
    """Check a one-argument call by resolved name and exact local variable."""
    return (
        isinstance(node, ast.Call)
        and _canary_call_name(node, aliases) == name
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == argument
    )


def _canary_reference(node, aliases):
    """Resolve only an imported name proven at the enclosing call site."""
    from .review_audits import _name

    raw = _name(node)
    head, _, tail = raw.partition(".")
    context = node
    while not isinstance(context, (ast.Call, ast.Assign, ast.AnnAssign)):
        context = _canary_parent(node, context)
        if context is None:
            return ""
    binding = _canary_reference_binding(context, head, aliases)
    if not binding:
        return ""
    return (
        raw
        if raw == binding or raw.startswith(binding + ".")
        else binding + ("." + tail if tail else "")
    )


def _canary_reference_binding(context, head, aliases):
    """Return a standard import still bound at one call or assignment site."""
    from .review_integrity import _security_scope_request_aliases
    from .security_configuration import _relative_binding

    scope = getattr(context, "_security_lexical_scope", None)
    if not isinstance(scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    flow_statement = (
        getattr(context, "_security_flow_statement", None)
        if isinstance(context, ast.Call)
        else context
    )
    binding = _security_scope_request_aliases(scope, aliases, flow_statement).get(head)
    if (
        binding is None
        or binding != aliases.get(head)
        or _relative_binding(context, head)
    ):
        return None
    return binding


def _canary_name_assignment(tree, name):
    """Return one simple assignment to a name in a bounded consumer module."""
    assignments = _canary_named_assignments(tree, name)
    if len(assignments) != 1:
        return None
    assignment = assignments[0]
    return (
        assignment
        if not _canary_has_competing_binding(tree, name, assignment.targets[0])
        else None
    )


def _canary_named_assignments(tree, name):
    """Collect direct single-name assignments to one local binding."""
    return [
        node
        for node in _canary_nodes(tree, ast.Assign)
        if len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == name
    ]


def _canary_has_competing_binding(tree, name, assignment_target):
    """Reject writes, definitions, and imports that replace an assigned name."""
    writes = _canary_index(tree).get("writes", {}).get(name, ())
    return len(writes) != 1 or writes[0] is not assignment_target


def _canary_index(root):
    """Build or reuse one capped parent and type index per source AST."""
    module = (
        root if isinstance(root, ast.Module) else getattr(root, "_oracle_module", None)
    )
    if module is None:
        from .review_integrity import _security_module_scope

        module = _security_module_scope(root)
    if not isinstance(module, ast.Module):
        return {"complete": False}
    cached = getattr(module, "_canary_ast_index", None)
    if cached is not None:
        return cached
    index = _canary_build_index(module)
    module._canary_ast_index = index
    return index


def _canary_build_index(module):
    """Index one module in a bounded preorder traversal."""
    nodes, parents, starts, ends, types, positions, writes, attrs, subscripts = (
        [],
        {},
        {},
        {},
        {},
        {},
        {},
        [],
        [],
    )
    for node, parent, leaving in _canary_walk_events(module):
        if leaving:
            ends[id(node)] = len(nodes)
            continue
        if len(nodes) >= 100_000:
            return {"complete": False, "node_visits": len(nodes)}
        starts[id(node)] = len(nodes)
        parents[id(node)] = parent
        nodes.append(node)
        node._oracle_module = module
        types.setdefault(type(node), []).append(node)
        positions.setdefault(type(node), []).append(len(nodes) - 1)
        _canary_index_bindings(node, writes, attrs, subscripts)
    index = {
        "complete": True,
        "nodes": tuple(nodes),
        "parents": parents,
        "starts": starts,
        "ends": ends,
        "types": {kind: tuple(items) for kind, items in types.items()},
        "positions": {kind: tuple(items) for kind, items in positions.items()},
        "writes": writes,
        "attribute_writes": tuple(attrs),
        "subscript_writes": tuple(subscripts),
        "node_visits": len(nodes),
        "parent_lookups": 0,
        "call_alias_signature": None,
        "resolved_call_names": {},
        "call_resolution_count": 0,
    }
    return index


def _canary_walk_events(root):
    """Yield enter/exit events for one iterative preorder walk."""
    stack = [(root, None, False)]
    while stack:
        node, parent, leaving = stack.pop()
        yield node, parent, leaving
        if not leaving:
            stack.append((node, parent, True))
            stack.extend(
                (child, node, False)
                for child in reversed(tuple(ast.iter_child_nodes(node)))
            )


def _canary_index_bindings(node, writes, attrs, subscripts):
    """Index name writes and dynamic helper mutation targets in the same walk."""
    for name in _canary_written_names(node):
        writes.setdefault(name, []).append(node)
    if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
        attrs.append(node)
    if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
        subscripts.append(node)


def _canary_written_names(node):
    """Return lexical names introduced or written by one AST node."""
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return (node.id,)
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return tuple(
            item.asname or item.name.split(".", 1)[0]
            for item in node.names
            if item.name != "*"
        )
    if isinstance(node, ast.arg):
        return (node.arg,)
    if isinstance(
        node,
        (
            ast.FunctionDef,
            ast.AsyncFunctionDef,
            ast.ClassDef,
            ast.ExceptHandler,
            ast.MatchAs,
            ast.MatchStar,
        ),
    ):
        name = getattr(node, "name", None)
        return (name,) if name else ()
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return tuple(node.names)
    return ()


def _canary_nodes(root, kind=None):
    """Read an indexed subtree or typed view without restarting an AST walk."""
    index = _canary_index(root)
    if not index.get("complete"):
        return ()
    start = index["starts"].get(id(root), 0)
    end = index["ends"].get(id(root), start)
    if kind is None:
        return index["nodes"][start:end]
    positions = index["positions"].get(kind, ())
    first, last = bisect_left(positions, start), bisect_left(positions, end)
    return index["types"].get(kind, ())[first:last]


def _canary_parent(root, child):
    """Return a direct parent from the source tree's bounded index."""
    index = _canary_index(root)
    if not index.get("complete"):
        return None
    index["parent_lookups"] += 1
    return index["parents"].get(id(child))


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
        literal_exec_rejected,
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


# Native database context is a static projection only.  Its cache stores canonical
# JSON bytes (never parser objects or source text) so callers cannot mutate entries.
_DB_CACHE: dict[str, bytes] = {}
_DB_CACHE_BYTES = 0
_DB_CACHE_LOCK = threading.RLock()
_DB_LOG_FILTER_LOCK = threading.RLock()
_DB_EXTRACTOR_ID = "native-db-v1"


def _nested_async_runner_invocations(test, definitions, targets, aliases):
    """Delegate async invocation proof to the bounded source-analysis helpers."""
    from .context_efficiency import _nested_async_runner_invocations as prove

    return prove(test, definitions, targets, aliases)


def _mock_scope_binding(nodes, name, endpoint, aliases):
    """Recognize an unchanged local mock-constructor binding."""
    from . import review_audits as audit

    endpoint_line = endpoint.lineno
    return any(
        isinstance(statement, (ast.Assign, ast.AnnAssign))
        and statement.lineno < endpoint_line
        and audit._in_current_test_body(statement)
        and audit._mock_constructor_binding(statement, name, aliases)
        and not audit._name_rebound(nodes, name, 0, statement.lineno)
        and not audit._name_rebound(nodes, name, statement.lineno, endpoint_line)
        for statement in nodes
    )


def _oracle_source_inputs(
    root,
    files,
    source_reader,
    safe_local_file,
    measure_hash,
    hash_bytes,
    runtime_error,
    max_bytes,
    retention_limit,
):
    """Read and bind a bounded oracle manifest through caller-owned safe I/O."""
    source_bytes, bindings, manifest = {}, [], []
    cacheable, retained_bytes, retain_source_bytes = True, 0, True
    for path in files:
        relative = path.relative_to(root).as_posix()
        try:
            if path.is_symlink():
                manifest.append({"path": relative, "state": "symlink"})
                cacheable = False
                continue
            initial = safe_local_file(root, relative).stat()
            if initial.st_size > max_bytes:
                manifest.append(
                    {
                        "path": relative,
                        "state": "oversized",
                        "bytes": int(initial.st_size),
                        "mtime_ns": int(initial.st_mtime_ns),
                    }
                )
                cacheable = False
                continue
            data = source_reader(root, relative)
            if len(data) > max_bytes:
                manifest.append(
                    {"path": relative, "state": "oversized", "bytes": len(data)}
                )
                cacheable = False
                continue
            digest = measure_hash("source_hash", hash_bytes, data)
            manifest.append(
                {
                    "path": relative,
                    "state": "read",
                    "bytes": len(data),
                    "sha256": digest,
                }
            )
            bindings.append({"path": relative, "sha256": digest, "bytes": len(data)})
            if retain_source_bytes and retained_bytes + len(data) <= retention_limit:
                source_bytes[path] = data
                retained_bytes += len(data)
            else:
                source_bytes.clear()
                retain_source_bytes = False
        except (OSError, SyntaxError, UnicodeError, runtime_error):
            manifest.append({"path": relative, "state": "unreadable"})
            cacheable = False
    manifest.sort(key=lambda item: item["path"])
    return source_bytes, bindings, manifest, cacheable


def _oracle_source_snapshots(
    root,
    files,
    source_bytes,
    source_reader,
    measure_parse,
    runtime_error,
    max_bytes,
):
    """Parse bounded retained oracle inputs while preserving their exact byte identity."""
    snapshots = {}
    for path in files:
        try:
            data = source_bytes.get(path)
            if data is None:
                relative = path.relative_to(root).as_posix()
                data = source_reader(root, relative)
                if len(data) > max_bytes:
                    continue
            tree = measure_parse(ast.parse, data, root, path)
            tree._oracle_source_lines = data.decode("utf-8").splitlines()
            tree._oracle_source_sha256 = sha256(data).hexdigest()
            for node in tree.body:
                node._oracle_layout = None
            for node in ast.walk(tree):
                node._scan_bound_names = None
            snapshots[path] = tree
        except (OSError, SyntaxError, UnicodeError, runtime_error):
            continue
    return snapshots


def _clear_analysis_sidecars(tree):
    """Remove transient oracle and security annotations before tree reuse."""
    preserved = {"_oracle_source_lines", "_oracle_source_sha256"}
    for node in ast.walk(tree):
        for name in tuple(vars(node)):
            if name in preserved:
                continue
            if name.startswith(
                ("_oracle_", "_scan_", "_security_", "_implementation_")
            ):
                delattr(node, name)


def database_structure(
    sources: dict[str, bytes],
    dialect: str = "postgres",
    snapshots: dict | None = None,
    migration_order: list[str] | None = None,
) -> dict:
    """Build a bounded projection; caller snapshots are ignored and gaps stay explicit."""
    return _database_structure(sources, dialect, migration_order)


def _database_structure(sources, dialect, migration_order, python_trees=None):
    """Project database facts, optionally reusing only invocation-owned trees."""
    from hashlib import sha256 as _sha256
    import inspect

    global _DB_CACHE_BYTES

    dialect_key = {"postgresql": "postgres", "sqlite3": "sqlite"}.get(dialect, dialect)
    if dialect_key not in {"postgres", "sqlite"}:
        return _db_result(
            "UNSUPPORTED", ["unsupported_dialect"], [], [], [], [], dialect_key
        )
    manifest, inputs, gaps, sql_count = _db_inventory(sources, _sha256)
    inputs, order_gaps, normalized_order = _db_apply_migration_order(
        inputs, migration_order
    )
    gaps.extend(order_gaps)
    if gaps:
        return _db_result("INCOMPLETE", gaps, manifest, [], [], [], dialect_key)
    parser = _db_load_parser()
    if parser is None:
        return _db_result(
            "UNSUPPORTED", ["parser_unavailable"], manifest, [], [], [], dialect_key
        )
    sqlglot, exp, parser_version = parser
    code_identity = _db_code_identity(inspect, _sha256)
    cache_key = _db_cache_key(
        _sha256, dialect_key, manifest, parser_version, code_identity, normalized_order
    )
    cached = _db_cache_read(cache_key)
    if cached is not None:
        return cached
    tables, operations, queries = _db_extract(
        inputs, sqlglot, exp, dialect_key, python_trees, gaps
    )
    _db_migration_order_gaps(inputs, operations, normalized_order, gaps)
    _db_validate_references(tables, queries, gaps)
    result = {
        "status": "INCOMPLETE" if gaps else "COMPLETE",
        "schema_evolution": {
            "mode": "declared_migration_order"
            if normalized_order is not None
            else "ordered_within_source_projection",
            "migration_order": normalized_order,
            "final_state": "INCOMPLETE" if gaps else "PROJECTED",
        },
        "coverage": {
            "sql_files": sql_count,
            "python_files": sum(k == "python" for _, _, _, k in inputs),
        },
        "gaps": sorted(set(gaps)),
        "dialect": dialect_key,
        "parser_identity": "sqlglot/" + parser_version,
        "extractor_identity": _DB_EXTRACTOR_ID + "/" + code_identity,
        "source_manifest": manifest,
        "tables": [tables[k] for k in sorted(tables)],
        "operations": operations,
        "queries": queries,
    }
    canonical = json.dumps(
        result, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    result["graph_digest"] = _sha256(canonical).hexdigest()
    serialized = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    _db_cache_write(cache_key, serialized)
    return json.loads(serialized)


def _db_migration_order_gaps(inputs, operations, normalized_order, gaps):
    sql_paths = {path for path, _, _, kind in inputs if kind == "sql"}
    evolving = {
        "add_column",
        "drop_column",
        "rename_column",
        "rename_table",
        "drop_table",
        "drop_index",
    }
    cross_file_order_unknown = (
        normalized_order is None
        and len(sql_paths) > 1
        and any(item["op"] in evolving for item in operations)
    )
    if cross_file_order_unknown:
        gaps.append("cross_file_migration_order_unknown")


def _db_inventory(sources, digest_fn):
    manifest, inputs, gaps = [], [], []
    sql_count = sql_bytes = 0
    for path, raw in sorted(sources.items()):
        normalized = str(path).replace("\\", "/")
        kind = (
            "sql"
            if normalized.lower().endswith(".sql")
            else "python"
            if normalized.lower().endswith(".py")
            else None
        )
        if kind is None:
            continue
        if not isinstance(raw, bytes):
            gaps.append("invalid_source_bytes")
            continue
        digest = digest_fn(raw).hexdigest()
        manifest.append({"path": normalized, "sha256": digest, "size": len(raw)})
        inputs.append((normalized, raw, digest, kind))
        if kind == "sql":
            sql_count += 1
            sql_bytes += len(raw)
            if len(raw) > 1_000_000:
                gaps.append("source_size_limit")
    if sql_count > 256:
        gaps.append("sql_input_limit")
    if sql_bytes > 16_000_000:
        gaps.append("total_source_limit")
    return manifest, inputs, gaps, sql_count


def _db_apply_migration_order(inputs, migration_order):
    if migration_order is None:
        return sorted(inputs, key=lambda item: item[3] == "python"), [], None
    if not isinstance(migration_order, list) or any(
        not isinstance(path, str) for path in migration_order
    ):
        return inputs, ["invalid_migration_order"], None
    paths = [path.replace("\\", "/") for path in migration_order]
    sql_paths = [path for path, _, _, kind in inputs if kind == "sql"]
    gaps = []
    if len(set(paths)) != len(paths):
        gaps.append("duplicate_migration_order_path")
    if set(paths) - set(sql_paths):
        gaps.append("unknown_migration_order_path")
    if set(sql_paths) - set(paths):
        gaps.append("missing_migration_order_path")
    if gaps:
        return inputs, gaps, paths
    by_path = {path: item for item in inputs if (path := item[0]) in sql_paths}
    ordered_sql = [by_path[path] for path in paths]
    python = sorted(
        (item for item in inputs if item[3] == "python"), key=lambda item: item[0]
    )
    return ordered_sql + python, [], paths


def _db_load_parser():
    try:
        import sqlglot
        from sqlglot import exp
    except ImportError:
        return None
    return sqlglot, exp, sqlglot.__version__


def _db_code_identity(inspect, digest_fn):
    helpers = (
        _db_result,
        _db_inventory,
        _db_apply_migration_order,
        _db_load_parser,
        _db_code_identity,
        _db_cache_key,
        _db_cache_read,
        _db_cache_write,
        _db_extract,
        _db_python_module_name,
        _db_python_import_module,
        _db_python_parse_modules,
        _db_python_declarations,
        _db_python_class_declaration,
        _db_python_has_unimplemented_migration,
        _db_python_export_bindings,
        _db_python_local_reexports,
        _db_python_update_module_reexports,
        _db_python_export_result,
        _db_python_imported_bindings,
        _db_python_project_exports,
        _db_merge_declarations,
        _db_declaration_facts,
        _db_check_column_duplicates,
        _db_validate_references,
        _db_validate_foreign_keys,
        _db_validate_queries,
        _db_read_sql,
        _db_parse_sql,
        _DatabaseParserLogFilter,
        _db_read_python,
        _db_python_symbols,
        _db_python_check_calls,
        _db_import_bindings,
        _db_python_call,
        _db_python_resolve,
        _db_python_base_names,
        _db_python_metadata_names,
        _db_python_model,
        _db_python_duplicate_table,
        _db_python_literal,
        _db_python_column,
        _db_python_type,
        _db_python_fk,
        _db_python_query,
        _db_python_scope,
        _db_python_scope_calls,
        _db_python_control_flow_branches,
        _db_python_isolated_control_flow_calls,
        _db_python_with_scope,
        _db_python_with_bindings,
        _db_python_invalidate_names,
        _db_python_invalidate_nested_bindings,
        _db_python_write_names,
        _DBPythonWriteCollector,
        _db_python_argument_names,
        _db_python_import_names,
        _db_python_target_names,
        _db_python_register_assignment,
        _db_python_connection_call,
        _db_assignment_targets,
        _db_python_execute,
        _db_python_sql_literal,
        _db_python_is_text_call,
        _db_python_contains_text,
        _db_python_core,
        _db_python_annotated,
        _db_python_is_mapped_annotation,
        _db_merge_python_column,
        _db_table_name,
        _db_ident,
        _db_read_statement,
        _db_empty_table,
        _db_valid_create_items,
        _db_create_table,
        _db_column_fact,
        _db_constraint_fact,
        _db_alter,
        _db_alter_action,
        _db_rename_table,
        _db_drop_statement,
        _db_remove_column,
        _db_rename_column,
        _db_query_wildcards,
        _db_query,
        _database_structure,
    )
    source = "".join(inspect.getsource(fn) for fn in helpers)
    return digest_fn(
        (inspect.getsource(database_structure) + source).encode()
    ).hexdigest()


def _db_cache_key(
    digest_fn, dialect, manifest, parser_version, code_identity, migration_order
):
    identity = [
        _DB_EXTRACTOR_ID,
        code_identity,
        parser_version,
        dialect,
        manifest,
        migration_order,
    ]
    return digest_fn(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _db_cache_read(key):
    with _DB_CACHE_LOCK:
        cached = _DB_CACHE.get(key)
    return json.loads(cached) if cached is not None else None


def _db_cache_write(key, serialized):
    global _DB_CACHE_BYTES
    if len(serialized) > 4_000_000:
        return
    with _DB_CACHE_LOCK:
        prior = _DB_CACHE.pop(key, None)
        if prior is not None:
            _DB_CACHE_BYTES -= len(prior)
        while _DB_CACHE and (
            _DB_CACHE_BYTES + len(serialized) > 4_000_000 or len(_DB_CACHE) >= 16
        ):
            _, removed = _DB_CACHE.popitem()
            _DB_CACHE_BYTES -= len(removed)
        _DB_CACHE[key] = serialized
        _DB_CACHE_BYTES += len(serialized)


def _db_extract(inputs, sqlglot, exp, dialect, python_trees, gaps):
    tables, operations, queries = {}, [], []
    modules, _paths, parsed_trees = _db_python_parse_modules(inputs, python_trees)
    project_exports = _db_python_project_exports(inputs, modules=modules, paths=_paths)
    for path, raw, digest, kind in inputs:
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            gaps.append("invalid_utf8:" + path)
            continue
        if kind == "python":
            declared = {}
            _db_read_python(
                path,
                text,
                digest,
                dialect,
                sqlglot,
                exp,
                declared,
                queries,
                gaps,
                project_exports.get(path),
                parsed_tree=parsed_trees[path],
            )
            _db_merge_declarations(tables, declared, path, digest, gaps)
        else:
            _db_read_sql(
                path,
                text,
                digest,
                sqlglot,
                exp,
                dialect,
                tables,
                operations,
                queries,
                gaps,
            )
    return tables, operations, queries


def _db_python_module_name(path):
    parts = list(Path(path).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _db_python_import_module(current, node):
    if node.level:
        package = current.split(".")[:-1]
        keep = max(0, len(package) - node.level + 1)
        base = package[:keep]
        suffix = node.module.split(".") if node.module else []
        return ".".join(base + suffix)
    return node.module or ""


def _db_python_parse_modules(inputs, python_trees=None):
    """Parse retained DB modules, reusing only exact invocation-owned trees."""
    modules, paths, parsed_trees = {}, {}, {}
    for path, raw, _, kind in inputs:
        if kind != "python":
            continue
        tree = (python_trees or {}).get(path)
        if not isinstance(tree, ast.Module):
            try:
                tree = ast.parse(raw.decode("utf-8", errors="strict"), filename=path)
            except (SyntaxError, UnicodeDecodeError):
                parsed_trees[path] = None
                continue
        parsed_trees[path] = tree
        module = _db_python_module_name(path)
        symbols, shadowed = _db_python_symbols(tree)
        exports = _db_python_export_bindings(tree, symbols, shadowed)
        modules.setdefault(module, []).append((path, tree, shadowed, exports))
        paths[path] = module
    return modules, paths, parsed_trees


def _db_python_export_bindings(tree, symbols, shadowed):
    exports = {
        name: ("symbol", value)
        for name, value in symbols.items()
        if name not in shadowed
    }
    exports.update(
        (name, ("base", None))
        for name in _db_python_base_names(tree, symbols, shadowed)
    )
    exports.update(
        (name, ("metadata", None))
        for name in _db_python_metadata_names(tree, symbols, shadowed)
    )
    return exports


def _db_python_local_reexports(unique):
    for _ in range(min(32, len(unique) + 1)):
        changed = False
        for module, (_, tree, shadowed, exports) in unique.items():
            changed |= _db_python_update_module_reexports(
                module, tree, shadowed, exports, unique
            )
        if not changed:
            break


def _db_python_update_module_reexports(module, tree, shadowed, exports, unique):
    changed = False
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom):
            continue
        provider = unique.get(_db_python_import_module(module, node))
        if provider is None:
            continue
        for alias in node.names:
            local = alias.asname or alias.name
            value = provider[3].get(alias.name)
            if (
                value is not None
                and local not in shadowed
                and exports.get(local) != value
            ):
                exports[local] = value
                changed = True
    return changed


def _db_python_export_result(paths, unique):
    result = {}
    for path, module in paths.items():
        _, tree, shadowed, _ = unique.get(module, (None, None, set(), {}))
        if tree is None:
            result[path] = {}
            continue
        result[path] = _db_python_imported_bindings(module, tree, shadowed, unique)
    return result


def _db_python_imported_bindings(module, tree, shadowed, unique):
    symbols, bases, metadatas = {}, set(), set()
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom):
            continue
        provider = unique.get(_db_python_import_module(module, node))
        if provider is None:
            continue
        for alias in node.names:
            local = alias.asname or alias.name
            if local in shadowed:
                continue
            kind, value = provider[3].get(alias.name, (None, None))
            if kind == "symbol":
                symbols[local] = value
            elif kind == "base":
                bases.add(local)
            elif kind == "metadata":
                metadatas.add(local)
    return {"symbols": symbols, "bases": bases, "metadatas": metadatas}


def _db_python_project_exports(inputs, *, modules=None, paths=None):
    if modules is None:
        modules, paths, _ = _db_python_parse_modules(inputs)
    unique = {name: values[0] for name, values in modules.items() if len(values) == 1}
    _db_python_local_reexports(unique)
    return _db_python_export_result(paths, unique)


def _db_declaration_facts(table):
    """Compare structure without treating source locations as schema facts."""
    return {
        "columns": sorted(
            (
                {key: value for key, value in column.items() if key != "source"}
                for column in table["columns"]
            ),
            key=lambda row: row["name"],
        ),
        **{
            key: sorted(table[key], key=lambda row: json.dumps(row, sort_keys=True))
            for key in ("primary_key", "foreign_keys", "unique", "indexes")
        },
    }


def _db_merge_declarations(tables, declared, path, digest, gaps):
    for name, table in declared.items():
        origin = {"kind": "sqlalchemy", "path": path, "sha256": digest}
        declaration = {"source": origin, "facts": _db_declaration_facts(table)}
        previous = tables.get(name)
        if previous is None:
            table["declarations"] = [declaration]
            tables[name] = table
            continue
        origins = previous.setdefault(
            "declarations",
            [
                {
                    "source": {
                        "kind": "sql",
                        "origins": [
                            column.get("source") for column in previous["columns"]
                        ],
                    },
                    "facts": _db_declaration_facts(previous),
                }
            ],
        )
        origins.append(declaration)
        if _db_declaration_facts(previous) != declaration["facts"]:
            gaps.append("database_declaration_conflict:" + name)
        previous.setdefault("models", []).extend(table.get("models", []))


def _db_check_column_duplicates(tables, gaps):
    for name, table in tables.items():
        seen = set()
        for column in table["columns"]:
            if column["name"] in seen:
                gaps.append(
                    "duplicate_column_declaration:" + name + "." + column["name"]
                )
            seen.add(column["name"])


def _db_validate_references(tables, queries, gaps):
    _db_check_column_duplicates(tables, gaps)
    _db_validate_foreign_keys(tables, gaps)
    _db_validate_queries(tables, queries, gaps)


def _db_validate_foreign_keys(tables, gaps):
    for table in tables.values():
        for foreign_key in table["foreign_keys"]:
            target = tables.get(foreign_key["target_table"])
            if target is None:
                gaps.append(
                    "foreign_key_target_unresolved:" + str(foreign_key["target_table"])
                )
            else:
                target_columns = {column["name"] for column in target["columns"]}
                if any(
                    column not in target_columns
                    for column in foreign_key["target_columns"]
                ):
                    gaps.append(
                        "foreign_key_target_column_unresolved:"
                        + str(foreign_key["target_table"])
                    )


def _db_validate_queries(tables, queries, gaps):
    for query in queries:
        for table in query["tables"]:
            if table not in tables:
                gaps.append("query_table_unresolved:" + str(table))
        for column in query["columns"]:
            table = tables.get(column["table"])
            if column.get("wildcard"):
                continue
            if table is not None and column["name"] not in {
                item["name"] for item in table["columns"]
            }:
                gaps.append(
                    "query_column_unresolved:"
                    + str(column["table"])
                    + "."
                    + str(column["name"])
                )


def _db_read_sql(
    path, text, digest, sqlglot, exp, dialect, tables, operations, queries, gaps
):
    try:
        statements = _db_parse_sql(sqlglot, text, dialect)
    except sqlglot.errors.ParseError:
        gaps.append("sql_parse_error:" + path)
        return
    if len(statements) > 2000:
        gaps.append("statement_limit:" + path)
        return
    for index, statement in enumerate(statements, 1):
        if statement is not None:
            _db_read_statement(
                statement,
                exp,
                path,
                digest,
                index,
                dialect,
                tables,
                operations,
                queries,
                gaps,
            )


class _DatabaseParserLogFilter(logging.Filter):
    def __init__(self, thread_id):
        super().__init__()
        self.thread_id = thread_id

    def filter(self, record):
        """Suppress parser messages only on the thread extracting private SQL."""
        return not (
            threading.get_ident() == self.thread_id
            and record.name.startswith("sqlglot")
        )


def _db_parse_sql(sqlglot, text, dialect):
    thread_filter = _DatabaseParserLogFilter(threading.get_ident())
    loggers = [logging.getLogger()]
    loggers.extend(
        value
        for value in list(logging.Logger.manager.loggerDict.values())
        if isinstance(value, logging.Logger) and value.name.startswith("sqlglot")
    )
    handlers = {handler for logger in loggers for handler in logger.handlers}
    if logging.lastResort is not None:
        handlers.add(logging.lastResort)
    with _DB_LOG_FILTER_LOCK:
        for handler in handlers:
            handler.addFilter(thread_filter)
        try:
            return sqlglot.parse(
                text, read=dialect, error_level=sqlglot.ErrorLevel.RAISE
            )
        finally:
            for handler in handlers:
                handler.removeFilter(thread_filter)


def _db_result(status, gaps, manifest, tables, operations, queries, dialect):
    from hashlib import sha256

    result = {
        "status": status,
        "coverage": {
            "sql_files": sum(x["path"].lower().endswith(".sql") for x in manifest),
            "python_files": sum(x["path"].lower().endswith(".py") for x in manifest),
        },
        "gaps": sorted(set(gaps)),
        "dialect": dialect,
        "parser_identity": None,
        "source_manifest": manifest,
        "tables": tables,
        "operations": operations,
        "queries": queries,
    }
    result["graph_digest"] = sha256(
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return result


def _db_read_python(
    path,
    text,
    digest,
    dialect,
    sqlglot,
    exp,
    tables,
    queries,
    gaps,
    project_exports=None,
    parsed_tree=None,
):
    if parsed_tree is None:
        gaps.append("python_parse_error:" + path)
        return
    tree = parsed_tree
    symbols, shadowed = _db_python_symbols(tree)
    project_exports = project_exports or {}
    symbols.update(
        {
            name: value
            for name, value in project_exports.get("symbols", {}).items()
            if name not in shadowed
        }
    )
    _db_python_check_calls(tree, path, symbols, shadowed, gaps)
    bases = _db_python_base_names(tree, symbols, shadowed) | {
        name for name in project_exports.get("bases", ()) if name not in shadowed
    }
    metadatas = _db_python_metadata_names(tree, symbols, shadowed) | {
        name for name in project_exports.get("metadatas", ()) if name not in shadowed
    }
    _db_python_declarations(
        tree,
        path,
        digest,
        dialect,
        exp,
        symbols,
        shadowed,
        bases,
        metadatas,
        tables,
        gaps,
    )
    _db_python_query(
        tree, path, digest, symbols, shadowed, dialect, sqlglot, exp, queries, gaps
    )
    if _db_python_has_unimplemented_migration(tree):
        gaps.append("python_migration_unimplemented:" + path)


def _db_python_has_unimplemented_migration(tree):
    """Detect migration calls that remain outside the supported projection."""
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr
        in {"create_table", "add_column", "drop_table", "create_index"}
        for node in ast.walk(tree)
    )


def _db_python_class_declaration(
    node, path, digest, dialect, exp, symbols, shadowed, bases, tables, gaps
):
    """Project or mark one SQLAlchemy ORM class declaration."""
    name = _db_python_literal(node, "__tablename__")
    inherited = any(
        isinstance(base, ast.Name) and base.id in bases for base in node.bases
    )
    if name is not None and inherited:
        _db_python_model(
            node, name, path, digest, symbols, shadowed, dialect, exp, tables, gaps
        )
    elif name is not None or inherited:
        gaps.append("unproven_orm_declaration:" + path)


def _db_python_declarations(
    tree, path, digest, dialect, exp, symbols, shadowed, bases, metadatas, tables, gaps
):
    """Project ORM and Core declarations from one retained Python module."""
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            _db_python_class_declaration(
                node, path, digest, dialect, exp, symbols, shadowed, bases, tables, gaps
            )
        elif (
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and isinstance(node.value, ast.Call)
            and _db_python_call(node.value, "sqlalchemy.Table", symbols, shadowed)
        ):
            _db_python_core(
                node.value, path, digest, symbols, shadowed, metadatas, tables, gaps
            )


def _db_python_symbols(tree):
    symbols, seen, import_counts = {}, {}, {}
    for node in tree.body:
        for local, qualified in _db_import_bindings(node):
            seen[local] = seen.get(local, 0) + 1
            symbols[local] = qualified
    for node in ast.walk(tree):
        for local in _db_python_import_names(node):
            import_counts[local] = import_counts.get(local, 0) + 1
    bound = set()
    if any(
        isinstance(node, ast.ImportFrom)
        and any(alias.name == "*" for alias in node.names)
        for node in ast.walk(tree)
    ):
        bound.update(symbols)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            bound.add(node.id)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
    return symbols, (
        bound
        | {name for name, count in seen.items() if count > 1}
        | {name for name, count in import_counts.items() if count > 1}
    ) & symbols.keys()


def _db_python_check_calls(tree, path, symbols, shadowed, gaps):
    supported = {
        "sqlalchemy.Column",
        "sqlalchemy.Table",
        "sqlalchemy.MetaData",
        "sqlalchemy.ForeignKey",
        "sqlalchemy.text",
        "sqlalchemy.create_engine",
        "sqlalchemy.orm.mapped_column",
        "sqlalchemy.orm.declarative_base",
        "sqlalchemy.ext.declarative.declarative_base",
    }
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        resolved = _db_python_resolve(node.func, symbols, shadowed)
        if (
            resolved
            and resolved.startswith("sqlalchemy")
            and resolved not in supported
            and _db_python_type(node.func, symbols, shadowed) is None
        ):
            gaps.append("unsupported_sqlalchemy_call:" + path)


def _db_import_bindings(node):
    if isinstance(node, ast.Import):
        return [
            (
                alias.asname or alias.name.split(".")[0],
                alias.name if alias.asname else alias.name.split(".")[0],
            )
            for alias in node.names
            if alias.name in {"sqlalchemy", "sqlite3", "psycopg", "psycopg2"}
            or alias.name.startswith("sqlalchemy.")
        ]
    if not isinstance(node, ast.ImportFrom) or not node.module:
        return []
    if node.module.startswith("sqlalchemy") or node.module in {
        "sqlite3",
        "psycopg",
        "psycopg2",
    }:
        return [
            (alias.asname or alias.name, node.module + "." + alias.name)
            for alias in node.names
        ]
    if node.module in {"typing", "typing_extensions"}:
        return [
            (alias.asname or alias.name, "typing.Annotated")
            for alias in node.names
            if alias.name == "Annotated"
        ]
    return []


def _db_python_resolve(node, symbols, shadowed):
    if isinstance(node, ast.Name):
        return symbols.get(node.id) if node.id not in shadowed else None
    if isinstance(node, ast.Attribute):
        parent = _db_python_resolve(node.value, symbols, shadowed)
        return parent + "." + node.attr if parent else None
    return None


def _db_python_call(node, qualified, symbols, shadowed):
    return (
        isinstance(node, ast.Call)
        and _db_python_resolve(node.func, symbols, shadowed) == qualified
    )


def _db_python_base_names(tree, symbols, shadowed):
    bases = set()
    base_functions = {
        "sqlalchemy.orm.declarative_base",
        "sqlalchemy.ext.declarative.declarative_base",
    }
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if not isinstance(target, ast.Name):
                    continue
                if (
                    isinstance(value, ast.Call)
                    and _db_python_resolve(value.func, symbols, shadowed)
                    in base_functions
                ):
                    bases.add(target.id)
                else:
                    bases.discard(target.id)
        elif isinstance(node, ast.ClassDef) and any(
            _db_python_resolve(base, symbols, shadowed)
            == "sqlalchemy.orm.DeclarativeBase"
            or isinstance(base, ast.Name)
            and base.id in bases
            for base in node.bases
        ):
            bases.add(node.name)
    return bases


def _db_python_metadata_names(tree, symbols, shadowed):
    names = set()
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if not isinstance(target, ast.Name) or target.id in shadowed:
                continue
            if isinstance(node.value, ast.Call) and _db_python_call(
                node.value, "sqlalchemy.MetaData", symbols, shadowed
            ):
                names.add(target.id)
            else:
                names.discard(target.id)
    return names


def _db_python_literal(node, name):
    for child in node.body:
        if (
            isinstance(child, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == name
                for target in child.targets
            )
            and isinstance(child.value, ast.Constant)
            and isinstance(child.value.value, str)
        ):
            return child.value.value
        if (
            isinstance(child, ast.AnnAssign)
            and isinstance(child.target, ast.Name)
            and child.target.id == name
            and isinstance(child.value, ast.Constant)
            and isinstance(child.value.value, str)
        ):
            return child.value.value
    return None


def _db_python_type(node, symbols, shadowed):
    types = {
        "Integer": "INTEGER",
        "BigInteger": "BIGINT",
        "SmallInteger": "SMALLINT",
        "String": "VARCHAR",
        "Text": "TEXT",
        "Boolean": "BOOLEAN",
        "Date": "DATE",
        "DateTime": "TIMESTAMP",
        "Time": "TIME",
        "Numeric": "NUMERIC",
        "Float": "FLOAT",
        "LargeBinary": "BLOB",
        "JSON": "JSON",
        "Uuid": "UUID",
    }
    resolved = _db_python_resolve(
        node.func if isinstance(node, ast.Call) else node, symbols, shadowed
    )
    if resolved is None or not resolved.startswith("sqlalchemy"):
        return None
    return types.get(resolved.split(".")[-1])


def _db_python_fk(node, symbols, shadowed):
    if (
        not _db_python_call(node, "sqlalchemy.ForeignKey", symbols, shadowed)
        or not node.args
    ):
        return None
    value = node.args[0]
    if (
        not isinstance(value, ast.Constant)
        or not isinstance(value.value, str)
        or "." not in value.value
    ):
        return None
    table, column = value.value.rsplit(".", 1)
    return {"target_table": table, "target_columns": [column]}


def _db_python_column(value, name, symbols, shadowed, core=False):
    if not isinstance(value, ast.Call) or not any(
        _db_python_call(value, func, symbols, shadowed)
        for func in ("sqlalchemy.Column", "sqlalchemy.orm.mapped_column")
    ):
        return None
    explicit_name = bool(
        value.args
        and isinstance(value.args[0], ast.Constant)
        and isinstance(value.args[0].value, str)
    )
    type_index = 1 if core or explicit_name else 0
    if (
        len(value.args) <= type_index
        or _db_python_type(value.args[type_index], symbols, shadowed) is None
    ):
        return None
    options = {
        keyword.arg: keyword.value.value
        for keyword in value.keywords
        if keyword.arg in {"nullable", "primary_key", "unique", "index"}
        and isinstance(keyword.value, ast.Constant)
        and isinstance(keyword.value.value, bool)
    }
    foreign_keys = [
        _db_python_fk(arg, symbols, shadowed) for arg in value.args[type_index + 1 :]
    ]
    column_name = value.args[0].value if explicit_name and not core else name
    return {
        "name": column_name,
        "type": _db_python_type(value.args[type_index], symbols, shadowed),
        "nullable": options.get("nullable", not options.get("primary_key", False)),
        "primary_key": options.get("primary_key", False),
        "unique": options.get("unique", False),
        "index": options.get("index", False),
        "foreign_keys": [fk for fk in foreign_keys if fk],
    }


def _db_python_model(
    node, table_name, path, digest, symbols, shadowed, dialect, exp, tables, gaps
):
    if _db_python_duplicate_table(tables, table_name, path):
        gaps.append("duplicate_orm_table_declaration:" + table_name)
        return
    table = tables.setdefault(table_name, _db_empty_table(table_name))
    table.setdefault("models", []).append(
        {
            "class": node.name,
            "source": {
                "path": path,
                "sha256": digest,
                "line": node.lineno,
                "kind": "sqlalchemy_declarative",
            },
        }
    )
    for child in node.body:
        if (
            isinstance(child, ast.Assign)
            and len(child.targets) == 1
            and isinstance(child.targets[0], ast.Name)
        ):
            if child.targets[0].id == "__table_args__":
                gaps.append("unsupported_orm_table_args:" + path)
                continue
            column = _db_python_column(
                child.value, child.targets[0].id, symbols, shadowed
            )
            if column:
                _db_merge_python_column(table, column, path, digest, child.lineno)
            elif isinstance(child.value, ast.Call) and child.targets[0].id not in {
                "__tablename__",
                "__table_args__",
            }:
                gaps.append("unsupported_orm_column:" + path)
        elif isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
            column = _db_python_annotated(
                child.annotation, child.value, child.target.id, symbols, shadowed
            )
            if column:
                _db_merge_python_column(table, column, path, digest, child.lineno)
            elif child.value or _db_python_is_mapped_annotation(
                child.annotation, symbols, shadowed
            ):
                gaps.append("unsupported_orm_annotation:" + path)
    table["columns"].sort(key=lambda column: column["name"])
    table["primary_key"] = sorted(set(table["primary_key"]))
    table["unique"] = sorted(
        {
            json.dumps(item, separators=(",", ":")): item for item in table["unique"]
        }.values(),
        key=lambda item: json.dumps(item),
    )
    table["foreign_keys"].sort(key=lambda item: json.dumps(item, sort_keys=True))


def _db_python_annotated(annotation, value, name, symbols, shadowed):
    base = annotation
    metadata = None
    mapped_type = False
    while isinstance(base, ast.Subscript):
        resolved = _db_python_resolve(base.value, symbols, shadowed)
        if (
            resolved == "typing.Annotated"
            and isinstance(base.slice, ast.Tuple)
            and base.slice.elts
        ):
            metadata = next(
                (item for item in base.slice.elts[1:] if isinstance(item, ast.Call)),
                None,
            )
            base = base.slice.elts[0]
        else:
            mapped_type = mapped_type or resolved == "sqlalchemy.orm.Mapped"
            base = base.slice
    builtins = {"int": "INTEGER", "str": "VARCHAR", "bool": "BOOLEAN", "float": "FLOAT"}
    type_name = (
        builtins.get(base.id)
        if isinstance(base, ast.Name)
        else _db_python_type(base, symbols, shadowed)
    )
    if type_name is None:
        return _db_python_column(value, name, symbols, shadowed)
    column_call = metadata or (value if isinstance(value, ast.Call) else None)
    options = (
        {
            keyword.arg: keyword.value.value
            for keyword in column_call.keywords
            if keyword.arg in {"nullable", "primary_key", "unique", "index"}
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, bool)
        }
        if column_call
        else {}
    )
    fks = (
        [_db_python_fk(arg, symbols, shadowed) for arg in column_call.args]
        if column_call
        else []
    )
    default_nullable = not mapped_type and not options.get("primary_key", False)
    return {
        "name": name,
        "type": type_name,
        "nullable": options.get("nullable", default_nullable),
        "primary_key": options.get("primary_key", False),
        "unique": options.get("unique", False),
        "index": options.get("index", False),
        "foreign_keys": [fk for fk in fks if fk],
    }


def _db_python_is_mapped_annotation(annotation, symbols, shadowed):
    current = annotation
    while isinstance(current, ast.Subscript):
        if _db_python_resolve(current.value, symbols, shadowed) in {
            "typing.Annotated",
            "sqlalchemy.orm.Mapped",
        }:
            return True
        current = current.slice
    return False


def _db_merge_python_column(table, column, path, digest, line):
    name = column["name"]
    table["columns"].append(
        {
            "name": name,
            "type": column["type"],
            "nullable": column["nullable"],
            "source": {
                "path": path,
                "sha256": digest,
                "line": line,
                "kind": "sqlalchemy_column",
            },
        }
    )
    if column["primary_key"]:
        table["primary_key"].append(name)
    if column["unique"]:
        table["unique"].append([name])
    if column["index"]:
        table["indexes"].append(
            {"name": None, "unique": column["unique"], "columns": [name]}
        )
    for fk in column["foreign_keys"]:
        table["foreign_keys"].append({"columns": [name], **fk})


def _db_python_duplicate_table(tables, name, path):
    table = tables.get(name)
    return bool(
        table
        and any(
            model["source"]["path"] == path
            and model["source"]["kind"]
            in {"sqlalchemy_declarative", "sqlalchemy_core_table"}
            for model in table.get("models", [])
        )
    )


def _db_python_core(call, path, digest, symbols, shadowed, metadatas, tables, gaps):
    if (
        not call.args
        or not isinstance(call.args[0], ast.Constant)
        or not isinstance(call.args[0].value, str)
    ):
        gaps.append("dynamic_core_table_name:" + path)
        return
    if (
        len(call.args) < 2
        or not isinstance(call.args[1], ast.Name)
        or call.args[1].id not in metadatas
    ):
        gaps.append("unproven_core_metadata:" + path)
        return
    schema = next(
        (
            kw.value.value
            for kw in call.keywords
            if kw.arg == "schema"
            and isinstance(kw.value, ast.Constant)
            and isinstance(kw.value.value, str)
        ),
        None,
    )
    if any(kw.arg != "schema" for kw in call.keywords) or any(
        kw.arg == "schema" and schema is None for kw in call.keywords
    ):
        gaps.append("unsupported_core_table_options:" + path)
        return
    name = (schema + "." if schema else "") + call.args[0].value
    if _db_python_duplicate_table(tables, name, path):
        gaps.append("duplicate_orm_table_declaration:" + name)
        return
    table = tables.setdefault(name, _db_empty_table(name))
    table.setdefault("models", []).append(
        {
            "class": name,
            "source": {
                "path": path,
                "sha256": digest,
                "line": call.lineno,
                "kind": "sqlalchemy_core_table",
            },
        }
    )
    for arg in call.args[2:]:
        if isinstance(arg, ast.Call) and _db_python_call(
            arg, "sqlalchemy.Column", symbols, shadowed
        ):
            colname = (
                arg.args[0].value
                if arg.args
                and isinstance(arg.args[0], ast.Constant)
                and isinstance(arg.args[0].value, str)
                else None
            )
            parsed = (
                _db_python_column(arg, colname, symbols, shadowed, core=True)
                if colname
                else None
            )
            if parsed:
                _db_merge_python_column(table, parsed, path, digest, arg.lineno)
            else:
                gaps.append("unsupported_core_column:" + path)
        else:
            gaps.append("unsupported_core_element:" + path)
    table["columns"].sort(key=lambda column: column["name"])


def _db_python_query(
    tree, path, digest, symbols, shadowed, dialect, sqlglot, exp, queries, gaps
):
    engines, connections = {}, {}
    _db_python_scope(
        tree.body,
        path,
        digest,
        symbols,
        shadowed,
        dialect,
        sqlglot,
        exp,
        engines,
        connections,
        queries,
        gaps,
        nested_scope_checks=False,
    )
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            local_names = _db_python_argument_names(node.args)
            local_connections = {
                key: value
                for key, value in connections.items()
                if key not in local_names
            }
            _db_python_scope(
                node.body,
                path,
                digest,
                symbols,
                shadowed,
                dialect,
                sqlglot,
                exp,
                {
                    key: value
                    for key, value in engines.items()
                    if key not in local_names
                },
                local_connections,
                queries,
                gaps,
            )


def _db_python_scope(
    statements,
    path,
    digest,
    symbols,
    shadowed,
    dialect,
    sqlglot,
    exp,
    engines,
    connections,
    queries,
    gaps,
    sql_bindings=None,
    nested_scope_checks=True,
):
    if sql_bindings is None:
        sql_bindings = {}
    for statement in statements:
        if not isinstance(statement, (ast.With, ast.AsyncWith)):
            _db_python_invalidate_nested_bindings(
                statement, engines, connections, sql_bindings
            )
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if nested_scope_checks:
                _db_python_scope_calls(
                    statement,
                    path,
                    digest,
                    symbols,
                    shadowed,
                    dialect,
                    sqlglot,
                    exp,
                    engines,
                    connections,
                    sql_bindings,
                    queries,
                    gaps,
                )
            continue
        destructured = (
            isinstance(statement, ast.Assign)
            and not all(isinstance(target, ast.Name) for target in statement.targets)
        ) or (
            isinstance(statement, ast.AnnAssign)
            and not isinstance(statement.target, ast.Name)
        )
        for name in _db_assignment_targets(statement):
            if destructured:
                _db_python_invalidate_names((name,), engines, connections, sql_bindings)
                continue
            _db_python_register_assignment(
                statement, name, symbols, shadowed, engines, connections
            )
            if isinstance(statement, ast.AugAssign):
                sql_bindings.pop(name, None)
                continue
            value = statement.value
            literal = _db_python_sql_literal(value, symbols, shadowed, sql_bindings)
            if literal is not None:
                sql_bindings[name] = (
                    literal,
                    _db_python_contains_text(value, symbols, shadowed, sql_bindings),
                )
            else:
                sql_bindings.pop(name, None)
        _db_python_scope_calls(
            statement,
            path,
            digest,
            symbols,
            shadowed,
            dialect,
            sqlglot,
            exp,
            engines,
            connections,
            sql_bindings,
            queries,
            gaps,
        )


def _db_python_scope_calls(
    node,
    path,
    digest,
    symbols,
    shadowed,
    dialect,
    sqlglot,
    exp,
    engines,
    connections,
    sql_bindings,
    queries,
    gaps,
):
    """Visit execute calls and nested manager scopes without crossing functions."""
    pending = [node]
    while pending:
        current = pending.pop()
        if isinstance(
            current,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            if any(
                isinstance(candidate, ast.Call)
                and isinstance(candidate.func, ast.Attribute)
                and candidate.func.attr == "execute"
                for candidate in ast.walk(current)
            ):
                gaps.append("python_execute_nested_scope_unsupported:" + path)
            continue
        if _db_python_control_flow_branches(current) is not None:
            _db_python_isolated_control_flow_calls(
                current,
                path,
                digest,
                symbols,
                shadowed,
                dialect,
                sqlglot,
                exp,
                engines,
                connections,
                sql_bindings,
                queries,
                gaps,
            )
            continue
        if isinstance(current, (ast.With, ast.AsyncWith)):
            _db_python_with_scope(
                current,
                path,
                digest,
                symbols,
                shadowed,
                dialect,
                sqlglot,
                exp,
                engines,
                connections,
                queries,
                gaps,
                sql_bindings,
            )
            continue
        if isinstance(
            current,
            (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
        ):
            if any(
                isinstance(candidate, ast.Call)
                and isinstance(candidate.func, ast.Attribute)
                and candidate.func.attr == "execute"
                for candidate in ast.walk(current)
            ):
                gaps.append("python_execute_comprehension_scope_unsupported:" + path)
            continue
        if (
            isinstance(current, ast.Call)
            and isinstance(current.func, ast.Attribute)
            and current.func.attr == "execute"
        ):
            _db_python_execute(
                current,
                path,
                digest,
                symbols,
                shadowed,
                dialect,
                sqlglot,
                exp,
                connections,
                sql_bindings,
                queries,
                gaps,
            )
        pending.extend(reversed(list(ast.iter_child_nodes(current))))


def _db_python_control_flow_branches(node):
    """Group uncertain control-flow paths so their binding facts stay isolated."""
    if isinstance(node, ast.If):
        return [[node.test], node.body, node.orelse]
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return [[node.iter], node.body, node.orelse]
    if isinstance(node, ast.While):
        return [[node.test], node.body, node.orelse]
    if isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
        branches = [node.body]
        branches.extend(
            ([handler.type] if handler.type else []) + handler.body
            for handler in node.handlers
        )
        if node.orelse:
            branches.append(node.orelse)
        if node.finalbody:
            branches.append(node.finalbody)
        return branches
    if isinstance(node, ast.Match):
        branches = [[node.subject]]
        branches.extend(
            ([case.guard] if case.guard else []) + case.body for case in node.cases
        )
        return branches
    return None


def _db_python_isolated_control_flow_calls(
    node,
    path,
    digest,
    symbols,
    shadowed,
    dialect,
    sqlglot,
    exp,
    engines,
    connections,
    sql_bindings,
    queries,
    gaps,
):
    """Scan each alternative with a private copy of facts that cannot escape."""
    for branch in _db_python_control_flow_branches(node):
        branch_engines = dict(engines)
        branch_connections = dict(connections)
        branch_sql = dict(sql_bindings)
        _db_python_scope(
            branch,
            path,
            digest,
            symbols,
            shadowed,
            dialect,
            sqlglot,
            exp,
            branch_engines,
            branch_connections,
            queries,
            gaps,
            branch_sql,
        )


def _db_python_with_scope(
    statement,
    path,
    digest,
    symbols,
    shadowed,
    dialect,
    sqlglot,
    exp,
    engines,
    connections,
    queries,
    gaps,
    sql_bindings,
):
    """Analyze a with body using only statically proven SQLite aliases."""
    for item in statement.items:
        _db_python_invalidate_nested_bindings(
            item.context_expr, engines, connections, sql_bindings
        )
        _db_python_scope_calls(
            item.context_expr,
            path,
            digest,
            symbols,
            shadowed,
            dialect,
            sqlglot,
            exp,
            engines,
            connections,
            sql_bindings,
            queries,
            gaps,
        )
        item_bindings = _db_python_with_bindings(
            statement, symbols, shadowed, items=(item,)
        )
        _db_python_invalidate_names(item_bindings, engines, connections, sql_bindings)
        for name, driver in item_bindings.items():
            if driver:
                connections[name] = driver
    _db_python_scope(
        statement.body,
        path,
        digest,
        symbols,
        shadowed,
        dialect,
        sqlglot,
        exp,
        engines,
        connections,
        queries,
        gaps,
        sql_bindings,
    )


def _db_python_invalidate_names(names, engines, connections, sql_bindings):
    """Forget tracked facts whenever a lexical name is rebound or shadowed."""
    for name in names:
        engines.pop(name, None)
        connections.pop(name, None)
        sql_bindings.pop(name, None)


def _db_python_invalidate_nested_bindings(node, engines, connections, sql_bindings):
    """Invalidate every same-scope write before evaluating uncertain control flow."""
    names, wildcard = _db_python_write_names(node)
    if wildcard:
        names.update(engines)
        names.update(connections)
        names.update(sql_bindings)
    _db_python_invalidate_names(names, engines, connections, sql_bindings)


def _db_python_write_names(node):
    """Collect same-scope writes while skipping nested execution scopes."""
    collector = _DBPythonWriteCollector()
    collector.visit(node)
    return collector.names, collector.wildcard


class _DBPythonWriteCollector(ast.NodeVisitor):
    """Visit binding writes without treating nested scopes as current locals."""

    def __init__(self):
        self.names = set()
        self.wildcard = False

    def visit_Name(self, node):
        """Record names written or deleted in this lexical scope."""
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)

    def visit_Import(self, node):
        """Record local names introduced by a plain import statement."""
        self.names.update(_db_python_import_names(node))

    def visit_ImportFrom(self, node):
        """Record imported names and whether a wildcard obscures bindings."""
        self.names.update(_db_python_import_names(node))
        self.wildcard |= any(alias.name == "*" for alias in node.names)

    def visit_FunctionDef(self, node):
        """Inspect a function name and expressions evaluated in its outer scope."""
        self._visit_function_outer_expressions(node)

    def visit_AsyncFunctionDef(self, node):
        """Inspect an async function name and outer-scope expressions."""
        self._visit_function_outer_expressions(node)

    def _visit_function_outer_expressions(self, node):
        self.names.add(node.name)
        expressions = node.decorator_list + node.args.defaults
        expressions.extend(value for value in node.args.kw_defaults if value)
        arguments = (
            node.args.posonlyargs
            + node.args.args
            + node.args.kwonlyargs
            + ([node.args.vararg] if node.args.vararg else [])
            + ([node.args.kwarg] if node.args.kwarg else [])
        )
        expressions.extend(arg.annotation for arg in arguments if arg.annotation)
        if node.returns:
            expressions.append(node.returns)
        for expression in expressions:
            self.visit(expression)

    def visit_ClassDef(self, node):
        """Inspect a class name, decorators, bases, and keyword expressions."""
        self.names.add(node.name)
        expressions = node.decorator_list + node.bases
        expressions.extend(keyword.value for keyword in node.keywords)
        for expression in expressions:
            self.visit(expression)

    def visit_Lambda(self, node):
        """Inspect only lambda defaults evaluated in the surrounding scope."""
        expressions = node.args.defaults + node.args.kw_defaults
        for expression in expressions:
            if expression:
                self.visit(expression)

    def visit_ListComp(self, node):
        """Inspect list-comprehension expressions evaluated in this scope."""
        self._visit_comprehension_expressions(node)

    def visit_SetComp(self, node):
        """Inspect set-comprehension expressions evaluated in this scope."""
        self._visit_comprehension_expressions(node)

    def visit_DictComp(self, node):
        """Inspect dict-comprehension expressions evaluated in this scope."""
        self._visit_comprehension_expressions(node)

    def visit_GeneratorExp(self, node):
        """Inspect generator expressions evaluated in this scope."""
        self._visit_comprehension_expressions(node)

    def _visit_comprehension_expressions(self, node):
        for generator in node.generators:
            self.visit(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        expressions = (
            (node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,)
        )
        for expression in expressions:
            self.visit(expression)

    def visit_ExceptHandler(self, node):
        """Record the exception target and inspect the handler's bound names."""
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_MatchAs(self, node):
        """Record a name captured by a structural pattern."""
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_MatchStar(self, node):
        """Record a name captured by a starred structural pattern."""
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_MatchMapping(self, node):
        """Record the rest name captured by a mapping pattern."""
        if node.rest:
            self.names.add(node.rest)
        self.generic_visit(node)


def _db_python_argument_names(arguments):
    """Collect all parameter names that shadow module-level connection facts."""
    values = (
        arguments.posonlyargs
        + arguments.args
        + arguments.kwonlyargs
        + ([arguments.vararg] if arguments.vararg else [])
        + ([arguments.kwarg] if arguments.kwarg else [])
    )
    return {argument.arg for argument in values}


def _db_python_import_names(node):
    """Return names introduced by an import for conservative symbol shadowing."""
    if isinstance(node, ast.Import):
        return {alias.asname or alias.name.split(".")[0] for alias in node.names}
    if isinstance(node, ast.ImportFrom):
        return {alias.asname or alias.name for alias in node.names if alias.name != "*"}
    return set()


def _db_python_with_bindings(statement, symbols, shadowed, *, items=None):
    """Map simple with targets to drivers proven by their context expressions."""
    bindings = {}
    for item in statement.items if items is None else items:
        target = item.optional_vars
        names = _db_python_target_names(target)
        driver = None
        if (
            isinstance(statement, ast.With)
            and isinstance(target, ast.Name)
            and _db_python_call(item.context_expr, "sqlite3.connect", symbols, shadowed)
        ):
            driver = "sqlite"
        for name in names:
            bindings[name] = driver
    return bindings


def _db_python_target_names(target):
    """Return local names assigned by a with optional target."""
    if target is None:
        return set()
    return {
        node.id
        for node in ast.walk(target)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    }


def _db_python_register_assignment(
    statement, name, symbols, shadowed, engines, connections
):
    engines.pop(name, None)
    connections.pop(name, None)
    value = (
        statement.value if isinstance(statement, (ast.Assign, ast.AnnAssign)) else None
    )
    if not isinstance(value, ast.Call):
        return
    if _db_python_call(value, "sqlalchemy.create_engine", symbols, shadowed):
        engines[name] = "sqlalchemy"
    elif _db_python_call(value, "sqlite3.connect", symbols, shadowed):
        connections[name] = "sqlite"
    elif any(
        _db_python_call(value, driver + ".connect", symbols, shadowed)
        for driver in ("psycopg", "psycopg2")
    ):
        connections[name] = "psycopg"
    elif _db_python_connection_call(value, "connect", engines):
        connections[name] = "sqlalchemy"
    elif _db_python_connection_call(value, "cursor", connections):
        connections[name] = "psycopg"


def _db_python_connection_call(value, method, known):
    return (
        isinstance(value.func, ast.Attribute)
        and value.func.attr == method
        and isinstance(value.func.value, ast.Name)
        and value.func.value.id in known
    )


def _db_assignment_targets(statement):
    if isinstance(statement, ast.Assign):
        targets = statement.targets
    elif isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
        targets = [statement.target]
    else:
        return []
    return sorted(
        {name for target in targets for name in _db_python_target_names(target)}
    )


def _db_python_execute(
    call,
    path,
    digest,
    symbols,
    shadowed,
    dialect,
    sqlglot,
    exp,
    connections,
    literal_texts,
    queries,
    gaps,
):
    receiver = call.func.value
    name = receiver.id if isinstance(receiver, ast.Name) else None
    if not call.args:
        gaps.append("python_execute_sql_missing:" + path)
        return
    argument = call.args[0]
    query_text = _db_python_sql_literal(argument, symbols, shadowed, literal_texts)
    if name is None or name not in connections:
        gaps.append("python_execute_receiver_unproven:" + path)
        return
    driver = connections[name]
    if query_text is None or (
        driver == "sqlalchemy"
        and not _db_python_contains_text(argument, symbols, shadowed, literal_texts)
    ):
        gaps.append("python_dynamic_or_unwrapped_sql:" + path)
        return
    try:
        statements = _db_parse_sql(sqlglot, query_text, dialect)
    except sqlglot.errors.ParseError:
        gaps.append("python_sql_parse_error:" + path)
        return
    for index, statement in enumerate(statements, 1):
        if isinstance(statement, (exp.Select, exp.Insert, exp.Update, exp.Delete)):
            location = {
                "path": path,
                "sha256": digest,
                "line": call.lineno,
                "statement": index,
                "kind": driver + "_execute",
            }
            _db_query(statement, exp, dialect, location, queries, gaps)
        else:
            gaps.append("python_executed_non_query_unsupported:" + path)


def _db_python_sql_literal(node, symbols, shadowed, bindings=None):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and bindings and node.id in bindings:
        return bindings[node.id][0]
    if (
        isinstance(node, ast.Call)
        and _db_python_is_text_call(node, symbols, shadowed)
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ):
        return node.args[0].value
    return None


def _db_python_is_text_call(node, symbols, shadowed):
    return _db_python_call(
        node, "sqlalchemy.text", symbols, shadowed
    ) or _db_python_call(node, "sqlalchemy.sql.text", symbols, shadowed)


def _db_python_contains_text(node, symbols, shadowed, bindings=None):
    if isinstance(node, ast.Name) and bindings and node.id in bindings:
        return bindings[node.id][1]
    return any(
        isinstance(child, ast.Call)
        and _db_python_is_text_call(child, symbols, shadowed)
        for child in ast.walk(node)
    )


def _db_table_name(table, dialect):
    if table is None:
        return None
    unaliased = table.copy()
    unaliased.set("alias", None)
    return unaliased.sql(dialect=dialect, normalize=False, pretty=False)


def _db_ident(identifier, dialect):
    return identifier.sql(dialect=dialect, normalize=False, pretty=False)


def _db_read_statement(
    statement, exp, path, digest, index, dialect, tables, operations, queries, gaps
):
    loc = {"path": path, "sha256": digest, "statement": index}
    if isinstance(statement, exp.Command):
        gaps.append("sql_command_fallback:" + path)
    elif isinstance(statement, exp.Create):
        if statement.kind == "INDEX" and isinstance(statement.this, exp.Index):
            table_name = _db_table_name(statement.this.args.get("table"), dialect)
            if table_name not in tables:
                gaps.append("index_table_unresolved:" + str(table_name))
            else:
                tables[table_name]["indexes"].append(
                    {
                        "name": _db_ident(statement.this.this, dialect),
                        "unique": bool(statement.this.args.get("unique")),
                        "columns": sorted(
                            _db_ident(c.this, dialect)
                            for c in statement.this.find_all(exp.Column)
                        ),
                    }
                )
            operations.append(
                {"op": "create_index", "table": table_name, "source": loc}
            )
        elif statement.kind == "TABLE" and isinstance(statement.this, exp.Schema):
            _db_create_table(statement, exp, dialect, loc, tables, operations, gaps)
        else:
            gaps.append("unsupported_create:" + path)
    elif isinstance(statement, exp.Alter):
        _db_alter(statement, exp, dialect, loc, tables, operations, gaps)
    elif isinstance(statement, exp.Drop):
        _db_drop_statement(statement, exp, dialect, loc, tables, operations, gaps)
    elif isinstance(statement, (exp.Select, exp.Insert, exp.Update, exp.Delete)):
        _db_query(statement, exp, dialect, loc, queries, gaps)
    else:
        gaps.append("unsupported_statement:" + path)


def _db_empty_table(name):
    return {
        "name": name,
        "columns": [],
        "primary_key": [],
        "foreign_keys": [],
        "unique": [],
        "indexes": [],
    }


def _db_valid_create_items(table_node, items, exp, path, gaps):
    if (
        not isinstance(table_node, exp.Table)
        or not isinstance(table_node.this, exp.Identifier)
        or not table_node.this.name.strip()
    ):
        gaps.append("malformed_create_table:" + path)
        return False
    for item in items:
        if isinstance(item, exp.ColumnDef) and (
            not isinstance(item.this, exp.Identifier) or not item.this.name.strip()
        ):
            gaps.append("malformed_column_name:" + path)
            return False
        if isinstance(item, exp.Constraint) and not item.expressions:
            gaps.append("malformed_table_constraint:" + path)
            return False
        if not isinstance(item, (exp.ColumnDef, exp.Constraint)):
            gaps.append("unsupported_table_element:" + path)
            return False
    return True


def _db_create_table(statement, exp, dialect, loc, tables, operations, gaps):
    table_node = statement.this.this
    items = statement.this.expressions
    if not _db_valid_create_items(table_node, items, exp, loc["path"], gaps):
        return
    table_name = _db_table_name(table_node, dialect)
    if table_name in tables:
        if statement.args.get("exists"):
            operations.append(
                {"op": "create_table_if_not_exists", "table": table_name, "source": loc}
            )
            return
        gaps.append("duplicate_create_table:" + loc["path"])
        return
    table = tables.setdefault(table_name, _db_empty_table(table_name))
    for item in items:
        if isinstance(item, exp.ColumnDef):
            _db_column_fact(item, exp, dialect, table, loc, gaps)
        elif isinstance(item, exp.Constraint):
            for constraint in item.expressions:
                _db_constraint_fact(constraint, exp, dialect, table, loc, gaps)
    table["primary_key"] = sorted(set(table["primary_key"]))
    table["unique"] = sorted(
        {json.dumps(x, separators=(",", ":")): x for x in table["unique"]}.values(),
        key=lambda x: json.dumps(x),
    )
    table["foreign_keys"].sort(key=lambda x: json.dumps(x, sort_keys=True))
    table["columns"].sort(key=lambda x: x["name"])
    operations.append({"op": "create_table", "table": table_name, "source": loc})


def _db_column_fact(column, exp, dialect, table, loc, gaps):
    if not isinstance(column.this, exp.Identifier) or not column.this.name.strip():
        gaps.append("malformed_column_name:" + loc["path"])
        return
    name = _db_ident(column.this, dialect)
    constraints = [c.args.get("kind") for c in column.constraints]
    for constraint in constraints:
        if isinstance(constraint, exp.PrimaryKeyColumnConstraint):
            table["primary_key"].append(name)
        elif isinstance(constraint, exp.UniqueColumnConstraint):
            table["unique"].append([name])
        elif isinstance(constraint, exp.Reference):
            ref = constraint.this
            table["foreign_keys"].append(
                {
                    "columns": [name],
                    "target_table": _db_table_name(ref.this, dialect),
                    "target_columns": [_db_ident(x, dialect) for x in ref.expressions],
                }
            )
        elif not isinstance(
            constraint, (exp.NotNullColumnConstraint, exp.DefaultColumnConstraint)
        ):
            gaps.append("unsupported_column_constraint:" + loc["path"])
    table["columns"].append(
        {
            "name": name,
            "type": column.args["kind"].sql(dialect=dialect)
            if column.args.get("kind")
            else None,
            "nullable": not any(
                isinstance(
                    c, (exp.NotNullColumnConstraint, exp.PrimaryKeyColumnConstraint)
                )
                for c in constraints
            ),
            "source": loc,
        }
    )


def _db_constraint_fact(constraint, exp, dialect, table, loc, gaps):
    if isinstance(constraint, exp.PrimaryKey):
        table["primary_key"].extend(
            _db_ident(x, dialect) for x in constraint.expressions
        )
    elif isinstance(constraint, exp.UniqueColumnConstraint):
        schema = constraint.this
        table["unique"].append(
            [_db_ident(x, dialect) for x in schema.expressions]
            if isinstance(schema, exp.Schema)
            else []
        )
    elif isinstance(constraint, exp.ForeignKey):
        ref = constraint.args.get("reference")
        table["foreign_keys"].append(
            {
                "columns": [_db_ident(x, dialect) for x in constraint.expressions],
                "target_table": _db_table_name(ref.this, dialect) if ref else None,
                "target_columns": [_db_ident(x, dialect) for x in ref.expressions]
                if ref
                else [],
            }
        )
    else:
        gaps.append("unsupported_table_constraint:" + loc["path"])


def _db_alter(statement, exp, dialect, loc, tables, operations, gaps):
    name = _db_table_name(statement.this, dialect)
    table = tables.get(name)
    actions = statement.args.get("actions") or []
    if table is None or not actions:
        gaps.append("alter_target_unresolved:" + loc["path"])
        return
    for action in actions:
        _db_alter_action(
            action, exp, dialect, loc, name, table, tables, operations, gaps
        )


def _db_alter_action(action, exp, dialect, loc, name, table, tables, operations, gaps):
    if isinstance(action, exp.ColumnDef):
        if not isinstance(action.this, exp.Identifier) or not action.this.name.strip():
            gaps.append("malformed_alter_column:" + loc["path"])
            return
        column_name = _db_ident(action.this, dialect)
        if any(column["name"] == column_name for column in table["columns"]):
            gaps.append("alter_add_column_duplicate:" + loc["path"])
            return
        _db_column_fact(action, exp, dialect, table, loc, gaps)
        operations.append(
            {"op": "add_column", "table": name, "column": column_name, "source": loc}
        )
    elif isinstance(action, exp.Drop) and action.args.get("kind") == "COLUMN":
        for column in action.args.get("tables") or []:
            column_name = _db_ident(column.this, dialect)
            if not any(item["name"] == column_name for item in table["columns"]):
                gaps.append("alter_drop_column_unresolved:" + loc["path"])
                continue
            _db_remove_column(table, column_name, tables)
            operations.append(
                {
                    "op": "drop_column",
                    "table": name,
                    "column": column_name,
                    "source": loc,
                }
            )
    elif isinstance(action, exp.RenameColumn):
        old = _db_ident(action.this.this, dialect)
        new = _db_ident(action.args["to"].this, dialect)
        names = {column["name"] for column in table["columns"]}
        if old not in names or new in names:
            gaps.append("rename_column_target_invalid:" + loc["path"])
            return
        _db_rename_column(table, old, new, name, tables)
        operations.append(
            {
                "op": "rename_column",
                "table": name,
                "from": old,
                "to": new,
                "source": loc,
            }
        )
    elif isinstance(action, exp.AlterRename) and isinstance(action.this, exp.Table):
        _db_rename_table(
            name, _db_table_name(action.this, dialect), tables, operations, loc, gaps
        )
    else:
        gaps.append("alter_semantics_incomplete:" + loc["path"])


def _db_remove_column(table, name, tables):
    table["columns"] = [column for column in table["columns"] if column["name"] != name]
    table["primary_key"] = [column for column in table["primary_key"] if column != name]
    table["unique"] = [columns for columns in table["unique"] if name not in columns]
    table["foreign_keys"] = [
        fk for fk in table["foreign_keys"] if name not in fk["columns"]
    ]
    table["indexes"] = [
        index for index in table["indexes"] if name not in index["columns"]
    ]


def _db_rename_column(table, old, new, name, tables):
    for column in table["columns"]:
        if column["name"] == old:
            column["name"] = new
    table["primary_key"] = [
        new if column == old else column for column in table["primary_key"]
    ]
    table["unique"] = [
        [new if column == old else column for column in cols]
        for cols in table["unique"]
    ]
    for fk in table["foreign_keys"]:
        fk["columns"] = [new if column == old else column for column in fk["columns"]]
    for index in table["indexes"]:
        index["columns"] = [
            new if column == old else column for column in index["columns"]
        ]
    for owner in tables.values():
        for fk in owner["foreign_keys"]:
            if fk["target_table"] == name:
                fk["target_columns"] = [
                    new if column == old else column for column in fk["target_columns"]
                ]


def _db_rename_table(old, new, tables, operations, loc, gaps):
    if old not in tables or new in tables:
        gaps.append("rename_table_target_invalid:" + loc["path"])
        return
    table = tables.pop(old)
    table["name"] = new
    tables[new] = table
    for owner in tables.values():
        for fk in owner["foreign_keys"]:
            if fk["target_table"] == old:
                fk["target_table"] = new
    operations.append({"op": "rename_table", "from": old, "to": new, "source": loc})


def _db_drop_statement(statement, exp, dialect, loc, tables, operations, gaps):
    kind = statement.args.get("kind")
    targets = statement.args.get("tables") or []
    if kind == "TABLE":
        for target in targets:
            name = _db_table_name(target, dialect)
            if name not in tables:
                if not statement.args.get("exists"):
                    gaps.append("drop_table_target_unresolved:" + loc["path"])
            else:
                del tables[name]
            operations.append({"op": "drop_table", "table": name, "source": loc})
    elif kind == "INDEX":
        target = _db_ident(targets[0], dialect) if targets else None
        found = False
        for table in tables.values():
            before = len(table["indexes"])
            table["indexes"] = [
                index for index in table["indexes"] if index["name"] != target
            ]
            found = found or len(table["indexes"]) != before
        if not found:
            gaps.append("drop_index_target_unresolved:" + loc["path"])
        operations.append({"op": "drop_index", "index": target, "source": loc})
    else:
        gaps.append("unsupported_drop:" + loc["path"])


def _db_query_wildcards(statement, exp, dialect, alias_map, path, gaps):
    columns = []
    for projection in statement.args.get("expressions") or []:
        target = None
        if isinstance(projection, exp.Star):
            columns.extend(
                {"table": table, "name": "*", "wildcard": True}
                for table in sorted(set(alias_map.values()))
            )
        elif isinstance(projection, exp.Column) and isinstance(
            projection.this, exp.Star
        ):
            target = alias_map.get(projection.table)
            if target is None:
                gaps.append("unresolved_query_qualifier:" + path)
            else:
                columns.append({"table": target, "name": "*", "wildcard": True})
    return columns


def _db_query(statement, exp, dialect, loc, queries, gaps):
    ctes = {cte.alias_or_name for cte in statement.find_all(exp.CTE)}
    nested = any(select is not statement for select in statement.find_all(exp.Select))
    if ctes or nested:
        gaps.append(
            ("unsupported_cte_scope:" if ctes else "unsupported_nested_query_scope:")
            + loc["path"]
        )
        queries.append(
            {
                "operation": type(statement).__name__.lower(),
                "tables": [],
                "columns": [],
                "source": loc,
            }
        )
        return
    alias_map = {}
    for table in statement.find_all(exp.Table):
        if table.name and table.alias_or_name not in ctes:
            relation = _db_table_name(table, dialect)
            if (
                table.alias_or_name in alias_map
                and alias_map[table.alias_or_name] != relation
            ):
                gaps.append("ambiguous_query_alias:" + loc["path"])
                queries.append(
                    {
                        "operation": type(statement).__name__.lower(),
                        "tables": [],
                        "columns": [],
                        "source": loc,
                    }
                )
                return
            alias_map[table.alias_or_name] = relation
    tables = sorted(set(alias_map.values()))
    columns = _db_query_wildcards(statement, exp, dialect, alias_map, loc["path"], gaps)
    for column in statement.find_all(exp.Column):
        if not column.name or isinstance(column.this, exp.Star):
            continue
        if column.table:
            target = alias_map.get(column.table)
            if target is None:
                gaps.append("unresolved_query_qualifier:" + loc["path"])
                continue
        elif len(tables) == 1:
            target = tables[0]
        else:
            gaps.append("unresolved_query_column_scope:" + loc["path"])
            continue
        columns.append({"table": target, "name": _db_ident(column.this, dialect)})
    queries.append(
        {
            "operation": type(statement).__name__.lower(),
            "tables": tables,
            "columns": sorted(columns, key=lambda x: (x["table"], x["name"])),
            "source": loc,
        }
    )


def literal_exec_rejected(node):
    """Prove only compilation failure for one source-bound builtin exec literal."""
    from . import review_integrity as integrity
    from .context_efficiency import (
        _bounded_ast_nodes,
        _module_has_dynamic_capability_access,
    )

    match node:
        case ast.Call(
            func=ast.Name(id="exec"),
            args=[ast.Constant(value=str()) as literal],
            keywords=[],
        ):
            pass
        case _:
            return {}
    if not hasattr(node, "_security_shadowed_names"):
        return {}
    module = integrity._security_module_scope(
        getattr(node, "_security_lexical_scope", None)
    )
    if module is None or integrity._builtin_repr_names_shadowed(node, {"exec"}):
        return {}
    nodes = _bounded_ast_nodes(module)
    if nodes is None or _module_has_dynamic_capability_access(
        [n for n in nodes if n is not node.func]
    ):
        return {}
    if any(
        isinstance(n, ast.Attribute)
        and n.attr == "__dict__"
        or isinstance(n, (ast.Import, ast.ImportFrom))
        and any(a.name in {"builtins", "*"} for a in n.names)
        or isinstance(n, ast.ImportFrom)
        and n.module == "builtins"
        for n in nodes
    ):
        return {}
    try:
        if len(literal.value.encode("utf-8")) > 4096:
            return {}
        ast.parse(literal.value, mode="exec")
    except SyntaxError:
        return dict(
            primitive_present=True,
            source_compilation="REJECTED_SYNTAX",
            execution_of_literal_source=False,
            evidence_scope="exact_builtin_call_literal",
        )
    except (MemoryError, RecursionError, UnicodeError, ValueError):
        pass
    return {}
