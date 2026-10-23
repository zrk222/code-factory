"""Model request-source identity and literal credentials at canonical security sinks."""

from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path
from typing import Any
import re
from urllib.parse import urlsplit

_HTTP_CALLS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "request"}
)
_AUTH_CALLS = frozenset({"requests.auth.HTTPBasicAuth", "httpx.BasicAuth"})
_AUTH_HEADER = re.compile(r"(?i)^\s*(?:bearer|basic)\s+(.+?)\s*$")


def _literal_credential(node):
    from .review_audits import _PLACEHOLDER_SECRET

    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return False
    value = node.value.strip()
    return bool(value and not _PLACEHOLDER_SECRET.match(value))


def _canonical_http_call(node, aliases):
    from .security_configuration import _canonical

    name = _canonical(node, aliases)
    supported = {
        f"{module}.{method}"
        for module in ("requests", "httpx")
        for method in _HTTP_CALLS
    }
    if name in supported:
        return name
    if (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Call)
        and _canonical(node.func.value, aliases) in {"httpx.Client", "requests.Session"}
        and node.func.attr in _HTTP_CALLS
    ):
        return f"{_canonical(node.func.value, aliases)}.{node.func.attr}"
    return ""


def _basic_auth_password(call, raw):
    if raw not in _AUTH_CALLS:
        return None
    if len(call.args) == 2 and not call.keywords:
        return call.args[1]
    if call.args or sorted(item.arg for item in call.keywords) != [
        "password",
        "username",
    ]:
        return None
    return next(item.value for item in call.keywords if item.arg == "password")


def _http_auth_password(call, name, raw, aliases):
    from .security_configuration import _keyword

    if name:
        auth = _keyword(call, "auth")
        if isinstance(auth, (ast.Tuple, ast.List)) and len(auth.elts) == 2:
            # Basic-auth tuples are (username, password); usernames are not secrets.
            return auth.elts[1]
        return None
    return _basic_auth_password(call, raw)


def _url_userinfo_credential(call, name):
    url = _http_url_argument(call, name)
    if url is None:
        return None
    password = _url_password(url)
    candidate = ast.Constant(password) if password else None
    return candidate if _literal_credential(candidate) else None


def _authorization_credential(call, name):
    from .security_configuration import _keyword

    headers = _keyword(call, "headers")
    if not name or not isinstance(headers, ast.Dict):
        return None
    value = _authorization_header_value(headers)
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
        return None
    match = _AUTH_HEADER.match(value.value)
    if match and _literal_credential(ast.Constant(match.group(1))):
        return value
    return None


def _auth_literal_nodes(call, aliases):
    from .security_configuration import _canonical, _expanded

    if _expanded(call):
        return []
    name = _canonical_http_call(call, aliases)
    raw = _canonical(call, aliases)
    values = []
    password = _http_auth_password(call, name, raw, aliases)
    if password is not None:
        values.append((password, "http_auth", "password"))
    if name:
        userinfo = _url_userinfo_credential(call, name)
        if userinfo is not None:
            values.append((userinfo, "http_url_userinfo", "userinfo_password"))
        authorization = _authorization_credential(call, name)
        if authorization is not None:
            values.append((authorization, "http_header", "authorization"))
    return values


def _http_url_argument(call, canonical):
    from .security_configuration import _keyword

    position = 1 if canonical.endswith(".request") else 0
    keywords = [item.value for item in call.keywords if item.arg == "url"]
    if len(keywords) > 1 or (keywords and len(call.args) > position):
        return None
    return keywords[0] if keywords else _keyword(call, "url", position)


def _url_password(node):
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return ""
    try:
        parsed = urlsplit(node.value)
        if parsed.scheme not in {"http", "https"} or not parsed.username:
            return ""
        return parsed.password or ""
    except (ValueError, UnicodeError):
        return ""


def _authorization_header_value(headers):
    exact_keys = {}
    for key, value in zip(headers.keys, headers.values):
        if (
            key is None
            or not isinstance(key, ast.Constant)
            or not isinstance(key.value, str)
        ):
            return None
        exact_keys[key.value] = value
    selected = None
    for key, value in exact_keys.items():
        if key.casefold() == "authorization":
            selected = value
    return selected


def _provider_identity_uncertain(
    tree, aliases, roots=("requests", "httpx"), *, nodes=None, parents=None
):
    """Veto HTTP proofs if the full provider mutation index finds a relevant escape."""
    from types import SimpleNamespace

    from .finite_capture import finite_provider_mutation_index
    from .review_audits import _resolved_ast_name

    nodes = list(ast.walk(tree)) if nodes is None else nodes
    if parents is None:
        parents = {
            id(child): node for node in nodes for child in ast.iter_child_nodes(node)
        }
    audit = SimpleNamespace(_resolved_ast_name=_resolved_ast_name)
    mutations = finite_provider_mutation_index(nodes, aliases, audit, parents)
    return any(
        path == root or path.startswith(root + ".")
        for path, _attribute in mutations
        for root in roots
    )


def _credential_candidates(tree, aliases, nodes=None):
    candidates = []
    nodes = ast.walk(tree) if nodes is None else nodes
    for call in (node for node in nodes if isinstance(node, ast.Call)):
        for value, consumer_role, slot in _auth_literal_nodes(call, aliases):
            if slot == "authorization":
                match = _AUTH_HEADER.match(value.value)
                value = ast.Constant(match.group(1) if match else "")
            if _literal_credential(value):
                candidates.append((call, consumer_role, slot))
    return candidates


def credential_findings(tree, aliases, relative="<source>", *, nodes=None):
    """Report only non-placeholder literals in statically bound HTTP auth slots."""
    from .review_audits import _security_finding
    from .review_integrity import bind_security_call_scopes

    if not hasattr(tree, "_security_scope_kind"):
        bind_security_call_scopes(tree)
    nodes = tuple(ast.walk(tree) if nodes is None else nodes)
    candidates = _credential_candidates(tree, aliases, nodes)
    if not candidates or _provider_identity_uncertain(tree, aliases, nodes=nodes):
        return []
    findings = []
    for call, consumer_role, slot in candidates:
        findings.append(
            _security_finding(
                "SECURITY_LITERAL_HTTP_CREDENTIAL",
                relative,
                call,
                "A non-placeholder credential literal is passed directly "
                "to an HTTP authentication sink.",
                "MEDIUM",
                source_role="credential_literal",
                consumer_role=consumer_role,
                value_role="credential",
                credential_slot=slot,
                proof_scope="local_static_wiring",
                deployment="unknown",
                credential_validity="not_established",
                sensor="semantic_credential_sensor",
                sensor_schema="factory.security.semantic_credential.v1",
                claim_boundary="static_not_runtime",
            )
        )
    return findings


def configuration_and_credential_findings(
    tree, aliases, relative="<source>", *, nodes=None
):
    """Combine configuration and credential sensors with one scope-binding pass."""
    from .security_configuration import configuration_findings

    findings = configuration_findings(tree, aliases, relative)
    findings.extend(credential_findings(tree, aliases, relative, nodes=nodes))
    return findings


def validation_modules():
    """Include semantic sensor implementations in native cache identity."""
    import sys

    return (sys.modules[__name__],)


def _new_security_request_alias_memo(tree):
    """Create bounded, invocation-local request alias caches for one AST."""
    return {"tree": tree, "values": {}, "pairs": 0, "bytes": 0}


def _security_scope_request_aliases(scope, aliases, flow_statement=None):
    """Resolve request aliases, reusing only exact-prefix results in one scan."""
    from . import intent_quality as request_contracts

    from . import review_integrity
    from . import review_audits as audit

    memo = request_contracts._SECURITY_REQUEST_ALIAS_MEMO.get()
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
    from . import intent_quality as request_contracts

    from . import review_audits as audit
    from .review_integrity import _security_apply_import_bindings

    memo = request_contracts._SECURITY_REQUEST_ALIAS_MEMO.get()
    key = (module, module, stop, alias_items)
    cached = memo["values"].get(key)
    if cached is not None:
        return dict(cached)
    resolved = _security_apply_import_bindings(module.body, {}, stop, audit)
    _security_store_request_alias_bindings(memo, key, alias_items, resolved)
    return dict(resolved)


def _security_store_request_alias_bindings(memo, key, alias_items, resolved):
    """Store a defensive alias copy only while all invocation budgets allow it."""
    from . import intent_quality as request_contracts

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
    if len(memo["values"]) >= request_contracts._SECURITY_REQUEST_ALIAS_MAX_ENTRIES:
        return
    if memo["pairs"] + pair_count > request_contracts._SECURITY_REQUEST_ALIAS_MAX_PAIRS:
        return
    if memo["bytes"] + byte_count > request_contracts._SECURITY_REQUEST_ALIAS_MAX_BYTES:
        return
    memo["values"][key] = value
    memo["pairs"] += pair_count
    memo["bytes"] += byte_count


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


def flask_upload_expression(node, aliases, scope, flow_statement, collection):
    """Recognize Flask file access through a files collection subscript or get call."""
    if isinstance(node, ast.Subscript):
        return collection(node.value, aliases, scope, flow_statement, "files")
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and collection(node.func.value, aliases, scope, flow_statement, "files")
    )


def password_comparison_finding(
    relative,
    test,
    password_fields,
    aliases,
    scope,
    flow_statement,
    password_source,
    literal_valid,
):
    """Create a critical hardcoded-secret finding when a request-derived password is compared with a valid literal using equality."""
    from . import review_audits as audit

    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return None
    if not isinstance(test.ops[0], ast.Eq) or len(test.comparators) != 1:
        return None
    left, right = test.left, test.comparators[0]
    if password_source(left, password_fields, aliases, scope, flow_statement):
        literal = right
    elif password_source(right, password_fields, aliases, scope, flow_statement):
        literal = left
    else:
        return None
    if not literal_valid(literal):
        return None
    return audit._security_finding(
        "SECURITY_HARDCODED_SECRET",
        relative,
        test,
        "A request-derived password is compared with a hardcoded value.",
        "CRITICAL",
        name="password_comparison",
    )


def flask_request_collection(
    node, aliases, scope, flow_statement, collection, request_aliases
):
    """Recognize an aliased Flask request collection only when it resolves to flask.request and the requested collection."""
    from .review_audits import _name

    if not isinstance(node, ast.Attribute) or node.attr != collection:
        return False
    raw = _name(node)
    head, _, tail = raw.partition(".")
    canonical = request_aliases(scope, aliases, flow_statement).get(head, "") + (
        "." + tail if tail else ""
    )
    return canonical == f"flask.request.{collection}"


def _django_request_parameter_name(node, scope, audit):
    if not isinstance(node, ast.Attribute) or node.attr != "GET":
        return None
    request = node.value
    if not isinstance(request, ast.Name):
        return None
    scope = scope or getattr(node, "_security_lexical_scope", None)
    parameters = getattr(scope, "_security_parameter_names", set())
    if request.id not in parameters or not isinstance(
        scope, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        return None
    if any(
        isinstance(child, ast.Name)
        and child.id == request.id
        and isinstance(child.ctx, (ast.Store, ast.Del))
        for statement in scope.body
        for child in audit._iter_ast_nodes(statement)
    ):
        return None
    return request


def django_request_parameter(
    node, aliases, scope, flow_statement, request_alias_reader
):
    """Recognize an unshadowed Django request parameter with a proven alias."""
    from . import review_audits as audit
    from .review_audits import _name

    scope = scope or getattr(node, "_security_lexical_scope", None)
    request = _django_request_parameter_name(node, scope, audit)
    if request is None:
        return False
    request_aliases = request_alias_reader(scope, aliases, flow_statement)
    if not any(value.startswith("django.") for value in request_aliases.values()):
        return False
    return _name(request) == request.id


def legacy_tls_verification_risk(call, node, aliases=None):
    """Recognize client use of ssl.wrap_socket with omitted or CERT_NONE checks."""
    from .security_configuration import _canonical, _expanded, _keyword, _literal_bool

    aliases = aliases or {}
    if (
        call != "ssl.wrap_socket"
        or _expanded(node)
        or _canonical(node, aliases) != call
    ):
        return False
    server = _keyword(node, "server_side", 3)
    if _literal_bool(server) is True or (
        server is not None and _literal_bool(server) is None
    ):
        return False
    verification = _keyword(node, "cert_reqs", 4)
    if verification is None:
        return True
    from .review_integrity import _security_scope_request_aliases
    from .review_audits import _name

    bindings = _security_scope_request_aliases(
        getattr(node, "_security_lexical_scope", None),
        aliases,
        getattr(node, "_security_flow_statement", None),
    )
    raw = _name(verification)
    head, _, tail = raw.partition(".")
    return bindings.get(head, "") + ("." + tail if tail else "") == "ssl.CERT_NONE"


def tls_finding(call, relative, node, aliases=None):
    """Preserve request TLS findings and add conditional legacy client findings."""
    from .review_audits import _security_finding
    from .review_integrity import tls_verification_disabled
    from .security_configuration import legacy_tls_verification_risk

    if tls_verification_disabled(call, node):
        return _security_finding(
            "SECURITY_TLS_VERIFY_DISABLED",
            relative,
            node,
            "TLS certificate verification is disabled for an outbound request.",
            "HIGH",
            call=call,
        )
    if not legacy_tls_verification_risk(call, node, aliases):
        return None
    return _security_finding(
        "SECURITY_TLS_VERIFY_DISABLED",
        relative,
        node,
        "Legacy client TLS configuration omits or disables certificate verification; runtime availability and hostname behavior are not established.",
        "MEDIUM",
        call=call,
        configuration="legacy_CERT_NONE",
        role="client",
        runtime_availability="unknown",
        hostname_verification="not_established",
        trust_or_exploitability="unknown",
    )


def security_evals() -> dict[str, Any]:
    """Evaluate security rules against fixed adversarial and safe-control fixtures."""
    from . import review_audits as audit

    fixture_path = Path(__file__).parent / "data" / "security_evals.json"
    fixtures = json.loads(fixture_path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    for item in fixtures:
        name, source, expected = item["name"], item["source"], set(item["expected"])
        tree = ast.parse(source, filename=f"{name}.py")
        calls = audit._tenant_contract_calls(tuple(item.get("tenant_read_calls", ())))
        bindings = audit._tenant_contract_bindings(
            tuple(item.get("tenant_read_bindings", ())), calls
        )
        findings = audit._security_scan_tree(
            Path("."), Path(f"{name}.py"), tree, calls, bindings
        )
        actual = {item["code"] for item in findings}
        passed = actual == expected
        rows.append(
            {
                "id": name,
                "expected": sorted(expected),
                "observed": sorted(actual),
                "passed": passed,
            }
        )
    fixture_expectations = [set(item["expected"]) for item in fixtures]
    attempted = sum(bool(expected) for expected in fixture_expectations)
    caught = sum(
        row["passed"] for row, expected in zip(rows, fixture_expectations) if expected
    )
    controls = sum(not expected for expected in fixture_expectations)
    controls_passed = sum(
        row["passed"]
        for row, expected in zip(rows, fixture_expectations)
        if not expected
    )
    state = "PASS" if all(row["passed"] for row in rows) else "BLOCKED"
    result: dict[str, Any] = {
        "schema": "factory.security-evals.v1",
        "marker": "SECURITY_EVALS_COMPLETE",
        "state": state,
        "fixtures": rows,
        "mutation_coverage": {
            "attempted": attempted,
            "caught": caught,
            "rate": round(caught / attempted, 4) if attempted else 1.0,
        },
        "safe_controls": {"attempted": controls, "passed": controls_passed},
        "authority": {
            "execution": False,
            "approval": False,
            "publication": False,
            "deployment": False,
        },
        "claim_boundary": "Fixed local AST evaluation of scanner rules only; not a penetration test, runtime exploit proof, dependency advisory, or release approval.",
    }
    result["audit_sha256"] = sha256(
        json.dumps(
            result, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    result["action_summary"] = (
        "All adversarial fixtures were caught and safe controls remained clean."
        if state == "PASS"
        else "A scanner rule failed an adversarial fixture or contaminated a safe control; block promotion and repair the evaluator."
    )
    return result


def _exec_literal_call(node):
    match node:
        case ast.Call(
            func=ast.Name(id="exec"),
            args=[ast.Constant(value=str()) as literal],
            keywords=[],
        ):
            return literal
        case _:
            return None


def _exec_literal_namespace_closed(nodes):
    return not any(
        isinstance(node, ast.Attribute)
        and node.attr == "__dict__"
        or isinstance(node, (ast.Import, ast.ImportFrom))
        and any(alias.name in {"builtins", "*"} for alias in node.names)
        or isinstance(node, ast.ImportFrom)
        and node.module == "builtins"
        for node in nodes
    )


def _exec_literal_dynamic_access_closed(nodes, call, capability_reader):
    return not capability_reader([node for node in nodes if node is not call.func])


def _exec_literal_module_is_closed(node, integrity):
    if not hasattr(node, "_security_shadowed_names"):
        return None
    module = integrity._security_module_scope(
        getattr(node, "_security_lexical_scope", None)
    )
    if module is None or integrity._builtin_repr_names_shadowed(node, {"exec"}):
        return None
    from .context_efficiency import (
        _bounded_ast_nodes,
        _module_has_dynamic_capability_access,
    )

    nodes = _bounded_ast_nodes(module)
    if nodes is None or not _exec_literal_dynamic_access_closed(
        nodes, node, _module_has_dynamic_capability_access
    ):
        return None
    if not _exec_literal_namespace_closed(nodes):
        return None
    return module


def _exec_literal_compile_fails(literal):
    try:
        if len(literal.value.encode("utf-8")) > 4096:
            return False
        ast.parse(literal.value, mode="exec")
    except SyntaxError:
        return True
    except (MemoryError, RecursionError, UnicodeError, ValueError):
        return False
    return False


def literal_exec_rejected(node):
    """Prove only compilation failure for one source-bound builtin exec literal."""
    from . import review_integrity as integrity

    literal = _exec_literal_call(node)
    if literal is None or _exec_literal_module_is_closed(node, integrity) is None:
        return {}
    if _exec_literal_compile_fails(literal):
        return dict(
            primitive_present=True,
            source_compilation="REJECTED_SYNTAX",
            execution_of_literal_source=False,
            evidence_scope="exact_builtin_call_literal",
        )
    return {}
