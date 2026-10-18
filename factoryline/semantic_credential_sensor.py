"""Detect literal credentials wired directly into canonical HTTP authentication sinks."""

from __future__ import annotations

import ast
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
            # Basic-auth tuples are (username, password); usernames alone are not credentials.
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
    from .security_configuration import _expanded, _canonical

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


def _provider_identity_uncertain(tree, aliases):
    """Veto HTTP proofs if the full provider mutation index finds a relevant escape."""
    from types import SimpleNamespace

    from .provider_mutations import finite_provider_mutation_index
    from .review_audits import _resolved_ast_name

    nodes = list(ast.walk(tree))
    parents = {
        id(child): node for node in nodes for child in ast.iter_child_nodes(node)
    }
    audit = SimpleNamespace(_resolved_ast_name=_resolved_ast_name)
    mutations = finite_provider_mutation_index(nodes, aliases, audit, parents)
    return any(
        path == root or path.startswith(root + ".")
        for path, _attribute in mutations
        for root in ("requests", "httpx")
    )


def credential_findings(tree, aliases, relative="<source>"):
    """Report only non-placeholder literals in statically bound HTTP auth slots."""
    from .review_audits import _security_finding
    from .review_integrity import bind_security_call_scopes

    if not hasattr(tree, "_security_scope_kind"):
        bind_security_call_scopes(tree)
    if _provider_identity_uncertain(tree, aliases):
        return []
    findings = []
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        for value, consumer_role, slot in _auth_literal_nodes(call, aliases):
            literal = value
            if slot == "authorization":
                match = _AUTH_HEADER.match(value.value)
                literal = ast.Constant(match.group(1) if match else "")
            if not _literal_credential(literal):
                continue
            findings.append(
                _security_finding(
                    "SECURITY_LITERAL_HTTP_CREDENTIAL",
                    relative,
                    call,
                    "A non-placeholder credential literal is passed directly to an HTTP authentication sink.",
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


def configuration_and_credential_findings(tree, aliases, relative="<source>"):
    """Combine configuration and credential sensors with one scope-binding pass."""
    from .security_configuration import configuration_findings

    findings = configuration_findings(tree, aliases, relative)
    findings.extend(credential_findings(tree, aliases, relative))
    return findings


def validation_modules():
    """Include semantic sensor implementations in native cache identity."""
    import sys

    return (sys.modules[__name__],)
