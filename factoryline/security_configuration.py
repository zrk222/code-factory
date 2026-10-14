"""Read bounded Python AST evidence for selected security configurations."""

from __future__ import annotations

import ast


_SCOPE_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_CONTROL_TYPES = tuple(
    getattr(ast, n) for n in "If For AsyncFor While Try With AsyncWith Match".split()
)
_DEFERRED_TYPES = tuple(
    getattr(ast, n) for n in "Lambda ListComp SetComp DictComp GeneratorExp".split()
)


def _scopes(tree):
    yield tree
    for node in ast.walk(tree):
        if isinstance(node, _SCOPE_TYPES):
            yield node


def _canonical(node, aliases):
    from .review_integrity import _security_flow_bindings
    from .review_audits import _call_name

    resolved, _ = _security_flow_bindings(node, aliases)
    raw = _call_name(node)
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
    from .review_integrity import _security_module_scope

    scope = getattr(node, "_security_lexical_scope", None)
    module = _security_module_scope(scope)
    for owner in (scope, module):
        relative = None
        for statement in getattr(owner, "body", []):
            if owner is scope and statement is getattr(
                node, "_security_flow_statement", None
            ):
                break
            if isinstance(statement, (ast.Import, ast.ImportFrom)) and head in _targets(
                statement
            ):
                relative = bool(getattr(statement, "level", 0))
        if relative is not None:
            return relative
    return False


def _expanded(node):
    return any(isinstance(arg, ast.Starred) for arg in node.args) or any(
        kw.arg is None for kw in node.keywords
    )


def _targets(node):
    from .review_audits import _bound_names

    return _bound_names(node)


def _keyword(call, name):
    return next((item.value for item in call.keywords if item.arg == name), None)


def _literal_bool(node):
    value = getattr(node, "value", None)
    return value if type(value) is bool else None


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
    for target in _targets(node):
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
    for scope in _scopes(tree):
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

    bind_security_call_scopes(tree)
    messages = _jinja_records(tree, aliases) + _xml_records(tree, aliases)
    return [
        _security_finding(code, relative, node, message, severity, **facts)
        for code, node, severity, message, facts in messages
    ]


def legacy_tls_verification_risk(call, node, aliases=None):
    """Recognize client use of ssl.wrap_socket with omitted or CERT_NONE checks."""
    aliases = aliases or {}
    if _canonical(node, aliases) != "ssl.wrap_socket" or _expanded(node):
        return False
    server = _keyword(node, "server_side")
    if server is None and len(node.args) > 3:
        server = node.args[3]
    if _literal_bool(server) is True or (
        server is not None and _literal_bool(server) is None
    ):
        return False
    verification = _keyword(node, "cert_reqs")
    if verification is None and len(node.args) > 4:
        verification = node.args[4]
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
