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
    tree,
    aliases,
    roots=("requests", "httpx"),
    *,
    nodes=None,
    parents=None,
    selected_paths=False,
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
    if selected_paths:
        return any(
            _provider_path_conflicts(path, attribute, root)
            for path, attribute in mutations
            for root in roots
        )
    return any(
        path == root or path.startswith(root + ".")
        for path, _attribute in mutations
        for root in roots
    )


def _provider_path_conflicts(path, attribute, selected):
    effective = path if attribute == "*" else path + "." + attribute
    return (
        effective == selected
        or effective.startswith(selected + ".")
        or attribute == "*"
        and selected.startswith(path + ".")
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


def signing_configuration_inventory(source_bytes, bindings):
    """Build one byte-bound package view; never import or execute target code."""
    from .credential_role_constructor_provider import SourceSnapshotIndex
    from .review_audits import _security_aliases
    from .review_integrity import bind_security_call_scopes

    if not _signing_inventory_input_closed(source_bytes, bindings):
        return None
    result = _signing_inventory_snapshots(
        source_bytes, bindings, bind_security_call_scopes
    )
    if result is None:
        return None
    snapshots, captured, inventory = result
    index = SourceSnapshotIndex(Path("."), snapshots, captured, inventory)
    paths = index.module_paths()
    if paths is None:
        return None
    aliases = _signing_inventory_aliases(snapshots, _security_aliases)
    return {"index": index, "paths": paths, "aliases": aliases}


def _signing_inventory_input_closed(source_bytes, bindings):
    return not (
        set(source_bytes) != set(bindings)
        or len(bindings) > 2000
        or sum(len(raw) for raw in source_bytes.values() if isinstance(raw, bytes))
        > 32 * 1024 * 1024
    )


def _signing_inventory_snapshots(source_bytes, bindings, bind_security_call_scopes):
    snapshots, captured, inventory = {}, {}, {}
    for name, digest in bindings.items():
        raw, path = source_bytes.get(name), Path(name)
        if (
            not isinstance(raw, bytes)
            or len(raw) > 1_000_000
            or path.is_absolute()
            or ".." in path.parts
            or path.as_posix() != name
            or path.suffix != ".py"
            or sha256(raw).hexdigest() != digest
        ):
            return None
        try:
            tree = ast.parse(raw)
        except (SyntaxError, ValueError, UnicodeError, RecursionError):
            return None
        tree._oracle_source_sha256 = digest
        bind_security_call_scopes(tree)
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                child._security_parent = node
        snapshots[path], captured[path], inventory[path] = tree, raw, digest
    return snapshots, captured, inventory


def _signing_inventory_aliases(snapshots, security_aliases):
    return {
        path: security_aliases(list(ast.walk(tree))) for path, tree in snapshots.items()
    }


def signing_configuration_evidence(finding, context):
    """Prove a literal's framework configuration consumer, not live deployment."""
    if context is None or finding.get("facts", {}).get("name") != "SECRET_KEY":
        return None
    path = Path(finding.get("path", ""))
    index = context["index"]
    tree = index.snapshots.get(path)
    if tree is None or not index.validate(path):
        return None
    declaration = _signing_literal_declaration(finding, tree)
    if declaration is None:
        return None
    if _signing_imported_key_written(path, context):
        return None
    witness = _signing_configuration_consumer_witness(index, path, context)
    if witness is None:
        return None
    return _signing_configuration_witness(index, path, declaration, witness)


def flask_credential_authority_evidence(finding, context):
    """Regenerate a configured credential's local Flask session authority chain."""
    facts = finding.get("facts", {})
    key = facts.get("name") if isinstance(facts, dict) else None
    if context is None or not isinstance(key, str):
        return None
    if key != "SECRET_KEY" and not key.isidentifier():
        return None
    index = context["index"]
    path = Path(finding.get("path", ""))
    tree = index.snapshots.get(path)
    if tree is None or not index.validate(path):
        return None
    declaration = _flask_credential_declaration(finding, tree, key)
    if declaration is None or _flask_imported_key_written(path, context, key):
        return None
    session_secret = _flask_config_key_declaration(index, path, "SECRET_KEY")
    if session_secret is None or not _literal_credential(session_secret.value):
        return None
    for app in _flask_configured_apps(path, tree, context, {key, "SECRET_KEY"}):
        authority = _flask_session_authority_witness(path, tree, context, app, key)
        if authority is None:
            continue
        password_key = authority["password_key"]
        password_declaration = _flask_config_key_declaration(index, path, password_key)
        if password_declaration is None or not _literal_credential(
            password_declaration.value
        ):
            continue
        if key not in {"SECRET_KEY", password_key}:
            continue
        return _flask_credential_authority_witness(
            index,
            path,
            declaration,
            session_secret,
            password_declaration,
            app,
            authority,
            key,
        )
    return None


def _flask_credential_declaration(finding, tree, key):
    declaration = _flask_config_key_declaration_in_tree(tree, key)
    if declaration is None or _signing_rejection_or_reflection(tree):
        return None
    return (
        declaration
        if (declaration.lineno, declaration.col_offset)
        == (
            finding.get("line"),
            finding.get("column", 0),
        )
        else None
    )


def _flask_config_key_declaration(index, path, key):
    tree = index.snapshots.get(path)
    if tree is None or not index.validate(path):
        return None
    return _flask_config_key_declaration_in_tree(tree, key)


def _flask_config_key_declaration_in_tree(tree, key):
    declarations = [
        node
        for node in tree.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
        and any(
            isinstance(target, ast.Name) and target.id == key
            for target in (
                node.targets if isinstance(node, ast.Assign) else [node.target]
            )
        )
    ]
    writes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id == key
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    return declarations[0] if len(declarations) == len(writes) == 1 else None


def _flask_imported_key_written(target, context, key):
    from .review_audits import _resolved_ast_name

    names = {
        name[:-3].replace("/", ".")
        for name, path in context["paths"].items()
        if path == target and name.endswith(".py")
    }
    suffix = target.with_suffix("").as_posix().split("/")
    names.update(".".join(suffix[-length:]) for length in range(1, len(suffix) + 1))
    return any(
        isinstance(node, ast.Attribute)
        and node.attr == key
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and _resolved_ast_name(node.value, context["aliases"][path]) in names
        for path, tree in context["index"].snapshots.items()
        for node in ast.walk(tree)
    )


def _flask_configured_apps(target, tree, context, protected_keys):
    if not _signing_framework_external(context, "flask"):
        return []
    if not _flask_authority_provider_clear(target, tree, context):
        return []
    receivers = {}
    configured = []
    aliases = context["aliases"][target]
    for statement in tree.body:
        _flask_bind_created_app(statement, receivers, aliases)
        call = getattr(statement, "value", None)
        if not isinstance(call, ast.Call):
            continue
        for receiver, creation in receivers.items():
            if not _flask_config_load(call, receiver, target, context, target):
                continue
            if _flask_config_mutated(tree, receiver, protected_keys):
                continue
            if _flask_configuration_reloaded(
                tree, receiver, target, context, protected_keys, target
            ):
                continue
            configured.append(
                {"receiver": receiver, "creation": creation, "load": call}
            )
    return configured


def _flask_authority_provider_clear(path, tree, context):
    from .review_audits import _resolved_ast_name

    aliases = context["aliases"][path]
    nodes = list(ast.walk(tree))
    roots = {
        "flask.Flask",
        "flask.Config.from_object",
    }
    provider_objects = roots | {"flask.request", "flask.session"}
    names = {
        name
        for name, provider in aliases.items()
        if any(provider == root or provider.startswith(root + ".") for root in roots)
    }
    if any(
        isinstance(node, (ast.Name, ast.Attribute))
        and _resolved_ast_name(node, aliases).startswith(("sys.modules", "importlib."))
        for node in nodes
    ):
        return False
    if not _flask_star_imports_clear(tree, context):
        return False
    if any(
        isinstance(node, ast.Name)
        and node.id in names
        and isinstance(node.ctx, (ast.Store, ast.Del))
        for node in nodes
    ):
        return False
    if any(
        isinstance(node, ast.Attribute)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and _resolved_ast_name(node, aliases) in provider_objects
        for node in nodes
    ):
        return False
    return not _provider_identity_uncertain(
        tree, aliases, roots=tuple(roots), nodes=nodes, selected_paths=True
    )


def _flask_star_imports_clear(tree, context):
    protected = {
        "Flask",
        "request",
        "session",
        "redirect",
        "functools",
        "__name__",
    }
    for statement in tree.body:
        if not isinstance(statement, ast.ImportFrom) or not any(
            item.name == "*" for item in statement.names
        ):
            continue
        if statement.level or not statement.module:
            return False
        provider = _signing_resolve_module(
            context, ast.Constant(value=statement.module)
        )
        if provider is None:
            return False
        exports = _flask_static_module_exports(context, provider, set())
        if exports is None or exports & protected:
            return False
    return True


def _flask_static_module_exports(context, path, visiting):
    index = context["index"]
    if path in visiting or not index.validate(path):
        return None
    tree = index.snapshots.get(path)
    if tree is None:
        return None
    visiting.add(path)
    names, stars, declarations = _flask_static_module_bindings(tree)
    if not _flask_expand_star_exports(context, stars, visiting, names):
        return None
    exported = _flask_explicit_module_exports(tree, names, declarations)
    visiting.remove(path)
    return exported


def _flask_static_module_bindings(tree):
    from .review_audits import _bound_names

    names, stars, declarations = set(), [], []
    for statement in tree.body:
        names.update(_bound_names(statement))
        if isinstance(statement, ast.ImportFrom) and any(
            item.name == "*" for item in statement.names
        ):
            stars.append(statement)
        if _flask_assigns_module_name(statement, "__all__"):
            declarations.append(statement)
    names.discard("*")
    return names, stars, declarations


def _flask_assigns_module_name(statement, name):
    if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
        return False
    targets = (
        statement.targets if isinstance(statement, ast.Assign) else [statement.target]
    )
    return any(isinstance(target, ast.Name) and target.id == name for target in targets)


def _flask_expand_star_exports(context, stars, visiting, names):
    for statement in stars:
        if statement.level or not statement.module:
            return False
        child = _signing_resolve_module(context, ast.Constant(value=statement.module))
        child_names = (
            _flask_static_module_exports(context, child, visiting)
            if child is not None
            else None
        )
        if child_names is None:
            return False
        names.update(child_names)
    return True


def _flask_explicit_module_exports(tree, names, declarations):
    from .review_audits import _name

    all_writes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id == "__all__"
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    if declarations:
        if len(declarations) != 1 or len(all_writes) != 1:
            return None
        if any(
            isinstance(node, ast.Call)
            and any(
                isinstance(child, ast.Name) and child.id == "__all__"
                for child in ast.walk(node)
            )
            for node in ast.walk(tree)
        ):
            return None
        if any(
            isinstance(node, (ast.Attribute, ast.Subscript))
            and _name(node).startswith(("__all__.", "__all__["))
            for node in ast.walk(tree)
        ):
            return None
        value = declarations[0].value
        if not isinstance(value, (ast.List, ast.Tuple)) or not all(
            isinstance(item, ast.Constant) and isinstance(item.value, str)
            for item in value.elts
        ):
            return None
        exported = {item.value for item in value.elts}
        if not exported <= names:
            return None
    else:
        exported = {name for name in names if not name.startswith("_")}
    return None if _flask_module_exports_dynamic(tree) else exported


def _flask_module_exports_dynamic(tree):
    dynamic = {"eval", "exec", "globals", "locals", "vars", "setattr", "__import__"}
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            nodes = [
                *statement.decorator_list,
                *statement.args.defaults,
                *statement.args.kw_defaults,
            ]
        elif isinstance(statement, ast.ClassDef):
            nodes = [*statement.decorator_list, *statement.bases, *statement.keywords]
        else:
            nodes = [statement]
        if any(
            isinstance(node, ast.Call)
            and (
                isinstance(node.func, ast.Name)
                and node.func.id in dynamic
                or isinstance(node.func, ast.Attribute)
                and node.func.attr == "import_module"
            )
            for root in nodes
            for node in ast.walk(root)
        ):
            return True
    return False


def _flask_config_module_matches(context, expression, target, consumer_path):
    if isinstance(expression, ast.Name) and expression.id == "__name__":
        return consumer_path == target
    return _signing_resolve_module(context, expression) == target


def _flask_session_authority_witness(path, tree, context, app, credential_key):
    from .review_integrity import _security_scope_request_aliases

    aliases = context["aliases"][path]
    receiver = app["receiver"]
    login_wrapper = _flask_login_wrapper(tree, aliases)
    protected = _flask_protected_route(tree, receiver, aliases)
    if login_wrapper is None or protected is None:
        return None
    for route in tree.body:
        if not isinstance(route, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _flask_route_bound_to_app(route, receiver):
            continue
        witness = _flask_route_authority(
            route,
            tree,
            receiver,
            credential_key,
            aliases,
            _security_scope_request_aliases,
        )
        if witness is not None:
            return {
                **witness,
                "login_wrapper": login_wrapper["guard"],
                "protected_route": protected,
            }
    return None


def _flask_route_authority(
    route, tree, receiver, credential_key, aliases, alias_reader
):
    if not isinstance(route, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    for guard in ast.walk(route):
        if not isinstance(guard, ast.If) or not _flask_path_conditions_clear(
            tree, guard
        ):
            continue
        witness = _flask_guard_authority(
            guard, route, tree, receiver, credential_key, aliases, alias_reader
        )
        if witness is not None:
            return witness
    return None


def _flask_guard_authority(
    guard, route, tree, receiver, credential_key, aliases, alias_reader
):
    comparison = _flask_password_config_comparison(
        guard.test, receiver, aliases, route, guard, alias_reader
    )
    if comparison is None:
        return None
    password_key, equality = comparison
    if _flask_config_key_declaration_in_tree(tree, password_key) is None:
        return None
    grant = _flask_session_grant(guard.body, aliases, route, alias_reader)
    if grant is None or credential_key not in {password_key, "SECRET_KEY"}:
        return None
    return {"password_key": password_key, "comparison": equality, "grant": grant}


def _flask_credential_authority_witness(
    index, path, declaration, session_secret, password_declaration, app, authority, key
):
    nodes = [declaration]
    if session_secret is not declaration:
        nodes.append(session_secret)
    nodes.extend(
        (
            app["creation"],
            app["load"],
            password_declaration,
            authority["comparison"],
            authority["grant"],
            authority["login_wrapper"],
            authority["protected_route"],
        )
    )
    transfers = [_signing_source_span(index, path, node) for node in nodes]
    return {
        "framework": "flask",
        "credential_key": key,
        "password_key": authority["password_key"],
        "transfers": transfers,
        "proof_scope": "source_bound_flask_session_authority",
        "runtime_execution": "not_performed",
        "deployment": "UNASSESSED",
        "claim": (
            "Captured source connects a literal configuration credential to a "
            "same-app login comparison, session grant, and local guarded route."
        ),
    }


def _flask_password_config_comparison(
    test, receiver, aliases, scope, flow_statement, alias_reader
):
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return None
    if not isinstance(test.ops[0], ast.Eq) or len(test.comparators) != 1:
        return None
    left, right = test.left, test.comparators[0]
    for config_side, request_side in ((left, right), (right, left)):
        key = _flask_config_field(config_side, receiver)
        if key is None:
            continue
        if _flask_password_request_value(
            request_side, aliases, scope, flow_statement, alias_reader
        ):
            return key, test
    return None


def _flask_password_request_value(node, aliases, scope, flow_statement, alias_reader):
    if isinstance(node, ast.Name):
        return _flask_password_local_value(
            node, aliases, scope, flow_statement, alias_reader
        )
    if isinstance(node, ast.Subscript):
        return (
            isinstance(node.slice, ast.Constant)
            and node.slice.value == "password"
            and _http_request_mapping(
                node.value, aliases, scope, flow_statement, alias_reader, "password"
            )
        )
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "password"
    ):
        return _http_request_mapping(
            node.func.value, aliases, scope, flow_statement, alias_reader, "password"
        )
    return False


def _flask_password_local_value(node, aliases, scope, flow_statement, alias_reader):
    writes = [
        statement
        for statement in _flask_preceding_statements(scope, flow_statement)
        if any(
            isinstance(target, ast.Name)
            and target.id == node.id
            and isinstance(target.ctx, (ast.Store, ast.Del))
            for target in ast.walk(statement)
        )
    ]
    if not writes:
        return False
    reaching = max(writes, key=lambda statement: statement.lineno)
    return (
        isinstance(reaching, (ast.Assign, ast.AnnAssign))
        and not (isinstance(reaching.value, ast.Name) and reaching.value.id == node.id)
        and _flask_password_request_value(
            reaching.value, aliases, scope, reaching, alias_reader
        )
    )


def _flask_preceding_statements(scope, statement):
    parents = {
        id(child): parent
        for parent in ast.walk(scope)
        for child in ast.iter_child_nodes(parent)
    }
    current = statement
    while current is not scope:
        parent = parents.get(id(current))
        if parent is None:
            return
        for _field, body in ast.iter_fields(parent):
            if isinstance(body, list) and current in body:
                yield from body[: body.index(current)]
        current = parent


def _flask_config_field(node, receiver):
    return (
        node.slice.value
        if isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "config"
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == receiver
        else None
    )


def _flask_session_grant(statements, aliases, scope, alias_reader):
    for position, node in enumerate(statements):
        if not isinstance(node, ast.Assign) or not (
            isinstance(node.value, ast.Constant) and node.value.value is True
        ):
            continue
        if not any(
            isinstance(target, ast.Subscript)
            and isinstance(target.ctx, ast.Store)
            and isinstance(target.slice, ast.Constant)
            and target.slice.value == "logged_in"
            and _flask_resolves_to(
                target.value, "flask.session", aliases, scope, node, alias_reader
            )
            for target in node.targets
        ):
            continue
        if _flask_path_conditions_clear(scope, node) and _flask_grant_persists(
            statements[position + 1 :], aliases, scope, alias_reader
        ):
            return node
    return None


def _flask_grant_persists(statements, aliases, scope, alias_reader):
    for statement in statements:
        if _flask_session_escapes(statement, aliases, scope, alias_reader):
            return False
        for node in ast.walk(statement):
            if isinstance(node, ast.Subscript) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                if _flask_resolves_to(
                    node.value, "flask.session", aliases, scope, statement, alias_reader
                ) and (
                    not isinstance(node.slice, ast.Constant)
                    or node.slice.value == "logged_in"
                ):
                    return False
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and _flask_resolves_to(
                    node.func.value,
                    "flask.session",
                    aliases,
                    scope,
                    statement,
                    alias_reader,
                )
                and node.func.attr not in {"get", "keys", "values", "items", "copy"}
            ):
                return False
        if isinstance(statement, ast.Return):
            return True
        if isinstance(statement, ast.Raise):
            return False
    return False


def _flask_session_escapes(statement, aliases, scope, alias_reader):
    values = []
    for node in ast.walk(statement):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.Return)):
            values.append(node.value)
        elif isinstance(node, ast.Call):
            values.extend(node.args)
            values.extend(keyword.value for keyword in node.keywords)
    return any(
        isinstance(node, (ast.Name, ast.Attribute))
        and _flask_resolves_to(
            node, "flask.session", aliases, scope, statement, alias_reader
        )
        for value in values
        if value is not None
        for node in ast.walk(value)
    )


def _flask_login_wrapper(tree, aliases):
    wrappers = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "login_required"
    ]
    reassigned = any(
        isinstance(node, ast.Name)
        and node.id == "login_required"
        and isinstance(node.ctx, (ast.Store, ast.Del))
        for node in ast.walk(tree)
    )
    if len(wrappers) != 1 or reassigned:
        return None
    wrapper = wrappers[0]
    if not wrapper.args.args:
        return None
    view_parameter = wrapper.args.args[0].arg
    inner = [node for node in wrapper.body if isinstance(node, ast.FunctionDef)]
    if len(inner) != 1:
        return None
    returned = [
        node
        for node in wrapper.body
        if isinstance(node, ast.Return)
        and isinstance(node.value, ast.Name)
        and node.value.id == inner[0].name
    ]
    if len(returned) != 1 or not _flask_path_conditions_clear(wrapper, returned[0]):
        return None
    if any(
        node is not inner[0]
        and node is not returned[0]
        and not (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        )
        for node in wrapper.body
    ):
        return None
    guarded = inner[0]
    for position, statement in enumerate(guarded.body):
        if not isinstance(statement, ast.If) or statement.orelse:
            continue
        if (
            _flask_session_get_key(statement.test, "logged_in", aliases, guarded)
            is False
        ):
            continue
        allowed = [
            node
            for node in ast.walk(statement)
            if isinstance(node, ast.Return)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == view_parameter
        ]
        denied = guarded.body[position + 1 :]
        if (
            len(allowed) == 1
            and all(
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
                for node in guarded.body[:position]
            )
            and any(isinstance(node, ast.Return) for node in denied)
            and not any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == view_parameter
                for sibling in denied
                for node in ast.walk(sibling)
            )
            and _flask_path_conditions_clear(guarded, statement)
        ):
            return {"function": wrapper, "guard": statement}
    return None


def _flask_session_get_key(node, key, aliases, scope):
    from .review_integrity import _security_scope_request_aliases

    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == key
    ):
        return False
    return _flask_resolves_to(
        node.func.value,
        "flask.session",
        aliases,
        scope,
        node,
        _security_scope_request_aliases,
    )


def _flask_protected_route(tree, receiver, aliases):
    wrappers = _flask_login_wrapper(tree, aliases)
    if wrappers is None:
        return None
    for function in tree.body:
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _flask_route_bound_to_app(function, receiver):
            continue
        guarded = [
            position
            for position, decorator in enumerate(function.decorator_list)
            if isinstance(decorator, ast.Name) and decorator.id == "login_required"
        ]
        registered = [
            position
            for position, decorator in enumerate(function.decorator_list)
            if isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr == "route"
            and isinstance(decorator.func.value, ast.Name)
            and decorator.func.value.id == receiver
        ]
        if len(guarded) == 1 and registered and len(registered) == guarded[0] and all(
            position < guarded[0] for position in registered
        ):
            return function
    return None


def _flask_route_bound_to_app(function, receiver):
    return any(
        isinstance(value, ast.Attribute)
        and value.attr == "route"
        and isinstance(value.value, ast.Name)
        and value.value.id == receiver
        for decorator in function.decorator_list
        for value in [decorator.func if isinstance(decorator, ast.Call) else decorator]
    )


def _flask_resolves_to(node, expected, aliases, scope, statement, alias_reader):
    from .review_audits import _name

    resolved = alias_reader(scope, aliases, statement)
    raw = _name(node)
    head, _, tail = raw.partition(".")
    return resolved.get(head, "") + ("." + tail if tail else "") == expected


def _flask_path_conditions_clear(scope, node):
    parents = {
        id(child): parent
        for parent in ast.walk(scope)
        for child in ast.iter_child_nodes(parent)
    }
    current = node
    while current is not scope:
        parent = parents.get(id(current))
        if parent is None:
            return False
        if not _security_control_branch_possible(parent, current):
            return False
        if not _security_no_prior_terminator(parent, current):
            return False
        current = parent
    return True


def _signing_configuration_consumer_witness(index, path, context):
    for consumer_path, consumer_tree in index.snapshots.items():
        if _signing_rejection_or_reflection(consumer_tree):
            continue
        witness = _django_signing_consumer(path, consumer_path, consumer_tree, context)
        if witness is None:
            witness = _flask_signing_consumer(
                path, consumer_path, consumer_tree, context
            )
        if witness is not None and _signing_bound_providers_clear(
            context, path, consumer_path, witness["framework"]
        ):
            return witness
    return None


def private_key_authentication_evidence(finding, context):
    """Bind a captured private key to HTTP password decryption and verification."""
    if context is None or finding.get("code") != "SECURITY_HARDCODED_SECRET":
        return None
    path = Path(finding.get("path", ""))
    index = context["index"]
    tree = index.snapshots.get(path)
    if tree is None or not index.validate(path):
        return None
    declaration = _credential_private_key_declaration(finding, tree)
    if declaration is None or not _credential_providers_clear(context):
        return None
    aliases = context["aliases"][path]
    decryptors = _credential_private_key_decryptors(tree, declaration, aliases)
    witness = _credential_http_password_witness(tree, decryptors, aliases)
    if witness is None:
        return None
    return _credential_private_key_witness(index, path, declaration, witness)


def _credential_private_key_decryptors(tree, declaration, aliases):
    return {
        node.name: witness
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and not node.decorator_list
        and not _credential_module_rebound(tree, node.name, node)
        and sum(
            isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and item.name == node.name
            for item in ast.walk(tree)
        )
        == 1
        and (witness := _credential_private_key_decryptor(node, declaration, aliases))
        is not None
    }


def _credential_http_password_witness(tree, decryptors, aliases):
    for endpoint in tree.body:
        if not isinstance(endpoint, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        witness = _credential_http_password_consumer(endpoint, decryptors, aliases)
        if witness is not None:
            return witness
    return None


def _credential_private_key_witness(index, path, declaration, witness):
    nodes = [declaration[0], *witness["transfers"]]
    return {
        "schema": "factory.security.private-key-auth-flow.v1",
        "source_role": "embedded_private_key",
        "consumer_role": "django_password_verifier",
        "transfers": [_signing_source_span(index, path, node) for node in nodes],
        "proof_scope": "captured_same_module_static_wiring",
        "runtime_execution": "not_performed",
        "deployment": "UNASSESSED",
        "credential_validity": "NOT_ESTABLISHED",
        "claim": "A captured PEM private-key literal feeds RSA decryption of a POST JSON password field whose plaintext reaches a Django password verifier.",
    }


def _credential_private_key_declaration(finding, tree):
    facts = finding.get("facts", {})
    name = facts.get("name") if isinstance(facts, dict) else None
    candidates = []
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        if (node.lineno, node.col_offset) != (
            finding.get("line"),
            finding.get("column", 0),
        ):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            continue
        value = node.value
        if not isinstance(value, ast.Constant) or type(value.value) is not str:
            continue
        if not _credential_pem_private_key(value.value):
            continue
        if isinstance(name, str) and name != targets[0].id:
            continue
        if _credential_module_rebound(tree, targets[0].id, node):
            continue
        writes = [
            item
            for item in ast.walk(tree)
            if isinstance(item, ast.Name)
            and item.id == targets[0].id
            and isinstance(item.ctx, (ast.Store, ast.Del))
        ]
        if len(writes) == 1:
            candidates.append((node, targets[0].id))
    return candidates[0] if len(candidates) == 1 else None


def _credential_pem_private_key(value):
    import base64
    import binascii
    from cryptography.hazmat.primitives.serialization import load_der_private_key
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

    match = re.fullmatch(
        r"\s*-----BEGIN (?P<label>(?:RSA )?PRIVATE KEY)-----\s+(?P<body>[A-Za-z0-9+/=\s]+)-----END (?P=label)-----\s*",
        value,
    )
    if match is None or len(value) > 65536:
        return False
    try:
        raw = base64.b64decode("".join(match["body"].split()), validate=True)
        return isinstance(load_der_private_key(raw, password=None), RSAPrivateKey)
    except (ValueError, TypeError, binascii.Error):
        return False


def _credential_private_key_decryptor(function, declaration, aliases):
    from .review_audits import _resolved_ast_name

    key_name = declaration[1]
    parameters = [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]
    provider_names = _credential_provider_alias_names(
        aliases,
        ("Crypto.PublicKey.RSA", "Crypto.Cipher.PKCS1_v1_5", "base64.b64decode"),
    )
    bound_names = _credential_scope_bound_names(function)
    if (
        len(parameters) != 1
        or function.args.vararg
        or function.args.kwarg
        or key_name in bound_names
        or provider_names & bound_names
    ):
        return None
    assignments = [
        node
        for node in function.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and isinstance(node.value, ast.Call)
    ]
    imported = [
        (node, target.id)
        for node in assignments
        if len(node.targets if isinstance(node, ast.Assign) else [node.target]) == 1
        and isinstance(
            (
                target := (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )[0]
            ),
            ast.Name,
        )
        and _resolved_ast_name(node.value.func, aliases)
        in {
            "Crypto.PublicKey.RSA.importKey",
            "Crypto.PublicKey.RSA.import_key",
        }
        and len(node.value.args) == 1
        and not node.value.keywords
        and isinstance(node.value.args[0], ast.Name)
        and node.value.args[0].id == key_name
    ]
    if len(imported) != 1:
        return None
    key_call, rsa_key = imported[0]
    cipher_assignment = _credential_named_assignment(
        assignments,
        lambda call: _resolved_ast_name(call.func, aliases)
        == "Crypto.Cipher.PKCS1_v1_5.new"
        and len(call.args) == 1
        and not call.keywords
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == rsa_key,
    )
    if cipher_assignment is None:
        return None
    cipher_call, cipher_name = cipher_assignment
    decrypt = _credential_named_assignment(
        assignments,
        lambda call: isinstance(call.func, ast.Attribute)
        and call.func.attr == "decrypt"
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == cipher_name
        and len(call.args) == 2
        and isinstance(call.args[1], ast.Constant)
        and call.args[1].value is None
        and not call.keywords
        and isinstance(call.args[0], ast.Call)
        and _resolved_ast_name(call.args[0].func, aliases) == "base64.b64decode",
    )
    if decrypt is None or not function.args.args:
        return None
    decrypt_call, plaintext_name = decrypt
    input_call = decrypt_call.args[0]
    if (
        len(input_call.args) != 1
        or input_call.keywords
        or not isinstance(input_call.args[0], ast.Name)
        or input_call.args[0].id != function.args.args[0].arg
        or _credential_name_writes(function, function.args.args[0].arg)
        or any(
            _credential_name_writes(function, local) != 1
            for local in (rsa_key, cipher_name, plaintext_name)
        )
    ):
        return None
    if not (
        _credential_transfer_precedes(key_call, cipher_call)
        and _credential_transfer_precedes(cipher_call, decrypt_call)
    ):
        return None
    returns = [
        node
        for node in _credential_function_nodes(function)
        if isinstance(node, ast.Return)
    ]
    if (
        not returns
        or any(
            not _credential_decoded_return(node.value, plaintext_name)
            or not _credential_transfer_precedes(decrypt_call, node)
            for node in returns
        )
        or not all(
            security_precondition_path_possible(node)
            for node in [key_call, cipher_call, decrypt_call, *returns]
        )
    ):
        return None
    return {
        "function": function.name,
        "transfers": [key_call, cipher_call, decrypt_call, *returns],
    }


def _credential_named_assignment(assignments, accepts):
    matches = []
    for node in assignments:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if (
            len(targets) == 1
            and isinstance(targets[0], ast.Name)
            and accepts(node.value)
        ):
            matches.append((node.value, targets[0].id))
    return matches[0] if len(matches) == 1 else None


def _credential_function_nodes(function):
    nodes, pending = [], list(function.body)
    while pending:
        node = pending.pop()
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        nodes.append(node)
        pending.extend(ast.iter_child_nodes(node))
    return nodes


def _credential_name_writes(scope, name):
    return sum(
        isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, (ast.Store, ast.Del))
        for node in ast.walk(scope)
    )


def _credential_scope_bound_names(scope):
    from .review_audits import _bound_names
    from .review_integrity import _implementation_bound_names

    names = _implementation_bound_names(scope)
    body = getattr(scope, "body", ())
    statements = body if isinstance(body, (list, tuple)) else [scope]
    for statement in statements:
        if isinstance(statement, ast.AST):
            names.update(_bound_names(statement))
    return names


def _credential_module_rebound(tree, name, declaration):
    from .review_audits import _bound_names

    return any(
        name in _bound_names(statement)
        for statement in tree.body
        if statement is not declaration
    )


def _credential_provider_alias_names(aliases, roots):
    return {
        name
        for name, canonical in aliases.items()
        if any(
            canonical == root
            or canonical.startswith(root + ".")
            or root.startswith(canonical + ".")
            for root in roots
        )
    }


def _credential_transfer_precedes(source, use):
    before, after = (
        _credential_control_context(source),
        _credential_control_context(use),
    )
    try_bodies = set()
    child = use
    while (parent := getattr(child, "_security_parent", None)) is not None:
        if isinstance(parent, ast.Try) and child in parent.body:
            try_bodies.add((id(parent), "body", None))
        child = parent
    return (
        (source.lineno, source.col_offset) < (use.lineno, use.col_offset)
        and after[: len(before)] == before
        and all(context in try_bodies for context in after[len(before) :])
        and security_precondition_path_possible(source)
        and security_precondition_path_possible(use)
    )


def _credential_control_context(node):
    context = []
    child = node
    while (parent := getattr(child, "_security_parent", None)) is not None:
        if isinstance(
            parent,
            (
                ast.If,
                ast.For,
                ast.AsyncFor,
                ast.While,
                ast.Try,
                ast.With,
                ast.AsyncWith,
                ast.Match,
            ),
        ):
            for field, value in ast.iter_fields(parent):
                if field not in {"body", "orelse", "finalbody", "handlers", "cases"}:
                    continue
                if isinstance(value, list) and child in value:
                    index = (
                        value.index(child) if field in {"handlers", "cases"} else None
                    )
                    context.append((id(parent), field, index))
                    break
        elif isinstance(parent, ast.ExceptHandler) and child in parent.body:
            context.append((id(parent), "body", None))
        elif isinstance(parent, ast.match_case) and child in parent.body:
            context.append((id(parent), "body", None))
        child = parent
    return tuple(reversed(context))


def _credential_decoded_return(value, plaintext_name):
    return (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and value.func.attr == "decode"
        and isinstance(value.func.value, ast.Name)
        and value.func.value.id == plaintext_name
        and len(value.args) <= 1
        and not value.keywords
        and all(
            isinstance(arg, ast.Constant) and isinstance(arg.value, str)
            for arg in value.args
        )
    )


def _credential_providers_clear(context):
    paths = context["paths"]
    if any(
        name.casefold() in {"crypto.py", "django.py", "json.py", "base64.py"}
        or name.casefold().startswith(("crypto/", "django/", "json/", "base64/"))
        for name in paths
    ):
        return False
    roots = (
        "Crypto.PublicKey.RSA",
        "Crypto.Cipher.PKCS1_v1_5",
        "base64.b64decode",
        "json.loads",
        "django.views.decorators.http",
        "django.contrib.auth.authenticate",
        "django.contrib.auth.hashers.check_password",
    )
    for path, tree in context["index"].snapshots.items():
        aliases = context["aliases"][path]
        provider_names = {
            name
            for name, canonical in aliases.items()
            if any(
                canonical == root
                or canonical.startswith(root + ".")
                or root.startswith(canonical + ".")
                for root in roots
            )
        }
        if any(
            (
                isinstance(node, ast.Name)
                and node.id in provider_names
                and isinstance(node.ctx, (ast.Store, ast.Del))
            )
            or (isinstance(node, ast.arg) and node.arg in provider_names)
            for node in ast.walk(tree)
        ) or _provider_identity_uncertain(
            tree,
            aliases,
            roots=roots,
            nodes=list(ast.walk(tree)),
            selected_paths=True,
        ):
            return False
    return True


def _credential_http_password_consumer(function, decryptors, aliases):
    request_name = _credential_post_request_name(function, aliases)
    parameters = [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]
    if (
        request_name is None
        or function.args.vararg
        or function.args.kwarg
        or {p.arg for p in parameters} & set(decryptors)
    ):
        return None
    provider_names = _credential_provider_alias_names(
        aliases,
        (
            "django.contrib.auth.hashers.check_password",
            "django.contrib.auth.authenticate",
            "json.loads",
        ),
    )
    bound_names = _credential_scope_bound_names(function)
    if set(decryptors) & bound_names or provider_names & bound_names:
        return None
    function_nodes = _credential_function_nodes(function)
    mappings = {
        node.targets[0].id
        for node in function_nodes
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and _credential_json_body_map(node.value, function, aliases, request_name)
        and _credential_json_mapping_unchanged(function, node.targets[0].id)
        and security_precondition_path_possible(node)
    }
    if not mappings:
        return None
    for assignment in function_nodes:
        if not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1:
            continue
        target, value = assignment.targets[0], assignment.value
        if (
            not isinstance(target, ast.Name)
            or not isinstance(value, ast.Call)
            or not isinstance(value.func, ast.Name)
            or value.func.id not in decryptors
            or len(value.args) != 1
            or value.keywords
            or not _credential_request_password_value(
                value.args[0], mappings, function, assignment
            )
            or _credential_name_writes(function, target.id) != 1
            or not security_precondition_path_possible(assignment)
        ):
            continue
        for call in (node for node in function_nodes if isinstance(node, ast.Call)):
            consumer = _credential_password_consumer(call, target.id, aliases)
            if consumer and _credential_transfer_precedes(assignment, call):
                return {
                    "transfers": [
                        *decryptors[value.func.id]["transfers"],
                        assignment.value,
                        call,
                    ]
                }
    return None


def _credential_post_request_name(function, aliases):
    from .review_audits import _resolved_ast_name

    parameters = [*function.args.posonlyargs, *function.args.args]
    if not parameters:
        return None
    for decorator in function.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        canonical = _resolved_ast_name(target, aliases)
        if canonical == "django.views.decorators.http.require_POST":
            if not isinstance(decorator, ast.Call) or (
                not decorator.args and not decorator.keywords
            ):
                return parameters[0].arg
        if (
            canonical == "django.views.decorators.http.require_http_methods"
            and isinstance(decorator, ast.Call)
            and len(decorator.args) == 1
            and not decorator.keywords
            and isinstance(decorator.args[0], (ast.List, ast.Tuple))
            and any(
                isinstance(item, ast.Constant) and item.value == "POST"
                for item in decorator.args[0].elts
            )
        ):
            return parameters[0].arg
    return None


def _credential_json_body_map(node, function, aliases, request_name):
    from .review_audits import _resolved_ast_name

    if (
        not isinstance(node, ast.Call)
        or _resolved_ast_name(node.func, aliases) != "json.loads"
        or len(node.args) != 1
        or node.keywords
    ):
        return False
    value = node.args[0]
    if isinstance(value, ast.Name):
        assignments = [
            item
            for item in _credential_function_nodes(function)
            if isinstance(item, ast.Assign)
            and len(item.targets) == 1
            and isinstance(item.targets[0], ast.Name)
            and item.targets[0].id == value.id
        ]
        if (
            len(assignments) != 1
            or _credential_name_writes(function, value.id) != 1
            or not _credential_transfer_precedes(assignments[0], node)
        ):
            return False
        value = assignments[0].value
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute):
        if (
            value.func.attr != "decode"
            or value.args
            and not all(
                isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                for arg in value.args
            )
            or value.keywords
        ):
            return False
        value = value.func.value
    if not isinstance(value, ast.Attribute) or value.attr != "body":
        return False
    return (
        isinstance(value.value, ast.Name)
        and value.value.id == request_name
        and _django_http_body_payload(value, function, aliases)
    )


def _credential_json_mapping_unchanged(function, name):
    parents = {
        id(child): parent
        for parent in ast.walk(function)
        for child in ast.iter_child_nodes(parent)
    }
    if _credential_name_writes(function, name) != 1:
        return False
    for node in _credential_function_nodes(function):
        if (
            not isinstance(node, ast.Name)
            or node.id != name
            or not isinstance(node.ctx, ast.Load)
        ):
            continue
        attribute = parents.get(id(node))
        call = (
            parents.get(id(attribute)) if isinstance(attribute, ast.Attribute) else None
        )
        if (
            not isinstance(attribute, ast.Attribute)
            or attribute.value is not node
            or attribute.attr != "get"
            or not isinstance(call, ast.Call)
            or call.func is not attribute
            or len(call.args) != 1
            or call.keywords
            or not isinstance(call.args[0], ast.Constant)
            or not isinstance(call.args[0].value, str)
        ):
            return False
    return True


def _credential_request_password_value(node, mappings, function, use):
    if isinstance(node, ast.Name):
        assignments = [
            item
            for item in _credential_function_nodes(function)
            if isinstance(item, ast.Assign)
            and len(item.targets) == 1
            and isinstance(item.targets[0], ast.Name)
            and item.targets[0].id == node.id
        ]
        return (
            len(assignments) == 1
            and _credential_name_writes(function, node.id) == 1
            and _credential_transfer_precedes(assignments[0], use)
            and _credential_request_password_value(
                assignments[0].value, mappings, function, assignments[0]
            )
        )
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return False
    mapping_assignments = (
        [
            item
            for item in _credential_function_nodes(function)
            if isinstance(item, ast.Assign)
            and len(item.targets) == 1
            and isinstance(item.targets[0], ast.Name)
            and item.targets[0].id == node.func.value.id
        ]
        if isinstance(node.func.value, ast.Name)
        else []
    )
    return (
        node.func.attr == "get"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in mappings
        and len(mapping_assignments) == 1
        and _credential_transfer_precedes(mapping_assignments[0], use)
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
        and "password" in node.args[0].value.casefold()
    )


def _credential_password_consumer(call, plaintext_name, aliases):
    from .review_audits import _resolved_ast_name

    name = _resolved_ast_name(call.func, aliases)
    if any(isinstance(arg, ast.Starred) for arg in call.args) or any(
        k.arg is None for k in call.keywords
    ):
        return False
    names = [k.arg for k in call.keywords]
    if len(names) != len(set(names)):
        return False
    if name == "django.contrib.auth.hashers.check_password":
        return (
            len(call.args) in {2, 3}
            and not call.keywords
            and isinstance(call.args[0], ast.Name)
            and call.args[0].id == plaintext_name
        )
    if name == "django.contrib.auth.authenticate":
        passwords = [item.value for item in call.keywords if item.arg == "password"]
        return (
            len(call.args) <= 1
            and len(passwords) == 1
            and isinstance(passwords[0], ast.Name)
            and passwords[0].id == plaintext_name
        )
    return False


def _signing_configuration_witness(index, path, declaration, witness):
    return {
        "schema": "factory.security.signing-configuration.v1",
        "source_role": "published_literal_default",
        "consumer_role": witness["framework"] + ".SECRET_KEY",
        "declaration": _signing_source_span(index, path, declaration),
        "transfers": witness["transfers"],
        "proof_scope": "captured_default_configuration_load",
        "deployment": "UNASSESSED",
        "runtime_execution": "not_performed",
        "configuration_overrides": "POSSIBLE; default load is the observed risk",
        "claim": "A published literal is wired as a framework signing-key default in captured application initialization.",
    }


def _signing_literal_declaration(finding, tree):
    declarations = [
        node
        for node in tree.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
        and any(
            isinstance(target, ast.Name) and target.id == "SECRET_KEY"
            for target in (
                node.targets if isinstance(node, ast.Assign) else [node.target]
            )
        )
    ]
    writes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id == "SECRET_KEY"
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    if len(declarations) != 1 or len(writes) != 1:
        return None
    declaration = declarations[0]
    if (declaration.lineno, declaration.col_offset) != (
        finding.get("line"),
        finding.get("column", 0),
    ):
        return None
    if _signing_rejection_or_reflection(tree):
        return None
    return declaration


def _signing_source_span(index, path, node):
    return {
        "path": index.relative(path),
        "sha256": index.inventory[path],
        "span": [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset],
    }


def _signing_imported_key_written(target, context):
    from .review_audits import _resolved_ast_name

    names = {
        name[:-3].replace("/", ".")
        for name, path in context["paths"].items()
        if path == target and name.endswith(".py")
    }
    suffix = target.with_suffix("").as_posix().split("/")
    names.update(".".join(suffix[-length:]) for length in range(1, len(suffix) + 1))
    for path, tree in context["index"].snapshots.items():
        aliases = context["aliases"][path]
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and node.attr == "SECRET_KEY"
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and _resolved_ast_name(node.value, aliases) in names
            ):
                return True
    return False


def _signing_provider_clear(tree, aliases, framework):
    from .review_audits import _resolved_ast_name

    nodes = list(ast.walk(tree))
    if any(
        isinstance(node, (ast.Name, ast.Attribute))
        and _resolved_ast_name(node, aliases).startswith(("sys.modules", "importlib."))
        for node in nodes
    ):
        return False
    roots = (
        (
            "django.core.wsgi.get_wsgi_application",
            "django.core.asgi.get_asgi_application",
            "os.environ",
        )
        if framework == "django"
        else ("flask.Flask",)
    )
    return not _provider_identity_uncertain(
        tree, aliases, roots=roots, nodes=nodes, selected_paths=True
    )


def _signing_bound_providers_clear(context, declaration_path, consumer_path, framework):
    index = context["index"]
    paths = {declaration_path, consumer_path}
    for selected in (declaration_path, consumer_path):
        parent = selected.parent
        while parent != Path("."):
            initializer = parent / "__init__.py"
            if initializer in index.snapshots:
                paths.add(initializer)
            parent = parent.parent
    return all(
        index.validate(path)
        and not _signing_rejection_or_reflection(index.snapshots[path])
        and _signing_provider_clear(
            index.snapshots[path], context["aliases"][path], framework
        )
        for path in paths
    )


def _signing_rejection_or_reflection(tree):
    """Unknown namespace replacement or a captured rejection guard must abstain."""
    nodes = list(ast.walk(tree))
    has_key = any(
        (isinstance(node, ast.Name) and node.id == "SECRET_KEY")
        or (isinstance(node, ast.Constant) and node.value == "SECRET_KEY")
        for node in nodes
    )
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id
        in {"globals", "locals", "vars", "exec", "eval", "setattr", "__import__"}
        or has_key
        and isinstance(node, ast.Raise)
        for node in nodes
    )


def _signing_resolve_module(context, literal):
    if not isinstance(literal, ast.Constant) or not isinstance(literal.value, str):
        return None
    parts = literal.value.split(".")
    if not parts or not all(part.isidentifier() for part in parts):
        return None
    paths = context["paths"]
    choices = {
        paths[name]
        for name in ("/".join(parts) + ".py", "/".join(parts) + "/__init__.py")
        if name in paths
    }
    if len(choices) == 1 and None not in choices:
        return next(iter(choices))
    suffix = "/".join(parts) + ".py"
    index = context["index"]
    choices = {
        path
        for path in index.snapshots
        if path.as_posix().endswith("/" + suffix)
        and _signing_regular_package(index, path, len(parts) - 1)
    }
    return next(iter(choices)) if len(choices) == 1 else None


def _signing_regular_package(index, path, package_depth):
    parent = path.parent
    for _step in range(package_depth):
        if not index.validate(parent / "__init__.py"):
            return False
        parent = parent.parent
    return True


def _django_signing_consumer(target, path, tree, context):
    from .review_integrity import security_call_name

    if not _signing_framework_external(context, "django"):
        return None
    aliases = context["aliases"][path]
    if _signing_environment_written(tree, aliases):
        return None
    selected = None
    for statement in tree.body:
        if not isinstance(statement, (ast.Expr, ast.Assign)):
            continue
        call = statement.value
        if not isinstance(call, ast.Call) or not security_precondition_path_possible(
            call
        ):
            continue
        name = security_call_name(call, aliases)
        if (
            name == "os.environ.setdefault"
            and len(call.args) == 2
            and not call.keywords
        ):
            if (
                isinstance(call.args[0], ast.Constant)
                and call.args[0].value == "DJANGO_SETTINGS_MODULE"
            ):
                selected = (
                    call
                    if _signing_resolve_module(context, call.args[1]) == target
                    else None
                )
        elif name in {
            "django.core.wsgi.get_wsgi_application",
            "django.core.asgi.get_asgi_application",
        }:
            if selected is not None and not call.args and not call.keywords:
                return {
                    "framework": "django",
                    "transfers": [
                        _signing_source_span(context["index"], path, selected),
                        _signing_source_span(context["index"], path, call),
                    ],
                }
    return None


def _signing_framework_external(context, framework):
    return not any(
        name == framework + ".py" or name.startswith(framework + "/")
        for name in context["paths"]
    )


def _signing_environment_written(tree, aliases):
    from .review_audits import _resolved_ast_name

    return any(
        isinstance(node, ast.Subscript)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and _resolved_ast_name(node.value, aliases) == "os.environ"
        and (
            not isinstance(node.slice, ast.Constant)
            or node.slice.value == "DJANGO_SETTINGS_MODULE"
        )
        for node in ast.walk(tree)
    )


def _flask_config_mutated(scope, receiver, protected_keys=None):
    from .review_audits import _name

    protected_keys = {"SECRET_KEY"} if protected_keys is None else protected_keys
    writes = [
        node
        for node in ast.walk(scope)
        if isinstance(node, ast.Name)
        and node.id == receiver
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    if len(writes) > 1:
        return True
    for node in ast.walk(scope):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and _name(node.value) in {
            receiver,
            receiver + ".config",
        }:
            return True
        if not isinstance(getattr(node, "ctx", None), (ast.Store, ast.Del)):
            continue
        if _name(node) in {receiver + ".config", receiver + ".secret_key"} or _name(
            node
        ).startswith(receiver + ".config."):
            return True
        if (
            isinstance(node, ast.Subscript)
            and _name(node.value) == receiver + ".config"
        ):
            if (
                not isinstance(node.slice, ast.Constant)
                or node.slice.value in protected_keys
            ):
                return True
    return False


def _flask_configuration_reloaded(
    scope, receiver, target, context, protected_keys=None, consumer_path=None
):
    from .review_audits import _name

    protected_keys = {"SECRET_KEY"} if protected_keys is None else protected_keys
    for statement in scope.body:
        call = getattr(statement, "value", None)
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
            continue
        if _name(call.func.value) != receiver + ".config":
            continue
        if call.func.attr == "from_object" and not _flask_config_load(
            call, receiver, target, context, consumer_path
        ):
            return True
        if call.func.attr in {
            "update",
            "from_mapping",
        } and _flask_mapping_may_replace_key(call, protected_keys):
            return True
    return False


def _flask_mapping_may_replace_key(call, protected_keys=None):
    protected_keys = {"SECRET_KEY"} if protected_keys is None else protected_keys
    if any(kw.arg is None or kw.arg in protected_keys for kw in call.keywords):
        return True
    for arg in call.args:
        if not isinstance(arg, ast.Dict):
            return True
        if any(
            not isinstance(key, ast.Constant) or key.value in protected_keys
            for key in arg.keys
        ):
            return True
    return False


def _signing_helper_receiver(helper, call, receiver):
    import inspect

    if (
        helper is None
        or helper.decorator_list
        or helper.args.vararg
        or helper.args.kwarg
    ):
        return None
    if any(isinstance(arg, ast.Starred) for arg in call.args):
        return None
    keywords = {kw.arg: kw.value for kw in call.keywords}
    if None in keywords or len(keywords) != len(call.keywords):
        return None
    args = helper.args
    positional = [*args.posonlyargs, *args.args]
    defaults = (
        dict(zip([arg.arg for arg in positional[-len(args.defaults) :]], args.defaults))
        if args.defaults
        else {}
    )
    defaults.update(
        {
            arg.arg: value
            for arg, value in zip(args.kwonlyargs, args.kw_defaults)
            if value is not None
        }
    )
    parameters = [
        inspect.Parameter(
            arg.arg,
            inspect.Parameter.POSITIONAL_ONLY
            if arg in args.posonlyargs
            else inspect.Parameter.KEYWORD_ONLY
            if arg in args.kwonlyargs
            else inspect.Parameter.POSITIONAL_OR_KEYWORD,
            default=defaults.get(arg.arg, inspect.Parameter.empty),
        )
        for arg in [*positional, *args.kwonlyargs]
    ]
    try:
        bound = inspect.Signature(parameters).bind(*call.args, **keywords)
    except (TypeError, ValueError):
        return None
    if not positional:
        return None
    actual = bound.arguments.get(positional[0].arg)
    if not isinstance(actual, ast.Name) or actual.id != receiver:
        return None
    return positional[0].arg


def _flask_config_load(call, receiver, target, context, consumer_path=None):
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "from_object"
        and isinstance(call.func.value, ast.Attribute)
        and call.func.value.attr == "config"
        and isinstance(call.func.value.value, ast.Name)
        and call.func.value.value.id == receiver
        and len(call.args) == 1
        and not call.keywords
        and _flask_config_module_matches(context, call.args[0], target, consumer_path)
    )


def _flask_signing_consumer(target, path, tree, context):
    if not _signing_framework_external(context, "flask"):
        return None
    for scope in [
        tree,
        *[
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and not node.decorator_list
        ],
    ]:
        witness = _flask_scope_signing_consumer(target, path, scope, context)
        if witness is not None:
            return witness
    return None


def _flask_bind_created_app(statement, receivers, aliases):
    from .review_integrity import security_call_name

    if not isinstance(statement, ast.Assign):
        return
    for target in statement.targets:
        if isinstance(target, ast.Name):
            receivers.pop(target.id, None)
            if (
                isinstance(statement.value, ast.Call)
                and security_call_name(statement.value, aliases) == "flask.Flask"
                and _flask_constructor_arguments(statement.value)
            ):
                receivers[target.id] = statement.value


def _flask_constructor_arguments(call):
    import inspect

    if any(isinstance(arg, ast.Starred) for arg in call.args):
        return False
    keywords = {kw.arg: kw.value for kw in call.keywords}
    if None in keywords or len(keywords) != len(call.keywords):
        return False
    names = (
        "import_name",
        "static_url_path",
        "static_folder",
        "static_host",
        "host_matching",
        "subdomain_matching",
        "template_folder",
        "instance_path",
        "instance_relative_config",
        "root_path",
    )
    params = [
        inspect.Parameter(
            name,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            default=inspect.Parameter.empty if position == 0 else None,
        )
        for position, name in enumerate(names)
    ]
    try:
        actual = (
            inspect.Signature(params)
            .bind(*call.args, **keywords)
            .arguments["import_name"]
        )
    except (TypeError, ValueError):
        return False
    return (
        isinstance(actual, ast.Name)
        and actual.id == "__name__"
        or isinstance(actual, ast.Constant)
        and isinstance(actual.value, str)
        and bool(actual.value)
    )


def _flask_scope_signing_consumer(target, path, scope, context):
    receivers = {}
    for statement in scope.body:
        _flask_bind_created_app(statement, receivers, context["aliases"][path])
        if not isinstance(statement, (ast.Expr, ast.Assign)) or not isinstance(
            statement.value, ast.Call
        ):
            continue
        call = statement.value
        if not security_precondition_path_possible(call):
            continue
        for receiver, creation in receivers.items():
            if _flask_config_mutated(scope, receiver) or _flask_configuration_reloaded(
                scope, receiver, target, context, consumer_path=path
            ):
                continue
            calls = _flask_configuration_calls(
                call, receiver, target, context, consumer_path=path
            )
            if calls:
                return {
                    "framework": "flask",
                    "transfers": [
                        _signing_source_span(context["index"], path, node)
                        for node in [creation, *calls]
                    ],
                }
    return None


def _flask_configuration_calls(
    call, receiver, target, context, *, protected_keys=None, consumer_path=None
):
    from .review_integrity import _security_local_helper_definition

    if _flask_config_load(call, receiver, target, context, consumer_path):
        return [call]
    helper = _security_local_helper_definition(call)
    formal = _signing_helper_receiver(helper, call, receiver)
    if (
        formal is None
        or _flask_config_mutated(helper, formal, protected_keys)
        or _flask_configuration_reloaded(
            helper, formal, target, context, protected_keys, consumer_path
        )
    ):
        return []
    if any(
        isinstance(node, ast.Name)
        and node.id == formal
        and isinstance(node.ctx, (ast.Store, ast.Del))
        for node in ast.walk(helper)
    ):
        return []
    for statement in helper.body:
        load = getattr(statement, "value", None)
        if (
            isinstance(load, ast.Call)
            and _flask_config_load(load, formal, target, context, consumer_path)
            and security_precondition_path_possible(load)
        ):
            return [call, load]
    return []


def supported_security_precondition(node, source_role, consumer_role):
    """Describe a native producer's local premise, never runtime exploitability."""
    return {
        "schema": "factory.security.precondition.v1",
        "status": "SUPPORTED",
        "source_role": source_role,
        "consumer_role": consumer_role,
        "sink_span": [
            node.lineno,
            node.col_offset,
            node.end_lineno,
            node.end_col_offset,
        ],
        "proof_scope": "local_static_wiring",
        "runtime_execution": "not_performed",
        "deployment": "UNASSESSED",
    }


def http_request_payload(node, aliases, scope, flow_statement, alias_reader):
    """Recognize body bytes or selected values, never arbitrary mapping methods."""
    if isinstance(node, ast.Subscript):
        return _http_request_subscript_payload(
            node, aliases, scope, flow_statement, alias_reader
        )
    if isinstance(node, ast.Call):
        return _http_request_call_payload(
            node, aliases, scope, flow_statement, alias_reader
        )
    if not isinstance(node, ast.Attribute) or not isinstance(node.ctx, ast.Load):
        return False
    return _http_request_attribute_payload(
        node, aliases, scope, flow_statement, alias_reader
    )


def _http_request_subscript_payload(node, aliases, scope, flow_statement, alias_reader):
    return (
        isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
        and _http_request_mapping(
            node.value,
            aliases,
            scope,
            flow_statement,
            alias_reader,
            node.slice.value,
        )
    )


def _http_request_call_payload(node, aliases, scope, flow_statement, alias_reader):
    if _flask_request_body_kind(node, aliases, scope, flow_statement, alias_reader):
        return True
    parts = _credential_get_source_key(node)
    return bool(
        parts is not None
        and isinstance(parts[1], ast.Constant)
        and isinstance(parts[1].value, str)
        and _http_request_mapping(
            parts[0], aliases, scope, flow_statement, alias_reader, parts[1].value
        )
    )


def _http_request_attribute_payload(node, aliases, scope, flow_statement, alias_reader):
    from .review_audits import _name

    resolved = alias_reader(scope, aliases, flow_statement)
    raw = _name(node)
    head, _, tail = raw.partition(".")
    canonical = resolved.get(head, "") + ("." + tail if tail else "")
    if canonical == "flask.request.data":
        return True
    return _django_http_body_payload(node, scope, resolved)


_FLASK_BODY_SIGNATURE = ast.parse(
    "def get_data(cache=True, as_text=False, parse_form_data=False): pass"
).body[0]


def _flask_request_body_kind(node, aliases, scope, statement, alias_reader):
    """Model only a source-bound body reader with exact boolean call options."""
    from . import _source_binding_helpers
    from .review_audits import _name

    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return None
    if node.func.attr != "get_data":
        return None
    resolved = alias_reader(
        scope or getattr(node, "_security_lexical_scope", None),
        aliases,
        statement or getattr(node, "_security_flow_statement", None),
    )
    head, _, tail = _name(node.func).partition(".")
    if (
        resolved.get(head, "") + ("." + tail if tail else "")
        != "flask.request.get_data"
    ):
        return None
    try:
        options = _source_binding_helpers()[1](node, _FLASK_BODY_SIGNATURE)
    except (TypeError, ValueError):
        return None
    if not all(
        isinstance(value, ast.Constant) and type(value.value) is bool
        for value in options.values()
    ):
        return None
    return "text" if options["as_text"].value else "bytes"


def request_payload_value_kind(node, requests, aliases, alias_reader):
    """Carry modeled request text/bytes through explicit codec operations only."""
    kind = _request_payload_name_kind(node, requests)
    if kind is not None:
        return kind
    kind = _request_payload_codec_kind(node, requests, aliases, alias_reader)
    if kind is not None:
        return kind
    return _request_payload_source_kind(node, aliases, alias_reader)


def _request_payload_name_kind(node, requests):
    if isinstance(node, ast.Name):
        for kind in ("bytes", "text"):
            if ("request-type:" + kind, node.id) in requests:
                return kind
    return None


def _request_payload_codec_kind(node, requests, aliases, alias_reader):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        codec = node.func.attr
        if codec in {"encode", "decode"} and not node.args and not node.keywords:
            original = request_payload_value_kind(
                node.func.value, requests, aliases, alias_reader
            )
            if original == ("text" if codec == "encode" else "bytes"):
                return "bytes" if codec == "encode" else "text"
    return None


def _request_payload_source_kind(node, aliases, alias_reader):
    body_kind = _flask_request_body_kind(node, aliases, None, None, alias_reader)
    if body_kind:
        return body_kind
    if http_request_payload(
        node,
        aliases,
        getattr(node, "_security_lexical_scope", None),
        getattr(node, "_security_flow_statement", None),
        alias_reader,
    ):
        return "bytes" if isinstance(node, ast.Attribute) else "text"
    return None


def _http_request_mapping(node, aliases, scope, flow_statement, alias_reader, key):
    from .review_audits import _name

    if isinstance(node, ast.Call):
        if node.args or node.keywords:
            return False
        raw = _name(node.func)
    elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
        raw = _name(node)
    else:
        return False
    scope = scope or getattr(node, "_security_lexical_scope", None)
    flow_statement = flow_statement or getattr(node, "_security_flow_statement", None)
    resolved = alias_reader(scope, aliases, flow_statement)
    head, _, tail = raw.partition(".")
    canonical = resolved.get(head, "") + ("." + tail if tail else "")
    if isinstance(node, ast.Call):
        return (
            canonical == "flask.request.get_json"
            and _request_mapping_value_unchanged(node, scope, key)
        )
    recognized = canonical in {
        "flask.request.args",
        "flask.request.form",
        "flask.request.json",
    } or _django_http_body_payload(node, scope, resolved, {"GET", "POST"})
    return recognized and _request_mapping_value_unchanged(node, scope, key)


def _request_mapping_aliases(node, nodes):
    origin, aliases = ast.dump(node, include_attributes=False), set()

    def references(value):
        return (
            isinstance(value, (ast.Attribute, ast.Call))
            and ast.dump(value, include_attributes=False) == origin
            or isinstance(value, ast.Name)
            and value.id in aliases
        )

    for _ in range(len(nodes)):
        before = len(aliases)
        for item in nodes:
            if isinstance(item, (ast.Assign, ast.AnnAssign)) and references(item.value):
                targets = (
                    item.targets if isinstance(item, ast.Assign) else [item.target]
                )
                aliases.update(t.id for t in targets if isinstance(t, ast.Name))
        if len(aliases) == before:
            return references
    return references


def _request_mapping_value_unchanged(node, scope, key):
    if scope is None:
        return False
    nodes = list(ast.walk(scope))
    references = _request_mapping_aliases(node, nodes)
    return not any(_request_mapping_mutation(item, references, key) for item in nodes)


def _request_mapping_mutation(item, references, key):
    if (
        isinstance(item, ast.Subscript)
        and isinstance(item.ctx, (ast.Store, ast.Del))
        and references(item.value)
    ):
        return not (
            isinstance(item.slice, ast.Constant)
            and isinstance(item.slice.value, str)
            and item.slice.value != key
        )
    if (
        isinstance(item, ast.Attribute)
        and isinstance(item.ctx, (ast.Store, ast.Del))
        and references(item.value)
    ):
        return True
    if isinstance(item, ast.Call):
        if isinstance(item.func, ast.Attribute) and references(item.func.value):
            return _credential_get_source_key(item) is None
        return any(
            references(value)
            for value in [*item.args, *(kw.value for kw in item.keywords)]
        )
    return isinstance(item, (ast.Return, ast.Yield)) and references(item.value)


def _django_http_body_payload(node, scope, resolved, attributes=frozenset({"body"})):
    from .review_audits import _name

    if node.attr not in attributes or not isinstance(node.value, ast.Name):
        return False
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    args = [*scope.args.posonlyargs, *scope.args.args]
    if not args or node.value.id != args[0].arg:
        return False
    if any(
        isinstance(item, ast.Name)
        and item.id == node.value.id
        and isinstance(item.ctx, (ast.Store, ast.Del))
        for item in ast.walk(scope)
    ):
        return False
    inventory = list(ast.walk(scope))
    if any(
        isinstance(item, ast.Attribute)
        and item.attr == node.attr
        and isinstance(item.ctx, (ast.Store, ast.Del))
        for item in inventory
    ):
        return False
    parents = {
        id(child): parent
        for parent in inventory
        for child in ast.iter_child_nodes(parent)
    }
    if any(
        isinstance(item, ast.Name)
        and item.id == node.value.id
        and isinstance(item.ctx, ast.Load)
        and not (
            isinstance(parents.get(id(item)), ast.Attribute)
            and parents[id(item)].value is item
            and isinstance(parents[id(item)].ctx, ast.Load)
            and not parents[id(item)].attr.startswith("__")
        )
        for item in inventory
    ):
        return False
    for decorator in scope.decorator_list:
        expression = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = _name(expression)
        root, _, suffix = name.partition(".")
        bound = resolved.get(root, "") + ("." + suffix if suffix else "")
        if bound in {
            "django.views.decorators.http.require_http_methods",
            "django.views.decorators.http.require_POST",
            "django.views.decorators.http.require_GET",
            "django.views.decorators.http.require_safe",
        }:
            return True
    return False


def security_precondition_providers_stable(tree, aliases, nodes):
    """Keep request payload values distinct from provider-object escapes."""
    from .review_integrity import _security_scope_request_aliases
    from .review_audits import _resolved_ast_name

    if any(
        isinstance(node, (ast.Name, ast.Attribute))
        and (
            _resolved_ast_name(node, aliases).startswith(("sys.modules", "importlib."))
            or (isinstance(node, ast.Name) and node.id == "__builtins__")
        )
        for node in nodes
    ):
        return False

    payloads = [
        node
        for node in nodes
        if isinstance(node, (ast.Attribute, ast.Call, ast.Subscript))
        and http_request_payload(
            node,
            aliases,
            getattr(node, "_security_lexical_scope", None),
            getattr(node, "_security_flow_statement", None),
            _security_scope_request_aliases,
        )
    ]
    payload_ids = {id(node) for node in payloads}
    payload_children = {id(child) for node in payloads for child in ast.walk(node)}
    loader_children = {
        id(child)
        for node in nodes
        if isinstance(node, ast.keyword)
        and node.arg == "Loader"
        and _resolved_ast_name(node.value, aliases)
        in {"yaml.Loader", "yaml.UnsafeLoader", "yaml.CLoader", "yaml.CUnsafeLoader"}
        for child in ast.walk(node.value)
    }
    inventory = [
        node
        for node in nodes
        if id(node) not in payload_children | loader_children
        and not (
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and id(node.value) in payload_ids
        )
    ]
    parents = {
        id(child): node for node in nodes for child in ast.iter_child_nodes(node)
    }
    return not _provider_identity_uncertain(
        tree,
        aliases,
        roots=(
            "os",
            "subprocess",
            "pickle",
            "_pickle",
            "dill",
            "yaml",
            "builtins",
            "flask",
            "django",
        ),
        nodes=inventory,
        parents=parents,
    )


def log_security_provider_stable(tree, aliases, nodes):
    """Check logging provider identity against the captured source mutation inventory."""
    return not _provider_identity_uncertain(
        tree, aliases, roots=("logging",), nodes=nodes
    )


def log_percent_slots(message):
    """Read actual percent-format conversion slots, excluding escaped percent signs."""
    import re

    return [
        code
        for code in re.findall(
            r"%(?:\([^)]*\))?[-+#0 ]*(?:\d+|\*)?(?:\.\d+|\.\*)?([a-zA-Z%])",
            message,
        )
        if code != "%"
    ]


def log_security_precondition(module, call):
    """Return a log-input premise only for a stable provider and a possible sink path."""
    if getattr(
        module, "_security_log_provider_stable", False
    ) and security_precondition_path_possible(call):
        return {
            "security_precondition": supported_security_precondition(
                call, "untrusted_input", "log_message"
            )
        }
    return {}


def security_precondition_call_shape(node, canonical):
    """Restrict support to modeled, unambiguous dangerous argument slots."""
    if len(node.args) != 1 or isinstance(node.args[0], ast.Starred):
        return False
    keyword_values = {item.arg: item.value for item in node.keywords}
    if None in keyword_values or len(keyword_values) != len(node.keywords):
        return False
    if canonical in _POSITIONAL_SECURITY_CALLS:
        return not keyword_values
    if canonical in _SHELL_SECURITY_CALLS:
        return _security_shell_call_shape(keyword_values)
    if canonical == "yaml.load" and set(keyword_values) == {"Loader"}:
        return _security_yaml_loader_call_shape(node, keyword_values)
    return False


_POSITIONAL_SECURITY_CALLS = {
    "eval",
    "exec",
    "builtins.eval",
    "builtins.exec",
    "os.system",
    "pickle.loads",
    "_pickle.loads",
    "dill.loads",
    "yaml.unsafe_load",
}
_SHELL_SECURITY_CALLS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
}


def _security_shell_call_shape(keyword_values):
    return (
        set(keyword_values) == {"shell"}
        and isinstance(keyword_values["shell"], ast.Constant)
        and keyword_values["shell"].value is True
    )


def _security_yaml_loader_call_shape(node, keyword_values):
    from .review_audits import _name, _security_aliases
    from .review_integrity import _security_flow_bindings, _security_module_scope

    scope = getattr(node, "_security_lexical_scope", None) or getattr(
        node, "_oracle_scope", None
    )
    module = _security_module_scope(scope)
    aliases = _security_aliases(module.body) if isinstance(module, ast.Module) else {}
    resolved, _constants = _security_flow_bindings(node, aliases)
    raw = _name(keyword_values["Loader"])
    head, _, tail = raw.partition(".")
    return resolved.get(head, "") + ("." + tail if tail else "") in {
        "yaml.Loader",
        "yaml.UnsafeLoader",
        "yaml.CLoader",
        "yaml.CUnsafeLoader",
    }


def security_precondition_path_possible(node):
    """Reject syntactically dead or unmodeled short-circuit sink positions."""
    child = node
    while (parent := getattr(child, "_security_parent", None)) is not None:
        if not _security_control_branch_possible(parent, child):
            return False
        if not _security_no_prior_terminator(parent, child):
            return False
        child = parent
    return True


def _security_control_branch_possible(parent, child):
    if isinstance(parent, (ast.If, ast.While, ast.IfExp)):
        test = parent.test
        if isinstance(test, ast.Constant):
            body = parent.body
            in_body = child in body if isinstance(body, list) else child is body
            other = getattr(parent, "orelse", [])
            in_other = child in other if isinstance(other, list) else child is other
            if (in_body and not bool(test.value)) or (in_other and bool(test.value)):
                return False
    return not (isinstance(parent, ast.BoolOp) and child is not parent.values[0])


def _security_no_prior_terminator(parent, child):
    for _field, value in ast.iter_fields(parent):
        if isinstance(value, list) and child in value:
            previous = value[: value.index(child)]
            if any(
                isinstance(item, (ast.Return, ast.Raise, ast.Break, ast.Continue))
                for item in previous
            ):
                return False
    return True


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
        security_precondition=supported_security_precondition(
            test, "untrusted_request", "password_comparison"
        ),
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
