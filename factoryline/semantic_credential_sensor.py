"""Model request-source identity and literal credentials at canonical security sinks."""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Any
import re
from urllib.parse import urlsplit
from .credential_endpoint_admission import (
    HTTP_CLIENT_METHODS as _HTTP_CALLS,
    SECURITY_EFFECT_CONTRACTS as SECURITY_EFFECT_CONTRACTS,
    SECURITY_EFFECT_WITNESS_SCHEMA as SECURITY_EFFECT_WITNESS_SCHEMA,
)

_AUTH_CALLS = frozenset({"requests.auth.HTTPBasicAuth", "httpx.BasicAuth"})
_AUTH_HEADER = re.compile(r"(?i)^\s*(?:bearer|basic)\s+(.+?)\s*$")
_AUTH_TEMPLATE = re.compile(r"(?:^\$\{[^}]+\}$|^<[^>]+>$|^your[-_]$|\{[^{}]+\})", re.I)

_SECURITY_EFFECT_WITNESS_SCHEMA_BASELINE = SECURITY_EFFECT_WITNESS_SCHEMA
_SECURITY_EFFECT_CONTRACTS_BASELINE = SECURITY_EFFECT_CONTRACTS


def _security_statement_operand_flow(statement, scope, flow):
    if not isinstance(statement, (ast.Expr, ast.Return)) or not isinstance(
        statement.value, ast.Call
    ):
        return flow
    calls = getattr(scope, "_security_calls_by_statement", {}).get(id(statement))
    if calls != [statement.value] or not _security_call_operand_evaluation_inert(
        statement.value
    ):
        return flow
    return (flow[0].copy(), *flow[1:])


def _security_call_operand_evaluation_inert(call):
    if any(keyword.arg is None for keyword in call.keywords):
        return False
    allowed = (ast.Name, ast.Constant, ast.List, ast.Tuple, ast.Load)
    operands = (*call.args, *(keyword.value for keyword in call.keywords))
    return all(
        isinstance(node, allowed) for operand in operands for node in ast.walk(operand)
    )


def _literal_credential(node, *, auth_slot=False):
    from .review_audits import _PLACEHOLDER_SECRET

    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return False
    value = node.value.strip()
    if not value:
        return False
    return not (
        _AUTH_TEMPLATE.search(value) if auth_slot else _PLACEHOLDER_SECRET.match(value)
    )


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
    return candidate if _literal_credential(candidate, auth_slot=True) else None


def _authorization_credential(call, name):
    from .security_configuration import _keyword

    headers = _keyword(call, "headers")
    if not name or not isinstance(headers, ast.Dict):
        return None
    value = _authorization_header_value(headers)
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
        return None
    match = _AUTH_HEADER.match(value.value)
    if match and _literal_credential(ast.Constant(match.group(1)), auth_slot=True):
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
    mutations=None,
    argument_predicate=None,
    inventory_projector=None,
    inventory_dependencies=(),
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
    if mutations is None:
        mutations = finite_provider_mutation_index(
            nodes,
            aliases,
            audit,
            parents,
            argument_predicate=argument_predicate,
            inventory_projector=inventory_projector,
            inventory_dependencies=inventory_dependencies,
        )
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
        or selected.startswith(effective + ".")
        or attribute == "*"
        and selected.startswith(path + ".")
    )


def yaml_loader_argument_consumer(node, aliases, parents):
    """Identify exact, modeled YAML consumer value slots for provider indexing."""
    from .security_configuration import _canonical, _expanded
    from .review_integrity import bind_security_call_scopes

    call, child = _yaml_consumer_call(node, parents)
    if call is None or _expanded(call):
        return None
    if not _yaml_consumer_slot_present(call, child):
        return None
    module = _yaml_consumer_module(call, parents)
    if module is None:
        return None
    if not hasattr(module, "_security_scope_kind"):
        bind_security_call_scopes(module)
    return _yaml_consumer_binding(call, child, aliases, _canonical)


def _yaml_consumer_call(node, parents):
    child = node
    parent = parents.get(id(child))
    while parent is not None and not isinstance(parent, ast.Call):
        if isinstance(parent, ast.keyword):
            child = parent.value
            parent = parents.get(id(parent))
            continue
        child = parent
        parent = parents.get(id(parent))
    call = parent
    return (call, child) if isinstance(call, ast.Call) else (None, child)


def _yaml_consumer_slot_present(call, child):
    return any(
        item.arg in {"Loader", "Dumper"} and item.value is child
        for item in call.keywords
    ) or any(index < len(call.args) and call.args[index] is child for index in (1, 2))


def _yaml_consumer_module(call, parents):
    module = call
    while id(module) in parents:
        module = parents[id(module)]
    return module if isinstance(module, ast.Module) else None


def _yaml_consumer_binding(call, child, aliases, canonicalize):
    canonical = canonicalize(call, aliases)
    if canonical in {"yaml.load", "yaml.load_all"} and not yaml_load_call_signature(
        call
    ):
        return None
    parameter = _YAML_TYPED_CONSUMER_SLOTS.get(canonical)
    if parameter is None or len({item.arg for item in call.keywords}) != len(
        call.keywords
    ):
        return None
    if any(item.arg is None for item in call.keywords):
        return None
    keyword = next((item for item in call.keywords if item.arg == parameter[0]), None)
    if keyword is not None:
        if len(call.args) > parameter[1] or keyword.value is not child:
            return None
    elif len(call.args) <= parameter[1] or call.args[parameter[1]] is not child:
        return None
    return canonical


def yaml_load_call_signature(call):
    """Validate the modeled PyYAML load/load_all call binding without guessing defaults."""
    return isinstance(call, ast.Call) and _yaml_load_signature_shape(call)


def _yaml_load_signature_shape(call):
    if any(isinstance(argument, ast.Starred) for argument in call.args):
        return False
    names = [keyword.arg for keyword in call.keywords]
    return (
        all(name is not None for name in names)
        and len(names) == len(set(names))
        and all(name in {"stream", "Loader"} for name in names)
        and len(call.args) <= 2
        and not (call.args and "stream" in names)
        and not (len(call.args) > 1 and "Loader" in names)
        and bool(call.args or "stream" in names)
    )


_YAML_TYPED_CONSUMER_SLOTS = {
    "yaml.load": ("Loader", 1),
    "yaml.load_all": ("Loader", 1),
    "yaml.compose": ("Loader", 1),
    "yaml.compose_all": ("Loader", 1),
    "yaml.parse": ("Loader", 1),
    "yaml.scan": ("Loader", 1),
    "yaml.dump": ("Dumper", 2),
    "yaml.dump_all": ("Dumper", 2),
}


def yaml_loader_provider_uncertain(module, aliases, selected):
    """Check typed YAML value uses and every modeled consumer against mutations."""
    roots = {selected, *_YAML_TYPED_CONSUMER_SLOTS}

    def argument_escapes(node, local_aliases, parents):
        consumer = yaml_loader_argument_consumer(node, local_aliases, parents)
        return consumer is None

    return _provider_identity_uncertain(
        module,
        aliases,
        roots=roots,
        selected_paths=True,
        argument_predicate=argument_escapes,
    )


def _credential_candidates(tree, aliases, nodes=None):
    candidates = []
    nodes = ast.walk(tree) if nodes is None else nodes
    for call in (node for node in nodes if isinstance(node, ast.Call)):
        for value, consumer_role, slot in _auth_literal_nodes(call, aliases):
            if slot == "authorization":
                match = _AUTH_HEADER.match(value.value)
                value = ast.Constant(match.group(1) if match else "")
            if _literal_credential(value, auth_slot=True):
                candidates.append((call, consumer_role, slot))
    return candidates


def credential_findings(tree, aliases, relative="<source>", *, nodes=None):
    """Report statically bound HTTP auth literals, including weak defaults."""
    from .review_audits import _security_finding
    from .review_integrity import bind_security_call_scopes

    if not hasattr(tree, "_security_scope_kind"):
        bind_security_call_scopes(tree)
    nodes = tuple(ast.walk(tree) if nodes is None else nodes)
    candidates = _credential_candidates(tree, aliases, nodes)
    if not candidates:
        return []
    from types import SimpleNamespace

    from .finite_capture import finite_provider_mutation_index
    from .review_audits import _resolved_ast_name
    from .security_configuration import _canonical

    parents = {
        id(child): node for node in nodes for child in ast.iter_child_nodes(node)
    }
    mutations = finite_provider_mutation_index(
        nodes, aliases, SimpleNamespace(_resolved_ast_name=_resolved_ast_name), parents
    )
    findings = []
    for call, consumer_role, slot in candidates:
        provider = (
            _canonical_http_call(call, aliases) or _canonical(call, aliases)
        ).split(".", 1)[0]
        if _provider_identity_uncertain(
            tree,
            aliases,
            roots=(provider,),
            nodes=nodes,
            parents=parents,
            mutations=mutations,
        ):
            continue
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
    if not isinstance(source_bytes, dict) or not isinstance(bindings, dict):
        return False
    if any(
        not isinstance(name, str)
        or not isinstance(raw, bytes)
        or Path(name).is_absolute()
        or ".." in Path(name).parts
        or Path(name).as_posix() != name
        or len(raw) > 1_000_000
        for name, raw in source_bytes.items()
    ) or any(not isinstance(name, str) for name in bindings):
        return False
    return not (
        not set(bindings).issubset(source_bytes)
        or {name for name in source_bytes if Path(name).suffix == ".py"}
        != {name for name in bindings if Path(name).suffix == ".py"}
        or len(source_bytes) > 2000
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
            or sha256(raw).hexdigest() != digest
        ):
            return None
        if path.suffix != ".py":
            continue
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
    inputs = _flask_credential_authority_inputs(finding, context)
    if inputs is None:
        return None
    index, path, declaration, session_secret, key = inputs
    from .credential_endpoint_admission import _flask_credential_authority_for_key

    return _flask_credential_authority_for_key(
        finding, context, index, path, declaration, session_secret, key
    )


def _flask_credential_authority_inputs(finding, context):
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
    return index, path, declaration, session_secret, key


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


def _flask_configured_apps(target, context, protected_keys):
    if not _signing_framework_external(context, "flask"):
        return []
    configured = []
    for path, tree in context["index"].snapshots.items():
        if not context["index"].validate(path) or not _flask_authority_provider_clear(
            path, tree, context
        ):
            continue
        aliases = _flask_module_aliases(path, tree, context)
        for scope in [
            tree,
            *[
                node
                for node in tree.body
                if isinstance(node, ast.FunctionDef) and not node.decorator_list
            ],
        ]:
            receivers = {}
            for statement in scope.body:
                _flask_bind_created_app(statement, receivers, aliases)
                call = getattr(statement, "value", None)
                if not isinstance(call, ast.Call):
                    continue
                for receiver, creation in receivers.items():
                    if (
                        not _flask_config_load(call, receiver, target, context, path)
                        or _flask_config_mutated(scope, receiver, protected_keys)
                        or _flask_configuration_reloaded(
                            scope, receiver, target, context, protected_keys, path
                        )
                    ):
                        continue
                    configured.append(
                        {
                            "path": path,
                            "tree": tree,
                            "scope": scope,
                            "receiver": receiver,
                            "creation": creation,
                            "load": call,
                        }
                    )
    return configured


def _flask_authority_provider_clear(path, tree, context):
    from .review_audits import _resolved_ast_name

    aliases = context["aliases"][path]
    nodes = list(ast.walk(tree))
    roots = {
        "flask.Flask",
        "flask.Config.from_object",
        "flask_login.LoginManager",
        "flask_login.login_user",
        "flask_login.login_required",
    }
    provider_objects = roots | {
        "flask.request",
        "flask.session",
        "flask_login.LoginManager",
        "flask_login.login_user",
        "flask_login.login_required",
    }
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
        if (
            provider is None
            and statement.module == "flask"
            and _signing_framework_external(context, "flask")
        ):
            continue
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


def _flask_config_module_matches(context, expression, target, consumer_path, seen=()):
    if isinstance(expression, ast.Name) and expression.id == "__name__":
        return consumer_path == target
    resolved = _signing_resolve_module(context, expression)
    if resolved is not None:
        return resolved == target
    if not isinstance(expression, ast.Name) or len(seen) >= 8:
        return False
    index = context["index"]
    parents = index.parents.get(consumer_path)
    from .credential_role_identity_effects import (
        _enclosing_function,
        resolve_source_identity_call,
    )

    function = _enclosing_function(expression, parents) if parents else None
    marker = (consumer_path, id(function), expression.id)
    if (
        function is None
        or expression.id
        not in {
            item.arg
            for item in (
                *function.args.posonlyargs,
                *function.args.args,
                *function.args.kwonlyargs,
            )
        }
        or marker in seen
        or _name_writes(function, expression.id)
    ):
        return False
    found = False
    for caller_path, caller_tree in index.snapshots.items():
        if not index.validate(caller_path):
            return False
        for resolved_call in (
            resolved
            for call in ast.walk(caller_tree)
            if isinstance(call, ast.Call)
            for resolved in (resolve_source_identity_call(call, caller_path, index),)
            if resolved is not None
            and resolved.path == consumer_path
            and resolved.function is function
        ):
            actual = resolved_call.arguments.get(expression.id)
            if actual is None:
                return False
            actual_module = _signing_resolve_module(context, actual)
            if actual_module is None and (
                not isinstance(actual, ast.Name)
                or not _flask_config_module_matches(
                    context, actual, target, caller_path, (*seen, marker)
                )
            ):
                return False
            found = found or actual_module == target or actual_module is None
    return found


def _flask_module_aliases(path, tree, context):
    aliases = dict(context["aliases"].get(path, {}))
    if _signing_framework_external(context, "flask") and any(
        isinstance(node, ast.ImportFrom)
        and node.module == "flask"
        and not node.level
        and any(item.name == "*" for item in node.names)
        for node in tree.body
    ):
        for name in (
            "Flask",
            "request",
            "session",
            "redirect",
            "current_app",
            "current_user",
        ):
            if name not in aliases and not _name_writes(tree, name):
                aliases[name] = "flask." + name
    return aliases


def _name_writes(scope, name):
    return any(
        isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, (ast.Store, ast.Del))
        for node in ast.walk(scope)
    )


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
        if (
            len(guarded) == 1
            and registered
            and len(registered) == guarded[0]
            and all(position < guarded[0] for position in registered)
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
    for call in ast.walk(scope):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
            continue
        if _name(call.func.value) != receiver + ".config":
            continue
        if call.func.attr not in {
            "from_object",
            "update",
            "from_mapping",
            "get",
            "keys",
            "values",
            "items",
            "copy",
        }:
            return True
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
            call = statement.value
            canonical = (
                security_call_name(call, aliases) if isinstance(call, ast.Call) else ""
            )
            if (
                not canonical
                and isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
            ):
                canonical = aliases.get(call.func.id, "")
            if (
                isinstance(call, ast.Call)
                and canonical == "flask.Flask"
                and _flask_constructor_arguments(call)
            ):
                receivers[target.id] = call


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


def bind_native_input_precondition(
    call, canonical, primitive, scope, requests, aliases
):
    """Attach the shared source-owned dangerous-input premise to a native call."""
    from . import review_integrity as flow

    if hasattr(requests, "supported_view"):
        requests = requests.supported_view()
    if requests is None or not _native_input_precondition_eligible(
        call, canonical, primitive, scope, flow
    ):
        return
    if _native_input_request_is_supported(
        call, canonical, requests, aliases, scope, flow
    ):
        premise = supported_security_precondition(call, "untrusted_request", canonical)
        if trace := security_input_value_flow(call.args[0], requests, aliases):
            premise["input_value_flow"] = trace
        call._security_supported_precondition = premise
    elif canonical in {
        "eval",
        "exec",
        "builtins.eval",
        "builtins.exec",
        "os.system",
        "subprocess.call",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
    } and (witness := persisted_field_input(call)):
        premise = supported_security_precondition(call, "untrusted_input", canonical)
        premise["persisted_input"] = witness
        call._security_supported_precondition = premise


def _native_input_precondition_eligible(call, canonical, primitive, scope, flow):
    supported = {
        "SECURITY_DYNAMIC_EXECUTION",
        "SECURITY_OS_COMMAND",
        "SECURITY_SHELL_COMMAND",
        "SECURITY_UNSAFE_DESERIALIZATION",
        "SECURITY_UNSAFE_YAML",
    }
    module = flow._security_module_scope(scope)
    return (
        getattr(module, "_security_precondition_providers_stable", False)
        and primitive is not None
        and primitive["code"] in supported
        and call.args
        and security_precondition_call_shape(call, canonical)
        and security_precondition_path_possible(call)
    )


def _native_input_request_is_supported(call, canonical, requests, aliases, scope, flow):
    if not flow._security_expr_tainted(call.args[0], requests, set(), aliases):
        return False
    if canonical not in {"pickle.loads", "_pickle.loads", "dill.loads"}:
        return True
    return (
        request_payload_value_kind(
            call.args[0],
            requests,
            aliases,
            flow._security_scope_request_aliases,
            scope,
            getattr(call, "_security_flow_statement", None),
        )
        == "bytes"
    )


def _persisted_field_read(call, index, path):
    from .credential_role_constructor_provider import binding_occurrences

    value = call.args[0]
    scope = getattr(call, "_security_lexical_scope", None)
    if not (
        isinstance(value, ast.Attribute)
        and isinstance(value.value, ast.Name)
        and isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not scope.decorator_list
        and scope.args.args
        and scope.args.args[0].arg == value.value.id
    ):
        return None
    owner = index.parents[path].get(id(scope))
    if (
        not isinstance(owner, ast.ClassDef)
        or owner.keywords
        or len(owner.bases) != 1
        or binding_occurrences(scope.body, value.value.id)
    ):
        return None
    from .credential_role_constructor_provider import DYNAMIC_HOOKS

    if any(
        binding_occurrences(owner.body, name)
        for name in {*DYNAMIC_HOOKS, "query", "query_class", "__query_class__"}
    ):
        return None
    if len(binding_occurrences(owner.body, value.attr)) != 1:
        return None
    if not _persisted_receiver_stable(
        scope, value.value.id, value.attr, index.parents[path]
    ):
        return None
    return (index.relative(path), owner.name), value.attr


def _persisted_receiver_stable(scope, receiver, field, parents):
    from . import finite_capture as finite, review_audits as audit

    reads = [
        node
        for node in ast.walk(scope)
        if isinstance(node, ast.Attribute)
        and isinstance(node.ctx, ast.Load)
        and isinstance(node.value, ast.Name)
        and node.value.id == receiver
        and node.attr == field
    ]
    excluded = {id(child) for node in reads for child in ast.walk(node)}
    nodes = [node for node in ast.walk(scope) if id(node) not in excluded]
    facts = set()
    finite._provider_mutation_facts(
        nodes,
        {receiver: "storage.receiver"},
        audit,
        parents,
        finite._provider_alias_bindings(nodes),
        facts,
        None,
        None,
    )
    return not any(
        path == "storage.receiver" or path.startswith("storage.receiver.")
        for path, _ in facts
    )


def _persisted_query_receiver(call):
    if not (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "update"
        and len(call.args) == 1
        and not call.keywords
        and isinstance(call.args[0], ast.Dict)
    ):
        return None
    keys = [
        key.value
        for key in call.args[0].keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    ]
    if len(keys) != len(call.args[0].keys) or len(keys) != len(set(keys)):
        return None
    receiver = call.func.value
    for _ in range(8):
        if isinstance(receiver, ast.Attribute) and receiver.attr == "query":
            return receiver.value
        if not (
            isinstance(receiver, ast.Call)
            and isinstance(receiver.func, ast.Attribute)
            and receiver.func.attr in {"filter", "filter_by"}
        ):
            return None
        from .finite_capture import captured_scalar_guard

        if any(
            captured_scalar_guard(value, {}, False) is False for value in receiver.args
        ):
            return None
        receiver = receiver.func.value
    return None


def _persisted_writer_origin(expression, environment, aliases, scope, module):
    from .finite_capture import security_structural_value
    from .credential_role_constructor_provider import binding_occurrences
    from .credential_role_identity_effects import _argument_names

    conversion = False
    if (
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Name)
        and expression.func.id == "str"
        and len(expression.args) == 1
        and not expression.keywords
    ):
        if (
            "str" in _argument_names(scope)
            or "str" in getattr(expression, "_security_shadowed_names", ())
            or binding_occurrences(scope.body, "str")
            or binding_occurrences(module.body, "str")
        ):
            return None
        conversion = True
        expression = expression.args[0]
    value = security_structural_value(expression, environment, aliases)
    if (
        not (value.scalar_kind == "text" or conversion)
        or not value.roots
        or not any(
            step[0] in {"REQUEST_SOURCE", "REQUEST_SOURCE_UNKNOWN_KIND"}
            for step in value.trace
        )
    ):
        return None
    return {
        "roots": sorted(value.roots),
        "value_kind": "text",
        "conversion": "builtin_str" if conversion else "none",
        "value_unknown": value.unknown,
        "content_unknown": value.content_unknown,
        "steps": [
            {"operation": op, "span": list(span), "ast_sha256": digest}
            for op, span, digest in value.trace
        ],
    }


def _persisted_query_witness(index, wrapper, models, selected, field):
    from . import review_integrity as flow, review_audits as audit
    from .mock_fixture_provenance import _app_source_symbol

    if not all(index.validate(path) for path in index.snapshots):
        return None
    context = (index.root, index.source_bytes)
    for path, tree in index.snapshots.items():
        if not index.validate(path):
            return None
        tree._security_source_context = context
        nodes = list(ast.walk(tree))
        candidates = [
            (node, receiver)
            for node in nodes
            if isinstance(node, ast.Call)
            if (receiver := _persisted_query_receiver(node)) is not None
        ]
        if not candidates:
            continue
        if not hasattr(tree, "_security_scope_kind"):
            flow.bind_security_call_scopes(tree)
        aliases = audit._security_aliases(nodes)
        if not security_precondition_providers_stable(tree, aliases, nodes):
            continue
        analyzed = set()
        for call, receiver in candidates:
            scope = getattr(call, "_security_lexical_scope", None)
            resolved = _app_source_symbol(wrapper, path, receiver, function=scope)
            if not (
                resolved
                and isinstance(resolved[1], ast.ClassDef)
                and (index.relative(resolved[0]), resolved[1].name) == selected
                and isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
                and security_precondition_path_possible(call)
            ):
                continue
            witness = _persisted_update_witness(
                index,
                models[selected],
                field,
                path,
                tree,
                call,
                scope,
                aliases,
                analyzed,
            )
            if witness is not None:
                return witness
    return None


def _persisted_update_witness(
    index, model, field, path, tree, call, scope, aliases, analyzed
):
    if id(scope) not in analyzed:
        from .review_integrity import _security_scope_source_sink_findings

        analyzed.add(id(scope))
        _security_scope_source_sink_findings(index.relative(path), scope, aliases, {})
    for key, expression in zip(call.args[0].keys, call.args[0].values):
        if not isinstance(key, ast.Constant) or key.value != field:
            continue
        origin = _persisted_writer_origin(
            expression,
            getattr(call, "_security_structural_values", {}) or {},
            aliases,
            scope,
            tree,
        )
        if origin is not None:
            return {
                "schema": "factory.security.persisted-input.v1",
                "model": model["identity"],
                "field": model["fields"][field],
                "writer": {
                    "path": index.relative(path),
                    "sha256": index.inventory[path],
                    "span": [
                        call.lineno,
                        call.col_offset,
                        call.end_lineno,
                        call.end_col_offset,
                    ],
                },
                "input_flow": origin,
                "authority": "possible_request_writer",
                "api_contract_assumptions": [
                    *model["api_contract_assumptions"],
                    "SQLAlchemy model query update writes selected mapped fields",
                ],
                "negative_writer_closure": "NOT_ESTABLISHED",
            }
    return None


def _persisted_base_providers(index, wrapper, owner, path):
    from .mock_fixture_provenance import _app_source_symbol, _app_expression_name
    from .credential_role_constructor_provider import binding_occurrences
    from .runtime_audit_integrity import _conditional_module_name

    additional = []
    for base in owner.bases:
        base_ref = _app_source_symbol(wrapper, path, base)
        if base_ref is None:
            continue  # Constructed default Model member is closed by its provider contract.
        base_path, declaration = base_ref
        if isinstance(declaration, ast.ClassDef) and any(
            binding_occurrences(declaration.body, name)
            for name in {"query", "query_class", "__query_class__"}
        ):
            return None
        base_canonical = _app_expression_name(wrapper, path, base)
        if base_canonical is None and isinstance(base, ast.Name):
            base_canonical = (
                _conditional_module_name(index.relative(base_path)) + "." + base.id
            )
        if base_canonical is not None and isinstance(base, ast.Name):
            additional.append(
                (base_canonical, (base_path, base_canonical.rsplit(".", 1)[1]))
            )
    return tuple(additional)


def persisted_field_input(call):
    """Witness one possible request write to the exact mapped field read by a sink.

    This is a positive static path, never a proof that all stored values or uses
    are known, that a row is reachable in deployment, or that storage is safe.
    """
    from .finite_capture import _security_helper_source_context
    from .credential_role_identity_effects import source_symbol_index
    from .credential_role_constructor_provider import model_field_identities

    module, index, path = _security_helper_source_context(call, None)
    if (
        index is None
        or path is None
        or getattr(index, "_storage_origin_building", False)
    ):
        return None
    if (
        not index.validate(path)
        or (read := _persisted_field_read(call, index, path)) is None
    ):
        return None
    selected, field = read
    models = model_field_identities(index)
    if not _persisted_field_is_text(models, selected, field):
        return None
    wrapper = source_symbol_index(index)
    if wrapper is None:
        return None
    from .credential_role_constructor_provider import (
        _captured_terminal_provider_mutation,
    )
    from .runtime_audit_integrity import _conditional_module_name
    from . import review_audits as audit

    canonical = _conditional_module_name(selected[0]) + "." + selected[1]
    owner = index.parents[path][id(getattr(call, "_security_lexical_scope"))]
    additional = _persisted_base_providers(index, wrapper, owner, path)
    if additional is None:
        return None
    if _captured_terminal_provider_mutation(
        index,
        audit,
        canonical,
        local_binding=(path, selected[1]),
        additional_bindings=tuple(additional),
    ):
        return None
    index._storage_origin_building = True
    try:
        return _persisted_query_witness(index, wrapper, models, selected, field)
    finally:
        index._storage_origin_building = False


def _persisted_field_is_text(models, selected, field):
    model = models.get(selected) if isinstance(models, dict) else None
    descriptor = model.get("fields", {}).get(field) if model else None
    return isinstance(descriptor, dict) and descriptor.get("type") in {
        "TEXT",
        "VARCHAR",
        "CHAR",
        "NCHAR",
        "NVARCHAR",
        "STRING",
        "UNICODE",
        "UNICODETEXT",
    }


def supported_security_precondition(
    node, source_role, consumer_role, effect_witness=None
):
    """Describe a native producer's local premise, never runtime exploitability."""
    premise = {
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
    if effect_witness is not None:
        premise["effect_witness"] = {
            "schema": _SECURITY_EFFECT_WITNESS_SCHEMA_BASELINE,
            "source_role": source_role,
            "consumer_role": consumer_role,
            "effect_kind": effect_witness["effect_kind"],
            "source_span": effect_witness["source_span"],
            "sink_span": [
                node.lineno,
                node.col_offset,
                node.end_lineno,
                node.end_col_offset,
            ],
            "effect_facts": effect_witness["effect_facts"],
        }
    return premise


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


def request_payload_value_kind(
    node, requests, aliases, alias_reader, scope=None, flow_statement=None
):
    """Carry modeled request text/bytes through explicit codec operations only."""
    from .review_integrity import _security_structural_expression

    value = _security_structural_expression(node, requests, aliases)
    if value is not None and not value.unknown and value.roots:
        return value.scalar_kind
    kind = _request_payload_name_kind(node, requests)
    if kind is not None:
        return kind
    kind = _request_payload_codec_kind(
        node, requests, aliases, alias_reader, scope, flow_statement
    )
    if kind is not None:
        return kind
    kind = _request_payload_source_kind(
        node, aliases, alias_reader, scope, flow_statement
    )
    if kind is not None:
        return kind
    from .finite_capture import security_helper_return_kind

    return security_helper_return_kind(node, requests, aliases)


def _request_payload_name_kind(node, requests):
    if isinstance(node, ast.Name):
        for kind in ("bytes", "text"):
            if ("request-type:" + kind, node.id) in requests:
                return kind
    return None


def _request_payload_codec_kind(
    node, requests, aliases, alias_reader, scope=None, flow_statement=None
):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        codec = node.func.attr
        if codec in {"encode", "decode"} and not node.args and not node.keywords:
            original = request_payload_value_kind(
                node.func.value, requests, aliases, alias_reader, scope, flow_statement
            )
            if original == ("text" if codec == "encode" else "bytes"):
                return "bytes" if codec == "encode" else "text"
    return None


def _request_payload_source_kind(
    node, aliases, alias_reader, scope=None, flow_statement=None
):
    scope = scope or getattr(node, "_security_lexical_scope", None)
    flow_statement = flow_statement or getattr(node, "_security_flow_statement", None)
    body_kind = _flask_request_body_kind(
        node, aliases, scope, flow_statement, alias_reader
    )
    if body_kind:
        return body_kind
    if http_request_payload(
        node,
        aliases,
        scope,
        flow_statement,
        alias_reader,
    ):
        if isinstance(node, ast.Attribute):
            return "bytes"
        container = (
            node.value
            if isinstance(node, ast.Subscript)
            else (_credential_get_source_key(node) or (None,))[0]
        )
        if not isinstance(container, ast.Attribute):
            return None
        resolved = alias_reader(scope, aliases, flow_statement)
        from .review_audits import _name

        head, _, tail = _name(container).partition(".")
        canonical = resolved.get(head, "") + ("." + tail if tail else "")
        if canonical in {
            "flask.request.args",
            "flask.request.form",
        } or _django_http_body_payload(container, scope, resolved, {"GET", "POST"}):
            return "text"
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


def _native_request_data_member(node, aliases):
    """Separate request-owned data projections from the imported provider object."""
    from .review_integrity import _security_scope_request_aliases
    from .review_audits import _resolved_ast_name

    members = {
        "args",
        "form",
        "files",
        "headers",
        "cookies",
        "values",
        "json",
        "method",
        "referrer",
        "remote_addr",
        "access_route",
        "path",
        "full_path",
        "script_root",
        "url",
        "base_url",
        "root_url",
        "url_root",
        "host_url",
        "host",
        "endpoint",
    }
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        if not isinstance(node.ctx, ast.Load):
            return False
        if isinstance(node, ast.Subscript):
            if not isinstance(node.slice, ast.Constant) or type(
                node.slice.value
            ) not in {str, int}:
                return False
        else:
            if node.attr.startswith("_"):
                return False
            if node.attr in members:
                bindings = _security_scope_request_aliases(
                    getattr(node, "_security_lexical_scope", None),
                    aliases,
                    getattr(node, "_security_flow_statement", None),
                )
                if _resolved_ast_name(node.value, bindings) == "flask.request":
                    return True
        node = node.value
    return False


def _native_input_provider_inventory(tree, aliases, nodes):
    """Use the same request-value/provider distinction in every captured module."""
    from .review_integrity import (
        bind_security_call_scopes,
        _security_scope_request_aliases,
    )
    from .review_audits import _resolved_ast_name

    if not hasattr(tree, "_security_scope_kind"):
        bind_security_call_scopes(tree)
    payloads = [
        node
        for node in nodes
        if isinstance(node, (ast.Attribute, ast.Call, ast.Subscript))
        and (
            http_request_payload(
                node,
                aliases,
                getattr(node, "_security_lexical_scope", None),
                getattr(node, "_security_flow_statement", None),
                _security_scope_request_aliases,
            )
            or _native_request_data_member(node, aliases)
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
    return [
        node
        for node in nodes
        if id(node) not in payload_children | loader_children
        and not (
            isinstance(node, ast.Name)
            and isinstance(getattr(node, "_security_parent", None), ast.Attribute)
            and getattr(node, "_security_parent").value is node
        )
        and not (
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and id(node.value) in payload_ids
        )
    ]


def _native_input_inventory_epoch():
    from .review_integrity import _native_input_inventory_epoch as epoch

    return epoch()


def security_precondition_providers_stable(tree, aliases, nodes):
    """Keep request payload values distinct from provider-object escapes."""
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

    inventory = _native_input_provider_inventory(tree, aliases, nodes)
    parents = {
        id(child): node for node in nodes for child in ast.iter_child_nodes(node)
    }
    return not _provider_identity_uncertain(
        tree,
        aliases,
        roots=(
            "os.system",
            "os.path.join",
            "subprocess",
            "pickle",
            "_pickle",
            "dill",
            "yaml",
            "builtins",
            # Unrelated framework components do not alias an imported provider.
            # Parent namespace escapes still conflict through selected_paths.
            *(
                path
                for path in aliases.values()
                if path.split(".")[0] in {"flask", "django"}
            ),
        ),
        selected_paths=True,
        nodes=inventory,
        parents=parents,
        inventory_projector=_native_input_provider_inventory,
        inventory_dependencies=_native_input_inventory_epoch(),
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


def log_security_precondition(module, call, effect_witness=None, input_value_flow=None):
    """Return a premise only for current typed request-to-plain-log evidence."""
    if not (
        isinstance(effect_witness, dict)
        and isinstance(input_value_flow, dict)
        and getattr(module, "_security_log_provider_stable", False)
        and security_precondition_path_possible(call)
    ):
        return {}
    premise = supported_security_precondition(
        call,
        effect_witness.get("source_role"),
        effect_witness.get("consumer_role"),
        effect_witness,
    )
    from .credential_role_paths import valid_security_precondition

    finding = {
        "code": "SECURITY_LOG_INJECTION",
        "line": call.lineno,
        "column": call.col_offset,
    }
    if not valid_security_precondition(premise, finding, require_effect_witness=True):
        return {}
    premise["input_value_flow"] = input_value_flow
    return {"security_precondition": premise}


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
    from .credential_role_paths import tls_security_finding

    return tls_security_finding(call, relative, node, aliases)


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


def bind_request_sink_precondition(
    finding, call, aliases, requests, connections, cursors, helpers
):
    from .credential_role_paths import bind_request_sink_precondition as bind

    return bind(finding, call, aliases, requests, connections, cursors, helpers)


def _security_request_sink_slot(
    finding, call, aliases, requests, connections, cursors, helpers
):
    from .intent_quality import bound_sink_argument, sql_statement_argument
    from .review_integrity import (
        _security_unsafe_open,
        _security_unsafe_request_url,
        _security_unsafe_sql,
        security_call_name,
    )

    if any(isinstance(arg, ast.Starred) for arg in call.args) or any(
        kw.arg is None for kw in call.keywords
    ):
        return None
    code = finding["code"]
    if code == "SECURITY_PATH_TRAVERSAL" and finding["facts"].get("call") == "open":
        return _path_traversal_sink(
            call,
            requests,
            aliases,
            bound_sink_argument,
            _security_open_builtin_closed,
            _security_unsafe_open,
        )
    if code == "SECURITY_SSRF":
        return _ssrf_sink(
            call,
            aliases,
            requests,
            bound_sink_argument,
            security_call_name,
            _security_unsafe_request_url,
        )
    if code == "SECURITY_SQL_INJECTION":
        return _sql_sink(
            call,
            aliases,
            requests,
            connections,
            cursors,
            helpers,
            sql_statement_argument,
            security_call_name,
            _security_unsafe_sql,
        )
    return None


def _path_traversal_sink(call, requests, aliases, bound, builtin_closed, unsafe):
    if call.keywords or not 1 <= len(call.args) <= 2 or not builtin_closed(call):
        return None
    modes = {"r", "rb", "w", "wb", "a", "ab", "r+", "w+", "a+"}
    if len(call.args) == 2 and not (
        isinstance(call.args[1], ast.Constant) and call.args[1].value in modes
    ):
        return None
    value = bound(call, 0, ("file",))
    return (
        (value, ("builtins",))
        if value is not None and unsafe(call, requests, aliases)
        else None
    )


def _ssrf_sink(call, aliases, requests, bound, call_name, unsafe):
    if len(call.args) != 1 or call.keywords:
        return None
    value = bound(call, 0, ("url",))
    return (
        (value, ("requests",))
        if value is not None
        and unsafe(call, call_name(call, aliases), requests, aliases)
        else None
    )


def _sql_sink(
    call,
    aliases,
    requests,
    connections,
    cursors,
    helpers,
    statement_argument,
    call_name,
    unsafe,
):
    if len(call.args) != 1 or call.keywords:
        return None
    driver = unsafe(
        call,
        call_name(call, aliases),
        set(),
        requests,
        aliases,
        connections,
        cursors,
        helpers,
    )
    if not driver:
        return None
    value = statement_argument(call, driver, aliases, call_name)
    return (
        (value, (driver,))
        if value is not None and _security_sql_receiver_closed(call)
        else None
    )


def _security_builtin_identity_closed(module, aliases, names):
    from .review_integrity import _resolve

    protected = (
        set(names)
        | {"builtins"}
        | {name for name, value in aliases.items() if value == "builtins"}
    )
    parents = {
        child: node for node in ast.walk(module) for child in ast.iter_child_nodes(node)
    }
    reflectors = {
        "exec",
        "eval",
        "globals",
        "locals",
        "vars",
        "__import__",
        "setattr",
        "delattr",
    }
    for node in ast.walk(module):
        if (
            isinstance(node, ast.Name)
            and node.id in protected
            and not isinstance(node.ctx, ast.Load)
        ):
            return False
        if isinstance(node, ast.arg) and node.arg in protected:
            return False
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name in protected
        ):
            return False
        if (
            isinstance(node, ast.alias)
            and (node.asname or node.name.split(".")[0]) in protected
            and node.name != "builtins"
        ):
            return False
        if isinstance(node, ast.ExceptHandler) and node.name in protected:
            return False
        if isinstance(node, (ast.Name, ast.Attribute)) and isinstance(
            node.ctx, ast.Load
        ):
            canonical = _resolve(node, aliases).removeprefix("builtins.")
            if canonical in reflectors:
                parent = parents.get(node)
                direct_attribute_write = (
                    canonical in {"setattr", "delattr"}
                    and isinstance(parent, ast.Call)
                    and parent.func is node
                )
                if not direct_attribute_write:
                    return False
    return not _provider_identity_uncertain(module, aliases, roots=("builtins",))


def _security_open_builtin_closed(call):
    from .review_integrity import (
        _security_module_scope,
        _security_scope_request_aliases,
    )

    scope = getattr(call, "_security_lexical_scope", None)
    module = _security_module_scope(scope)
    aliases = _security_scope_request_aliases(
        scope, {}, getattr(call, "_security_flow_statement", None)
    )
    return module is not None and _security_builtin_identity_closed(
        module, aliases, {"open"}
    )


def log_scalar_metadata(node, reader):
    """Prove scalar log output while retaining uncertain builtin identities."""
    if not isinstance(node, ast.Call):
        return False
    name = reader.resolve(node, reader.aliases)
    if name in {"int", "builtins.int"}:
        return reader._builtin_unshadowed(node, name)
    if not _log_scalar_call_shape(node, name, reader):
        return False
    module = reader.module_scope(reader.scope)
    if module is None:
        return False
    if not hasattr(module, "_security_log_builtin_identity_stable"):
        module._security_log_builtin_identity_stable = (
            _security_builtin_identity_closed(module, reader.aliases, {"bool", "len"})
        )
    return module._security_log_builtin_identity_stable


def _log_scalar_call_shape(node, name, reader):
    if name not in {"bool", "builtins.bool", "len", "builtins.len"}:
        return False
    return (
        not node.keywords
        and not any(isinstance(arg, ast.Starred) for arg in node.args)
        and (len(node.args) == 1 or name in {"bool", "builtins.bool"} and not node.args)
        and reader._builtin_unshadowed(node, name)
    )


def _security_sql_receiver_closed(call):
    """Decline a receiver whose methods/capability escape in the captured module."""
    from .review_integrity import _security_module_scope

    receiver = call.func.value if isinstance(call.func, ast.Attribute) else None
    if not isinstance(receiver, ast.Name):
        return False
    module = _security_module_scope(getattr(call, "_security_lexical_scope", None))
    parents = {
        child: node for node in ast.walk(module) for child in ast.iter_child_nodes(node)
    }
    for node in ast.walk(module):
        if (
            not isinstance(node, ast.Name)
            or node.id != receiver.id
            or not isinstance(node.ctx, ast.Load)
        ):
            continue
        parent = parents.get(node)
        if not (
            isinstance(parent, ast.Attribute)
            and isinstance(parent.ctx, ast.Load)
            and parent.attr
            in {
                "execute",
                "fetchone",
                "fetchall",
                "fetchmany",
                "commit",
                "rollback",
                "close",
            }
            and isinstance(parents.get(parent), ast.Call)
            and parents[parent].func is parent
        ):
            return False
    return True


def _native_span(node):
    span = [
        getattr(node, key, None)
        for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
    ]
    if (
        any(type(value) is not int for value in span)
        or span[0] < 1
        or min(span[1], span[3]) < 0
        or tuple(span[:2]) > tuple(span[2:])
    ):
        return None
    return span


def _captured_sink_failure(schema, code, reason, base=None):
    return {
        **(base or {"schema": schema, "status": "INCOMPLETE"}),
        "code": code,
        "truncation": [reason],
    }


def _captured_sink_source(
    path_arg, expected, index, raw, tree, max_sources, max_states, max_output, schema
):
    import io
    import tokenize

    limits = (max_sources, max_states, max_output)
    if any(type(value) is not int or value < 1 for value in limits) or max_output < 256:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_INVALID", "invalid_limit"
            )
        }
    limits = tuple(
        min(value, ceiling) for value, ceiling in zip(limits, (64, 512, 64000))
    )
    path = path_arg.as_posix() if hasattr(path_arg, "as_posix") else path_arg
    tree_supplied = tree is not None
    indexed = index is not None
    if indexed:
        capture = _captured_sink_index(index, path_arg, raw, path, schema)
        if "error" in capture:
            return capture
        raw, tree, parents = capture["raw"], capture["tree"], capture["parents"]
    else:
        parents = None
    if not isinstance(path, str) or not path:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "invalid_source_path"
            )
        }
    if not isinstance(raw, bytes) or len(raw) > 1_000_000:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_EXHAUSTED", "max_source_bytes"
            )
        }
    digest = hashlib.sha256(raw).hexdigest()
    if not isinstance(expected, str) or expected != digest:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_hash_mismatch"
            )
        }
    if not indexed:
        capture = _captured_sink_raw_tree(path, raw, tree, schema)
        if "error" in capture:
            return capture
        tree, parents = capture["tree"], capture["parents"]
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        text = raw.decode(encoding)
    except (SyntaxError, UnicodeError, LookupError):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_encoding_invalid"
            )
        }
    base = {
        "schema": schema,
        "status": "INCOMPLETE",
        "source": {"path": path[:1024], "sha256": digest, "bytes": len(raw)},
        "source_count": 1,
    }
    return {
        "tree": tree,
        "parents": parents,
        "text": text,
        "base": base,
        "digest": digest,
        "limits": limits,
        "indexed": indexed,
        "tree_supplied": tree_supplied,
    }


def _captured_sink_index(index, path_arg, raw, path, schema):
    inventory = getattr(index, "source_bytes", {})
    if not isinstance(path, str) or path_arg not in getattr(index, "snapshots", {}):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_not_indexed"
            )
        }
    if (
        sum(len(value) for value in inventory.values() if isinstance(value, bytes))
        > 32_000_000
    ):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_EXHAUSTED", "max_inventory_bytes"
            )
        }
    captured = inventory.get(path_arg)
    if raw is not None and raw != captured:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_bytes_changed"
            )
        }
    if not isinstance(captured, bytes) or len(captured) > 1_000_000:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_EXHAUSTED", "max_source_bytes"
            )
        }
    validation_inputs = getattr(index, "_validation_inputs", None)
    if not isinstance(validation_inputs, dict):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_validation_cache_unavailable"
            )
        }
    validation_inputs.pop(path_arg, None)
    if not index.validate(path_arg):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_snapshot_invalid"
            )
        }
    return {
        "raw": captured,
        "tree": index.snapshots[path_arg],
        "parents": index.parents[path_arg],
    }


def _captured_sink_raw_tree(path, raw, tree, schema):
    try:
        parsed = ast.parse(raw, filename=path)
        if tree is not None and ast.dump(parsed, include_attributes=True) != ast.dump(
            tree, include_attributes=True
        ):
            return {
                "error": _captured_sink_failure(
                    schema, "SINK_SOURCE_STALE", "ast_source_mismatch"
                )
            }
        tree = tree or parsed
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_parse_failed"
            )
        }
    return {"tree": tree, "parents": {}}


def _captured_sink_location(node, ctx):
    base, tree, parents = ctx["base"], ctx["tree"], ctx["parents"]
    schema = base["schema"]
    span = _native_span(node) if isinstance(node, ast.AST) else None
    if span is None:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_LOCATION_UNRESOLVED", "invalid_sink_span", base
            )
        }
    if ctx["indexed"] and isinstance(node, ast.Call) and id(node) in parents:
        return {"node": node, "parents": parents, "source_ast_nodes_examined": 0}
    if ctx["indexed"]:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_LOCATION_UNRESOLVED", "sink_not_in_captured_tree", base
            )
        }
    matches = []
    for count, item in enumerate(ast.walk(tree), 1):
        if count > 200_000:
            return {
                "error": _captured_sink_failure(
                    schema, "SINK_BUDGET_EXHAUSTED", "max_source_ast_nodes", base
                )
            }
        parents.update({id(child): item for child in ast.iter_child_nodes(item)})
        if (
            isinstance(item, ast.Call)
            and _native_span(item) == span
            and ast.dump(item, include_attributes=True)
            == ast.dump(node, include_attributes=True)
        ):
            matches.append(item)
    if ctx["tree_supplied"] and id(node) not in parents:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_LOCATION_UNRESOLVED", "sink_not_in_supplied_tree", base
            )
        }
    if len(matches) == 1:
        return {
            "node": matches[0],
            "parents": parents,
            "source_ast_nodes_examined": count,
        }
    return {
        "error": _captured_sink_failure(
            schema, "SINK_LOCATION_UNRESOLVED", "sink_span_not_unique", base
        )
    }


def _captured_sink_fact(item, path, digest, status="OBSERVED"):
    span = _native_span(item)
    return (
        {"status": status, "source": {"path": path, "sha256": digest, "span": span}}
        if span is not None
        else {"status": "UNKNOWN", "reason": "span_unavailable"}
    )


def _captured_sink_excerpt(item, text, truncation):
    excerpt = ast.get_source_segment(text, item)
    if not isinstance(excerpt, str):
        return ""
    if len(excerpt) > 512:
        if "excerpt_truncated" not in truncation:
            truncation.append("excerpt_truncated")
        return excerpt[:512] + "[truncated]"
    return excerpt


def _captured_sink_scope(node, parents, fact, budget, base):
    scope = node
    while id(scope) in parents:
        scope = parents[id(scope)]
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            break
    else:
        scope = None
    row, body, statement = (
        {"status": "UNKNOWN", "reason": "no_enclosing_callable"},
        None,
        None,
    )
    if scope is not None:
        statement = node
        while id(statement) in parents and parents[id(statement)] is not scope:
            statement = parents[id(statement)]
        if (
            isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
            and statement in scope.body
        ):
            body = scope.body
            row = {
                "status": "OBSERVED",
                "name": scope.name,
                "kind": type(scope).__name__,
                **fact(scope),
            }
        else:
            row = {
                "status": "UNKNOWN",
                "reason": "sink_outside_callable_body",
                **fact(scope),
            }
    nodes, stack = [], [scope] if body is not None else []
    while stack:
        item = stack.pop()
        nodes.append(item)
        if len(nodes) > budget:
            return {
                "error": _captured_sink_failure(
                    base["schema"], "SINK_BUDGET_EXHAUSTED", "max_states", base
                )
            }
        if item is not scope and isinstance(
            item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        stack.extend(ast.iter_child_nodes(item))
    return {
        "scope": scope,
        "body": body,
        "statement": statement,
        "nodes": nodes,
        "row": row,
    }


def _captured_sink_arguments(node, fact, excerpt):
    arguments, names = [], set()
    for index, value in enumerate(node.args):
        arguments.append(
            {
                "position": index,
                "kind": "starred" if isinstance(value, ast.Starred) else "positional",
                "expression": excerpt(value),
                "span": _native_span(value),
                **fact(value),
            }
        )
        names.update(
            item.id
            for item in ast.walk(value)
            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
        )
    for keyword in node.keywords:
        value = keyword.value
        arguments.append(
            {
                "keyword": keyword.arg,
                "kind": "expanded_keyword" if keyword.arg is None else "keyword",
                "expression": excerpt(value),
                "span": _native_span(value),
                **fact(value),
            }
        )
        names.update(
            item.id
            for item in ast.walk(value)
            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
        )
    callees = [
        item
        for item in ast.walk(node.func)
        if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
    ]
    names.update(item.id for item in callees)
    return arguments, names, callees


def _captured_sink_imports(tree, scope, nodes, parents, fact, budget, base):
    from .credential_role_constructor_provider import binding_occurrences

    modules = [
        item for item in tree.body if isinstance(item, (ast.Import, ast.ImportFrom))
    ]
    if len(nodes) + len(modules) > budget:
        return {
            "error": _captured_sink_failure(
                base["schema"], "SINK_BUDGET_EXHAUSTED", "max_states", base
            )
        }
    rows, params = [], _captured_sink_parameter_names(scope)
    for item in modules + [
        row for row in nodes if isinstance(row, (ast.Import, ast.ImportFrom))
    ]:
        owner = _captured_sink_enclosing_callable(item, parents)
        if owner not in (None, scope):
            continue
        container = owner.body if owner is not None else tree.body
        for alias in item.names:
            name = alias.asname or (
                alias.name.split(".")[0] if isinstance(item, ast.Import) else alias.name
            )
            wildcard = isinstance(item, ast.ImportFrom) and alias.name == "*"
            stable = (
                not wildcard
                and binding_occurrences(container, name) == [item]
                and name not in params
            )
            status = "OBSERVED" if stable else "UNKNOWN"
            rows.append(
                {
                    "name": name,
                    "module": item.module
                    if isinstance(item, ast.ImportFrom)
                    else alias.name,
                    "kind": type(item).__name__,
                    "status": status,
                    "reason": None if stable else "binding_replaced_or_ambiguous",
                    "span": _native_span(item),
                    **fact(item, status),
                }
            )
    return {
        "rows": rows,
        "module_imports": modules,
        "states_used": sum(len(item.names) for item in modules),
        "binding_occurrences": binding_occurrences,
    }


def _captured_sink_values(
    node, names, scope, body, statement, nodes, parents, tree, fact, excerpt
):
    from .credential_role_constructor_provider import binding_occurrences

    if body is None:
        return [
            {
                "name": name,
                "status": "UNKNOWN",
                "reason": "no_supported_callable_scope",
                "origin": "UNRESOLVED",
                "definitions": [],
                "replacements": [],
            }
            for name in sorted(names)
        ]
    params = _captured_sink_parameter_names(scope)
    reflective = _captured_sink_reflective_barrier(node, scope, nodes, parents)
    pending, visited, result = sorted(names), set(), []
    while pending:
        name = pending.pop(0)
        if name in visited:
            continue
        visited.add(name)
        evidence = _captured_sink_value(
            name,
            scope,
            body,
            statement,
            parents,
            tree,
            params,
            fact,
            excerpt,
            binding_occurrences,
        )
        value, assignment = evidence["value"], evidence["assignment"]
        if assignment is not None:
            pending.extend(
                row.id
                for row in ast.walk(assignment.value)
                if isinstance(row, ast.Name)
                and isinstance(row.ctx, ast.Load)
                and row.id not in visited
                and row.id not in pending
            )
        if reflective:
            value.update(
                status="UNKNOWN",
                reason="reflective_binding_possible",
                origin="UNRESOLVED",
            )
            value["replacements"].append(
                {"kind": "REFLECTIVE_WRITE_POSSIBLE", **fact(node, "UNKNOWN")}
            )
        result.append(value)
    return result


def _captured_sink_reflective_barrier(node, scope, nodes, parents):
    """Return whether a reflective call can precede or feed this selected sink."""
    reflective_names = {
        "exec",
        "eval",
        "globals",
        "locals",
        "vars",
        "setattr",
        "delattr",
    }
    selected_span = _native_span(node)
    selected_start = tuple(selected_span[:2]) if selected_span else None
    selected_subtree = {id(item) for item in ast.walk(node)}
    for item in nodes:
        if (
            not isinstance(item, ast.Call)
            or not isinstance(item.func, ast.Name)
            or item.func.id not in reflective_names
            or item is node
        ):
            continue
        if id(item) in selected_subtree:
            return True
        if _captured_sink_enclosing_callable(item, parents) is not scope:
            continue
        span = _native_span(item)
        if selected_start is None or span is None:
            return True
        if tuple(span[:2]) <= selected_start:
            return True
    return False


def _captured_sink_value(
    name,
    scope,
    body,
    statement,
    parents,
    tree,
    params,
    fact,
    excerpt,
    binding_occurrences,
):
    bindings = binding_occurrences(body, name)
    rows = []
    for binding in bindings:
        statement_node = (
            parents.get(id(binding)) if isinstance(binding, ast.Name) else binding
        )
        if statement_node is None:
            statement_node = binding
        rows.append(
            {
                "kind": type(binding).__name__,
                "binding_span": _native_span(binding),
                "expression": excerpt(statement_node),
                **fact(statement_node, "UNKNOWN"),
            }
        )
    assignment = None
    if (
        len(bindings) == 1
        and isinstance(bindings[0], ast.Name)
        and isinstance(bindings[0].ctx, ast.Store)
    ):
        candidate = parents.get(id(bindings[0]))
        targets = (
            candidate.targets
            if isinstance(candidate, ast.Assign)
            else [candidate.target]
            if isinstance(candidate, ast.AnnAssign)
            else []
        )
        if (
            candidate in body
            and body.index(candidate) < body.index(statement)
            and getattr(candidate, "value", None) is not None
            and len(targets) == 1
            and targets[0] is bindings[0]
        ):
            assignment = candidate
    if assignment is not None:
        value = {
            "name": name,
            "status": "INFERRED",
            "reason": None,
            "origin": "LOCAL_DEFINITION",
            "definitions": [
                {
                    "expression": excerpt(assignment.value),
                    "span": _native_span(assignment),
                    **fact(assignment),
                }
            ],
            "replacements": [],
        }
        value["definitions"][0]["target_source"] = fact(
            assignment.targets[0]
            if isinstance(assignment, ast.Assign)
            else assignment.target
        )
    elif not bindings and name in params:
        args = (
            *scope.args.posonlyargs,
            *scope.args.args,
            *scope.args.kwonlyargs,
            *([scope.args.vararg] if scope.args.vararg else []),
            *([scope.args.kwarg] if scope.args.kwarg else []),
        )
        arg = next(row for row in args if row.arg == name)
        value = {
            "name": name,
            "status": "INFERRED",
            "reason": None,
            "origin": "CALLABLE_PARAMETER",
            "definitions": [
                {"kind": "PARAMETER", "span": _native_span(arg), **fact(arg)}
            ],
            "replacements": [],
        }
    elif not bindings and any(
        row in tree.body for row in binding_occurrences(tree.body, name)
    ):
        module_bindings = binding_occurrences(tree.body, name)
        if len(module_bindings) == 1 and isinstance(
            module_bindings[0], (ast.Import, ast.ImportFrom)
        ):
            value = {
                "name": name,
                "status": "INFERRED",
                "reason": None,
                "origin": "LEXICAL_IMPORT",
                "definitions": [
                    {
                        "kind": type(module_bindings[0]).__name__,
                        "span": _native_span(module_bindings[0]),
                        **fact(module_bindings[0]),
                    }
                ],
                "replacements": [],
            }
        else:
            value = {
                "name": name,
                "status": "UNKNOWN",
                "reason": "module_binding_ambiguous",
                "origin": "UNRESOLVED",
                "definitions": [],
                "replacements": rows,
            }
    else:
        value = {
            "name": name,
            "status": "UNKNOWN",
            "reason": "binding_replaced_or_not_straight_line"
            if bindings
            else "no_source_definition_or_parameter",
            "origin": "UNRESOLVED",
            "definitions": [],
            "replacements": rows,
        }
    return {"value": value, "assignment": assignment}


def _captured_sink_guards(node, scope, parents, fact, excerpt):
    guards, current = [], node
    control = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        getattr(ast, "TryStar", ast.Try),
        ast.With,
        ast.AsyncWith,
        ast.Match,
        ast.Assert,
    )
    while id(current) in parents and parents[id(current)] is not scope:
        current = parents[id(current)]
        if isinstance(current, control):
            test = getattr(current, "test", None) or getattr(current, "subject", None)
            guards.append(
                {
                    "kind": type(current).__name__,
                    "expression": excerpt(test) if test is not None else "",
                    "semantics": "UNKNOWN",
                    "span": _native_span(current),
                    **fact(current),
                }
            )
    return guards


def _captured_sink_callee_binding(names, scope, body, tree, module_imports, fact):
    from .credential_role_constructor_provider import binding_occurrences

    name = names[0].id if names else None
    row = {"status": "UNKNOWN", "reason": "unresolved_callee_binding", "name": name}
    if name is None or body is None:
        return row
    if any(
        isinstance(item, ast.ImportFrom)
        and any(alias.name == "*" for alias in item.names)
        for item in module_imports
    ):
        row["reason"] = "wildcard_import_may_bind_name"
    elif not binding_occurrences(
        body, name
    ) and name not in _captured_sink_parameter_names(scope):
        bindings = binding_occurrences(tree.body, name)
        if (
            len(bindings) == 1
            and bindings[0] in tree.body
            and isinstance(bindings[0], (ast.Import, ast.ImportFrom))
        ):
            row = {
                "status": "INFERRED",
                "reason": None,
                "name": name,
                "declaration": fact(bindings[0]),
            }
    return row


@dataclass(frozen=True)
class _SecurityFlowValue:
    """Scanner-owned scalar shape and source trace, never an executed value."""

    tainted: bool
    kind: str
    steps: tuple = ()


def _security_flow_tainted(value):
    return value is True or isinstance(value, _SecurityFlowValue) and value.tainted


def _security_flow_step(expression, operation):
    return (
        operation,
        tuple(_finite_source_span(expression) or ()),
        hashlib.sha256(
            ast.dump(expression, include_attributes=False).encode()
        ).hexdigest(),
    )


def _security_flow_combine(expression, values, kind, operation):
    if not values or any(
        not isinstance(value, _SecurityFlowValue) or value.kind != kind
        for value in values
    ):
        return False, None
    steps = tuple(dict.fromkeys(step for value in values for step in value.steps))
    if len(steps) >= 64:
        return False, None
    return True, _SecurityFlowValue(
        any(value.tainted for value in values),
        kind,
        (*steps, _security_flow_step(expression, operation)),
    )


def _security_flow_shaped(expression, environment, aliases):
    if isinstance(expression, ast.BinOp):
        if not isinstance(expression.op, ast.Add):
            return False, None
        parts = [
            _security_flow_value(value, environment, aliases)[1]
            for value in (expression.left, expression.right)
        ]
        kind = parts[0].kind if isinstance(parts[0], _SecurityFlowValue) else None
        return _security_flow_combine(expression, parts, kind, "SCALAR_CONCAT")
    if isinstance(expression, ast.JoinedStr):
        values = []
        for part in expression.values:
            if isinstance(part, ast.FormattedValue):
                if part.conversion != -1 or part.format_spec is not None:
                    return False, None
                part = part.value
            known, value = _security_flow_value(part, environment, aliases)
            if not known:
                return False, None
            values.append(value)
        return _security_flow_combine(expression, values, "text", "TEXT_INTERPOLATION")
    receiver = expression.func.value
    if expression.args or expression.keywords:
        return False, None
    known, value = _security_flow_value(receiver, environment, aliases)
    incoming, outgoing = (
        ("text", "bytes") if expression.func.attr == "encode" else ("bytes", "text")
    )
    if (
        not known
        or not isinstance(value, _SecurityFlowValue)
        or value.kind != incoming
        or len(value.steps) >= 64
    ):
        return False, None
    return True, _SecurityFlowValue(
        value.tainted,
        outgoing,
        (
            *value.steps,
            _security_flow_step(expression, "BUILTIN_" + expression.func.attr.upper()),
        ),
    )


def _security_flow_request_leaf(expression, environment, aliases):
    from . import review_integrity as flow
    from .semantic_credential_sensor import (
        http_request_payload,
        _request_payload_source_kind,
    )

    if not http_request_payload(
        expression,
        aliases,
        getattr(expression, "_security_lexical_scope", None),
        getattr(expression, "_security_flow_statement", None),
        flow._security_scope_request_aliases,
    ):
        return False, None
    kind = _request_payload_source_kind(
        expression, aliases, flow._security_scope_request_aliases
    )
    if kind is None:
        return True, True
    return True, _SecurityFlowValue(
        True, kind, (_security_flow_step(expression, "REQUEST_SOURCE"),)
    )


def _security_flow_name_value(expression, environment):
    value = environment.get(expression.id)
    if isinstance(value, _SecurityFlowValue):
        if len(value.steps) >= 64:
            return False, None
        value = _SecurityFlowValue(
            value.tainted,
            value.kind,
            (*value.steps, _security_flow_step(expression, "ALIAS_USE")),
        )
    return value is not None, value


def _security_flow_value(expression, environment, aliases):
    from . import review_integrity as flow
    from .finite_capture import _fixed_literal_value

    if sum(1 for _ in ast.walk(expression)) > 512:
        return False, None
    if isinstance(expression, ast.Name):
        return _security_flow_name_value(expression, environment)
    if isinstance(expression, ast.Constant) and type(expression.value) in {str, bytes}:
        return True, _SecurityFlowValue(
            False,
            "text" if type(expression.value) is str else "bytes",
            (_security_flow_step(expression, "FIXED_LITERAL"),),
        )
    if _fixed_literal_value(expression):
        return True, False
    shaped = isinstance(expression, (ast.BinOp, ast.JoinedStr)) or (
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Attribute)
        and expression.func.attr in {"encode", "decode"}
    )
    if shaped:
        return _security_flow_shaped(expression, environment, aliases)
    if not isinstance(expression, (ast.Call, ast.Attribute, ast.Subscript)):
        # A may-taint arithmetic expression is not a proved evaluable value.
        return False, None
    return _security_flow_unshaped(expression, environment, aliases, flow)


def _security_flow_unshaped(expression, environment, aliases, flow):
    if isinstance(expression, ast.Call) and flow.security_call_name(
        expression, aliases
    ) in {
        "os.path.join",
        "pathlib.Path",
        "pathlib.PurePath",
        "werkzeug.utils.secure_filename",
    }:
        return False, None
    leaf = _security_flow_request_leaf(expression, environment, aliases)
    if leaf[0]:
        return leaf
    tainted = {
        name
        for name, value in environment.items()
        if isinstance(name, str) and _security_flow_tainted(value)
    }
    if isinstance(expression, ast.Call):
        function = flow._security_local_helper_definition(expression)
        if function is not None:
            for name, value in environment.items():
                if isinstance(value, _SecurityFlowValue) and value.tainted:
                    tainted.add(("request-type:" + value.kind, name))
            value = security_helper_return_value(
                expression, function, tainted, set(), aliases, caller_values=environment
            )
            return value is not None, value
    if flow._security_expr_tainted(expression, tainted, set(), aliases):
        return True, True
    return False, None


def _security_helper_initial(
    call, actuals, requests, parameters, aliases, caller_values=None
):
    from .finite_capture import _fixed_literal_value

    supplied = {id(value) for value in call.args}
    supplied.update(id(keyword.value) for keyword in call.keywords)
    caller = dict(caller_values or {})
    caller.update(
        {name: True for name in requests | parameters if isinstance(name, str)}
    )
    for item in requests:
        if (
            isinstance(item, tuple)
            and len(item) == 2
            and item[0] in {"request-type:text", "request-type:bytes"}
        ):
            caller[item[1]] = _SecurityFlowValue(True, item[0].split(":", 1)[1])
    initial = {}
    for name, value in actuals.items():
        # Omitted defaults belong to the definition, never to the caller's scope.
        if _fixed_literal_value(value):
            initial[name] = _security_flow_value(value, {}, aliases)[1]
        elif id(value) in supplied:
            known, tainted = _security_flow_value(value, caller, aliases)
            initial[name] = tainted if known else None
        else:
            initial[name] = None
    return initial


def security_helper_return_value(
    call,
    function,
    requests,
    parameters,
    aliases,
    *,
    caller_values=None,
    source_index=None,
    source_path=None,
    structural_values=None,
    resolve_call=None,
):
    """Trace an exact source helper return without executing the helper."""
    from .finite_capture import _security_helper_binding, evaluate_helper_flow

    if not isinstance(call, ast.Call):
        return None
    if source_index is None:
        _module, source_index, source_path = _security_helper_source_context(
            call, function
        )
        if source_index is not None and source_path is not None:
            structural_values = structural_values or getattr(requests, "values", None)
    if source_index is not None and source_path is not None:
        return _security_structural_helper_return(
            call,
            function,
            requests,
            caller_values,
            structural_values,
            source_path,
            source_index,
            resolve_call,
        )
    return _security_legacy_helper_return_value(
        call,
        function,
        requests,
        parameters,
        aliases,
        caller_values,
        _security_helper_binding,
        evaluate_helper_flow,
    )


def _security_legacy_helper_return_value(
    call, function, requests, parameters, aliases, caller_values, bind, evaluate
):
    binding = bind(call, function)
    if binding is None:
        return None
    module, actuals = binding
    initial = _security_helper_initial(
        call, actuals, requests, parameters, aliases, caller_values
    )
    if any(value is None for value in initial.values()):
        return None
    function._security_helper_active = True
    module._security_helper_flow_depth = (
        getattr(module, "_security_helper_flow_depth", 0) + 1
    )
    try:
        result = evaluate(
            function,
            initial,
            lambda expression, environment: _security_flow_value(
                expression, environment, aliases
            ),
        )
        value = (
            result["return_values"][0]
            if result["status"] == "COMPLETE" and len(result["return_values"]) == 1
            else None
        )
        if isinstance(value, _SecurityFlowValue):
            if len(value.steps) >= 62:
                return None
            value = _SecurityFlowValue(
                value.tainted,
                value.kind,
                (
                    *value.steps,
                    _security_flow_step(call, "ACTUAL_TO_FORMAL"),
                    _security_flow_step(function, "HELPER_RETURN"),
                ),
            )
        return value
    finally:
        function._security_helper_active = False
        module._security_helper_flow_depth -= 1


def _security_structural_helper_return(
    call,
    function,
    requests,
    caller_values,
    structural_values,
    source_path,
    source_index,
    resolve_call,
):
    from .finite_capture import security_structural_helper_summary

    roots = structural_values
    if roots is None:
        roots = getattr(requests, "values", None)
    if roots is None:
        roots = caller_values or {}
    summary = security_structural_helper_summary(
        call,
        function,
        roots,
        path=source_path,
        index=source_index,
        resolve_call=resolve_call,
    )
    return _security_structural_helper_flow_value(
        call, function, summary, source_path, source_index
    )


def _security_structural_helper_flow_value(
    call, function, summary, source_path, source_index
):
    """Project one exact structural helper result into legacy flow steps."""
    if summary.return_status != "COMPLETE" or len(summary.return_values) != 1:
        return None
    value = summary.return_values[0].value
    from .credential_role_identity_effects import _Value

    if (
        not isinstance(value, _Value)
        or value.unknown
        or value.content_unknown
        or value.scalar_kind not in {"text", "bytes"}
    ):
        return None
    from .review_integrity import bind_source_call

    try:
        actuals = bind_source_call(call, function, apply_defaults=True)
    except (TypeError, ValueError):
        return None
    actual_steps = {
        _security_flow_step(expression, "BOUND_EXPRESSION")
        for expression in actuals.values()
        if isinstance(expression, ast.expr)
    }
    from .credential_role_identity_effects import own_function_nodes

    function_nodes = own_function_nodes(function, source_path, source_index)
    actual_steps.update(
        _security_flow_step(node, "BOUND_EXPRESSION")
        for node in function_nodes
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id in actuals
    )
    matched_actual_steps = {
        step
        for step in value.trace
        if step and step[0] == "BOUND_EXPRESSION" and step in actual_steps
    }
    trace = [
        step
        for step in value.trace
        if not (value.roots and step in matched_actual_steps)
    ]
    helper_returns = {
        _security_flow_step(node, "HELPER_RETURN")
        for node in function_nodes
        if isinstance(node, ast.Return)
    }
    replace_return = bool(
        trace and trace[-1][0] == "HELPER_RETURN" and trace[-1] in helper_returns
    )
    if replace_return:
        trace[-1] = _security_flow_step(function, "HELPER_RETURN")
    if value.roots and matched_actual_steps:
        trace.insert(
            -1 if replace_return else len(trace),
            _security_flow_step(call, "ACTUAL_TO_FORMAL"),
        )
    return _SecurityFlowValue(bool(value.roots), value.scalar_kind, tuple(trace))


def _security_structural_call_flow_value(call, requests, aliases):
    """Resolve a captured helper call and project its exact source-bound return."""
    if not isinstance(call, ast.Call):
        return None
    from . import review_integrity as flow
    from .credential_role_identity_effects import resolve_source_identity_call
    from .finite_capture import security_structural_helper_summary

    function = flow._security_local_helper_definition(call)
    _module, source_index, source_path = _security_helper_source_context(call, function)
    roots = getattr(requests, "values", None)
    if source_index is None or source_path is None or not isinstance(roots, dict):
        return None
    if function is not None:
        summary = security_structural_helper_summary(
            call,
            function,
            roots,
            path=source_path,
            index=source_index,
            request_aliases=aliases,
        )
    else:
        resolved = resolve_source_identity_call(
            call, source_path, source_index, defer_negative_binding=True
        )
        if resolved is None:
            return None
        function = resolved.function
        summary = security_structural_helper_summary(
            call,
            function,
            roots,
            path=source_path,
            index=source_index,
            callee_path=resolved.path,
            source_resolved=True,
            negative_binding_closed=resolved.negative_binding_closed,
            negative_binding_check=resolved.negative_binding_check,
            request_aliases=aliases,
            resolve_call=lambda candidate, candidate_path: resolve_source_identity_call(
                candidate,
                candidate_path,
                source_index,
                defer_negative_binding=True,
            ),
        )
    return _security_structural_helper_flow_value(
        call, function, summary, source_path, source_index
    )


def _legacy_security_value(value):
    """Project shared origins into the old scalar API without discarding unknownness."""
    from .credential_role_identity_effects import _Value

    if not isinstance(value, _Value) or value.unknown or value.content_unknown:
        return None
    kind = value.scalar_kind
    if kind not in {"text", "bytes"}:
        return None
    steps = tuple(
        step for step in value.trace if isinstance(step, tuple) and len(step) == 3
    )
    return _SecurityFlowValue(bool(value.roots), kind, steps)


def _security_source_path(index, module):
    """Resolve an already captured module by identity, caching only its path map."""
    snapshots = getattr(index, "snapshots", None)
    if not isinstance(snapshots, dict) or not isinstance(module, ast.Module):
        return None
    cache = getattr(index, "_finite_capture_module_paths", None)
    if cache is None:
        cache = {id(tree): path for path, tree in snapshots.items()}
        index._finite_capture_module_paths = cache
    path = cache.get(id(module))
    return path if path is not None and snapshots.get(path) is module else None


def _security_helper_source_context(call, function):
    from . import review_integrity as flow

    module = flow._security_module_scope(getattr(call, "_security_lexical_scope", None))
    index = getattr(module, "_security_source_model", None)
    return module, index, _security_source_path(index, module)


def _captured_sink_enclosing_callable(node, parents):
    current = node
    while id(current) in parents:
        current = parents[id(current)]
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return current
    return None


def _captured_sink_parameter_names(scope):
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        return set()
    args = scope.args
    parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    parameters.extend(item for item in (args.vararg, args.kwarg) if item is not None)
    return {item.arg for item in parameters}


def _finite_source_span(node):
    return [
        getattr(node, key, None)
        for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
    ]


def source_built_ast_program_witness(node, call_name, *, source_bytes, source_path):
    """Prove a closed AST-to-code builder without executing its generated code."""
    from .finite_capture import (
        _fixed_program_span,
        _source_built_ast_scope,
        _source_built_ast_sink,
        _source_built_ast_builder,
    )

    parsed = _source_built_ast_input(
        node, call_name, source_bytes, source_path, _fixed_program_span
    )
    if parsed is None:
        return {}
    tree, parents, source_call, span = parsed
    builder = _source_built_ast_builder_pair(
        source_call,
        tree,
        parents,
        _source_built_ast_scope,
        _source_built_ast_sink,
        _source_built_ast_builder,
    )
    if builder is None:
        return {}
    sink, helper, owner = builder
    profile = _source_built_ast_profile(sink, helper, owner)
    return {
        "schema": "factory.source-built-ast-program.v1",
        "disposition": "PROVEN_SOURCE_BUILT_AST_PROGRAM",
        "source_path": source_path,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "call_span": span,
        "builder_ast_sha256": profile,
        "program_shape": "one-generated-function-with-closed-ast-construction",
        "input_effect": "data-enters-identifiers-or-constant-values-only",
        "runtime_assurance": "INCOMPLETE",
        "target_execution": "not_performed",
    }


def _source_built_ast_input(node, call_name, source_bytes, source_path, span_for):
    if (
        call_name != "exec"
        or not isinstance(node, ast.Call)
        or not isinstance(node.func, ast.Name)
        or node.func.id != "exec"
        or len(node.args) != 3
        or node.keywords
        or not isinstance(source_bytes, bytes)
        or len(source_bytes) > 128 * 1024
        or not isinstance(source_path, str)
    ):
        return None
    try:
        tree = ast.parse(source_bytes, filename=source_path)
    except (SyntaxError, ValueError, MemoryError, RecursionError, UnicodeError):
        return None
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    span = span_for(node)
    calls = [
        item
        for item in ast.walk(tree)
        if isinstance(item, ast.Call) and span_for(item) == span
    ]
    if span is None or len(calls) != 1 or ast.unparse(calls[0]) != ast.unparse(node):
        return None
    return tree, parents, calls[0], span


def _source_built_ast_builder_pair(
    source_call, tree, parents, scope_for, sink_is_closed, builder_is_closed
):
    sink = scope_for(source_call, parents)
    if (
        sink is None
        or sink.name != "_get_func_code"
        or not sink_is_closed(sink, source_call)
    ):
        return None
    owner = parents.get(sink)
    if not isinstance(owner, ast.ClassDef):
        return None
    builders = [
        item
        for item in owner.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.name == "_compile_builder"
    ]
    if len(builders) != 1:
        return None
    builder = builders[0]
    if not builder_is_closed(tree, builder, sink, parents):
        return None
    return sink, builder, owner


def _source_built_ast_profile(sink, builder, owner):
    profile_nodes = (
        sink,
        builder,
        *[
            item
            for item in owner.body
            if isinstance(item, ast.FunctionDef) and item.name == "_prefix_names"
        ],
    )
    return hashlib.sha256(
        "\n".join(
            ast.dump(item, include_attributes=False) for item in profile_nodes
        ).encode()
    ).hexdigest()


def security_input_value_flow(expression, requests, aliases):
    """Return a regenerable scalar input trace, not runtime authority or safety."""
    if hasattr(requests, "values"):
        helper_value = _security_structural_call_flow_value(
            expression, requests, aliases
        )
        if evidence := _security_input_flow_evidence(
            helper_value, value_type=_SecurityFlowValue
        ):
            return evidence
        from .credential_role_identity_effects import _Value

        from .finite_capture import security_structural_value

        value = security_structural_value(
            expression,
            requests.values,
            aliases,
            request_aliases=aliases,
        )
        if evidence := _security_input_flow_evidence(
            value,
            value_type=_Value,
        ):
            return evidence
        from .review_integrity import _security_module_scope

        module = _security_module_scope(
            getattr(expression, "_security_lexical_scope", None)
        )
        if getattr(module, "_security_source_model", None) is not None:
            return None

    environment = {name: True for name in requests if isinstance(name, str)}
    for item in requests:
        if (
            isinstance(item, tuple)
            and len(item) == 2
            and item[0] in {"request-type:text", "request-type:bytes"}
        ):
            environment[item[1]] = _SecurityFlowValue(True, item[0].split(":", 1)[1])
    known, value = _security_flow_value(expression, environment, aliases)
    if not known:
        return None
    return _security_input_flow_evidence(value, value_type=_SecurityFlowValue)


def _security_input_flow_evidence(value, *, value_type):
    import json

    if value_type is _SecurityFlowValue:
        if not isinstance(value, value_type) or not value.tainted:
            return None
        kind, steps = value.kind, value.steps
    else:
        if (
            not isinstance(value, value_type)
            or value.unknown
            or value.content_unknown
            or not value.roots
            or value.scalar_kind not in {"text", "bytes"}
        ):
            return None
        kind, steps = value.scalar_kind, value.trace
    evidence = {
        "schema": "factory.security.scalar-input-flow.v1",
        "value_kind": kind,
        "scope": "dangerous_argument_only",
        "runtime_execution": "not_performed",
        "steps": [
            {"operation": operation, "span": list(span), "ast_sha256": digest}
            for operation, span, digest in steps
            if isinstance(operation, str)
            and isinstance(span, tuple)
            and isinstance(digest, str)
        ],
    }
    evidence["trace_sha256"] = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return evidence


def _captured_path_expression(node, seen, resolve, callee, path_type):
    if isinstance(node, ast.Attribute):
        value = resolve(node.value, seen) if node.attr == "parent" else None
        return value.parent if isinstance(value, path_type) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left, right = resolve(node.left, seen), resolve(node.right, seen)
        return (
            left / right if isinstance(left, path_type) and type(right) is str else None
        )
    if not isinstance(node, ast.Call) or node.keywords:
        return None
    name = callee(node.func)
    values = [resolve(arg, seen) for arg in node.args]
    standard = _captured_standard_path_call(name, values, path_type)
    if standard is not None:
        return standard
    return _captured_method_path_call(node, values, resolve, seen, path_type)


def _captured_standard_path_call(name, values, path_type):
    if name == "pathlib.Path" and len(values) == 1 and isinstance(values[0], path_type):
        return values[0]
    if (
        name in {"os.path.abspath", "os.path.dirname"}
        and len(values) == 1
        and isinstance(values[0], path_type)
    ):
        return values[0].parent if name.endswith("dirname") else values[0]
    if (
        name == "os.path.join"
        and values
        and isinstance(values[0], path_type)
        and all(type(value) is str for value in values[1:])
    ):
        return values[0].joinpath(*values[1:])
    return None


def _captured_method_path_call(node, values, resolve, seen, path_type):
    if not isinstance(node.func, ast.Attribute):
        return None
    value = resolve(node.func.value, seen)
    if not isinstance(value, path_type):
        return None
    if node.func.attr in {"absolute", "resolve"} and not values:
        return value
    if node.func.attr == "joinpath" and all(type(item) is str for item in values):
        return value.joinpath(*values)
    return None
