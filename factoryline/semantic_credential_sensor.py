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

    if (
        set(source_bytes) != set(bindings)
        or len(bindings) > 2000
        or sum(len(raw) for raw in source_bytes.values() if isinstance(raw, bytes))
        > 32 * 1024 * 1024
    ):
        return None
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
    index = SourceSnapshotIndex(Path("."), snapshots, captured, inventory)
    paths = index.module_paths()
    if paths is None:
        return None
    aliases = {
        path: _security_aliases(list(ast.walk(tree)))
        for path, tree in snapshots.items()
    }
    return {"index": index, "paths": paths, "aliases": aliases}


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
            return _signing_configuration_witness(index, path, declaration, witness)
    return None


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


def _flask_config_mutated(scope, receiver):
    from .review_audits import _name

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
                or node.slice.value == "SECRET_KEY"
            ):
                return True
    return False


def _flask_configuration_reloaded(scope, receiver, target, context):
    from .review_audits import _name

    for statement in scope.body:
        call = getattr(statement, "value", None)
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
            continue
        if _name(call.func.value) != receiver + ".config":
            continue
        if call.func.attr == "from_object" and not _flask_config_load(
            call, receiver, target, context
        ):
            return True
        if call.func.attr in {
            "update",
            "from_mapping",
        } and _flask_mapping_may_replace_key(call):
            return True
    return False


def _flask_mapping_may_replace_key(call):
    if any(kw.arg in {None, "SECRET_KEY"} for kw in call.keywords):
        return True
    for arg in call.args:
        if not isinstance(arg, ast.Dict):
            return True
        if any(
            not isinstance(key, ast.Constant) or key.value == "SECRET_KEY"
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


def _flask_config_load(call, receiver, target, context):
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "from_object"
        and isinstance(call.func.value, ast.Attribute)
        and call.func.value.attr == "config"
        and isinstance(call.func.value.value, ast.Name)
        and call.func.value.value.id == receiver
        and len(call.args) == 1
        and not call.keywords
        and _signing_resolve_module(context, call.args[0]) == target
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
                scope, receiver, target, context
            ):
                continue
            calls = _flask_configuration_calls(call, receiver, target, context)
            if calls:
                return {
                    "framework": "flask",
                    "transfers": [
                        _signing_source_span(context["index"], path, node)
                        for node in [creation, *calls]
                    ],
                }
    return None


def _flask_configuration_calls(call, receiver, target, context):
    from .review_integrity import _security_local_helper_definition

    if _flask_config_load(call, receiver, target, context):
        return [call]
    helper = _security_local_helper_definition(call)
    formal = _signing_helper_receiver(helper, call, receiver)
    if (
        formal is None
        or _flask_config_mutated(helper, formal)
        or _flask_configuration_reloaded(helper, formal, target, context)
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
            and _flask_config_load(load, formal, target, context)
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
    from .review_audits import _name

    if isinstance(node, ast.Subscript):
        return (
            isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
            and _http_request_mapping(node.value, aliases, scope, flow_statement, alias_reader, node.slice.value)
        )
    if isinstance(node, ast.Call):
        parts = _credential_get_source_key(node)
        return bool(
            parts is not None
            and isinstance(parts[1], ast.Constant)
            and isinstance(parts[1].value, str)
            and _http_request_mapping(parts[0], aliases, scope, flow_statement, alias_reader, parts[1].value)
        )
    if not isinstance(node, ast.Attribute) or not isinstance(node.ctx, ast.Load):
        return False
    resolved = alias_reader(scope, aliases, flow_statement)
    raw = _name(node)
    head, _, tail = raw.partition(".")
    canonical = resolved.get(head, "") + ("." + tail if tail else "")
    if canonical == "flask.request.data":
        return True
    return _django_http_body_payload(node, scope, resolved)


def request_payload_value_kind(node, requests, aliases, alias_reader):
    """Carry modeled request text/bytes through explicit codec operations only."""
    if isinstance(node, ast.Name):
        for kind in ("bytes", "text"):
            if ("request-type:" + kind, node.id) in requests:
                return kind
        return None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        codec = node.func.attr
        if codec in {"encode", "decode"} and not node.args and not node.keywords:
            original = request_payload_value_kind(node.func.value, requests, aliases, alias_reader)
            if original == ("text" if codec == "encode" else "bytes"):
                return "bytes" if codec == "encode" else "text"
    if http_request_payload(node, aliases, getattr(node, "_security_lexical_scope", None),
                            getattr(node, "_security_flow_statement", None), alias_reader):
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
        return canonical == "flask.request.get_json" and _request_mapping_value_unchanged(node, scope, key)
    recognized = canonical in {
        "flask.request.args", "flask.request.form", "flask.request.json",
    } or _django_http_body_payload(node, scope, resolved, {"GET", "POST"})
    return recognized and _request_mapping_value_unchanged(node, scope, key)


def _request_mapping_aliases(node, nodes):
    origin, aliases = ast.dump(node, include_attributes=False), set()

    def references(value):
        return (
            isinstance(value, (ast.Attribute, ast.Call)) and ast.dump(value, include_attributes=False) == origin
            or isinstance(value, ast.Name) and value.id in aliases
        )

    for _ in range(len(nodes)):
        before = len(aliases)
        for item in nodes:
            if isinstance(item, (ast.Assign, ast.AnnAssign)) and references(item.value):
                targets = item.targets if isinstance(item, ast.Assign) else [item.target]
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
    if isinstance(item, ast.Subscript) and isinstance(item.ctx, (ast.Store, ast.Del)) and references(item.value):
        return not (isinstance(item.slice, ast.Constant) and isinstance(item.slice.value, str) and item.slice.value != key)
    if isinstance(item, ast.Attribute) and isinstance(item.ctx, (ast.Store, ast.Del)) and references(item.value):
        return True
    if isinstance(item, ast.Call):
        if isinstance(item.func, ast.Attribute) and references(item.func.value):
            return _credential_get_source_key(item) is None
        return any(references(value) for value in [*item.args, *(kw.value for kw in item.keywords)])
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
    inventory = [
        node
        for node in nodes
        if id(node) not in payload_children
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


def security_precondition_call_shape(node, canonical):
    """Restrict support to modeled, unambiguous dangerous argument slots."""
    if len(node.args) != 1 or isinstance(node.args[0], ast.Starred):
        return False
    keywords = {item.arg: item.value for item in node.keywords}
    if None in keywords or len(keywords) != len(node.keywords):
        return False
    if canonical in {
        "eval",
        "exec",
        "builtins.eval",
        "builtins.exec",
        "os.system",
        "pickle.loads",
        "_pickle.loads",
        "dill.loads",
        "yaml.unsafe_load",
    }:
        return not keywords
    if canonical in {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
    }:
        return (
            set(keywords) == {"shell"}
            and isinstance(keywords["shell"], ast.Constant)
            and keywords["shell"].value is True
        )
    if canonical == "yaml.load" and set(keywords) == {"Loader"}:
        from .review_audits import _name
        from .review_integrity import _security_flow_bindings

        resolved, _constants = _security_flow_bindings(node, {})
        raw = _name(keywords["Loader"])
        head, _, tail = raw.partition(".")
        return resolved.get(head, "") + ("." + tail if tail else "") in {
            "yaml.Loader",
            "yaml.UnsafeLoader",
            "yaml.CLoader",
            "yaml.CUnsafeLoader",
        }
    return False


def security_precondition_path_possible(node):
    """Reject syntactically dead or unmodeled short-circuit sink positions."""
    child = node
    while (parent := getattr(child, "_security_parent", None)) is not None:
        if isinstance(parent, (ast.If, ast.While, ast.IfExp)):
            test = parent.test
            if isinstance(test, ast.Constant):
                body = parent.body
                in_body = child in body if isinstance(body, list) else child is body
                other = getattr(parent, "orelse", [])
                in_other = child in other if isinstance(other, list) else child is other
                if (in_body and not bool(test.value)) or (
                    in_other and bool(test.value)
                ):
                    return False
        if isinstance(parent, ast.BoolOp) and child is not parent.values[0]:
            return False
        for _field, value in ast.iter_fields(parent):
            if isinstance(value, list) and child in value:
                previous = value[: value.index(child)]
                if any(
                    isinstance(item, (ast.Return, ast.Raise, ast.Break, ast.Continue))
                    for item in previous
                ):
                    return False
        child = parent
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
