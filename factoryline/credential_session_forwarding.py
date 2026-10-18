"""Source-only Session factory summaries with exact request-slot preservation."""

import ast
import hashlib


def _span(node):
    return [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset]


def _hop(path, node, kind, index):
    return {
        "path": index.relative(path),
        "source_sha256": hashlib.sha256(index.source_bytes[path]).hexdigest(),
        "span": _span(node),
        "kind": kind,
    }


def _body(function):
    body = list(function.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
    ):
        if isinstance(body[0].value.value, str):
            body.pop(0)
    while body and isinstance(body[0], (ast.Import, ast.ImportFrom)):
        body.pop(0)
    return body


def _construction(statement, aliases):
    from .security_configuration import _canonical

    if not (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and isinstance(statement.value, ast.Call)
        and not statement.value.args
        and not statement.value.keywords
        and _canonical(statement.value, aliases) == "requests.Session"
    ):
        return None
    return statement.targets[0].id


def _request_attribute(node, receiver):
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "request"
        and isinstance(node.value, ast.Name)
        and node.value.id == receiver
    )


def _timeout_forwarder(statement, receiver, aliases):
    from .security_configuration import _canonical

    if not (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and _request_attribute(statement.targets[0], receiver)
        and isinstance(statement.value, ast.Call)
    ):
        return False
    call = statement.value
    return bool(
        _canonical(call, aliases) == "functools.partial"
        and len(call.args) == 1
        and _request_attribute(call.args[0], receiver)
        and len(call.keywords) == 1
        and call.keywords[0].arg == "timeout"
        and isinstance(call.keywords[0].value, (ast.Constant, ast.Name, ast.Attribute))
    )


def _forwarder_provider_uncertain(tree, statement, aliases):
    from .review_integrity import _security_flow_bindings
    from .semantic_credential_sensor import _provider_identity_uncertain

    resolved, _ = _security_flow_bindings(statement.value, aliases)
    return _provider_identity_uncertain(tree, resolved, roots=("functools",))


def _factory_owner_valid(path, function, index):
    if not index.validate(path) or not isinstance(function, ast.FunctionDef):
        return False
    if function.decorator_list or id(function) not in index.parents[path]:
        return False
    owner = index.parents[path][id(function)]
    if not isinstance(owner, (ast.Module, ast.ClassDef)):
        return False
    if isinstance(owner, ast.ClassDef) and (owner.decorator_list or owner.keywords):
        return False
    from . import review_audits as audit
    from .credential_class_values import _class_bindings

    bindings = [
        statement
        for statement in owner.body
        if _class_bindings(statement, audit) & {function.name, "*"}
    ]
    if bindings != [function]:
        return False
    return True


def session_factory_witness(path, function, index, aliases):
    """Summarize a declared factory; never assert runtime adapter/provider identity."""
    from .review_integrity import bind_security_call_scopes, _security_flow_bindings
    from .semantic_credential_sensor import _provider_identity_uncertain

    if not _factory_owner_valid(path, function, index):
        return None
    tree = index.snapshots[path]
    if not hasattr(tree, "_security_scope_kind"):
        bind_security_call_scopes(tree)
    body = _body(function)
    if len(body) not in {2, 3}:
        return None
    receiver = _construction(body[0], aliases)
    if receiver is None:
        return None
    resolved, _ = _security_flow_bindings(body[0].value, aliases)
    if _provider_identity_uncertain(tree, resolved):
        return None
    returned = body[-1]
    if not (
        receiver
        and isinstance(returned, ast.Return)
        and isinstance(returned.value, ast.Name)
        and returned.value.id == receiver
    ):
        return None
    hops = [
        _hop(path, function, "declared_session_factory", index),
        _hop(path, body[0], "canonical_session_construction", index),
    ]
    if len(body) == 3:
        if not _timeout_forwarder(
            body[1], receiver, aliases
        ) or _forwarder_provider_uncertain(tree, body[1], aliases):
            return None
        hops.append(_hop(path, body[1], "timeout_only_request_forwarding", index))
    hops.append(_hop(path, returned, "factory_return", index))
    return {
        "provider": "requests.Session",
        "profile": "DECLARED_FACTORY_MAY_FLOW",
        "preserved_slots": ["method", "url", "auth", "headers"],
        "runtime_provider_identity": "UNASSESSED",
        "runtime_factory_dispatch": "UNASSESSED",
        "hops": hops,
    }
