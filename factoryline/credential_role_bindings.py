"""Bounded structural binding between declarations and consumer ASTs."""

import ast
from urllib.parse import urlsplit

from .credential_role_sources import (
    declaration_fact,
)
from .credential_role_scope_bindings import instance_receiver
from .credential_role_chain_memo import _import_binding_is_exact
from .credential_role_scope_bindings import match_name


def _class_ref(path, node, imports, classes, audit, index=None):
    name = audit._name(node) if isinstance(node, (ast.Name, ast.Attribute)) else ""
    if not name:
        return None
    parts = name.split(".")
    imported = imports.get(path, {}).get(parts[0])
    if imported:
        if index is not None and not _import_binding_is_exact(
            index, path, parts[0], imported
        ):
            return None
        target, symbol = imported
        if symbol:
            return (target, symbol) if len(parts) == 1 else None
        return (target, parts[1]) if len(parts) == 2 else None
    if len(parts) == 1 and (path, parts[0]) in classes:
        if index is None:
            return path, parts[0]
        from .credential_role_scope_bindings import binding_occurrences

        if index.validate(path):
            owner = classes[(path, parts[0])]
            definitions = binding_occurrences(index.snapshots[path].body, parts[0])
            if len(definitions) == 1 and definitions[0] is owner:
                return path, parts[0]
    return None


def class_chain(index, path, name, imports, classes, audit):
    """Resolve and memoize a class inheritance chain only while the import, class, and audit views still match."""
    memo = getattr(index, "class_chain_memo", None)
    if memo is None:
        return _uncached_class_chain(index, path, name, imports, classes, audit)
    if not memo.matches(imports, classes, audit):
        return None
    return memo.resolve(
        path,
        name,
        lambda: _uncached_class_chain(index, path, name, imports, classes, audit),
    )


def _uncached_class_chain(index, path, name, imports, classes, audit):
    from .credential_role_chain_memo import resolve_class_chain

    return resolve_class_chain(index, path, name, imports, classes, audit)


def _scope_assignments(function):
    rows = {}
    for statement in function.body:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            for target in targets:
                if isinstance(target, ast.Name):
                    rows.setdefault(target.id, []).append((statement, statement.value))
    return rows


def matches_fact(fact, path, node, index, imports, classes, audit, seen=()):
    """Match a credential fact to a name or attribute through bounded scope and import resolution; reject cycles and invalid snapshots."""
    if id(node) in seen or len(seen) > 8 or not index.validate(path):
        return False
    function, owner = _scope(node, index, path)
    if isinstance(node, ast.Name):
        return match_name(
            fact, path, node, function, index, imports, classes, audit, seen
        )
    if isinstance(node, ast.Attribute):
        return _match_attribute(fact, path, node, owner, index, imports, classes, audit)
    return False


def _scope(node, index, path):
    function = owner = None
    current = node
    while current is not None:
        current = index.parents[path].get(id(current))
        if (
            isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef))
            and function is None
        ):
            function = current
        if isinstance(current, ast.ClassDef) and owner is None:
            owner = current
    return function, owner


def _match_attribute(fact, path, node, owner, index, imports, classes, audit):
    if isinstance(node.value, ast.Name) and node.value.id == "self":
        function, _ = _scope(node, index, path)
        chain = (
            class_chain(
                index, index.root / fact.path, fact.owner, imports, classes, audit
            )
            if owner
            else None
        )
        return bool(
            owner
            and instance_receiver(node, function, owner, index, path)
            and fact.owner != "<module>"
            and fact.source_role in {"class_literal", "instance_literal"}
            and node.attr == fact.member
            and chain
            and (path, owner.name) in {(p, name) for p, name, _ in chain}
        )
    function, _ = _scope(node, index, path)
    root = node.value
    from .credential_role_scope_bindings import function_bindings

    if isinstance(root, ast.Attribute):
        while isinstance(root, ast.Attribute):
            root = root.value
    if isinstance(root, ast.Name) and function is not None:
        bindings = function_bindings(function, root.id, audit)
        if bindings is None or bindings:
            return False
    if fact.source_role not in {"class_literal", "module_literal"}:
        return False
    resolved = _class_ref(path, node.value, imports, classes, audit, index)
    ancestry = (
        class_chain(index, *resolved, imports, classes, audit) if resolved else ()
    )
    return bool(
        ancestry
        and node.attr == fact.member
        and (index.root / fact.path, fact.owner)
        in {(p, name) for p, name, _ in ancestry}
    )


def url_use(fact, record, evidence, publications):
    """Record URL user-info as an authentication use, matched publications as sanitized witnesses, and unmatched URLs as unknown links."""
    parsed = urlsplit(fact._literal)
    if parsed.username and parsed.password:
        record["slot"] = "http_url_userinfo"
        evidence["known_auth_uses"].append(record)
    elif fact._literal in publications:
        publication = dict(publications[fact._literal])
        publication.pop("value", None)
        record["publication"] = publication
        evidence["url_witnesses"].append(record)
    else:
        evidence["linked_unknown_uses"].append(
            {**record, "reason": "endpoint_publication_unmatched"}
        )


def _literal_target(node):
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    value = getattr(node, "value", None)
    if (
        len(targets) != 1
        or not isinstance(value, ast.Constant)
        or not isinstance(value.value, str)
    ):
        return None
    target = targets[0]
    if isinstance(target, ast.Name):
        return target.id
    if (
        isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Name)
        and target.value.id == "self"
    ):
        return target.attr
    return None


def auth_constructor_password(call, path, aliases):
    """Return the password expression only for the supported requests or httpx basic-auth constructor forms."""
    from .security_configuration import _canonical

    if _canonical(call, aliases[path]) not in {
        "requests.auth.HTTPBasicAuth",
        "httpx.BasicAuth",
    }:
        return None
    if len(call.args) == 2 and not call.keywords:
        return call.args[1]
    if not call.args and sorted(item.arg for item in call.keywords) == [
        "password",
        "username",
    ]:
        return next(item.value for item in call.keywords if item.arg == "password")
    return None


def candidate_facts(index, snapshots, sink_rows, publications):
    """Collect literal declaration facts whose member names or values occur in sink expressions or endpoint publications."""
    names = {
        part
        for _, _, _, _, expr, *_ in sink_rows
        for node in ast.walk(expr)
        for part in (
            (node.id,)
            if isinstance(node, ast.Name)
            else (node.attr,)
            if isinstance(node, ast.Attribute)
            else ()
        )
    }
    facts = []
    for path, tree in snapshots.items():
        if not isinstance(tree, ast.Module):
            continue
        for node in ast.walk(tree):
            if (
                not isinstance(node, (ast.Assign, ast.AnnAssign))
                or _literal_target(node) is None
            ):
                continue
            fact = declaration_fact(index, path, node)
            if fact and (fact.member in names or fact._literal in publications):
                facts.append(fact)
    return facts
