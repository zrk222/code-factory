"""Exact consumer roles for getter results; never candidate-origin witnesses."""

import ast
from copy import deepcopy

from .credential_publication_catalog import endpoint_publication
from .credential_role_method_evidence import source_span
from .review_integrity import (
    _security_flow_assignment,
    _security_flow_bindings,
    _security_scope_body,
    _security_scope_initial,
)
from .security_configuration import _canonical
from .semantic_credential_sensor import (
    _canonical_http_call,
    _provider_identity_uncertain,
)

METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def getter_consumer_role(node, index, path, audit):
    """Classify this exact result use without resolving the getter receiver."""
    if not index.validate(path):
        return None
    parents = index.parents[path]
    result = parents.get(id(node))
    if (
        not isinstance(result, ast.Call)
        or result.func is not node
        or result.args
        or result.keywords
    ):
        return None
    parent = parents.get(id(result))
    if isinstance(parent, ast.Expr) and parent.value is result:
        return source_span(index, path, result, "verified_discarded_getter_result")
    aliases = _imports(index.snapshots[path], audit)
    _security_flow_bindings(result, aliases)
    preceding = _preceding_bindings(result, aliases, audit)
    scope = getattr(result, "_security_lexical_scope", None)
    lexical = getattr(scope, "_security_flow_final", ({}, {}))[0]
    if _provider_result(index, path, lexical, records=False):
        return None
    parent = parents.get(id(result))
    outer = parents.get(id(parent)) if isinstance(parent, ast.keyword) else parent
    direct, _ = (
        _security_flow_bindings(outer, aliases)
        if isinstance(outer, ast.Call)
        else ({}, {})
    )
    if isinstance(outer, ast.Call) and _url_slot(outer, direct) is result:
        return source_span(index, path, result, "verified_url_consumer_result")
    if _provider_result(index, path, lexical):
        return None
    if _url_comparison(parent, result, parents, index, path, preceding):
        return source_span(index, path, result, "verified_url_comparison_result")
    if _url_matcher(parent, result, index, path, preceding):
        return source_span(index, path, result, "verified_url_matcher_result")
    return None


def _preceding_bindings(node, aliases, audit):
    scope = getattr(node, "_security_lexical_scope", None)
    if scope is None:
        return {}
    resolved, constants = _security_scope_initial(scope, aliases)
    for statement in _security_scope_body(scope):
        if any(child is node for child in ast.walk(statement)):
            return resolved
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            resolved.update(audit._security_aliases([statement]))
        else:
            _security_flow_assignment(statement, resolved, constants)
    return {}


def _url_slot(call, aliases):
    root = call.func
    while isinstance(root, ast.Attribute):
        root = root.value
    if not isinstance(root, ast.Name) or root.id not in aliases:
        return None
    canonical = _canonical(call, aliases)
    if canonical in {"responses.add", "responses.replace"}:
        position = 1
    elif canonical in {"responses." + method for method in METHODS}:
        position = 0
    else:
        http = _canonical_http_call(call, aliases)
        if not http:
            return None
        position = 1 if http.endswith(".request") else 0
    if any(isinstance(arg, ast.Starred) for arg in call.args):
        return None
    names = [keyword.arg for keyword in call.keywords]
    if None in names or len(names) != len(set(names)):
        return None
    values = [call.args[position]] if len(call.args) > position else []
    values.extend(keyword.value for keyword in call.keywords if keyword.arg == "url")
    return values[0] if len(values) == 1 else None


def _url_comparison(parent, result, parents, index, path, aliases):
    if (
        not isinstance(parent, ast.Compare)
        or len(parent.ops) != 1
        or not isinstance(parent.ops[0], ast.Eq)
    ):
        return False
    left, right = parent.left, parent.comparators[0]
    other = right if left is result else left if right is result else None
    if other is None:
        return False
    if _request_url(other, index, path, aliases):
        return True
    assertion = parents.get(id(parent))
    return bool(
        isinstance(assertion, ast.Assert)
        and assertion.test is parent
        and isinstance(other, ast.Constant)
        and isinstance(other.value, str)
        and endpoint_publication(other.value) is not None
    )


def _url_matcher(parent, result, index, path, aliases):
    return bool(
        isinstance(parent, ast.Call)
        and isinstance(parent.func, ast.Attribute)
        and parent.func.attr in {"startswith", "endswith"}
        and len(parent.args) == 1
        and parent.args[0] is result
        and not parent.keywords
        and _request_url(parent.func.value, index, path, aliases)
    )


def _request_url(node, index, path, aliases):
    if isinstance(node, ast.Call) and _canonical(node, aliases) == "typing.cast":
        if len(node.args) != 2 or node.keywords:
            return False
        node = node.args[1]
    if not isinstance(node, ast.Attribute) or node.attr != "url":
        return False
    request = node.value
    if not isinstance(request, ast.Attribute) or request.attr != "request":
        return False
    return _recorded_call(request.value, index, path, aliases)


def _recorded_call(node, index, path, aliases):
    if isinstance(node, ast.Subscript):
        return bool(
            _named(node.value, aliases) == "responses.calls"
            and isinstance(node.slice, ast.Constant)
            and type(node.slice.value) is int
            and node.slice.value >= 0
        )
    if not isinstance(node, ast.Name):
        return False
    current = index.parents[path].get(id(node))
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return False
        if isinstance(current, (ast.GeneratorExp, ast.ListComp, ast.SetComp)):
            if len(current.generators) != 1:
                return False
            generator = current.generators[0]
            return bool(
                isinstance(generator.target, ast.Name)
                and generator.target.id == node.id
                and _named(generator.iter, aliases) == "responses.calls"
            )
        current = index.parents[path].get(id(current))
    return False


def _named(node, aliases):
    if isinstance(node, ast.Name):
        return aliases.get(node.id, "")
    if isinstance(node, ast.Attribute):
        base = _named(node.value, aliases)
        return base + "." + node.attr if base else ""
    return ""


def _imports(tree, audit):
    aliases = dict(audit._module_security_aliases(tree))
    for node in tree.body:
        if isinstance(node, ast.Import):
            for name in node.names:
                if name.name in {"responses", "typing", "requests", "httpx"}:
                    aliases[name.asname or name.name] = name.name
        elif isinstance(node, ast.ImportFrom) and node.module in {
            "responses",
            "typing",
            "requests",
            "httpx",
        }:
            for name in node.names:
                if name.name != "*":
                    aliases[name.asname or name.name] = node.module + "." + name.name
    return aliases


def _provider_mutated(tree, aliases, records=True):
    from .credential_role_getter_records import _record_escape

    if records and _record_escape(tree, aliases):
        return True

    class RecordedReads(ast.NodeTransformer):
        def visit_Attribute(self, node):
            if isinstance(node.ctx, ast.Load) and _named(node, aliases) in {
                "responses.calls",
                *("responses." + method.upper() for method in METHODS),
            }:
                return ast.copy_location(ast.Constant(None), node)
            return self.generic_visit(node)

    checked = RecordedReads().visit(deepcopy(tree))
    return _provider_identity_uncertain(
        checked, aliases, roots=("requests", "httpx", "responses", "typing")
    )


def _provider_result(index, path, aliases, records=True):
    """Reuse pure checks only inside a derivation with final fresh validation."""
    memo = getattr(index, "class_chain_memo", None)
    if memo is None:
        return _provider_mutated(index.snapshots[path], aliases, records)
    cache = getattr(memo, "getter_provider_checks", {})
    key = (
        path,
        id(index.snapshots[path]),
        index.inventory.get(path),
        tuple(sorted(aliases.items())),
        records,
        _provider_mutated,
    )
    if key not in cache:
        cache[key] = _provider_mutated(index.snapshots[path], aliases, records)
    memo.getter_provider_checks = cache
    return cache[key]
