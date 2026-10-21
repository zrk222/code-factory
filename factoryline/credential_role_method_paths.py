"""Enumerate bounded, separate source-flow routes to one HTTP URL slot."""

from .credential_role_class_binding import effective_method, scope_class
from .credential_role_method_contracts import source_current, source_span
from .credential_role_method_flow import _Flow
from .credential_role_method_return import enclosing_function
from .credential_role_forwarding_decorator import method_rows

_MAX_STATES = 128
_MAX_PATHS = 32


def method_url_hop_paths(
    fact,
    sink_path,
    call,
    expression,
    index,
    imports,
    classes,
    aliases,
    audit,
    integrity,
):
    """Return distinct caller/branch paths; status concerns enumeration only."""
    from .security_configuration import _keyword
    from .semantic_credential_sensor import _canonical_http_call

    if sink_path not in aliases or _canonical_http_call(
        call, aliases[sink_path]
    ) not in {"requests.request", "httpx.request"}:
        return _result("INCOMPLETE", [], "unsupported_sink")
    if _keyword(call, "url", 1) is not expression:
        return _result("INCOMPLETE", [], "unsupported_url_binding")
    if not source_current(index, sink_path):
        return _result("INCOMPLETE", [], "stale_sink_source")
    source_path = index.root / fact.path
    chain = _chain(fact, source_path, index, imports, classes, audit)
    if not chain:
        return _result("INCOMPLETE", [], "unresolved_class_chain")
    owner, function = (
        scope_class(call, index, sink_path),
        enclosing_function(call, index, sink_path),
    )
    if not _sink_method(chain, owner, function, sink_path):
        return _result("INCOMPLETE", [], "unresolved_sink_method")
    return _enumerate(
        fact,
        chain,
        index,
        imports,
        classes,
        aliases,
        audit,
        integrity,
        sink_path,
        call,
        expression,
        function,
    )


def _chain(fact, source_path, index, imports, classes, audit):
    from .credential_role_bindings import class_chain

    if not source_current(index, source_path):
        return None
    chain = class_chain(index, source_path, fact.owner, imports, classes, audit)
    if chain is None or any(not source_current(index, path) for path, _, _ in chain):
        return None
    return chain


def _sink_method(chain, owner, function, sink_path):
    return bool(
        chain
        and owner
        and function
        and (sink_path, owner.name) in {(path, name) for path, name, _ in chain}
        and effective_method(chain, function.name) == (sink_path, function)
    )


def _enumerate(
    fact,
    chain,
    index,
    imports,
    classes,
    aliases,
    audit,
    integrity,
    sink_path,
    call,
    expression,
    function,
):
    memo = getattr(index, "class_chain_memo", None)
    shared_methods = None
    deferred = bool(
        memo is not None and memo.defers_validation(index, imports, classes, audit)
    )
    if memo is not None:
        if not callable(getattr(memo, "valid", None)) or (
            not deferred and not memo.valid()
        ):
            return _result("INCOMPLETE", [], "snapshot_revalidation_failed")
        shared_methods = method_rows(chain, index, imports)
    pending, seen_states, seen_paths, paths = [frozenset()], set(), set(), []
    while pending and len(seen_states) < _MAX_STATES and len(paths) < _MAX_PATHS:
        blocked = pending.pop(0)
        if blocked in seen_states:
            continue
        seen_states.add(blocked)
        flow = _Flow(
            fact,
            chain,
            index,
            imports,
            classes,
            aliases,
            audit,
            integrity,
            blocked,
            shared_methods,
        )
        traced = flow.trace(expression, function, sink_path)
        if traced:
            path = _format_path(fact, traced, sink_path, call, index)
            key = tuple((r["path"], r["line"], r["column"], r["role"]) for r in path)
            if key not in seen_paths:
                seen_paths.add(key)
                paths.append(path)
        for choice in flow.branch_choices:
            candidate = blocked | {choice}
            if candidate not in seen_states and candidate not in pending:
                pending.append(candidate)
    complete = not pending
    if shared_methods is not None and not deferred and not memo.valid():
        return _result("INCOMPLETE", [], "snapshot_revalidation_failed")
    state = "BRANCH_ENUMERATION_COMPLETE" if complete else "INCOMPLETE"
    return _result(state, paths, None if complete else "branch_budget_exhausted")


def _format_path(fact, traced, sink_path, call, index):
    hops = [
        {
            "path": fact.path,
            "line": fact.line,
            "column": fact.column,
            "end_line": fact.end_line,
            "end_column": fact.end_column,
            "source_sha256": fact.source_sha256,
            "role": "declared_literal",
        }
    ]
    for path, node, role in reversed(traced):
        if not source_current(index, path):
            return []
        hops.append(source_span(index, path, node, role))
    hops.append(source_span(index, sink_path, call, "canonical_http_url_sink"))
    return hops


def _result(state, paths, reason):
    return {"state": state, "paths": paths, "reason": reason}
