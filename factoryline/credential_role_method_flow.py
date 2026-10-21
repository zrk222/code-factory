"""Bounded source-only propagation through declared instance methods."""

import ast
from .credential_role_bindings import class_chain, matches_fact
from .credential_role_class_binding import (
    effective_method,
    scope_class,
)
from .credential_role_method_contracts import alias_value
from .credential_role_method_contracts import (
    source_current as _current,
    source_span as _span,
)
from .credential_role_forwarding_decorator import method_rows
from .credential_role_method_return import (
    enclosing_function,
    is_parameter,
    method_returns,
    verified_instance_receiver,
)
from .credential_role_method_call import call_argument, trace_call, trace_return


class _Flow:
    def __init__(
        self,
        fact,
        chain,
        index,
        imports,
        classes,
        aliases,
        audit,
        integrity,
        blocked_choices=frozenset(),
        method_table=None,
    ):
        self.fact, self.chain, self.index = fact, chain, index
        self.imports = imports
        self.classes = classes
        self.aliases = aliases
        self.audit = audit
        self.integrity = integrity
        self.blocked_choices = blocked_choices
        self.branch_choices = []
        self.methods, self.decorator_proofs = method_table or method_rows(
            chain, index, imports
        )

    def trace(
        self, expression, function, path, seen=frozenset(), depth=0, bindings=None
    ):
        if depth > 8 or not self.index.validate(path):
            return None
        marker = (path, id(function), id(expression))
        if marker in seen:
            return None
        seen = seen | {marker}
        if matches_fact(
            self.fact,
            path,
            expression,
            self.index,
            self.imports,
            self.classes,
            self.audit,
        ):
            return [(path, expression, "declared_member_read")]
        if isinstance(expression, ast.Name):
            return self._trace_name(expression, function, path, seen, depth, bindings)
        if isinstance(expression, ast.Call):
            return trace_call(self, expression, function, path, seen, depth, bindings)
        if isinstance(expression, ast.BoolOp):
            return self._trace_boolean(
                expression, function, path, seen, depth, bindings
            )
        return None

    def _trace_name(self, expression, function, path, seen, depth, bindings):
        if is_parameter(function, expression.id):
            if bindings is not None:
                context = bindings.get(expression.id)
                if context is None:
                    return None
                actual, caller, caller_path, parent_bindings = context
                return self.trace(
                    actual, caller, caller_path, seen, depth + 1, parent_bindings
                )
            return self._call_argument(expression.id, function, seen, depth)
        alias = alias_value(expression, function)
        if alias:
            found = self.trace(alias[0], function, path, seen, depth + 1, bindings)
            return self._prepend("unique_local_alias", path, alias[1], found)
        return None

    def _trace_boolean(self, expression, function, path, seen, depth, bindings):
        if not isinstance(expression.op, ast.Or):
            return None
        for offset, operand in enumerate(expression.values):
            choice = ("boolean", id(expression), offset)
            if choice in self.blocked_choices:
                continue
            found = self.trace(operand, function, path, seen, depth + 1, bindings)
            if found:
                self.branch_choices.append(choice)
                found = self._prepend("declared_boolean_operand", path, operand, found)
                return self._prepend(
                    "declared_boolean_value_choice", path, expression, found
                )
            if isinstance(operand, ast.Constant) and bool(operand.value):
                break
        return None

    def _return_call(self, expression, caller, caller_path, seen, depth, bindings=None):
        target = expression.func
        if (
            not isinstance(target, ast.Attribute)
            or not isinstance(target.value, ast.Name)
            or target.value.id != "self"
        ):
            return None
        row = self.methods.get(target.attr)
        if row is None:
            return None
        receiver_owner = scope_class(expression, self.index, caller_path)
        if receiver_owner is None or not verified_instance_receiver(
            expression,
            caller,
            receiver_owner,
            self.index,
            caller_path,
            bool(self.decorator_proofs.get(caller.name)),
        ):
            return None
        path, function, _ = row
        returns = method_returns(function, self.index, path)
        if not returns:
            return None
        from .credential_role_method_call import _callee_bindings

        callee_bindings = _callee_bindings(
            self, expression, function, caller, caller_path, bindings
        )
        if callee_bindings is None:
            return None
        traces = []
        for row in returns:
            choice = ("return", id(expression), id(row))
            if choice in self.blocked_choices:
                continue
            traced = trace_return(
                self,
                row,
                expression,
                path,
                function,
                caller,
                caller_path,
                seen,
                depth,
                bindings,
                callee_bindings,
            )
            if traced:
                self.branch_choices.append(choice)
                traces = self._prepend("declared_method_return", path, row, traced)
                break
        found = traces or None
        for proof_path, proof_function in self.decorator_proofs.get(target.attr, ()):
            found = self._prepend(
                "verified_return_preserving_decorator",
                proof_path,
                proof_function,
                found,
            )
        return self._prepend("method_call", caller_path, expression, found)

    def _call_argument(self, name, function, seen, depth):
        return call_argument(self, name, function, seen, depth)

    @staticmethod
    def _prepend(role, path, node, found):
        return [(path, node, role), *found] if found else None


def method_url_hops(
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
    """Trace URL arguments through source-defined self-method returns/calls."""
    from .security_configuration import _keyword
    from .semantic_credential_sensor import _canonical_http_call

    if sink_path not in aliases or _canonical_http_call(
        call, aliases[sink_path]
    ) not in {"requests.request", "httpx.request"}:
        return None
    if _keyword(call, "url", 1) is not expression:
        return None
    if not _current(index, sink_path):
        return None
    source_path = index.root / fact.path
    chain = class_chain(index, source_path, fact.owner, imports, classes, audit)
    if chain is None or any(not _current(index, path) for path, _, _ in chain):
        return None
    owner, function = (
        scope_class(call, index, sink_path),
        enclosing_function(call, index, sink_path),
    )
    if (
        not chain
        or owner is None
        or function is None
        or (sink_path, owner.name) not in {(p, n) for p, n, _ in chain}
    ):
        return None
    if effective_method(chain, function.name) != (sink_path, function):
        return None
    traced = _Flow(
        fact, chain, index, imports, classes, aliases, audit, integrity
    ).trace(expression, function, sink_path)
    if not traced:
        return None
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
        if not index.validate(path):
            return None
        hops.append(_span(index, path, node, role))
    hops.append(_span(index, sink_path, call, "canonical_http_url_sink"))
    return hops
