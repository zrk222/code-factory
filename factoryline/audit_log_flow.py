"""Bounded source-to-log flow recognition for Python security audits."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from itertools import chain
from .semantic_credential_sensor import log_percent_slots, log_scalar_metadata
from . import credential_role_paths as log_evidence

_LOGGING_LEVELS = frozenset("debug info warning error critical exception log".split())


def audit_log_source_findings(relative, tree, nodes, aliases):
    """Find unneutralized input values passed to proven stdlib logging calls."""
    from . import review_audits as audit
    from .review_integrity import (
        _security_django_request_parameter,
        _security_flask_request_collection,
        _security_flow_bindings,
        _security_module_scope,
        _security_scope_local_names,
        _security_ast_span_contains,
        security_call_name,
    )

    from .semantic_credential_sensor import log_security_provider_stable

    tree._security_log_provider_stable = log_security_provider_stable(
        tree, aliases, nodes
    )
    findings = []
    for scope in nodes:
        if not isinstance(scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        calls_by_statement = getattr(scope, "_security_calls_by_statement", {})
        reader = _LogReader(
            relative,
            scope,
            aliases,
            findings,
            audit,
            _security_django_request_parameter,
            _security_flask_request_collection,
            _security_flow_bindings,
            security_call_name,
            _security_module_scope,
            _security_scope_local_names,
            _security_ast_span_contains,
            calls_by_statement,
            tuple(chain.from_iterable(calls_by_statement.values())),
        )
        reader._block(scope.body, {})
    return findings


@dataclass(frozen=True)
class _LogReader:
    """Hold immutable scope bindings while analyzing one mutable taint state."""

    relative: str
    scope: ast.AST
    aliases: dict
    findings: list
    audit: object
    django_source: object
    flask_source: object
    flow_bindings: object
    resolve: object
    module_scope: object
    module_names: object
    span_contains: object
    calls_by_statement: dict
    scope_calls: tuple

    def _block(self, body, tainted, snapshots=None):
        for statement in body:
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue
            if isinstance(statement, ast.Try):
                self._try_block(statement, tainted)
                continue
            if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                self._loop(statement, tainted)
                continue
            if isinstance(statement, ast.If):
                self._calls(statement.test, tainted, statement)
                branches = [dict(tainted), dict(tainted)]
                self._block(statement.body, branches[0], snapshots)
                self._block(statement.orelse, branches[1], snapshots)
                tainted.clear()
                tainted.update(log_evidence.logging_merge_log_flow(branches))
                continue
            if isinstance(statement, (ast.With, ast.AsyncWith)):
                self._with_block(statement, tainted, snapshots)
                continue
            self._calls(statement, tainted)
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                self._assign(statement, tainted, snapshots)
            elif not isinstance(
                statement, (ast.Expr, ast.Return, ast.Raise, ast.Assert)
            ):
                for name in self.audit._bound_names(statement):
                    tainted.pop(name, None)

    def _with_block(self, statement, tainted, snapshots):
        for item in statement.items:
            self._calls(item.context_expr, tainted, statement)
            if item.optional_vars is not None:
                for name in self.audit._bound_names(item.optional_vars):
                    tainted.pop(name, None)
        self._block(statement.body, tainted, snapshots)

    def _loop(self, statement, tainted):
        expression = (
            statement.test if isinstance(statement, ast.While) else statement.iter
        )
        self._calls(expression, tainted, statement)
        entry, body = dict(tainted), dict(tainted)
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            for name in self.audit._bound_names(statement.target):
                body.pop(name, None)
                if self._flow(statement.iter, entry, True):
                    body[name] = self._flow(statement.iter, entry)
        self._block(statement.body, body)
        self._block(statement.orelse, body)
        tainted.clear()
        tainted.update(log_evidence.logging_merge_log_flow([entry, body]))

    def _try_block(self, statement, tainted):
        normal, snapshots = dict(tainted), []
        self._block(statement.body, normal, snapshots)
        if statement.orelse:
            self._block(statement.orelse, normal)
        outcomes = [normal]
        for handler in statement.handlers:
            state = (
                log_evidence.logging_merge_log_flow(snapshots)
                if snapshots and _catches_value_error(handler.type)
                else dict(tainted)
            )
            self._block(handler.body, state)
            outcomes.append(state)
        merged = log_evidence.logging_merge_log_flow(outcomes)
        self._block(statement.finalbody, merged)
        tainted.clear()
        tainted.update(merged)

    def _calls(self, expression, tainted, owner=None):
        calls = self.calls_by_statement.get(id(owner), ()) if owner else ()
        if not calls:
            calls = self.scope_calls
        for call in calls:
            if not self.span_contains(call, expression):
                continue
            name = self._logging_name(call)
            source_value = self._unsafe(call, tainted, name) if name else None
            if source_value is not None:
                module = self.module_scope(self.scope)
                self.findings.append(
                    self.audit._security_finding(
                        "SECURITY_LOG_INJECTION",
                        self.relative,
                        call,
                        "Input may reach a log message without neutralizing carriage return and line feed.",
                        "HIGH",
                        call=name,
                        source="input_or_request_parameter",
                        cwe="CWE-117",
                        **log_evidence.logging_security_precondition(
                            module, call, source_value, name, self.aliases, tainted
                        ),
                    )
                )

    def _logging_name(self, call):
        resolved, _constants = self.flow_bindings(call, self.aliases)
        name = self.resolve(call, self.aliases).replace(
            "logging.Logger.", "logging.", 1
        )
        imported_logging = any(
            target == "logging" or target.startswith("logging.")
            for target in resolved.values()
        )
        return (
            name
            if imported_logging
            and name.startswith("logging.")
            and name.removeprefix("logging.") in _LOGGING_LEVELS
            else ""
        )

    def _unsafe(self, call, tainted, name):
        keyword = next(
            (item.value for item in call.keywords if item.arg == "msg"), None
        )
        index = 1 if name == "logging.log" else 0
        offset = index + 1
        positional = len(call.args) > index
        message = call.args[index] if positional else keyword
        if message is None:
            return False
        values = [message, *(call.args[offset:] if positional else [])]
        values.extend(
            item.value for item in call.keywords if item.arg in {"args", "values"}
        )
        if self._percent_repr(message, values[1:], tainted):
            return None
        return next(
            (
                value
                for value in values
                if self._flow(value, tainted) and not self._safe(value, tainted)
            ),
            None,
        )

    def _flow(self, node, tainted, provenance=False):
        if isinstance(node, ast.Name):
            value = tainted.get(node.id, False)
            return (
                node.id in tainted if provenance else getattr(value, "tainted", value)
            )
        if log_scalar_metadata(node, self):
            return False
        if self._source(node):
            return True
        children = self._children(node)
        if provenance:
            return any(self._flow(child, tainted, True) for child in children)
        if any(self._flow(child, tainted, True) for child in children):
            return not self._safe(node, tainted)
        return any(self._flow(child, tainted) for child in children)

    def _source(self, node):
        if isinstance(node, ast.Call):
            name = self.resolve(node, self.aliases)
            if name in {"input", "builtins.input"} and self._builtin_unshadowed(
                node, name
            ):
                return True
        if isinstance(node, ast.Subscript):
            base = node.value
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
        ):
            base = node.func.value
        else:
            return False
        if not isinstance(base, ast.Attribute):
            return False
        flow = getattr(node, "_security_flow_statement", None)
        flask_parameter = base.attr in {"args", "form"} and self.flask_source(
            base, self.aliases, self.scope, flow, base.attr
        )
        django_parameter = self.django_source(base, self.aliases, self.scope, flow)
        if flask_parameter or django_parameter:
            node._security_log_newline_source = True
            return True
        return False

    def _safe(self, node, tainted):
        if isinstance(node, ast.JoinedStr):
            values = [
                item for item in node.values if isinstance(item, ast.FormattedValue)
            ]
            return bool(values) and all(
                not self._flow(item.value, tainted, True)
                or item.conversion == ord("r")
                or not self._flow(item.value, tainted)
                for item in values
            )
        if (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Mod)
            and isinstance(node.left, ast.Constant)
            and isinstance(node.left.value, str)
        ):
            slots = log_percent_slots(node.left.value)
            return (
                bool(slots)
                and all(code == "r" for code in slots)
                and self._flow(node.right, tainted, True)
            )
        if isinstance(node, ast.Call):
            name = self.resolve(node, self.aliases)
            if name in {"repr", "builtins.repr"} and self._builtin_unshadowed(
                node, name
            ):
                return any(self._flow(arg, tainted, True) for arg in node.args)
            return self._safe_newline_replacement(node, tainted)
        return False

    def _safe_newline_replacement(self, node, tainted):
        replaced, current = set(), node
        while (
            isinstance(current, ast.Call)
            and isinstance(current.func, ast.Attribute)
            and current.func.attr == "replace"
            and len(current.args) == 2
        ):
            old, new = current.args[:2]
            if any(
                not isinstance(item, ast.Constant) or not isinstance(item.value, str)
                for item in (old, new)
            ) or any(char in new.value for char in "\r\n"):
                return False
            if old.value in {"\r", "\n"}:
                replaced.add(old.value)
            current = current.func.value
        return replaced == {"\r", "\n"} and self._flow(current, tainted, True)

    def _percent_repr(self, message, values, tainted):
        if not isinstance(message, ast.Constant) or not isinstance(message.value, str):
            return False
        slots = log_percent_slots(message.value)
        return (
            bool(slots)
            and all(code == "r" for code in slots)
            and len(slots) == len(values)
        )

    def _children(self, node):
        if isinstance(node, ast.Lambda):
            return []
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Lambda):
            return [node.func.body, *node.args, *(kw.value for kw in node.keywords)]
        return [
            child
            for child in ast.iter_child_nodes(node)
            if not isinstance(child, ast.Lambda)
        ]

    def _builtin_unshadowed(self, call, canonical):
        raw = ast.unparse(call.func).split(".", 1)[0]
        expected = canonical.split(".", 1)[0]
        resolved, _constants = self.flow_bindings(call, self.aliases)
        if canonical.startswith("builtins."):
            return resolved.get(raw) in {"builtins", canonical}
        if raw != expected or raw in getattr(call, "_security_shadowed_names", set()):
            return False
        scope = getattr(call, "_security_lexical_scope", self.scope)
        module = self.module_scope(scope)
        if module is None:
            return True
        if scope is module:
            target = getattr(call, "_security_flow_statement", None)
            return not any(
                raw in self.audit._bound_names(statement)
                for statement in module.body
                if statement is not target
                and (target is None or statement.lineno < target.lineno)
            )
        return raw not in self.module_names(module)

    def _assign(self, statement, tainted, snapshots):
        value = getattr(statement, "value", None)
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
        )
        if (
            snapshots is not None
            and log_scalar_metadata(value, self)
            and any(self._flow(arg, tainted, True) for arg in value.args)
        ):
            snapshots.append(dict(tainted))
        marked = isinstance(value, ast.AST) and self._flow(value, tainted, True)
        unsafe = isinstance(value, ast.AST) and self._flow(value, tainted)
        trace = (
            log_evidence.logging_input_value_trace(value, tainted, "LOCAL_ASSIGN")
            if unsafe
            else None
        )
        for target in targets:
            if isinstance(target, ast.Name):
                tainted.pop(target.id, None)
                if marked:
                    tainted[target.id] = trace if trace is not None else unsafe


def _catches_value_error(node):
    accepted = {"ValueError", "Exception", "BaseException"}
    return (
        node is None
        or (isinstance(node, ast.Name) and node.id in accepted)
        or (
            isinstance(node, ast.Tuple)
            and any(
                isinstance(item, ast.Name) and item.id in accepted for item in node.elts
            )
        )
    )
