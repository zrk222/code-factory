"""Bounded source-to-log flow recognition for Python security audits."""

from __future__ import annotations

import ast
from dataclasses import dataclass
import re


def audit_log_source_findings(relative, tree, nodes, aliases):
    """Find unneutralized input values passed to proven stdlib logging calls."""
    from . import review_audits as audit
    from .review_integrity import (
        _security_django_request_parameter,
        _security_flask_request_collection,
        _security_flow_bindings,
        _security_module_scope,
        _security_scope_local_names,
        security_call_name,
    )

    findings = []
    for scope in nodes:
        if not isinstance(scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
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
                self._calls([statement.test], tainted)
                branches = [dict(tainted), dict(tainted)]
                self._block(statement.body, branches[0], snapshots)
                self._block(statement.orelse, branches[1], snapshots)
                tainted.clear()
                tainted.update(_merge_flow(branches))
                continue
            self._calls([statement], tainted)
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                self._assign(statement, tainted, snapshots)
            elif not isinstance(
                statement, (ast.Expr, ast.Return, ast.Raise, ast.Assert)
            ):
                for name in self.audit._bound_names(statement):
                    tainted.pop(name, None)

    def _loop(self, statement, tainted):
        self._calls(
            [statement.test if isinstance(statement, ast.While) else statement.iter],
            tainted,
        )
        entry, body = dict(tainted), dict(tainted)
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            for name in self.audit._bound_names(statement.target):
                body.pop(name, None)
                if self._has_source(statement.iter, entry):
                    body[name] = self._expression(statement.iter, entry)
        self._block(statement.body, body)
        self._block(statement.orelse, body)
        tainted.clear()
        tainted.update(_merge_flow([entry, body]))

    def _try_block(self, statement, tainted):
        normal, snapshots = dict(tainted), []
        self._block(statement.body, normal, snapshots)
        if statement.orelse:
            self._block(statement.orelse, normal)
        outcomes = [normal]
        for handler in statement.handlers:
            state = (
                _merge_flow(snapshots)
                if snapshots and _catches_value_error(handler.type)
                else dict(tainted)
            )
            self._block(handler.body, state)
            outcomes.append(state)
        merged = _merge_flow(outcomes)
        self._block(statement.finalbody, merged)
        tainted.clear()
        tainted.update(merged)

    def _calls(self, statements, tainted):
        for statement in statements:
            for call in ast.walk(statement):
                if (
                    not isinstance(call, ast.Call)
                    or getattr(call, "_security_lexical_scope", self.scope)
                    is not self.scope
                ):
                    continue
                name = self._logging_name(call)
                if name and self._unsafe(call, tainted, name):
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
                        )
                    )

    def _logging_name(self, call):
        name = self.resolve(call, self.aliases)
        accepted = {
            f"logging.{level}"
            for level in (
                "debug",
                "info",
                "warning",
                "error",
                "critical",
                "exception",
                "log",
            )
        }
        return name if name in accepted else ""

    def _unsafe(self, call, tainted, name):
        keyword = next(
            (item.value for item in call.keywords if item.arg == "msg"), None
        )
        if name == "logging.log":
            message = call.args[1] if len(call.args) > 1 else keyword
        else:
            message = call.args[0] if call.args else keyword
        if message is None:
            return False
        values = [message]
        if name == "logging.log":
            values.extend(call.args[2:])
        else:
            values.extend(
                call.args[1:] if call.args and message is call.args[0] else []
            )
        values.extend(
            item.value for item in call.keywords if item.arg in {"args", "values"}
        )
        if self._percent_repr(message, values[1:], tainted):
            return False
        return any(
            self._expression(value, tainted) and not self._safe(value, tainted)
            for value in values
        )

    def _expression(self, node, tainted):
        if isinstance(node, ast.Name):
            return tainted.get(node.id, False)
        if self._builtin_integer(node):
            return False
        if self._source(node):
            return True
        if self._has_source(node, tainted):
            return not self._safe(node, tainted)
        return any(self._expression(child, tainted) for child in self._children(node))

    def _has_source(self, node, tainted):
        if isinstance(node, ast.Name) and node.id in tainted:
            return True
        if self._builtin_integer(node):
            return False
        return self._source(node) or any(
            self._has_source(child, tainted) for child in self._children(node)
        )

    def _source(self, node):
        if isinstance(node, ast.Call):
            name = self.resolve(node, self.aliases)
            if name in {"input", "builtins.input"} and self._builtin_unshadowed(
                node, name
            ):
                return True
        base = node.value if isinstance(node, ast.Subscript) else None
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
        ):
            base = node.func.value
        if not isinstance(base, ast.Attribute):
            return False
        flow = getattr(node, "_security_flow_statement", None)
        if base.attr in {"args", "form"} and self.flask_source(
            base, self.aliases, self.scope, flow, base.attr
        ):
            return True
        return self.django_source(base, self.aliases, self.scope, flow)

    def _safe(self, node, tainted):
        if isinstance(node, ast.JoinedStr):
            values = [
                item for item in node.values if isinstance(item, ast.FormattedValue)
            ]
            return bool(values) and all(
                not self._has_source(item.value, tainted)
                or item.conversion == ord("r")
                or not self._expression(item.value, tainted)
                for item in values
            )
        if (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Mod)
            and isinstance(node.left, ast.Constant)
            and isinstance(node.left.value, str)
        ):
            codes = _percent_codes(node.left.value)
            slots = [code for code in codes if code != "%"]
            return (
                bool(slots)
                and all(code == "r" for code in slots)
                and self._has_source(node.right, tainted)
            )
        if isinstance(node, ast.Call):
            name = self.resolve(node, self.aliases)
            if name in {"repr", "builtins.repr"} and self._builtin_unshadowed(
                node, name
            ):
                return any(self._has_source(arg, tainted) for arg in node.args)
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
            if not all(
                isinstance(item, ast.Constant) and isinstance(item.value, str)
                for item in (old, new)
            ):
                return False
            if any(char in new.value for char in "\r\n"):
                return False
            if old.value in {"\r", "\n"}:
                replaced.add(old.value)
            current = current.func.value
        return replaced == {"\r", "\n"} and self._has_source(current, tainted)

    def _percent_repr(self, message, values, tainted):
        if not isinstance(message, ast.Constant) or not isinstance(message.value, str):
            return False
        codes = _percent_codes(message.value)
        slots = [code for code in codes if code != "%"]
        return (
            bool(slots)
            and all(code == "r" for code in slots)
            and len(slots) == len(values)
        )

    def _builtin_integer(self, node):
        if not isinstance(node, ast.Call) or self.resolve(node, self.aliases) not in {
            "int",
            "builtins.int",
        }:
            return False
        return self._builtin_unshadowed(node, self.resolve(node, self.aliases))

    def _children(self, node):
        if isinstance(node, ast.Lambda):
            return []
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Lambda):
            return [
                node.func.body,
                *node.args,
                *(keyword.value for keyword in node.keywords),
            ]
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
        if raw != expected:
            return False
        if raw in getattr(call, "_security_shadowed_names", set()):
            return False
        scope = getattr(call, "_security_lexical_scope", self.scope)
        module = self.module_scope(scope)
        if module is None:
            return True
        if scope is module:
            target = getattr(call, "_security_flow_statement", None)
            for statement in module.body:
                if statement is target:
                    break
                if raw in self.audit._bound_names(statement):
                    return False
            return True
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
            and self._builtin_integer(value)
            and any(self._has_source(arg, tainted) for arg in value.args)
        ):
            snapshots.append(dict(tainted))
        marked = isinstance(value, ast.AST) and self._has_source(value, tainted)
        unsafe = isinstance(value, ast.AST) and self._expression(value, tainted)
        for target in targets:
            if isinstance(target, ast.Name):
                tainted.pop(target.id, None)
                if marked:
                    tainted[target.id] = unsafe


def _catches_value_error(node):
    accepted = {"ValueError", "Exception", "BaseException"}
    if node is None:
        return True
    if isinstance(node, ast.Name):
        return node.id in accepted
    return isinstance(node, ast.Tuple) and any(
        isinstance(item, ast.Name) and item.id in accepted for item in node.elts
    )


def _merge_flow(states):
    merged = {}
    for state in states:
        for name, unsafe in state.items():
            merged[name] = merged.get(name, False) or unsafe
    return merged


def _percent_codes(value):
    return re.findall(
        r"%(?:\([^)]*\))?[-+#0 ]*(?:\d+|\*)?(?:\.\d+|\.\*)?([a-zA-Z%])", value
    )
