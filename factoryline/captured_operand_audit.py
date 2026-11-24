"""Source-bound operands for bounded Python security proofs."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
import re
from string import Formatter


_COOKIE_NAME_PROVIDERS = frozenset(
    {
        "fastapi.FastAPI",
        "fastapi.Request",
        "fastapi.Response",
        "fastapi.applications.FastAPI",
        "fastapi.responses.RedirectResponse",
        "fastapi.responses.Response",
        "starlette.applications.Starlette",
        "starlette.middleware.base.BaseHTTPMiddleware",
        "starlette.middleware.base._CachedRequest",
        "starlette.requests.HTTPConnection",
        "starlette.requests.Request",
        "starlette.requests.cookie_parser",
        "starlette.responses.RedirectResponse",
        "starlette.responses.Response",
    }
)
_COOKIE_NAME_ROLE = "http_cookie_name"


def cookie_name_trace(index, checked_uses):
    """Record exact name operands from closed uses, without source literal values."""
    from .captured_security_audit import _native_span

    steps = []
    for (reference, path, _), role in checked_uses:
        parents = index.parents[path]
        parent = parents.get(id(reference))
        keyword = parent.arg if isinstance(parent, ast.keyword) else None
        call = parents.get(id(parent)) if keyword is not None else parent
        if not isinstance(call, ast.Call):
            return None
        span, call_span = _native_span(reference), _native_span(call)
        if span is None or call_span is None or not index.validate(path):
            return None
        operation, receiver_role = _registry_trace_operation(call, role)
        if not operation:
            return None
        steps.append(
            {
                "path": index.relative(path),
                "source_sha256": index.inventory[path],
                "call_span": list(call_span),
                "operand_span": list(span),
                "operand": keyword if keyword is not None else 0,
                "role": role,
                "operation": operation,
                "receiver_role": receiver_role,
            }
        )
    return sorted(steps, key=lambda row: (row["path"], row["operand_span"]))


def _registry_trace_operation(call, role):
    """Return the operation name and receiver contract for one proven use."""
    if role == _COOKIE_NAME_ROLE:
        operation = getattr(call.func, "attr", None)
    else:
        operation = role
    if operation == "get":
        return operation, "fastapi_middleware_request"
    if role == _COOKIE_NAME_ROLE:
        return operation, "fresh_redirect_response"
    return operation, "security_locator"


def _registry_cookie_name_use(reference, parent, aliases, source, path):
    """Bind a public name to an exact cookie slot on a captured HTTP receiver."""
    from .captured_security_audit import (
        _captured_argument_definition,
        _captured_call_provider,
    )

    parents = source.parents[path]
    call = parents.get(id(parent)) if isinstance(parent, ast.keyword) else parent
    match call:
        case ast.Call(
            func=ast.Attribute(
                attr="get",
                value=ast.Attribute(attr="cookies", value=ast.Name() as request),
            ),
            args=[operand],
            keywords=[],
        ) if operand is reference:
            return _registry_middleware_request(request, call, aliases, source, path)
        case ast.Call(
            func=ast.Attribute(attr="delete_cookie", value=ast.Name() as reply),
            args=[operand],
            keywords=[],
        ) if operand is reference:
            pass
        case ast.Call(
            func=ast.Attribute(attr="set_cookie", value=ast.Name() as reply),
            args=[],
            keywords=keywords,
        ) if (
            isinstance(parent, ast.keyword)
            and parent.arg == "key"
            and len(keys := {kw.arg for kw in keywords}) == len(keywords)
            and "value" in keys
            and keys
            <= {
                "key",
                "value",
                "max_age",
                "expires",
                "path",
                "domain",
                "secure",
                "httponly",
                "samesite",
                "partitioned",
            }
        ):
            pass
        case _:
            return False
    allocation = _captured_argument_definition(
        reply, call, parents, source.snapshots[path]
    )
    assignment = parents.get(id(allocation))
    use = parents.get(id(call))
    suite_owner = parents.get(id(use))
    return (
        isinstance(allocation, ast.Call)
        and _captured_call_provider(allocation, aliases, source, path)
        in {
            "fastapi.responses.RedirectResponse",
            "starlette.responses.RedirectResponse",
        }
        and isinstance(use, ast.Expr)
        and suite_owner is not None
        and any(
            previous is assignment and current is use
            for _, field in ast.iter_fields(suite_owner)
            if isinstance(field, list)
            for previous, current in zip(field, field[1:])
        )
    )


def _registry_middleware_request(request, call, aliases, source, path):
    """Bind an unrebound first parameter of a captured FastAPI HTTP middleware."""
    from .credential_role_constructor_provider import (
        _direct_terminal_import,
        _scope_scope_bindings,
        binding_occurrences,
    )
    from .credential_role_identity_effects import source_symbol_index
    from .captured_security_audit import (
        _captured_call_provider,
        _captured_named_provider_unchanged,
        _text_binding_reads,
    )

    parents, module = source.parents[path], source.snapshots[path]
    scope = _scope_scope_bindings(call, parents, module)
    if not isinstance(scope, ast.AsyncFunctionDef) or scope not in module.body:
        return False
    match scope.args:
        case ast.arguments(
            posonlyargs=[],
            args=[
                ast.arg(arg=name, annotation=ast.Name(id=annotation)),
                ast.arg(arg=next_name),
            ],
            defaults=[],
            kwonlyargs=[],
            vararg=None,
            kwarg=None,
        ) if name == request.id and next_name != name:
            pass
        case _:
            return False
    provider = _direct_terminal_import(source, path, annotation)
    if provider is None or provider[0] not in {
        "fastapi.Request",
        "starlette.requests.Request",
    }:
        return False
    match scope.decorator_list:
        case [
            ast.Call(
                func=ast.Attribute(value=ast.Name(id=app_name), attr="middleware"),
                args=[ast.Constant(value="http")],
                keywords=[],
            )
        ]:
            pass
        case _:
            return False
    matches = binding_occurrences(module.body, app_name)
    if (
        len(matches) != 1
        or binding_occurrences(module.body, scope.name) != [scope]
        or any(binding_occurrences(scope.body, bound) for bound in (name, next_name))
    ):
        return False
    statement = parents.get(id(matches[0]))
    if not (
        isinstance(statement, ast.Assign)
        and statement in module.body
        and statement.targets == matches
        and statement.lineno < scope.lineno
        and isinstance(statement.value, ast.Call)
        and not statement.value.args
        and all(
            kw.arg
            in {
                "debug",
                "docs_url",
                "openapi_url",
                "redoc_url",
                "title",
                "version",
                "workers",
            }
            for kw in statement.value.keywords
        )
        and _captured_call_provider(statement.value, aliases, source, path)
        == "fastapi.FastAPI"
    ):
        return False
    symbols = source_symbol_index(source)
    return (
        symbols is not None
        and _text_binding_reads(source, symbols, (path, scope), None) == set()
        and _captured_named_provider_unchanged(
            source, path, app_name, readonly_nodes=tuple(matches)
        )
        and _registry_request_uses_closed(scope, name, next_name, parents)
    )


def _registry_request_uses_closed(scope, name, next_name, parents):
    """Allow captured slot reads and fall-through-free ASGI forwarding."""
    for node in ast.walk(scope):
        if isinstance(node, (ast.Global, ast.Nonlocal)) and (
            name in node.names or next_name in node.names
        ):
            return False
        if not isinstance(node, ast.Name) or node.id != name:
            continue
        if not _registry_middleware_body_use(node, scope, parents):
            return False
        parent = parents.get(id(node))
        match parent:
            case ast.Attribute(
                value=value, attr=("cookies" | "url") as attr, ctx=ast.Load()
            ) if value is node:
                member = parents.get(id(parent))
                if (
                    isinstance(member, ast.Attribute)
                    and isinstance(member.ctx, ast.Load)
                    and member.value is parent
                    and member.attr == ("get" if attr == "cookies" else "path")
                ):
                    continue
            case ast.Call(func=ast.Name(id=callee), args=[value], keywords=[]) if (
                callee == next_name and value is node
            ):
                awaited = parents.get(id(parent))
                forwarded = parents.get(id(awaited))
                if (
                    isinstance(awaited, ast.Await)
                    and isinstance(forwarded, ast.Return)
                    and _registry_return_without_handlers(forwarded, scope, parents)
                ):
                    continue
        return False
    return True


def _registry_middleware_body_use(node, scope, parents):
    """Exclude definition-time expressions and independent lexical scopes."""
    while (owner := parents.get(id(node))) is not None:
        if owner is scope:
            return node in scope.body
        if isinstance(
            owner, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
        ):
            return False
        node = owner
    return False


def _registry_return_without_handlers(statement, scope, parents):
    while (statement := parents.get(id(statement))) is not None:
        if statement is scope:
            return True
        if not isinstance(statement, ast.If):
            return False
    return False


def _captured_closed_text_callers(
    index, projection, owner_path, owner, resolve, scope, bind, dynamic
):
    callers, work = {}, 0
    for path, tree in index.snapshots.items():
        if not index.validate(path):
            return {}
        nodes = tuple(ast.walk(tree))
        work += len(nodes)
        if work > 16000 or dynamic(nodes):
            return {}
        parents = index.parents[path]
        for expr in nodes:
            if not isinstance(expr, (ast.Name, ast.Attribute)) or not isinstance(
                expr.ctx, ast.Load
            ):
                continue
            found = resolve(projection.symbols, path, expr, scope(expr, parents, None))
            if found is None or found[0] != owner_path or found[1] is not owner:
                continue
            site = parents.get(id(expr))
            if not isinstance(site, ast.Call) or site.func is not expr:
                return {}
            resolved = bind(site, path, index)
            if (
                resolved is None
                or resolved.function is not owner
                or not resolved.negative_binding_closed
            ):
                return {}
            callers[id(site)] = {
                formal: _captured_literal_argument_origin(actual, site, parents, tree)
                for formal, actual in resolved.arguments.items()
            }
    return callers


def _captured_literal_argument_origin(argument, call, parents, module):
    """Resolve a literal through a unique preceding assignment in this lexical scope."""
    value = _captured_argument_definition(argument, call, parents, module)
    return value if _CapturedTextDefinitions.literal(value) else argument


def _captured_argument_definition(argument, call, parents, module, *, aliases=False):
    """Find the assignment that reaches this argument on the captured branch."""
    from .credential_role_constructor_provider import (
        _binding_precedes_sibling,
        _scope_scope_bindings,
        binding_occurrences,
    )

    if not isinstance(argument, ast.Name):
        return None
    scope = _scope_scope_bindings(call, parents, module)
    if not isinstance(scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    if _argument_binding_is_parameter_or_external(argument.id, scope):
        return None
    writes = binding_occurrences(scope.body, argument.id)
    current = call
    while (owner := parents.get(id(current))) is not None:
        if isinstance(
            owner,
            (
                ast.ClassDef,
                ast.comprehension,
                ast.ListComp,
                ast.SetComp,
                ast.DictComp,
                ast.GeneratorExp,
            ),
        ):
            return None
        if isinstance(owner, ast.Try) and current in owner.body:
            handler_nodes = {
                node for handler in owner.handlers for node in ast.walk(handler)
            }
            writes = [node for node in writes if node not in handler_nodes]
        if len(writes) == 1:
            assignment = parents.get(id(writes[0]))
            if _captured_assignment_targets(
                assignment, writes[0], aliases=aliases
            ) and _binding_precedes_sibling(assignment, current, owner):
                return assignment.value
        if owner is scope:
            break
        current = owner
    return None


def _captured_assignment_targets(assignment, target, *, aliases):
    if isinstance(assignment, ast.AnnAssign):
        return aliases and assignment.target is target and assignment.value is not None
    if not isinstance(assignment, ast.Assign):
        return False
    if assignment.targets == [target]:
        return True
    if not aliases or not all(
        isinstance(node, ast.Name) for node in assignment.targets
    ):
        return False
    return len({node.id for node in assignment.targets}) == len(assignment.targets)


def _argument_binding_is_parameter_or_external(name, scope):
    from .review_audits import _scope_parameters

    return isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
        name in _scope_parameters(scope)
        or any(
            isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names
            for node in ast.walk(scope)
        )
    )


def captured_log_field_text_closed(expression):
    """Prove that the selected record slot can emit only closed scalar text."""
    from .semantic_credential_sensor import _security_helper_source_context

    selected = _captured_record_read(expression)
    if selected is None:
        return False
    receiver, key = selected
    module, index, path = _security_helper_source_context(expression, None)
    if path is None or not index.validate(path):
        return False
    parents = index.parents[path]
    value = _captured_argument_definition(receiver, expression, parents, module)
    if not isinstance(value, (ast.Call, ast.Dict)):
        return False
    scope = getattr(expression, "_security_lexical_scope", None)
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    if _captured_record_receiver_escapes(scope, parents, receiver, value, expression):
        return False
    return _CapturedRecordText(index).field(value, path, key, {})


def _captured_record_receiver_escapes(scope, parents, receiver, value, expression):
    """Check for an unmodeled read between the receiver's definition and use."""
    return any(
        isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id == receiver.id
        and value.lineno <= node.lineno <= expression.end_lineno
        and _captured_record_read(parents.get(id(node))) is None
        and _captured_record_read(parents.get(id(parents.get(id(node))))) is None
        for node in ast.walk(scope)
    )


def _captured_record_read(node):
    match node:
        case ast.Subscript(
            value=ast.Name() as receiver,
            slice=ast.Constant(value=str() as key),
            ctx=ast.Load(),
        ):
            return receiver, key
        case ast.Call(
            func=ast.Attribute(value=ast.Name() as receiver, attr="get"),
            args=[ast.Constant(value=str() as key), *defaults],
            keywords=[],
        ) if len(defaults) <= 1 and all(
            map(_CapturedTextDefinitions.literal, defaults)
        ):
            return receiver, key
        case _:
            return None


class _CapturedRecordText:
    """Follow one record field through source-resolved returns and scalar definitions."""

    def __init__(self, index):
        self.index = index
        self.remaining = 64

    def field(self, expression, path, key, formals):
        from .credential_role_identity_effects import resolve_source_identity_call
        from .review_integrity import _lexical_nodes

        self.remaining -= 1
        if self.remaining < 0:
            return False
        if isinstance(expression, ast.Dict):
            keys = [
                item.value
                for item in expression.keys
                if isinstance(item, ast.Constant) and type(item.value) is str
            ]
            return (
                len(keys) == len(set(keys)) == len(expression.keys)
                and key in keys
                and self.scalar(expression.values[keys.index(key)], path, formals)
            )
        if not isinstance(expression, ast.Call):
            return False
        resolved = resolve_source_identity_call(expression, path, self.index)
        if (
            resolved is None
            or not resolved.negative_binding_closed
            or not isinstance(resolved.function, ast.FunctionDef)
            or resolved.function.decorator_list
        ):
            return False
        nodes = tuple(_lexical_nodes(resolved.function))
        if any(
            isinstance(node, (ast.Global, ast.Nonlocal))
            for node in ast.walk(resolved.function)
        ) or any(isinstance(node, (ast.Yield, ast.YieldFrom)) for node in nodes):
            return False
        returns = [node.value for node in nodes if isinstance(node, ast.Return)]
        actuals = {
            formal: (actual, path, formals)
            for formal, actual in resolved.arguments.items()
        }
        return bool(returns) and all(
            self.field(value, resolved.path, key, actuals) for value in returns
        )

    def scalar(self, expression, path, formals):
        from .credential_role_constructor_provider import (
            _scope_scope_bindings,
            binding_occurrences,
        )

        self.remaining -= 1
        if self.remaining < 0:
            return False
        if _CapturedTextDefinitions.literal(expression):
            return True
        if isinstance(expression, ast.IfExp):
            return self.scalar(expression.body, path, formals) and self.scalar(
                expression.orelse, path, formals
            )
        if not isinstance(expression, ast.Name):
            return False
        module, parents = self.index.snapshots[path], self.index.parents[path]
        scope = _scope_scope_bindings(expression, parents, module)
        if not isinstance(scope, ast.FunctionDef):
            return False
        writes = binding_occurrences(scope.body, expression.id)
        formal = formals.get(expression.id)
        if formal is not None and not self.scalar(*formal):
            return False
        return (formal is not None or bool(writes)) and all(
            isinstance(statement := parents.get(id(node)), ast.Assign)
            and statement.targets == [node]
            and self.scalar(statement.value, path, formals)
            for node in writes
        )


class _CapturedTextDefinitions:
    """Prove scalar text from bounded captured definitions and literal record fields."""

    def __init__(self, nodes, parents, actuals, owner, binds):
        self.parents, self.actuals = parents, actuals
        self.owner, self.binds, self.cache = owner, binds, {}
        self.refs, self.active, self.known, self.fields = {}, set(), {}, {}
        for n in nodes:
            if isinstance(n, ast.Name):
                self.refs.setdefault(n.id, []).append(n)

    @staticmethod
    def literal(expr):
        return isinstance(expr, ast.Constant) and type(expr.value) in {
            str,
            int,
            bool,
            type(None),
        }

    def formal(self, name):
        return [row.get(name) for row in self.actuals]

    def prove(self, expr):
        match expr:
            case ast.Constant():
                return self.literal(expr)
            case ast.Name(id=name):
                return self.name(name)
            case ast.BinOp(left=left, op=ast.Add(), right=right):
                return self.prove(left) and self.prove(right)
            case ast.IfExp(body=left, orelse=right):
                return self.prove(left) and self.prove(right)
            case ast.JoinedStr(values=parts):
                return all(self.prove(part) for part in parts)
            case ast.FormattedValue(value=value, conversion=-1, format_spec=None):
                return self.prove(value)
            case ast.Call(
                func=ast.Attribute(value=ast.Name(id=row), attr="get"),
                args=[ast.Constant(value=key), *defaults],
                keywords=[],
            ) if type(key) is str:
                return (
                    len(defaults) <= 1
                    and all(map(self.literal, defaults))
                    and self.row_field(row, key)
                )
            case _:
                return False

    def name(self, name):
        if name in self.known:
            return self.known[name]
        if name in self.active or len(self.active) >= 24:
            return False
        self.active.add(name)
        is_formal = any(name in row for row in self.actuals)
        base = is_formal and all(map(self.literal, self.formal(name)))
        if is_formal and not base:
            self.active.remove(name)
            return False
        for node in self.binds(self.owner.body, name, per_pass_facts=self.cache):
            statement = self.parents.get(id(node))
            if not self.assignment(statement, node):
                self.active.remove(name)
                return False
            base |= isinstance(statement, (ast.Assign, ast.AnnAssign))
        self.active.remove(name)
        self.known[name] = base
        return base

    def assignment(self, statement, node):
        match statement:
            case ast.Assign(targets=[target], value=value) if target is node:
                return self.prove(value)
            case ast.AnnAssign(target=target, value=value) if target is node:
                return self.prove(value)
            case ast.AugAssign(target=target, op=ast.Add(), value=value) if (
                target is node
            ):
                return self.prove(value)
            case _:
                return False

    def row_field(self, name, key):
        if name not in self.fields:
            self.fields[name] = self.row_fields(name)
        return key in self.fields[name]

    def row_fields(self, row):
        refs = self.refs.get(row, ())
        writes = self.binds(self.owner.body, row, per_pass_facts=self.cache)
        if len(writes) != 1:
            return set()
        loop = self.parents.get(id(writes[0]))
        if (
            not isinstance(loop, ast.For)
            or loop.target is not writes[0]
            or not isinstance(loop.iter, ast.Name)
        ):
            return set()
        if not all(self.row_read(n) for n in refs if isinstance(n.ctx, ast.Load)):
            return set()
        formal = loop.iter.id
        if self.binds(self.owner.body, formal, per_pass_facts=self.cache) or not all(
            self.collection_read(n, loop.iter) for n in self.refs.get(formal, ())
        ):
            return set()
        fields = None
        for incoming in self.formal(formal):
            if isinstance(incoming, ast.Constant) and incoming.value is None:
                continue
            if (
                not isinstance(incoming, (ast.List, ast.Tuple))
                or len(incoming.elts) > 64
            ):
                return set()
            for expr in incoming.elts:
                known = self.record_fields(expr)
                if known is None:
                    return set()
                fields = known if fields is None else fields & known
        return fields or set()

    def record_fields(self, expr):
        if not isinstance(expr, ast.Dict) or not all(
            isinstance(k, ast.Constant) and type(k.value) is str for k in expr.keys
        ):
            return None
        keys = [k.value for k in expr.keys]
        if len(keys) != len(set(keys)) or not all(
            self.literal(v) or isinstance(v, ast.Name) for v in expr.values
        ):
            return None
        return {k for k, v in zip(keys, expr.values) if self.literal(v)}

    def row_read(self, node):
        member = self.parents.get(id(node))
        call = self.parents.get(id(member))
        return (
            isinstance(member, ast.Attribute)
            and member.value is node
            and member.attr == "get"
            and isinstance(call, ast.Call)
            and call.func is member
        )

    def collection_read(self, node, iterator):
        parent = self.parents.get(id(node))
        return isinstance(node.ctx, ast.Load) and (
            node is iterator or isinstance(parent, ast.If) and parent.test is node
        )


def _closed_shell_provider_mutated(node, head, supported):
    """Reject source-visible provider writes, reflection and monkey patches."""
    if isinstance(node, ast.ImportFrom) and any(
        alias.name == "*" for alias in node.names
    ):
        return True
    if (
        isinstance(node, ast.Name)
        and node.id == head
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ):
        return True
    if isinstance(node, (ast.arg, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        if getattr(node, "arg", getattr(node, "name", None)) == head:
            return True
    if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
        base = node.value
        while isinstance(base, ast.Attribute):
            base = base.value
        if (isinstance(base, ast.Name) and base.id == head) or node.attr in {
            name.rsplit(".", 1)[-1] for name in supported
        }:
            return True
    if (
        isinstance(node, ast.Call)
        and (
            node.func.id
            if isinstance(node.func, ast.Name)
            else getattr(node.func, "attr", "")
        )
        in "eval exec globals locals setattr delattr __import__ patch".split()
    ):
        return True
    return False


def _closed_shell_namespace(tree, head):
    """Reject capability escapes, namespace access and aliased reflection."""
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    reflective = set(
        "eval exec globals locals vars setattr delattr getattr __import__".split()
    )
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and node.id == head
            and isinstance(node.ctx, ast.Load)
        ):
            if not isinstance(parents.get(node), ast.Attribute):
                return False
        if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            base = node.value
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name) and base.id == head:
                return False
        if isinstance(node, ast.ImportFrom) and node.module in {
            "builtins",
            "__builtin__",
        }:
            if any(alias.name in reflective for alias in node.names):
                return False
    return True


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


_COMMAND_ABSENT = object()
_COMMAND_NAMESPACE_QUERIES = frozenset(
    {"__import__", "eval", "exec", "globals", "locals", "vars", "setattr", "delattr"}
)
_COMMAND_DIRECTORY_MUTATORS = frozenset({"chdir", "fchdir", "chroot"})
_COMMAND_CLASS_HOOKS = frozenset(
    {
        "__new__",
        "__getattribute__",
        "__getattr__",
        "__setattr__",
        "__delattr__",
        "__dict__",
        "__slots__",
        "__classcell__",
        "__class__",
    }
)


def captured_command_operand_proof(index, path, node):
    """Bind every command operand to a closed captured source role."""
    if not _command_candidate(node):
        return None
    if not index.bounded or len(index.snapshots) > 128 or not index.validate(path):
        return None
    proof = _CommandOperandProof(index)
    if id(node) not in index.parents[path] or not proof.inventory_closed():
        return None
    result = proof.command(path, node)
    if result is None or not proof.providers_closed():
        return None
    return {
        "hypothesis": "CAPTURED_SOURCE_COMMAND_INJECTION",
        "scope": "CAPTURED_PYTHON_SOURCE",
        "externally_invoked_callers": "UNASSESSED",
        "deployment_path": "UNASSESSED",
        "shell_operation": "RETAINED",
        "operands": result,
    }


class _CommandOperandProof:
    """Resolve source roles through immutable worktree bindings and exact call slots."""

    def __init__(self, source):
        self.source = source
        self.modules = {}
        self.nodes = {}
        self.bindings = {}
        self.providers = set()
        self.source_bindings = set()

    def inventory_closed(self):
        from .runtime_audit_integrity import _conditional_module_name

        paths = self.source.module_paths()
        if paths is None:
            return False
        for name, path in paths.items():
            canonical = _conditional_module_name(name)
            if canonical in self.modules and self.modules[canonical] != path:
                return False
            self.modules[canonical] = path
        work = 0
        for path, tree in self.source.snapshots.items():
            if not self.source.validate(path):
                return False
            nodes = tuple(ast.walk(tree))
            work += len(nodes)
            if work > 100_000 or not all(self.node_closed(node) for node in nodes):
                return False
            self.nodes[path] = nodes
        return True

    @staticmethod
    def node_closed(node):
        if isinstance(node, ast.Name):
            return node.id not in _COMMAND_NAMESPACE_QUERIES
        if isinstance(node, ast.Attribute):
            return node.attr not in _COMMAND_NAMESPACE_QUERIES | {
                "__dict__",
                "__globals__",
                "modules",
            }
        if isinstance(node, ast.alias):
            return node.name.rsplit(".", 1)[-1] not in _COMMAND_NAMESPACE_QUERIES
        return True

    def providers_closed(self, *, readonly_argument=None):
        from . import review_audits as audit
        from .credential_role_constructor_provider import (
            _captured_terminal_provider_mutation,
        )

        if not self.providers:
            return False
        canonical, *others = sorted(self.providers)
        return not _captured_terminal_provider_mutation(
            self.source,
            audit,
            canonical,
            readonly_argument=readonly_argument,
            additional_bindings=(
                *((name, None) for name in others),
                *sorted(self.source_bindings),
            ),
        )

    def seal_source_binding(self, path, declaration):
        matches = [module for module, peer in self.modules.items() if peer == path]
        if not matches:
            return False
        self.source_bindings.update(
            (module + "." + declaration.name, (path, declaration.name))
            for module in matches
        )
        return True

    def scope(self, path, node):
        from .credential_role_constructor_provider import _scope_scope_bindings

        return _scope_scope_bindings(
            node, self.source.parents[path], self.source.snapshots[path]
        )

    def resolve(self, path, expression, scope=None):
        """Resolve exact reads, including a captured wildcard re-export."""
        from .credential_role_constructor_provider import binding_occurrences

        if not self.reference_scope_closed(path, expression, scope):
            return None
        if isinstance(expression, ast.Attribute):
            return self.member(
                self.resolve(path, expression.value, scope), expression.attr
            )
        if not isinstance(expression, ast.Name):
            return None
        name = expression.id
        if isinstance(scope, ast.Lambda):
            return None
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
            _argument_binding_is_parameter_or_external(name, scope)
            or binding_occurrences(scope.body, name)
        ):
            return None
        return self.lookup(path, name, ())

    def reference_scope_closed(self, path, expression, scope):
        parents = self.source.parents[path]
        tree = self.source.snapshots[path]
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            owner = parents.get(id(scope))
            if owner is not tree and not (
                isinstance(owner, ast.ClassDef) and owner in tree.body
            ):
                return False
        while (owner := parents.get(id(expression))) is not None:
            if owner is scope:
                return True
            if isinstance(
                owner,
                (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
            ):
                return False
            if isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return False
            if isinstance(owner, ast.ClassDef) and expression in owner.body:
                return False
            expression = owner
        return scope is None or scope is tree

    def member(self, namespace, name, trail=()):
        if not isinstance(namespace, str):
            return None
        if namespace in self.modules:
            if (path := self.modules[namespace]) is None:
                return None
            binding = self.lookup(path, name, trail)
            return None if binding is _COMMAND_ABSENT else binding
        return namespace + "." + name

    def lookup(self, path, name, trail):
        key = path, name
        if key in trail or len(trail) >= 16:
            return None
        if key not in self.bindings:
            self.bindings[key] = self.lookup_binding(path, name, (*trail, key))
        return self.bindings[key]

    def lookup_binding(self, path, name, trail):
        from .credential_role_constructor_provider import binding_occurrences

        tree = self.source.snapshots[path]
        bindings = binding_occurrences(tree.body, name)
        if any(
            binding not in tree.body
            for binding in bindings
            if not isinstance(binding, ast.Name)
        ):
            return None
        ordered = sorted(bindings, key=lambda node: (node.lineno, node.col_offset))
        binding = _COMMAND_ABSENT
        for statement in ordered:
            selected = self.statement_binding(path, statement, name, trail)
            if selected is _COMMAND_ABSENT:
                continue
            if selected is None or (
                binding is not _COMMAND_ABSENT and selected != binding
            ):
                return None
            binding = selected
        return binding

    def statement_binding(self, path, statement, name, trail):
        if isinstance(statement, ast.Import):
            candidates = [
                alias.name if alias.asname else alias.name.split(".")[0]
                for alias in statement.names
                if (alias.asname or alias.name.split(".")[0]) == name
            ]
            return candidates[0] if len(candidates) == 1 else None
        if isinstance(statement, ast.ImportFrom):
            return self.import_binding(path, statement, name, trail)
        if isinstance(statement, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
            return path, statement
        owner = self.source.parents[path].get(id(statement))
        if (
            isinstance(owner, ast.Assign)
            and owner in self.source.snapshots[path].body
            and owner.targets == [statement]
        ):
            return path, owner
        return None

    def import_binding(self, path, statement, name, trail):
        candidates = [
            alias.name
            for alias in statement.names
            if alias.name == "*" or (alias.asname or alias.name) == name
        ]
        if not candidates:
            return _COMMAND_ABSENT
        if len(candidates) != 1:
            return None
        selected = candidates[0]
        module = self.import_module(path, statement)
        if module is None:
            return None
        if selected == "*":
            if name.startswith("_"):
                return _COMMAND_ABSENT
            return self.wildcard_binding(module, name, trail)
        if selected_module := self.direct_child_import(
            path, statement, module, selected
        ):
            return selected_module
        if module in self.modules and self.modules[module] is not None:
            value = self.lookup(self.modules[module], selected, trail)
            return None if value is _COMMAND_ABSENT else value
        return module + "." + selected

    def wildcard_binding(self, module, name, trail):
        from .credential_role_constructor_provider import binding_occurrences

        target = self.modules.get(module)
        if target is None:
            return None
        if any(
            not isinstance(site, ast.ImportFrom)
            for site in binding_occurrences(
                self.source.snapshots[target].body, "__all__"
            )
        ):
            return None
        return self.lookup(target, name, trail)

    def import_module(self, path, statement):
        if not statement.level:
            return statement.module
        relative = self.source.relative(path)
        package = relative.split("/")[:-1]
        if len(package) < statement.level:
            return None
        parts = package[: len(package) - statement.level + 1]
        return ".".join((*parts, *([statement.module] if statement.module else [])))

    def direct_child_import(self, path, statement, module, selected):
        # `from . import child` is authoritative only for the captured package's
        # own exact child import, where recursively reading the export cycles.
        candidate = f"{module}.{selected}"
        if (
            statement.level == 1
            and statement.module is None
            and path.name == "__init__.py"
            and path == self.modules.get(module)
            and self.modules.get(candidate) is not None
        ):
            return candidate
        return None

    def check_call(self, path, node, provider, count):
        if not _command_call_shape(node, count):
            return False
        if self.resolve(path, node.func, self.scope(path, node)) != provider:
            return False
        if provider.split(".")[0] in self.modules:
            return False
        self.providers.add(provider)
        return True

    def call_sites(self, declaration_path, declaration):
        from .credential_role_constructor_provider import _scope_scope_bindings

        calls = []
        exact = declaration_path, declaration
        names = self.reference_spellings(declaration.name)
        for path, nodes in self.nodes.items():
            parents = self.source.parents[path]
            for item in nodes:
                if not _command_matching_reference(item, names):
                    continue
                scope = _scope_scope_bindings(item, parents, None)
                binding = self.resolve(path, item, scope)
                if binding == exact:
                    calls.append((path, item, parents.get(id(item))))
                elif binding is None:
                    return None
        return calls

    def reference_spellings(self, original):
        aliases = [
            (alias.name, alias.asname)
            for nodes in self.nodes.values()
            for item in nodes
            if isinstance(item, ast.ImportFrom)
            for alias in item.names
            if alias.asname
        ]
        names = {original}
        for _ in range(len(aliases)):
            expanded = names | {
                local for exported, local in aliases if exported in names
            }
            if expanded == names:
                break
            names = expanded
        return names

    def command(self, path, node):
        from .intent_quality import bound_sink_argument

        if not self.check_call(path, node, "os.system", 1):
            return None
        operand = bound_sink_argument(node, 0)
        pieces = _command_concat(operand)
        owner = self.scope(path, node)
        if not isinstance(owner, ast.FunctionDef):
            return None
        return (
            self.generated_file(path, node, owner, pieces)
            if owner in self.source.snapshots[path].body
            else self.startup_directory(path, node, owner, pieces)
        )

    def generated_file(self, path, node, owner, pieces):
        if not _command_generated_syntax(pieces):
            return None
        joined = pieces[1]
        if not self.check_call(path, joined, "os.path.join", 2):
            return None
        directory, argument = joined.args
        if not self.module_directory(path, directory, owner, ()) or not isinstance(
            argument, ast.Name
        ):
            return None
        parameter = argument.id
        if not (
            _command_exact_positionals(owner, 2)
            and owner.args.args[0].arg == parameter
            and _command_unrebound_parameter(owner, parameter)
        ):
            return None
        sites = self.call_sites(path, owner)
        if not sites or not all(
            self.generated_actual(site, owner, parameter) for site in sites
        ):
            return None
        return (
            ["MODULE_LOCAL_DIRECTORY", "ALPHABET_AND_CLOCK_FILENAME"]
            if self.seal_source_binding(path, owner)
            else None
        )

    def module_directory(self, path, expr, scope, seen):
        if len(seen) >= 12 or id(expr) in seen:
            return False
        chain = (*seen, id(expr))
        if isinstance(expr, ast.Name):
            selected = self.resolve(path, expr, scope)
            if not isinstance(selected, tuple) or not isinstance(
                selected[1], ast.Assign
            ):
                return False
            next_path, assignment = selected
            target = assignment.targets[0]
            return self.namespace_slot_stable(target.id) and self.module_directory(
                next_path, assignment.value, None, chain
            )
        if not isinstance(expr, ast.Call) or not expr.args or expr.keywords:
            return False
        if self.check_call(path, expr, "os.path.dirname", 1):
            return self.absolute_module_file(path, expr.args[0], scope)
        if not self.check_call(path, expr, "os.path.join", len(expr.args)):
            return False
        return self.module_directory(path, expr.args[0], scope, chain) and all(
            _command_literal(arg, r"[A-Za-z0-9_.-]*") for arg in expr.args[1:]
        )

    def absolute_module_file(self, path, expr, scope):
        return (
            self.check_call(path, expr, "os.path.abspath", 1)
            and isinstance(expr.args[0], ast.Name)
            and expr.args[0].id == "__file__"
            and self.resolve(path, expr.args[0], scope) is _COMMAND_ABSENT
            and self.namespace_slot_stable("__file__")
        )

    def namespace_slot_stable(self, name):
        return not any(
            _command_field_change(item, name)
            or isinstance(item, (ast.Global, ast.Nonlocal))
            and name in item.names
            for nodes in self.nodes.values()
            for item in nodes
        )

    def generated_actual(self, site, owner, parameter):
        from .review_integrity import bind_source_call

        path, reference, call = site
        if not isinstance(call, ast.Call) or call.func is not reference:
            return False
        try:
            operand = bind_source_call(call, owner, apply_defaults=True)[parameter]
        except (KeyError, TypeError, ValueError):
            return False
        if isinstance(operand, ast.Name):
            operand = _command_branch_assignment(
                operand, call, self.source.parents[path], self.scope(path, call)
            )
        parts = _command_concat(operand)
        return (
            len(parts) == 2
            and self.alphabet_token(path, parts[0])
            and self.clock_token(path, parts[1])
        )

    def alphabet_token(self, path, expression):
        match expression:
            case ast.Call(
                func=ast.Attribute(value=ast.Constant(value=""), attr="join"),
                args=[sample],
                keywords=[],
            ) if self.check_call(path, sample, "random.sample", 2):
                alphabet, length = sample.args
                return (
                    _command_literal(alphabet, r"[A-Za-z0-9_-]{1,128}")
                    and isinstance(length, ast.Constant)
                    and type(length.value) is int
                    and 1 <= length.value <= len(alphabet.value)
                )
        return False

    def clock_token(self, path, expression):
        match expression:
            case ast.Subscript(
                value=ast.Call(
                    func=ast.Attribute(value=conversion, attr="split"),
                    args=[ast.Constant(value=".")],
                    keywords=[],
                ),
                slice=ast.Constant(value=0),
            ) if _command_call_shape(conversion, 1):
                callee = conversion.func
                if (
                    not isinstance(callee, ast.Name)
                    or callee.id != "str"
                    or self.resolve(path, callee, self.scope(path, conversion))
                    is not _COMMAND_ABSENT
                ):
                    return False
                self.providers.add("builtins.str")
                return self.check_call(path, conversion.args[0], "time.time", 0)
        return False

    def startup_directory(self, path, node, owner, pieces):
        """Close private constructor dispatch and both startup-path operands."""
        cls = self.source.parents[path].get(id(owner))
        if not _command_direct_class(cls, self.source.snapshots[path]):
            return None
        if not _command_options(pieces) or not _command_private_method(owner, cls):
            return None
        receiver = owner.args.args[0].arg
        directory = pieces[1]
        if not _command_field(directory, receiver) or not isinstance(
            pieces[3], ast.Name
        ):
            return None
        joined = _command_branch_assignment(
            pieces[3], node, self.source.parents[path], owner
        )
        if not self.check_call(path, joined, "os.path.join", 2):
            return None
        if not _command_same_field(
            joined.args[0], receiver, directory.attr
        ) or not _command_literal(joined.args[1], r"[A-Za-z0-9_][A-Za-z0-9_.-]*"):
            return None
        if not _command_private_receiver_reads(
            owner, receiver, directory, joined.args[0], self.source.parents[path]
        ):
            return None
        role = self.startup_field(path, owner, cls, directory.attr)
        if role is None:
            return None
        constructor, formal, key, dictionary_slots = role
        if not self.startup_call_sites(
            path, cls, constructor, formal, key, dictionary_slots
        ):
            return None
        return (
            ["PROCESS_STARTUP_DIRECTORY", "FIXED_CHILD_DIRECTORY"]
            if self.seal_source_binding(path, cls)
            else None
        )

    def startup_field(self, path, owner, cls, field):
        constructor = _command_method(cls, "__init__")
        if constructor is None or not constructor.args.args:
            return None
        receiver = constructor.args.args[0].arg
        if not _command_unrebound_parameter(constructor, receiver):
            return None
        call = self.private_dispatch(path, cls, constructor, owner, receiver)
        if call is None:
            return None
        value = self.field_before(path, constructor, call, receiver, field)
        if not _command_call_shape(value, 1) or not _command_field(
            value.args[0], receiver
        ):
            return None
        normalized = self.resolve(path, value.func, constructor)
        if not isinstance(normalized, tuple) or not self.normalizes_directory(
            *normalized
        ):
            return None
        settings = self.field_before(
            path, constructor, value, receiver, value.args[0].attr
        )
        source = _command_settings_slot(settings)
        if source is None or not _command_readonly_configuration(
            constructor, source[0], self.source.parents[path]
        ):
            return None
        dictionary_slots = _command_constructor_receiver_reads(
            constructor,
            cls,
            call,
            receiver,
            value.args[0],
            source[0],
            self.source.parents[path],
        )
        return (
            (constructor, *source, dictionary_slots)
            if dictionary_slots is not None
            else None
        )

    def private_dispatch(self, path, cls, constructor, method, receiver):
        method_name = method.name
        names = {method_name, "_" + cls.name.lstrip("_") + method_name}
        references = [
            (peer, item)
            for peer, items in self.nodes.items()
            for item in items
            if _command_member_probe(item, names)
        ]
        if len(references) != 1 or references[0][0] != path:
            return None
        member = references[0][1]
        if not _command_same_field(member, receiver, method_name):
            return None
        call = self.source.parents[path].get(id(member))
        if (
            _command_call_shape(call, 0)
            and call.func is member
            and self.scope(path, call) is constructor
            and _command_if_context(call, self.source.parents[path], constructor)
        ):
            return call
        return None

    def field_before(self, path, constructor, use, receiver, field):
        from .credential_role_constructor_provider import binding_dominates

        parents = self.source.parents[path]
        writes = self.field_writes(path, constructor, receiver, field)
        if writes is None:
            return None
        values = [write for write in writes if not _command_default_none(write.value)]
        if len(values) != 1 or not binding_dominates(
            values[0], use, parents, constructor
        ):
            return None
        if any(
            write is not values[0]
            and (not binding_dominates(write, values[0], parents, constructor))
            for write in writes
        ):
            return None
        return values[0].value

    def field_writes(self, path, constructor, receiver, field):
        from .credential_role_constructor_provider import binding_occurrences

        cls = self.source.parents[path].get(id(constructor))
        if not isinstance(cls, ast.ClassDef) or binding_occurrences(cls.body, field):
            return None
        rows = []
        for peer, items in self.nodes.items():
            for item in items:
                if not _command_field_change(item, field):
                    continue
                assignment = self.source.parents[peer].get(id(item))
                if peer != path or not _command_same_field(item, receiver, field):
                    return None
                if (
                    self.scope(path, item) is not constructor
                    or not isinstance(assignment, ast.Assign)
                    or assignment.targets != [item]
                ):
                    return None
                rows.append(assignment)
        return rows

    def normalizes_directory(self, path, normalizer):
        if (
            not isinstance(normalizer, ast.FunctionDef)
            or normalizer not in self.source.snapshots[path].body
        ):
            return False
        if not _command_exact_positionals(normalizer, 1):
            return False
        body = _command_body(normalizer)
        if len(body) != 3 or not _command_path_rewrite(
            body[:2], normalizer.args.args[0].arg
        ):
            return False
        statement = body[-1]
        if not isinstance(statement, ast.Return) or not self.check_call(
            path, statement.value, "os.path.normpath", 1
        ):
            return False
        if self.lookup(path, "ValueError", ()) is not _COMMAND_ABSENT:
            return False
        self.providers.add("builtins.ValueError")
        return _command_name(
            statement.value.args[0], body[0].targets[0].id
        ) and self.seal_source_binding(path, normalizer)

    def startup_call_sites(self, path, cls, constructor, formal, key, dictionary_slots):
        if any(
            _command_cwd_mutator(item)
            for nodes in self.nodes.values()
            for item in nodes
        ):
            return False
        if not self.constructor_access_closed():
            return False
        sites = self.call_sites(path, cls)
        if not sites:
            return False
        starts = 0
        for peer, reference, call in sites:
            if isinstance(call, ast.ClassDef) and reference in call.bases:
                if not _command_detached_subclass(call):
                    return False
            elif self.startup_actual(
                peer, reference, call, constructor, formal, key, dictionary_slots
            ):
                starts += 1
            else:
                return False
        return starts > 0

    def constructor_access_closed(self):
        for path, nodes in self.nodes.items():
            for node in nodes:
                if (
                    _command_member_probe(node, {"getattr"})
                    or _command_name(node, "getattr")
                    or _command_alias_name(node, "getattr")
                ):
                    return False
                if _command_member_probe(
                    node, {"__init__"}
                ) and not self.super_constructor(path, node):
                    return False
        return True

    def super_constructor(self, path, node):
        if not isinstance(node, ast.Attribute):
            return False
        invocation = self.source.parents[path].get(id(node))
        scope = self.scope(path, node)
        if (
            not isinstance(invocation, ast.Call)
            or invocation.func is not node
            or not isinstance(scope, ast.FunctionDef)
            or scope.name != "__init__"
        ):
            return False
        call = node.value
        if not _command_call_shape(call, 0) or not _command_name(call.func, "super"):
            return False
        if self.resolve(path, call.func, scope) is not _COMMAND_ABSENT:
            return False
        self.providers.add("builtins.super")
        return True

    def startup_actual(
        self, path, reference, call, constructor, formal, key, dictionary_slots
    ):
        from .review_integrity import bind_source_call

        if not isinstance(call, ast.Call) or call.func is not reference:
            return False
        tree, parents = self.source.snapshots[path], self.source.parents[path]
        use = parents.get(id(call))
        if (
            use not in tree.body
            or not isinstance(use, (ast.Assign, ast.Expr))
            or use.value is not call
        ):
            return False
        try:
            bound = bind_source_call(
                call, constructor, receiver=reference, apply_defaults=True
            )
        except (TypeError, ValueError):
            return False
        config = self.startup_config(path, call, bound.get(formal))
        if not isinstance(config, ast.Dict):
            return False
        if not all(
            _command_literal(item, r"[A-Za-z_][A-Za-z0-9_]*") for item in config.keys
        ):
            return False
        items = {item.value: value for item, value in zip(config.keys, config.values)}
        return (
            len(items) == len(config.keys)
            and all(
                _command_default_none(items.get(slot, ast.Constant(value=None)))
                or isinstance(items.get(slot), ast.Dict)
                for slot in dictionary_slots
            )
            and self.check_call(path, items.get(key), "os.getcwd", 0)
        )

    def startup_config(self, path, call, value):
        if not isinstance(value, ast.Name):
            return value
        tree = self.source.snapshots[path]
        selected = self.resolve(path, value)
        if not isinstance(selected, tuple):
            return None
        owner, statement = selected
        if (
            owner != path
            or not isinstance(statement, ast.Assign)
            or not _command_startup_binding(
                tree, self.source.parents[path], statement, value, call
            )
        ):
            return None
        if any(
            peer != path and _command_alias_import(items, value.id)
            for peer, items in self.nodes.items()
        ):
            return None
        if any(
            isinstance(item, ast.Attribute) and item.attr == value.id
            for items in self.nodes.values()
            for item in items
        ):
            return None
        return statement.value


def _command_call_shape(node, count):
    return (
        isinstance(node, ast.Call)
        and len(node.args) == count
        and not node.keywords
        and not any(isinstance(arg, ast.Starred) for arg in node.args)
    )


def _command_candidate(node):
    if not _command_call_shape(node, 1):
        return False
    pieces = _command_concat(node.args[0])
    return _command_generated_syntax(pieces) or _command_options(pieces)


def _command_generated_syntax(pieces):
    return (
        len(pieces) == 3
        and _command_literal(pieces[0], r"pdflatex ")
        and _command_literal(pieces[2], r"\.tex")
    )


def _command_concat(node):
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return [*_command_concat(node.left), *_command_concat(node.right)]
    return [node]


def _command_literal(node, pattern):
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and re.fullmatch(pattern, node.value) is not None
    )


def _command_matching_reference(item, names):
    match item:
        case ast.Name(id=name, ctx=ast.Load()):
            return name in names
        case ast.Attribute(attr=name, ctx=ast.Load()):
            return name in names
    return False


def _command_unrebound_parameter(function, name):
    from .credential_role_constructor_provider import binding_occurrences
    from .review_audits import _scope_parameters

    return (
        name in _scope_parameters(function)
        and not binding_occurrences(function.body, name)
        and not any(
            isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names
            for node in ast.walk(function)
        )
    )


def _command_branch_assignment(reference, use, parents, scope):
    from .credential_role_constructor_provider import binding_occurrences

    if (
        not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
        or _argument_binding_is_parameter_or_external(reference.id, scope)
        or not _command_if_context(use, parents, scope)
    ):
        return None
    targets = binding_occurrences(scope.body, reference.id)
    assignments = [parents.get(id(target)) for target in targets]
    if not all(
        isinstance(statement, ast.Assign) and statement.targets == [target]
        for target, statement in zip(targets, assignments)
    ):
        return None
    # A definition on the current executed branch wins over definitions in
    # sibling branches. Unmodeled intervening same-name stores retain the alert.
    cursor = use
    while (owner := parents.get(id(cursor))) is not None:
        for _, suite in ast.iter_fields(owner):
            if not isinstance(suite, list) or cursor not in suite:
                continue
            before = suite[: suite.index(cursor)]
            for prior in reversed(before):
                if prior in assignments:
                    return prior.value
                if any(item in assignments for item in ast.walk(prior)):
                    return None
        if owner is scope:
            break
        cursor = owner
    return None


def _command_if_context(use, parents, scope):
    while (owner := parents.get(id(use))) is not None:
        if owner is scope:
            return True
        if isinstance(owner, ast.stmt) and not isinstance(
            owner, (ast.Assign, ast.Return, ast.Expr, ast.If)
        ):
            return False
        use = owner
    return False


def _command_direct_class(cls, module):
    from .credential_role_constructor_provider import binding_occurrences

    return (
        isinstance(cls, ast.ClassDef)
        and cls in module.body
        and not cls.bases
        and not cls.decorator_list
        and not cls.keywords
        and not any(
            binding_occurrences(cls.body, name) for name in _COMMAND_CLASS_HOOKS
        )
    )


def _command_options(pieces):
    return (
        len(pieces) == 4
        and _command_literal(pieces[0], r"apidoc -i ")
        and _command_literal(pieces[2], r" -o ")
    )


def _command_private_method(method, cls):
    return (
        method.name.startswith("__")
        and not method.name.endswith("__")
        and _command_exact_positionals(method, 1)
        and _command_method(cls, method.name) is method
        and _command_unrebound_parameter(method, method.args.args[0].arg)
    )


def _command_exact_positionals(function, count):
    args = function.args
    return (
        not function.decorator_list
        and len(args.args) == count
        and not args.posonlyargs
        and not args.kwonlyargs
        and args.vararg is None
        and args.kwarg is None
        and not args.defaults
        and all(item.annotation is None for item in args.args)
        and function.returns is None
    )


def _command_field(node, receiver):
    return isinstance(node, ast.Attribute) and _command_name(node.value, receiver)


def _command_same_field(node, receiver, field):
    return _command_field(node, receiver) and node.attr == field


def _command_name(node, name):
    return isinstance(node, ast.Name) and node.id == name


def _command_method(cls, name):
    from .credential_role_constructor_provider import binding_occurrences

    rows = binding_occurrences(cls.body, name)
    if (
        len(rows) == 1
        and isinstance(rows[0], ast.FunctionDef)
        and rows[0] in cls.body
        and not rows[0].decorator_list
    ):
        return rows[0]
    return None


def _command_member_probe(node, names):
    if isinstance(node, ast.Attribute):
        return node.attr in names
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value in names
    )


def _command_field_change(node, field):
    return (
        isinstance(node, ast.Attribute)
        and node.attr == field
        and isinstance(node.ctx, (ast.Store, ast.Del))
    )


def _command_default_none(node):
    return isinstance(node, ast.Constant) and node.value is None


def _command_settings_slot(node):
    match node:
        case ast.Call(
            func=ast.Attribute(value=ast.Name(id=formal), attr="get"),
            args=[ast.Constant(value=str() as key), ast.Constant(value=None)],
            keywords=[],
        ):
            return formal, key
    return None


def _command_body(function):
    return (
        function.body[1:]
        if ast.get_docstring(function, clean=False) is not None
        else function.body
    )


def _command_path_rewrite(statements, parameter):
    match statements:
        case [
            ast.Assign(targets=[ast.Name(id=result)]),
            ast.For(
                target=ast.Name(id=directory),
                body=[ast.Try(handlers=[ast.ExceptHandler(name=error)])],
            ),
        ]:
            pass
        case _:
            return False
    names = (parameter, result, directory, error)
    if any(name is None or not name.isidentifier() for name in names) or len(
        set(names)
    ) != len(names):
        return False
    expected = ast.parse(f"""{result} = ""
for {directory} in {parameter}.split("/"):
    try:
        {directory}.index(" ")
        {result} += "'" + {directory} + "'/"
    except ValueError as {error}:
        {result} += {directory} + "/"
""").body
    return all(
        ast.dump(actual) == ast.dump(pattern)
        for actual, pattern in zip(statements, expected)
    )


def _command_detached_subclass(cls):
    initializer = _command_method(cls, "__init__")
    if (
        initializer is None
        or cls.decorator_list
        or cls.keywords
        or not initializer.args.args
    ):
        return False
    if any(isinstance(node, ast.Name) and node.id == "super" for node in ast.walk(cls)):
        return False
    receiver = initializer.args.args[0].arg
    return all(
        _command_detached_initialization(stmt, receiver)
        for stmt in _command_body(initializer)
    )


def _command_detached_initialization(statement, receiver):
    if isinstance(statement, ast.Pass):
        return True
    if (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and _command_field(statement.targets[0], receiver)
    ):
        return not any(
            _command_name(node, receiver) for node in ast.walk(statement.value)
        )
    return False


def _command_startup_binding(module, parents, statement, value, call):
    use = parents.get(id(call))
    if (
        statement not in module.body
        or use not in module.body
        or module.body.index(statement) >= module.body.index(use)
    ):
        return False
    return all(
        item is value
        or not _command_name(item, value.id)
        or not isinstance(item.ctx, ast.Load)
        for item in ast.walk(module)
    )


def _command_alias_import(nodes, name):
    return any(
        isinstance(item, ast.ImportFrom)
        and any(alias.name in {name, "*"} for alias in item.names)
        for item in nodes
    )


def _command_readonly_configuration(function, name, parents):
    if not _command_unrebound_parameter(function, name):
        return False
    return all(
        _command_configuration_read(node, parents)
        for node in ast.walk(function)
        if _command_name(node, name) and isinstance(node.ctx, ast.Load)
    )


def _command_private_receiver_reads(method, receiver, root, joined, parents):
    return all(
        parents.get(id(node)) in (root, joined)
        for node in ast.walk(method)
        if _command_name(node, receiver) and isinstance(node.ctx, ast.Load)
    )


def _command_constructor_receiver_reads(
    constructor, cls, dispatch, receiver, normalizer_arg, formal, parents
):
    """Close self access before dispatch and bind built-in dictionary reads."""
    from .credential_role_constructor_provider import binding_occurrences

    dictionary_slots = set()
    limit = (dispatch.lineno, dispatch.col_offset)
    for node in ast.walk(constructor):
        if not _command_name(node, receiver) or not isinstance(node.ctx, ast.Load):
            continue
        if (node.lineno, node.col_offset) >= limit:
            continue
        member = parents.get(id(node))
        if not _command_field(member, receiver) or binding_occurrences(
            cls.body, member.attr
        ):
            return None
        if member is normalizer_arg or _command_inert_receiver_member(member, parents):
            continue
        slot = _command_receiver_dictionary(
            member, constructor, receiver, formal, parents
        )
        if slot is None:
            return None
        dictionary_slots.add(slot)
    return tuple(sorted(dictionary_slots))


def _command_inert_receiver_member(member, parents):
    match parents.get(id(member)):
        case ast.Assign(targets=[target]) if target is member:
            return isinstance(member.ctx, ast.Store) and not member.attr.startswith(
                "__"
            )
        case ast.Compare(
            left=subject,
            ops=[ast.Is() | ast.IsNot()],
            comparators=[ast.Constant(value=None)],
        ):
            return subject is member
    return False


def _command_receiver_dictionary(member, constructor, receiver, formal, parents):
    from .credential_role_constructor_provider import binding_dominates

    access = parents.get(id(member))
    call = parents.get(id(access))
    if not _command_dict_get(call, access, member):
        return None
    found = []
    for node in ast.walk(constructor):
        if not _command_same_field(node, receiver, member.attr) or not isinstance(
            node.ctx, ast.Store
        ):
            continue
        definition = parents.get(id(node))
        if isinstance(definition, ast.Assign) and binding_dominates(
            definition, access, parents, constructor
        ):
            if origin := _command_settings_slot(definition.value):
                found.append(origin)
            else:
                return None
    return found[0][1] if len(found) == 1 and found[0][0] == formal else None


def _command_dict_get(call, access, member):
    return (
        _command_call_shape(call, 2)
        and call.func is access
        and isinstance(access, ast.Attribute)
        and access.attr == "get"
        and access.value is member
        and all(isinstance(arg, ast.Constant) for arg in call.args)
    )


def _command_configuration_read(node, parents):
    parent = parents.get(id(node))
    match parent:
        case ast.Compare(
            left=subject,
            ops=[ast.Is() | ast.IsNot()],
            comparators=[ast.Constant(value=None)],
        ):
            return subject is node
        case ast.Subscript(
            value=subject, slice=ast.Constant(value=str()), ctx=ast.Load()
        ):
            return subject is node
        case ast.Attribute(value=subject, attr="get", ctx=ast.Load()) if (
            subject is node
        ):
            call = parents.get(id(parent))
            return (
                _command_call_shape(call, 2)
                and call.func is parent
                and all(isinstance(argument, ast.Constant) for argument in call.args)
            )
    return False


def _command_cwd_mutator(item):
    match item:
        case ast.Attribute(attr=name) | ast.Name(id=name):
            return name in _COMMAND_DIRECTORY_MUTATORS
        case ast.alias(name=name):
            return name.rsplit(".", 1)[-1] in _COMMAND_DIRECTORY_MUTATORS
        case ast.Constant(value=str() as name):
            return name in _COMMAND_DIRECTORY_MUTATORS
    return False


def _command_alias_name(node, name):
    return isinstance(node, ast.alias) and node.name.rsplit(".", 1)[-1] == name


_COMMAND_PROOF_FUNCTIONS = tuple(
    name
    for name, value in globals().items()
    if name.startswith("_command_") and callable(value)
)
_COMMAND_PROOF_METHODS = tuple(
    name
    for name in vars(_CommandOperandProof)
    if callable(getattr(_CommandOperandProof, name))
)


def command_operand_proof_helpers():
    """Fingerprint actual producer and verifier lookup slots used by the proof."""
    from . import credential_role_constructor_provider as provider
    from . import intent_quality as intent
    from . import review_audits as audit
    from . import review_integrity as binding
    from . import runtime_audit_integrity as runtime

    return (
        captured_command_operand_proof,
        command_operand_proof_helpers,
        _CommandOperandProof,
        _COMMAND_NAMESPACE_QUERIES,
        _COMMAND_DIRECTORY_MUTATORS,
        _COMMAND_CLASS_HOOKS,
        _argument_binding_is_parameter_or_external,
        *(globals()[name] for name in _COMMAND_PROOF_FUNCTIONS),
        *(getattr(_CommandOperandProof, name) for name in _COMMAND_PROOF_METHODS),
        provider.binding_occurrences,
        provider.binding_dominates,
        provider._captured_terminal_provider_mutation,
        provider._scope_scope_bindings,
        intent.bound_sink_argument,
        audit._scope_parameters,
        *binding.source_binding_helpers(),
        runtime._conditional_module_name,
    )


_INSTALLER_TABLE_NAME = re.compile(
    r"[A-Za-z_][A-Za-z_0-9-]*(?:\.[A-Za-z_][A-Za-z_0-9-]*)*"
)
_INSTALLER_FIELD_NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9-]*")


def captured_installer_prerequisite(index, path, node):
    """Observe the captured manifest prerequisite without resolving the launch cwd."""
    from hashlib import sha256

    from .pytest_collection_audit import captured_pytest_documents
    from .runtime_audit_integrity import _source_span

    if not _command_call_shape(node, 1) or len(index.snapshots) > 128:
        return None
    module = index.snapshots.get(path)
    parsed = _installer_manifest_gate(module, node)
    if parsed is None or not index.validate(path):
        return None
    read, gate, search, flag, expected, failure = parsed
    documents = captured_pytest_documents(module)
    manifest = documents.get("pyproject.toml") if isinstance(documents, dict) else None
    if not _installer_required_header_absent(manifest, expected):
        return None
    if not _installer_providers_closed(index, path, node, search, flag):
        return None
    return {
        "hypothesis": "CAPTURED_ROOT_MANIFEST_PREREQUISITE",
        "scope": "CAPTURED_ROOT_MANIFEST_UTF8",
        "manifest": {"path": "pyproject.toml", "sha256": sha256(manifest).hexdigest()},
        "required_header": expected,
        "read_span": _source_span(read),
        "guard_span": _source_span(gate),
        "raise_span": _source_span(failure),
        "manifest_encoding": "UTF-8",
        "working_directory_selection": "UNASSESSED",
        "failure": "REQUIRED_HEADER_ABSENT",
        "shell_operation": "RETAINED",
    }


def _installer_manifest_gate(module, sink):
    if not isinstance(module, ast.Module) or not any(
        isinstance(stmt, ast.Expr) and stmt.value is sink for stmt in module.body
    ):
        return None
    body = module.body[1:] if ast.get_docstring(module) is not None else module.body
    pos = next(
        (
            i
            for i, stmt in enumerate(body)
            if not isinstance(stmt, (ast.Import, ast.ImportFrom))
        ),
        len(body),
    )
    match body[pos : pos + 2]:
        case [read, ast.If() as gate]:
            name = _installer_manifest_read_name(read)
            selector = _installer_gate_search(gate, name)
            if selector is not None:
                search, flag, expected, failure = selector
                return read, gate, search, flag, expected, failure
    return None


def _installer_manifest_read_name(statement):
    match statement:
        case ast.Assign(
            targets=[ast.Name(id=name)],
            value=ast.Call(
                func=ast.Attribute(
                    value=ast.Call(
                        func=ast.Name(id="open"),
                        args=[
                            ast.Constant(value="pyproject.toml" | "./pyproject.toml")
                        ],
                        keywords=[],
                    ),
                    attr="read",
                ),
                args=[],
                keywords=[],
            ),
        ):
            return name
    return None


def _installer_gate_search(gate, content):
    match gate:
        case ast.If(
            test=ast.NamedExpr(
                target=ast.Name(),
                value=ast.Call(
                    func=search,
                    args=[
                        ast.Constant(value=str() as pattern),
                        ast.Name(id=name),
                        flag,
                    ],
                    keywords=[],
                ),
            ),
            orelse=[
                ast.Raise(
                    exc=ast.Call(
                        func=ast.Name(id="ValueError"),
                        args=[ast.Constant(value=str())],
                        keywords=[],
                    ),
                    cause=None,
                ) as failure
            ],
        ) if name == content:
            header = _installer_required_header(pattern)
            if header is not None:
                return search, flag, header, failure
    return None


def _installer_required_header(pattern):
    """Recognize the fixed-width table prefix of a bounded installer pattern."""
    if len(pattern) > 256 or not pattern.startswith(r"\["):
        return None
    table, separator, tail = pattern[2:].partition(r"\]\n")
    key, equals, values = tail.partition(" = ")
    if (
        separator
        and equals
        and _INSTALLER_TABLE_NAME.fullmatch(table)
        and _INSTALLER_FIELD_NAME.fullmatch(key)
        and values == r'"[^"]+"\n(.+?)\n\n'
    ):
        return f"[{table}]"
    return None


def _installer_required_header_absent(manifest, expected):
    if not isinstance(manifest, bytes) or not 0 < len(manifest) <= 64_000:
        return False
    try:
        text = manifest.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except UnicodeDecodeError:
        return False
    # Dots in the original header are single-character regex wildcards. The
    # validated table-name alphabet admits no repetitions or other operators.
    return re.search(r"\[" + expected[1:-1] + r"\]", text, re.DOTALL) is None


def _installer_providers_closed(index, path, node, search, flag):
    from .credential_role_constructor_provider import binding_occurrences

    module = index.snapshots[path]
    if any(binding_occurrences(module.body, name) for name in ("open", "ValueError")):
        return False
    proof = _CommandOperandProof(index)
    if not proof.inventory_closed() or not all(
        _installer_provider_import_precedes(module, operand)
        and proof.resolve(path, operand) == provider
        for operand, provider in (
            (node.func, "os.system"),
            (search, "re.search"),
            (flag, "re.DOTALL"),
        )
    ):
        return False
    proof.providers.update(
        ("os.system", "re.search", "re.DOTALL", "builtins.open", "builtins.ValueError")
    )
    return proof.providers_closed(
        readonly_argument=lambda operand, _aliases, _parents: operand is flag
    )


def _installer_provider_import_precedes(module, expression):
    from .credential_role_constructor_provider import binding_occurrences

    root = expression
    while isinstance(root, ast.Attribute):
        root = root.value
    if not isinstance(root, ast.Name):
        return False
    match binding_occurrences(module.body, root.id):
        case [ast.Import() | ast.ImportFrom() as declaration]:
            return declaration in module.body and declaration.lineno < expression.lineno
    return False


def installer_prerequisite_helpers():
    """Declare the live prerequisite-analysis dependencies for replay caching."""
    from hashlib import sha256

    from .credential_role_constructor_provider import binding_occurrences
    from .pytest_collection_audit import captured_pytest_documents
    from .runtime_audit_integrity import _source_span

    return (
        captured_installer_prerequisite,
        installer_prerequisite_helpers,
        _installer_manifest_gate,
        _installer_manifest_read_name,
        _installer_gate_search,
        _installer_required_header,
        _installer_required_header_absent,
        _installer_providers_closed,
        _installer_provider_import_precedes,
        _INSTALLER_TABLE_NAME,
        _INSTALLER_FIELD_NAME,
        re.search,
        re.DOTALL,
        sha256,
        binding_occurrences,
        captured_pytest_documents,
        _source_span,
        *command_operand_proof_helpers(),
    )


_UNMODELED_REPRESENTATION = object()
_REPRESENTATION_BUILTINS = frozenset({"eval", "repr", "str", "print"})
_REPRESENTATION_METHODS = frozenset(
    {"__init__", "__repr__", "__str__", "__eq__", "__ne__", "__add__"}
)
_REPRESENTATION_LIMIT = 20
_REPRESENTATION_TERMS = 2048


@dataclass(frozen=True)
class _RepresentationValue:
    """A source-derived local allocation, with no runtime Python instance."""

    owner: str
    field: str
    value: object


def captured_local_representation_proof(index, path, node):
    """Prove one reconstructive eval operand using only bounded captured Python AST."""
    from .runtime_audit_integrity import _exact_source_call, _source_span

    if _representation_receiver(node) is None or not index.validate(path):
        return None
    if len(index.snapshots) > 128 or len(index.source_bytes[path]) > 64_000:
        return None
    exact = _exact_source_call(index.source_bytes[path], node)
    if exact is None:
        return None
    tree, call = exact
    if not _representation_reconstructs_receiver(index, path, tree, call):
        return None
    return {
        "hypothesis": "CAPTURED_SOURCE_INJECTION",
        "scope": "CAPTURED_PYTHON_SOURCE",
        "program_role": "CLOSED_LOCAL_CONSTRUCTOR_REPRESENTATION",
        "operand_span": _source_span(call.args[0]),
        "external_callers": "UNASSESSED",
        "runtime_effects": "UNASSESSED",
        "dynamic_execution_primitive": "RETAINED",
    }


def _representation_reconstructs_receiver(index, path, tree, call):
    target = _representation_assertion(tree, call)
    if target is None or not _representation_providers_closed(index, path, tree, call):
        return False
    model = _LocalRepresentation()
    if not model.prefix(tree.body[:target]):
        return False
    original = model.values.get(_representation_receiver(call))
    return isinstance(original, _RepresentationValue) and model.round_trip(original)


def _representation_receiver(node):
    match node:
        case ast.Call(
            func=ast.Name(id="eval"),
            args=[
                ast.Call(
                    func=ast.Name(id="repr"), args=[ast.Name(id=name)], keywords=[]
                )
            ],
            keywords=[],
        ):
            return name
    return None


def _representation_assertion(tree, call):
    receiver = _representation_receiver(call)
    for position, statement in enumerate(tree.body):
        if position > 64:
            break
        match statement:
            case ast.Assert(
                test=ast.Compare(
                    left=ast.Name(id=name), ops=[ast.Eq()], comparators=[target]
                ),
                msg=None,
            ) if target is call and name == receiver:
                return position
    return None


def _representation_providers_closed(index, target, tree, call):
    from .finite_capture import _fixed_eval_builtin_source_clear

    for path in index.snapshots:
        if not index.validate(path) or index.relative(path) is None:
            return False
        if path.stem in {"typing", "__future__"} or path.parent.name in {
            "typing",
            "__future__",
        }:
            return False
        module = tree if path == target else index.snapshots[path]
        if not _fixed_eval_builtin_source_clear(module, call):
            return False
        if any(_representation_provider_escape(item) for item in ast.walk(module)):
            return False
    return True


def _representation_provider_escape(node):
    match node:
        case ast.alias(name=name) | ast.ImportFrom(module=name) if name:
            return name.split(".", 1)[0] in {
                "builtins",
                "sys",
                "importlib",
                "runpy",
                "ctypes",
                "inspect",
                "types",
                "pytest",
                "_pytest",
                "unittest",
                "mock",
            }
        case ast.Attribute(attr=name):
            return name in {
                "__class__",
                "__subclasses__",
                "__bases__",
                "__mro__",
                "__closure__",
                "__code__",
                "f_globals",
                "f_locals",
                "f_builtins",
                "_getframe",
                "modules",
                "patch",
                "patch_object",
                "setattr",
                "delattr",
                "setitem",
                "delitem",
            }
    return False


def _representation_scalar(value):
    if type(value) is str:
        return len(value) <= 256
    if type(value) is int:
        return value.bit_length() <= 256
    return type(value) in {bool, type(None)}


def _representation_method_parameters(method, count):
    if method is None or getattr(method, "type_params", ()):
        return ()
    params = method.args
    if len(params.args) != count or any(
        (params.posonlyargs, params.kwonlyargs, params.vararg, params.kwarg)
    ):
        return ()
    names = tuple(argument.arg for argument in params.args)
    return (
        names
        if len(set(names)) == count and not (set(names) & _REPRESENTATION_BUILTINS)
        else ()
    )


def _representation_class_methods(owner, future_annotations):
    if any(
        (
            owner.bases,
            owner.keywords,
            owner.decorator_list,
            getattr(owner, "type_params", ()),
        )
    ):
        return None
    methods = {}
    for node in owner.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            continue
        if not _representation_method_declaration(node, methods, future_annotations):
            return None
        methods[node.name] = node
    return methods


def _representation_method_declaration(node, methods, future_annotations):
    if (
        not isinstance(node, ast.FunctionDef)
        or node.name in methods
        or node.decorator_list
    ):
        return False
    if node.name.startswith("__") and node.name not in _REPRESENTATION_METHODS:
        return False
    if getattr(node, "type_params", ()) or not all(
        isinstance(value, ast.Constant) and _representation_scalar(value.value)
        for value in (
            *node.args.defaults,
            *(item for item in node.args.kw_defaults if item),
        )
    ):
        return False
    return future_annotations or (
        node.returns is None
        and not any(
            isinstance(item, ast.arg) and item.annotation is not None
            for item in ast.walk(node.args)
        )
    )


class _LocalRepresentation:
    """Interpret source forms needed to trace a fresh local representation."""

    def __init__(self):
        self.values = {}
        self.classes = {}
        self.names = set(_REPRESENTATION_BUILTINS)
        self.future_annotations = False
        self.remaining = _REPRESENTATION_TERMS

    def prefix(self, statements):
        for statement in statements:
            if not self.statement(statement):
                return False
        return True

    def statement(self, node):
        match node:
            case ast.Expr(value=ast.Constant()):
                return True
            case ast.ImportFrom(
                module="__future__",
                names=[ast.alias(name="annotations", asname=None)],
                level=0,
            ):
                self.future_annotations = True
                return self.bind("annotations")
            case ast.ImportFrom(
                module="typing", names=[ast.alias(name="List", asname=None)], level=0
            ):
                return self.bind("List")
            case ast.ClassDef(name=name) if self.bind(name):
                methods = _representation_class_methods(node, self.future_annotations)
                if methods is not None:
                    self.classes[name] = methods
                    return True
            case ast.Assign(targets=[ast.Name(id=name)], value=expr) if self.bind(name):
                value = self.value(expr, self.values, 0)
                if value is not _UNMODELED_REPRESENTATION:
                    self.values[name] = value
                    return True
            case ast.Assert(
                test=ast.Compare(left=left, ops=[ast.Eq()], comparators=[right]),
                msg=None,
            ):
                # A prior equality may abort the module. Prove only that either
                # outcome leaves the bindings untouched for a later reachable call.
                return all(
                    _representation_scalar(self.value(term, self.values, 0))
                    for term in (left, right)
                )
        return False

    def bind(self, name):
        if name in self.names or name.startswith("__"):
            return False
        self.names.add(name)
        return True

    def value(self, node, env, depth):
        if not self.take_term(depth):
            return _UNMODELED_REPRESENTATION
        next_depth = depth + 1
        match node:
            case ast.Constant(value=value) if _representation_scalar(value):
                return value
            case ast.Name(id=name):
                return env.get(name, _UNMODELED_REPRESENTATION)
            case ast.Attribute(value=ast.Name(id=name), attr=field):
                base = env.get(name)
                if isinstance(base, _RepresentationValue) and field == base.field:
                    return base.value
            case ast.List(elts=elts) if len(elts) <= _REPRESENTATION_LIMIT:
                return self.sequence(elts, env, next_depth)
            case ast.Call():
                return self.invoke(node, env, next_depth)
            case ast.JoinedStr(values=parts):
                return self.fstring(parts, env, next_depth)
            case ast.ListComp():
                return self.comprehension(node, env, next_depth)
        return _UNMODELED_REPRESENTATION

    def take_term(self, depth):
        self.remaining -= 1
        return self.remaining >= 0 and depth < _REPRESENTATION_LIMIT

    def comprehension(self, node, env, depth):
        match node:
            case ast.ListComp(
                elt=elt,
                generators=[
                    ast.comprehension(
                        target=ast.Name(id=name), iter=source, ifs=[], is_async=0
                    )
                ],
            ) if name not in _REPRESENTATION_BUILTINS:
                values = self.value(source, env, depth)
                if isinstance(values, tuple):
                    items = tuple(
                        self.value(elt, {**env, name: value}, depth) for value in values
                    )
                    if _UNMODELED_REPRESENTATION not in items:
                        return items
        return _UNMODELED_REPRESENTATION

    def sequence(self, elts, env, depth):
        items = tuple(self.value(item, env, depth) for item in elts)
        return (
            items
            if _UNMODELED_REPRESENTATION not in items
            else _UNMODELED_REPRESENTATION
        )

    def invoke(self, call, env, depth):
        match call:
            case ast.Call(func=ast.Name(id="str"), args=[value], keywords=[]):
                text = self.render(self.value(value, env, depth), False, depth)
                return text if text is not None else _UNMODELED_REPRESENTATION
            case ast.Call(func=ast.Name(id=name)) if (
                name in self.classes and name not in env
            ):
                return self.construct(name, call, env, depth)
            case ast.Call(
                func=ast.Attribute(value=ast.Call() as origin, attr=name),
                args=[value],
                keywords=[],
            ):
                base = self.fresh(origin, env, depth)
                if isinstance(base, _RepresentationValue):
                    return self.append(base, name, self.value(value, env, depth))
        return _UNMODELED_REPRESENTATION

    def fresh(self, node, env, depth):
        if depth >= _REPRESENTATION_LIMIT:
            return _UNMODELED_REPRESENTATION
        match node:
            case ast.Call(func=ast.Name(id=name), args=[], keywords=[]) if (
                name in self.classes and name not in env
            ):
                return self.construct(name, node, env, depth + 1)
            case ast.Call(
                func=ast.Attribute(value=ast.Call(), attr=_), args=[_], keywords=[]
            ):
                return self.invoke(node, env, depth + 1)
        return _UNMODELED_REPRESENTATION

    def construct(self, name, call, env, depth):
        init = self.classes[name].get("__init__")
        formals = _representation_method_parameters(init, 2)
        if not formals or len(init.args.defaults) > 1:
            return _UNMODELED_REPRESENTATION
        receiver, argument = formals
        match call:
            case ast.Call(args=[actual], keywords=[]):
                value = self.value(actual, env, depth)
            case ast.Call(args=[], keywords=[ast.keyword(arg=key, value=actual)]) if (
                key == argument
            ):
                value = self.value(actual, env, depth)
            case ast.Call(args=[], keywords=[]) if init.args.defaults:
                value = init.args.defaults[0].value
            case _:
                return _UNMODELED_REPRESENTATION
        if value is _UNMODELED_REPRESENTATION:
            return value
        field, value = _representation_initializer(init.body, receiver, argument, value)
        if field is None or field.startswith("__"):
            return _UNMODELED_REPRESENTATION
        # An instance field must not replace an existing method.
        if field in self.classes[name]:
            return _UNMODELED_REPRESENTATION
        return _RepresentationValue(name, field, value)

    def append(self, base, name, item):
        if item is _UNMODELED_REPRESENTATION or not isinstance(base.value, tuple):
            return _UNMODELED_REPRESENTATION
        if len(base.value) >= _REPRESENTATION_LIMIT:
            return _UNMODELED_REPRESENTATION
        method = self.classes[base.owner].get(name)
        arguments = _representation_method_parameters(method, 2)
        if (
            arguments
            and not method.args.defaults
            and _representation_append_body(method.body, base.field, *arguments)
        ):
            return _RepresentationValue(base.owner, base.field, (*base.value, item))
        return _UNMODELED_REPRESENTATION

    def fstring(self, parts, env, depth):
        text = []
        for item in parts:
            match item:
                case ast.Constant(value=str() as literal):
                    text.append(literal)
                case ast.FormattedValue(
                    value=expr, conversion=conversion, format_spec=None
                ) if conversion in {-1, ord("s"), ord("r")}:
                    part = self.render(
                        self.value(expr, env, depth), conversion == ord("r"), depth
                    )
                    if part is None:
                        return _UNMODELED_REPRESENTATION
                    text.append(part)
                case _:
                    return _UNMODELED_REPRESENTATION
        return (
            "".join(text) if sum(map(len, text)) <= 4096 else _UNMODELED_REPRESENTATION
        )

    def render(self, value, representation, depth):
        if not self.take_term(depth):
            return None
        if _representation_scalar(value):
            return repr(value) if representation else str(value)
        if isinstance(value, tuple):
            pieces = [self.render(item, True, depth + 1) for item in value]
            return "[" + ", ".join(pieces) + "]" if None not in pieces else None
        if isinstance(value, _RepresentationValue):
            return self.render_instance(value, representation, depth + 1)
        return None

    def render_instance(self, value, representation, depth):
        methods = self.classes[value.owner]
        name = "__repr__" if representation or "__str__" not in methods else "__str__"
        method = methods.get(name)
        parameters = _representation_method_parameters(method, 1)
        if not parameters or method.args.defaults:
            return None
        env = {parameters[0]: value}
        *prefix, result = method.body
        if prefix and (
            name != "__str__" or not self.display_prefix(prefix, env, depth)
        ):
            return None
        if isinstance(result, ast.Return):
            output = self.value(result.value, env, depth)
            if type(output) is str:
                return output
        return None

    def display_prefix(self, statements, env, depth):
        for statement in statements:
            match statement:
                case ast.Expr(
                    value=ast.Call(func=ast.Name(id="print"), args=args, keywords=[])
                ):
                    if not all(
                        type(self.value(arg, env, depth)) is str for arg in args
                    ):
                        return False
                case _:
                    return False
        return True

    def round_trip(self, original):
        program = self.render(original, True, 0)
        if program is None or len(program) > 4096:
            return False
        try:
            expression = ast.parse(program, mode="eval").body
        except (SyntaxError, ValueError, TypeError, RecursionError):
            return False
        return self.constructor_expression(expression) and _representation_same_value(
            self.value(expression, {}, 0), original
        )

    def constructor_expression(self, expression):
        for node in ast.walk(expression):
            if isinstance(node, ast.Call):
                if (
                    not isinstance(node.func, ast.Name)
                    or node.func.id not in self.classes
                ):
                    return False
            elif not isinstance(
                node, (ast.Name, ast.List, ast.Constant, ast.Load, ast.keyword)
            ):
                return False
        return True


def _representation_initializer(body, receiver, formal, value):
    match body:
        case [
            ast.If(
                test=ast.Compare(
                    left=ast.Name(id=name),
                    ops=[ast.Is()],
                    comparators=[ast.Constant(value=None)],
                ),
                body=[empty],
                orelse=[assigned],
            )
        ] if name == formal:
            return _representation_optional_list(
                empty, assigned, receiver, formal, value
            )
        case [assignment]:
            return _representation_field(assignment, receiver, formal), value
    return None, None


def _representation_field(assignment, receiver, formal):
    match assignment:
        case ast.Assign(
            targets=[ast.Attribute(value=ast.Name(id=owner), attr=field)],
            value=ast.Name(id=name),
        ) if (owner, name) == (receiver, formal):
            return field
    return None


def _representation_optional_list(empty, assigned, receiver, formal, value):
    field = _representation_field(assigned, receiver, formal)
    match empty:
        case ast.Assign(
            targets=[ast.Attribute(value=ast.Name(id=owner), attr=attribute)],
            value=ast.List(elts=[]),
        ) if (owner, attribute) == (receiver, field):
            return field, () if value is None else value
    return None, None


def _representation_append_body(body, field, receiver, argument):
    match body:
        case [
            ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(
                        value=ast.Attribute(value=ast.Name(id=owner), attr=attribute),
                        attr="append",
                    ),
                    args=[ast.Name(id=item)],
                    keywords=[],
                )
            ),
            ast.Return(value=ast.Name(id=result)),
        ]:
            return (owner, attribute, item, result) == (
                receiver,
                field,
                argument,
                receiver,
            )
    return False


def _representation_same_value(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, _RepresentationValue):
        return (left.owner, left.field) == (right.owner, right.field) and (
            _representation_same_value(left.value, right.value)
        )
    if isinstance(left, tuple):
        return len(left) == len(right) and all(
            _representation_same_value(first, second)
            for first, second in zip(left, right)
        )
    return left == right


# Bind the exact proof implementation to the native verifier cache epoch.
_LOCAL_REPRESENTATION_HELPERS = tuple(
    name
    for name in globals()
    if name.startswith("_representation_") and callable(globals()[name])
)
_LOCAL_REPRESENTATION_METHODS = tuple(
    name for name, member in vars(_LocalRepresentation).items() if callable(member)
)


def captured_local_representation_helpers():
    """Expose the live callable bindings that control representation refutation."""
    from .finite_capture import _fixed_eval_builtin_source_clear
    from .runtime_audit_integrity import _exact_source_call, _source_span

    return (
        captured_local_representation_proof,
        _exact_source_call,
        _source_span,
        _fixed_eval_builtin_source_clear,
        _UNMODELED_REPRESENTATION,
        _REPRESENTATION_BUILTINS,
        _REPRESENTATION_METHODS,
        _REPRESENTATION_LIMIT,
        _REPRESENTATION_TERMS,
        _LocalRepresentation,
        _RepresentationValue,
        *(globals()[name] for name in _LOCAL_REPRESENTATION_HELPERS),
        *(
            getattr(_LocalRepresentation, name)
            for name in _LOCAL_REPRESENTATION_METHODS
        ),
        _RepresentationValue.__init__,
        _RepresentationValue.__eq__,
    )


# Cross-function entry reach for parameter-sourced sinks.
#
# Cross-function reach for parameter-sourced pattern findings (Python).
#
# The ``*.parameter-*`` pattern rules see one function: a parameter that reaches a
# shell, SQL or file sink. This pass follows that parameter to its callers and
# iterates to a fixpoint, so each finding gets one of four reach states:
#
# ``entry_reached``
#     An untrusted input (request data, ``sys.argv``, ``input()``, parsed CLI
#     arguments, or a parameter of a route, MCP tool or CLI command handler)
#     reaches the parameter through resolved calls. The chain is recorded.
# ``callers_constant_only``
#     The function is private and every resolved call site passes a literal,
#     an upper-case constant or a sanitized value.
# ``public_api``
#     No resolved untrusted caller, and the function is public: library users
#     can still call it with untrusted data.
# ``unresolved``
#     Anything else, including calls through ``*args``/``**kwargs``.
#
# Only ``entry_reached`` raises confidence and only ``callers_constant_only``
# lowers it; the pass never removes a finding. Resolution is static and
# conservative: direct names, imported names, module aliases, ``self``/``cls``
# methods, and attribute calls whose method name is unique in the repository.


REACH_SCHEMA = "factory.parameter-reach.v1"
MAX_ITERATIONS = 12
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "site-packages", "__pycache__"}
_ENTRY_DECORATOR = re.compile(
    r"(?:^|\.)(route|get|post|put|patch|delete|api_view|websocket|tool|command|"
    r"group|callback|action|endpoint|resource|prompt)$"
)
_REQUEST_ATTRS = {
    "args",
    "form",
    "values",
    "json",
    "data",
    "files",
    "GET",
    "POST",
    "FILES",
    "query_params",
    "body",
    "headers",
    "cookies",
    "COOKIES",
    "META",
    "path_params",
}
_MCP_CLASS = re.compile(r"(?i)(tool|mcp|server|handler)")
_REGISTRATION = re.compile(
    r"(?:^|\.)(add_url_rule|add_api_route|add_api_websocket_route|add_route|"
    r"add_websocket_route|register_tool|add_tool|add_command|add_typer|"
    r"add_resource|add_handler|register_handler|add_view)$"
)
_REGISTRY_NAME = re.compile(r"(?i)(tools|handlers|commands|routes|registry|dispatch)")


_FUNCTION_OR_CLASS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _registers_handlers(call: ast.Call) -> bool:
    """``app.add_url_rule(..., view)`` style calls, or ``mcp.tool()(handler)``."""
    if _REGISTRATION.search(_dotted(call.func)):
        return True
    inner = call.func
    return isinstance(inner, ast.Call) and bool(
        _ENTRY_DECORATOR.search(_dotted(inner.func))
    )


def _is_handler_registry(node: ast.AST) -> bool:
    """A module-level ``NAME = {key: function, ...}`` registry of handlers."""
    return (
        isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Dict)
        and any(
            isinstance(t, ast.Name) and _REGISTRY_NAME.search(t.id)
            for t in node.targets
        )
    )


_MCP_ARGUMENTS = {"arguments", "args", "params", "tool_input", "input_data", "kwargs"}
_SANITIZERS = re.compile(
    r"(?:^|\.)(quote|escape|int|float|bool|basename|secure_filename|abs|len|"
    r"Identifier|Literal|validate\w*|sanitize\w*|safe\w*)$"
)


@dataclass
class Function:
    key: str
    module: str
    path: str
    node: ast.AST
    params: list[str]
    class_name: str | None
    is_entry: bool
    public: bool


@dataclass
class Reach:
    state: str
    chain: list[str] = field(default_factory=list)


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _module_name(relative: str) -> str:
    parts = relative.removesuffix(".py").split("/")
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _params(node: ast.AST, method: bool) -> list[str]:
    args = node.args
    names = [a.arg for a in [*args.posonlyargs, *args.args]]
    if method and names and names[0] in {"self", "cls"}:
        names = names[1:]
    variadic = [a.arg for a in (args.vararg, args.kwarg) if a is not None]
    return names + [a.arg for a in args.kwonlyargs] + variadic


def _is_entry(node: ast.AST) -> bool:
    return any(_ENTRY_DECORATOR.search(_dotted(d)) for d in node.decorator_list)


def _relative_import_prefix(module: str, is_package: bool, node: ast.ImportFrom) -> str:
    package = module if is_package else module.rpartition(".")[0]
    parts = package.split(".") if package else []
    if node.level > 1:
        parts = parts[: len(parts) - (node.level - 1)]
    return ".".join(p for p in (".".join(parts), node.module or "") if p)


def _module_imports(module: str, is_package: bool, tree: ast.Module) -> dict[str, str]:
    imports: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level:
                prefix = _relative_import_prefix(module, is_package, node)
            else:
                prefix = node.module or ""
            for alias in node.names:
                imports[alias.asname or alias.name] = f"{prefix}.{alias.name}"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                imports[alias.asname or top] = alias.name if alias.asname else top
    return imports


class Index:
    """Functions, imports and call sites of one Python source tree."""

    def __init__(self, sources: dict[str, str]):
        self.functions: dict[str, Function] = {}
        self._function_spans: dict[str, list[tuple[int, int, str]]] = {}
        self.imports: dict[str, dict[str, str]] = {}
        self.calls: list[tuple[str, ast.Call, str]] = []  # caller key, call, module
        self.method_names: dict[str, list[str]] = {}
        self.cli_args: dict[str, set[str]] = {}
        self.trees: dict[str, ast.Module] = {}
        for relative in sorted(sources):
            if not relative.endswith(".py") or _SKIP_DIRS.intersection(
                relative.split("/")
            ):
                continue
            try:
                tree = ast.parse(sources[relative])
            except (SyntaxError, ValueError, RecursionError):
                continue
            self.trees[relative] = tree
            self._index_module(relative, tree)
        self._mark_registered_entries()

    @cached_property
    def _callers(self) -> dict[str, list[tuple[Function, ast.Call]]]:
        return _call_graph(self)

    def _mark_registered_entries(self) -> None:
        """Handlers passed to a route, tool or command registration are entries."""
        calls = [
            (self.functions[key], call, module) for key, call, module in self.calls
        ]
        for relative, tree in self.trees.items():
            module = _module_name(relative)
            for node in tree.body:
                if _is_handler_registry(node):
                    for value in node.value.values:
                        self._mark_reference(value, module, None)
                if not isinstance(node, _FUNCTION_OR_CLASS):
                    calls.extend(
                        (None, call, module)
                        for call in ast.walk(node)
                        if isinstance(call, ast.Call)
                    )
        for caller, call, module in calls:
            if _registers_handlers(call):
                for value in [*call.args, *(k.value for k in call.keywords)]:
                    self._mark_reference(value, module, caller)

    def _mark_reference(self, value: ast.AST, module: str, caller) -> None:
        if not isinstance(value, (ast.Name, ast.Attribute)):
            return
        if isinstance(value, ast.Name):
            target = self._resolve_name(value.id, module)
        else:
            target = self._resolve_attribute(value, module, caller)
        if target is not None:
            target.is_entry = True

    @classmethod
    def from_root(cls, root: Path) -> Index:
        """Index every Python file under ``root`` outside vendored directories."""
        sources = {}
        for path in sorted(root.rglob("*.py")):
            relative = path.relative_to(root).as_posix()
            if path.is_file() and not _SKIP_DIRS.intersection(relative.split("/")):
                try:
                    sources[relative] = path.read_text(
                        encoding="utf-8", errors="replace"
                    )
                except OSError:
                    continue
        return cls(sources)

    def _index_module(self, relative: str, tree: ast.Module) -> None:
        module = _module_name(relative)
        is_package = relative.rsplit("/", 1)[-1] == "__init__.py"
        self.imports[module] = _module_imports(module, is_package, tree)
        private = any(
            part.startswith("_") and part != "__init__" for part in module.split(".")
        )
        self._visit(tree.body, None, "", (module, relative, private))

    def _visit(self, body, class_name: str | None, scope: str, context) -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                self._visit(node.body, node.name, f"{scope}{node.name}.", context)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._add_function(node, class_name, scope, context)
                inner = f"{scope}{node.name}.<locals>."
                self._visit(node.body, class_name, inner, context)

    def _add_function(self, node, class_name, scope, context) -> None:
        module, relative, private = context
        key = f"{module}:{scope}{node.name}"
        public = not (
            node.name.startswith("_") or private or (class_name or "").startswith("_")
        )
        entry = _is_entry(node) or _is_mcp_handler(relative, node, class_name)
        params = _params(node, class_name is not None)
        self.functions[key] = Function(
            key, module, relative, node, params, class_name, entry, public
        )
        end = getattr(node, "end_lineno", node.lineno)
        self._function_spans.setdefault(relative, []).append((node.lineno, end, key))
        if class_name is not None:
            self.method_names.setdefault(node.name, []).append(key)
        self.cli_args[key] = _parsed_cli_names(node)
        self.calls.extend(
            (key, child, module)
            for child in ast.walk(node)
            if isinstance(child, ast.Call)
        )

    def enclosing(self, relative: str, line: int) -> Function | None:
        """The innermost indexed function whose span contains ``line``."""
        best = None
        for start, end, key in self._function_spans.get(relative, []):
            if start <= line <= end:
                if best is None or start >= self.functions[best].node.lineno:
                    best = key
        return self.functions.get(best) if best else None

    def resolve(self, call: ast.Call, module: str, caller: Function) -> Function | None:
        """The indexed function a call names, when it resolves statically."""
        if isinstance(call.func, ast.Name):
            return self._resolve_name(call.func.id, module)
        if isinstance(call.func, ast.Attribute):
            return self._resolve_attribute(call.func, module, caller)
        return None

    def _resolve_name(self, name: str, module: str) -> Function | None:
        local = self.functions.get(f"{module}:{name}")
        if local:
            return local
        target = self.imports.get(module, {}).get(name)
        if target and "." in target:
            owner, attribute = target.rsplit(".", 1)
            return self.functions.get(f"{owner}:{attribute}")
        return None

    def _resolve_attribute(self, func, module: str, caller: Function):
        base, imports = func.value, self.imports.get(module, {})
        if (
            isinstance(base, ast.Name)
            and base.id in {"self", "cls"}
            and caller is not None
            and caller.class_name
        ):
            prefix = caller.key.split(":", 1)[1].split(".")[0]
            return self.functions.get(f"{module}:{prefix}.{func.attr}")
        if isinstance(base, ast.Name) and base.id in imports:
            return self.functions.get(f"{imports[base.id]}:{func.attr}")
        candidates = self.method_names.get(func.attr, [])
        return self.functions[candidates[0]] if len(candidates) == 1 else None


def _in_mcp_module(relative: str) -> bool:
    return any("mcp" in part.lower() for part in relative.split("/"))


def _is_mcp_handler(relative: str, node: ast.AST, class_name: str | None) -> bool:
    """Public methods of tool/server classes in an MCP module receive tool arguments."""
    if not _in_mcp_module(relative) or node.name.startswith("_"):
        return False
    return class_name is not None and bool(_MCP_CLASS.search(class_name))


def _parsed_cli_names(node: ast.AST) -> set[str]:
    """Names bound to ``parser.parse_args()`` results inside a function."""
    names = set()
    for child in ast.walk(node):
        if (
            isinstance(child, ast.Assign)
            and isinstance(child.value, ast.Call)
            and _dotted(child.value.func).endswith(("parse_args", "parse_known_args"))
        ):
            names.update(t.id for t in child.targets if isinstance(t, ast.Name))
    return names


def _untrusted(expr: ast.AST, caller: Function, cli_names: set[str]) -> str | None:
    for node in ast.walk(expr):
        dotted = _dotted(node) if isinstance(node, (ast.Attribute, ast.Call)) else ""
        if isinstance(node, ast.Attribute) and node.attr in _REQUEST_ATTRS:
            if _dotted(node.value).split(".")[-1] in {"request", "req"}:
                return f"request.{node.attr}"
        if dotted in {"sys.argv", "input"} or (
            isinstance(node, ast.Subscript) and _dotted(node.value) == "sys.argv"
        ):
            return dotted or "sys.argv"
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in cli_names
        ):
            return f"cli argument {node.value.id}.{node.attr}"
        if _in_mcp_module(caller.path):
            target = None
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
            ):
                target = node.func.value
            elif isinstance(node, ast.Subscript):
                target = node.value
            if isinstance(target, ast.Name) and target.id in _MCP_ARGUMENTS:
                return f"MCP tool {target.id}"
    return None


def _classify(expr: ast.AST, caller: Function, cli_names: set[str]) -> tuple[str, str]:
    if (
        isinstance(expr, ast.Constant)
        or (isinstance(expr, ast.Name) and expr.id.isupper())
        or (
            isinstance(expr, ast.JoinedStr)
            and not any(isinstance(v, ast.FormattedValue) for v in expr.values)
        )
    ):
        return "constant", ""
    if isinstance(expr, ast.Call) and _SANITIZERS.search(_dotted(expr.func)):
        return "sanitized", _dotted(expr.func)
    source = _untrusted(expr, caller, cli_names)
    if source:
        return "untrusted", source
    names = {
        n.id
        for n in ast.walk(expr)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
    }
    params = [p for p in caller.params if p in names]
    if params:
        return "param", params[0]
    return "other", ""


def _argument(call: ast.Call, target: Function, param: str) -> ast.AST | None | str:
    """The expression bound to ``param`` at this call.

    ``None`` when the call omits it; the starred or double-starred value when
    the call forwards ``*args``/``**kwargs`` over it, so pass-through wrappers
    propagate; ``"*"`` when it cannot be determined.
    """
    if param in target.params:
        index = target.params.index(param)
        positional = list(call.args)
        starred = [a for a in positional[: index + 1] if isinstance(a, ast.Starred)]
        if starred:
            return starred[0].value
        if index < len(positional):
            return positional[index]
    for keyword in call.keywords:
        if keyword.arg == param:
            return keyword.value
        if keyword.arg is None:
            return keyword.value
    return None


def _call_graph(index: Index) -> dict[str, list[tuple[Function, ast.Call]]]:
    callers: dict[str, list[tuple[Function, ast.Call]]] = {}
    for caller_key, call, module in index.calls:
        caller = index.functions[caller_key]
        target = index.resolve(call, module, caller)
        if target is not None and target.key != caller_key:
            callers.setdefault(target.key, []).append((caller, call))
    return callers


def _seed(index: Index, findings: list[dict], summary: dict) -> list:
    seeds = []
    for finding in findings:
        func = index.enclosing(finding["path"], finding["line"])
        if func is None or finding.get("source") not in func.params:
            seeds.append(None)
            continue
        where = f"{finding['rule']} at {finding['path']}:{finding['line']}"
        chain = [f"{func.key}({finding['source']}) -> {where}"]
        summary.setdefault(func.key, {}).setdefault(finding["source"], chain)
        seeds.append((func, finding["source"]))
    return seeds


def _call_kind(index: Index, caller: Function, call: ast.Call, func: Function, param):
    argument = _argument(call, func, param)
    if argument is None:
        return "constant", "default"
    if argument == "*":
        return "other", "starred"
    return _classify(argument, caller, index.cli_args.get(caller.key, set()))


class _Propagation:
    """Worklist fixpoint from sink parameters to untrusted callers."""

    def __init__(self, index: Index, callers, summary):
        self.index, self.callers, self.summary = index, callers, summary
        self.confirmed: dict[tuple[str, str], list[str]] = {}
        self.observed: dict[tuple[str, str], set[str]] = {}

    def run(self) -> None:
        """Propagate summaries to callers until no new parameter is reached."""
        work = [
            (key, param) for key, params in self.summary.items() for param in params
        ]
        budget = MAX_ITERATIONS * max(1, len(self.index.functions))
        while work and budget:
            budget -= 1
            key, param = work.pop()
            work.extend(self._step(key, param))
        while self._settle():
            pass

    def _step(self, key: str, param: str) -> list[tuple[str, str]]:
        func, chain = self.index.functions[key], self.summary[key][param]
        if func.is_entry:
            entry = f"entry {func.key} parameter {param}"
            self.confirmed.setdefault((key, param), [entry, *chain])
        new = []
        for caller, call in self.callers.get(key, []):
            kind, detail = _call_kind(self.index, caller, call, func, param)
            self.observed.setdefault((key, param), set()).add(kind)
            step = f"{caller.key} calls {func.key} at {caller.path}:{call.lineno}"
            if kind == "untrusted":
                origin = f"{detail} in {caller.key}"
                self.confirmed.setdefault((key, param), [origin, step, *chain])
            elif kind == "param" and detail not in self.summary.setdefault(
                caller.key, {}
            ):
                self.summary[caller.key][detail] = [step, *chain]
                new.append((caller.key, detail))
        return new

    def _settle(self) -> bool:
        """Copy a caller's confirmation down to callees processed before it."""
        changed = False
        for key, params in self.summary.items():
            for param in params:
                if (key, param) not in self.confirmed:
                    changed |= self._settle_one(key, param)
        return changed

    def _settle_one(self, key: str, param: str) -> bool:
        func = self.index.functions[key]
        for caller, call in self.callers.get(key, []):
            kind, detail = _call_kind(self.index, caller, call, func, param)
            if kind == "param" and (caller.key, detail) in self.confirmed:
                self.confirmed[(key, param)] = self.confirmed[(caller.key, detail)]
                return True
        return False

    def state(self, seed) -> Reach:
        """Reach state and chain for one seeded finding."""
        if seed is None:
            return Reach("unresolved")
        func, param = seed
        if (func.key, param) in self.confirmed:
            return Reach("entry_reached", self.confirmed[(func.key, param)])
        kinds = self.observed.get((func.key, param), set())
        if not func.public and kinds and kinds <= {"constant", "sanitized"}:
            return Reach("callers_constant_only")
        return Reach("public_api" if func.public else "unresolved")


def reach(root: Path | Index, findings: list[dict]) -> list[dict]:
    """Annotate ``findings`` ({rule, path, line, source}) with reach state and chain."""
    if not findings:
        return []
    index = root if isinstance(root, Index) else Index.from_root(root)
    summary: dict[str, dict[str, list[str]]] = {}
    seeds = _seed(index, findings, summary)
    propagation = _Propagation(index, index._callers, summary)
    propagation.run()
    annotated = []
    for finding, seed in zip(findings, seeds):
        result = propagation.state(seed)
        annotated.append(
            {**finding, "reach": result.state, "reach_chain": result.chain}
        )
    return annotated


ENTRY_REACH_SCOPE = "source_bound_entry_reach"
REACH_CODES = {
    "SECURITY_OS_COMMAND",
    "SECURITY_SHELL_COMMAND",
    "SECURITY_SQL_INJECTION",
    "SECURITY_PATH_TRAVERSAL",
}


def _matches_reach_span(node: ast.Call, finding: dict) -> bool:
    if node.lineno != finding["line"]:
        return False
    return all(
        finding.get(key, value) == value
        for key, value in (
            ("column", node.col_offset),
            ("end_line", node.end_lineno),
            ("end_column", node.end_col_offset),
        )
    )


def _reach_format_values(template, args, keywords):
    named = {kw.arg: kw.value for kw in keywords}
    if (
        None in named
        or len(named) != len(keywords)
        or any(isinstance(arg, ast.Starred) for arg in args)
    ):
        return []

    values = []
    automatic, explicit = 0, False
    try:
        for _, field, spec, conversion in Formatter().parse(template):
            if field is None:
                continue
            if spec or conversion not in (None, "s", "r", "a"):
                return []
            if field == "":
                if explicit:
                    return []
                values.append(args[automatic])
                automatic += 1
            elif field.isascii() and field.isdecimal():
                if automatic:
                    return []
                explicit = True
                values.append(args[int(field)])
            else:
                values.append(named[field])
    except (ValueError, IndexError, KeyError):
        return []
    return values


def _reach_percent_values(template, operand):
    fields = re.findall(r"%%|%[sra]|%", template)
    if any(field not in ("%%", "%s", "%r", "%a") for field in fields):
        return []
    count = sum(field != "%%" for field in fields)
    values = operand.elts if isinstance(operand, ast.Tuple) else [operand]
    if count != len(values) or any(isinstance(value, ast.Starred) for value in values):
        return []
    return values


def _reach_operand_names(expr: ast.AST):
    match expr:
        case ast.Name(ctx=ast.Load()):
            yield expr
        case ast.Call(
            func=ast.Attribute(
                value=ast.Constant(value=str() as template), attr="format"
            ),
            args=args,
            keywords=keywords,
        ):
            for value in _reach_format_values(template, args, keywords):
                yield from _reach_operand_names(value)
        case ast.BinOp(
            op=ast.Mod(), left=ast.Constant(value=str() as template), right=operand
        ):
            for value in _reach_percent_values(template, operand):
                yield from _reach_operand_names(value)
        case ast.BinOp(op=ast.Add() | ast.Mod() | ast.Div(), left=left, right=right):
            yield from _reach_operand_names(left)
            yield from _reach_operand_names(right)
        case ast.JoinedStr(values=values):
            for value in values:
                yield from _reach_operand_names(value)
        case (
            ast.FormattedValue(value=value)
            | ast.Attribute(value=value)
            | ast.Subscript(value=value)
        ):
            yield from _reach_operand_names(value)


def _reach_call_and_parents(func, finding):
    nested = (
        *_FUNCTION_OR_CLASS,
        ast.Lambda,
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
    )
    pending = list(func.node.body)
    parents = {id(statement): func.node for statement in pending}
    matches, closure_writes = [], set()
    while pending:
        node = pending.pop()
        if isinstance(node, nested):
            if isinstance(node, _FUNCTION_OR_CLASS):
                closure_writes.update(
                    name
                    for child in ast.walk(node)
                    if isinstance(child, ast.Nonlocal)
                    for name in child.names
                )
            continue
        if isinstance(node, ast.Call) and _matches_reach_span(node, finding):
            matches.append(node)
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
            pending.append(child)
    call = matches[0] if len(matches) == 1 else None
    return call, parents, closure_writes


def _parameter_reaches_read(name, scope, parents, closure_writes):
    from .credential_role_constructor_provider import (
        binding_dominates,
        binding_occurrences,
    )

    # A nested function can reassign the parameter via its closure.
    if name.id in closure_writes:
        return False
    writes = binding_occurrences(scope.body, name.id)
    if not writes:
        return True
    statement = name
    while parents[id(statement)] is not scope:
        statement = parents[id(statement)]
    # A write in the same top-level statement could reach a later loop iteration.
    return all(binding_dominates(statement, write, parents, scope) for write in writes)


def _reach_shell_sequence_command(operand, call, finding):
    if not isinstance(operand, (ast.List, ast.Tuple)):
        return operand
    if finding["code"] != "SECURITY_SHELL_COMMAND" or not operand.elts:
        return None

    from .finite_capture import shell_execution_calls
    from .review_integrity import shell_execution_enabled

    if finding.get(
        "call"
    ) not in shell_execution_calls() or not shell_execution_enabled(call):
        return None
    # The first element supplies the shell command on POSIX. Later elements
    # require platform-specific proof before they can support a promotion.
    return operand.elts[0]


def _sink_parameters(func: Function, finding: dict) -> list[str]:
    """Prove parameter reach to the operand of one source-bound call."""
    call, parents, closure_writes = _reach_call_and_parents(func, finding)
    if call is None or not call.args:
        return []
    found, seen, pending = {}, set(), [call.args[0]]
    while pending:
        operand = _reach_shell_sequence_command(pending.pop(), call, finding)
        for name in _reach_operand_names(operand):
            if id(name) in seen:
                continue
            seen.add(id(name))
            if _argument_binding_is_parameter_or_external(name.id, func.node):
                if name.id in func.params and _parameter_reaches_read(
                    name, func.node, parents, closure_writes
                ):
                    found[name.id] = None
                continue
            value = _captured_argument_definition(
                name, name, parents, None, aliases=True
            )
            if value is not None:
                pending.append(value)
    return list(found)


def _source_index(source_bytes: dict) -> Index:
    return Index(
        {
            path: data.decode("utf-8", errors="replace")
            for path, data in source_bytes.items()
            if isinstance(path, str) and isinstance(data, (bytes, bytearray))
        }
    )


def entry_reach_tier(finding, source_bytes, decided, *, get_source_index=None):
    """Promote a command, SQL or path finding whose sink parameter an entry reaches.

    Only a ``NEEDS_CONTEXT`` decision changes; the reach chain becomes the
    evidence detail. The index is rebuilt from the captured source bytes, so an
    independent regeneration of the tier report reaches the same decision.
    """
    tier, evidence, details = decided
    path, line = finding.get("path"), finding.get("line")
    if (
        tier != "NEEDS_CONTEXT"
        or finding.get("code") not in REACH_CODES
        or not isinstance(source_bytes, dict)
        or path not in source_bytes
        or not isinstance(line, int)
    ):
        return decided
    index = (
        _source_index(source_bytes) if get_source_index is None else get_source_index()
    )
    func = index.enclosing(path, line)
    if func is None:
        return decided
    rows = [
        {"rule": finding["code"], "path": path, "line": line, "source": param}
        for param in _sink_parameters(func, finding)
    ]
    for row in reach(index, rows):
        if row["reach"] == "entry_reached":
            detail = {
                "schema": REACH_SCHEMA,
                "parameter": row["source"],
                "chain": row["reach_chain"],
            }
            return "SUPPORTED_DEFECT", ENTRY_REACH_SCOPE, {"entry_reach": detail}
    return decided


def _relative_report_path(path: str, prefix: str) -> str:
    if prefix:
        try:
            return Path(path).relative_to(prefix).as_posix()
        except ValueError:
            pass
    return Path(path).as_posix()


def findings_from_opengrep(report: dict, prefix: str = "") -> list[dict]:
    """Parameter-rule findings from opengrep JSON run with ``--dataflow-traces``."""
    rows = []
    for result in report.get("results", []):
        rule = ".".join(result["check_id"].split(".")[-2:])
        if not rule.startswith("python.parameter-"):
            continue
        extra = result.get("extra", {})
        trace = extra.get("dataflow_trace") or {}
        source = trace.get("taint_source")
        name = source[1][1] if isinstance(source, list) and len(source) > 1 else None
        if name is None:
            # Search-mode rules bind the parameter as $P instead of a taint source.
            name = (extra.get("metavars", {}).get("$P") or {}).get("abstract_content")
        path = _relative_report_path(result["path"], prefix)
        rows.append(
            {
                "rule": rule,
                "path": path,
                "line": result["start"]["line"],
                "source": name,
            }
        )
    return rows
