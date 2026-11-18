"""Source-bound operands for bounded Python security proofs."""

import ast


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


def _captured_argument_definition(argument, call, parents, module):
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
            if (
                isinstance(assignment, ast.Assign)
                and assignment.targets == writes
                and _binding_precedes_sibling(assignment, current, owner)
            ):
                return assignment.value
        if owner is scope:
            break
        current = owner
    return None


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
            isinstance(node, (ast.Yield, ast.YieldFrom, ast.Global, ast.Nonlocal))
            for node in nodes
        ):
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
