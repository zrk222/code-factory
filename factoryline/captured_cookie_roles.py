"""Source-bound HTTP cookie name slots over captured FastAPI and Starlette."""

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
        operation = (
            getattr(call.func, "attr", None) if role == _COOKIE_NAME_ROLE else role
        )
        if not operation:
            return None
        receiver_role = (
            "fastapi_middleware_request"
            if operation == "get"
            else "fresh_redirect_response"
            if role == _COOKIE_NAME_ROLE
            else "security_locator"
        )
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
