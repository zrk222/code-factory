"""Source-bound captured security evidence shared by verification consumers."""

import ast
import hashlib
from pathlib import Path


def _captured_hmac_operands(call):
    """Bind a one-shot HMAC constructor with explicit message and digest operands."""
    from . import _bind_source_call

    signature = ast.parse("def new(key, msg, digestmod): pass").body[0]
    try:
        bound = _bind_source_call(call, signature, apply_defaults=False)
    except ValueError:
        return None
    return bound["key"], bound["msg"], bound["digestmod"]


def _captured_credential_handler_authority(context, finding, handler, declaration):
    from .credential_endpoint_admission import _OperativeCredentialOrigin
    from .review_audits import _resolved_ast_name

    framework = handler["application"]["framework"]
    if framework == "fastapi":
        return _OperativeCredentialOrigin(
            context, finding, handler, declaration
        ).handler_authority()
    function, path = handler["function"], handler["path"]
    if framework != "flask" or not any(
        isinstance(node, ast.Call)
        and _resolved_ast_name(node.func, context["aliases"][path])
        == "hmac.compare_digest"
        for node in ast.walk(function)
    ):
        return None
    origin = _OperativeCredentialOrigin(context, finding, handler, declaration)
    return _CapturedHTTPSignatureFlow(origin).authority()


class _CapturedHTTPSignatureFlow:
    """Join a typed signature calculation to an HTTP rejection boundary."""

    def __init__(self, origin):
        self.origin = origin
        handler = origin.handler
        self.path, self.function = handler["path"], handler["function"]
        self.providers, self.transfers, self.readonly = set(), [], set()
        self.request_reads = set()

    def canonical(self, node):
        return self.origin.canonical(self.path, node, self.function)

    def expression(self, node, values):
        match node:
            case ast.Name(id=name) if name in values:
                return values[name]
            case ast.Attribute() if self.canonical(node) == "flask.request.data":
                self.request_reads.add(node)
                return "payload", frozenset()
            case ast.Name() | ast.Attribute() if self.key_origin(node):
                return "key_text", frozenset()
            case ast.Constant(value=bytes()):
                return "bytes", frozenset()
            case ast.Subscript(value=receiver, slice=ast.Constant(value=str() as name)):
                if self.canonical(receiver) == "flask.request.headers":
                    self.request_reads.add(node)
                    return "header", frozenset({name.casefold()})
            case ast.BinOp(left=left, op=ast.Add(), right=right):
                operands = [self.expression(item, values) for item in (left, right)]
                kinds = {kind for kind, _ in operands}
                if kinds <= {"bytes", "payload"}:
                    return (
                        "payload" if "payload" in kinds else "bytes",
                        frozenset().union(*(headers for _, headers in operands)),
                    )
            case ast.Call():
                return self.call(node, values)
        return "", frozenset()

    def key_origin(self, node):
        from .credential_role_constructor_provider import binding_occurrences

        origin = self.origin
        if origin.literal_reference(self.path, node, self.function, origin.projection):
            return True
        name = origin.finding["facts"]["name"]
        tree = origin.index.snapshots[self.path]
        return (
            self.path == origin.path
            and isinstance(node, ast.Name)
            and node.id == name
            and origin.declaration in tree.body
            and origin.declaration.lineno < self.function.lineno
            and len(bindings := binding_occurrences(tree.body, name)) == 1
            and origin.index.parents[self.path].get(id(bindings[0]))
            is origin.declaration
            and not binding_occurrences(self.function.body, name)
        )

    def call(self, node, values):
        canonical = self.canonical(node.func)
        if canonical == "hmac.new":
            return self.constructor(node, values)
        if (
            canonical == "hmac.compare_digest"
            and len(node.args) == 2
            and not node.keywords
        ):
            operands = dict(self.expression(arg, values) for arg in node.args)
            if (
                operands.keys() == {"digest", "header"}
                and not operands["digest"] & operands["header"]
            ):
                self.providers.add(canonical)
                self.transfers.append(node)
                return "verified", frozenset()
        if (encoded := self.encoded_header(node, values)) is not None:
            return encoded
        return self.member_call(node, values)

    def constructor(self, node, values):
        operands = _captured_hmac_operands(node)
        if operands is None:
            return "", frozenset()
        key, message, digest = operands
        payload_kind, headers = self.expression(message, values)
        if (
            self.expression(key, values)[0] != "key_bytes"
            or payload_kind != "payload"
            or self.canonical(digest) != "hashlib.sha256"
        ):
            return "", frozenset()
        self.providers.update({"hmac.new", "hmac.HMAC", "hashlib.sha256"})
        self.readonly.add(id(digest))
        self.transfers.extend((key, message, digest, node))
        return "hmac", headers

    def encoded_header(self, node, values):
        from .credential_role_constructor_provider import binding_occurrences

        match node:
            case ast.Call(
                func=ast.Name(id="bytes"),
                args=[value, ast.Constant(value="utf8" | "utf-8")],
                keywords=[],
            ):
                source = self.origin.index.snapshots[self.path]
                if not any(
                    binding_occurrences(scope.body, "bytes")
                    for scope in (source, self.function)
                ):
                    kind, headers = self.expression(value, values)
                    if kind == "header":
                        self.providers.add("builtins.bytes")
                        return "bytes", headers
        return None

    def member_call(self, node, values):
        if node.keywords:
            return "", frozenset()
        match node.func, node.args:
            case ast.Attribute(value=receiver, attr="get"), [
                ast.Constant(value=str() as name),
                ast.Constant(value=str()),
            ]:
                if self.canonical(receiver) == "flask.request.headers":
                    self.request_reads.add(node)
                    return "header", frozenset({name.casefold()})
            case ast.Attribute(value=receiver, attr="split"), [
                ast.Constant(value=str() as sep)
            ] if sep:
                kind, headers = self.expression(receiver, values)
                if kind == "header":
                    return "headers", headers
            case ast.Attribute(value=receiver, attr=method), []:
                kind, headers = self.expression(receiver, values)
                projected = {
                    ("key_text", "encode"): "key_bytes",
                    ("header", "encode"): "bytes",
                    ("hmac", "hexdigest"): "digest",
                }.get((kind, method), "")
                return projected, headers
        return "", frozenset()

    def response(self, statement, success):
        match statement:
            case ast.Return(
                value=ast.Call(
                    func=func,
                    args=[ast.Constant(value=str())],
                    keywords=[
                        ast.keyword(
                            arg="status", value=ast.Constant(value=int() as status)
                        )
                    ],
                )
            ):
                if self.canonical(func) == "flask.Response" and status // 100 == (
                    2 if success else 4
                ):
                    self.providers.add("flask.Response")
                    return True
        return False

    def logging(self, statement):
        receiver = self.origin.handler["application"]["name"]
        match statement:
            case ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(
                        value=ast.Attribute(value=ast.Name(id=owner), attr="logger"),
                        attr="warning" | "info",
                    ),
                    args=[value],
                    keywords=[],
                )
            ) if owner == receiver:
                if isinstance(value, ast.Constant):
                    self.providers.add("logging.Logger")
                    return True
                if self.canonical(value) == "flask.request.json":
                    self.request_reads.add(value)
                    self.providers.add("logging.Logger")
                    return True
        return False

    def rejects(self, statement, values):
        match statement:
            case ast.If(
                test=ast.UnaryOp(op=ast.Not(), operand=condition),
                body=[*prefix, response],
                orelse=[],
            ):
                if (
                    self.expression(condition, values)[0] == "verified"
                    and all(self.logging(item) for item in prefix)
                    and self.response(response, False)
                ):
                    self.transfers.extend((statement, response))
                    return True
        return False

    def assignments(self, statements, values):
        for statement in statements:
            match statement:
                case ast.Assign(targets=[ast.Name(id=name)], value=node):
                    kind = self.expression(node, values)
                    if not kind[0]:
                        return False
                    values[name] = kind
                case _:
                    return False
        return True

    def guarded(self, statements, values):
        if not statements:
            return False
        *prefix, guard = statements
        if not self.assignments(prefix, values):
            return False
        match guard:
            case ast.For(
                target=ast.Name(id=name),
                iter=sequence,
                body=[*inner, rejection],
                orelse=[],
            ):
                # A fixed nonempty separator leaves at least one input-derived item.
                kind, headers = self.expression(sequence, values)
                if kind != "headers":
                    return False
                values[name] = "header", headers
                return self.assignments(inner, values) and self.rejects(
                    rejection, values
                )
        return self.rejects(guard, values)

    def authority(self):
        from .semantic_credential_sensor import _flask_constructor_arguments

        handler, function = self.origin.handler, self.function
        tree = self.origin.index.snapshots[self.path]
        creation = handler["application"]["creation"]
        if not (
            function in tree.body
            and function.decorator_list == [handler["decorator"]]
            and handler["application"]["path"] == self.path
            and handler["receiver"] is handler["application"]
            and len(creation.args) + len(creation.keywords) == 1
            and _flask_constructor_arguments(creation)
            and self.route_path(handler["decorator"])
            and not any(
                getattr(function.args, field) for field in function.args._fields
            )
            and len(function.body) >= 2
        ):
            return None
        *prefix, accepted = function.body
        while prefix and self.logging(prefix[-1]):
            prefix.pop()
        if not self.response(accepted, True) or not self.guarded(prefix, {}):
            return None
        if not self.providers_closed(tree):
            return None
        self.origin.consumer = ("hmac", "verified_http_signature_rejection")
        from .semantic_credential_sensor import _signing_source_span

        self.origin.consumer_transfers = [
            _signing_source_span(self.origin.index, self.path, node)
            for node in sorted(
                {*self.transfers, *self.request_reads},
                key=lambda item: (
                    item.lineno,
                    item.col_offset,
                    item.end_lineno,
                    item.end_col_offset,
                ),
            )
        ]
        return self.origin.witness(accepted, self.origin.key)

    @staticmethod
    def route_path(decorator):
        match decorator:
            case ast.Call(
                func=ast.Attribute(attr=method),
                args=[ast.Constant(value=str() as path)],
                keywords=keywords,
            ) if path.startswith("/") and "<" not in path:
                if not keywords:
                    return True
                match keywords:
                    case [
                        ast.keyword(
                            arg="methods",
                            value=ast.List(elts=methods) | ast.Tuple(elts=methods),
                        )
                    ] if method == "route":
                        return bool(methods) and all(
                            isinstance(item, ast.Constant)
                            and item.value
                            in (
                                "GET",
                                "POST",
                                "PUT",
                                "PATCH",
                                "DELETE",
                                "OPTIONS",
                                "HEAD",
                            )
                            for item in methods
                        )
        return False

    def providers_closed(self, tree):
        from . import review_audits as audit
        from .credential_role_constructor_provider import (
            _captured_terminal_provider_mutation,
        )
        from .credential_identity_audit import _app_digest_algorithm_argument
        from .runtime_audit_integrity import _conditional_module_name
        from .semantic_credential_sensor import _signing_framework_external

        origin, handler = self.origin, self.origin.handler
        index, app = origin.index, handler["application"]["name"]
        allowed_calls = {
            handler["decorator"].func,
            *(
                node.func
                for node in ast.walk(self.function)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "logger"
                and isinstance(node.func.value.value, ast.Name)
                and node.func.value.value.id == app
            ),
        }
        parents = index.parents[self.path]
        for node in ast.walk(tree):
            if (
                not isinstance(node, ast.Name)
                or node.id != app
                or not isinstance(node.ctx, ast.Load)
            ):
                continue
            owner = parents.get(id(node))
            if (
                owner not in allowed_calls
                and parents.get(id(owner)) not in allowed_calls
            ):
                return False
        providers = sorted(
            self.providers
            | {
                "flask.Flask",
                "flask.request",
                "flask.Request",
                "flask.wrappers.Request",
                "flask.wrappers.Response",
                "werkzeug.wrappers.Request",
                "werkzeug.wrappers.Response",
            }
        )
        if not all(
            _signing_framework_external(
                origin.context, name.split(".")[0], origin.execution_root
            )
            for name in providers
        ):
            return False
        module = _conditional_module_name(index.relative(self.path))
        bindings = [(name, None) for name in providers]
        bindings.extend(
            (qualified + "." + name, (self.path, name))
            for qualified in sorted({module, self.path.stem})
            for name in (app, self.function.name, origin.finding["facts"]["name"])
        )
        return not _captured_terminal_provider_mutation(
            index,
            audit,
            providers[0],
            additional_bindings=tuple(bindings[1:]),
            readonly_nodes=self.request_reads
            | {
                node
                for node in ast.walk(self.function)
                if isinstance(node, ast.Assign) and node.value in self.request_reads
            },
            readonly_argument=lambda node, aliases, parents: id(node) in self.readonly
            or _app_digest_algorithm_argument(node, aliases, parents),
        )


def _native_span(node):
    span = [
        getattr(node, key, None)
        for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
    ]
    if (
        any(type(value) is not int for value in span)
        or span[0] < 1
        or min(span[1], span[3]) < 0
        or tuple(span[:2]) > tuple(span[2:])
    ):
        return None
    return span


def _captured_sink_failure(schema, code, reason, base=None):
    return {
        **(base or {"schema": schema, "status": "INCOMPLETE"}),
        "code": code,
        "truncation": [reason],
    }


def _captured_sink_source(
    path_arg, expected, index, raw, tree, max_sources, max_states, max_output, schema
):
    import io
    import tokenize

    limits = (max_sources, max_states, max_output)
    if any(type(value) is not int or value < 1 for value in limits) or max_output < 256:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_INVALID", "invalid_limit"
            )
        }
    limits = tuple(
        min(value, ceiling) for value, ceiling in zip(limits, (64, 512, 64000))
    )
    path = path_arg.as_posix() if hasattr(path_arg, "as_posix") else path_arg
    tree_supplied = tree is not None
    indexed = index is not None
    if indexed:
        capture = _captured_sink_index(index, path_arg, raw, path, schema)
        if "error" in capture:
            return capture
        raw, tree, parents = capture["raw"], capture["tree"], capture["parents"]
    else:
        parents = None
    if not isinstance(path, str) or not path:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "invalid_source_path"
            )
        }
    if not isinstance(raw, bytes) or len(raw) > 1_000_000:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_EXHAUSTED", "max_source_bytes"
            )
        }
    digest = hashlib.sha256(raw).hexdigest()
    if not isinstance(expected, str) or expected != digest:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_hash_mismatch"
            )
        }
    if not indexed:
        capture = _captured_sink_raw_tree(path, raw, tree, schema)
        if "error" in capture:
            return capture
        tree, parents = capture["tree"], capture["parents"]
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        text = raw.decode(encoding)
    except (SyntaxError, UnicodeError, LookupError):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_encoding_invalid"
            )
        }
    base = {
        "schema": schema,
        "status": "INCOMPLETE",
        "source": {"path": path[:1024], "sha256": digest, "bytes": len(raw)},
        "source_count": 1,
    }
    return {
        "tree": tree,
        "parents": parents,
        "text": text,
        "base": base,
        "digest": digest,
        "limits": limits,
        "indexed": indexed,
        "tree_supplied": tree_supplied,
    }


def _captured_sink_index(index, path_arg, raw, path, schema):
    inventory = getattr(index, "source_bytes", {})
    if not isinstance(path, str) or path_arg not in getattr(index, "snapshots", {}):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_not_indexed"
            )
        }
    if (
        sum(len(value) for value in inventory.values() if isinstance(value, bytes))
        > 32_000_000
    ):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_EXHAUSTED", "max_inventory_bytes"
            )
        }
    captured = inventory.get(path_arg)
    if raw is not None and raw != captured:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_bytes_changed"
            )
        }
    if not isinstance(captured, bytes) or len(captured) > 1_000_000:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_EXHAUSTED", "max_source_bytes"
            )
        }
    validation_inputs = getattr(index, "_validation_inputs", None)
    if not isinstance(validation_inputs, dict):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_validation_cache_unavailable"
            )
        }
    validation_inputs.pop(path_arg, None)
    if not index.validate(path_arg):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_snapshot_invalid"
            )
        }
    return {
        "raw": captured,
        "tree": index.snapshots[path_arg],
        "parents": index.parents[path_arg],
    }


def _captured_sink_raw_tree(path, raw, tree, schema):
    from .ops_telemetry import _measure_parse

    source = Path(path)
    try:
        parsed = _measure_parse(ast.parse, raw, source.parent, source)
        if tree is not None and ast.dump(parsed, include_attributes=True) != ast.dump(
            tree, include_attributes=True
        ):
            return {
                "error": _captured_sink_failure(
                    schema, "SINK_SOURCE_STALE", "ast_source_mismatch"
                )
            }
        tree = tree or parsed
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_parse_failed"
            )
        }
    return {"tree": tree, "parents": {}}


def _captured_sink_location(node, ctx):
    base, tree, parents = ctx["base"], ctx["tree"], ctx["parents"]
    schema = base["schema"]
    span = _native_span(node) if isinstance(node, ast.AST) else None
    if span is None:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_LOCATION_UNRESOLVED", "invalid_sink_span", base
            )
        }
    if ctx["indexed"] and isinstance(node, ast.Call) and id(node) in parents:
        return {"node": node, "parents": parents, "source_ast_nodes_examined": 0}
    if ctx["indexed"]:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_LOCATION_UNRESOLVED", "sink_not_in_captured_tree", base
            )
        }
    matches = []
    for count, item in enumerate(ast.walk(tree), 1):
        if count > 200_000:
            return {
                "error": _captured_sink_failure(
                    schema, "SINK_BUDGET_EXHAUSTED", "max_source_ast_nodes", base
                )
            }
        parents.update({id(child): item for child in ast.iter_child_nodes(item)})
        if (
            isinstance(item, ast.Call)
            and _native_span(item) == span
            and ast.dump(item, include_attributes=True)
            == ast.dump(node, include_attributes=True)
        ):
            matches.append(item)
    if ctx["tree_supplied"] and id(node) not in parents:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_LOCATION_UNRESOLVED", "sink_not_in_supplied_tree", base
            )
        }
    if len(matches) == 1:
        return {
            "node": matches[0],
            "parents": parents,
            "source_ast_nodes_examined": count,
        }
    return {
        "error": _captured_sink_failure(
            schema, "SINK_LOCATION_UNRESOLVED", "sink_span_not_unique", base
        )
    }


def _captured_sink_fact(item, path, digest, status="OBSERVED"):
    span = _native_span(item)
    return (
        {"status": status, "source": {"path": path, "sha256": digest, "span": span}}
        if span is not None
        else {"status": "UNKNOWN", "reason": "span_unavailable"}
    )


def _captured_sink_excerpt(item, text, truncation):
    excerpt = ast.get_source_segment(text, item)
    if not isinstance(excerpt, str):
        return ""
    if len(excerpt) > 512:
        if "excerpt_truncated" not in truncation:
            truncation.append("excerpt_truncated")
        return excerpt[:512] + "[truncated]"
    return excerpt


def _captured_sink_scope(node, parents, fact, budget, base):
    scope = node
    while id(scope) in parents:
        scope = parents[id(scope)]
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            break
    else:
        scope = None
    row, body, statement = (
        {"status": "UNKNOWN", "reason": "no_enclosing_callable"},
        None,
        None,
    )
    if scope is not None:
        statement = node
        while id(statement) in parents and parents[id(statement)] is not scope:
            statement = parents[id(statement)]
        if (
            isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
            and statement in scope.body
        ):
            body = scope.body
            row = {
                "status": "OBSERVED",
                "name": scope.name,
                "kind": type(scope).__name__,
                **fact(scope),
            }
        else:
            row = {
                "status": "UNKNOWN",
                "reason": "sink_outside_callable_body",
                **fact(scope),
            }
    nodes, stack = [], [scope] if body is not None else []
    while stack:
        item = stack.pop()
        nodes.append(item)
        if len(nodes) > budget:
            return {
                "error": _captured_sink_failure(
                    base["schema"], "SINK_BUDGET_EXHAUSTED", "max_states", base
                )
            }
        if item is not scope and isinstance(
            item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        stack.extend(ast.iter_child_nodes(item))
    return {
        "scope": scope,
        "body": body,
        "statement": statement,
        "nodes": nodes,
        "row": row,
    }


def _captured_sink_arguments(node, fact, excerpt):
    arguments, names = [], set()
    for index, value in enumerate(node.args):
        arguments.append(
            {
                "position": index,
                "kind": "starred" if isinstance(value, ast.Starred) else "positional",
                "expression": excerpt(value),
                "span": _native_span(value),
                **fact(value),
            }
        )
        names.update(
            item.id
            for item in ast.walk(value)
            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
        )
    for keyword in node.keywords:
        value = keyword.value
        arguments.append(
            {
                "keyword": keyword.arg,
                "kind": "expanded_keyword" if keyword.arg is None else "keyword",
                "expression": excerpt(value),
                "span": _native_span(value),
                **fact(value),
            }
        )
        names.update(
            item.id
            for item in ast.walk(value)
            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
        )
    callees = [
        item
        for item in ast.walk(node.func)
        if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
    ]
    names.update(item.id for item in callees)
    return arguments, names, callees


def _captured_sink_imports(tree, scope, nodes, parents, fact, budget, base):
    from .credential_role_constructor_provider import binding_occurrences

    modules = [
        item for item in tree.body if isinstance(item, (ast.Import, ast.ImportFrom))
    ]
    if len(nodes) + len(modules) > budget:
        return {
            "error": _captured_sink_failure(
                base["schema"], "SINK_BUDGET_EXHAUSTED", "max_states", base
            )
        }
    rows, params = [], _captured_sink_parameter_names(scope)
    for item in modules + [
        row for row in nodes if isinstance(row, (ast.Import, ast.ImportFrom))
    ]:
        owner = _captured_sink_enclosing_callable(item, parents)
        if owner not in (None, scope):
            continue
        container = owner.body if owner is not None else tree.body
        for alias in item.names:
            name = alias.asname or (
                alias.name.split(".")[0] if isinstance(item, ast.Import) else alias.name
            )
            wildcard = isinstance(item, ast.ImportFrom) and alias.name == "*"
            stable = (
                not wildcard
                and binding_occurrences(container, name) == [item]
                and name not in params
            )
            status = "OBSERVED" if stable else "UNKNOWN"
            rows.append(
                {
                    "name": name,
                    "module": (
                        item.module if isinstance(item, ast.ImportFrom) else alias.name
                    ),
                    "kind": type(item).__name__,
                    "status": status,
                    "reason": None if stable else "binding_replaced_or_ambiguous",
                    "span": _native_span(item),
                    **fact(item, status),
                }
            )
    return {
        "rows": rows,
        "module_imports": modules,
        "states_used": sum(len(item.names) for item in modules),
        "binding_occurrences": binding_occurrences,
    }


def _captured_sink_values(
    node, names, scope, body, statement, nodes, parents, tree, fact, excerpt
):
    from .credential_role_constructor_provider import binding_occurrences

    if body is None:
        return [
            {
                "name": name,
                "status": "UNKNOWN",
                "reason": "no_supported_callable_scope",
                "origin": "UNRESOLVED",
                "definitions": [],
                "replacements": [],
            }
            for name in sorted(names)
        ]
    params = _captured_sink_parameter_names(scope)
    reflective = _captured_sink_reflective_barrier(node, scope, nodes, parents)
    pending, visited, result = sorted(names), set(), []
    while pending:
        name = pending.pop(0)
        if name in visited:
            continue
        visited.add(name)
        evidence = _captured_sink_value(
            name,
            scope,
            body,
            statement,
            parents,
            tree,
            params,
            fact,
            excerpt,
            binding_occurrences,
        )
        value, assignment = evidence["value"], evidence["assignment"]
        if assignment is not None:
            pending.extend(
                row.id
                for row in ast.walk(assignment.value)
                if isinstance(row, ast.Name)
                and isinstance(row.ctx, ast.Load)
                and row.id not in visited
                and row.id not in pending
            )
        if reflective:
            value.update(
                status="UNKNOWN",
                reason="reflective_binding_possible",
                origin="UNRESOLVED",
            )
            value["replacements"].append(
                {"kind": "REFLECTIVE_WRITE_POSSIBLE", **fact(node, "UNKNOWN")}
            )
        result.append(value)
    return result


def _captured_sink_reflective_barrier(node, scope, nodes, parents):
    """Return whether a reflective call can precede or feed this selected sink."""
    reflective_names = {
        "exec",
        "eval",
        "globals",
        "locals",
        "vars",
        "setattr",
        "delattr",
    }
    selected_span = _native_span(node)
    selected_start = tuple(selected_span[:2]) if selected_span else None
    selected_subtree = {id(item) for item in ast.walk(node)}
    for item in nodes:
        if (
            not isinstance(item, ast.Call)
            or not isinstance(item.func, ast.Name)
            or item.func.id not in reflective_names
            or item is node
        ):
            continue
        if id(item) in selected_subtree:
            return True
        if _captured_sink_enclosing_callable(item, parents) is not scope:
            continue
        span = _native_span(item)
        if selected_start is None or span is None:
            return True
        if tuple(span[:2]) <= selected_start:
            return True
    return False


def _captured_sink_value(
    name,
    scope,
    body,
    statement,
    parents,
    tree,
    params,
    fact,
    excerpt,
    binding_occurrences,
):
    bindings = binding_occurrences(body, name)
    rows = []
    for binding in bindings:
        statement_node = (
            parents.get(id(binding)) if isinstance(binding, ast.Name) else binding
        )
        if statement_node is None:
            statement_node = binding
        rows.append(
            {
                "kind": type(binding).__name__,
                "binding_span": _native_span(binding),
                "expression": excerpt(statement_node),
                **fact(statement_node, "UNKNOWN"),
            }
        )
    assignment = None
    if (
        len(bindings) == 1
        and isinstance(bindings[0], ast.Name)
        and isinstance(bindings[0].ctx, ast.Store)
    ):
        candidate = parents.get(id(bindings[0]))
        targets = (
            candidate.targets
            if isinstance(candidate, ast.Assign)
            else [candidate.target]
            if isinstance(candidate, ast.AnnAssign)
            else []
        )
        if (
            candidate in body
            and body.index(candidate) < body.index(statement)
            and getattr(candidate, "value", None) is not None
            and len(targets) == 1
            and targets[0] is bindings[0]
        ):
            assignment = candidate
    if assignment is not None:
        value = {
            "name": name,
            "status": "INFERRED",
            "reason": None,
            "origin": "LOCAL_DEFINITION",
            "definitions": [
                {
                    "expression": excerpt(assignment.value),
                    "span": _native_span(assignment),
                    **fact(assignment),
                }
            ],
            "replacements": [],
        }
        value["definitions"][0]["target_source"] = fact(
            assignment.targets[0]
            if isinstance(assignment, ast.Assign)
            else assignment.target
        )
    elif not bindings and name in params:
        args = (
            *scope.args.posonlyargs,
            *scope.args.args,
            *scope.args.kwonlyargs,
            *([scope.args.vararg] if scope.args.vararg else []),
            *([scope.args.kwarg] if scope.args.kwarg else []),
        )
        arg = next(row for row in args if row.arg == name)
        value = {
            "name": name,
            "status": "INFERRED",
            "reason": None,
            "origin": "CALLABLE_PARAMETER",
            "definitions": [
                {"kind": "PARAMETER", "span": _native_span(arg), **fact(arg)}
            ],
            "replacements": [],
        }
    elif not bindings and any(
        row in tree.body for row in binding_occurrences(tree.body, name)
    ):
        module_bindings = binding_occurrences(tree.body, name)
        if len(module_bindings) == 1 and isinstance(
            module_bindings[0], (ast.Import, ast.ImportFrom)
        ):
            value = {
                "name": name,
                "status": "INFERRED",
                "reason": None,
                "origin": "LEXICAL_IMPORT",
                "definitions": [
                    {
                        "kind": type(module_bindings[0]).__name__,
                        "span": _native_span(module_bindings[0]),
                        **fact(module_bindings[0]),
                    }
                ],
                "replacements": [],
            }
        else:
            value = {
                "name": name,
                "status": "UNKNOWN",
                "reason": "module_binding_ambiguous",
                "origin": "UNRESOLVED",
                "definitions": [],
                "replacements": rows,
            }
    else:
        value = {
            "name": name,
            "status": "UNKNOWN",
            "reason": (
                "binding_replaced_or_not_straight_line"
                if bindings
                else "no_source_definition_or_parameter"
            ),
            "origin": "UNRESOLVED",
            "definitions": [],
            "replacements": rows,
        }
    return {"value": value, "assignment": assignment}


def _captured_sink_guards(node, scope, parents, fact, excerpt):
    guards, current = [], node
    control = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        getattr(ast, "TryStar", ast.Try),
        ast.With,
        ast.AsyncWith,
        ast.Match,
        ast.Assert,
    )
    while id(current) in parents and parents[id(current)] is not scope:
        current = parents[id(current)]
        if isinstance(current, control):
            test = getattr(current, "test", None) or getattr(current, "subject", None)
            guards.append(
                {
                    "kind": type(current).__name__,
                    "expression": excerpt(test) if test is not None else "",
                    "semantics": "UNKNOWN",
                    "span": _native_span(current),
                    **fact(current),
                }
            )
    return guards


def _captured_sink_callee_binding(names, scope, body, tree, module_imports, fact):
    from .credential_role_constructor_provider import binding_occurrences

    name = names[0].id if names else None
    row = {"status": "UNKNOWN", "reason": "unresolved_callee_binding", "name": name}
    if name is None or body is None:
        return row
    if any(
        isinstance(item, ast.ImportFrom)
        and any(alias.name == "*" for alias in item.names)
        for item in module_imports
    ):
        row["reason"] = "wildcard_import_may_bind_name"
    elif not binding_occurrences(
        body, name
    ) and name not in _captured_sink_parameter_names(scope):
        bindings = binding_occurrences(tree.body, name)
        if (
            len(bindings) == 1
            and bindings[0] in tree.body
            and isinstance(bindings[0], (ast.Import, ast.ImportFrom))
        ):
            row = {
                "status": "INFERRED",
                "reason": None,
                "name": name,
                "declaration": fact(bindings[0]),
            }
    return row


def _captured_sink_enclosing_callable(node, parents):
    current = node
    while id(current) in parents:
        current = parents[id(current)]
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return current
    return None


def _captured_sink_parameter_names(scope):
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        return set()
    args = scope.args
    parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    parameters.extend(item for item in (args.vararg, args.kwarg) if item is not None)
    return {item.arg for item in parameters}


def _security_request_binary_decode_kind(
    value, requests, aliases, scope, statement, *, audit
):
    """Carry request text through an exact, source-stable base64-to-bytes transform."""
    if not isinstance(value, ast.Call) or len(value.args) != 1 or value.keywords:
        return None
    if any((isinstance(argument, ast.Starred) for argument in value.args)):
        return None
    if audit.security_call_name(value, aliases) not in {
        "base64.b64decode",
        "base64.urlsafe_b64decode",
    }:
        return None
    from .semantic_credential_sensor import (
        _provider_identity_uncertain,
        request_payload_value_kind,
    )

    module = audit._security_module_scope(scope)
    if module is None or _provider_identity_uncertain(
        module, aliases, roots=(audit.security_call_name(value, aliases),)
    ):
        return None
    source = value.args[0]
    if request_payload_value_kind(
        source,
        requests,
        aliases,
        audit._security_scope_request_aliases,
        scope,
        statement,
    ) == "text" and audit._security_expr_tainted(source, requests, set(), aliases):
        return "bytes"
    return None


def _security_bind_local_native_input_precondition(
    call, canonical, primitive, scope, requests, aliases, *, audit
):
    """Bind one sink against its own provider identities when unrelated module code is ambiguous."""
    from .semantic_credential_sensor import (
        _native_input_request_is_supported,
        security_precondition_call_shape,
        security_precondition_path_possible,
        supported_security_precondition,
    )
    from .finite_capture import security_input_value_flow

    eligible = {
        "SECURITY_DYNAMIC_EXECUTION",
        "SECURITY_OS_COMMAND",
        "SECURITY_SHELL_COMMAND",
        "SECURITY_UNSAFE_DESERIALIZATION",
        "SECURITY_UNSAFE_YAML",
    }
    if primitive.get("code") not in eligible or not call.args:
        return
    module = audit._security_module_scope(scope)
    if module is None or not (
        security_precondition_call_shape(call, canonical)
        or audit._security_shell_call_shape_for_flow(call, canonical)
    ):
        return
    if not security_precondition_path_possible(call):
        return
    supported = getattr(requests, "supported_view", lambda: requests)()
    if supported is None or not _native_input_request_is_supported(
        call, canonical, supported, aliases, scope, audit
    ):
        return
    if audit._security_local_request_provider_identity_uncertain(module, aliases):
        return
    provider_roots = (
        ("subprocess",)
        if canonical.startswith("subprocess.")
        else ("os.system",)
        if canonical == "os.system"
        else ("_pickle",)
        if canonical.startswith("_pickle.")
        else ("pickle",)
        if canonical.startswith("pickle.")
        else ("dill",)
        if canonical.startswith("dill.")
        else ("yaml",)
        if canonical.startswith("yaml.")
        else ("builtins",)
    )
    if audit._security_local_provider_identity_uncertain(
        module, aliases, provider_roots, audit=audit
    ):
        return
    premise = supported_security_precondition(call, "untrusted_request", canonical)
    if trace := security_input_value_flow(call.args[0], supported, aliases):
        premise["input_value_flow"] = trace
    call._security_supported_precondition = premise


def _security_local_request_provider_identity_uncertain(module, aliases):
    """Keep request-provider mutations in every captured module as source blockers."""
    from .review_audits import _security_aliases
    from .semantic_credential_sensor import (
        _native_input_inventory_epoch,
        _native_input_provider_inventory,
        _provider_identity_uncertain,
    )

    selected_providers = (
        "flask.request",
        *(
            path
            for path in aliases.values()
            if path.split(".")[0] in {"flask", "django"}
        ),
    )
    source_model = getattr(module, "_security_source_model", None)
    trees = (
        tuple(source_model.snapshots.values())
        if source_model is not None
        else (module,)
    )
    for tree in trees:
        nodes = list(ast.walk(tree))
        source_aliases = aliases if tree is module else _security_aliases(nodes)
        inventory = _native_input_provider_inventory(tree, source_aliases, nodes)
        parents = {
            id(child): parent
            for parent in nodes
            for child in ast.iter_child_nodes(parent)
        }
        if _provider_identity_uncertain(
            tree,
            source_aliases,
            roots=selected_providers,
            selected_paths=True,
            nodes=inventory,
            parents=parents,
            inventory_projector=_native_input_provider_inventory,
            inventory_dependencies=_native_input_inventory_epoch(),
        ):
            return True
    return False


def _security_shell_call_shape_for_flow(call, canonical):
    """Allow inert process options around an explicitly enabled shell sink."""
    if (
        canonical
        not in {
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.Popen",
        }
        or len(call.args) != 1
        or isinstance(call.args[0], ast.Starred)
    ):
        return False
    keywords = {item.arg: item.value for item in call.keywords}
    if (
        None in keywords
        or len(keywords) != len(call.keywords)
        or "shell" not in keywords
        or (not isinstance(keywords["shell"], ast.Constant))
        or (keywords["shell"].value is not True)
    ):
        return False
    inert_options = {
        "shell",
        "stdin",
        "stdout",
        "stderr",
        "timeout",
        "check",
        "cwd",
        "env",
        "text",
        "encoding",
        "errors",
        "universal_newlines",
        "bufsize",
        "close_fds",
        "start_new_session",
        "creationflags",
    }
    return set(keywords).issubset(inert_options)


def _security_local_provider_identity_uncertain(module, aliases, roots, *, audit):
    """Ignore only read-only subprocess stream constants in otherwise exact provider checks."""
    from types import SimpleNamespace
    from .finite_capture import finite_provider_mutation_index
    from .review_audits import _resolved_ast_name

    nodes = list(ast.walk(module))
    parents = {
        id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)
    }
    mutations = finite_provider_mutation_index(
        nodes, aliases, SimpleNamespace(_resolved_ast_name=_resolved_ast_name), parents
    )
    if "subprocess" in roots:
        inert = set()
        for node in nodes:
            if not (
                isinstance(node, ast.Attribute)
                and node.attr in {"STDOUT", "PIPE", "DEVNULL"}
                and isinstance(node.ctx, ast.Load)
                and (audit._resolve(node, aliases) == f"subprocess.{node.attr}")
            ):
                continue
            keyword = parents.get(id(node))
            call = (
                parents.get(id(keyword)) if isinstance(keyword, ast.keyword) else None
            )
            if (
                isinstance(keyword, ast.keyword)
                and keyword.value is node
                and (keyword.arg in {"stdin", "stdout", "stderr"})
                and isinstance(call, ast.Call)
                and audit.security_call_name(call, aliases).startswith("subprocess.")
            ):
                inert.add((f"subprocess.{node.attr}", "*"))
        mutations = [item for item in mutations if item not in inert]
    return any(
        (
            path == root or path.startswith(root + ".")
            for path, _attribute in mutations
            for root in roots
        )
    )


_NATIVE_INPUT_EPOCH_BINDINGS = tuple(
    (module, names.split())
    for module, names in {
        "factoryline.semantic_credential_sensor": """
        _signing_provider_clear _signing_provider_reads _signing_bound_providers_clear
        _security_builtin_identity_closed _provider_identity_uncertain _provider_path_conflicts
        _native_input_provider_inventory http_request_payload
        _http_request_subscript_payload _http_request_call_payload
        _http_request_attribute_payload _flask_request_body_kind
        _credential_get_source_key _http_request_mapping
        _request_mapping_value_unchanged _request_mapping_aliases
        _request_mapping_mutation _django_http_body_payload
        _native_request_data_member _new_security_request_alias_memo
        _security_scope_request_aliases _security_scope_request_aliases_uncached
        _security_request_alias_module_bindings
        _security_store_request_alias_bindings
        supported_security_precondition tls_finding log_security_precondition
        bind_request_sink_precondition _security_request_sink_slot
        """,
        "factoryline.captured_security_audit": """
        _security_request_binary_decode_kind _security_bind_local_native_input_precondition _security_local_request_provider_identity_uncertain _security_shell_call_shape_for_flow _security_local_provider_identity_uncertain _native_input_inventory_epoch
        """,
        "factoryline.import_context": """
        finite_key_reflection_reads _finite_loop_reflection_reads _finite_dictionary_key_domain _finite_dictionary_key_use_closed _finite_key_reflection_call _finite_table_peers_closed import_resolution_helpers close_selected_import_sources eager_import_closure _eager_import_model_roots _eager_import_edges _eager_import_target
        """,
        "factoryline.credential_endpoint_admission": """
        _django_setting_import_closure _django_setting_import_aliases _django_setting_import_sites _django_setting_import_operand _django_import_namespace_unknown _django_importer_external
        """,
        "factoryline.credential_role_constructor_provider": """
        binding_occurrences _binds
        """,
        "factoryline.credential_role_identity_effects": """
        source_symbol_index
        """,
        "factoryline.mock_fixture_provenance": """
        _django_import_rows _django_name _django_assignment
        """,
        "factoryline.review_integrity": """
        _security_request_binary_decode_kind _security_bind_local_native_input_precondition _security_local_request_provider_identity_uncertain _security_shell_call_shape_for_flow _security_local_provider_identity_uncertain
        bind_security_call_scopes _bind_security_scope_node _bind_security_function
        _bind_security_class _function_annotations _security_scope_local_names
        _security_scope_nonlocal_names _security_scope_declared_names
        _security_module_scope _security_apply_import_bindings
        _security_scope_request_aliases
        _security_unsafe_flask_file_save _security_upload_path_expression
        tls_verification_disabled
        """,
        "factoryline.audit_log_flow": """
        audit_log_source_findings
        """,
        "factoryline.finite_capture": """
        finite_provider_mutation_index _provider_mutation_for_node
        _provider_mutation_facts _record_provider_paths _record_provider_capture
        _provider_alias_bindings _provider_paths _provider_call_argument
        _reflective_provider_write _foreign_provider_inputs
        _foreign_provider_source_mutations _project_provider_inventory
        """,
        "factoryline.credential_role_paths": """
        matches_regenerated_security_precondition valid_security_precondition
        security_effect_fact_matches logging_consumer_configuration
        logging_security_effect_witness logging_security_precondition source_span
        upload_path_expression bind_request_sink_precondition tls_security_finding
        upload_name_origin upload_join_effect upload_concat_effect source_domain_guarded
        _upload_filename_domain_kind _upload_guard_dominates
        _upload_control_path _upload_definition_reaches _upload_receiver_names
        _upload_prior_field_write _upload_filename_mutated
        bind_upload_sink_precondition
        regenerate_security_source_model
        _logging_configuration _logging_direct_configuration
        _logging_declared_configuration _logging_active_settings
        _logging_node_possible _logging_reference _logging_dict_fields
        _logging_literal _logging_assignment _logging_receiver
        _logging_receiver_name _logging_receiver_assignments _logging_call_level
        _logging_logger_route _logging_logger_entry _logging_root_route
        _logging_plain_handler_routes _logging_plain_handler_route
        _logging_plain_formatter _logging_route_facts _logging_config_sections
        _logging_mutation_present _logging_local_mutation_present
        _logging_filter_provider_uncertain
        logging_input_value_trace logging_merge_log_flow
        """,
        "factoryline.review_audits": """
        _name _resolved_ast_name _security_aliases _bound_names _binding_name
        _iter_ast_nodes
        """,
        "factoryline.intent_quality": """
        _security_scope_request_aliases
        """,
        "factoryline": """
        _source_binding_helpers _bind_source_call _source_call_signature
        """,
    }.items()
)


def _native_input_inventory_epoch(_cache_owner):
    from importlib import import_module
    from . import review_audits, intent_quality, semantic_credential_sensor
    from . import credential_role_paths
    from . import audit_log_flow

    functions = [
        getattr(import_module(module), name)
        for module, names in import_module(
            _cache_owner.__module__
        )._NATIVE_INPUT_EPOCH_BINDINGS
        for name in names
    ]
    helpers = import_module("factoryline.import_context").import_resolution_helpers()
    functions.extend(helpers if isinstance(helpers, tuple) else ())
    identity = (
        tuple(
            (
                (
                    fn,
                    getattr(fn, "__code__", None),
                    id(getattr(fn, "__defaults__", None)),
                )
                for fn in functions
            )
        ),
        semantic_credential_sensor.SECURITY_EFFECT_WITNESS_SCHEMA,
        import_module("factoryline.import_context")._eager_import_model_roots(),
        semantic_credential_sensor.SECURITY_EFFECT_CONTRACTS,
        semantic_credential_sensor._SECURITY_EFFECT_WITNESS_SCHEMA_BASELINE,
        semantic_credential_sensor._SECURITY_EFFECT_CONTRACTS_BASELINE,
        tuple(sorted(credential_role_paths._LOG_LEVEL_VALUES.items())),
        tuple(sorted(credential_role_paths._LOG_STANDARD_HANDLERS)),
        tuple(
            (
                (name, fn, getattr(fn, "__code__", None))
                for name, fn in vars(audit_log_flow._LogReader).items()
                if callable(fn)
            )
        ),
        audit_log_flow._LOGGING_LEVELS,
        audit_log_flow.log_evidence,
        ast.dump(semantic_credential_sensor._FLASK_BODY_SIGNATURE),
        review_audits._FUNCTION_NODES,
        intent_quality._SECURITY_REQUEST_ALIAS_MEMO,
        intent_quality._SECURITY_REQUEST_ALIAS_MAX_ENTRIES,
        intent_quality._SECURITY_REQUEST_ALIAS_MAX_PAIRS,
        intent_quality._SECURITY_REQUEST_ALIAS_MAX_BYTES,
    )
    cached = getattr(_cache_owner, "_cached_epoch", None)
    if cached is None or cached[0] != identity:
        cached = (identity, object())
        _cache_owner._cached_epoch = cached
    return cached[1]
