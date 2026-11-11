__version__ = "0.49.6"

import ast
import hashlib
import json as _json


def canonical_json_bytes(value: object) -> bytes:
    """Strict UTF-8 receipt encoding shared by byte-equivalent producers."""
    return _json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_json_compat_bytes(value: object) -> bytes:
    """Preserve existing UTF-8 receipt bytes, including legacy non-finite values."""
    return _json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=True
    ).encode("utf-8")


def canonical_ascii_json_compat_bytes(value: object) -> bytes:
    """Preserve existing ASCII-escaped receipt bytes and non-finite handling."""
    return _json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=True
    ).encode("utf-8")


def _source_call_signature(function):
    """Describe captured Python parameters without evaluating source tokens."""
    import ast
    from inspect import Parameter, Signature

    if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        raise ValueError("SOURCE_SIGNATURE_UNKNOWN")
    args = function.args
    positional = [*args.posonlyargs, *args.args]
    defaults = dict(
        zip(
            (n.arg for n in positional),
            [Parameter.empty] * (len(positional) - len(args.defaults)) + args.defaults,
        )
    )
    defaults.update(
        (n.arg, d) for n, d in zip(args.kwonlyargs, args.kw_defaults) if d is not None
    )

    def parameter(node, kind):
        return Parameter(
            node.arg,
            kind,
            default=defaults.get(node.arg, Parameter.empty),
            annotation=node.annotation or Parameter.empty,
        )

    parameters = [
        parameter(n, kind)
        for kind, nodes in (
            (Parameter.POSITIONAL_ONLY, args.posonlyargs),
            (Parameter.POSITIONAL_OR_KEYWORD, args.args),
            (Parameter.KEYWORD_ONLY, args.kwonlyargs),
        )
        for n in nodes
    ]
    if args.vararg:
        parameters.insert(
            len(positional), parameter(args.vararg, Parameter.VAR_POSITIONAL)
        )
    if args.kwarg:
        parameters.append(parameter(args.kwarg, Parameter.VAR_KEYWORD))
    return Signature(parameters)


def _bind_source_call(
    call, function, receiver=None, previous=None, *, apply_defaults=True
):
    """Associate AST tokens only; this proves neither execution nor safe effects."""
    import ast

    if (
        not isinstance(call, ast.Call)
        or any(isinstance(n, ast.Starred) for n in call.args)
        or any(n.arg is None for n in call.keywords)
    ):
        raise ValueError("SOURCE_ARGUMENT_EXPANSION_UNKNOWN")
    previous = {} if previous is None else previous

    def value(node):
        return previous.get(node.id, node) if isinstance(node, ast.Name) else node

    keywords = {n.arg: value(n.value) for n in call.keywords}
    if len(keywords) != len(call.keywords):
        raise ValueError("SOURCE_ARGUMENT_DUPLICATE_KEYWORD")
    try:
        bound = _source_call_signature(function).bind(
            *([receiver] if receiver is not None else []),
            *(value(n) for n in call.args),
            **keywords,
        )
        if apply_defaults:
            bound.apply_defaults()
        return bound.arguments
    except (TypeError, ValueError) as exc:
        raise ValueError("SOURCE_ARGUMENT_BINDING_UNKNOWN") from exc


def _source_binding_helpers():
    return (_source_call_signature, _bind_source_call)


def _db_python_witnessed_field_contexts_impl(
    unique,
    import_module,
    plain_fields,
    export_stable,
    witnesses,
    called_methods,
    mutated,
):
    """Attach bounded, source-bound constructor contexts for plain instance fields."""
    rows = [(module, *row[:2]) for module, row in unique.items()]
    for _, _, tree in rows:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                node.__dict__.pop("_db_field_contexts", None)
    for module, path, tree in rows:
        digest = getattr(tree, "_db_source_sha256", None)
        if not isinstance(digest, str):
            continue
        path_name = _db_python_path_import(tree)
        if not path_name:
            continue
        for cls in tree.body:
            _db_python_witnessed_class(
                cls,
                path_name,
                rows,
                module,
                path,
                digest,
                import_module,
                plain_fields,
                export_stable,
                witnesses,
                called_methods,
                mutated,
            )


def _db_python_witnessed_class(
    cls,
    path_name,
    rows,
    module,
    path,
    digest,
    import_module,
    plain_fields,
    export_stable,
    witnesses,
    called_methods,
    mutated,
):
    init = _db_python_witness_initializer(cls)
    if not init:
        return
    fields = plain_fields(cls, init, path_name)
    if not fields:
        return
    trees = [(m, t) for m, _, t in rows]
    if not export_stable(trees, module, cls.name, import_module):
        return
    for witness in witnesses(rows, module, cls.name, import_module):
        _db_python_record_witness(
            cls, init, fields, path, digest, witness, called_methods, mutated
        )


def _db_python_record_witness(
    cls, init, fields, path, digest, witness, called_methods, mutated
):
    called = called_methods(init, witness["call"])
    for method in cls.body:
        if (
            not isinstance(method, ast.FunctionDef)
            or method.name not in called
            or method.decorator_list
            or mutated(method, fields)
        ):
            continue
        context = {
            "class_path": path,
            "class_sha256": digest,
            "class": cls.name,
            "method": method.name,
            "callsite_path": witness["path"],
            "callsite_sha256": witness["sha256"],
            "callsite_line": witness["call"].lineno,
            "plain_fields": sorted(fields),
        }
        method.__dict__.setdefault("_db_field_contexts", []).append(context)


def _db_python_path_import(tree):
    names = [
        a.asname or a.name
        for n in tree.body
        if isinstance(n, ast.ImportFrom) and n.module == "pathlib"
        for a in n.names
        if a.name == "Path"
    ]
    if len(names) != 1:
        return None
    name = names[0]
    if any(
        isinstance(n, ast.Name)
        and n.id == name
        and isinstance(n.ctx, (ast.Store, ast.Del))
        or isinstance(n, ast.arg)
        and n.arg == name
        for n in ast.walk(tree)
    ):
        return None
    return name


def _db_python_witness_initializer(cls):
    if (
        not isinstance(cls, ast.ClassDef)
        or cls.bases
        or cls.keywords
        or cls.decorator_list
    ):
        return None
    if any(
        isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and n.name in {"__new__", "__getattribute__", "__getattr__", "__setattr__"}
        for n in cls.body
    ):
        return None
    constructors = [
        n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "__init__"
    ]
    if len(constructors) != 1:
        return None
    init = constructors[0]
    if any(
        isinstance(n, ast.Call)
        and any(isinstance(a, ast.Name) and a.id == "self" for a in n.args)
        or isinstance(n, ast.Attribute)
        and isinstance(n.value, ast.Name)
        and n.value.id == "self"
        and n.attr == "__dict__"
        for n in ast.walk(init)
    ):
        return None
    return init


def _db_witness_identity_functions():
    return (
        _db_python_witnessed_field_contexts_impl,
        _db_python_witnessed_class,
        _db_python_record_witness,
        _db_python_path_import,
        _db_python_witness_initializer,
    )


def _db_python_import_before_call(import_node, call, parents):
    """Require an earlier import in the same lexical suite or module suite."""
    child = call
    while child in parents:
        parent = parents[child]
        for _, value in ast.iter_fields(parent):
            if isinstance(value, list) and child in value and import_node in value:
                return value.index(import_node) < value.index(child)
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            module = parents.get(parent)
            while module is not None and not isinstance(module, ast.Module):
                module = parents.get(module)
            return bool(
                module is not None
                and import_node in module.body
                and import_node.lineno < parent.lineno
            )
        child = parent
    return False


def _db_python_self_or_field_mutated(method, fields):
    return any(
        isinstance(n, ast.Name)
        and n.id == "self"
        and isinstance(n.ctx, (ast.Store, ast.Del))
        or isinstance(n, ast.Attribute)
        and isinstance(n.value, ast.Name)
        and n.value.id == "self"
        and n.attr in fields | {"__class__"}
        and isinstance(n.ctx, (ast.Store, ast.Del))
        or isinstance(n, ast.Call)
        and any(isinstance(a, ast.Name) and a.id == "self" for a in n.args)
        or isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and isinstance(n.func.value, ast.Name)
        and n.func.value.id == "self"
        or isinstance(n, ast.Attribute)
        and isinstance(n.value, ast.Name)
        and n.value.id == "self"
        and n.attr == "__dict__"
        for n in ast.walk(method)
    )


def _db_python_http_stdlib_digest():
    """Validate the current stdlib handler/server association and bind its bytes."""
    import inspect
    import socketserver
    import textwrap

    try:
        setup = inspect.getsource(socketserver.BaseRequestHandler.__init__)
        finish = inspect.getsource(socketserver.BaseServer.finish_request)
        first = ast.parse(textwrap.dedent(setup)).body[0]
        second = ast.parse(textwrap.dedent(finish)).body[0]
    except (OSError, TypeError, SyntaxError, IndexError):
        return None
    assigned = any(
        isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Attribute)
        and isinstance(n.targets[0].value, ast.Name)
        and n.targets[0].value.id == "self"
        and n.targets[0].attr == "server"
        and isinstance(n.value, ast.Name)
        and n.value.id == "server"
        for n in first.body
    )
    instantiated = any(
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and isinstance(n.func.value, ast.Name)
        and n.func.value.id == "self"
        and n.func.attr == "RequestHandlerClass"
        and len(n.args) == 3
        and isinstance(n.args[2], ast.Name)
        and n.args[2].id == "self"
        for n in ast.walk(second)
    )
    return (
        hashlib.sha256((setup + finish).encode()).hexdigest()
        if assigned and instantiated
        else None
    )


def _db_python_server_field_contexts(unique, import_module):
    """Bind plain forwarding fields along a captured stdlib HTTP construction."""
    stdlib = _db_python_http_stdlib_digest()
    if not stdlib:
        return
    classes = {}
    paths = {}
    for module, (path, tree, _, _) in unique.items():
        digest = getattr(tree, "_db_source_sha256", None)
        if not isinstance(digest, str):
            continue
        paths[path] = (module, tree)
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                classes[module, node.name] = (node, path, digest, tree)

    from functools import partial

    resolve = partial(_db_python_server_resolve, classes, import_module)

    for (store_module, _), (store_cls, store_path, store_hash, _) in classes.items():
        contexts = [
            c
            for m in store_cls.body
            if isinstance(m, ast.FunctionDef)
            for c in getattr(m, "_db_field_contexts", ())
        ]
        for seed in contexts:
            _db_python_server_seed(
                seed,
                paths,
                classes,
                unique,
                import_module,
                resolve,
                store_cls,
                store_path,
                store_hash,
                stdlib,
                _bind_source_call,
            )


def _db_python_server_seed(
    seed,
    paths,
    classes,
    unique,
    import_module,
    resolve,
    store_cls,
    store_path,
    store_hash,
    stdlib,
    _bind_source_call,
):
    if seed["callsite_path"] not in paths:
        return
    server_module, tree = paths[seed["callsite_path"]]
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    stores = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and n.lineno == seed["callsite_line"]
        and isinstance(n.func, ast.Name)
        and (resolved := resolve(server_module, n.func.id, n, tree))
        and resolved[0] is store_cls
    ]
    if len(stores) != 1:
        return
    store_call = stores[0]
    outer = parents.get(store_call)
    if not isinstance(outer, ast.Call) or not isinstance(outer.func, ast.Name):
        return
    server = resolve(server_module, outer.func.id, outer, tree)
    if not server:
        return
    server_cls, server_path, server_hash, _ = server
    server_init = _db_python_server_initializer(server_cls)
    if not server_init or server_cls.decorator_list or server_cls.keywords:
        return
    try:
        bindings = _bind_source_call(
            outer, server_init, receiver=ast.Name(id="self"), apply_defaults=False
        )
    except ValueError:
        return
    parameters = [k for k, v in bindings.items() if v is store_call]
    if len(parameters) != 1:
        return
    server_store = parameters[0]
    _db_python_server_context_from_init(
        unique,
        import_module,
        classes,
        resolve,
        server_module,
        tree,
        server_cls,
        server_init,
        server_store,
        (server_path, server_hash),
        (store_cls, store_path, store_hash),
        seed,
        stdlib,
    )


def _db_python_server_resolve(classes, import_module, module, name, at, tree):
    candidates = []
    if (module, name) in classes:
        candidates.append(classes[module, name])
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    for imp in ast.walk(tree):
        if not isinstance(imp, ast.ImportFrom):
            continue
        scope = parents.get(at)
        while scope is not None and not isinstance(
            scope, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            scope = parents.get(scope)
        visible_local = bool(scope and imp in scope.body and imp.lineno < at.lineno)
        if not visible_local and not _db_python_import_before_call(imp, at, parents):
            continue
        provider = import_module(module, imp)
        for alias in imp.names:
            if (alias.asname or alias.name) == name and (
                provider,
                alias.name,
            ) in classes:
                candidates.append(classes[provider, alias.name])
    if any(
        isinstance(n, ast.Name)
        and n.id == name
        and isinstance(n.ctx, (ast.Store, ast.Del))
        or isinstance(n, ast.arg)
        and n.arg == name
        for n in ast.walk(tree)
    ):
        return None
    return candidates[0] if len(candidates) == 1 else None


def _db_python_server_initializer(cls):
    found = [
        n
        for n in cls.body
        if isinstance(n, ast.FunctionDef)
        and n.name == "__init__"
        and not n.decorator_list
    ]
    return found[0] if len(found) == 1 else None


def _db_python_server_forward(init, parameter):
    found = [
        n.targets[0].attr
        for n in init.body
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Attribute)
        and isinstance(n.targets[0].value, ast.Name)
        and n.targets[0].value.id == "self"
        and isinstance(n.value, ast.Name)
        and n.value.id == parameter
    ]
    return found[0] if len(found) == 1 else None


def _db_python_server_plain(cls, field):
    if cls.decorator_list or cls.keywords:
        return False
    return not any(
        isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and (
            n.name
            in {"__new__", "__getattribute__", "__getattr__", "__setattr__", field}
        )
        or isinstance(n, (ast.Assign, ast.AnnAssign))
        and any(
            isinstance(t, ast.Name) and t.id == field
            for t in (n.targets if isinstance(n, ast.Assign) else [n.target])
        )
        for n in cls.body
    )


def _db_python_server_context_from_init(
    unique,
    import_module,
    classes,
    resolve,
    module,
    tree,
    server_cls,
    server_init,
    server_store,
    server_source,
    store_source,
    seed,
    stdlib,
):
    handler = _db_python_server_handler(module, tree, server_cls, server_init, resolve)
    if handler is None:
        return
    handler_cls, handler_path, handler_hash = handler
    service_rows = _db_python_server_services(
        module,
        tree,
        server_cls,
        server_init,
        server_store,
        resolve,
        _bind_source_call,
    )
    if not service_rows:
        return
    chain_sources = _db_python_constructor_resource_closure(
        module,
        tree,
        server_cls,
        server_init,
        server_store,
        unique,
        resolve,
        import_module,
    )
    if chain_sources is None:
        return
    for service_field, service, store_field in service_rows:
        _db_python_handler_work_contexts(
            module,
            tree,
            handler_cls,
            handler_path,
            handler_hash,
            service_field,
            store_field,
            store_source,
            server_source,
            service,
            seed,
            stdlib,
            chain_sources,
            resolve,
            unique,
            import_module,
        )


def _db_python_server_handler(module, tree, server_cls, server_init, resolve):
    stdlib_imports = {
        a.name: a.asname or a.name
        for n in tree.body
        if isinstance(n, ast.ImportFrom) and n.module == "http.server"
        for a in n.names
    }
    if not (
        len(server_cls.bases) == 1
        and isinstance(server_cls.bases[0], ast.Name)
        and server_cls.bases[0].id == stdlib_imports.get("ThreadingHTTPServer")
    ):
        return
    if any(
        isinstance(n, ast.FunctionDef)
        and n.name in {"finish_request", "process_request", "get_request"}
        for n in server_cls.body
    ):
        return
    handlers = []
    for n in ast.walk(server_init):
        if (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "__init__"
            and isinstance(n.func.value, ast.Call)
            and isinstance(n.func.value.func, ast.Name)
            and n.func.value.func.id == "super"
        ):
            handlers.extend(a for a in n.args if isinstance(a, ast.Name))
    handler_classes = [resolve(module, h.id, h, tree) for h in handlers]
    handler_classes = [
        h
        for h in handler_classes
        if h
        and len(h[0].bases) == 1
        and isinstance(h[0].bases[0], ast.Name)
        and h[0].bases[0].id == stdlib_imports.get("BaseHTTPRequestHandler")
    ]
    if len(handler_classes) != 1:
        return
    handler_cls, handler_path, handler_hash, _ = handler_classes[0]
    if not _db_python_server_plain(handler_cls, "server") or any(
        isinstance(n, ast.FunctionDef) and n.name in {"__init__", "setup", "handle"}
        for n in handler_cls.body
    ):
        return
    return handler_cls, handler_path, handler_hash


def _db_python_server_services(
    module,
    tree,
    server_cls,
    server_init,
    server_store,
    resolve,
    _bind_source_call,
):
    service_rows = []
    for n in server_init.body:
        if not (
            isinstance(n, ast.Assign)
            and len(n.targets) == 1
            and isinstance(n.targets[0], ast.Attribute)
            and isinstance(n.targets[0].value, ast.Name)
            and n.targets[0].value.id == "self"
            and isinstance(n.value, ast.Call)
            and isinstance(n.value.func, ast.Name)
        ):
            continue
        service = resolve(module, n.value.func.id, n.value, tree)
        if not service or not _db_python_server_plain(server_cls, n.targets[0].attr):
            continue
        service_init = _db_python_server_initializer(service[0])
        if not service_init:
            continue
        try:
            bound = _bind_source_call(
                n.value,
                service_init,
                receiver=ast.Name(id="self"),
                apply_defaults=False,
            )
        except ValueError:
            continue
        formals = [
            k
            for k, v in bound.items()
            if isinstance(v, ast.Name) and v.id == server_store
        ]
        if len(formals) != 1:
            continue
        field = _db_python_server_forward(service_init, formals[0])
        if field and _db_python_server_plain(service[0], field):
            service_rows.append((n.targets[0].attr, service, field))
    return service_rows


def _db_python_constructor_resource_closure(
    module, tree, cls, init, parameter, unique, resolve, import_module
):
    pending = [(module, tree, cls, init, parameter)]
    visited, sources = set(), []
    while pending:
        if len(visited) >= 64:
            return None
        mod, current_tree, owner, constructor, resource = pending.pop()
        key = (mod, owner.name, resource)
        if key in visited:
            continue
        visited.add(key)
        digest = getattr(current_tree, "_db_source_sha256", None)
        path = unique[mod][0] if mod in unique else None
        if not path or not isinstance(digest, str):
            return None
        sources.append({"path": path, "sha256": digest, "class": owner.name})
        if not _db_python_resource_visit(
            mod,
            current_tree,
            owner,
            constructor,
            resource,
            unique,
            resolve,
            _bind_source_call,
            pending,
        ):
            return None
    return sources


def _db_python_resource_visit(
    mod,
    current_tree,
    owner,
    constructor,
    resource,
    unique,
    resolve,
    _bind_source_call,
    pending,
):
    parents = {
        child: parent
        for parent in ast.walk(constructor)
        for child in ast.iter_child_nodes(parent)
    }
    for n in ast.walk(constructor):
        if (
            isinstance(n, ast.Name)
            and n.id == resource
            and isinstance(n.ctx, (ast.Store, ast.Del))
        ):
            return False
        if isinstance(n, ast.Name) and n.id == resource and isinstance(n.ctx, ast.Load):
            if not _db_python_resource_load_safe(n, parents, owner):
                return False
        if (
            isinstance(n, ast.Attribute)
            and isinstance(n.value, ast.Name)
            and n.value.id == resource
            and isinstance(n.ctx, (ast.Store, ast.Del))
        ):
            return False
        if not (
            isinstance(n, ast.Call)
            and any(
                isinstance(a, ast.Name) and a.id == resource
                for a in list(n.args) + [k.value for k in n.keywords]
            )
        ):
            continue
        next_item = _db_python_resource_call(
            n,
            resource,
            mod,
            current_tree,
            unique,
            resolve,
            _bind_source_call,
        )
        if next_item is None:
            return False
        pending.append(next_item)
    return True


def _db_python_resource_load_safe(n, parents, owner):
    parent = parents.get(n)
    if isinstance(parent, ast.Tuple) and n in parent.elts:
        assignment = parents.get(parent)
        if (
            isinstance(assignment, ast.Assign)
            and assignment.value is parent
            and len(assignment.targets) == 1
            and isinstance(assignment.targets[0], ast.Tuple)
            and len(assignment.targets[0].elts) == len(parent.elts)
        ):
            target = assignment.targets[0].elts[parent.elts.index(n)]
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "self"
                and not any(
                    isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and m.name == target.attr
                    or isinstance(m, (ast.Assign, ast.AnnAssign))
                    and any(
                        isinstance(t, ast.Name) and t.id == target.attr
                        for t in (
                            m.targets if isinstance(m, ast.Assign) else [m.target]
                        )
                    )
                    for m in owner.body
                )
            ):
                return True
    forwarded = (
        isinstance(parent, ast.Assign)
        and parent.value is n
        and len(parent.targets) == 1
        and isinstance(parent.targets[0], ast.Attribute)
        and isinstance(parent.targets[0].value, ast.Name)
        and parent.targets[0].value.id == "self"
    )
    argument = (
        isinstance(parent, ast.Call)
        and n in parent.args
        or (
            isinstance(parent, ast.keyword)
            and parent.arg is not None
            and parent.value is n
        )
    )
    if forwarded and any(
        isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
        and m.name == parent.targets[0].attr
        or isinstance(m, (ast.Assign, ast.AnnAssign))
        and any(
            isinstance(t, ast.Name) and t.id == parent.targets[0].attr
            for t in (m.targets if isinstance(m, ast.Assign) else [m.target])
        )
        for m in owner.body
    ):
        return False
    if not forwarded and not argument:
        return False
    return True


def _db_python_resource_call(
    n, resource, mod, current_tree, unique, resolve, _bind_source_call
):
    if not isinstance(n.func, ast.Name):
        return None
    selected = resolve(mod, n.func.id, n, current_tree)
    if not selected:
        return None
    next_cls, _, _, next_tree = selected
    if next_cls.bases or next_cls.decorator_list or next_cls.keywords:
        return None
    if any(
        isinstance(m, ast.FunctionDef)
        and m.name in {"__new__", "__getattribute__", "__getattr__", "__setattr__"}
        for m in next_cls.body
    ):
        return None
    next_init = _db_python_server_initializer(next_cls)
    if not next_init:
        return None
    try:
        bound = _bind_source_call(
            n, next_init, receiver=ast.Name(id="self"), apply_defaults=False
        )
    except ValueError:
        return None
    formals = [
        k for k, v in bound.items() if isinstance(v, ast.Name) and v.id == resource
    ]
    if len(formals) != 1:
        return None
    next_module = next((m for m, row in unique.items() if row[1] is next_tree), None)
    if not next_module:
        return None
    return next_module, next_tree, next_cls, next_init, formals[0]


def _db_python_handler_reachable(handler_cls):
    methods = {
        m.name: m
        for m in handler_cls.body
        if isinstance(m, ast.FunctionDef) and not m.decorator_list
    }
    reachable, pending = set(), ["do_POST"]
    while pending and len(reachable) < 64:
        name = pending.pop()
        if name in reachable or name not in methods:
            continue
        reachable.add(name)
        for n in ast.walk(methods[name]):
            if (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and isinstance(n.func.value, ast.Name)
                and n.func.value.id == "self"
            ):
                pending.append(n.func.attr)
    return methods, reachable


def _db_python_handler_work_contexts(
    module,
    tree,
    handler_cls,
    handler_path,
    handler_hash,
    service_field,
    store_field,
    store_source,
    server_source,
    service,
    seed,
    stdlib,
    chain_sources,
    resolve,
    unique,
    import_module,
):
    methods, reachable = _db_python_handler_reachable(handler_cls)
    store_cls, store_path, store_hash = store_source
    store_fields = set(seed["plain_fields"])
    for method_name in reachable:
        method = methods[method_name]
        aliases = []
        for n in ast.walk(method):
            if not (
                isinstance(n, ast.Assign)
                and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Name)
            ):
                continue
            value = n.value
            if (
                isinstance(value, ast.Attribute)
                and value.attr == store_field
                and isinstance(value.value, ast.Attribute)
                and value.value.attr == service_field
                and isinstance(value.value.value, ast.Attribute)
                and value.value.value.attr == "server"
                and isinstance(value.value.value.value, ast.Name)
                and value.value.value.value.id == "self"
            ):
                aliases.append(n.targets[0].id)
        if len(aliases) != 1:
            continue
        alias = aliases[0]
        if (
            sum(
                isinstance(n, ast.Name)
                and n.id == alias
                and isinstance(n.ctx, ast.Store)
                for n in ast.walk(method)
            )
            != 1
        ):
            continue
        for call in ast.walk(method):
            if not (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Call)
                and isinstance(call.func.value.func, ast.Name)
            ):
                continue
            _db_python_handler_work_call(
                call,
                module,
                tree,
                method,
                alias,
                store_source,
                unique,
                resolve,
                import_module,
                store_fields,
                handler_path,
                handler_hash,
                chain_sources,
                server_source,
                service,
                stdlib,
            )


def _db_python_handler_barriers(target, work_field, store_fields, store_cls):
    barriers = [
        n.lineno
        for n in ast.walk(target)
        if isinstance(n, ast.Name)
        and n.id == "self"
        and isinstance(n.ctx, (ast.Store, ast.Del))
        or isinstance(n, ast.Attribute)
        and isinstance(n.value, ast.Name)
        and n.value.id == "self"
        and n.attr in {work_field, "__class__", "__dict__"}
        and (isinstance(n.ctx, (ast.Store, ast.Del)) or n.attr == "__dict__")
        or isinstance(n, ast.Call)
        and any(
            isinstance(a, ast.Name) and a.id == "self"
            for argument in list(n.args) + [k.value for k in n.keywords]
            if not (
                isinstance(argument, ast.Attribute)
                and argument.attr in store_fields
                and isinstance(argument.value, ast.Attribute)
                and argument.value.attr == work_field
                and isinstance(argument.value.value, ast.Name)
                and argument.value.value.id == "self"
            )
            for a in ast.walk(argument)
        )
        or isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and isinstance(n.func.value, ast.Name)
        and n.func.value.id == "self"
    ]
    target_parents = {
        child: parent
        for parent in ast.walk(target)
        for child in ast.iter_child_nodes(parent)
    }
    for field_ref in ast.walk(target):
        if not (
            isinstance(field_ref, ast.Attribute)
            and isinstance(field_ref.value, ast.Name)
            and field_ref.value.id == "self"
            and field_ref.attr == work_field
            and isinstance(field_ref.ctx, ast.Load)
        ):
            continue
        parent = target_parents.get(field_ref)
        if isinstance(parent, ast.Attribute) and parent.attr in store_fields:
            continue
        call_parent = target_parents.get(parent)
        if (
            isinstance(parent, ast.Attribute)
            and isinstance(call_parent, ast.Call)
            and call_parent.func is parent
        ):
            known = [
                n
                for n in store_cls.body
                if isinstance(n, ast.FunctionDef)
                and n.name == parent.attr
                and not n.decorator_list
            ]
            if len(known) == 1 and not _db_python_self_or_field_mutated(
                known[0], store_fields
            ):
                continue
        barriers.append(field_ref.lineno)
    return barriers


def _db_python_handler_work_call(
    call,
    module,
    tree,
    method,
    alias,
    store_source,
    unique,
    resolve,
    import_module,
    store_fields,
    handler_path,
    handler_hash,
    chain_sources,
    server_source,
    service,
    stdlib,
):
    store_cls, store_path, store_hash = store_source
    work_call = call.func.value
    prefix = _db_python_handler_prefix_safe(
        module,
        tree,
        method,
        alias,
        work_call,
        store_source,
        unique,
        resolve,
        import_module,
        store_fields,
    )
    if prefix is None:
        return
    work = resolve(module, work_call.func.id, work_call, tree)
    if not work:
        return
    work_cls, work_path, work_hash, _ = work
    if work_cls.bases or work_cls.decorator_list or work_cls.keywords:
        return
    work_init = _db_python_server_initializer(work_cls)
    if not work_init:
        return
    try:
        bound = _bind_source_call(
            work_call, work_init, receiver=ast.Name(id="self"), apply_defaults=False
        )
    except ValueError:
        return
    formals = [k for k, v in bound.items() if isinstance(v, ast.Name) and v.id == alias]
    if len(formals) != 1:
        return
    work_field = _db_python_server_forward(work_init, formals[0])
    if not work_field or not _db_python_server_plain(work_cls, work_field):
        return
    targets = [
        n
        for n in work_cls.body
        if isinstance(n, ast.FunctionDef)
        and n.name == call.func.attr
        and not n.decorator_list
    ]
    if len(targets) != 1:
        return
    target = targets[0]
    barriers = _db_python_handler_barriers(target, work_field, store_fields, store_cls)
    target.__dict__.setdefault("_db_field_contexts", []).append(
        {
            "class_path": work_path,
            "class_sha256": work_hash,
            "class": work_cls.name,
            "method": target.name,
            "callsite_path": handler_path,
            "callsite_sha256": handler_hash,
            "callsite_line": work_call.lineno,
            "plain_fields": [],
            "plain_chains": [[work_field, field] for field in sorted(store_fields)],
            "plain_before_line": min(barriers, default=1 << 30),
            "constructor_sources": chain_sources + prefix,
            "server_path": server_source[0],
            "server_sha256": server_source[1],
            "service_path": service[1],
            "service_sha256": service[2],
            "store_path": store_path,
            "store_sha256": store_hash,
            "http_stdlib_sha256": stdlib,
        }
    )


def _db_python_handler_store_call_safe(call, alias, store_cls, store_fields):
    if (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == alias
    ):
        targets = [
            n
            for n in store_cls.body
            if isinstance(n, ast.FunctionDef)
            and n.name == call.func.attr
            and not n.decorator_list
        ]
        if len(targets) != 1 or _db_python_self_or_field_mutated(
            targets[0], store_fields
        ):
            return False
    return True


def _db_python_handler_prefix_closure(
    call,
    actuals,
    alias,
    module,
    tree,
    unique,
    resolve,
    import_module,
    _bind_source_call,
):
    if len(actuals) != 1 or not isinstance(call.func, ast.Name):
        return None
    selected = resolve(module, call.func.id, call, tree)
    if not selected:
        return None
    cls, _, _, selected_tree = selected
    init = _db_python_server_initializer(cls)
    if not init or cls.bases or cls.decorator_list or cls.keywords:
        return None
    try:
        bound = _bind_source_call(
            call, init, receiver=ast.Name(id="self"), apply_defaults=False
        )
    except ValueError:
        return None
    formals = [k for k, v in bound.items() if isinstance(v, ast.Name) and v.id == alias]
    next_module = next(
        (m for m, row in unique.items() if row[1] is selected_tree), None
    )
    if len(formals) != 1 or not next_module:
        return None
    closure = _db_python_constructor_resource_closure(
        next_module,
        selected_tree,
        cls,
        init,
        formals[0],
        unique,
        resolve,
        import_module,
    )
    if closure is None:
        return None
    return closure


def _db_python_handler_prefix_safe(
    module,
    tree,
    method,
    alias,
    work_call,
    store_source,
    unique,
    resolve,
    import_module,
    store_fields,
):
    """Check captured Store-bearing calls that precede the witnessed work call."""
    store_cls, store_path, store_hash = store_source
    sources = [{"path": store_path, "sha256": store_hash, "class": store_cls.name}]
    for call in ast.walk(method):
        if (
            not isinstance(call, ast.Call)
            or call is work_call
            or call.lineno >= work_call.lineno
        ):
            continue
        if not _db_python_handler_store_call_safe(call, alias, store_cls, store_fields):
            return None
        actuals = [
            a
            for a in list(call.args) + [k.value for k in call.keywords]
            if isinstance(a, ast.Name) and a.id == alias
        ]
        if not actuals:
            continue
        closure = _db_python_handler_prefix_closure(
            call,
            actuals,
            alias,
            module,
            tree,
            unique,
            resolve,
            import_module,
            _bind_source_call,
        )
        if closure is None:
            return None
        sources.extend(closure)
    return sources


def _db_server_graph_identity_functions():
    return (
        _db_server_graph_identity_functions,
        _db_python_import_before_call,
        _db_python_self_or_field_mutated,
        _db_python_http_stdlib_digest,
        _db_python_server_field_contexts,
        _db_python_server_seed,
        _db_python_server_resolve,
        _db_python_server_initializer,
        _db_python_server_forward,
        _db_python_server_plain,
        _db_python_server_context_from_init,
        _db_python_server_handler,
        _db_python_server_services,
        _db_python_constructor_resource_closure,
        _db_python_resource_visit,
        _db_python_resource_load_safe,
        _db_python_resource_call,
        _db_python_handler_reachable,
        _db_python_handler_work_contexts,
        _db_python_handler_barriers,
        _db_python_handler_work_call,
        _db_python_handler_store_call_safe,
        _db_python_handler_prefix_closure,
        _db_python_handler_prefix_safe,
    )
