"""AST-only implementation contracts and hash-bound project contract helpers."""

import ast
from hashlib import sha256

from .ops_telemetry import _measured_phase


def intentional_implementation_contract(node, parents, aliases):
    """Recognize explicit container, extension, borrowed-resource, and null-IO contracts."""
    return (
        click_group_container(node, parents, aliases)
        or _method_contract(node, parents)
        or _borrowed_resource_contract(node, parents)
        or _null_io_contract(node, parents, aliases)
    )


def _borrowed_resource_contract(node, parents):
    owner = parents.get(node)
    if not isinstance(owner, ast.ClassDef) or owner.decorator_list:
        return False
    if node.name != "__exit__" or node.decorator_list:
        return False
    if _borrowed_method(owner, "__exit__") is not node:
        return False
    body = node.body[1:] if ast.get_docstring(node) is not None else node.body
    if len(body) != 1 or not isinstance(body[0], ast.Pass):
        return False
    methods = {
        name: _borrowed_method(owner, name)
        for name in ("__init__", "__enter__", "__getattr__")
    }
    if any(method is None or method.decorator_list for method in methods.values()):
        return False
    if not _borrowed_owner_documented(owner):
        return False
    return _borrowed_shape(methods, owner, parents)


def _borrowed_owner_documented(owner):
    """Require explicit, coherent owner intent; documentation alone is insufficient."""
    doc = " ".join((ast.get_docstring(owner) or "").casefold().split())
    unfinished = ("todo", "tbd", "not implemented", "not yet implemented")
    contradiction = (
        "must close on exit",
        "must be closed on exit",
        "close on exit",
        "closed on exit",
        "close it when exiting",
        "will close on exit",
    )
    borrowed = "borrowed" in doc and any(
        word in doc for word in ("resource", "file", "stream", "handle")
    )
    no_close = any(
        phrase in doc
        for phrase in (
            "does not close",
            "doesn't close",
            "not close",
            "remains open",
            "remain open",
            "keep it open",
            "keep open",
            "stay open",
        )
    )
    return (
        borrowed
        and no_close
        and not any(marker in doc for marker in unfinished + contradiction)
    )


def _borrowed_shape(methods, owner, parents):
    init, enter, delegated = (
        methods[name] for name in ("__init__", "__enter__", "__getattr__")
    )
    field = _borrowed_constructor_shape(init)
    return (
        field is not None
        and _borrowed_enter_shape(init, enter)
        and _borrowed_delegation_shape(init, delegated, owner, parents, field)
    )


def _borrowed_constructor_shape(init):
    body = init.body[1:] if ast.get_docstring(init) is not None else init.body
    if len(body) != 1 or not isinstance(body[0], (ast.Assign, ast.AnnAssign)):
        return False
    assignment = body[0]
    targets = (
        assignment.targets
        if isinstance(assignment, ast.Assign)
        else [assignment.target]
    )
    if len(targets) != 1 or not isinstance(targets[0], ast.Attribute):
        return False
    receiver, value = targets[0].value, assignment.value
    parameters = init.args.posonlyargs + init.args.args + init.args.kwonlyargs
    if not parameters or not isinstance(receiver, ast.Name):
        return False
    if (
        receiver.id != parameters[0].arg
        or not isinstance(value, ast.Name)
        or value.id not in {arg.arg for arg in parameters[1:]}
    ):
        return None
    return targets[0].attr


def _borrowed_enter_shape(init, enter):
    init_args = init.args.posonlyargs + init.args.args
    if not init_args or not enter.args.args or len(enter.body) != 1:
        return False
    receiver = init_args[0].arg
    returned = enter.body[0].value if isinstance(enter.body[0], ast.Return) else None
    return (
        isinstance(returned, ast.Name)
        and returned.id == receiver == enter.args.args[0].arg
    )


def _borrowed_delegation_shape(init, delegated, owner, parents, field):
    init_args = init.args.posonlyargs + init.args.args
    getter_args = delegated.args.posonlyargs + delegated.args.args
    if not init_args or len(getter_args) < 2 or len(delegated.body) != 1:
        return False
    receiver = init_args[0].arg
    returned = (
        delegated.body[0].value if isinstance(delegated.body[0], ast.Return) else None
    )
    if not isinstance(returned, ast.Call) or not _borrowed_getattr_is_builtin(
        delegated, owner, parents
    ):
        return False
    if (
        not isinstance(returned.func, ast.Name)
        or returned.func.id != "getattr"
        or returned.keywords
        or len(returned.args) != 2
    ):
        return False
    resource, attribute = returned.args
    return (
        isinstance(resource, ast.Attribute)
        and isinstance(resource.value, ast.Name)
        and resource.value.id == receiver == getter_args[0].arg
        and resource.attr == field
        and isinstance(attribute, ast.Name)
        and attribute.id == getter_args[1].arg
    )


def _borrowed_method(owner, name):
    methods = [
        item
        for item in owner.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.name == name
    ]
    if (
        len(methods) != 1
        or not isinstance(methods[0], ast.FunctionDef)
        or any(
            _scope_statement_binds_name(statement, name)
            for statement in owner.body
            if statement is not methods[0]
        )
    ):
        return None
    return methods[0]


def _borrowed_getattr_is_builtin(method, owner, parents):
    if _scope_binds_name(method, "getattr"):
        return False
    scope = parents.get(owner)
    while scope is not None:
        if isinstance(scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)):
            if _scope_binds_name(scope, "getattr"):
                return False
        scope = parents.get(scope)
    return True


def _scope_binds_name(scope, name):
    if (
        isinstance(scope, ast.Module)
        and name == "getattr"
        and any(
            _function_rebinds_module_getattr(item)
            for item in ast.walk(scope)
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
    ):
        return True
    arguments = getattr(scope, "args", None)
    if arguments and (
        any(
            arg.arg == name
            for arg in arguments.posonlyargs + arguments.args + arguments.kwonlyargs
        )
        or (arguments.vararg is not None and arguments.vararg.arg == name)
        or (arguments.kwarg is not None and arguments.kwarg.arg == name)
    ):
        return True
    return any(_scope_statement_binds_name(statement, name) for statement in scope.body)


def _scope_statement_binds_name(statement, name):
    """Find bindings in one lexical scope, including nested control-flow suites."""
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return statement.name == name
    for item in _walk_scope_nodes(statement):
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if item.name == name:
                return True
            continue
        if isinstance(item, (ast.Import, ast.ImportFrom)) and any(
            (alias.asname or alias.name.split(".")[0]) == name
            or alias.name == "*"
            and name == "getattr"
            for alias in item.names
        ):
            return True
        if (
            isinstance(item, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar))
            and item.name == name
            or isinstance(item, ast.MatchMapping)
            and item.rest == name
        ):
            return True
        if (
            isinstance(item, ast.Name)
            and isinstance(item.ctx, (ast.Store, ast.Del))
            and item.id == name
        ):
            return True
    return False


def _function_rebinds_module_getattr(function):
    return any(
        isinstance(item, ast.Global) and "getattr" in item.names
        for statement in function.body
        for item in _walk_scope_nodes(statement)
    ) and _scope_binds_name(function, "getattr")


def _walk_scope_nodes(root):
    """Walk a scope's statements without entering nested lexical scopes."""
    pending = [root]
    while pending:
        item = pending.pop()
        yield item
        if isinstance(
            item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        pending.extend(reversed(list(ast.iter_child_nodes(item))))


def _null_io_contract(node, parents, aliases):
    """Recognize an inert IO implementation by its complete local behavior.

    Neither the class name nor an isolated pass/zero return is sufficient.
    """
    owner = parents.get(node)
    if not isinstance(owner, ast.ClassDef) or owner.decorator_list:
        return False
    if node.decorator_list or not _stable_api_origin(
        owner, parents, aliases, {"typing", "typing.IO"}
    ):
        return False
    if node.name not in {"close", "flush", "writelines", "__exit__"}:
        return False
    body = node.body[1:] if ast.get_docstring(node) is not None else node.body
    if len(body) != 1 or not isinstance(body[0], ast.Pass):
        return False
    bases = [
        base.value if isinstance(base, ast.Subscript) else base for base in owner.bases
    ]
    if len(bases) != 1 or not _typing_io_base(bases[0], aliases):
        return False
    methods = [n for n in owner.body if isinstance(n, ast.FunctionDef)]
    names = {n.name: n for n in methods}
    if len(names) != len(methods) or "__init__" in names:
        return False
    if any(
        isinstance(n, ast.Attribute) and isinstance(n.ctx, (ast.Store, ast.Del))
        for n in ast.walk(owner)
    ):
        return False
    required = {
        "readable": False,
        "writable": False,
        "seekable": False,
        "read": "",
        "readline": "",
        "write": 0,
    }
    return all(
        _literal_method(names.get(name), value) for name, value in required.items()
    )


def _typing_io_base(base, aliases):
    if isinstance(base, ast.Name):
        return aliases.get(base.id) == "typing.IO"
    return (
        isinstance(base, ast.Attribute)
        and base.attr == "IO"
        and isinstance(base.value, ast.Name)
        and aliases.get(base.value.id) == "typing"
    )


def _literal_method(node, expected):
    if node is None or node.decorator_list:
        return False
    body = node.body[1:] if ast.get_docstring(node) is not None else node.body
    return (
        len(body) == 1
        and isinstance(body[0], ast.Return)
        and isinstance(body[0].value, ast.Constant)
        and type(body[0].value.value) is type(expected)
        and body[0].value.value == expected
    )


def _method_contract(node, parents):
    owner = parents.get(node)
    if not isinstance(owner, ast.ClassDef):
        return False
    body = node.body[1:] if ast.get_docstring(node) is not None else node.body
    if len(body) != 1:
        return False
    documentation = " ".join((ast.get_docstring(node) or "").lower().split())
    if isinstance(body[0], ast.Pass):
        return "nothing by default" in documentation and "overrid" in documentation
    if not isinstance(body[0], ast.Raise):
        return False
    error = body[0].exc
    error = error.func if isinstance(error, ast.Call) else error
    if not isinstance(error, ast.Name) or error.id != "NotImplementedError":
        return False
    scope = parents.get(owner)
    if (
        not isinstance(scope, ast.Module)
        or _shadowed_error(scope)
        or owner.decorator_list
    ):
        return False
    if any(
        isinstance(item, ast.Call)
        and isinstance(item.func, ast.Name)
        and item.func.id == owner.name
        for item in ast.walk(scope)
    ):
        return False
    if "subclasses must override" in documentation or (
        "must be implemented" in documentation and "subclasses" in documentation
    ):
        return True
    return _local_override(owner, node.name, scope)


def _shadowed_error(scope):
    return any(
        (
            isinstance(item, ast.Name)
            and isinstance(item.ctx, (ast.Store, ast.Del))
            and item.id == "NotImplementedError"
        )
        or (
            isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and item.name == "NotImplementedError"
        )
        or (
            isinstance(item, ast.alias)
            and (item.asname or item.name.split(".")[0]) == "NotImplementedError"
        )
        or (isinstance(item, ast.arg) and item.arg == "NotImplementedError")
        for item in ast.walk(scope)
    )


def _local_override(owner, method, scope):
    # Require an unambiguous local base binding and a non-stub override.
    if (
        sum(isinstance(n, ast.ClassDef) and n.name == owner.name for n in scope.body)
        != 1
    ):
        return False
    if any(
        isinstance(n, ast.Name)
        and isinstance(n.ctx, (ast.Store, ast.Del))
        and n.id == owner.name
        for n in ast.walk(scope)
    ):
        return False
    return any(
        isinstance(child, ast.ClassDef)
        and any(
            isinstance(base, ast.Name) and base.id == owner.name for base in child.bases
        )
        and any(
            isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
            and function.name == method
            and _concrete_contract_method(function)
            for function in child.body
        )
        for child in scope.body
    )


def click_group_container(node, parents, aliases):
    """Recognize a default Click group with a statically registered child.

    This proves a container role, not that callbacks execute or commands work.
    Custom group implementations and invocation modes remain unverified.
    """
    if not node.decorator_list:
        return False
    if not _stable_api_origin(node, parents, aliases, {"click", "click.group"}):
        return False
    scope = parents.get(node)
    if not isinstance(scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    definitions = {
        item.name: item
        for item in scope.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if not _stable_scope(scope, {node.name, *aliases, *definitions}, definitions):
        return False
    if not _recognized_group(node, definitions, aliases, set()):
        return False
    return any(
        isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and isinstance(decorator.func.value, ast.Name)
        and decorator.func.value.id == node.name
        and decorator.func.attr in {"command", "group"}
        for function in definitions.values()
        if function is not node
        for decorator in function.decorator_list
    )


def _stable_scope(scope, names, definitions):
    # A redefinition or assignment makes decorator ownership ambiguous.
    for statement in scope.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if (
                statement.name in names
                and definitions.get(statement.name) is not statement
            ):
                return False
            continue
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            continue
        if any(
            isinstance(item, (ast.Name, ast.Attribute))
            and isinstance(item.ctx, (ast.Store, ast.Del))
            and (
                item.id
                if isinstance(item, ast.Name)
                else ast.unparse(item).split(".")[0]
            )
            in names
            for item in ast.walk(statement)
        ):
            return False
    return True


def _recognized_group(function, definitions, aliases, visiting):
    if function.name in visiting or len(function.decorator_list) != 1:
        return False
    visiting = visiting | {function.name}
    return any(
        _group_decorator(d, definitions, aliases, visiting)
        for d in function.decorator_list
    )


def _group_decorator(decorator, definitions, aliases, visiting):
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(decorator, ast.Call) and (
        decorator.args
        or any(
            keyword.arg not in {"help", "short_help"}
            or not isinstance(keyword.value, ast.Constant)
            or not isinstance(keyword.value.value, str)
            for keyword in decorator.keywords
        )
    ):
        return False
    if isinstance(target, ast.Name):
        return aliases.get(target.id) == "click.group"
    if not isinstance(target, ast.Attribute) or target.attr != "group":
        return False
    if not isinstance(target.value, ast.Name):
        return False
    owner = target.value.id
    if aliases.get(owner) == "click":
        return True
    return owner in definitions and _recognized_group(
        definitions[owner], definitions, aliases, visiting
    )


def bind_project_contracts(root, snapshots, contexts, edges):
    """Resolve direct local imported bases from the already hash-bound snapshots."""
    from .review_audits import _oracle_imports

    indexes = {path: _stable_import_index(tree) for path, tree in snapshots.items()}
    eligible = {p.resolve(): p for p in snapshots}
    resolved = {
        path: _oracle_imports(root, path, tree, eligible)
        for path, tree in snapshots.items()
    }
    blocked = _unsafe_project_bases(snapshots, resolved, indexes)
    for path, tree in snapshots.items():
        imports, index = resolved[path], indexes[path]
        _bind_file_contracts(
            root, path, tree, imports, snapshots, contexts, edges, blocked, index
        )


def _bind_file_contracts(
    root, path, tree, imports, snapshots, contexts, edges, blocked, index=None
):
    index = _stable_import_index(tree) if index is None else index
    for child in (n for n in tree.body if isinstance(n, ast.ClassDef)):
        if child.decorator_list:
            continue
        for base in child.bases:
            if not isinstance(base, ast.Name) or base.id not in imports:
                continue
            if not _stable_import_contract(tree, base.id, child.lineno, index):
                continue
            source, symbol = imports[base.id]
            if (
                symbol is not None
                and source in snapshots
                and (source, symbol) not in blocked
            ):
                _bind_imported_base(
                    root,
                    path,
                    child,
                    source,
                    symbol,
                    snapshots[source],
                    contexts,
                    edges,
                )


def _bind_imported_base(root, path, child, source, symbol, tree, contexts, edges):
    bases = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == symbol]
    if len(bases) != 1 or bases[0].decorator_list or _shadowed_error(tree):
        return
    if not _stable_base_contract(tree, bases[0]):
        return
    if any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == symbol
        for n in ast.walk(tree)
    ):
        return
    if any(
        isinstance(n, ast.Name)
        and isinstance(n.ctx, (ast.Store, ast.Del))
        and n.id == symbol
        for n in ast.walk(tree)
    ):
        return
    methods = {
        n.name: n
        for n in child.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for method in bases[0].body:
        if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        override = methods.get(method.name)
        if not _declared_stub_method(method) or not _concrete_contract_method(override):
            continue
        if type(method) is not type(override):
            continue
        contexts[source].setdefault("implementation_contract_lines", set()).add(
            method.lineno
        )
        edges.append(
            {
                "caller": path.relative_to(root).as_posix(),
                "target": source.relative_to(root).as_posix(),
                "kind": "implementation_contract",
                "symbol": symbol + "." + method.name,
                "strength": "declared_override",
            }
        )


@_measured_phase("source_index")
def _stable_import_index(tree):
    imports, unstable, module_calls = {}, set(), {}
    for statement in tree.body:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            for alias in statement.names:
                local = alias.asname or alias.name.split(".")[0]
                imports.setdefault(local, []).append(statement.lineno)
    for node in ast.walk(tree):
        _track_import_binding(node, unstable, module_calls)
    return imports, unstable, module_calls


def _track_import_binding(node, unstable, module_calls):
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        unstable.add(node.id)
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        unstable.add(node.name)
    elif isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
        if isinstance(node.value, ast.Name):
            unstable.add(node.value.id)
    elif isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            unstable.add(node.func.id)
        elif isinstance(node.func, ast.Attribute) and isinstance(
            node.func.value, ast.Name
        ):
            module_calls.setdefault(node.func.value.id, set()).add(node.func.attr)


def _stable_import_contract(tree, local, before, index=None):
    imports, unstable, _ = _stable_import_index(tree) if index is None else index
    lines = imports.get(local, ())
    return len(lines) == 1 and lines[0] < before and local not in unstable


def _stable_base_contract(tree, owner):
    return not any(
        (
            isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == owner.name
            and node is not owner
        )
        or (
            isinstance(node, ast.alias)
            and (node.asname or node.name.split(".")[0]) == owner.name
        )
        for node in ast.walk(tree)
    )


def _declared_stub_method(node):
    body = node.body[1:] if ast.get_docstring(node) is not None else node.body
    if len(body) != 1:
        return False
    statement = body[0]
    if isinstance(statement, ast.Raise):
        error = (
            statement.exc.func if isinstance(statement.exc, ast.Call) else statement.exc
        )
        return isinstance(error, ast.Name) and error.id == "NotImplementedError"
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and statement.value.value is Ellipsis
        and node.returns is not None
    )


def _concrete_contract_method(node):
    if node is None or node.decorator_list:
        return False
    body = node.body[1:] if ast.get_docstring(node) is not None else node.body
    if not body or _declared_stub_method(node):
        return False
    nodes = list(_contract_body_nodes(body))
    if any(_placeholder_statement(n) for n in nodes):
        return False
    return any(
        isinstance(n, (ast.Return, ast.Assign, ast.AnnAssign))
        or (isinstance(n, ast.Expr) and isinstance(n.value, (ast.Call, ast.Await)))
        for n in nodes
    )


def _contract_body_nodes(statements):
    for statement in statements:
        if isinstance(
            statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        yield statement
        yield from _contract_body_nodes(ast.iter_child_nodes(statement))


def _placeholder_statement(node):
    if isinstance(node, ast.Raise):
        error = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
        return isinstance(error, ast.Name) and error.id == "NotImplementedError"
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and node.value.value is Ellipsis
    )


def _stable_api_origin(node, parents, aliases, targets):
    roots = {name for name, target in aliases.items() if target in targets}
    if not roots:
        return False
    scopes, parent = [], parents.get(node)
    while parent is not None:
        if isinstance(
            parent, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            scopes.append(parent)
        parent = parents.get(parent)
    for name in roots:
        imports = [
            statement
            for scope in scopes
            for statement in scope.body
            if isinstance(statement, (ast.Import, ast.ImportFrom))
            for alias in statement.names
            if (alias.asname or alias.name.split(".")[0]) == name
        ]
        if len(imports) != 1 or imports[0].lineno >= node.lineno:
            return False
    return not any(
        isinstance(item, ast.Attribute)
        and isinstance(item.ctx, (ast.Store, ast.Del))
        and ast.unparse(item).split(".")[0] in roots
        for scope in scopes
        for item in ast.walk(scope)
    )


def _unsafe_project_bases(snapshots, resolved, indexes=None):
    if indexes is None:
        indexes = {path: _stable_import_index(tree) for path, tree in snapshots.items()}
    blocked = set()
    for path, tree in snapshots.items():
        for local, (source, symbol) in resolved[path].items():
            if symbol is not None:
                if not _stable_import_contract(
                    tree, local, float("inf"), indexes[path]
                ):
                    blocked.add((source, symbol))
                continue
            blocked.update((source, attr) for attr in indexes[path][2].get(local, ()))
    return blocked


class _BoundSourceBytes:
    def __init__(self, root, data, bindings):
        self.root, self.data = root, data
        self.expected = {row["path"]: row["sha256"] for row in bindings}

    def get(self, path):
        """Read source bytes only when they match the original scan identity."""
        from .review_audits import _security_source_bytes, ReviewAuditError, MAX_BYTES
        from .runtime_audit_common import RuntimeAuditError
        from .deep_audit_io import local_file

        relative = path.relative_to(self.root).as_posix()
        expected = self.expected.get(relative)
        if expected is None:
            raise RuntimeAuditError(
                "SOURCE_IDENTITY_MISSING", "Snapshot has no original source identity"
            )
        data = self.data.get(path)
        if data is None:
            if (
                path.is_symlink()
                or local_file(self.root, relative).stat().st_size > MAX_BYTES
            ):
                raise RuntimeAuditError(
                    "SOURCE_BOUNDARY_INVALID", "Snapshot exceeds source boundary"
                )
            data = _security_source_bytes(self.root, relative)
        if len(data) > MAX_BYTES or sha256(data).hexdigest() != expected:
            raise ReviewAuditError(
                "Source changed before snapshot parsing: " + relative
            )
        return data


def bound_snapshots(root, files, data, bindings):
    """Parse only byte snapshots bound to the original source manifest."""
    from .review_audits import _oracle_snapshots

    return _oracle_snapshots(root, files, _BoundSourceBytes(root, data, bindings))
