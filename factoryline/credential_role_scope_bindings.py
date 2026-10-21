"""Python lexical binding occurrences; nested local scopes do not bind parents."""

import ast

_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _binds(node, name):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name == name
    if isinstance(node, ast.Name):
        return node.id == name and isinstance(node.ctx, (ast.Store, ast.Del))
    if isinstance(node, ast.Import):
        return any((a.asname or a.name.split(".")[0]) == name for a in node.names)
    if isinstance(node, ast.ImportFrom):
        return any(a.name == "*" or (a.asname or a.name) == name for a in node.names)
    if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
        return node.name == name
    return isinstance(node, ast.MatchMapping) and node.rest == name


def binding_occurrences(statements, name):
    found, pending = [], list(statements)
    while pending:
        node = pending.pop()
        if _binds(node, name):
            found.append(node)
        if isinstance(node, _SCOPES):
            continue
        if isinstance(node, _COMPREHENSIONS):
            found.extend(
                n.target
                for n in ast.walk(node)
                if isinstance(n, ast.NamedExpr) and _binds(n.target, name)
            )
            continue
        pending.extend(ast.iter_child_nodes(node))
    return found


def function_bindings(function, name, audit):
    args = [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]
    args.extend(item for item in (function.args.vararg, function.args.kwarg) if item)
    if any(argument.arg == name for argument in args):
        return None

    return binding_statements(function.body, name)


def module_literal_binding(fact, path, index, node, audit):
    if (
        fact.owner != "<module>"
        or fact.source_role != "module_literal"
        or path != index.root / fact.path
    ):
        return False
    tree = index.snapshots[path]
    statements = [item for item in tree.body if fact.member in audit._bound_names(item)]
    if len(statements) != 1 or not isinstance(
        statements[0], (ast.Assign, ast.AnnAssign)
    ):
        return False
    from .credential_role_bindings import _literal_target

    statement = statements[0]
    return bool(
        _literal_target(statement) == fact.member
        and statement.value.value == fact._literal
        and node.id == fact.member
    )


def import_is_stable(path, name, index, audit):
    tree = index.snapshots.get(path)
    if not isinstance(tree, ast.Module):
        return False
    statements = [item for item in tree.body if name in audit._bound_names(item)]
    return len(statements) == 1 and isinstance(
        statements[0], (ast.Import, ast.ImportFrom)
    )


def match_name(fact, path, node, function, index, imports, classes, audit, seen):
    from .credential_role_bindings import matches_fact

    if function is None and module_literal_binding(fact, path, index, node, audit):
        return True
    values = []
    if function is not None:
        from .credential_role_bindings import _scope_assignments

        values = _scope_assignments(function).get(node.id, ())
        bindings = function_bindings(function, node.id, audit)
        if bindings is None:
            return False
        if bindings:
            return bool(
                len(bindings) == len(values) == 1
                and bindings[0] is values[0][0]
                and values[0][0].lineno < node.lineno
                and matches_fact(
                    fact,
                    path,
                    values[0][1],
                    index,
                    imports,
                    classes,
                    audit,
                    (*seen, id(node)),
                )
            )
    if values:
        return False
    imported = imports.get(path, {}).get(node.id)
    if imported and import_is_stable(path, node.id, index, audit):
        return bool(
            fact.owner == "<module>"
            and imported == (index.root / fact.path, fact.member)
        )
    return False


def binding_statements(statements, name):
    return [s for s in statements if binding_occurrences([s], name)]


def declared_origins(path, node, index, imports, classes, seen=()):
    key = (path, id(node))
    if key in seen or len(seen) > 12 or not index.validate(path):
        return set()
    seen = (*seen, key)
    if isinstance(node, ast.Call):
        return declared_origins(path, node.func, index, imports, classes, seen)
    if isinstance(node, ast.Attribute):
        return _imported_attribute(path, node, imports, classes)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict, ast.Subscript)):
        return _container_origins(path, node, index, imports, classes, seen)
    if not isinstance(node, ast.Name):
        return set()
    scope = _scope(node, index.parents[path], index.snapshots[path])
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        args = [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
        args.extend(a for a in (scope.args.vararg, scope.args.kwarg) if a)
        if any(a.arg == node.id for a in args):
            return set()
        statements = _scope_bindings(scope, node.id)
        if statements:
            return _assigned_origins(path, statements, index, imports, classes, seen)
    tree = index.snapshots[path]
    statements = binding_statements(tree.body, node.id)
    origins = _assigned_origins(path, statements, index, imports, classes, seen)
    origins.update(_direct_origins(path, node.id, imports, classes))
    return origins


def _direct_origins(path, name, imports, classes):
    origins = {(path, name)} if (path, name) in classes else set()
    imported = imports.get(path, {}).get(name)
    if imported and imported in classes:
        origins.add(imported)
    return origins


def _imported_attribute(path, node, imports, classes):
    if isinstance(node.value, ast.Name):
        imported = imports.get(path, {}).get(node.value.id)
        if imported and imported[1] is None and (imported[0], node.attr) in classes:
            return {(imported[0], node.attr)}
    return set()


def _assigned_origins(path, statements, index, imports, classes, seen):
    result = set()
    for statement in statements:
        for n in ast.walk(statement):
            if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
                result.update(
                    declared_origins(path, n.value, index, imports, classes, seen)
                )
    return result


def _container_origins(path, node, index, imports, classes, seen):
    values = (
        [node.value]
        if isinstance(node, ast.Subscript)
        else (node.values if isinstance(node, ast.Dict) else node.elts)
    )
    result = set()
    for value in values:
        result.update(declared_origins(path, value, index, imports, classes, seen))
    return result


def _scope_bindings(scope, name):
    suite = scope.body if isinstance(scope.body, list) else [scope.body]
    return binding_statements(suite, name)


def _scope(node, parents, module):
    while node is not None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return node
        node = parents.get(id(node))
    return module


def binding_dominates(binding, use, parents, scope):
    """Prove lexical statement ordering on the same executed branch only."""
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    current = use
    for _ in range(256):
        owner = parents.get(id(current))
        if owner is None:
            return False
        if (
            isinstance(
                owner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
            )
            and owner is not scope
        ):
            return False
        for _, field in ast.iter_fields(owner):
            if isinstance(field, list) and binding in field and current in field:
                if field.index(binding) < field.index(current):
                    return True
        if owner is scope:
            return False
        current = owner
    return False
