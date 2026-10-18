"""Conservative declared class origins for alias and instance value-use audits."""

import ast

from .credential_role_scope_bindings import binding_occurrences


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
