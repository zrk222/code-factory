"""Lexical-name proof helpers shared by source-role consumer matching."""

import ast


def function_bindings(function, name, audit):
    args = [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]
    args.extend(item for item in (function.args.vararg, function.args.kwarg) if item)
    if any(argument.arg == name for argument in args):
        return None
    from .credential_role_object_identity import binding_statements

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
