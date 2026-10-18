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
