"""Source-bound lexical branch ordering for native credential consumers."""

import ast


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
