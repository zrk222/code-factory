"""Conservative source evidence for intentional implementation containers."""

import ast


def click_group_container(node, parents, aliases):
    """Recognize a default Click group with a statically registered child.

    This proves a container role, not that callbacks execute or commands work.
    Custom group implementations and invocation modes remain unverified.
    """
    if not node.decorator_list:
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
