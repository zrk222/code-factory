"""Resolve exact local constructor receivers for getter-use closure."""

import ast

from .credential_role_class_binding import resolve_class
from .credential_role_scope_bindings import binding_occurrences


def exact_receiver_class(path, receiver, index, imports, classes, audit):
    """Resolve a receiver Name from one direct local `name = Class(...)` binding."""
    if (
        not isinstance(receiver, ast.Name)
        or not index.validate(path)
        or path not in index.snapshots
    ):
        return None
    parents = index.parents[path]
    function = _enclosing_function(receiver, parents)
    if function is None:
        return None
    constructor = _local_constructor(receiver, function, parents)
    if constructor is None:
        return None
    class_name = _root_name(constructor.func)
    if class_name is None:
        return None
    class_ref = resolve_class(path, constructor.func, imports, classes)
    if class_ref is None or not _class_binding_is_exact(
        class_ref, constructor.func, path, index, imports, classes, function, parents
    ):
        return None
    chain = _class_chain(index, class_ref, imports, classes, audit)
    if not chain or any(_custom_new(owner) for _, _, owner in chain):
        return None
    return class_ref


def _local_constructor(receiver, function, parents):
    if _has_nested_scope(receiver, function, parents):
        return None
    if receiver.id in _argument_names(function):
        return None
    bindings = binding_occurrences(function.body, receiver.id)
    if len(bindings) != 1 or not isinstance(bindings[0], ast.Name):
        return None
    target = bindings[0]
    statement = parents.get(id(target))
    if (
        not isinstance(statement, ast.Assign)
        or parents.get(id(statement)) is not function
    ):
        return None
    if len(statement.targets) != 1 or statement.targets[0] is not target:
        return None
    constructor = statement.value
    if not isinstance(constructor, ast.Call):
        return None
    class_name = _root_name(constructor.func)
    if class_name is None or class_name in _argument_names(function):
        return None
    if binding_occurrences(function.body, class_name):
        return None
    return constructor


def _class_binding_is_exact(
    class_ref, expression, path, index, imports, classes, function, parents
):
    return bool(
        not _outer_scope_shadows(function, expression, parents)
        and _module_binding_is_exact(
            class_ref, expression, path, index, imports, classes
        )
    )


def _module_binding_is_exact(class_ref, expression, path, index, imports, classes):
    root_name = _root_name(expression)
    if root_name is None:
        return False
    tree = index.snapshots[path]
    rows = binding_occurrences(tree.body, root_name)
    if len(rows) != 1:
        return False
    binding = rows[0]
    resolved = imports.get(path, {}).get(root_name)
    if resolved:
        expected = (
            (resolved[0], expression.attr)
            if isinstance(expression, ast.Attribute)
            else resolved
        )
        return (
            isinstance(binding, (ast.Import, ast.ImportFrom)) and expected == class_ref
        )
    return class_ref == (path, root_name) and classes.get(class_ref) is binding


def _class_chain(index, class_ref, imports, classes, audit):
    from .credential_role_bindings import class_chain

    return class_chain(index, class_ref[0], class_ref[1], imports, classes, audit)


def _custom_new(owner):
    return bool(binding_occurrences(owner.body, "__new__"))


def _enclosing_function(node, parents):
    current = node
    while current is not None:
        current = parents.get(id(current))
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
        if isinstance(current, ast.ClassDef):
            return None
    return None


def _has_nested_scope(node, function, parents):
    current = node
    while current is not function:
        current = parents.get(id(current))
        if current is None or isinstance(
            current,
            (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
        ):
            return True
    return False


def _argument_names(function):
    args = function.args
    result = {arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    if args.vararg:
        result.add(args.vararg.arg)
    if args.kwarg:
        result.add(args.kwarg.arg)
    return result


def _outer_scope_shadows(function, expression, parents):
    root_name = _root_name(expression)
    current = parents.get(id(function))
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if root_name in _argument_names(current):
                return True
            if binding_occurrences(current.body, root_name):
                return True
        current = parents.get(id(current))
    return False


def _root_name(expression):
    if isinstance(expression, ast.Name):
        return expression.id
    if isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
        return expression.value.id
    return None
