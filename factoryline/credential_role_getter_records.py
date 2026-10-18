"""Reject captured record mutation and escapes before URL matcher credit."""

import ast

from .credential_role_getter_consumers import _named


def _record_escape(tree, aliases):
    parents = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    for node in ast.walk(tree):
        if (
            not isinstance(node, ast.Attribute)
            or _named(node, aliases) != "responses.calls"
        ):
            continue
        parent = parents.get(id(node))
        if isinstance(parent, ast.comprehension) and parent.iter is node:
            comprehension = parents.get(id(parent))
            if not _record_iterator_readonly(comprehension, parent, parents):
                return True
            if _returned_record_escape(comprehension, tree, parents):
                return True
            continue
        if not isinstance(parent, ast.Subscript) or parent.value is not node:
            return True
        current = parent
        while isinstance(parents.get(id(current)), (ast.Subscript, ast.Attribute)):
            current = parents[id(current)]
        if not isinstance(current, ast.Attribute) or current.attr != "url":
            return True
        if not isinstance(current.ctx, ast.Load):
            return True
        use = parents.get(id(current))
        if not isinstance(use, ast.Compare):
            return True
    return False


def _record_iterator_readonly(comprehension, generator, parents):
    if not isinstance(generator.target, ast.Name) or not isinstance(
        comprehension, (ast.GeneratorExp, ast.ListComp, ast.SetComp)
    ):
        return False
    name = generator.target.id
    for node in ast.walk(comprehension):
        if (
            not isinstance(node, ast.Name)
            or node.id != name
            or node is generator.target
        ):
            continue
        if node is comprehension.elt:
            continue
        current = parents.get(id(node))
        if not isinstance(current, ast.Attribute) or current.attr != "request":
            return False
        current = parents.get(id(current))
        if (
            not isinstance(current, ast.Attribute)
            or current.attr != "url"
            or not isinstance(current.ctx, ast.Load)
        ):
            return False
        use = parents.get(id(current))
        if not isinstance(use, (ast.Compare, ast.Call, ast.Attribute)):
            return False
    return True


def _returned_record_escape(comprehension, tree, parents):
    current = comprehension
    parent = parents.get(id(current))
    if (
        isinstance(parent, ast.Call)
        and isinstance(parent.func, ast.Name)
        and parent.func.id == "next"
    ):
        current, parent = parent, parents.get(id(parent))
    if not isinstance(parent, ast.Assign) or parent.value is not current:
        return True
    if len(parent.targets) != 1 or not isinstance(parent.targets[0], ast.Name):
        return True
    name = parent.targets[0].id
    for node in ast.walk(tree):
        if (
            not isinstance(node, ast.Name)
            or node.id != name
            or not isinstance(node.ctx, ast.Load)
        ):
            continue
        use = parents.get(id(node))
        if not isinstance(use, ast.Attribute) or use.attr != "request":
            return True
        value = parents.get(id(use))
        if (
            not isinstance(value, ast.Attribute)
            or value.attr != "url"
            or not isinstance(value.ctx, ast.Load)
            or not isinstance(parents.get(id(value)), ast.Compare)
        ):
            return True
    return False
