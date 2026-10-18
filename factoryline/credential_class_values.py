import ast

from .credential_class_value_flows import (
    DYNAMIC_HOOKS,
    direct_class_reads,
    method_reads,
    mutated,
    unresolved,
)


def _class_chain(graph, path, name):
    chain, seen = [], set()
    while (path, name) not in seen and graph._tick():
        seen.add((path, name))
        tree = graph.trees.get(path)
        if not isinstance(tree, ast.Module):
            return None
        rows = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name]
        owner = rows[0] if len(rows) == 1 else None
        if owner is None or owner.decorator_list or owner.keywords:
            return None
        if any(_class_bindings(s, graph.audit) & DYNAMIC_HOOKS for s in owner.body):
            return None
        chain.append((path, name, owner))
        if not owner.bases:
            return chain
        if len(owner.bases) != 1 or not isinstance(
            owner.bases[0], (ast.Name, ast.Attribute)
        ):
            return None
        ref = graph.resolve(path, tuple(graph.audit._name(owner.bases[0]).split(".")))
        if not ref or ref[0] != "class" or ref[3]:
            return None
        path, name = ref[1], ref[2]
    return None


def _class_bindings(statement, audit):
    names = audit._bound_names(statement)
    if isinstance(
        statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
    ):
        return names
    pending = list(ast.iter_child_nodes(statement))
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        else:
            pending.extend(ast.iter_child_nodes(node))
    return names


def _methods(chain, audit):
    effective = {}
    for path, name, owner in reversed(chain):
        if any(
            _class_bindings(s, audit) & (effective.keys() | {"*"})
            for s in owner.body
            if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            return None
        rows = [
            n
            for n in owner.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        if len({n.name for n in rows}) != len(rows):
            return None
        for method in rows:
            if method.decorator_list and method.name in effective:
                return None
            effective[method.name] = (path, name, method)
    return effective


def source_member(graph, path, class_name, member):
    if not isinstance(member, str) or not member.isidentifier():
        return None
    try:
        chain = _class_chain(graph, path, class_name)
        methods = _methods(chain, graph.audit) if chain else None
        if not chain or methods is None or mutated(graph, chain, member, methods):
            return None
        for owner_path, _, owner in chain:
            bindings = [
                s for s in owner.body if member in _class_bindings(s, graph.audit)
            ]
            if len(bindings) > 1:
                return None
            if not bindings:
                continue
            statement = bindings[0]
            if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
                return None
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            target = next(
                (t for t in targets if isinstance(t, ast.Name) and t.id == member), None
            )
            value = getattr(statement, "value", None)
            if target is None or not isinstance(value, ast.Constant):
                return None
            source_hash = getattr(
                graph.trees[owner_path], "_oracle_source_sha256", None
            )
            return {
                "node": statement,
                "member": member,
                "owner_path": owner_path,
                "owner_class": owner.name,
                "source_sha256": source_hash,
                "line": statement.lineno,
            }
    except Exception:
        return None


def member_reads(graph, path, class_name, member):
    if source_member(graph, path, class_name, member) is None:
        return unresolved("source_member_unresolved")
    chain = _class_chain(graph, path, class_name)
    methods = _methods(chain, graph.audit) if chain else None
    if methods is None or mutated(graph, chain, member, methods):
        return unresolved("member_mutated_or_unknown")
    reads, reason = direct_class_reads(graph, chain, member)
    if reason:
        return unresolved(reason)
    method_rows, reason = method_reads(graph, methods, member)
    if reason:
        return unresolved(reason)
    reads.extend(method_rows)
    if not graph.complete:
        return unresolved("graph_incomplete")
    result = {}
    for use_path, node, owner_path, owner_name, method in reads:
        key = (use_path, node.lineno, node.col_offset, method)
        result[key] = {
            "path": use_path,
            "line": node.lineno,
            "node": node,
            "owner_path": owner_path,
            "owner_class": owner_name,
            "method": method,
        }
    return {"reads": list(result.values()), "unresolved_reason": None}
