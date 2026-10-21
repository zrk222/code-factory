import ast

DYNAMIC_HOOKS = set(
    "__getattr__ __getattribute__ __setattr__ __delattr__ __dict__ __mro__ __bases__".split()
)

_REFLECTION = set(
    "getattr setattr delattr vars builtins.getattr builtins.setattr builtins.delattr "
    "builtins.vars object.__getattribute__ object.__setattr__ object.__delattr__".split()
)


def unresolved(reason):
    return {"reads": [], "unresolved_reason": reason}


def _receiver(method):
    args = [*method.args.posonlyargs, *method.args.args]
    return args[0].arg if args else None


def _method_mutated(graph, path, method, member):
    receiver = _receiver(method)
    if receiver is None:
        return False
    nodes = list(graph._walk(method))
    if any(
        isinstance(n, ast.Name)
        and n.id == receiver
        and isinstance(n.ctx, (ast.Store, ast.Del))
        or isinstance(n, ast.Attribute)
        and n.attr in {member, "__dict__"}
        and isinstance(n.value, ast.Name)
        and n.value.id == receiver
        and (n.attr == "__dict__" or isinstance(n.ctx, (ast.Store, ast.Del)))
        for n in nodes
    ):
        return True
    return any(
        isinstance(n, ast.Call)
        and graph.audit._resolved_ast_name(n.func, graph.aliases[path]) in _REFLECTION
        and n.args
        and isinstance(n.args[0], ast.Name)
        and n.args[0].id == receiver
        for n in nodes
    )


def _class_refs_mutated(graph, chain, member, methods):
    for path, name, _ in chain:
        for ref_path, node, tail in graph.refs.get(("class", path, name), ()):
            if tail and (
                tail[0] in DYNAMIC_HOOKS
                or (tail[-1] == member or tail[0] in methods)
                and isinstance(node, ast.Attribute)
                and isinstance(node.ctx, (ast.Store, ast.Del))
            ):
                return True
            if not tail and isinstance(node, ast.Name):
                parent = graph.parents.get(id(node))
                if (
                    isinstance(parent, ast.Call)
                    and parent.args
                    and parent.args[0] is node
                    and graph.audit._resolved_ast_name(
                        parent.func, graph.aliases[ref_path]
                    )
                    in _REFLECTION
                ):
                    return True
    return False


def mutated(graph, chain, member, methods):
    return (
        not graph.complete
        or any(
            _method_mutated(graph, path, method, member)
            for path, _, method in methods.values()
        )
        or _class_refs_mutated(graph, chain, member, methods)
    )


def direct_class_reads(graph, chain, member):
    reads, classes = [], [owner for _, _, owner in chain]
    for owner_path, owner_name, _ in chain:
        for use_path, node, tail in graph.refs.get(
            ("class", owner_path, owner_name), ()
        ):
            if tail == (member,):
                if not isinstance(node, ast.Attribute) or not isinstance(
                    node.ctx, ast.Load
                ):
                    return [], "member_write_or_unknown_access"
                reads.append((use_path, node, owner_path, owner_name, None))
            elif tail and tail[0] == member:
                return [], "member_transform_or_unknown_tail"
            elif not tail and isinstance(node, ast.Name):
                parent = graph.parents.get(id(node))
                if not isinstance(parent, ast.ClassDef) or parent not in classes:
                    return [], "class_escape_or_reflection"
    return reads, None


def _one_method_reads(graph, path, name, method, member):
    receiver, reads = _receiver(method), []
    if receiver is None:
        return reads, None
    for node in graph._walk(method):
        if (
            isinstance(node, ast.Name)
            and node.id == receiver
            and isinstance(node.ctx, ast.Load)
        ):
            parent = graph.parents.get(id(node))
            if not isinstance(parent, ast.Attribute) or parent.value is not node:
                return [], "receiver_escape_or_alias"
        if (
            not isinstance(node, ast.Attribute)
            or node.attr != member
            or not isinstance(node.ctx, ast.Load)
        ):
            continue
        if method.decorator_list:
            return [], "decorated_method_access"
        if isinstance(node.value, ast.Name) and node.value.id == receiver:
            reads.append((path, node, path, name, method.name))
    return reads, None


def method_reads(graph, methods, member):
    reads = []
    for path, name, method in methods.values():
        found, reason = _one_method_reads(graph, path, name, method, member)
        if reason:
            return [], reason
        reads.extend(found)
    return reads, None


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
