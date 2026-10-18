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
