"""Check captured constructor and selector providers without executing code."""

import ast
import hashlib
import copy
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from types import FunctionType, MethodType, SimpleNamespace
from contextlib import contextmanager
from .finite_capture import finite_provider_mutation_index
from .review_audits import _resolved_ast_name
from .review_integrity import bind_source_call
from urllib.parse import urlsplit
from functools import partial
from . import (
    finite_capture,
    credential_role_constructor_provider as _constructor_provider,
    finite_capture as _finite_capture,
)

"""Check captured constructor and selector providers without executing code."""


DYNAMIC_HOOKS = set(
    "__getattr__ __getattribute__ __setattr__ __delattr__ __dict__ __mro__ __bases__".split()
)

_REFLECTION = set(
    "getattr setattr delattr vars builtins.getattr builtins.setattr builtins.delattr "
    "builtins.vars object.__getattribute__ object.__setattr__ object.__delattr__".split()
)


def unresolved(reason):
    """Create an unresolved member-read result with no read records and the supplied explanation."""
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
    """Report mutation when the source graph is incomplete or class/member writes and reflective changes are found."""
    return (
        not graph.complete
        or any(
            _method_mutated(graph, path, method, member)
            for path, _, method in methods.values()
        )
        or _class_refs_mutated(graph, chain, member, methods)
    )


def direct_class_reads(graph, chain, member):
    """Collect direct class-member reads across the owner chain; return no reads when writes, transformations, or escapes make access ambiguous."""
    reads, classes = [], [owner for _, _, owner in chain]
    for owner_path, owner_name, _ in chain:
        for use_path, node, tail in graph.refs.get(
            ("class", owner_path, owner_name), ()
        ):
            error = _direct_class_read_error(graph, member, classes, node, tail)
            if error:
                return [], error
            if tail == (member,):
                reads.append((use_path, node, owner_path, owner_name, None))
    return reads, None


def _direct_class_read_error(graph, member, classes, node, tail):
    if tail == (member,):
        if not isinstance(node, ast.Attribute) or not isinstance(node.ctx, ast.Load):
            return "member_write_or_unknown_access"
    elif tail and tail[0] == member:
        return "member_transform_or_unknown_tail"
    elif not tail and isinstance(node, ast.Name):
        parent = graph.parents.get(id(node))
        if not isinstance(parent, ast.ClassDef) or parent not in classes:
            return "class_escape_or_reflection"
    return None


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
    """Collect reads from validated methods and stop with an unresolved reason when any method's access cannot be closed."""
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
    """Locate a literal class-member declaration only when its inheritance chain and methods are unmutated; otherwise return no source fact."""
    if not isinstance(member, str) or not member.isidentifier():
        return None
    try:
        chain = _class_chain(graph, path, class_name)
        methods = _methods(chain, graph.audit) if chain else None
        if methods is None or mutated(graph, chain, member, methods):
            return None
        for owner_path, _, owner in chain:
            binding = _source_member_binding(owner, member, graph.audit)
            if binding is False:
                return None
            if binding is not None:
                return _source_member_fact(graph, owner_path, owner, member, binding)
    except Exception:
        return None


def _source_member_binding(owner, member, audit):
    bindings = [s for s in owner.body if member in _class_bindings(s, audit)]
    if len(bindings) > 1:
        return False
    if not bindings:
        return None
    statement = bindings[0]
    if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
        return False
    targets = (
        statement.targets if isinstance(statement, ast.Assign) else [statement.target]
    )
    target = next(
        (
            target
            for target in targets
            if isinstance(target, ast.Name) and target.id == member
        ),
        None,
    )
    if target is None or not isinstance(
        getattr(statement, "value", None), ast.Constant
    ):
        return False
    return statement


def _source_member_fact(graph, owner_path, owner, member, statement):
    return {
        "node": statement,
        "member": member,
        "owner_path": owner_path,
        "owner_class": owner.name,
        "source_sha256": getattr(
            graph.trees[owner_path], "_oracle_source_sha256", None
        ),
        "line": statement.lineno,
    }


def member_reads(graph, path, class_name, member):
    """Return deduplicated class-member reads only when declaration, mutation analysis, and source graph are complete; otherwise explain the unresolved state."""
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


def _class_binding_statements(owner, name):
    return binding_occurrences(owner.body, name)


def effective_method(chain, name, allowed_decorators=()):
    """Return the first effective inherited method with exactly the permitted decorator set."""
    allowed = set(allowed_decorators)
    for path, _, owner in chain:
        bindings = _class_binding_statements(owner, name)
        if not bindings:
            continue
        rows = [
            node
            for node in owner.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ]
        if len(bindings) != 1 or len(rows) != 1 or bindings[0] is not rows[0]:
            return None
        row = rows[0]
        if not _method_decorators_allowed(row, allowed):
            return None
        return path, row
    return None


def _method_decorators_allowed(row, allowed):
    decorators = {_decorator_name(item) for item in row.decorator_list}
    if row.decorator_list and (
        any(not isinstance(item, ast.Name) for item in row.decorator_list)
        or None in decorators
        or decorators != allowed
    ):
        return False
    return not (decorators - allowed)


def _decorator_name(node):
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def class_attribute(chain, name):
    """Resolve a unique simple class attribute from the first class in the inheritance chain that binds it."""
    for path, _, owner in chain:
        bindings = _class_binding_statements(owner, name)
        if not bindings:
            continue
        rows = _class_attribute_values(owner, name)
        if len(bindings) != 1 or len(rows) != 1 or not isinstance(rows[0], ast.Name):
            return None
        return path, rows[0]
    return None


def _class_attribute_values(owner, name):
    values = []
    for statement in owner.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
        )
        if any(
            isinstance(target, ast.Name) and target.id == name for target in targets
        ):
            values.append(statement.value)
    return values


def resolve_class(path, expression, imports, classes):
    """Resolve a class name or one-level imported class attribute from the current source and import maps."""
    if isinstance(expression, ast.Name):
        imported = imports.get(path, {}).get(expression.id)
        if imported:
            return imported if imported[1] else None
        return (path, expression.id) if (path, expression.id) in classes else None
    if isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
        imported = imports.get(path, {}).get(expression.value.id)
        if imported and imported[1] is None:
            return imported[0], expression.attr
    return None


def scope_class(node, index, path):
    """Find the nearest enclosing class node through the validated parent map."""
    current = node
    while current is not None:
        current = index.parents[path].get(id(current))
        if isinstance(current, ast.ClassDef):
            return current
    return None


def instance_receiver(node, function, owner, index, path):
    """Only bind self.FIELD in a direct, unshadowed instance method."""
    if function is None or owner is None:
        return False
    parents = index.parents[path]
    if parents.get(id(function)) is not owner:
        return False
    return _direct_instance_method(node, function, parents)


def _direct_instance_method(node, function, parents):
    args = function.args
    positional = [*args.posonlyargs, *args.args]
    if not positional or positional[0].arg != "self":
        return False
    if function.decorator_list or binding_occurrences(function.body, "self"):
        return False
    return _node_in_instance_body(node, function, parents) and not _self_keyword_bound(
        args
    )


def _node_in_instance_body(node, function, parents):
    current = node
    while current is not function:
        current = parents.get(id(current))
        if current is None or isinstance(current, _COMPREHENSIONS + (ast.Lambda,)):
            return False
    return True


def _self_keyword_bound(args):
    return any(item.arg == "self" for item in args.kwonlyargs) or bool(
        (args.vararg and args.vararg.arg == "self")
        or (args.kwarg and args.kwarg.arg == "self")
    )


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
    """Collect name bindings while respecting nested scopes and named-expression targets in comprehensions."""
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


def function_bindings(function, name, audit):
    """Return local binding statements unless a function parameter already shadows the requested name."""
    args = [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]
    args.extend(item for item in (function.args.vararg, function.args.kwarg) if item)
    if any(argument.arg == name for argument in args):
        return None

    return binding_statements(function.body, name)


def module_literal_binding(fact, path, index, node, audit):
    """Confirm that a source fact is the unique matching module-level literal declaration and that the name refers to it."""
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
    from .credential_role_constructor_provider import _literal_target

    statement = statements[0]
    return bool(
        _literal_target(statement) == fact.member
        and statement.value.value == fact._literal
        and node.id == fact.member
    )


def import_is_stable(path, name, index, audit):
    """Confirm a name has exactly one top-level import binding."""
    tree = index.snapshots.get(path)
    if not isinstance(tree, ast.Module):
        return False
    statements = [item for item in tree.body if name in audit._bound_names(item)]
    return len(statements) == 1 and isinstance(
        statements[0], (ast.Import, ast.ImportFrom)
    )


def match_name(fact, path, node, function, index, imports, classes, audit, seen):
    """Match a source fact through module literals, local aliases, or stable imports, returning false for rebinding or ambiguity."""
    if function is None and module_literal_binding(fact, path, index, node, audit):
        return True
    local = _local_fact_match(
        fact, path, node, function, index, imports, classes, audit, seen
    )
    if local is not None:
        return local
    if function is not None and _scope_assignments_for(function, node.id):
        return False
    return _imported_fact_match(fact, path, node.id, index, imports, audit)


def _scope_assignments_for(function, name):
    from .credential_role_constructor_provider import _scope_assignments

    return _scope_assignments(function).get(name, ())


def _local_fact_match(fact, path, node, function, index, imports, classes, audit, seen):
    if function is None:
        return None
    from .credential_role_constructor_provider import matches_fact

    values = _scope_assignments_for(function, node.id)
    bindings = function_bindings(function, node.id, audit)
    if bindings is None:
        return False
    if not bindings:
        return None
    return bool(
        len(bindings) == len(values) == 1
        and bindings[0] is values[0][0]
        and values[0][0].lineno < node.lineno
        and matches_fact(
            fact, path, values[0][1], index, imports, classes, audit, (*seen, id(node))
        )
    )


def _imported_fact_match(fact, path, name, index, imports, audit):
    imported = imports.get(path, {}).get(name)
    return bool(
        imported
        and import_is_stable(path, name, index, audit)
        and fact.owner == "<module>"
        and imported == (index.root / fact.path, fact.member)
    )


def binding_statements(statements, name):
    """Return top-level statements that bind the requested name."""
    return [s for s in statements if binding_occurrences([s], name)]


def declared_origins(path, node, index, imports, classes, seen=()):
    """Resolve declared class origins through local and imported bindings."""
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
    return _name_origins(path, node, index, imports, classes, seen)


def _name_origins(path, node, index, imports, classes, seen):
    scope = _scope_scope_bindings(node, index.parents[path], index.snapshots[path])
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


def _scope_scope_bindings(node, parents, module):
    while node is not None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return node
        node = parents.get(id(node))
    return module


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
        if _binding_precedes_sibling(binding, current, owner):
            return True
        if owner is scope:
            return False
        current = owner
    return False


def _binding_precedes_sibling(binding, use, owner):
    return any(
        isinstance(field, list)
        and binding in field
        and use in field
        and field.index(binding) < field.index(use)
        for _, field in ast.iter_fields(owner)
    )


class SourceSnapshotIndex:
    """Lazily bind used ASTs to producer-owned source bytes and inventory hashes."""

    def __init__(self, root, snapshots, source_bytes, inventory):
        self.root = Path(root)
        self.snapshots, self.source_bytes, self.inventory = (
            snapshots,
            source_bytes,
            inventory,
        )
        self.validated, self.parents = {}, {}
        self._validation_inputs = {}
        self._relative_root, self._relative_paths = self.root, {}
        self.bounded = (
            isinstance(inventory, dict)
            and set(snapshots) == set(source_bytes) == set(inventory)
            and len(snapshots) <= 2000
            and all(isinstance(raw, bytes) for raw in source_bytes.values())
            and sum(len(raw) for raw in source_bytes.values()) <= 32 * 1024 * 1024
        )

    def validate(self, path):
        """Validate captured source bytes against the snapshot digest and AST, enforcing the one-megabyte source limit."""
        tree, raw = self.snapshots.get(path), self.source_bytes.get(path)
        signature = (
            self.inventory.get(path),
            getattr(tree, "_oracle_source_sha256", None),
        )
        cached = self._validation_inputs.get(path)
        if cached and cached[0] is tree and cached[1] is raw and cached[2] == signature:
            return self.validated[path]
        digest = hashlib.sha256(raw).hexdigest() if isinstance(raw, bytes) else None
        valid = self._matches_snapshot(path, tree, raw, digest)
        self.validated[path] = valid
        self._validation_inputs[path] = tree, raw, signature
        self.parents.pop(path, None)
        if valid:
            self.parents[path] = {
                id(child): node
                for node in ast.walk(tree)
                for child in ast.iter_child_nodes(node)
            }
        return valid

    def _matches_snapshot(self, path, tree, raw, digest):
        if not (
            self.bounded
            and isinstance(tree, ast.Module)
            and isinstance(raw, bytes)
            and len(raw) <= 1_000_000
            and self.inventory.get(path) == digest
            and getattr(tree, "_oracle_source_sha256", None) == digest
        ):
            return False
        return _ast_matches_source(raw, tree)

    def relative(self, path):
        """Return a source-relative POSIX path only when the path is inside the snapshot root."""
        try:
            candidate = Path(path)
            if self._relative_root != self.root:
                self._relative_root, self._relative_paths = self.root, {}
            if candidate in self._relative_paths:
                return self._relative_paths[candidate]
            relative = candidate.relative_to(self.root).as_posix()
            if candidate in self.snapshots:
                self._relative_paths[candidate] = relative
            return relative
        except (ValueError, TypeError):
            return None

    def module_paths(self):
        """Index regular-package roots; ambiguous aliases stay unresolved locally."""
        paths = {self.relative(path): path for path in self.snapshots}
        if None in paths or not self.bounded:
            return None
        for path in self.snapshots:
            directory = path.parent
            package_root = None
            while (
                directory != self.root and (directory / "__init__.py") in self.snapshots
            ):
                if not self.validate(directory / "__init__.py"):
                    return None
                package_root = directory.parent
                directory = directory.parent
            if package_root is None:
                continue
            alias = path.relative_to(package_root).as_posix()
            if alias in paths and paths[alias] != path:
                paths[alias] = None
            else:
                paths[alias] = path
        return paths


def source_session_factories(tree, aliases):
    """Find top-level functions that create and return the same requests.Session local name."""
    from .security_configuration import _canonical

    rows = {}
    for function in tree.body:
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _returns_created_session(function, aliases, _canonical):
                rows[function.name] = {"requests.Session"}
    return {name for name, values in rows.items() if values == {"requests.Session"}}


def _returns_created_session(function, aliases, canonical):
    assigned, returned = [], []
    for statement in ast.walk(function):
        _record_session_assignment(statement, aliases, canonical, assigned)
        if isinstance(statement, ast.Return) and isinstance(statement.value, ast.Name):
            returned.append(statement.value.id)
    return len(assigned) == len(returned) == 1 and assigned == returned


def _record_session_assignment(statement, aliases, canonical, assigned):
    if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
        return
    targets = (
        statement.targets if isinstance(statement, ast.Assign) else [statement.target]
    )
    if (
        len(targets) == 1
        and isinstance(targets[0], ast.Name)
        and isinstance(statement.value, ast.Call)
        and canonical(statement.value, aliases) == "requests.Session"
    ):
        assigned.append(targets[0].id)


@dataclass(frozen=True)
class DeclarationFact:
    path: str
    member: str
    owner: str
    source_role: str
    source_sha256: str
    value_sha256: str
    line: int
    column: int
    end_line: int
    end_column: int
    _literal: str = dataclass_field(repr=False)

    def public_facts(self):
        """Expose allowlisted declaration provenance fields while omitting literal values."""
        return {
            key: getattr(self, key)
            for key in (
                "path",
                "member",
                "owner",
                "source_role",
                "source_sha256",
                "value_sha256",
                "line",
                "column",
                "end_line",
                "end_column",
            )
        }


def declaration_fact(index, path, node):
    """Bind one direct string assignment to its exact source span and hash."""
    if not _valid_literal_assignment(index, path, node):
        return None
    target, value = _assignment_target(node), node.value
    member = _target_member(target)
    if member is None:
        return None
    owner, source_role = _declaration_role(index, path, node, target)
    return _fact(index, path, node, member, owner, source_role, value.value)


def _valid_literal_assignment(index, path, node):
    return bool(
        index.validate(path)
        and isinstance(node, (ast.Assign, ast.AnnAssign))
        and len(node.targets if isinstance(node, ast.Assign) else [node.target]) == 1
        and isinstance(getattr(node, "value", None), ast.Constant)
        and isinstance(node.value.value, str)
    )


def _assignment_target(node):
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return targets[0]


def _target_member(target):
    if isinstance(target, ast.Name):
        return target.id
    if (
        isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Name)
        and target.value.id == "self"
    ):
        return target.attr
    return None


def _declaration_role(index, path, node, target):
    current = index.parents[path].get(id(node))
    function = owner = None
    direct = True
    while current is not None:
        if (
            isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef))
            and function is None
        ):
            function = current
            direct = index.parents[path].get(id(node)) is current
        if isinstance(current, ast.ClassDef) and owner is None:
            owner = current
        current = index.parents[path].get(id(current))
    if function is not None:
        if isinstance(target, ast.Attribute) and owner is not None:
            role = "instance_literal" if direct else "conditional_instance_literal"
            return owner.name, role
        return f"<local:{function.name}>", "local_literal"
    if owner is not None:
        direct = index.parents[path].get(id(node)) is owner
        role = "class_literal" if direct else "conditional_class_literal"
        return owner.name, role
    direct = index.parents[path].get(id(node)) is index.snapshots[path]
    return "<module>", "module_literal" if direct else "conditional_module_literal"


def _fact(index, path, node, member, owner, source_role, value):
    raw = index.source_bytes[path]
    source_hash = hashlib.sha256(raw).hexdigest()
    value_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
    relative = index.relative(path)
    if relative is None:
        return None
    return DeclarationFact(
        relative,
        member,
        owner,
        source_role,
        source_hash,
        value_hash,
        node.lineno,
        node.col_offset,
        getattr(node, "end_lineno", node.lineno),
        getattr(node, "end_col_offset", node.col_offset),
        value,
    )


def _presentation_provider_facts(tree, nodes, parents, audit):
    """Index canonical provider changes once, including nested import aliases."""
    aliases = audit._module_security_aliases(tree)
    mutation_aliases, mutations = dict(aliases), set()
    for node in nodes:
        if isinstance(node, (ast.Import, ast.ImportFrom)) and node not in tree.body:
            for name, canonical in audit._module_security_aliases(
                ast.Module(body=[node], type_ignores=[])
            ).items():
                prior = mutation_aliases.get(name)
                if prior is not None and prior != canonical:
                    mutations.update(((prior, "*"), (canonical, "*")))
                else:
                    mutation_aliases[name] = canonical
    mutations.update(
        finite_provider_mutation_index(nodes, mutation_aliases, audit, parents)
    )
    if any(
        audit._resolved_ast_name(node, mutation_aliases) == "sys.modules"
        for node in nodes
        if isinstance(node, ast.Attribute)
    ):
        mutations.add(("sys.modules", "*"))
    star_imports = any(
        isinstance(node, ast.ImportFrom)
        and any(alias.name == "*" for alias in node.names)
        for node in nodes
    )
    return aliases, mutations, star_imports


def _presentation_provider_shadow(expression, name, source, path, audit):
    """An enclosing lexical binder prevents credit for a module import."""
    current, parents = expression, source.parents[path]
    while (current := parents.get(id(current))) is not None:
        if (
            isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef))
            and function_bindings(current, name, audit) != []
        ):
            return True
        if isinstance(current, ast.ClassDef) and binding_occurrences(
            current.body, name
        ):
            return True
        if isinstance(
            current,
            (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
        ) and any(
            isinstance(item, ast.arg)
            and item.arg == name
            or isinstance(item, ast.Name)
            and item.id == name
            and isinstance(item.ctx, (ast.Store, ast.Del))
            for item in ast.walk(current)
        ):
            return True
    return False


class PresentationRoleIndex:
    """Bounded captured uses under schema-annotation and masking API profiles."""

    def __init__(self, source, imports, audit):
        self.source, self.imports, self.audit = source, imports, audit
        self.classes = {
            (path, node.name): node
            for path, tree in source.snapshots.items()
            for node in tree.body
            if isinstance(node, ast.ClassDef)
        }
        self.complete = source.bounded and all(
            source.validate(path) for path in source.snapshots
        )
        self.references, self.reflected_members = {}, set()
        self.reflective_paths, self.calls = set(), []
        self.provider_aliases, self.provider_mutations = {}, set()
        self.star_imports = False
        self._data_paths = source.module_paths() if self.complete else None
        for path, tree in source.snapshots.items() if self.complete else ():
            nodes = list(ast.walk(tree))
            aliases, mutations, star = _presentation_provider_facts(
                tree, nodes, source.parents[path], audit
            )
            self.provider_aliases[path] = aliases
            self.provider_mutations.update(mutations)
            self.star_imports = self.star_imports or star
            for node in nodes:
                if isinstance(node, (ast.Name, ast.Attribute)):
                    name = node.id if isinstance(node, ast.Name) else node.attr
                    self.references.setdefault(name, []).append((path, node))
                    if name in {
                        "getattr",
                        "setattr",
                        "delattr",
                        "vars",
                        "__getattribute__",
                        "__dict__",
                    }:
                        self.reflective_paths.add(path)
                if (
                    isinstance(node, ast.ImportFrom)
                    and node.module == "builtins"
                    and any(
                        alias.name in {"getattr", "setattr", "delattr", "vars"}
                        for alias in node.names
                    )
                ):
                    self.reflective_paths.add(path)
                if isinstance(node, ast.Call):
                    self.calls.append((path, node))
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in {"getattr", "setattr", "delattr"}
                    and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Constant)
                    and isinstance(node.args[1].value, str)
                ):
                    self.reflected_members.add(node.args[1].value)

    def evidence(self, path, node):
        """Classify a declaration as presentation metadata only when source-linked schema or masking uses are proven; runtime and downstream security remain unassessed."""
        fact = declaration_fact(self.source, path, node) if self.complete else None
        if fact is None:
            return {"eligible": False, "reason": "unbound or incomplete declaration"}
        if fact.source_role == "class_literal":
            uses = self._schema_uses(fact)
            profile = "JSON_SCHEMA_ANNOTATION"
        elif fact.source_role == "module_literal":
            uses = self._mask_uses(fact)
            profile = "MASKING_SENTINEL"
            if not uses:
                uses = (
                    None
                    if self._data_reflection_conflict(fact)
                    else self._module_uses(fact, self._data_role)
                )
                profile = "STATIC_API_DATA_ROLE"
        else:
            uses, profile = None, None
        if not uses:
            return {
                "eligible": False,
                "reason": "missing or conflicting demanded value uses",
            }
        return {
            "eligible": True,
            "classification": "PRESENTATION_METADATA_ROLE",
            "profile": profile,
            "declaration": fact.public_facts(),
            "uses": uses,
            "runtime_assurance": "INCOMPLETE",
            "transport_role": "UNASSESSED",
            "target_execution": "not_performed",
            "downstream_consumer_security": "UNASSESSED",
        }

    def _chain(self, path, name):
        from .credential_role_constructor_provider import class_chain

        return class_chain(
            self.source, path, name, self.imports, self.classes, self.audit
        )

    def _schema_uses(self, fact):
        from .credential_role_constructor_provider import _scope
        from .credential_role_constructor_provider import binding_occurrences

        selected = self._chain(self.source.root / fact.path, fact.owner)
        if not selected or not _presentation_literal_matches(
            selected, fact, self.source.root
        ):
            return None
        keys = {(path, name) for path, name, _ in selected}
        uses = []
        if fact.member in self.reflected_members or self._reflection_conflict(
            fact, keys
        ):
            return None
        for path, node in self.references.get(fact.member, ()):
            if (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and path == self.source.root / fact.path
            ):
                return None
            if not isinstance(node, ast.Attribute) or node.attr != fact.member:
                continue
            function, owner = _scope(node, self.source, path)
            if function is None or owner is None or not isinstance(node.ctx, ast.Load):
                return None
            related = self._schema_receiver(path, owner, keys, fact)
            if related is None:
                return None
            if related is False:
                continue
            if (
                not _presentation_class_receiver(
                    node, function, owner, self.source, path
                )
                or binding_occurrences(self.source.snapshots[path].body, "classmethod")
                or not _presentation_schema_title(
                    node, function, self.source.parents[path]
                )
            ):
                return None
            uses.append(self._witness(path, node, "SCHEMA_TITLE"))
        return uses

    def _schema_receiver(self, path, owner, keys, fact):
        chain = self._chain(path, owner.name)
        if not chain:
            return None
        if (path, owner.name) in keys:
            return True
        if not any((p, name) in keys for p, name, _ in chain):
            return None
        return _presentation_literal_matches(chain, fact, self.source.root)

    def _reflection_conflict(self, fact, keys=()):
        from .credential_role_constructor_provider import resolve_class

        for path, call in self.calls:
            if path not in self.reflective_paths or not call.args:
                continue
            selected = resolve_class(path, call.args[0], self.imports, self.classes)
            if selected in keys:
                return True
            if isinstance(call.args[0], ast.Name) and self._namespace_alias(
                path, call.args[0].id, fact
            ):
                return True
        return False

    def _namespace_alias(self, path, name, fact):
        binding = self.imports.get(path, {}).get(name)
        return (
            binding is not None
            and binding[0] == self.source.root / fact.path
            and _presentation_namespace_binding(self.source, path, name, binding)
        )

    def _mask_uses(self, fact):
        uses = self._module_uses(
            fact,
            lambda path, node: _presentation_mask_output(
                node, self.source.parents[path]
            )
            or _presentation_mask_restore(node, self.source.parents[path]),
        )
        return (
            uses
            if uses
            and {row["role"] for row in uses}
            == {"MASK_OUTPUT", "PRESERVE_PREVIOUS_VALUE"}
            else None
        )

    def _module_uses(self, fact, classify):
        """Share exact import/rebinding closure across modeled scalar roles."""
        from .credential_role_constructor_provider import matches_fact

        uses = []
        if fact.member in self.reflected_members or self._reflection_conflict(fact):
            return None
        names = {fact.member}
        for path, view in self.imports.items():
            names.update(
                name
                for name, binding in view.items()
                if binding == (self.source.root / fact.path, fact.member)
                or self._namespace_alias(path, name, fact)
            )
        for path, node in [
            row for name in names for row in self.references.get(name, ())
        ]:
            status = self._mask_reference(fact, path, node)
            if status == "conflict":
                return None
            if status == "ignore":
                continue
            if not (
                _presentation_global_match(
                    fact, path, node, self.source, self.audit, self.imports
                )
                or matches_fact(
                    fact,
                    path,
                    node,
                    self.source,
                    self.imports,
                    self.classes,
                    self.audit,
                )
            ):
                continue
            role = classify(path, node)
            if role is None:
                return None
            uses.append(self._witness(path, node, role))
        return uses

    def _data_reflection_conflict(self, fact):
        """Dynamic namespace access cannot establish complete scalar-use closure."""
        origin = self.source.root / fact.path
        if self.star_imports:
            return True
        for name in (
            "globals",
            "locals",
            "eval",
            "exec",
            "__dict__",
            "__globals__",
            "__getattribute__",
        ):
            for path, node in self.references.get(name, ()):
                if path == origin:
                    return True
                if (
                    isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)
                    and self._namespace_alias(path, node.value.id, fact)
                ):
                    return True
        return False

    def _data_role(self, path, node):
        """Model argument roles, never identifier spelling or test-directory names."""
        parents = self.source.parents[path]
        parent = parents.get(id(node))
        call = parents.get(id(parent)) if isinstance(parent, ast.keyword) else parent
        if (
            not isinstance(call, ast.Call)
            or any(isinstance(arg, ast.Starred) for arg in call.args)
            or any(item.arg is None for item in call.keywords)
        ):
            return None
        aliases = self.provider_aliases[path]
        canonical = self.audit._resolved_ast_name(call.func, aliases)
        # A pattern or cache key can itself confer authentication authority.
        # Those roles require downstream evidence; argument position is insufficient.
        roles = {
            "os.getenv": ("key", "ENVIRONMENT_NAME"),
            "os.environ.get": ("key", "ENVIRONMENT_NAME"),
        }
        selected = roles.get(canonical)
        if selected is None or not self._data_provider_stable(
            path, call.func, canonical
        ):
            return None
        keyword, role = selected
        actuals = [
            *call.args[:1],
            *(kw.value for kw in call.keywords if kw.arg == keyword),
        ]
        return role if len(actuals) == 1 and actuals[0] is node else None

    def _data_provider_stable(self, path, expression, canonical):
        """Reuse provider escape/mutation facts and exact lexical import binding."""
        root = expression
        while isinstance(root, ast.Attribute):
            root = root.value
        if not isinstance(root, ast.Name) or root.id not in self.provider_aliases[path]:
            return False
        if _presentation_provider_shadow(
            expression, root.id, self.source, path, self.audit
        ):
            return False
        if not import_is_stable(path, root.id, self.source, self.audit):
            return False
        paths = self._data_paths
        provider = canonical.split(".")[0]
        if paths is None or any(
            name in paths for name in (provider + ".py", provider + "/__init__.py")
        ):
            return False
        for owner, member in self.provider_mutations:
            changed = owner if member == "*" else owner + "." + member
            # getenv delegates through environ; function mutation and module-table
            # indirection can replace the modeled provider too.
            dependencies = {canonical, "os.environ", "sys.modules"}
            if any(
                dependency == changed
                or dependency.startswith(changed + ".")
                or changed.startswith(dependency + ".")
                for dependency in dependencies
            ):
                return False
        return True

    def _mask_reference(self, fact, path, node):
        if not isinstance(node.ctx, ast.Load):
            if (
                path == self.source.root / fact.path
                and isinstance(node, ast.Name)
                and node.id == fact.member
                and node.lineno != fact.line
            ):
                return "conflict"
            return "ignore"
        if isinstance(node, ast.Name) and self._namespace_alias(path, node.id, fact):
            parent = self.source.parents[path].get(id(node))
            return (
                "ignore"
                if isinstance(parent, ast.Attribute) and parent.value is node
                else "conflict"
            )
        return "read"

    def _witness(self, path, node, role):
        return {
            "path": self.source.relative(path),
            "sha256": self.source.inventory[path],
            "span": [
                node.lineno,
                node.col_offset,
                node.end_lineno,
                node.end_col_offset,
            ],
            "role": role,
        }


def _presentation_literal_matches(chain, fact, root):
    from .credential_role_constructor_provider import binding_occurrences

    for path, _, owner in chain:
        bindings = binding_occurrences(owner.body, fact.member)
        if not bindings:
            continue
        if len(bindings) != 1:
            return False
        rows = [
            row
            for row in owner.body
            if _presentation_assignment_name(row) == fact.member
        ]
        if len(rows) != 1:
            return False
        row = rows[0]
        return (
            isinstance(row, (ast.Assign, ast.AnnAssign))
            and row.lineno == fact.line
            and row.col_offset == fact.column
            and path == root / fact.path
            and isinstance(row.value, ast.Constant)
            and row.value.value == fact._literal
        )
    return False


def _presentation_class_receiver(node, function, owner, source, path):
    from .credential_role_constructor_provider import binding_occurrences

    args = [*function.args.posonlyargs, *function.args.args]
    return (
        source.parents[path].get(id(function)) is owner
        and len(args) == 1
        and len(function.decorator_list) == 1
        and isinstance(function.decorator_list[0], ast.Name)
        and function.decorator_list[0].id == "classmethod"
        and isinstance(node.value, ast.Name)
        and node.value.id == args[0].arg
        and not binding_occurrences(function.body, args[0].arg)
    )


def _presentation_dict_value(node, key):
    if not isinstance(node, ast.Dict):
        return None
    rows = [
        value
        for name, value in zip(node.keys, node.values)
        if isinstance(name, ast.Constant) and name.value == key
    ]
    return (
        rows[0]
        if len(rows) == 1 and all(name is not None for name in node.keys)
        else None
    )


def _presentation_schema_title(node, function, parents):
    descriptor = parents.get(id(node))
    if (
        _presentation_dict_value(descriptor, "title") is not node
        or not isinstance(
            kind := _presentation_dict_value(descriptor, "type"), ast.Constant
        )
        or kind.value != "string"
    ):
        return False
    properties = parents.get(id(descriptor))
    schema = parents.get(id(properties))
    if (
        _presentation_dict_value(schema, "properties") is not properties
        or not isinstance(
            kind := _presentation_dict_value(schema, "type"), ast.Constant
        )
        or kind.value != "object"
    ):
        return False
    statement = parents.get(id(schema))
    returns = [row for row in ast.walk(function) if isinstance(row, ast.Return)]
    if len(returns) != 1 or returns[0] not in function.body:
        return False
    if isinstance(statement, ast.Return):
        return statement is returns[0] and _presentation_active_statement(
            statement, function
        )
    name = _presentation_assignment_name(statement)
    if (
        name is None
        or statement not in function.body
        or not _presentation_active_statement(statement, function)
    ):
        return False
    return (
        _presentation_unique_binding(function, name, statement)
        and isinstance(returns[0].value, ast.Name)
        and returns[0].value.id == name
        and _presentation_local_uses(function, name, parents, "schema")
    )


def _presentation_active_statement(statement, function):
    if statement not in function.body:
        return False
    return not any(
        isinstance(row, (ast.Return, ast.Raise))
        for row in function.body[: function.body.index(statement)]
    )


def _presentation_unique_binding(function, name, statement):
    from .credential_role_constructor_provider import binding_occurrences

    bindings = binding_occurrences(function.body, name)
    return len(bindings) == 1 and _presentation_assignment_name(statement) == name


def _presentation_local_uses(function, name, parents, mode):
    return all(
        _presentation_local_use(node, parents, mode)
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, ast.Load)
    )


def _presentation_local_use(node, parents, mode):
    parent = parents.get(id(node))
    if isinstance(parent, ast.Return) and parent.value is node:
        return mode != "restore"
    if isinstance(parent, ast.For) and parent.iter is node:
        return mode == "mask"
    if isinstance(parent, ast.Assign) and parent.value is node:
        return (
            mode == "restore"
            and len(parent.targets) == 1
            and _presentation_member(parent.targets[0]) == ["self", "_config"]
        )
    if not isinstance(parent, ast.Subscript) or parent.value is not node:
        return False
    if mode in {"mask", "restore"}:
        return isinstance(parent.ctx, ast.Store)
    return (
        isinstance(parent.ctx, ast.Store)
        and isinstance(parent.slice, ast.Constant)
        and parent.slice.value == "required"
    )


def _presentation_member(node):
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        base = _presentation_member(node.value)
        return [*base, node.attr] if base else None
    return None


def _presentation_subscript(node):
    return (
        (node.value.id, node.slice.id)
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and isinstance(node.slice, ast.Name)
        )
        else None
    )


def _presentation_secret_membership(node, name):
    if (
        not isinstance(node, ast.Compare)
        or len(node.ops) != 1
        or not isinstance(node.ops[0], ast.In)
    ):
        return False
    if not isinstance(node.left, ast.Name) or node.left.id != name:
        return False
    schema = node.comparators[0]
    if isinstance(schema, ast.Subscript) and isinstance(schema.slice, ast.Constant):
        return schema.slice.value == "secret" and _presentation_member(
            schema.value
        ) == ["self", "schema"]
    return (
        isinstance(schema, ast.Call)
        and _presentation_member(schema.func) == ["self", "schema", "get"]
        and len(schema.args) in {1, 2}
        and not schema.keywords
        and isinstance(schema.args[0], ast.Constant)
        and schema.args[0].value == "secret"
    )


def _presentation_mask_output(node, parents):
    statement = parents.get(id(node))
    if (
        not isinstance(statement, ast.Assign)
        or statement.value is not node
        or len(statement.targets) != 1
    ):
        return None
    target = _presentation_subscript(statement.targets[0])
    guard = parents.get(id(statement))
    if target is None or not isinstance(guard, ast.If) or statement not in guard.body:
        return None
    if not _presentation_secret_membership(guard.test, target[1]):
        return None
    loop = parents.get(id(guard))
    function = parents.get(id(loop))
    if not (
        isinstance(loop, ast.For)
        and guard in loop.body
        and isinstance(loop.target, ast.Name)
        and loop.target.id == target[1]
        and isinstance(loop.iter, ast.Name)
        and loop.iter.id == target[0]
        and isinstance(function, ast.FunctionDef)
        and loop in function.body
    ):
        return None
    if not (
        _presentation_active_statement(loop, function)
        and _presentation_output_copy(function, target[0], parents)
    ):
        return None
    return "MASK_OUTPUT"


def _presentation_mask_restore(node, parents):
    compare = parents.get(id(node))
    if not (
        isinstance(compare, ast.Compare)
        and len(compare.ops) == 1
        and isinstance(compare.ops[0], ast.Eq)
        and len(compare.comparators) == 1
    ):
        return None
    value = compare.left if compare.comparators[0] is node else compare.comparators[0]
    if not isinstance(value, ast.Name):
        return None
    condition = parents.get(id(compare))
    guard = parents.get(id(condition))
    if not (
        isinstance(condition, ast.BoolOp)
        and isinstance(condition.op, ast.And)
        and isinstance(guard, ast.If)
        and guard.test is condition
        and len(guard.body) == 1
        and len(condition.values) == 2
    ):
        return None
    assignment = guard.body[0]
    if not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1:
        return None
    target = _presentation_subscript(assignment.targets[0])
    old = _presentation_subscript(assignment.value)
    if target is None or old != ("self", target[1]):
        return None
    if not any(
        _presentation_secret_membership(test, target[1]) for test in condition.values
    ):
        return None
    loop = parents.get(id(guard))
    if (
        not isinstance(loop, ast.For)
        or not isinstance(loop.target, ast.Tuple)
        or len(loop.target.elts) != 2
    ):
        return None
    if not all(isinstance(item, ast.Name) for item in loop.target.elts):
        return None
    if [item.id for item in loop.target.elts] != [target[1], value.id]:
        return None
    return (
        "PRESERVE_PREVIOUS_VALUE"
        if _presentation_restore_flow(loop, target[0], parents)
        else None
    )


def _presentation_output_copy(function, name, parents):
    from .credential_role_constructor_provider import binding_occurrences

    bindings = binding_occurrences(function.body, name)
    rows = [row for row in function.body if _presentation_assignment_name(row) == name]
    if len(bindings) != 1 or len(rows) != 1:
        return False
    value = rows[0].value
    if not (
        isinstance(value, ast.Call)
        and not value.args
        and not value.keywords
        and _presentation_member(value.func) == ["self", "_config", "copy"]
    ):
        return False
    return (
        _presentation_active_statement(rows[0], function)
        and _presentation_local_uses(function, name, parents, "mask")
        and any(
            isinstance(row, ast.Return)
            and isinstance(row.value, ast.Name)
            and row.value.id == name
            for row in function.body
        )
    )


def _presentation_assignment_name(node):
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        target = node.targets[0]
    elif isinstance(node, ast.AnnAssign):
        target = node.target
    else:
        return None
    return target.id if isinstance(target, ast.Name) else None


def _presentation_global_match(fact, path, node, source, audit, imports=None):
    from .credential_role_constructor_provider import _scope
    from .credential_role_constructor_provider import (
        function_bindings,
        module_literal_binding,
    )

    if (
        isinstance(node, ast.Attribute)
        and node.attr == fact.member
        and isinstance(node.value, ast.Name)
    ):
        from .credential_role_constructor_provider import import_is_stable

        alias = node.value.id
        function, _ = _scope(node, source, path)
        return (
            (binding := (imports or {}).get(path, {}).get(alias)) is not None
            and binding[0] == source.root / fact.path
            and _presentation_namespace_binding(source, path, alias, binding)
            and import_is_stable(path, alias, source, audit)
            and (function is None or function_bindings(function, alias, audit) == [])
        )
    if not isinstance(node, ast.Name):
        return False
    function, _ = _scope(node, source, path)
    if function is not None and function_bindings(function, node.id, audit) != []:
        return False
    return module_literal_binding(fact, path, source, node, audit)


def _presentation_restore_flow(loop, name, parents):
    from .credential_role_constructor_provider import binding_occurrences

    function = parents.get(id(loop))
    if not isinstance(function, ast.FunctionDef) or not _presentation_active_statement(
        loop, function
    ):
        return False
    iterator = loop.iter
    if not (
        isinstance(iterator, ast.Call)
        and not iterator.args
        and not iterator.keywords
        and isinstance(iterator.func, ast.Attribute)
        and iterator.func.attr == "items"
        and isinstance(iterator.func.value, ast.Name)
    ):
        return False
    incoming = iterator.func.value.id
    args = [*function.args.posonlyargs, *function.args.args]
    if incoming not in {arg.arg for arg in args[1:]} or binding_occurrences(
        function.body, incoming
    ):
        return False
    rows = [row for row in function.body if _presentation_assignment_name(row) == name]
    if len(rows) != 1 or not isinstance(rows[0].value, ast.Dict) or rows[0].value.keys:
        return False
    # The published mapping cannot be read, aliased, mutated or replaced here.
    writes = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Attribute)
        and _presentation_member(node) == ["self", "_config"]
    ]
    if len(writes) != 1:
        return False
    publication = parents.get(id(writes[0]))
    if not (
        isinstance(publication, ast.Assign)
        and publication in function.body
        and len(publication.targets) == 1
        and publication.targets[0] is writes[0]
        and isinstance(publication.value, ast.Name)
        and publication.value.id == name
        and publication.lineno > loop.end_lineno
    ):
        return False
    return (
        _presentation_active_statement(rows[0], function)
        and _presentation_unique_binding(function, name, rows[0])
        and _presentation_local_uses(function, name, parents, "restore")
    )


def _presentation_namespace_binding(source, path, alias, binding):
    from .credential_role_constructor_provider import binding_occurrences

    if binding[1] is None:
        return True
    rows = binding_occurrences(source.snapshots[path].body, alias)
    if len(rows) != 1 or not isinstance(rows[0], ast.ImportFrom):
        return False
    statement = rows[0]
    selected = [item for item in statement.names if (item.asname or item.name) == alias]
    if len(selected) != 1 or selected[0].name != binding[1]:
        return False
    if statement.level:
        base = path.parent
        for _ in range(statement.level - 1):
            base = base.parent
        roots = [base]
    else:
        roots = [source.root, source.root / "src"]
    parts = (statement.module or "").split(".") if statement.module else []
    return any(
        binding[0]
        in {
            (base.joinpath(*parts) / binding[1]).with_suffix(".py"),
            base.joinpath(*parts) / binding[1] / "__init__.py",
        }
        for base in roots
    )


_FUNCTION = object()

_BOUND_METHOD = object()

_PROVIDER = object()


def source_model(self, key, derive, *, helper_epoch=None):
    """Reuse a model only while its supplied helper identity epoch stays fixed."""
    if not self.defers_validation(self.index, self.imports, self.classes, self.audit):
        return derive()
    return _derive_cached_model(self, key, derive, helper_epoch)


def _derive_cached_model(self, key, derive, helper_epoch):
    state = self._analysis_batch
    before = _helper_snapshot(helper_epoch) if helper_epoch is not None else ()
    cache_key = key if helper_epoch is None else (key, _helper_epoch_key(before or ()))
    if not _cache_epoch_ready(state, key, helper_epoch, before):
        return derive()
    if cache_key not in self.source_models:
        self.source_models[cache_key] = (before, derive())
    if helper_epoch is not None and not _same_helper_epoch(
        before, _helper_snapshot(helper_epoch)
    ):
        state.helper_epoch[key] = (helper_epoch, None)
    return self.source_models[cache_key][1]


def _cache_epoch_ready(state, key, helper_epoch, before):
    if helper_epoch is None:
        return True
    prior = state.helper_epoch.setdefault(key, (helper_epoch, before))
    if not _same_helper_epoch(prior[1], before) or before is None:
        state.helper_epoch[key] = (helper_epoch, None)
    return before is not None


def _ast_matches_source(raw, tree):
    try:
        parsed = ast.parse(raw)
        return ast.dump(parsed, include_attributes=True) == ast.dump(
            tree, include_attributes=True
        )
    except (SyntaxError, ValueError, TypeError, RecursionError, MemoryError):
        return False


def _helper_snapshot(helper_epoch):
    """Code freshness; mutable defaults, globals and closures need explicit epochs."""
    try:
        provider = _provider_snapshot(helper_epoch)
        values = helper_epoch()
        if not isinstance(values, tuple):
            return None
        return (provider, *(_helper_identity(value) for value in values))
    except Exception:
        return None


def _provider_snapshot(provider):
    if isinstance(provider, MethodType):
        function = provider.__func__
        return (_PROVIDER, provider.__self__, function.__code__, function.__globals__)
    if isinstance(provider, FunctionType):
        return (_PROVIDER, provider.__code__, provider.__globals__)
    return (provider,)


def _helper_identity(value):
    if isinstance(value, MethodType):
        return (_BOUND_METHOD, value.__self__, value.__func__, value.__func__.__code__)
    if isinstance(value, FunctionType):
        return (_FUNCTION, value, value.__code__)
    return (value,)


def _same_helper_epoch(left, right):
    if left is None or right is None or len(left) != len(right):
        return False
    return all(
        len(a) == len(b) and all(x is y for x, y in zip(a, b))
        for a, b in zip(left, right)
    )


def _helper_epoch_key(epoch):
    return tuple(tuple(id(part) for part in value) for value in epoch)


def helper_epochs_valid(epochs):
    """Check that cached helper epochs still match the current helper snapshots."""
    return all(
        snapshot is not None and _same_helper_epoch(_helper_snapshot(epoch), snapshot)
        for epoch, snapshot in epochs.values()
    )


def _view(imports, classes):
    return (copy.deepcopy(imports), {key: id(value) for key, value in classes.items()})


class ClassChainMemo:
    source_model = source_model

    def __init__(self, index, imports, classes, audit):
        self.index, self.imports, self.classes, self.audit = (
            index,
            imports,
            classes,
            audit,
        )
        self.view = _view(imports, classes)
        self.inventory = dict(index.inventory)
        self.root = index.root
        self.names = audit._name
        self.entries = {}
        self._analysis_batch = None
        self.getter_role_checks = {}
        self.source_models = {}

    def getter_role(self, node, path, audit, derive):
        """Memoize candidate-independent consumer checks within this derivation."""
        key = (
            path,
            id(node),
            id(self.index.snapshots.get(path)),
            self.index.inventory.get(path),
            derive,
            audit._module_security_aliases,
        )
        if audit is not self.audit:
            return derive(node, self.index, path, audit) is not None
        if key not in self.getter_role_checks:
            self.getter_role_checks[key] = (
                derive(node, self.index, path, audit) is not None
            )
        return self.getter_role_checks[key]

    @contextmanager
    def analysis_batch(self):
        """Defer repeated fresh checks until the producer's all-evidence exit."""
        if self._analysis_batch is not None:
            raise ValueError("nested analysis batch")
        state = SimpleNamespace(started=self.valid(), accepted=False, helper_epoch={})
        if not state.started:
            yield state
            return
        self._analysis_batch = state
        completed = False
        try:
            yield state
            completed = True
        finally:
            self._analysis_batch = None
            fresh = self.valid()
            state.accepted = (
                completed and fresh and helper_epochs_valid(state.helper_epoch)
            )

    def defers_validation(self, index, imports, classes, audit):
        """Allow batched analysis to defer validation only for the memo's matching index and current source views."""
        return bool(
            self._analysis_batch is not None
            and index is self.index
            and self.matches(imports, classes, audit)
        )

    def matches(self, imports, classes, audit):
        """Confirm that the memo still references the same import, class, audit, name-resolution, and root objects."""
        return (
            imports is self.imports
            and classes is self.classes
            and audit is self.audit
            and audit._name is self.names
            and self.index.root == self.root
        )

    def resolve(self, path, name, resolver):
        """Resolve a class chain once per path and name, caching successful tuples and failed lookups."""
        key = path, name
        if key not in self.entries:
            result = resolver()
            self.entries[key] = tuple(result) if result else None
        return self.entries[key]

    def valid(self):
        """Revalidate memo inputs and every previously validated source path against a fresh bounded snapshot index."""
        if (
            not self.matches(self.imports, self.classes, self.audit)
            or _view(self.imports, self.classes) != self.view
            or self.index.inventory != self.inventory
        ):
            return False
        fresh = SourceSnapshotIndex(
            self.root,
            self.index.snapshots,
            self.index.source_bytes,
            self.index.inventory,
        )
        return bool(
            fresh.bounded and all(fresh.validate(path) for path in self.index.validated)
        )


def resolve_class_chain(index, path, name, imports, classes, audit):
    """Resolve a class MRO to source class nodes, returning None when the inheritance chain is incomplete or ambiguous."""
    keys = _class_mro(index, (path, name), imports, classes, audit, set(), {})
    if keys is None:
        return None
    return [
        (class_path, class_name, classes[(class_path, class_name)])
        for class_path, class_name in keys
    ]


def resolve_class_chain_with_terminals(
    index, path, name, imports, classes, audit, terminal_contracts
):
    """Resolve captured owners and disclose caller-contracted external C3 terminals."""
    contracts = _terminal_contracts(terminal_contracts)
    if contracts is None:
        return None
    memo = {(None, canonical): [(None, canonical)] for canonical in contracts}
    keys = _class_mro(
        index, (path, name), imports, classes, audit, set(), memo, contracts
    )
    if keys is None:
        return None
    return {
        "chain": [
            (class_path, class_name, classes[(class_path, class_name)])
            for class_path, class_name in keys
            if class_path is not None
        ],
        "terminal_assumptions": [
            {"canonical": canonical, "contract": contracts[canonical]}
            for source_path, canonical in keys
            if source_path is None
        ],
    }


def _terminal_contracts(value):
    if not isinstance(value, dict) or not value or len(value) > 16:
        return None
    contracts = {}
    for canonical, contract in value.items():
        if not _valid_terminal_contract(canonical, contract):
            return None
        contracts[canonical] = contract
    return contracts


def _valid_terminal_contract(canonical, contract):
    if not isinstance(canonical, str) or not isinstance(contract, str):
        return False
    if not contract or len(contract) > 200 or not contract.isprintable():
        return False
    parts = canonical.split(".")
    return 2 <= len(parts) <= 16 and all(part.isidentifier() for part in parts)


def _class_mro(
    index, key, imports, classes, audit, active, memo, terminal_contracts=None
):
    if key in memo:
        return memo[key]
    if key in active or len(active) >= 16:
        return None
    path, name = key
    owner = classes.get(key)
    if not _class_binding_is_exact(index, path, name, owner):
        return None
    active.add(key)
    bases = []
    for expression in owner.bases:
        base = _class_base_reference(
            index, path, expression, imports, classes, audit, terminal_contracts
        )
        if base is None or base in bases:
            active.remove(key)
            return None
        bases.append(base)
    if not bases:
        result = [key]
    else:
        base_mros = [
            _class_mro(
                index, base, imports, classes, audit, active, memo, terminal_contracts
            )
            for base in bases
        ]
        if any(mro is None for mro in base_mros):
            active.remove(key)
            return None
        result = _c3_merge([[*mro] for mro in base_mros] + [[*bases]])
        if result is None:
            active.remove(key)
            return None
        result.insert(0, key)
    active.remove(key)
    if len(result) > 16:
        return None
    memo[key] = result
    return result


def _class_base_reference(index, path, expression, imports, classes, audit, contracts):
    from .credential_role_constructor_provider import _class_ref

    base = _class_ref(path, expression, imports, classes, audit, index)
    if base is None and contracts:
        return _external_class_terminal(
            index, path, expression, imports, audit, contracts
        )
    return base


def _external_class_terminal(index, path, expression, imports, audit, contracts):
    if not isinstance(expression, ast.Name) or not index.validate(path):
        return None
    alias = expression.id
    if alias in imports.get(path, {}):
        return None
    imported = _direct_terminal_import(index, path, alias)
    if imported is None:
        return None
    canonical, statement = imported
    if (
        statement.lineno >= expression.lineno
        or canonical not in contracts
        or _captured_module_shadows_terminal(index, path, statement, canonical)
    ):
        return None
    if _captured_terminal_provider_mutation(index, audit, canonical):
        return None
    return None, canonical


def _direct_terminal_import(index, path, alias):
    statement = _direct_terminal_import_statement(index, path, alias)
    if statement is None or not _terminal_alias_unmodified(
        index.snapshots[path], alias
    ):
        return None
    selected = statement.names[0]
    return f"{statement.module}.{selected.name}", statement


def _direct_terminal_import_statement(index, path, alias):
    from .credential_role_constructor_provider import binding_occurrences

    rows = binding_occurrences(index.snapshots[path].body, alias)
    if len(rows) != 1 or not isinstance(rows[0], ast.ImportFrom):
        return None
    statement = rows[0]
    if (
        index.parents[path].get(id(statement)) is not index.snapshots[path]
        or statement.level
        or not statement.module
        or len(statement.names) != 1
    ):
        return None
    selected = statement.names[0]
    if (selected.asname or selected.name) != alias or selected.name == "*":
        return None
    return statement


def _terminal_alias_unmodified(tree, alias):
    nodes = ast.walk(tree)
    if any(
        isinstance(node, ast.Name)
        and node.id == alias
        and isinstance(node.ctx, (ast.Store, ast.Del))
        for node in nodes
    ):
        return False
    return not any(
        isinstance(node, ast.Global) and alias in node.names for node in ast.walk(tree)
    )


def _captured_module_shadows_terminal(index, path, statement, canonical):
    try:
        from .import_context import import_source_bases

        module_parts = canonical.rpartition(".")[0].split(".")
        captured = set(index.snapshots)
        for base in import_source_bases(index.root, path, statement):
            for size in range(1, len(module_parts) + 1):
                target = base.joinpath(*module_parts[:size])
                if target.with_suffix(".py") in captured:
                    return True
                if target.joinpath("__init__.py") in captured:
                    return True
        return False
    except (AttributeError, TypeError, ValueError):
        return True


def _captured_terminal_provider_mutation(index, audit, canonical):
    for path, tree in index.snapshots.items():
        if not index.validate(path):
            return True
        aliases = audit._module_security_aliases(tree)
        nodes = list(ast.walk(tree))
        if _terminal_registry_mutation(nodes, aliases, audit, canonical):
            return True
        if not any(
            isinstance(value, str) and _terminal_provider_related(value, canonical)
            for value in aliases.values()
        ):
            continue
        parents = {
            id(child): node for node in nodes for child in ast.iter_child_nodes(node)
        }
        mutations = finite_provider_mutation_index(nodes, aliases, audit, parents)
        if any(
            _terminal_mutation_overlaps(provider, attribute, canonical)
            for provider, attribute in mutations
        ):
            return True
    return False


def _terminal_registry_mutation(nodes, aliases, audit, canonical):
    from .finite_capture import _provider_alias_bindings
    from .finite_capture import _provider_paths

    bindings = _provider_alias_bindings(nodes)
    parents = {
        id(child): node for node in nodes for child in ast.iter_child_nodes(node)
    }
    for node in nodes:
        if _terminal_registry_augmented_alias(node, aliases, audit, bindings):
            return True
        if _terminal_registry_node_targets(node, aliases, audit, bindings, canonical):
            return True
        if isinstance(node, ast.Call) and _terminal_registry_call(
            node, aliases, audit, bindings, canonical
        ):
            return True
        if isinstance(node, (ast.Name, ast.Attribute)) and _terminal_registry_escape(
            node, parents, aliases, audit, bindings, canonical, _provider_paths
        ):
            return True
    return False


def _terminal_registry_augmented_alias(node, aliases, audit, bindings):
    if not isinstance(node, ast.AugAssign) or not isinstance(node.target, ast.Name):
        return False
    paths, _ = finite_capture._provider_paths(node.target, aliases, audit, bindings)
    return _terminal_registry_paths(paths)


def _terminal_registry_node_targets(node, aliases, audit, bindings, canonical):
    targets = getattr(node, "targets", None)
    if targets is None:
        target = getattr(node, "target", None)
        targets = (target,) if target is not None else ()
    return any(
        _terminal_registry_target(target, aliases, audit, bindings, canonical)
        or _terminal_registry_store_value_escape(
            node, target, aliases, audit, bindings, canonical
        )
        for target in targets
    )


def _terminal_registry_target(target, aliases, audit, bindings, canonical):
    if not isinstance(target, (ast.Subscript, ast.Attribute)) or not isinstance(
        target.ctx, (ast.Store, ast.Del)
    ):
        return False
    return _terminal_registry_target_paths(target, aliases, audit, bindings, canonical)


def _terminal_registry_target_paths(target, aliases, audit, bindings, canonical):
    from .finite_capture import _provider_paths

    target_paths, _ = _provider_paths(target, aliases, audit, bindings)
    if isinstance(target, ast.Attribute) and _terminal_registry_paths(target_paths):
        return True
    receiver = target.value
    while isinstance(receiver, ast.Subscript):
        receiver = receiver.value
    paths, unresolved = _provider_paths(receiver, aliases, audit, bindings)
    if not _terminal_registry_paths(paths):
        return False
    if unresolved or not isinstance(target, ast.Subscript):
        return True
    key = target.slice
    if not isinstance(key, ast.Constant) or type(key.value) is not str:
        return True
    return _terminal_registry_key_related(key.value, canonical)


def _terminal_registry_paths(paths):
    return any(
        path == "sys.modules" or path.startswith("sys.modules.") for path in paths
    )


def _terminal_registry_call(call, aliases, audit, bindings, canonical):
    from .finite_capture import _provider_paths

    if not isinstance(call.func, ast.Attribute):
        return False
    paths, unresolved = _provider_paths(call.func.value, aliases, audit, bindings)
    if not _terminal_registry_paths(paths):
        return False
    if unresolved:
        return True
    items = _terminal_registry_call_items(call)
    if items is None:
        return True
    keys, values = items
    if any(_terminal_registry_key_related(key, canonical) for key in keys):
        return True
    return _terminal_registry_values_escape(values, aliases, audit, bindings, canonical)


def _terminal_registry_call_items(call):
    result = _terminal_registry_call_operands(call)
    if result is None:
        return None
    keys, values = result
    if any(
        not isinstance(key, ast.Constant) or type(key.value) is not str for key in keys
    ):
        return None
    return [key.value for key in keys], values


def _terminal_registry_call_operands(call):
    method = call.func.attr
    if method in {"get", "__getitem__"} and len(call.args) == 1 and not call.keywords:
        return [call.args[0]], []
    if (
        method in {"pop", "setdefault"}
        and 1 <= len(call.args) <= 2
        and not call.keywords
    ):
        return call.args[:1], call.args[1:]
    if method != "update":
        return None
    return _terminal_registry_update_items(call)


def _terminal_registry_update_items(call):
    if len(call.args) > 1:
        return None
    keys, values = [], []
    if call.args:
        mapping = call.args[0]
        if not isinstance(mapping, ast.Dict) or any(
            key is None for key in mapping.keys
        ):
            return None
        keys.extend(mapping.keys)
        values.extend(mapping.values)
    for keyword in call.keywords:
        if keyword.arg is None:
            return None
        keys.append(ast.Constant(value=keyword.arg))
        values.append(keyword.value)
    if not keys:
        return None
    return keys, values


def _terminal_registry_values_escape(values, aliases, audit, bindings, canonical):
    from .finite_capture import _provider_paths

    for value in values:
        for item in ast.walk(value):
            if not isinstance(item, (ast.Name, ast.Attribute)):
                continue
            paths, unresolved = _provider_paths(item, aliases, audit, bindings)
            if _terminal_registry_paths(paths) or unresolved and paths:
                return True
            if any(_terminal_provider_related(path, canonical) for path in paths):
                return True
    return False


def _terminal_registry_escape(
    node, parents, aliases, audit, bindings, canonical, provider_paths
):
    if not isinstance(node.ctx, ast.Load):
        return False
    parent = parents.get(id(node))
    if isinstance(parent, ast.Attribute) and parent.value is node:
        return False
    paths, unresolved = provider_paths(node, aliases, audit, bindings)
    if not _terminal_registry_paths(paths):
        return False
    if unresolved:
        return True
    return _terminal_registry_escape_use(
        node, parent, paths, aliases, audit, bindings, canonical
    )


def _terminal_registry_escape_use(
    node, parent, paths, aliases, audit, bindings, canonical
):
    if isinstance(parent, ast.Subscript) and parent.value is node:
        return False
    if _terminal_registry_alias_assignment(parent, node, paths):
        return False
    if isinstance(parent, ast.Call) and parent.func is node:
        return _terminal_registry_call(parent, aliases, audit, bindings, canonical)
    return True


def _terminal_registry_alias_assignment(parent, node, paths):
    if paths != {"sys.modules"}:
        return False
    if isinstance(parent, ast.Assign) and parent.value is node:
        return all(isinstance(target, ast.Name) for target in parent.targets)
    if isinstance(parent, ast.AnnAssign) and parent.value is node:
        return isinstance(parent.target, ast.Name)
    return False


def _terminal_registry_store_value_escape(
    node, target, aliases, audit, bindings, canonical
):
    if not isinstance(target, ast.Subscript) or not isinstance(target.ctx, ast.Store):
        return False
    receiver = target.value
    while isinstance(receiver, ast.Subscript):
        receiver = receiver.value
    paths, unresolved = finite_capture._provider_paths(
        receiver, aliases, audit, bindings
    )
    if not _terminal_registry_paths(paths) or unresolved:
        return False
    value = getattr(node, "value", None)
    return value is not None and _terminal_registry_values_escape(
        [value], aliases, audit, bindings, canonical
    )


def _terminal_registry_key_related(key, canonical):
    module = canonical.rpartition(".")[0]
    key_parts, module_parts = key.split("."), module.split(".")
    return bool(
        key_parts
        and len(key_parts) <= len(module_parts)
        and module_parts[: len(key_parts)] == key_parts
    )


def _terminal_provider_related(provider, canonical):
    return _overlaps(provider, canonical) or _overlaps(canonical, provider)


def _terminal_mutation_overlaps(provider, attribute, canonical):
    target = provider if attribute == "*" else provider + "." + attribute
    return _terminal_provider_related(target, canonical)


def _class_binding_is_exact(index, path, name, owner):
    if (
        owner is None
        or owner.decorator_list
        or owner.keywords
        or not index.validate(path)
    ):
        return False
    from .credential_role_constructor_provider import binding_occurrences

    definitions = binding_occurrences(index.snapshots[path].body, name)
    return len(definitions) == 1 and definitions[0] is owner


def _c3_merge(sequences):
    result = []
    while any(sequences):
        sequences = [sequence for sequence in sequences if sequence]
        candidate = next(
            (
                sequence[0]
                for sequence in sequences
                if all(sequence[0] not in other[1:] for other in sequences)
            ),
            None,
        )
        if candidate is None:
            return None
        result.append(candidate)
        for sequence in sequences:
            if sequence and sequence[0] == candidate:
                sequence.pop(0)
        if len(result) >= 16 and any(sequences):
            return None
    return result


def _import_binding_is_exact(index, path, name, imported):
    if not index.validate(path):
        return False
    from .credential_role_constructor_provider import binding_occurrences

    definitions = binding_occurrences(index.snapshots[path].body, name)
    if len(definitions) != 1:
        return False
    binding = definitions[0]
    if isinstance(binding, ast.ImportFrom):
        rows = [
            alias for alias in binding.names if (alias.asname or alias.name) == name
        ]
        return bool(
            len(rows) == 1
            and imported[1] == rows[0].name
            and imported[0] in index.snapshots
        )
    if isinstance(binding, ast.Import):
        rows = [
            alias
            for alias in binding.names
            if (alias.asname or alias.name.split(".")[0]) == name
        ]
        return bool(
            len(rows) == 1
            and imported[1] is None
            and len(imported[0:1]) == 1
            and imported[0] in index.snapshots
        )
    return False


def class_binding(owner, name, parents):
    """Resolve a unique direct class binding to its name or attribute expression; return None when absent and false when ambiguous."""
    bindings = binding_occurrences(owner.body, name)
    if not bindings:
        return None
    if len(bindings) != 1:
        return False
    target = bindings[0]
    statement = parents.get(id(target))
    if parents.get(id(statement)) is not owner:
        return False
    targets = getattr(statement, "targets", [getattr(statement, "target", None)])
    if (
        len(targets) != 1
        or targets[0] is not target
        or not isinstance(getattr(statement, "value", None), (ast.Name, ast.Attribute))
    ):
        return False
    return statement.value


def init_override(owner, parents):
    """Report whether a class defines exactly one direct __init__ method, distinguishing absence from an unsafe override."""
    bindings = binding_occurrences(owner.body, "__init__")
    if not bindings:
        return None
    return (
        len(bindings) == 1
        and isinstance(bindings[0], (ast.FunctionDef, ast.AsyncFunctionDef))
        and parents.get(id(bindings[0])) is owner
    )


def capture_holder_instances(
    tree, parents, aliases, owners, roots, path, filtered, field_aliases, resolve
):
    """Track holder instances and class aliases into provider roots; stop when a holder escapes or its selector use is ambiguous."""
    for node, target in _single_name_assignments(tree):
        if not _capture_holder_assignment(
            node,
            target,
            tree,
            parents,
            aliases,
            owners,
            roots,
            path,
            filtered,
            field_aliases,
            resolve,
        ):
            return False
    return True


def _capture_holder_assignment(
    node,
    target,
    tree,
    parents,
    aliases,
    owners,
    roots,
    path,
    filtered,
    field_aliases,
    resolve,
):
    name, parent, value = target.id, parents.get(id(node)), node.value
    if name != "client_class" and isinstance(value, (ast.Name, ast.Attribute)):
        holder = resolve(value, aliases)
        if holder in owners:
            if not _capture_class_alias(
                tree, parent, name, holder, aliases, field_aliases, resolve
            ):
                return False
            filtered.setdefault(path, set()).add(id(node))
        return True
    if isinstance(value, ast.Call):
        return _capture_holder_call(
            node, name, parent, tree, parents, aliases, owners, roots, resolve
        )
    return True


def _capture_holder_call(
    node, name, parent, tree, parents, aliases, owners, roots, resolve
):
    holder = resolve(node.value.func, aliases)
    if holder not in owners:
        return True
    if not isinstance(parent, ast.Module):
        return _local_holder_unused_selector(parent, parents, name)
    if len(binding_occurrences(tree.body, name)) != 1:
        return False
    aliases[name] = holder
    roots.add(holder + ".client_class")
    return True


def _single_name_assignments(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(targets) == 1 and isinstance(targets[0], ast.Name):
                yield node, targets[0]


def _local_holder_unused_selector(parent, parents, name):
    scope = parent
    while scope is not None and not isinstance(
        scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    ):
        scope = parents.get(id(scope))
    return isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and not any(
        isinstance(item, ast.Attribute)
        and item.attr == "client_class"
        and isinstance(item.value, ast.Name)
        and item.value.id == name
        for item in ast.walk(scope)
    )


def _capture_class_alias(tree, parent, name, holder, aliases, fields, resolve):
    scope = parent if parent is tree or isinstance(parent, ast.ClassDef) else None
    if scope is None or len(binding_occurrences(scope.body, name)) != 1:
        return False
    if scope is tree:
        aliases[name] = holder
    else:
        class_path = resolve(ast.Name(scope.name, ast.Load()), aliases)
        if not class_path.startswith("captured_"):
            return False
        fields[class_path + "." + name] = holder
    return True


def instance_selector_edges(tree, aliases, owners, roots, path, filtered, resolve):
    """Record unique captured client_class assignments and extend the provider roots and owner set."""
    selected = _selected_instance_selector_edges(tree, aliases, roots, resolve)
    for node, owner in selected:
        if not _unique_selected_owner(owner, selected):
            return False
        owners.add(owner)
        roots.add(owner + ".client_class")
        filtered.setdefault(path, set()).add(id(node))
    return True


def _selected_instance_selector_edges(tree, aliases, roots, resolve):
    selected = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Attribute):
            continue
        target = targets[0]
        owner = resolve(target.value, aliases)
        if (
            target.attr == "client_class"
            and owner.startswith("captured_")
            and resolve(node.value, aliases) in roots
        ):
            selected.append((node, owner))
    return selected


def _unique_selected_owner(owner, selected):
    return sum(item == owner for _, item in selected) == 1


def field_alias_path(provider, aliases):
    """Rewrite a provider path through the longest matching captured field alias, preserving unmatched paths."""
    return next(
        (
            owner + provider[len(alias) :]
            for alias, owner in aliases.items()
            if provider == alias or provider.startswith(alias + ".")
        ),
        provider,
    )


def owner_path(node, aliases, fields):
    """Resolve a node's canonical provider name through imports and captured field aliases."""
    return field_alias_path(_resolved_ast_name(node, aliases), fields)


def class_index(index, aliases_by_path):
    """Index top-level classes by resolved name across validated snapshots, omitting names that cannot be resolved."""
    rows = {}
    for path, tree in index.snapshots.items():
        aliases = aliases_by_path[path]
        for owner in tree.body:
            if isinstance(owner, ast.ClassDef):
                rows[aliases.get(owner.name)] = (path, owner, aliases, tree)
    return {name: row for name, row in rows.items() if name}


def constructor_provider_provenance_epoch():
    """Return the functions and binding helpers used to invalidate constructor-provider provenance caches."""
    from .credential_role_identity_effects import summarize_identity_effect

    return (
        class_binding,
        init_override,
        capture_holder_instances,
        _capture_holder_assignment,
        _capture_holder_call,
        _capture_class_alias,
        _local_holder_unused_selector,
        _single_name_assignments,
        instance_selector_edges,
        _selected_instance_selector_edges,
        _unique_selected_owner,
        field_alias_path,
        owner_path,
        class_index,
        source_owner_consumer,
        _consumer_method,
        _safe_consumer_formal,
        _captured_method,
        _classmethod,
        _is_call_argument,
        _consumer_effect_safe,
        _is_safe_isinstance_value,
        binding_occurrences,
        summarize_identity_effect,
        bind_source_call,
        _resolved_ast_name,
    )


def source_owner_consumer(
    node,
    path,
    tree,
    parents,
    index,
    aliases,
    classes,
    owners,
    builtin_stable,
    aliases_by_path=None,
):
    """Return a consumer method name only when the captured owner call maps to a safe class method and ordinary type operand."""
    call = parents.get(id(node))
    if (
        _resolved_ast_name(node, aliases) not in owners
        or not _is_call_argument(node, call)
        or not isinstance(call.func, ast.Attribute)
    ):
        return None
    method_row = _consumer_method(call, aliases, classes, builtin_stable)
    if method_row is None:
        return None
    receiver, method_owner_path, method_path, owner, method = method_row
    try:
        bound = bind_source_call(call, method, receiver=receiver, apply_defaults=False)
    except (TypeError, ValueError):
        return None
    formals = [name for name, value in bound.items() if value is node]
    if len(formals) != 1 or not _safe_consumer_formal(
        formals[0],
        method,
        method_path,
        method_owner_path,
        index,
        classes,
        owners,
        builtin_stable,
        aliases_by_path,
    ):
        return None
    if aliases_by_path is None or not ordinary_type_operand(
        node, tree, parents, index, classes, aliases, owners, aliases_by_path
    ):
        return None
    return method_owner_path + "." + method.name


def _consumer_method(call, aliases, classes, builtin_stable):
    receiver = call.func.value
    row = _captured_method(
        _resolved_ast_name(receiver, aliases), call.func.attr, classes, set()
    )
    if row is None:
        return None
    method_owner_path, method_path, owner, method = row
    if not _classmethod(method, owner, classes, builtin_stable):
        return None
    return receiver, method_owner_path, method_path, owner, method


def _safe_consumer_formal(
    formal,
    method,
    method_path,
    owner_path,
    index,
    classes,
    owners,
    builtin_stable,
    aliases_by_path,
):
    return _consumer_effect_safe(
        method,
        method_path,
        index,
        formal,
        builtin_stable,
        (classes, classes[owner_path][2], owners, aliases_by_path),
    )


def _captured_method(path, name, classes, seen):
    if path in seen:
        return None
    row = classes.get(path)
    if row is None:
        return None
    file_path, owner, aliases, _ = row
    definitions = binding_occurrences(owner.body, name)
    if definitions:
        if (
            len(definitions) == 1
            and isinstance(definitions[0], ast.FunctionDef)
            and definitions[0] in owner.body
        ):
            return path, file_path, owner, definitions[0]
        return None
    if len(owner.bases) == 1:
        return _captured_method(
            _resolved_ast_name(owner.bases[0], aliases), name, classes, seen | {path}
        )
    if owner.bases:
        first_path = _resolved_ast_name(owner.bases[0], aliases)
        first = classes.get(first_path)
        if first is not None:
            base = binding_occurrences(first[1].body, name)
            if (
                len(base) == 1
                and isinstance(base[0], ast.FunctionDef)
                and base[0] in first[1].body
            ):
                return first_path, first[0], first[1], base[0]
    return None


def _classmethod(method, owner, classes, builtin_stable):
    row = next((entry for entry in classes.values() if entry[1] is owner), None)
    return bool(
        row
        and builtin_stable
        and len(method.decorator_list) == 1
        and isinstance(method.decorator_list[0], ast.Name)
        and method.decorator_list[0].id == "classmethod"
        and not binding_occurrences(row[3].body, "classmethod")
        and binding_occurrences(owner.body, method.name) == [method]
    )


def _is_call_argument(node, call):
    return bool(
        isinstance(call, ast.Call)
        and (
            any(value is node for value in call.args)
            or any(k.value is node for k in call.keywords)
        )
    )


def _consumer_effect_safe(method, path, index, parameter, builtin_stable, types=None):
    from .credential_role_identity_effects import summarize_identity_effect

    nested = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
    if any(
        node is not method and isinstance(node, nested) for node in ast.walk(method)
    ):
        return False
    tree, parents = index.snapshots[path], index.parents[path]

    def ordinary_type(operand):
        if types is None:
            return False
        classes, aliases, owners, aliases_by_path = types
        if aliases_by_path is None:
            return False
        return ordinary_type_operand(
            operand, tree, parents, index, classes, aliases, owners, aliases_by_path
        )

    uses = [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Name)
        and node.id == parameter
        and isinstance(node.ctx, ast.Load)
    ]
    if not all(
        _is_safe_isinstance_value(node, tree, parents, builtin_stable, ordinary_type)
        for node in uses
    ):
        return False
    effects = summarize_identity_effect(method, path, index, {parameter: "owner"})
    allowed_unknowns = {
        "implicit special-method dispatch on tracked root",
        "return/yield contains unresolved tracked value",
    }
    return bool(
        not effects.class_writes
        and set(effects.escapes) <= {"owner"}
        and set(effects.unknowns) <= allowed_unknowns
    )


def _is_safe_isinstance_value(node, tree, parents, builtin_stable, ordinary_type=None):
    call = parents.get(id(node))
    if not (
        builtin_stable
        and isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "isinstance"
        and len(call.args) == 2
        and call.args[0] is node
        and not call.keywords
        and not binding_occurrences(tree.body, "isinstance")
        and ordinary_type is not None
        and ordinary_type(call.args[1])
    ):
        return False
    scope = parents.get(id(call))
    while scope is not None:
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
            if any(arg.arg == "isinstance" for arg in params) or binding_occurrences(
                scope.body, "isinstance"
            ):
                return False
        elif isinstance(scope, ast.ClassDef) and binding_occurrences(
            scope.body, "isinstance"
        ):
            return False
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
            isinstance(item, (ast.Global, ast.Nonlocal)) and "isinstance" in item.names
            for item in ast.walk(scope)
        ):
            return False
        scope = parents.get(id(scope))
    return True


def ordinary_type_operand(
    node, tree, parents, index, classes, aliases, owners, aliases_by_path
):
    """Confirm that a name or attribute denotes a stable ordinary class whose type metadata is not provider-controlled."""
    if not isinstance(node, (ast.Name, ast.Attribute)):
        return False
    root = node
    while isinstance(root, ast.Attribute):
        root = root.value
    if not isinstance(root, ast.Name) or not _lexical_binding_stable(root, parents):
        return False
    canonical = _resolved_ast_name(node, aliases)
    return _ordinary_class(canonical, classes, set()) and _type_metadata_stable(
        canonical, index, owners, aliases_by_path
    )


def _lexical_binding_stable(node, parents):
    scope = parents.get(id(node))
    while scope is not None:
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
            args.extend(arg for arg in (scope.args.vararg, scope.args.kwarg) if arg)
            if any(arg.arg == node.id for arg in args):
                return False
            body = scope.body if isinstance(scope.body, list) else [scope.body]
            if binding_occurrences(body, node.id):
                return False
        scope = parents.get(id(scope))
    return True


def _ordinary_class(canonical, classes, seen):
    row = classes.get(canonical)
    if row is None or canonical in seen:
        return False
    _, owner, aliases, tree = row
    if owner.keywords or owner.decorator_list:
        return False
    for base in owner.bases:
        if isinstance(base, ast.Name) and base.id == "object":
            if binding_occurrences(tree.body, "object"):
                return False
        elif not _ordinary_class(
            _resolved_ast_name(base, aliases), classes, seen | {canonical}
        ):
            return False
    return True


def _type_metadata_stable(canonical, index, owners, aliases_by_path):
    audit = SimpleNamespace(_resolved_ast_name=_resolved_ast_name)
    for path, tree in index.snapshots.items():
        aliases = aliases_by_path.get(path)
        if aliases is None or not index.validate(path):
            return False
        parents = index.parents[path]
        nodes = [
            item
            for item in ast.walk(tree)
            if not _exact_type_argument(item, parents, tree)
        ]
        if canonical not in owners and any(
            isinstance(item, (ast.Name, ast.Attribute))
            and _resolved_ast_name(item, aliases) == canonical
            for item in nodes
        ):
            return False
        facts = finite_provider_mutation_index(nodes, aliases, audit, parents)
        if any(
            _metadata_overlap(provider, attr, canonical, owners)
            for provider, attr in facts
        ):
            return False
    return True


def _exact_type_argument(node, parents, tree):
    call = parents.get(id(node))
    return bool(
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "isinstance"
        and len(call.args) == 2
        and call.args[1] is node
        and not call.keywords
        and not binding_occurrences(tree.body, "isinstance")
        and _lexical_binding_stable(call.func, parents)
    )


def _metadata_overlap(provider, attribute, canonical, owners):
    if attribute == "*":
        return provider == canonical and canonical not in owners
    path = provider + "." + attribute
    return any(
        path == canonical + "." + name or path.startswith(canonical + "." + name + ".")
        for name in ("__bases__", "__class__", "__instancecheck__")
    )


def _class_ref(path, node, imports, classes, audit, index=None):
    name = audit._name(node) if isinstance(node, (ast.Name, ast.Attribute)) else ""
    if not name:
        return None
    parts = name.split(".")
    imported = imports.get(path, {}).get(parts[0])
    if imported:
        if index is not None and not _import_binding_is_exact(
            index, path, parts[0], imported
        ):
            return None
        target, symbol = imported
        if symbol:
            return (target, symbol) if len(parts) == 1 else None
        return (target, parts[1]) if len(parts) == 2 else None
    if len(parts) == 1 and (path, parts[0]) in classes:
        if index is None:
            return path, parts[0]
        from .credential_role_constructor_provider import binding_occurrences

        if index.validate(path):
            owner = classes[(path, parts[0])]
            definitions = binding_occurrences(index.snapshots[path].body, parts[0])
            if len(definitions) == 1 and definitions[0] is owner:
                return path, parts[0]
    return None


def class_chain(index, path, name, imports, classes, audit):
    """Resolve and memoize a class inheritance chain only while the import, class, and audit views still match."""
    memo = getattr(index, "class_chain_memo", None)
    if memo is None:
        return _uncached_class_chain(index, path, name, imports, classes, audit)
    if not memo.matches(imports, classes, audit):
        return None
    return memo.resolve(
        path,
        name,
        lambda: _uncached_class_chain(index, path, name, imports, classes, audit),
    )


def _uncached_class_chain(index, path, name, imports, classes, audit):
    from .credential_role_constructor_provider import resolve_class_chain

    return resolve_class_chain(index, path, name, imports, classes, audit)


def _scope_assignments(function):
    rows = {}
    for statement in function.body:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            for target in targets:
                if isinstance(target, ast.Name):
                    rows.setdefault(target.id, []).append((statement, statement.value))
    return rows


def matches_fact(fact, path, node, index, imports, classes, audit, seen=()):
    """Match a credential fact to a name or attribute through bounded scope and import resolution; reject cycles and invalid snapshots."""
    if id(node) in seen or len(seen) > 8 or not index.validate(path):
        return False
    function, owner = _scope(node, index, path)
    if isinstance(node, ast.Name):
        return match_name(
            fact, path, node, function, index, imports, classes, audit, seen
        )
    if isinstance(node, ast.Attribute):
        return _match_attribute(fact, path, node, owner, index, imports, classes, audit)
    return False


def _scope(node, index, path):
    function = owner = None
    current = node
    while current is not None:
        current = index.parents[path].get(id(current))
        if (
            isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef))
            and function is None
        ):
            function = current
        if isinstance(current, ast.ClassDef) and owner is None:
            owner = current
    return function, owner


def _match_attribute(fact, path, node, owner, index, imports, classes, audit):
    if isinstance(node.value, ast.Name) and node.value.id == "self":
        function, _ = _scope(node, index, path)
        chain = (
            class_chain(
                index, index.root / fact.path, fact.owner, imports, classes, audit
            )
            if owner
            else None
        )
        return bool(
            owner
            and instance_receiver(node, function, owner, index, path)
            and fact.owner != "<module>"
            and fact.source_role in {"class_literal", "instance_literal"}
            and node.attr == fact.member
            and chain
            and (path, owner.name) in {(p, name) for p, name, _ in chain}
        )
    function, _ = _scope(node, index, path)
    root = node.value
    from .credential_role_constructor_provider import function_bindings

    if isinstance(root, ast.Attribute):
        while isinstance(root, ast.Attribute):
            root = root.value
    if isinstance(root, ast.Name) and function is not None:
        bindings = function_bindings(function, root.id, audit)
        if bindings is None or bindings:
            return False
    if fact.source_role not in {"class_literal", "module_literal"}:
        return False
    resolved = _class_ref(path, node.value, imports, classes, audit, index)
    ancestry = (
        class_chain(index, *resolved, imports, classes, audit) if resolved else ()
    )
    return bool(
        ancestry
        and node.attr == fact.member
        and (index.root / fact.path, fact.owner)
        in {(p, name) for p, name, _ in ancestry}
    )


def url_use(fact, record, evidence, publications):
    """Record URL user-info as an authentication use, matched publications as sanitized witnesses, and unmatched URLs as unknown links."""
    parsed = urlsplit(fact._literal)
    if parsed.username and parsed.password:
        record["slot"] = "http_url_userinfo"
        evidence["known_auth_uses"].append(record)
    elif fact._literal in publications:
        publication = dict(publications[fact._literal])
        publication.pop("value", None)
        record["publication"] = publication
        evidence["url_witnesses"].append(record)
    else:
        evidence["linked_unknown_uses"].append(
            {**record, "reason": "endpoint_publication_unmatched"}
        )


def _literal_target(node):
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    value = getattr(node, "value", None)
    if (
        len(targets) != 1
        or not isinstance(value, ast.Constant)
        or not isinstance(value.value, str)
    ):
        return None
    target = targets[0]
    if isinstance(target, ast.Name):
        return target.id
    if (
        isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Name)
        and target.value.id == "self"
    ):
        return target.attr
    return None


def auth_constructor_password(call, path, aliases):
    """Return the password expression only for the supported requests or httpx basic-auth constructor forms."""
    from .security_configuration import _canonical

    if _canonical(call, aliases[path]) not in {
        "requests.auth.HTTPBasicAuth",
        "httpx.BasicAuth",
    }:
        return None
    if len(call.args) == 2 and not call.keywords:
        return call.args[1]
    if not call.args and sorted(item.arg for item in call.keywords) == [
        "password",
        "username",
    ]:
        return next(item.value for item in call.keywords if item.arg == "password")
    return None


def candidate_facts(index, snapshots, sink_rows, publications):
    """Collect literal declaration facts whose member names or values occur in sink expressions or endpoint publications."""
    names = _sink_expression_names(sink_rows)
    facts = []
    for path, tree in snapshots.items():
        if not isinstance(tree, ast.Module):
            continue
        for node in ast.walk(tree):
            if (
                not isinstance(node, (ast.Assign, ast.AnnAssign))
                or _literal_target(node) is None
            ):
                continue
            fact = declaration_fact(index, path, node)
            if fact and (fact.member in names or fact._literal in publications):
                facts.append(fact)
    return facts


def _sink_expression_names(sink_rows):
    return {
        part
        for _, _, _, _, expr, *_ in sink_rows
        for node in ast.walk(expr)
        for part in (
            (node.id,)
            if isinstance(node, ast.Name)
            else (node.attr,)
            if isinstance(node, ast.Attribute)
            else ()
        )
    }


def constructor_provider_bindings_inert(chain, index, imports):
    """Reject source-bound constructor/selector mutation, escape, or unknowns."""
    if not chain or not index.bounded:
        return False
    selected = {_source_module(path) + "." + name for path, name, _ in chain}
    model = constructor_provider_model(
        selected, index, imports, _source_aliases, _has_opaque_owner_capture
    )
    if model is None:
        return False
    roots, aliases, filtered, shared, field_aliases, consumers = model
    return _captured_mutations_inert(
        index, roots, aliases, filtered, shared, field_aliases, consumers
    )


def _captured_mutations_inert(
    index, roots, aliases_by_path, filtered, shared, field_aliases, consumers
):
    from .review_audits import _resolved_ast_name

    audit = SimpleNamespace(_resolved_ast_name=_resolved_ast_name)
    for path, tree in index.snapshots.items():
        aliases = aliases_by_path[path]
        ignored = filtered.get(path, set())
        nodes = [node for node in ast.walk(tree) if id(node) not in ignored]
        mutations = finite_provider_mutation_index(
            nodes, aliases, audit, index.parents[path]
        )
        mutations = {
            (field_alias_path(provider, field_aliases), attribute)
            for provider, attribute in mutations
        }
        if any(
            _mutation_overlaps(provider, attribute, consumer)
            for provider, attribute in mutations
            for consumer in consumers
        ):
            return False
        owners = {root[:-13] for root in roots if root.endswith(".client_class")}
        if _owner_method_mutation(
            tree, aliases, owners, roots, audit, index.parents[path]
        ):
            return False
        if any(
            _mutation_overlaps(provider, attribute, root)
            for provider, attribute in mutations
            for root in roots
        ) or any(
            _shared_function_mutation(provider, attribute, item)
            for provider, attribute in mutations
            for item in shared
        ):
            return False
    return True


def _overlaps(provider, root):
    return provider == root or provider.startswith(root + ".")


def _mutation_overlaps(provider, attribute, root):
    return _overlaps(provider if attribute == "*" else provider + "." + attribute, root)


def _shared_function_mutation(provider, attribute, function):
    path = provider if attribute == "*" else provider + "." + attribute
    return path == function and attribute == "*" or path.startswith(function + ".")


def _source_aliases(path, tree, imports, index):
    from .credential_role_constructor_provider import _import_binding_is_exact

    module, aliases = _source_module(path), {}
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            defs = binding_occurrences(tree.body, node.name)
            if len(defs) == 1 and defs[0] is node:
                aliases[node.name] = f"{module}.{node.name}"
    for name, imported in imports.items():
        if _import_binding_is_exact(index, path, name, imported):
            target, symbol = imported
            aliases[name] = _source_module(target) + (f".{symbol}" if symbol else "")
    return aliases


def _source_module(path):
    return "captured_" + hashlib.sha256(str(path).encode()).hexdigest()


def _resolved_name(node, aliases):
    from .review_audits import _resolved_ast_name

    return _resolved_ast_name(node, aliases)


def _owner_method_mutation(tree, aliases, owners, roots, audit, parents):
    for owner in (n for n in tree.body if isinstance(n, ast.ClassDef)):
        owner_class_path = _resolved_name(ast.Name(owner.name, ast.Load()), aliases)
        if owner_class_path not in owners:
            continue
        for method in (
            n
            for n in owner.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            params = [*method.args.posonlyargs, *method.args.args]
            if not params:
                continue
            scoped = dict(aliases, **{params[0].arg: owner_class_path})
            nodes = [
                node
                for node in ast.walk(method)
                if not (
                    isinstance(parents.get(id(node)), ast.Attribute)
                    and parents[id(node)].value is node
                )
            ]
            mutations = finite_provider_mutation_index(nodes, scoped, audit, parents)
            _owner_container_paths(nodes, scoped, audit, parents, mutations)
            if any(
                _mutation_overlaps(p, a, r) or (a == "*" and r.startswith(p + "."))
                for p, a in mutations
                for r in roots
            ):
                return True
    return False


def _owner_container_paths(nodes, aliases, audit, parents, mutations):
    bindings = finite_capture._provider_alias_bindings(nodes)
    containers = (
        ast.List,
        ast.Tuple,
        ast.Set,
        ast.Dict,
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
    )
    for node in nodes:
        if not isinstance(node, containers):
            continue
        for item in ast.walk(node):
            parent = parents.get(id(item))
            if isinstance(parent, ast.Attribute) and parent.value is item:
                continue
            if isinstance(item, (ast.Name, ast.Attribute)):
                finite_capture._record_provider_paths(
                    item, "*", aliases, audit, bindings, mutations
                )


def constructor_provider_helper_epoch():
    """Return semantic helper identities for batch-cache freshness checks."""
    from .credential_role_constructor_provider import _import_binding_is_exact
    from .credential_role_constructor_provider import _terminal_contracts
    from .credential_role_constructor_provider import _valid_terminal_contract
    from .credential_role_constructor_provider import _class_base_reference
    from .credential_role_constructor_provider import _external_class_terminal
    from .credential_role_constructor_provider import _direct_terminal_import
    from .credential_role_constructor_provider import _direct_terminal_import_statement
    from .credential_role_constructor_provider import _terminal_alias_unmodified
    from .credential_role_constructor_provider import _captured_module_shadows_terminal
    from .credential_role_constructor_provider import (
        _captured_terminal_provider_mutation,
    )
    from .credential_role_constructor_provider import _terminal_provider_related
    from .credential_role_constructor_provider import _terminal_mutation_overlaps
    from .credential_role_constructor_provider import _terminal_registry_mutation
    from .credential_role_constructor_provider import _terminal_registry_node_targets
    from .credential_role_constructor_provider import _terminal_registry_augmented_alias
    from .credential_role_constructor_provider import _terminal_registry_target
    from .credential_role_constructor_provider import _terminal_registry_target_paths
    from .credential_role_constructor_provider import _terminal_registry_paths
    from .credential_role_constructor_provider import _terminal_registry_call
    from .credential_role_constructor_provider import _terminal_registry_call_items
    from .credential_role_constructor_provider import _terminal_registry_call_operands
    from .credential_role_constructor_provider import _terminal_registry_update_items
    from .credential_role_constructor_provider import _terminal_registry_values_escape
    from .credential_role_constructor_provider import _terminal_registry_escape
    from .credential_role_constructor_provider import _terminal_registry_escape_use
    from .credential_role_constructor_provider import (
        _terminal_registry_alias_assignment,
    )
    from .credential_role_constructor_provider import (
        _terminal_registry_store_value_escape,
    )
    from .credential_role_constructor_provider import _terminal_registry_key_related
    from .finite_capture import _provider_alias_bindings
    from .finite_capture import _provider_paths
    from .import_context import import_source_bases
    from .finite_capture import _provider_mutation_for_node
    from .finite_capture import _provider_call_argument
    from .review_audits import _resolved_ast_name
    from .review_audits import _module_security_aliases
    from .review_audits import _security_aliases
    from .review_audits import _name

    model_helpers = constructor_provider_model_helper_epoch()
    return (
        constructor_provider_bindings_inert,
        constructor_provider_model,
        constructor_provider_model_helper_epoch,
        _captured_mutations_inert,
        finite_provider_mutation_index,
        _import_binding_is_exact,
        resolve_class_chain_with_terminals,
        _terminal_contracts,
        _valid_terminal_contract,
        _class_mro,
        _class_base_reference,
        _external_class_terminal,
        _direct_terminal_import,
        _direct_terminal_import_statement,
        _terminal_alias_unmodified,
        _captured_module_shadows_terminal,
        _captured_terminal_provider_mutation,
        _terminal_provider_related,
        _terminal_mutation_overlaps,
        _terminal_registry_mutation,
        _terminal_registry_node_targets,
        _terminal_registry_augmented_alias,
        _terminal_registry_target,
        _terminal_registry_target_paths,
        _terminal_registry_paths,
        _terminal_registry_call,
        _terminal_registry_call_items,
        _terminal_registry_call_operands,
        _terminal_registry_update_items,
        _terminal_registry_values_escape,
        _terminal_registry_escape,
        _terminal_registry_escape_use,
        _terminal_registry_alias_assignment,
        _terminal_registry_store_value_escape,
        _terminal_registry_key_related,
        _provider_alias_bindings,
        _provider_paths,
        import_source_bases,
        _resolved_ast_name,
        _module_security_aliases,
        _security_aliases,
        _name,
        _overlaps,
        _mutation_overlaps,
        _shared_function_mutation,
        _source_aliases,
        _source_module,
        _has_opaque_owner_capture,
        _owner_call_argument,
        _captured_builtins_mutate_isinstance,
        _owner_reflection_access,
        _contains_owner_escape,
        _safe_isinstance_type,
        _resolved_name,
        _owner_method_mutation,
        _owner_container_paths,
        *constructor_provider_provenance_epoch(),
        _provider_call_argument,
        finite_capture._record_provider_paths,
        finite_capture._record_provider_capture,
        finite_capture._provider_alias_bindings,
        finite_capture._provider_paths,
        _provider_mutation_for_node,
        finite_capture._reflective_provider_write,
        *model_helpers,
    )


def _has_opaque_owner_capture(
    index, aliases_by_path, owners, filtered, field_aliases, consumers
):
    builtin_stable = not _captured_builtins_mutate_isinstance(index)
    classes = class_index(index, aliases_by_path)
    for path, tree in index.snapshots.items():
        aliases, parents = aliases_by_path[path], index.parents[path]
        fields = field_aliases

        ordinary_type = partial(
            ordinary_type_operand,
            tree=tree,
            parents=parents,
            index=index,
            classes=classes,
            aliases=aliases,
            owners=owners,
            aliases_by_path=aliases_by_path,
        )

        for node in ast.walk(tree):
            if id(node) in filtered.get(path, set()):
                continue
            if _owner_reflection_access(node, aliases, owners, fields):
                return True
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                value = node.value
                if (
                    isinstance(value, ast.Call)
                    and not value.args
                    and not value.keywords
                    and owner_path(value.func, aliases, fields) in owners
                ):
                    continue
                if _contains_owner_escape(
                    value,
                    tree,
                    parents,
                    aliases,
                    owners,
                    builtin_stable,
                    fields,
                    ordinary_type,
                ):
                    return True
            returned = _returned_value(node)
            if returned is not None and _contains_owner_escape(
                returned,
                tree,
                parents,
                aliases,
                owners,
                builtin_stable,
                fields,
                ordinary_type,
            ):
                return True
            if isinstance(node, (ast.Name, ast.Attribute)) and _owner_call_argument(
                node,
                path,
                tree,
                parents,
                index,
                aliases,
                classes,
                owners,
                builtin_stable,
                fields,
                consumers,
                ordinary_type,
                aliases_by_path,
            ):
                return True
    return False


def _returned_value(node):
    return (
        node.value if isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)) else None
    )


def _captured_builtins_mutate_isinstance(index):
    return any(
        isinstance(node, ast.Name)
        and node.id == "__builtins__"
        or isinstance(node, ast.Constant)
        and node.value in {"builtins", "__builtins__"}
        or isinstance(node, ast.Import)
        and any(item.name == "builtins" for item in node.names)
        or isinstance(node, ast.ImportFrom)
        and node.module == "builtins"
        or isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"exec", "eval"}
        for tree in index.snapshots.values()
        for node in ast.walk(tree)
    )


def _owner_reflection_access(node, aliases, owners, fields):
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return owner_path(node.value, aliases, fields) in owners
    return bool(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == "client_class"
        and owner_path(node.args[0], aliases, fields) in owners
    )


def _owner_call_argument(
    node,
    path,
    tree,
    parents,
    index,
    aliases,
    classes,
    owners,
    builtin_stable,
    fields,
    consumers,
    ordinary_type,
    aliases_by_path,
):
    from .finite_capture import _provider_call_argument

    if (
        owner_path(node, aliases, fields) not in owners
        or not _provider_call_argument(node, parents)
        or _safe_isinstance_type(node, tree, parents, builtin_stable, ordinary_type)
    ):
        return False
    consumer = source_owner_consumer(
        node,
        path,
        tree,
        parents,
        index,
        aliases,
        classes,
        owners,
        builtin_stable,
        aliases_by_path,
    )
    if consumer is None:
        return True
    consumers.add(consumer)
    return False


def _contains_owner_escape(
    value, tree, parents, aliases, owners, builtin_stable, fields, ordinary_type
):
    return any(
        owner_path(item, aliases, fields) in owners
        and not _safe_isinstance_type(
            item, tree, parents, builtin_stable, ordinary_type
        )
        and getattr(parents.get(id(item)), "func", None) is not item
        for item in ast.walk(value)
        if isinstance(item, (ast.Name, ast.Attribute))
    )


def _safe_isinstance_type(node, tree, parents, builtin_stable, ordinary_type=None):
    call = parents.get(id(node))
    while call is not None and not isinstance(call, ast.Call):
        call = parents.get(id(call))
    if (
        not isinstance(call, ast.Call)
        or not isinstance(call.func, ast.Name)
        or call.func.id != "isinstance"
        or len(call.args) != 2
        or call.args[1] is not node
        or call.keywords
        or not builtin_stable
        or binding_occurrences(tree.body, "isinstance")
        or ordinary_type is None
        or not ordinary_type(call.args[1])
    ):
        return False
    scope = parents.get(id(call))
    while scope is not None:
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
            args.extend(arg for arg in (scope.args.vararg, scope.args.kwarg) if arg)
            if any(arg.arg == "isinstance" for arg in args) or binding_occurrences(
                scope.body, "isinstance"
            ):
                return False
        elif isinstance(scope, ast.ClassDef) and binding_occurrences(
            scope.body, "isinstance"
        ):
            return False
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
            isinstance(item, (ast.Global, ast.Nonlocal)) and "isinstance" in item.names
            for item in ast.walk(scope)
        ):
            return False
        scope = parents.get(id(scope))
    return True


def constructor_provider_model(selected, index, imports, source_aliases, capture_guard):
    """Construct the provider model only when every source snapshot and selector, inheritance, alias, and capture guard is complete."""
    from .review_audits import _resolved_ast_name

    roots, owners, shared = set(selected), set(), set()
    filtered, aliases_by_path, field_aliases, consumers = {}, {}, {}, set()
    for path, tree in index.snapshots.items():
        if not index.validate(path):
            return None
        aliases_by_path[path] = source_aliases(path, tree, imports.get(path, {}), index)
    if (
        not _class_selector_edges(
            index, aliases_by_path, roots, owners, filtered, _resolved_ast_name
        )
        or not _class_descendant_edges(
            index, aliases_by_path, selected, owners, roots, shared, _resolved_ast_name
        )
        or not _instance_aliases(
            index,
            aliases_by_path,
            owners,
            roots,
            filtered,
            field_aliases,
            _resolved_ast_name,
        )
        or capture_guard(
            index, aliases_by_path, owners, filtered, field_aliases, consumers
        )
    ):
        return None
    return roots, aliases_by_path, filtered, shared, field_aliases, consumers


def _class_selector_edges(index, aliases_by_path, roots, owners, filtered, resolve):
    for path, tree in index.snapshots.items():
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            owner = index.parents[path].get(id(node))
            if (
                len(targets) != 1
                or not isinstance(targets[0], ast.Name)
                or targets[0].id != "client_class"
                or not isinstance(node.value, (ast.Name, ast.Attribute))
                or not isinstance(owner, ast.ClassDef)
            ):
                continue
            owner = ast.Name(id=owner.name, ctx=ast.Load())
            owner_path = resolve(owner, aliases_by_path[path])
            if resolve(node.value, aliases_by_path[path]) not in roots:
                continue
            if not owner_path.startswith("captured_"):
                return False
            roots.add(owner_path + ".client_class")
            owners.add(owner_path)
            filtered.setdefault(path, set()).add(id(node))
    return True


def _class_descendant_edges(
    index, aliases_by_path, selected, owners, roots, shared, resolve
):
    init_classes = set(selected)
    for _ in range(16):
        changed = False
        for path, tree in index.snapshots.items():
            aliases, parents = aliases_by_path[path], index.parents[path]
            for child in (item for item in tree.body if isinstance(item, ast.ClassDef)):
                result = _descendant_edges_for_class(
                    child,
                    aliases,
                    parents,
                    owners,
                    roots,
                    init_classes,
                    shared,
                    resolve,
                )
                if result is None:
                    return False
                changed |= result
        if not changed:
            return True
    return False


def _descendant_edges_for_class(
    child, aliases, parents, owners, roots, init_classes, shared, resolve
):
    path = resolve(ast.Name(child.name, ast.Load()), aliases)
    bases = [resolve(base, aliases) for base in child.bases]
    selector_parent = any(base in owners for base in bases)
    init_parent = any(base in init_classes for base in bases)
    if not selector_parent and not init_parent:
        return False
    if len(bases) != 1 or not path.startswith("captured_"):
        return None
    changed = False
    if selector_parent and path not in owners:
        field = class_binding(child, "client_class", parents)
        value = (
            resolve(field, aliases) if field is not None and field is not False else ""
        )
        if field is False or (
            field is not None
            and value not in roots
            and not value.startswith("captured_")
        ):
            return None
        if field is None or value in roots:
            owners.add(path)
            roots.add(path + ".client_class")
            changed = True
    if init_parent:
        override = init_override(child, parents)
        if override is False:
            return None
        if override is None and path not in init_classes:
            init_classes.add(path)
            shared.add(path + ".__init__")
            changed = True
    return changed


def _instance_aliases(
    index, aliases_by_path, owners, roots, filtered, field_aliases, resolve
):
    for path, tree in index.snapshots.items():
        aliases = aliases_by_path[path]
        if not capture_holder_instances(
            tree,
            index.parents[path],
            aliases,
            owners,
            roots,
            path,
            filtered,
            field_aliases,
            resolve,
        ):
            return False
        if not instance_selector_edges(
            tree, aliases, owners, roots, path, filtered, resolve
        ):
            return False
    return True


def constructor_provider_model_helper_epoch():
    """Return the helper functions that determine constructor-provider model cache epochs."""
    from .review_audits import _resolved_ast_name

    return (
        constructor_provider_model,
        _class_selector_edges,
        _class_descendant_edges,
        _descendant_edges_for_class,
        _instance_aliases,
        binding_occurrences,
        _resolved_ast_name,
        *constructor_provider_provenance_epoch(),
    )


def constructor_bindings_inert(chain, index, imports):
    """Reject captured mutations/escapes of the selected constructor providers."""

    def derive():
        return _constructor_provider.constructor_provider_bindings_inert(
            chain, index, imports
        )

    memo = getattr(index, "class_chain_memo", None)
    if memo is None or index is not memo.index or imports is not memo.imports:
        return derive()
    key = (
        "constructor-provider-bindings",
        tuple((path, name, id(owner)) for path, name, owner in chain),
    )
    return memo.source_model(key, derive, helper_epoch=_constructor_provider_epoch)


def _constructor_provider_epoch():
    from importlib import import_module

    modules = (
        _finite_capture,
        *(
            import_module("." + name, __package__)
            for name in ("credential_role_constructor_provider",)
        ),
    )
    mutation_helpers = tuple(
        helper
        for module in modules
        for _, helper in sorted(vars(module).items())
        if callable(helper)
    )
    helpers = (
        constructor_bindings_inert,
        _constructor_provider_epoch,
        SourceSnapshotIndex._matches_snapshot,
        _ast_matches_source,
        *_constructor_provider.constructor_provider_helper_epoch(),
        *mutation_helpers,
    )
    return tuple(
        identity
        for helper in helpers
        for identity in (helper, getattr(helper, "__code__", None))
    )


def direct_factory_call(call, function, index, path):
    """Recognize a direct factory call only when it is the instance method's immediate return or assignment value."""
    owner = index.parents[path].get(id(function))
    if not instance_receiver(call, function, owner, index, path):
        return False
    statement = index.parents[path].get(id(call))
    return (
        statement in function.body
        and isinstance(statement, (ast.Return, ast.Assign, ast.AnnAssign))
        and statement.value is call
    )


def exact_parameter_field(ctor, assignment, param, index, path):
    """Accept a constructor field binding only when one parameter read feeds one instance-field write with no reflective mutation."""
    if assignment not in ctor.body or binding_occurrences(ctor.body, param):
        return False
    target = assignment.targets[0]
    owner = index.parents[path].get(id(ctor))
    if not instance_receiver(target, ctor, owner, index, path):
        return False
    return (
        _exact_parameter_read(ctor, assignment, param)
        and _unique_parameter_field_write(ctor, target)
        and not any(_reflective_mutation(n, target.attr) for n in ast.walk(ctor))
    )


def _exact_parameter_read(ctor, assignment, param):
    reads = [
        n
        for n in ast.walk(ctor)
        if isinstance(n, ast.Name) and n.id == param and isinstance(n.ctx, ast.Load)
    ]
    return len(reads) == 1 and reads[0] is assignment.value


def _unique_parameter_field_write(ctor, target):
    writes = [
        n
        for n in ast.walk(ctor)
        if isinstance(n, ast.Attribute)
        and n.attr == target.attr
        and isinstance(n.ctx, (ast.Store, ast.Del))
    ]
    return len(writes) == 1 and writes[0] is target


def _reflective_mutation(node, field):
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return isinstance(node.value, ast.Name) and node.value.id == "self"
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"setattr", "delattr", "exec", "locals", "vars"}
    ):
        return False
    if node.func.id in {"exec", "locals", "vars"}:
        return True
    return bool(
        node.args
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "self"
        and (
            len(node.args) < 2
            or not isinstance(node.args[1], ast.Constant)
            or node.args[1].value == field
        )
    )


def _function_alias(expression, function, source_name, use_line):
    if isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
        return expression.value.id == "self" and expression.attr == source_name
    if not isinstance(expression, ast.Name):
        return False
    from .credential_role_constructor_provider import binding_occurrences

    bindings = binding_occurrences(function.body, expression.id)
    if len(bindings) != 1 or not isinstance(bindings[0], ast.Name):
        return False
    rows = []
    for statement in function.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
        )
        if any(
            isinstance(target, ast.Name) and target.id == expression.id
            for target in targets
        ):
            rows.append(statement)
    return (
        len(rows) == 1
        and rows[0].lineno < use_line
        and isinstance(rows[0].value, ast.Attribute)
        and isinstance(rows[0].value.value, ast.Name)
        and rows[0].value.value.id == "self"
        and rows[0].value.attr == source_name
    )


def _hop(index, path, node, role):
    if not index.validate(path):
        return None
    relative = index.relative(path)
    if relative is None:
        return None
    raw = index.source_bytes[path]
    return {
        "path": relative,
        "line": node.lineno,
        "column": node.col_offset,
        "end_line": getattr(node, "end_lineno", node.lineno),
        "end_column": getattr(node, "end_col_offset", node.col_offset),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "role": role,
    }


def constructor_url_hops(
    fact, sink_path, call, expression, index, imports, classes, audit, integrity
):
    """Return verified transfer hops, or None when any source binding is ambiguous."""
    if not index.validate(sink_path):
        return None
    candidate = _constructor_candidate_context(fact, index, imports, classes, audit)
    if candidate is None:
        return None
    candidate_chain, client_path, client_expr, client_attr, client_ref, client_chain = (
        candidate
    )
    transfer = _find_constructor_transfer(
        fact, candidate_chain, client_chain, index, imports, classes, audit, integrity
    )
    if transfer is None:
        return None
    ctor_call, factory, ctor, assignment, param, factory_path, ctor_path = transfer
    sink = _verified_constructor_sink(
        call,
        expression,
        sink_path,
        ctor,
        assignment,
        client_ref,
        ctor_path,
        index,
        imports,
        classes,
        audit,
    )
    if sink is None:
        return None
    sink_function, field = sink
    return build_hops(
        fact,
        index,
        client_path,
        client_expr,
        client_attr,
        ctor_call,
        factory,
        ctor,
        assignment,
        call,
        param,
        factory_path,
        ctor_path,
        sink_path,
    )


def _constructor_candidate_context(fact, index, imports, classes, audit):
    candidate_path = index.root / fact.path
    candidate_chain = class_chain(
        index, candidate_path, fact.owner, imports, classes, audit
    )
    if not candidate_chain or fact.owner == "<module>":
        return None
    client_attr = class_attribute(candidate_chain, "client_class")
    if client_attr is None:
        return None
    client_path, client_expr = client_attr
    client_ref = resolve_class(client_path, client_expr, imports, classes)
    if client_ref is None:
        return None
    client_chain = class_chain(index, *client_ref, imports, classes, audit)
    if not client_chain or not constructor_bindings_inert(client_chain, index, imports):
        return None
    return (
        candidate_chain,
        client_path,
        client_expr,
        client_attr,
        client_ref,
        client_chain,
    )


def _verified_constructor_sink(
    call,
    expression,
    sink_path,
    ctor,
    assignment,
    client_ref,
    ctor_path,
    index,
    imports,
    classes,
    audit,
):
    sink_owner = scope_class(call, index, sink_path)
    if not _inherits_transfer(
        sink_path,
        sink_owner,
        client_ref,
        ctor_path,
        ctor,
        index,
        imports,
        classes,
        audit,
    ):
        return None
    sink_function = _enclosing_function(call, index, sink_path)
    field = _assignment_field(assignment)
    if not instance_receiver(call, sink_function, sink_owner, index, sink_path):
        return None
    if sink_function is None or not _function_alias(
        expression, sink_function, field, call.lineno
    ):
        return None
    return sink_function, field


def _inherits_transfer(
    path, owner, origin, ctor_path, ctor, index, imports, classes, audit
):
    if owner is None:
        return False
    chain = class_chain(index, path, owner.name, imports, classes, audit)
    selected = class_chain(index, *origin, imports, classes, audit)
    if not chain or not selected:
        return False
    descendant = origin in {(p, name) for p, name, _ in chain}
    ancestor = (path, owner.name) in {(p, name) for p, name, _ in selected}
    active_chain = chain if descendant else selected
    return bool(
        (descendant or ancestor)
        and effective_method(active_chain, "__init__") == (ctor_path, ctor)
    )


def _find_constructor_transfer(
    fact, chain, client_chain, index, imports, classes, audit, integrity
):
    factory_row = effective_method(chain, "get_client")
    ctor_row = effective_method(client_chain, "__init__")
    if factory_row is None or ctor_row is None:
        return None
    factory_path, factory = factory_row
    ctor_path, ctor = ctor_row
    candidates = []
    for call in (node for node in ast.walk(factory) if isinstance(node, ast.Call)):
        func = call.func
        if not isinstance(func, ast.Attribute) or func.attr != "client_class":
            continue
        if not isinstance(func.value, ast.Name) or func.value.id != "self":
            continue
        if not direct_factory_call(call, factory, index, factory_path):
            continue
        matching = [
            arg
            for arg in call.args
            if matches_fact(fact, factory_path, arg, index, imports, classes, audit)
        ]
        if len(matching) != 1:
            continue
        try:
            bound = integrity.bind_source_call(
                call, ctor, ast.Name("_bound_self", ast.Load()), apply_defaults=False
            )
        except (TypeError, ValueError):
            continue
        param = next(
            (name for name, value in bound.items() if value is matching[0]), None
        )
        if param is None:
            continue
        assignments = [
            node
            for node in ctor.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Attribute)
            and isinstance(node.targets[0].value, ast.Name)
            and node.targets[0].value.id == "self"
            and isinstance(node.value, ast.Name)
            and node.value.id == param
        ]
        assignments = [
            node
            for node in assignments
            if exact_parameter_field(ctor, node, param, index, ctor_path)
        ]
        if len(assignments) == 1:
            candidates.append(
                (call, factory, ctor, assignments[0], param, factory_path, ctor_path)
            )
    return candidates[0] if len(candidates) == 1 else None


def _assignment_field(node):
    target = node.targets[0]
    return target.attr if isinstance(target, ast.Attribute) else None


def _enclosing_function(node, index, path):
    current = node
    while current is not None:
        current = index.parents[path].get(id(current))
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
    return None


def build_hops(
    fact,
    index,
    client_path,
    client_expr,
    client_attr,
    ctor_call,
    factory,
    ctor,
    assignment,
    sink,
    param,
    factory_path,
    ctor_path,
    sink_path,
):
    """Build source-hashed provenance hops from the literal declaration through client selection and constructor binding to the HTTP sink."""
    fact_path = index.root / fact.path
    fact_node = next(
        (
            node
            for node in ast.walk(index.snapshots[fact_path])
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            and getattr(node, "lineno", 0) == fact.line
            and getattr(node, "value", None) is not None
            and isinstance(node.value, ast.Constant)
            and node.value.value == fact._literal
        ),
        None,
    )
    param_node = next((node for node in ctor.args.args if node.arg == param), None)
    value_argument = next(
        (
            arg
            for arg in ctor_call.args
            if isinstance(arg, ast.Attribute) and arg.attr == fact.member
        ),
        None,
    )
    nodes = [
        (fact_path, fact_node, "declared_literal"),
        (client_path, client_expr, "client_class_selection"),
        (factory_path, value_argument, "constructor_argument"),
        (ctor_path, param_node, "constructor_parameter"),
        (ctor_path, assignment.targets[0], "constructor_field_binding"),
        (sink_path, sink, "canonical_http_url_consumer"),
    ]
    hops = [_hop(index, path, node, role) for path, node, role in nodes]
    return hops if all(hops) else None
