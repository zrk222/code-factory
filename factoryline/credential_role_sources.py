"""Source-bound literal declarations for semantic role-flow evidence."""

from dataclasses import dataclass, field
import ast
import hashlib
from pathlib import Path


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
        self._relative_root, self._relative_paths = self.root, {}
        self.bounded = (
            isinstance(inventory, dict)
            and set(snapshots) == set(source_bytes) == set(inventory)
            and len(snapshots) <= 2000
            and all(isinstance(raw, bytes) for raw in source_bytes.values())
            and sum(len(raw) for raw in source_bytes.values()) <= 32 * 1024 * 1024
        )

    def validate(self, path):
        if path in self.validated:
            return self.validated[path]
        tree, raw = self.snapshots.get(path), self.source_bytes.get(path)
        digest = hashlib.sha256(raw).hexdigest() if isinstance(raw, bytes) else None
        valid = bool(
            self.bounded
            and isinstance(tree, ast.Module)
            and isinstance(raw, bytes)
            and len(raw) <= 1_000_000
            and self.inventory.get(path) == digest
            and getattr(tree, "_oracle_source_sha256", None) == digest
        )
        if valid:
            try:
                valid = ast.dump(ast.parse(raw), include_attributes=True) == ast.dump(
                    tree, include_attributes=True
                )
            except (SyntaxError, ValueError, TypeError, RecursionError, MemoryError):
                valid = False
        self.validated[path] = valid
        if valid:
            self.parents[path] = {
                id(child): node
                for node in ast.walk(tree)
                for child in ast.iter_child_nodes(node)
            }
        return valid

    def relative(self, path):
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


def source_session_factories(tree, aliases):
    from .security_configuration import _canonical

    rows = {}
    for function in tree.body:
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        assigned, returned = [], []
        for statement in ast.walk(function):
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = (
                    statement.targets
                    if isinstance(statement, ast.Assign)
                    else [statement.target]
                )
                if (
                    len(targets) == 1
                    and isinstance(targets[0], ast.Name)
                    and isinstance(statement.value, ast.Call)
                ):
                    if _canonical(statement.value, aliases) == "requests.Session":
                        assigned.append(targets[0].id)
            if isinstance(statement, ast.Return) and isinstance(
                statement.value, ast.Name
            ):
                returned.append(statement.value.id)
        if len(assigned) == len(returned) == 1 and assigned == returned:
            rows[function.name] = {"requests.Session"}
    return {name for name, values in rows.items() if values == {"requests.Session"}}


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
    _literal: str = field(repr=False)

    def public_facts(self):
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
        for path, tree in source.snapshots.items() if self.complete else ():
            for node in ast.walk(tree):
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
        fact = declaration_fact(self.source, path, node) if self.complete else None
        if fact is None:
            return {"eligible": False, "reason": "unbound or incomplete declaration"}
        if fact.source_role == "class_literal":
            uses = self._schema_uses(fact)
            profile = "JSON_SCHEMA_ANNOTATION"
        elif fact.source_role == "module_literal":
            uses = self._mask_uses(fact)
            profile = "MASKING_SENTINEL"
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
        from .credential_role_bindings import class_chain

        return class_chain(
            self.source, path, name, self.imports, self.classes, self.audit
        )

    def _schema_uses(self, fact):
        from .credential_role_bindings import _scope
        from .credential_role_scope_bindings import binding_occurrences

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
        from .credential_role_scope_bindings import resolve_class

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
        from .credential_role_bindings import matches_fact

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
            parents = self.source.parents[path]
            role = _presentation_mask_output(
                node, parents
            ) or _presentation_mask_restore(node, parents)
            if role is None:
                return None
            uses.append(self._witness(path, node, role))
        return (
            uses
            if {row["role"] for row in uses}
            == {"MASK_OUTPUT", "PRESERVE_PREVIOUS_VALUE"}
            else None
        )

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
    from .credential_role_scope_bindings import binding_occurrences

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
    from .credential_role_scope_bindings import binding_occurrences

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
    from .credential_role_scope_bindings import binding_occurrences

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
    from .credential_role_scope_bindings import binding_occurrences

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
    from .credential_role_bindings import _scope
    from .credential_role_scope_bindings import (
        function_bindings,
        module_literal_binding,
    )

    if (
        isinstance(node, ast.Attribute)
        and node.attr == fact.member
        and isinstance(node.value, ast.Name)
    ):
        from .credential_role_scope_bindings import import_is_stable

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
    from .credential_role_scope_bindings import binding_occurrences

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
    from .credential_role_scope_bindings import binding_occurrences

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
