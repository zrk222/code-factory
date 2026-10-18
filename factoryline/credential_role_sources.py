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
        self.bounded = (
            isinstance(inventory, dict)
            and set(snapshots) == set(source_bytes) == set(inventory)
            and len(snapshots) <= 2000
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
            return Path(path).relative_to(self.root).as_posix()
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
