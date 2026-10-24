"""Shared machine-readable provenance envelope for FactoryLine itself."""

from __future__ import annotations

import ast
import hashlib
import importlib.metadata
import json
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

from .finite_capture import (
    _FiniteInputCapture,
    finite_blocked_provider_prefixes,
    finite_provider_attribute_write_index,
    finite_scope_binding_candidate,
)

from . import __version__
from ._build_provenance import SOURCE_COMMIT


class _LiteralConsumers(_FiniteInputCapture):
    def __init__(
        self, root, snapshots, imports, audit, integrity, *, source_bytes, inventory
    ):
        self.root, self.trees, self.imports = root, snapshots, imports
        self.audit, self.integrity = audit, integrity
        self.parents, self.objects, self.refs = {}, {}, defaultdict(list)
        self.functions, self.methods, self.node_paths = {}, {}, {}
        self.fixture_cache, self.provider_cache = {}, {}
        self.app_fixture_cache = {}
        self.assignment_cache = {}
        self.aliases, self.blocked, self.members = {}, set(), {}
        self.unmodeled_imports = []
        self.provider_closure = {}
        self.provider_attribute_writes = set()
        self.provider_blocked_prefixes = set()
        self.source_profiles = {}
        self.pending_fixture_parameters = []
        self.file_indexes = {}
        self.complete = True
        self.snapshot_complete = True
        self.source_bytes = source_bytes
        self.inventory = inventory
        self.remaining_work = 1_000_000
        self.enum_demand_only = False
        self.enum_demand_complete = False
        self.enum_demand_witnesses = {}
        self.enum_demand_rejected_keys = set()
        self.enum_demand_rejection_details = {}
        self.demand_unresolved_imports = set()
        self.enum_demand_stats = {}
        if (
            set(snapshots) != set(imports)
            or set(snapshots) != set(source_bytes)
            or not isinstance(inventory, dict)
            or set(snapshots) != set(inventory)
        ):
            self._snapshot_incomplete()
            return
        if (
            len(snapshots) > 2000
            or sum(map(len, source_bytes.values())) > 32 * 1024 * 1024
        ):
            self._snapshot_incomplete()
            return
        self.eligible = {path.resolve(): path for path in snapshots}
        self.aliases = {
            path: self.audit._module_security_aliases(tree)
            for path, tree in snapshots.items()
        }
        if len(snapshots) > 200:
            self.enum_demand_only = True
            self._build_enum_demand_index()
            self.complete = False
            return
        total = 0
        for path, tree in snapshots.items():
            raw = source_bytes[path]
            if not self._snapshot_valid(path, tree, raw):
                self._snapshot_incomplete()
                return
            indexed = self._index_source_nodes(path, tree, total)
            if indexed is None:
                return
            total, nodes, scope_nodes, load_names, provider_imports = indexed
            self.parents.update(
                {id(c): n for n in nodes for c in ast.iter_child_nodes(n)}
            )
            self.provider_attribute_writes.update(
                finite_provider_attribute_write_index(
                    nodes, self.aliases[path], self.audit, self.parents
                )
            )
            self.integrity.bind_security_call_scopes(tree)
            self._objects(path, tree)
            origins = (
                set(self.imports[path])
                | {name for p, name in self.objects if p == path}
                | {name for p, name in self.functions if p == path}
            )
            scope_nodes = [
                n for n in scope_nodes if finite_scope_binding_candidate(n, origins)
            ]
            self.file_indexes[path] = (
                nodes,
                scope_nodes,
                origins,
                load_names,
                provider_imports,
            )
        for path, (nodes, scope_nodes, origins, _, _) in self.file_indexes.items():
            self._bindings(path, nodes, scope_nodes, origins)
        self._bind_guarded_script_imports()
        self._finalize_fixture_parameters()
        self._references()
        self._reject_unmodeled_origins()
        self._provider_uses()

    def _build_enum_demand_index(self):
        """Index candidate enum bindings and references without retaining irrelevant AST nodes."""
        try:
            for path, tree in self.trees.items():
                if not self._snapshot_valid(path, tree, self.source_bytes[path]):
                    self._snapshot_incomplete()
                    return
                nodes = list(self._walk(tree))
                parents = {
                    id(child): node
                    for node in nodes
                    for child in ast.iter_child_nodes(node)
                }
                self.provider_attribute_writes.update(
                    finite_provider_attribute_write_index(
                        nodes, self.aliases[path], self.audit, parents
                    )
                )
            self.snapshot_complete = True

            for path, tree in self.trees.items():
                tree._security_scope_kind = "module"
                binding_counts = defaultdict(int)
                for statement in tree.body:
                    if isinstance(statement, ast.ClassDef):
                        statement._security_parent_scope = tree
                        statement._security_scope_kind = "class"
                        for item in statement.body:
                            if isinstance(item, (ast.Assign, ast.AnnAssign)):
                                item._security_lexical_scope = statement
                        self.objects[path, statement.name] = statement
                        bases = [
                            self.audit._resolved_ast_name(base, self.aliases[path])
                            for base in statement.bases
                        ]
                        if bases == ["str", "enum.Enum"]:
                            self._class_members(path, statement)
                    elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.functions[path, statement.name] = statement
                    elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                        targets = (
                            statement.targets
                            if isinstance(statement, ast.Assign)
                            else [statement.target]
                        )
                        value = statement.value
                        if (
                            len(targets) == 1
                            and isinstance(targets[0], ast.Name)
                            and isinstance(value, (ast.Name, ast.Attribute, ast.Call))
                        ):
                            self.objects[path, targets[0].id] = value
                            if isinstance(value, (ast.Name, ast.Attribute)):
                                binding_counts[targets[0].id] += 1
                                self.demand_static_aliases = getattr(
                                    self, "demand_static_aliases", set()
                                )
                                self.demand_static_aliases.add((path, id(targets[0])))
                for name, count in binding_counts.items():
                    if count != 1:
                        self.blocked.add((path, name))

            enum_classes = {(path, cls) for path, cls, _member in self.members}
            if not enum_classes:
                self.enum_demand_complete = True
                return

            module_relevance = {}
            relevant_roots = {path: set() for path in self.trees}
            relevant_paths = {path for path, _cls in enum_classes}
            for path in self.trees:
                names = (
                    set(self.imports[path])
                    | {name for owner, name in self.objects if owner == path}
                    | {name for owner, name in self.functions if owner == path}
                )
                for name in names:
                    resolved = self.resolve(path, (name,))
                    if (
                        resolved is not None
                        and resolved[0] == "class"
                        and resolved[1:3] in enum_classes
                    ):
                        relevant_roots[path].add(name)
                        relevant_paths.add(path)
                    elif resolved is not None and resolved[0] == "module":
                        source = resolved[1]
                        if source not in module_relevance:
                            module_relevance[source] = self._relevant_origin(
                                source, None
                            )
                        if module_relevance[source]:
                            relevant_roots[path].add(name)
                            relevant_paths.add(path)
            if not self.complete:
                return

            # Star imports cannot be matched to a finite native binding view.
            # They remain a workspace-level unresolved edge.
            if any(
                isinstance(statement, ast.ImportFrom)
                and any(alias.name == "*" for alias in statement.names)
                for tree in self.trees.values()
                for statement in tree.body
            ):
                return

            unsupported_nodes = []
            enum_members_by_class = defaultdict(set)
            for member_path, member_class, member_name in self.members:
                enum_members_by_class[member_path, member_class].add(member_name)
            self.demand_reference_scopes = {}
            self.demand_unsupported_scopes = []
            for path, tree in self.trees.items():
                if path not in relevant_paths:
                    continue
                ancestors = []
                stack = [(tree, False)]
                while stack:
                    node, exiting = stack.pop()
                    if exiting:
                        ancestors.pop()
                        continue
                    if not self._tick():
                        return
                    if isinstance(node, ast.ImportFrom) and any(
                        alias.name == "*" for alias in node.names
                    ):
                        unsupported_nodes.append((path, node, tuple(ancestors)))
                    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
                        unsupported_nodes.append((path, node, tuple(ancestors)))
                    if isinstance(node, ast.Call):
                        call_name = self.audit._resolved_ast_name(
                            node.func, self.aliases[path]
                        )
                        if call_name in {
                            "builtins.__import__",
                            "__import__",
                            "importlib.import_module",
                            "builtins.eval",
                            "eval",
                            "builtins.exec",
                            "exec",
                            "globals",
                            "locals",
                            "vars",
                            "getattr",
                            "setattr",
                            "delattr",
                        }:
                            unsupported_nodes.append((path, node, tuple(ancestors)))

                    if isinstance(node, (ast.Name, ast.arg)):
                        bound_name = node.id if isinstance(node, ast.Name) else node.arg
                        if isinstance(node, ast.arg) or isinstance(
                            node.ctx, (ast.Store, ast.Del)
                        ):
                            if (
                                isinstance(node, ast.Name)
                                and isinstance(node.ctx, ast.Store)
                                and (path, id(node))
                                in getattr(self, "demand_static_aliases", set())
                                and (path, bound_name) not in self.blocked
                            ):
                                pass
                            elif bound_name in relevant_roots[path]:
                                resolved_binding = self.resolve(path, (bound_name,))
                                if (
                                    resolved_binding is not None
                                    and resolved_binding[0] == "class"
                                    and resolved_binding[1:3] in enum_classes
                                ):
                                    for member_name in enum_members_by_class[
                                        resolved_binding[1:3]
                                    ]:
                                        key = (*resolved_binding[1:3], member_name)
                                        self.enum_demand_rejected_keys.add(key)
                                        self.enum_demand_rejection_details.setdefault(
                                            key, (path, node.lineno, "rebinding")
                                        )

                    if isinstance(node, ast.Attribute) and isinstance(
                        node.ctx, (ast.Store, ast.Del)
                    ):
                        root_name = self.audit._name(node).split(".", 1)[0]
                        resolved_write = (
                            self.resolve(path, tuple(self.audit._name(node).split(".")))
                            if root_name in relevant_roots[path]
                            else None
                        )
                        if (
                            resolved_write is not None
                            and resolved_write[0] == "class"
                            and resolved_write[1:3] in enum_classes
                            and resolved_write[3]
                        ):
                            written_member = resolved_write[3][0]
                            names = enum_members_by_class[resolved_write[1:3]]
                            affected = (
                                {written_member} if written_member in names else names
                            )
                            for member_name in affected:
                                key = (*resolved_write[1:3], member_name)
                                self.enum_demand_rejected_keys.add(key)
                                self.enum_demand_rejection_details.setdefault(
                                    key, (path, node.lineno, "member mutation")
                                )

                    if (
                        isinstance(node, ast.Name)
                        and isinstance(node.ctx, ast.Load)
                        and node.id in relevant_roots[path]
                    ):
                        end = node
                        for parent in reversed(ancestors):
                            if (
                                isinstance(parent, ast.Attribute)
                                and parent.value is end
                            ):
                                end = parent
                            else:
                                break
                        resolved = self.resolve(
                            path, tuple(self.audit._name(end).split("."))
                        )
                        if (
                            resolved is not None
                            and resolved[0] == "class"
                            and resolved[1:3] in enum_classes
                        ):
                            chain = (*ancestors, node)
                            for index in range(1, len(chain)):
                                self.parents[id(chain[index])] = chain[index - 1]
                            self.refs[resolved[:3]].append((path, end, resolved[3]))
                            self.demand_reference_scopes[path, id(end)] = (
                                self._demand_lexical_scope(ancestors, tree),
                                tuple(ancestors),
                            )

                    ancestors.append(node)
                    stack.append((node, True))
                    for child in reversed(list(ast.iter_child_nodes(node))):
                        stack.append((child, False))

            if not self.complete or self.remaining_work < 0:
                return
            for path, unsupported, ancestors in unsupported_nodes:
                unsupported_scope = self._demand_lexical_scope(
                    ancestors, self.trees[path]
                )
                reflection_call = isinstance(
                    unsupported, ast.Call
                ) and self.audit._resolved_ast_name(
                    unsupported.func, self.aliases[path]
                ) in {"getattr", "setattr", "delattr"}
                reflection_receiver = (
                    self._demand_receiver_class(path, unsupported.args[0], ancestors)
                    if reflection_call
                    and unsupported.args
                    and isinstance(unsupported.args[0], (ast.Name, ast.Attribute))
                    else None
                )
                reflection_attr_node = (
                    unsupported.args[1]
                    if reflection_call and len(unsupported.args) > 1
                    else None
                )
                reflection_attr = (
                    reflection_attr_node.value
                    if isinstance(reflection_attr_node, ast.Constant)
                    and type(reflection_attr_node.value) is str
                    else None
                )
                for (kind, enum_path, enum_class), refs in self.refs.items():
                    if kind != "class":
                        continue
                    for reference_path, _node, tail in refs:
                        if reference_path != path:
                            continue
                        reference_scope, reference_ancestors = (
                            self.demand_reference_scopes[reference_path, id(_node)]
                        )
                        same_scope = reference_scope is unsupported_scope
                        if reflection_call:
                            direct_reflection = (
                                unsupported in reference_ancestors or _node in ancestors
                            )
                            if not self._demand_reflection_affects(
                                reflection_receiver,
                                reflection_attr,
                                ("class", enum_path, enum_class),
                                tail,
                                direct_reflection,
                            ):
                                continue
                            same_scope = True
                        direct_dependency = any(
                            item is unsupported for item in reference_ancestors
                        ) or any(item is _node for item in ancestors)
                        if not (same_scope or direct_dependency):
                            continue
                        member_name = tail[0] if tail else None
                        if member_name in enum_members_by_class[enum_path, enum_class]:
                            key = enum_path, enum_class, member_name
                            self.enum_demand_rejected_keys.add(key)
                            self.enum_demand_rejection_details.setdefault(
                                key,
                                (path, unsupported.lineno, type(unsupported).__name__),
                            )
                        else:
                            for name in enum_members_by_class[enum_path, enum_class]:
                                key = enum_path, enum_class, name
                                self.enum_demand_rejected_keys.add(key)
                                self.enum_demand_rejection_details.setdefault(
                                    key,
                                    (
                                        path,
                                        unsupported.lineno,
                                        type(unsupported).__name__,
                                    ),
                                )
            # An unresolved import or star import blocks only enum obligations
            # whose source binding occurs in that same module. It does not
            # poison unrelated enum declarations elsewhere in the corpus.
            for path in relevant_paths:
                uncertain_names = {
                    name
                    for name, origin in self.imports[path].items()
                    if origin is None
                }
                has_star_import = any(
                    isinstance(statement, ast.ImportFrom)
                    and any(alias.name == "*" for alias in statement.names)
                    for statement in self.trees[path].body
                )
                if not uncertain_names and not has_star_import:
                    continue
                for (kind, enum_path, enum_class), refs in self.refs.items():
                    if kind != "class":
                        continue
                    for reference_path, reference, tail in refs:
                        if reference_path != path:
                            continue
                        source_name = self.audit._name(reference).split(".", 1)[0]
                        if has_star_import or source_name in uncertain_names:
                            member_name = tail[0] if tail else None
                            if (
                                member_name
                                in enum_members_by_class[enum_path, enum_class]
                            ):
                                key = enum_path, enum_class, member_name
                                self.enum_demand_rejected_keys.add(key)
                                self.enum_demand_rejection_details.setdefault(
                                    key,
                                    (path, reference.lineno, "unresolved/star import"),
                                )
                            else:
                                for name in enum_members_by_class[
                                    enum_path, enum_class
                                ]:
                                    key = enum_path, enum_class, name
                                    self.enum_demand_rejected_keys.add(key)
                                    self.enum_demand_rejection_details.setdefault(
                                        key,
                                        (
                                            path,
                                            reference.lineno,
                                            "unresolved/star import",
                                        ),
                                    )

            consumer_symbols = self._demand_consumer_symbols()
            effect_paths = set(relevant_paths)
            for path in self.trees:
                names = (
                    set(self.imports[path])
                    | {name for owner, name in self.objects if owner == path}
                    | {name for owner, name in self.functions if owner == path}
                )
                for name in names:
                    resolved = self.resolve(path, (name,))
                    if resolved is not None and resolved[:3] in consumer_symbols:
                        effect_paths.add(path)
            if not self.complete:
                return
            self.enum_effect_paths = effect_paths

            self.enum_demand_witnesses = self._collect_enum_witnesses()
            self.enum_demand_complete = self.complete
            self.enum_demand_stats = {
                "sources_examined": len(self.trees),
                "source_bytes_hashed_and_parsed": sum(
                    map(len, self.source_bytes.values())
                ),
                "candidate_classes": len(enum_classes),
                "candidate_members": len(self.members),
                "candidate_references": sum(map(len, self.refs.values())),
                "relevant_paths": len(relevant_paths),
                "effect_paths": len(effect_paths),
                "unresolved_imports": len(self.demand_unresolved_imports),
                "rejected_member_obligations": len(self.enum_demand_rejected_keys),
                "retained_reference_nodes": len(self.demand_reference_scopes),
            }
        except (
            AttributeError,
            KeyError,
            TypeError,
            ValueError,
            RecursionError,
            MemoryError,
        ):
            self.enum_demand_complete = False

    def _demand_consumer_symbols(self):
        """Find class/helper definitions on candidate enum reference paths."""
        result = set()
        for enum_path, enum_class, member in self.members:
            for path, node, tail in self.refs.get(("class", enum_path, enum_class), []):
                if tail != (member,) or not isinstance(node.ctx, ast.Load):
                    continue
                value = node
                parent = self.parents.get(id(value))
                while isinstance(parent, ast.Tuple) and parent.elts and self._tick():
                    value, parent = parent, self.parents.get(id(parent))
                if not isinstance(parent, ast.keyword):
                    continue
                call = self.parents.get(id(parent))
                if not isinstance(call, ast.Call) or not isinstance(
                    call.func, (ast.Name, ast.Attribute)
                ):
                    continue
                consumer = self.resolve(
                    path, tuple(self.audit._name(call.func).split("."))
                )
                if consumer is None or consumer[0] not in {"class", "function"}:
                    continue
                result.add(consumer[:3])
                if consumer[0] != "function":
                    continue
                helper = self.functions.get(consumer[1:3])
                if not isinstance(helper, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                returns = [item for item in helper.body if isinstance(item, ast.Return)]
                if (
                    len(returns) == 1
                    and isinstance(returns[0].value, ast.Call)
                    and isinstance(returns[0].value.func, (ast.Name, ast.Attribute))
                ):
                    result_class = self.resolve(
                        consumer[1],
                        tuple(self.audit._name(returns[0].value.func).split(".")),
                    )
                    if result_class is not None and result_class[0] == "class":
                        result.add(result_class[:3])
        return result

    @staticmethod
    def _demand_lexical_scope(ancestors, module):
        for item in reversed(ancestors):
            if isinstance(
                item,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef),
            ):
                return item
        return module

    def _demand_reflection_affects(
        self, receiver_class, literal_attr, enum_key, tail, direct_dependency
    ):
        """Tie reflective attribute operations to the enum class or typed field they can reach."""
        if direct_dependency:
            return True
        if receiver_class is None:
            return False
        candidate_class = enum_key[1:3]
        if receiver_class == candidate_class:
            return literal_attr is None or literal_attr == (tail[0] if tail else None)
        definition = self.objects.get(receiver_class)
        if not isinstance(definition, ast.ClassDef):
            return False
        for item in definition.body:
            if not (
                isinstance(item, ast.AnnAssign)
                and isinstance(item.target, ast.Name)
                and (literal_attr is None or item.target.id == literal_attr)
            ):
                continue
            if self._enum_annotation_contains(
                receiver_class[0], item.annotation, enum_key
            ):
                return True
        return False

    def _demand_receiver_class(self, path, expression, ancestors):
        parts = tuple(self.audit._name(expression).split("."))
        if not parts:
            return None
        resolved = self.resolve(path, parts)
        if resolved is not None and resolved[0] == "class" and not resolved[3]:
            return resolved[1:3]
        if len(parts) != 1:
            return None
        name = parts[0]
        scope = self._demand_lexical_scope(ancestors, self.trees[path])
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for argument in (
                *scope.args.posonlyargs,
                *scope.args.args,
                *scope.args.kwonlyargs,
            ):
                if argument.arg == name and argument.annotation is not None:
                    annotation = argument.annotation
                    if (
                        isinstance(annotation, ast.Constant)
                        and type(annotation.value) is str
                    ):
                        if len(annotation.value) > 256:
                            return None
                        try:
                            annotation = ast.parse(annotation.value, mode="eval").body
                        except (SyntaxError, ValueError):
                            return None
                    for node in self._walk(annotation):
                        if isinstance(node, (ast.Name, ast.Attribute)):
                            origin = self.resolve(
                                path, tuple(self.audit._name(node).split("."))
                            )
                            if origin is not None and origin[0] == "class":
                                return origin[1:3]
            assignments = [
                node
                for node in self._walk(scope)
                if isinstance(node, (ast.Assign, ast.AnnAssign))
                and any(
                    isinstance(target, ast.Name) and target.id == name
                    for target in (
                        node.targets if isinstance(node, ast.Assign) else [node.target]
                    )
                )
            ]
            if len(assignments) == 1:
                value = assignments[0].value
                if isinstance(value, ast.Call) and isinstance(
                    value.func, (ast.Name, ast.Attribute)
                ):
                    origin = self.resolve(
                        path, tuple(self.audit._name(value.func).split("."))
                    )
                    if origin is not None and origin[0] == "class" and not origin[3]:
                        return origin[1:3]
                if isinstance(value, (ast.Name, ast.Attribute)):
                    origin = self.resolve(
                        path, tuple(self.audit._name(value).split("."))
                    )
                    if origin is not None and origin[0] == "class" and not origin[3]:
                        return origin[1:3]
        for owner in reversed(ancestors):
            if isinstance(owner, ast.ClassDef) and name == "self":
                return path, owner.name
        return None

    def _collect_enum_witnesses(self):
        """Apply the same all-reference consumer effects to the demanded enum index."""
        result = {}
        for (path, cls, member), declaration in self.members.items():
            if (path, cls, member) in self.enum_demand_rejected_keys:
                continue
            enum_key = ("class", path, cls)
            refs = self.refs.get(enum_key, [])
            if not refs:
                continue
            if not self._tick(len(refs)):
                return {}
            relevant = [
                (consumer_path, node, tail)
                for consumer_path, node, tail in refs
                if not tail or tail[0] == member
            ]
            if not any(tail == (member,) for _, _, tail in relevant):
                continue
            effects = []
            for consumer_path, node, tail in relevant:
                if not tail:
                    effect = (
                        "ENUM_TYPE_ANNOTATION"
                        if self._enum_type_consumer(consumer_path, node, enum_key)
                        else None
                    )
                elif tail == (member,) and isinstance(node.ctx, ast.Load):
                    if self.public(consumer_path, node):
                        effect = "PUBLIC_ASSERTION_OR_RESPONSE"
                    elif self._enum_metadata_consumer(consumer_path, node, enum_key):
                        effect = "TYPED_METADATA_CONSTRUCTOR"
                    else:
                        effect = None
                else:
                    effect = None
                effects.append(effect)
            if not effects or any(effect is None for effect in effects):
                continue
            result[path, declaration.lineno, member] = [
                {
                    "path": consumer_path.relative_to(self.root).as_posix(),
                    "line": node.lineno,
                    "span": [
                        node.lineno,
                        node.col_offset,
                        node.end_lineno,
                        node.end_col_offset,
                    ],
                    "effect": effect,
                    "source_sha256": getattr(
                        self.trees[consumer_path], "_oracle_source_sha256", None
                    ),
                }
                for (consumer_path, node, _tail), effect in zip(relevant, effects)
            ]
        return result

    def _index_source_nodes(self, path, tree, total):
        nodes = []
        scope_nodes = []
        load_names = []
        provider_imports = []
        for node in self._walk(tree):
            total += 1
            if total > 200_000 or not self._tick(4):
                self._snapshot_incomplete()
                return None
            nodes.append(node)
            self.node_paths[id(node)] = path
            if isinstance(node, (ast.arg, ast.Global, ast.Nonlocal)) or (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, (ast.Store, ast.Del))
            ):
                scope_nodes.append(node)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                load_names.append(node)
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                provider_imports.append(node)
        return total, nodes, scope_nodes, load_names, provider_imports

    def _snapshot_valid(self, path, tree, raw):
        digest = hashlib.sha256(raw).hexdigest()
        if self.inventory[path] != digest or len(raw) > 1_000_000:
            return False
        if digest != getattr(tree, "_oracle_source_sha256", None):
            return False
        try:
            parsed = ast.parse(raw)
            return ast.dump(parsed, include_attributes=True) == ast.dump(
                tree, include_attributes=True
            )
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return False

    def _finalize_fixture_parameters(self):
        self.provider_blocked_prefixes = finite_blocked_provider_prefixes(
            self.blocked, self.aliases
        )
        for path, node in self.pending_fixture_parameters:
            name = node.arg
            if name in self.imports[path] or not self._fixture_parameter_value(
                path, name, node
            ):
                self.blocked.add((path, name))
        self.provider_blocked_prefixes = finite_blocked_provider_prefixes(
            self.blocked, self.aliases
        )

    def _finite_pytest_provider_closed(self, candidate_path):
        if any(name.startswith("pytest_") for _, name in self.functions):
            return False
        if not all(
            self._finite_pytest_tree_closed(path, tree)
            for path, tree in self.trees.items()
        ):
            return False
        return self._provider_is_unmodified(
            "pytest", {"mark", "parametrize", "fixture"}
        )

    def _finite_pytest_tree_closed(self, path, tree):
        return all(
            self._finite_pytest_name_closed(path, node)
            for node in self._walk(tree)
            if isinstance(node, ast.Name)
        )

    def _finite_pytest_name_closed(self, path, node):
        canonical = self.audit._resolved_ast_name(node, self.aliases[path])
        if canonical != "pytest" and not canonical.startswith("pytest."):
            return True
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            return False
        if node.id in getattr(node, "_security_shadowed_names", set()):
            return False
        parent = self.parents.get(id(node))
        if (
            isinstance(parent, ast.Call)
            and parent.func is node
            and canonical.startswith("pytest.")
        ):
            return True
        if not isinstance(parent, ast.Attribute) or parent.value is not node:
            return False
        end = parent
        while isinstance(self.parents.get(id(end)), ast.Attribute):
            end = self.parents[id(end)]
        consumer = self.parents.get(id(end))
        if isinstance(consumer, ast.Call) and consumer.func is end:
            return True
        if (
            isinstance(consumer, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and end in consumer.decorator_list
            and (
                self.audit._resolved_ast_name(end, self.aliases[path])
                == "pytest.fixture"
                or self.audit._resolved_ast_name(end, self.aliases[path]).startswith(
                    "pytest.mark."
                )
            )
        ):
            return True
        if isinstance(consumer, ast.arg) and consumer.annotation is end:
            return True
        return (
            isinstance(consumer, (ast.FunctionDef, ast.AsyncFunctionDef))
            and consumer.returns is end
        )

    @staticmethod
    def _finite_module_initializer_safe(tree):
        pending = list(tree.body)
        local_functions = {
            n.name
            for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        while pending:
            node = pending.pop()
            if (
                isinstance(node, ast.ImportFrom)
                and node.module == "builtins"
                and any(
                    alias.name
                    in {
                        "globals",
                        "locals",
                        "vars",
                        "getattr",
                        "setattr",
                        "delattr",
                        "__import__",
                        "*",
                    }
                    for alias in node.names
                )
            ):
                return False
            if isinstance(node, ast.Name) and node.id in local_functions:
                return False
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                pending.extend(node.decorator_list)
                pending.extend(node.args.defaults)
                pending.extend(value for value in node.args.kw_defaults if value)
                pending.extend(
                    arg.annotation
                    for arg in node.args.posonlyargs
                    + node.args.args
                    + node.args.kwonlyargs
                    if arg.annotation is not None
                )
                if node.returns is not None:
                    pending.append(node.returns)
                continue
            if isinstance(node, ast.Name) and node.id in {
                "globals",
                "locals",
                "vars",
                "getattr",
                "setattr",
                "delattr",
                "__import__",
                "__builtins__",
                "builtins",
            }:
                return False
            if isinstance(node, ast.Attribute) and node.attr in {
                "__dict__",
                "__globals__",
                "__builtins__",
            }:
                return False
            pending.extend(ast.iter_child_nodes(node))
        return True

    def _objects(self, path, tree):
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                self.objects[path, node.name] = node
                self._class_members(path, node)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[path, node.name] = node
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                if len(targets) == 1 and isinstance(targets[0], ast.Name):
                    self.objects[path, targets[0].id] = node.value

    def _class_members(self, path, owner):
        for item in owner.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.methods[path, owner.name, item.name] = item
                continue
            if not isinstance(item, (ast.Assign, ast.AnnAssign)):
                continue
            targets = item.targets if isinstance(item, ast.Assign) else [item.target]
            for target in targets:
                if (
                    isinstance(target, ast.Name)
                    and self.audit._SECRET_ASSIGNMENT.search(target.id)
                    and self.audit._credential_role_witness(
                        item, target, self.aliases[path]
                    )
                ):
                    self.members[path, owner.name, target.id] = item

    def _provider_uses(self):
        providers = {"enum.Enum", "fastapi.HTTPException", "fastapi.APIRouter"}
        for path, (_, _, _, load_names, provider_imports) in self.file_indexes.items():
            if not self._tick(len(provider_imports)):
                return
            aliases = self.audit._module_security_aliases(
                ast.Module(
                    body=provider_imports,
                    type_ignores=[],
                )
            )
            for node in load_names:
                if not self._tick():
                    return
                api = aliases.get(node.id, "")
                if api not in providers | {"enum", "fastapi"}:
                    continue
                end = node
                while (
                    isinstance(self.parents.get(id(end)), ast.Attribute)
                    and self._tick()
                ):
                    end = self.parents[id(end)]
                tail = self.audit._name(end).split(".")[1:]
                resolved = ".".join([api, *tail])
                parent = self.parents.get(id(end))
                valid = (
                    resolved == "enum.Enum"
                    and isinstance(parent, ast.ClassDef)
                    and end in parent.bases
                    or resolved in providers - {"enum.Enum"}
                    and isinstance(parent, ast.Call)
                    and parent.func is end
                    or resolved == "fastapi.APIRouter"
                    and isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and parent.returns is end
                )
                if not valid:
                    self.complete = False

        if any(
            p.name in {"enum.py", "fastapi.py"}
            or {"enum", "fastapi"} & set(p.relative_to(self.root).parts[:-1])
            for p in self.trees
        ):
            self.complete = False

    def _guarded_script_profile(self, path, tree):
        if len(tree.body) != 2:
            return None
        imported, guard = tree.body
        if (
            not isinstance(imported, ast.Import)
            or len(imported.names) != 1
            or imported.names[0].name != "uvicorn"
            or imported.names[0].asname is not None
            or self.aliases[path].get("uvicorn") != "uvicorn"
            or (path, "uvicorn") in self.blocked
            or not isinstance(guard, ast.If)
            or guard.orelse
            or not isinstance(guard.test, ast.Compare)
            or len(guard.test.ops) != 1
            or not isinstance(guard.test.ops[0], ast.Eq)
            or not isinstance(guard.test.left, ast.Name)
            or guard.test.left.id != "__name__"
            or len(guard.test.comparators) != 1
            or not isinstance(guard.test.comparators[0], ast.Constant)
            or guard.test.comparators[0].value != "__main__"
            or len(guard.body) != 1
            or not isinstance(guard.body[0], ast.Expr)
            or not isinstance(guard.body[0].value, ast.Call)
        ):
            return None
        call = guard.body[0].value
        if (
            not isinstance(call.func, ast.Attribute)
            or not isinstance(call.func.value, ast.Name)
            or call.func.value.id != "uvicorn"
            or call.func.attr != "run"
            or len(call.args) != 1
            or not isinstance(call.args[0], ast.Constant)
            or call.args[0].value != "app.app:app"
            or {item.arg for item in call.keywords} != {"host", "log_level"}
            or len(call.keywords) != 2
            or any(
                not isinstance(item.value, ast.Constant)
                or type(item.value.value) is not str
                for item in call.keywords
            )
        ):
            return None
        entry_imports = self.audit._oracle_imports(self.root, path, tree, self.eligible)
        if "uvicorn" in entry_imports:
            return None
        module = path.parent / "app" / "app.py"
        if module not in self.trees:
            return None
        return module, path.parent

    def _bind_guarded_script_imports(self):
        candidates = defaultdict(list)
        for path, tree in self.trees.items():
            profile = self._guarded_script_profile(path, tree)
            if profile is not None:
                candidates[profile[0]].append((path, profile[1]))
        for module, profiles in candidates.items():
            if len(profiles) == 1:
                entry, root = profiles[0]
                staged = self._guarded_import_stage(module, root)
                if staged is not None:
                    imports, top = staged
                    self._commit_guarded_imports(module, entry, root, imports, top)

    def _guarded_import_stage(self, module, root):
        resolved = self.audit._oracle_imports(
            root, module, self.trees[module], self.eligible
        )
        top = defaultdict(list)
        for statement in self.trees[module].body:
            for name in self.audit._bound_names(statement):
                top[name].append(statement)
        staged = {}
        for name, origin in resolved.items():
            if not origin[0].is_relative_to(root):
                continue
            current = self.imports[module].get(name)
            if name in self.imports[module]:
                if current != origin:
                    return None
                continue
            if len(top[name]) != 1 or not isinstance(
                top[name][0], (ast.Import, ast.ImportFrom)
            ):
                return None
            staged[name] = origin
        return (staged, top) if staged else None

    def _commit_guarded_imports(self, module, entry, root, staged, top):
        blocked_before = set(self.blocked)
        pending = self._scope_bindings(
            module,
            list(self._walk(self.trees[module])),
            set(staged),
            top,
            defer_fixture_checks=True,
        )
        self.blocked.update((module, node.arg) for node in pending)
        if any((module, name) in self.blocked for name in staged):
            self.blocked.difference_update(self.blocked - blocked_before)
            return False
        self.imports[module] = {**self.imports[module], **staged}
        self.source_profiles[module] = {
            "schema": "factory.guarded-uvicorn-import-root.v1",
            "entrypoint": entry.relative_to(self.root).as_posix(),
            "entrypoint_path": entry.relative_to(self.root).as_posix(),
            "entrypoint_sha256": getattr(
                self.trees[entry], "_oracle_source_sha256", None
            ),
            "module": "app.app",
            "source_path": module.relative_to(self.root).as_posix(),
            "module_sha256": getattr(self.trees[module], "_oracle_source_sha256", None),
            "import_root": root.relative_to(self.root).as_posix(),
            "invocation": "direct-script",
            "other_invocations": "UNKNOWN",
            "runtime_assurance": "INCOMPLETE",
        }
        return True

    def _bindings(self, path, nodes, scope_nodes, origins):
        tree = self.trees[path]
        top = defaultdict(list)
        for statement in tree.body:
            if not self._tick():
                return
            for name in self.audit._bound_names(statement):
                top[name].append(statement)
        self.blocked.update((path, name) for name in origins if len(top[name]) != 1)
        self.pending_fixture_parameters.extend(
            (path, node)
            for node in self._scope_bindings(
                path,
                scope_nodes,
                origins,
                top,
                defer_fixture_checks=True,
            )
        )
        if any(
            isinstance(n, ast.Name)
            and n.id in {"globals", "locals", "eval", "exec", "__import__", "vars"}
            or isinstance(n, ast.Attribute)
            and n.attr in {"__dict__", "import_module", "modules"}
            for n in nodes
        ):
            self.complete = False
        self._nested_imports(path, nodes)
        if any(
            isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names)
            for n in nodes
        ):
            self.complete = False

    def _scope_bindings(self, path, nodes, origins, top, *, defer_fixture_checks=False):
        pending = []
        for node in nodes:
            if not self._tick():
                return pending
            if isinstance(node, ast.arg) and node.arg in origins:
                if defer_fixture_checks and node.arg not in self.imports[path]:
                    pending.append(node)
                elif defer_fixture_checks or not self._fixture_parameter_value(
                    path, node.arg, node
                ):
                    self.blocked.add((path, node.arg))
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                self.blocked.update((path, name) for name in origins & set(node.names))
            if (
                isinstance(node, ast.Name)
                and node.id in origins
                and isinstance(node.ctx, (ast.Store, ast.Del))
            ):
                if self.parents.get(id(node)) not in top[node.id]:
                    self.blocked.add((path, node.id))
        return pending

    def _fixture_parameter_value(self, path, name, node):
        function = self._containing_function(node)
        fixture = self.functions.get((path, name))
        return bool(
            function
            and fixture
            and any(arg.arg == name for arg in function.args.args)
            and self._is_pytest_fixture(path, fixture)
            and self._nearest_fixture(path, name, function) == (path, fixture)
        )

    def _nested_imports(self, path, nodes):
        tree = self.trees[path]
        for node in nodes:
            if isinstance(node, (ast.Import, ast.ImportFrom)) and node not in tree.body:
                view = self.audit._oracle_imports(
                    self.root,
                    path,
                    ast.Module(body=[node], type_ignores=[]),
                    self.eligible,
                )
                self.unmodeled_imports.extend(view.values())

    def _relevant_origin(self, source, symbol):
        if not self._tick(len(self.members)):
            return False
        if (
            symbol is None
            and source.name == "__init__.py"
            and any(p.is_relative_to(source.parent) for p, _, _ in self.members)
        ):
            return True
        names = (
            [symbol]
            if symbol
            else [name for p, name in self.objects if p == source]
            + list(self.imports[source])
        )
        candidate_classes = {(p, cls) for p, cls, _ in self.members}
        for name in names:
            ref = self.resolve(source, (name,))
            if ref and ref[0] == "class" and ref[1:3] in candidate_classes:
                return True
            if ref and ref[0] == "value":
                value = self.objects.get(ref[1:3])
                for node in self._walk(value):
                    if isinstance(node, (ast.Name, ast.Attribute)):
                        use = self.resolve(
                            ref[1], tuple(self.audit._name(node).split("."))
                        )
                        if use and use[0] == "class" and use[1:3] in candidate_classes:
                            return True
        return False

    def _reject_unmodeled_origins(self):
        self.ignore_blocked = True
        for path, name in self.blocked:
            imported = self.imports[path].get(name)
            if imported and self._relevant_origin(*imported):
                self.complete = False
            if self._relevant_origin(path, name):
                self.complete = False
        if any(self._relevant_origin(*origin) for origin in self.unmodeled_imports):
            self.complete = False
        self.ignore_blocked = False

    def resolve(self, path, parts, seen=()):
        """Resolve a bounded source name through captured classes, functions, values, and imports; return None on cycles, blocked names, or budget exhaustion."""
        if not self._tick():
            return None
        if not parts or (path, parts) in seen or len(seen) > 16:
            return None
        name, *tail = parts
        if (path, name) in self.blocked and not getattr(self, "ignore_blocked", False):
            return None
        seen = (*seen, (path, parts))
        obj = self.objects.get((path, name))
        if isinstance(obj, ast.ClassDef):
            return "class", path, name, tuple(tail)
        if (path, name) in self.functions:
            return "function", path, name, tuple(tail)
        if obj is not None:
            if isinstance(obj, (ast.Name, ast.Attribute)):
                return self.resolve(
                    path, (*self.audit._name(obj).split("."), *tail), seen
                )
            return "value", path, name, tuple(tail)
        return self._resolve_import(path, name, tail, seen)

    def _resolve_import(self, path, name, tail, seen):
        imported = self.imports[path].get(name)
        if name in self.imports[path] and imported is None:
            if self.enum_demand_only:
                self.demand_unresolved_imports.add((path, name))
            else:
                self.complete = False
        if imported is None:
            return None
        source, symbol = imported
        if (
            symbol is None
            or symbol == source.stem
            and (source, symbol) not in self.objects
        ):
            return (
                self.resolve(source, tuple(tail), seen)
                if tail
                else ("module", source, "", ())
            )
        return self.resolve(source, (symbol, *tail), seen)

    def _references(self):
        for path, (_, _, _, load_names, _) in self.file_indexes.items():
            for node in load_names:
                if not self._tick():
                    return
                if self._fixture_parameter_value(path, node.id, node):
                    continue
                end = node
                while (
                    isinstance(self.parents.get(id(end)), ast.Attribute)
                    and self._tick()
                ):
                    end = self.parents[id(end)]
                ref = self.resolve(path, tuple(self.audit._name(end).split(".")))
                if ref is not None:
                    if ref[0] == "module" and self._relevant_origin(ref[1], None):
                        self.complete = False
                    self.refs[ref[:3]].append((path, end, ref[3]))

    def _router(self, path, call):
        if not isinstance(call.func, ast.Attribute) or call.func.attr not in {
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "options",
            "head",
            "api_route",
        }:
            return False
        receiver = call.func.value
        if not isinstance(receiver, ast.Name):
            return False
        scope = getattr(call, "_security_lexical_scope", None)
        if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        stores = [
            n
            for n in self._walk(scope)
            if isinstance(n, ast.Name)
            and n.id == receiver.id
            and isinstance(n.ctx, (ast.Store, ast.Del))
        ]
        if len(stores) != 1:
            return False
        assignment = self.parents.get(id(stores[0]))
        if (
            not isinstance(assignment, ast.Assign)
            or len(assignment.targets) != 1
            or not isinstance(assignment.value, ast.Call)
        ):
            return False
        if (
            self.integrity.security_call_name(assignment.value, self.aliases[path])
            != "fastapi.APIRouter"
        ):
            return False
        return self._router_closed(scope, receiver)

    def _router_closed(self, scope, receiver):
        for node in self._walk(scope):
            if (
                isinstance(node, ast.Attribute)
                and self.audit._name(node.value) == receiver.id
                and isinstance(node.ctx, (ast.Store, ast.Del))
            ):
                return False
            if (
                isinstance(node, ast.Name)
                and node.id == receiver.id
                and isinstance(node.ctx, ast.Load)
            ):
                parent = self.parents.get(id(node))
                if isinstance(parent, ast.Return) and parent.value is node:
                    if not self._router_return_consumers(scope):
                        return False
                    continue
                if isinstance(parent, ast.Attribute):
                    invocation = self.parents.get(id(parent))
                    if (
                        parent.attr
                        not in {
                            "get",
                            "post",
                            "put",
                            "patch",
                            "delete",
                            "options",
                            "head",
                            "api_route",
                        }
                        or not isinstance(invocation, ast.Call)
                        or invocation.func is not parent
                    ):
                        return False
                else:
                    return False
        return True

    def _router_return_consumers(self, factory):
        path = self.node_paths.get(id(factory))
        if path is None:
            return False
        key = ("function", path, factory.name)
        uses = self.refs.get(key, [])
        if not uses or not self._tick(len(uses)):
            return False
        wrapped = []
        for use_path, end, tail in uses:
            if tail:
                return False
            call = self.parents.get(id(end))
            if not isinstance(call, ast.Call) or call.func is not end:
                return False
            parent = self.parents.get(id(call))
            if isinstance(parent, ast.Return) and parent.value is call:
                wrapper = getattr(call, "_security_lexical_scope", None)
                wrapper_path = self.node_paths.get(id(wrapper), use_path)
                owner = self.parents.get(id(wrapper)) if wrapper is not None else None
                if not isinstance(owner, ast.ClassDef) or not self._router_wrapper_safe(
                    wrapper_path, owner, wrapper, call
                ):
                    return False
                wrapped.append((wrapper_path, owner, wrapper))
            elif not self._router_call_published(use_path, call):
                from .credential_endpoint_admission import router_factory_call_published

                if not router_factory_call_published(self, use_path, call):
                    return False
        return bool(uses) and all(
            self._router_wrapper_consumers(*item) for item in wrapped
        )

    def _router_wrapper_safe(self, path, owner, method, returned_call):
        body = [
            node
            for node in method.body
            if not isinstance(node, ast.Expr)
            or not isinstance(node.value, ast.Constant)
            or not isinstance(node.value.value, str)
        ]
        return (
            not owner.decorator_list
            and self._router_wrapper_class_safe(path, owner)
            and not method.decorator_list
            and len(body) == 1
            and isinstance(body[0], ast.Return)
            and body[0].value is returned_call
            and (path, owner.name, method.name) in self.methods
        )

    def _router_wrapper_class_safe(self, path, owner):
        hooks = {
            "__class_getitem__",
            "__delattr__",
            "__getattr__",
            "__getattribute__",
            "__init_subclass__",
            "__mro_entries__",
            "__new__",
            "__setattr__",
        }
        return (
            not owner.keywords
            and all(self._router_wrapper_base_safe(path, base) for base in owner.bases)
            and not any(
                self.audit._bound_names(member) & hooks for member in owner.body
            )
        )

    def _router_wrapper_base_safe(self, path, base):
        target = base.value if isinstance(base, ast.Subscript) else base
        if not isinstance(target, (ast.Name, ast.Attribute)):
            return False
        parts = self.audit._name(target).split(".")
        canonical = self.aliases[path].get(parts[0], parts[0])
        canonical = ".".join((canonical, *parts[1:]))
        if canonical != "typing.Generic" or not isinstance(base, ast.Subscript):
            return False
        arguments = (
            base.slice.elts if isinstance(base.slice, ast.Tuple) else [base.slice]
        )
        return bool(arguments) and all(
            isinstance(argument, ast.Attribute) and isinstance(argument.value, ast.Name)
            for argument in arguments
        )

    def _router_wrapper_consumers(self, path, owner, method):
        from .credential_endpoint_admission import _memo

        return _memo(
            self,
            "router_wrapper_cache",
            (path, id(owner), id(method)),
            lambda: self._router_wrapper_consumers_uncached(path, owner, method),
        )

    def _router_wrapper_consumers_uncached(self, path, owner, method):
        found = 0
        for source, tree in self.trees.items():
            for node in self._walk(tree):
                if not isinstance(node, ast.Attribute) or node.attr != method.name:
                    continue
                parent = self.parents.get(id(node))
                if not isinstance(parent, ast.Call) or parent.func is not node:
                    return False
                if self._class_of_expression(
                    source,
                    node.value,
                    getattr(parent, "_security_lexical_scope", None),
                ) != (path, owner.name):
                    return False
                if not self._router_call_published(source, parent):
                    return False
                found += 1
        return found > 0

    def _class_of_expression(self, path, value, scope, seen=()):
        if not self._tick() or id(value) in seen or len(seen) > 8:
            return None
        seen = (*seen, id(value))
        if isinstance(value, ast.Name) and isinstance(
            scope, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            value = self._class_scope_value(path, value, scope)
            if value is None:
                return None
        if isinstance(value, ast.Call):
            value = value.func
        if isinstance(value, ast.Subscript):
            value = value.value
        if not isinstance(value, (ast.Name, ast.Attribute)):
            return None
        resolved = self.resolve(path, tuple(self.audit._name(value).split(".")))
        if resolved and resolved[0] == "class" and not resolved[3]:
            return resolved[1], resolved[2]
        if resolved and resolved[0] == "value" and not resolved[3]:
            origin = self.objects.get(resolved[1:3])
            if isinstance(origin, ast.AST):
                return self._class_of_expression(resolved[1], origin, None, seen)
        return None

    def _class_scope_value(self, path, value, scope):
        binding = self._unique_name_assignment(scope, value.id)
        local_bindings = [
            statement
            for statement in scope.body
            if value.id in self.audit._bound_names(statement)
        ]
        if binding is not None:
            return (
                binding.value
                if len(local_bindings) == 1 and local_bindings[0] is binding
                else None
            )
        if local_bindings:
            return None
        arguments = (
            *scope.args.posonlyargs,
            *scope.args.args,
            *scope.args.kwonlyargs,
            scope.args.vararg,
            scope.args.kwarg,
        )
        if not any(arg is not None and arg.arg == value.id for arg in arguments):
            return value
        fixture = self._nearest_fixture(path, value.id)
        if fixture is None or not self._is_pytest_fixture(*fixture):
            return None
        returns = [node for node in fixture[1].body if isinstance(node, ast.Return)]
        return (
            returns[0].value
            if len(returns) == 1 and isinstance(returns[0].value, ast.Call)
            else None
        )

    def _unique_name_assignment(self, scope, name):
        key = id(scope)
        if key not in self.assignment_cache:
            index = defaultdict(list)
            for node in self._walk(scope):
                if isinstance(node, ast.Name) and isinstance(
                    node.ctx, (ast.Store, ast.Del)
                ):
                    index[node.id].append(node)
            if not self.snapshot_complete:
                return None
            self.assignment_cache[key] = index
        writes = self.assignment_cache[key].get(name, [])
        if len(writes) != 1 or isinstance(writes[0].ctx, ast.Del):
            return None
        binding = self.parents.get(id(writes[0]))
        if isinstance(binding, ast.AnnAssign) and binding.target is writes[0]:
            return binding
        if isinstance(binding, ast.Assign) and writes[0] in binding.targets:
            return binding
        if isinstance(binding, ast.NamedExpr) and binding.target is writes[0]:
            return binding
        return None

    def _router_call_published(self, path, call):
        parent = self.parents.get(id(call))
        if isinstance(parent, ast.Call) and call in parent.args:
            return bool(
                parent.args and parent.args[0] is call
            ) and self._fastapi_include(path, parent)
        if isinstance(parent, ast.keyword) and parent.arg == "router":
            outer = self.parents.get(id(parent))
            return isinstance(outer, ast.Call) and self._fastapi_include(path, outer)
        return self._router_assignment_published(path, call, parent)

    def _router_assignment_published(self, path, call, parent):
        if not isinstance(parent, (ast.Assign, ast.AnnAssign)):
            return False
        targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            return False
        scope = getattr(parent, "_security_lexical_scope", None)
        if scope is None:
            scope = self.trees[path]
        alias = targets[0].id
        found = 0
        for node in self._walk(scope):
            if not isinstance(node, ast.Name) or node.id != alias:
                continue
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                if node is not targets[0]:
                    return False
                continue
            parent_node = self.parents.get(id(node))
            if not isinstance(parent_node, ast.Call):
                return False
            if (
                not parent_node.args
                or parent_node.args[0] is not node
                or not self._fastapi_include(path, parent_node)
            ):
                return False
            found += 1
        return found > 0

    def _fastapi_include(self, path, call):
        if (
            not isinstance(call.func, ast.Attribute)
            or call.func.attr != "include_router"
            or not call.args
            or not isinstance(call.func.value, ast.Name)
        ):
            return False
        app_name = call.func.value.id
        scope = getattr(call, "_security_lexical_scope", None)
        value = None
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            assignments = [
                statement
                for statement in scope.body
                if isinstance(statement, (ast.Assign, ast.AnnAssign))
                and any(
                    isinstance(target, ast.Name) and target.id == app_name
                    for target in (
                        statement.targets
                        if isinstance(statement, ast.Assign)
                        else [statement.target]
                    )
                )
            ]
            if len(assignments) != 1:
                return False
            value = assignments[0].value
            binding = self._unique_name_assignment(scope, app_name)
        else:
            value = self.objects.get((path, app_name))
            if isinstance(value, (ast.Assign, ast.AnnAssign)):
                value = value.value
            binding = self._unique_name_assignment(self.trees[path], app_name)
        if (
            not isinstance(value, ast.Call)
            or self.integrity.security_call_name(value, self.aliases[path])
            != "fastapi.FastAPI"
            or binding is None
            or binding.value is not value
        ):
            return False
        for node in self._walk(scope or self.trees[path]):
            if (
                isinstance(node, ast.Attribute)
                and self.audit._name(node.value) == app_name
                and isinstance(node.ctx, (ast.Store, ast.Del))
            ):
                return False
        return self._fastapi_app_uses_closed(path, scope, app_name, binding)

    def _fastapi_app_uses_closed(self, path, scope, app_name, binding):
        for node in self._walk(scope or self.trees[path]):
            if isinstance(node, ast.Name) and node.id == app_name:
                if not self._fastapi_app_use_closed(
                    path, scope, app_name, binding, node
                ):
                    return False
        return True

    def _fastapi_app_use_closed(self, path, scope, app_name, binding, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            targets = (
                binding.targets if isinstance(binding, ast.Assign) else [binding.target]
            )
            return node in targets
        parent = self.parents.get(id(node))
        if isinstance(parent, ast.Return) and parent.value is node:
            return self._returned_app_fixture_closed(path, scope, app_name)
        if isinstance(parent, ast.Call) and node in parent.args:
            loop = self.parents.get(id(parent))
            return (
                isinstance(loop, ast.AsyncFor)
                and loop.iter is parent
                and isinstance(loop.target, ast.Name)
                and self._test_client_fixture(path, scope, app_name, loop.target.id)
            )
        if not isinstance(parent, ast.Attribute) or parent.value is not node:
            return False
        invocation = self.parents.get(id(parent))
        if not isinstance(invocation, ast.Call) or invocation.func is not parent:
            return False
        if parent.attr in {
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "options",
            "head",
            "api_route",
            "include_router",
        }:
            return True
        return (
            parent.attr == "url_path_for"
            and not invocation.keywords
            and all(
                isinstance(arg, ast.Constant)
                and type(arg.value) in {str, int, bool, type(None)}
                for arg in invocation.args
            )
        )

    def _fixture_export_closed(self, path, fixture):
        if (
            (path, fixture.name) in self.blocked
            or not self._is_pytest_fixture(path, fixture)
            or self.refs.get(("function", path, fixture.name))
            or any(
                origin == (path, fixture.name) or origin == (path, None)
                for view in self.imports.values()
                for origin in view.values()
            )
        ):
            return False
        return not any(
            isinstance(node, ast.Attribute) and node.attr == "getfixturevalue"
            for node in self._walk(self.trees[path])
        )

    def _returned_app_fixture_closed(self, path, fixture, app_name):
        key = path, getattr(fixture, "name", None), app_name
        if key in self.app_fixture_cache:
            return self.app_fixture_cache[key]
        self.app_fixture_cache[key] = False
        if not isinstance(fixture, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        returns = [node for node in self._walk(fixture) if isinstance(node, ast.Return)]
        if (
            not self._fixture_export_closed(path, fixture)
            or len(returns) != 1
            or not isinstance(returns[0].value, ast.Name)
            or returns[0].value.id != app_name
        ):
            return False
        self.app_fixture_cache[key] = self._app_fixture_consumers_closed(path, fixture)
        return self.app_fixture_cache[key]

    def _app_fixture_consumers_closed(self, path, fixture):
        consumers = 0
        for source, tree in self.trees.items():
            for caller in self._walk(tree):
                if not isinstance(caller, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                parameters = [
                    arg.arg
                    for arg in (
                        *caller.args.posonlyargs,
                        *caller.args.args,
                        *caller.args.kwonlyargs,
                    )
                    if arg.arg == fixture.name
                ]
                if not parameters:
                    continue
                origin = self._nearest_fixture(source, fixture.name, caller)
                if origin is None:
                    if source == path:
                        return False
                    continue
                if origin != (path, fixture) or len(parameters) != 1:
                    continue
                if self._app_client_consumer(source, caller, parameters[0]):
                    consumers += 1
                elif self._app_openapi_consumer(source, caller, parameters[0]):
                    consumers += 1
                else:
                    return False
        return consumers > 0

    def _parameter_used_once(self, scope, name, allowed):
        uses = [
            node
            for node in self._walk(scope)
            if isinstance(node, ast.Name) and node.id == name
        ]
        return (
            len(uses) == 1
            and uses[0] is allowed
            and not any(name in self.audit._bound_names(stmt) for stmt in scope.body)
        )

    def _app_client_consumer(self, path, function, parameter):
        if not self._is_pytest_fixture(path, function):
            return False
        loops = [
            node
            for node in self._walk(function)
            if isinstance(node, ast.AsyncFor)
            and isinstance(node.target, ast.Name)
            and isinstance(node.iter, ast.Call)
            and len(node.iter.args) == 1
            and isinstance(node.iter.args[0], ast.Name)
            and node.iter.args[0].id == parameter
            and not node.iter.keywords
        ]
        return (
            len(loops) == 1
            and self._parameter_used_once(function, parameter, loops[0].iter.args[0])
            and self._test_client_fixture(path, function, parameter, loops[0].target.id)
        )

    def _app_openapi_consumer(self, path, function, parameter):
        if not self._is_pytest_fixture(path, function):
            return False
        returns = [node for node in function.body if isinstance(node, ast.Return)]
        if len(returns) != 1 or not isinstance(returns[0].value, ast.Call):
            return False
        call = returns[0].value
        if (
            not isinstance(call.func, ast.Attribute)
            or call.func.attr != "openapi"
            or not isinstance(call.func.value, ast.Name)
            or call.args
            or call.keywords
        ):
            return False
        return (
            self._parameter_used_once(function, parameter, call.func.value)
            and call.func.value.id == parameter
            and self._openapi_fixture_consumers_closed(path, function)
        )

    def _openapi_fixture_consumers_closed(self, path, fixture):
        if not self._fixture_export_closed(path, fixture):
            return False
        found = 0
        for source, tree in self.trees.items():
            for consumer in self._walk(tree):
                if not isinstance(consumer, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                parameters = [
                    arg.arg
                    for arg in (
                        *consumer.args.posonlyargs,
                        *consumer.args.args,
                        *consumer.args.kwonlyargs,
                    )
                    if arg.arg == fixture.name
                ]
                if not parameters:
                    continue
                origin = self._nearest_fixture(source, fixture.name, consumer)
                if origin is None:
                    if source == path:
                        return False
                    continue
                if origin != (path, fixture) or len(parameters) != 1:
                    continue
                if not self._openapi_projection_only(source, consumer, parameters[0]):
                    return False
                found += 1
        return found > 0

    def _openapi_projection_only(self, path, function, parameter):
        uses = [
            node
            for node in self._walk(function)
            if isinstance(node, ast.Name) and node.id == parameter
        ]
        if len(uses) != 1 or not isinstance(uses[0].ctx, ast.Load):
            return False
        outer = uses[0]
        while True:
            parent = self.parents.get(id(outer))
            if not isinstance(parent, ast.Subscript) or parent.value is not outer:
                break
            if (
                not isinstance(parent.slice, ast.Constant)
                or type(parent.slice.value) is not str
            ):
                return False
            outer = parent
        assignment = self.parents.get(id(outer))
        if (
            not isinstance(assignment, ast.Assign)
            or assignment.value is not outer
            or assignment not in function.body
            or len(assignment.targets) != 1
            or not isinstance(assignment.targets[0], ast.Name)
        ):
            return False
        route_name = assignment.targets[0].id
        if self._unique_name_assignment(function, route_name) is not assignment:
            return False
        route_uses = [
            node
            for node in self._walk(function)
            if isinstance(node, ast.Name)
            and node.id == route_name
            and isinstance(node.ctx, ast.Load)
        ]
        if len(route_uses) != 1:
            return False
        return self._openapi_response_keys_asserted(path, function, route_uses[0])

    def _openapi_response_keys_asserted(self, path, function, route_use):
        response = self.parents.get(id(route_use))
        if (
            not isinstance(response, ast.Subscript)
            or response.value is not route_use
            or not isinstance(response.slice, ast.Constant)
            or response.slice.value != "responses"
        ):
            return False
        keys = self.parents.get(id(response))
        keys_call = self.parents.get(id(keys))
        listed = self.parents.get(id(keys_call))
        comparison = self.parents.get(id(listed))
        assertion = self.parents.get(id(comparison))
        if (
            not isinstance(keys, ast.Attribute)
            or keys.value is not response
            or keys.attr != "keys"
            or not isinstance(keys_call, ast.Call)
            or keys_call.func is not keys
            or keys_call.args
            or keys_call.keywords
            or not isinstance(listed, ast.Call)
            or not isinstance(listed.func, ast.Name)
            or listed.func.id != "list"
            or listed.args != [keys_call]
            or listed.keywords
            or not isinstance(comparison, ast.Compare)
            or len(comparison.ops) != 1
            or not isinstance(comparison.ops[0], ast.Eq)
            or len(comparison.comparators) != 1
            or not isinstance(assertion, ast.Assert)
            or assertion.msg is not None
        ):
            return False
        expected = (
            comparison.comparators[0] if comparison.left is listed else comparison.left
        )
        if (
            (comparison.left is not listed and comparison.comparators[0] is not listed)
            or not isinstance(expected, ast.List)
            or any(
                not isinstance(item, ast.Constant) or type(item.value) is not str
                for item in expected.elts
            )
        ):
            return False
        if self.aliases[path].get("list") is not None:
            return False
        return not any(
            isinstance(node, ast.Name)
            and node.id == "list"
            and isinstance(node.ctx, (ast.Store, ast.Del))
            or isinstance(node, ast.arg)
            and node.arg == "list"
            for node in self._walk(self.trees[path])
        )

    def public(self, path, node, seen=()):
        """Determine whether a value appears in a public assertion, response, detail field, or top-level assignment according to the captured AST."""
        if not self._tick():
            return False
        if id(node) in seen or len(seen) > 16:
            return False
        seen = (*seen, id(node))
        while (
            isinstance(self.parents.get(id(node)), (ast.Dict, ast.List, ast.Tuple))
            and self._tick()
        ):
            node = self.parents[id(node)]
        parent = self.parents.get(id(node))
        if isinstance(parent, ast.keyword):
            call = self.parents.get(id(parent))
            if not isinstance(call, ast.Call):
                return False
            if parent.arg == "detail":
                return self._public_detail(path, call)
            return parent.arg == "responses" and self._router(path, call)
        if (
            isinstance(parent, (ast.Assign, ast.AnnAssign))
            and parent.value is node
            and parent in self.trees[path].body
        ):
            return self._public_assignment(path, parent, seen)
        return self._primitive_assertion(path, node, parent) or self._public_assertion(
            path, node, parent
        )

    def _enum_metadata_consumer(self, path, node, enum_key):
        """Prove a member read is a typed, immutable metadata constructor input."""
        value = node
        parent = self.parents.get(id(value))
        while isinstance(parent, ast.Tuple) and parent.elts and self._tick():
            value, parent = parent, self.parents.get(id(parent))
        call = (
            self.parents.get(id(parent))
            if isinstance(parent, ast.keyword)
            else parent
            if isinstance(parent, ast.Call)
            else None
        )
        if not isinstance(call, ast.Call) or not isinstance(
            call.func, (ast.Name, ast.Attribute)
        ):
            return False
        consumer = self.resolve(path, tuple(self.audit._name(call.func).split(".")))
        if consumer is None:
            return False
        field_name = parent.arg if isinstance(parent, ast.keyword) else None
        if isinstance(parent, ast.Call):
            if (
                value not in call.args
                or any(isinstance(item, ast.Starred) for item in call.args)
                or any(item.arg is None for item in call.keywords)
            ):
                return False
            position = call.args.index(value)
            if consumer[0] == "function":
                helper = self.functions.get(consumer[1:3])
                if not isinstance(helper, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return False
                positional = (*helper.args.posonlyargs, *helper.args.args)
                if position >= len(positional):
                    return False
                field_name = positional[position].arg
            elif consumer[0] == "class":
                definition = self.objects.get(consumer[1:3])
                if not isinstance(
                    definition, ast.ClassDef
                ) or not self._frozen_metadata_class(consumer[1], definition):
                    return False
                fields = [
                    item.target.id
                    for item in definition.body
                    if isinstance(item, ast.AnnAssign)
                    and isinstance(item.target, ast.Name)
                ]
                if position >= len(fields):
                    return False
                field_name = fields[position]
            if field_name is None or any(
                item.arg == field_name for item in call.keywords
            ):
                return False
        elif not isinstance(parent, ast.keyword) or parent.value is not value:
            return False
        if field_name is None:
            return False
        if consumer[0] == "class":
            definition = self.objects.get(consumer[1:3])
            definition_path = consumer[1]
            if not isinstance(
                definition, ast.ClassDef
            ) or not self._frozen_metadata_class(definition_path, definition):
                return False
            field = next(
                (
                    item
                    for item in definition.body
                    if isinstance(item, ast.AnnAssign)
                    and isinstance(item.target, ast.Name)
                    and item.target.id == field_name
                ),
                None,
            )
            return bool(
                field is not None
                and self._enum_annotation_contains(
                    definition_path, field.annotation, enum_key
                )
                and self._metadata_field_escapes(
                    definition_path, definition, field_name
                )
                == "closed-benign"
            )
        if consumer[0] != "function":
            return False
        helper = self.functions.get(consumer[1:3])
        if not isinstance(helper, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        if (
            helper.decorator_list
            or helper.args.defaults
            or any(value is not None for value in helper.args.kw_defaults)
            or helper.args.vararg is not None
            or helper.args.kwarg is not None
            or any(
                isinstance(node, ast.Call)
                for annotation in [
                    *(
                        arg.annotation
                        for arg in (
                            *helper.args.posonlyargs,
                            *helper.args.args,
                            *helper.args.kwonlyargs,
                        )
                    ),
                    helper.returns,
                ]
                if annotation is not None
                for node in self._walk(annotation)
            )
        ):
            return False
        argument = next(
            (
                arg
                for arg in (
                    *helper.args.posonlyargs,
                    *helper.args.args,
                    *helper.args.kwonlyargs,
                )
                if arg.arg == field_name
            ),
            None,
        )
        if (
            argument is None
            or argument.annotation is None
            or not self._enum_annotation_contains(
                consumer[1], argument.annotation, enum_key
            )
        ):
            return False
        returns = [item for item in helper.body if isinstance(item, ast.Return)]
        if (
            len(returns) != 1
            or len(helper.body) != 1
            or not isinstance(returns[0].value, ast.Call)
            or not isinstance(returns[0].value.func, (ast.Name, ast.Attribute))
        ):
            return False
        result = self.resolve(
            consumer[1], tuple(self.audit._name(returns[0].value.func).split("."))
        )
        if result is None or result[0] != "class":
            return False
        result_class = self.objects.get(result[1:3])
        result_path = result[1]
        if not isinstance(
            result_class, ast.ClassDef
        ) or not self._frozen_metadata_class(result_path, result_class):
            return False
        result_field = next(
            (
                item
                for item in result_class.body
                if isinstance(item, ast.AnnAssign)
                and isinstance(item.target, ast.Name)
                and item.target.id == field_name
            ),
            None,
        )
        forwarded = [
            item.value for item in returns[0].value.keywords if item.arg == field_name
        ]
        return bool(
            result_field is not None
            and self._enum_annotation_contains(
                result_path, result_field.annotation, enum_key
            )
            and self._metadata_field_escapes(result_path, result_class, field_name)
            == "closed-benign"
            and len(forwarded) == 1
            and isinstance(forwarded[0], ast.Name)
            and forwarded[0].id == field_name
            and sum(
                isinstance(use, ast.Name)
                and use.id == field_name
                and isinstance(use.ctx, ast.Load)
                for use in self._walk(helper)
            )
            == 1
        )

    def _metadata_field_escapes(self, definition_path, definition, field_name):
        key = definition_path, definition.name, field_name
        if not getattr(self, "metadata_field_escape_index_ready", False):
            self._build_metadata_field_escape_index()
        if not getattr(self, "metadata_field_escape_index_complete", False):
            return "unknown"
        return (
            "dangerous"
            if self.metadata_field_escape_cache.get(key, False)
            else "closed-benign"
        )

    def _build_metadata_field_escape_index(self):
        self.metadata_field_escape_cache = {}
        classes = {
            key
            for key, value in self.objects.items()
            if isinstance(value, ast.ClassDef)
            and self._frozen_metadata_class(key[0], value)
        }
        instances = defaultdict(set)
        instance_names = defaultdict(set)
        parents = {}
        for path, tree in self.trees.items():
            stack = [(tree, None)]
            while stack:
                node, parent = stack.pop()
                if not self._tick():
                    self.metadata_field_escape_index_ready = True
                    self.metadata_field_escape_index_complete = False
                    return
                if parent is not None:
                    parents[id(node)] = parent
                stack.extend((child, node) for child in ast.iter_child_nodes(node))
                if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                    continue
                value = node.value
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                if (
                    len(targets) != 1
                    or not isinstance(targets[0], ast.Name)
                    or not isinstance(value, ast.Call)
                ):
                    continue
                resolved = (
                    self.resolve(path, tuple(self.audit._name(value.func).split(".")))
                    if isinstance(value.func, (ast.Name, ast.Attribute))
                    else None
                )
                result = resolved
                if resolved is not None and resolved[0] == "function":
                    helper = self.functions.get(resolved[1:3])
                    returns = (
                        [item for item in helper.body if isinstance(item, ast.Return)]
                        if isinstance(helper, (ast.FunctionDef, ast.AsyncFunctionDef))
                        else []
                    )
                    if (
                        len(returns) == 1
                        and len(helper.body) == 1
                        and not helper.decorator_list
                        and isinstance(returns[0].value, ast.Call)
                        and isinstance(returns[0].value.func, (ast.Name, ast.Attribute))
                    ):
                        result = self.resolve(
                            resolved[1],
                            tuple(self.audit._name(returns[0].value.func).split(".")),
                        )
                if (
                    result is not None
                    and result[0] == "class"
                    and result[1:3] in classes
                ):
                    instances[path, targets[0].id].add(result[1:3])
                    instance_names[targets[0].id].add(result[1:3])

        escaped = set()
        for path, tree in self.trees.items():
            for node in self._walk(tree):
                if isinstance(node, ast.Call) and isinstance(
                    node.func, (ast.Name, ast.Attribute)
                ):
                    result = self.resolve(
                        path, tuple(self.audit._name(node.func).split("."))
                    )
                    if (
                        result is not None
                        and result[0] == "class"
                        and result[1:3] in classes
                    ):
                        parent = parents.get(id(node))
                        targets = (
                            parent.targets
                            if isinstance(parent, ast.Assign)
                            else [parent.target]
                            if isinstance(parent, ast.AnnAssign)
                            else []
                        )
                        assigned = (
                            parent is not None
                            and getattr(parent, "value", None) is node
                            and len(targets) == 1
                            and isinstance(targets[0], ast.Name)
                        )
                        returned = (
                            isinstance(parent, ast.Return)
                            and isinstance(
                                parents.get(id(parent)),
                                (ast.FunctionDef, ast.AsyncFunctionDef),
                            )
                            and len(parents[id(parent)].body) == 1
                            and not parents[id(parent)].decorator_list
                        )
                        if not assigned and not returned:
                            escaped.add(result[1:3])
                if isinstance(node, ast.Call):
                    name = self.audit._resolved_ast_name(node.func, self.aliases[path])
                    if name in {
                        "builtins.__import__",
                        "__import__",
                        "importlib.import_module",
                        "builtins.eval",
                        "eval",
                        "builtins.exec",
                        "exec",
                        "globals",
                        "locals",
                        "vars",
                        "getattr",
                        "setattr",
                        "delattr",
                    }:
                        imported = any(
                            (resolved := self.resolve(path, (name,))) is not None
                            and (
                                resolved[0] == "value"
                                and resolved[1:3] in instances
                                or resolved[0] == "module"
                                and any(owner == resolved[1] for owner, _ in instances)
                            )
                            for name in self.imports[path]
                        )
                        if (
                            path in {owner for owner, _ in instances}
                            or imported
                            or path in getattr(self, "enum_effect_paths", ())
                        ):
                            self.metadata_field_escape_index_ready = True
                            self.metadata_field_escape_index_complete = False
                            return
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else [node.target]
                    )
                    if any(
                        isinstance(target, ast.Name) and target.id == "__all__"
                        for target in targets
                    ):
                        names = (
                            {
                                item.value
                                for item in node.value.elts
                                if isinstance(item, ast.Constant)
                                and type(item.value) is str
                            }
                            if isinstance(node.value, (ast.List, ast.Tuple))
                            else set()
                        )
                        if not names:
                            escaped.update(
                                class_key
                                for (owner, _), keys in instances.items()
                                if owner == path
                                for class_key in keys
                            )
                        for name in names:
                            result = self.resolve(path, (name,))
                            if (
                                result is not None
                                and result[0] == "value"
                                and result[1:3] in instances
                            ):
                                escaped.add(result[1:3])
                            origin = self.imports[path].get(name)
                            if origin in instances:
                                escaped.update(instances[origin])
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    result = self.resolve(path, (node.id,))
                    escaped.update(instance_names.get(node.id, ()))
                    if (
                        (path, node.id) in instances
                        or result is not None
                        and result[0] == "value"
                        and result[1:3] in instances
                    ):
                        escaped.update(
                            instances.get(
                                (path, node.id), {result[1:3]} if result else set()
                            )
                        )
                elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
                    result = self.resolve(
                        path, tuple(self.audit._name(node).split("."))
                    )
                    if (
                        result is not None
                        and result[0] == "value"
                        and result[1:3] in instances
                    ):
                        escaped.add(result[1:3])
        for class_key in escaped:
            definition = self.objects.get(class_key)
            if isinstance(definition, ast.ClassDef):
                for item in definition.body:
                    if isinstance(item, ast.AnnAssign) and isinstance(
                        item.target, ast.Name
                    ):
                        self.metadata_field_escape_cache[
                            (*class_key, item.target.id)
                        ] = True
        self.metadata_field_escape_index_ready = True
        self.metadata_field_escape_index_complete = self.complete and not getattr(
            self, "demand_unresolved_imports", ()
        )

    def _frozen_metadata_class(self, path, definition):
        if (
            definition.bases
            or definition.keywords
            or any(
                not isinstance(item, ast.Pass)
                and not isinstance(item, ast.AnnAssign)
                or isinstance(item, ast.AnnAssign)
                and (not isinstance(item.target, ast.Name) or item.value is not None)
                or isinstance(item, ast.AnnAssign)
                and any(
                    isinstance(node, ast.Call) for node in self._walk(item.annotation)
                )
                for item in definition.body
            )
            or not self._provider_is_unmodified("dataclasses", {"dataclass"})
        ):
            return False
        if len(definition.decorator_list) != 1:
            return False
        decorator = definition.decorator_list[0]
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if (
            self.audit._resolved_ast_name(target, self.aliases[path])
            != "dataclasses.dataclass"
        ):
            return False
        options = (
            {keyword.arg: keyword.value for keyword in decorator.keywords}
            if isinstance(decorator, ast.Call)
            else {}
        )
        return (
            isinstance(decorator, ast.Call)
            and not decorator.args
            and all(keyword.arg in {"frozen", "eq"} for keyword in decorator.keywords)
            and isinstance(options.get("frozen"), ast.Constant)
            and options["frozen"].value is True
            and isinstance(options.get("eq"), ast.Constant)
            and options["eq"].value is False
        )

    def _enum_annotation_contains(self, path, annotation, enum_key):
        if not self._provider_is_unmodified("enum", {"Enum"}):
            return False
        for node in self._walk(annotation):
            if not isinstance(node, (ast.Name, ast.Attribute)):
                continue
            resolved = self.resolve(path, tuple(self.audit._name(node).split(".")))
            if resolved is not None and resolved[:3] == enum_key:
                return True
        return False

    def _enum_type_consumer(self, path, node, enum_key):
        current = node
        while True:
            parent = self.parents.get(id(current))
            if isinstance(parent, ast.arg) and parent.annotation is not None:
                return self._enum_annotation_contains(path, parent.annotation, enum_key)
            if isinstance(parent, ast.AnnAssign) and parent.annotation is not None:
                return self._enum_annotation_contains(path, parent.annotation, enum_key)
            if not isinstance(parent, (ast.Subscript, ast.Tuple, ast.BinOp)):
                break
            current = parent
        parent = self.parents.get(id(node))
        if (
            isinstance(parent, ast.Call)
            and self.audit._resolved_ast_name(parent.func, self.aliases[path])
            == "isinstance"
            and len(parent.args) == 2
            and parent.args[1] is node
            and not parent.keywords
            and not self.integrity._builtin_repr_names_shadowed(parent, {"isinstance"})
        ):
            return True
        return False

    def _public_detail(self, path, call):
        from .context_efficiency import _module_import_aliases_are_closed

        if (
            self.integrity.security_call_name(call, self.aliases[path])
            != "fastapi.HTTPException"
        ):
            return False
        if path not in self.provider_closure:
            count = sum(1 for _ in self._walk(self.trees[path]))
            if not self._tick(count * 4):
                return False
            self.provider_closure[path] = _module_import_aliases_are_closed(
                self.trees[path], "fastapi", self.audit, api="fastapi.HTTPException"
            )
        return self.provider_closure[path]

    def _provider_is_unmodified(self, module, attributes):
        key = module, tuple(sorted(attributes))
        if key in self.provider_cache:
            return self.provider_cache[key]
        if module in self.provider_blocked_prefixes:
            self.provider_cache[key] = False
            return False
        provider_roots = {module, *(module + "." + item for item in attributes)}
        if any(
            (receiver == module and (attribute in attributes or attribute == "*"))
            or any(
                receiver == root or receiver.startswith(root + ".")
                for root in provider_roots - {module}
            )
            for receiver, attribute in self.provider_attribute_writes
        ):
            self.provider_cache[key] = False
            return False
        self.provider_cache[key] = True
        return True

    def _is_pytest_fixture(self, path, function):
        if len(function.decorator_list) != 1:
            return False
        decorator = function.decorator_list[0]
        if isinstance(decorator, ast.Call):
            if decorator.args or decorator.keywords:
                return False
            decorator = decorator.func
        provider = self.audit._resolved_ast_name(decorator, self.aliases[path])
        if provider not in {"pytest.fixture", "pytest_asyncio.fixture"}:
            return False
        return self._provider_is_unmodified(provider.split(".")[0], {"fixture"})

    def _nearest_fixture(self, path, name, scope=None):
        def alias_override(body):
            return any(
                isinstance(decorator, ast.Call)
                and any(
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                    for keyword in decorator.keywords
                )
                for statement in body
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
                for decorator in statement.decorator_list
            )

        owner = self.parents.get(id(scope))
        if isinstance(owner, ast.ClassDef):
            if owner.bases or alias_override(owner.body):
                return None
            for statement in owner.body:
                if name in self.audit._bound_names(statement):
                    return None
        candidates = [
            path,
            *(
                parent / "conftest.py"
                for parent in path.parents
                if parent == self.root or parent.is_relative_to(self.root)
            ),
        ]
        for candidate in dict.fromkeys(candidates):
            tree = self.trees.get(candidate)
            if tree is None:
                continue
            if alias_override(tree.body):
                return None
            bindings = [
                statement
                for statement in tree.body
                if name in self.audit._bound_names(statement)
            ]
            if bindings:
                return (
                    (candidate, bindings[0])
                    if (
                        len(bindings) == 1
                        and isinstance(
                            bindings[0], (ast.FunctionDef, ast.AsyncFunctionDef)
                        )
                    )
                    else None
                )
        return None

    def _test_client_fixture(self, test_path, fixture, app_name, yielded_name):
        key = test_path, fixture.name, app_name, yielded_name
        if key in self.fixture_cache:
            return self.fixture_cache[key]
        if not self._is_pytest_fixture(test_path, fixture):
            self.fixture_cache[key] = False
            return False
        loops = [
            node
            for node in self._walk(fixture)
            if isinstance(node, ast.AsyncFor)
            and isinstance(node.target, ast.Name)
            and node.target.id == yielded_name
            and isinstance(node.iter, ast.Call)
            and isinstance(node.iter.func, ast.Name)
            and len(node.iter.args) == 1
            and isinstance(node.iter.args[0], ast.Name)
            and node.iter.args[0].id == app_name
            and not node.iter.keywords
        ]
        if len(loops) != 1:
            self.fixture_cache[key] = False
            return False
        loop = loops[0]
        helper_name = loop.iter.func.id
        if any(
            helper_name in self.audit._bound_names(statement)
            for statement in fixture.body
        ):
            self.fixture_cache[key] = False
            return False
        if (
            len(loop.body) != 1
            or loop.orelse
            or not isinstance(loop.body[0], ast.Expr)
            or not isinstance(loop.body[0].value, ast.Yield)
            or sum(
                isinstance(use, ast.Name) and use.id == yielded_name
                for use in self._walk(fixture)
            )
            != 2
            or any(
                isinstance(use, ast.Name)
                and use.id == helper_name
                and isinstance(use.ctx, ast.Load)
                and use is not loop.iter.func
                for use in self._walk(fixture)
            )
        ):
            self.fixture_cache[key] = False
            return False
        if not any(arg.arg == loop.iter.func.id for arg in fixture.args.args):
            self.fixture_cache[key] = False
            return False
        yields = [node for node in self._walk(loop) if isinstance(node, ast.Yield)]
        if (
            len(yields) != 1
            or not isinstance(yields[0].value, ast.Name)
            or yields[0].value.id != yielded_name
        ):
            self.fixture_cache[key] = False
            return False
        origin = self._nearest_fixture(test_path, loop.iter.func.id)
        if origin is None:
            self.fixture_cache[key] = False
            return False
        provider_path, provider = origin
        result = self._returned_httpx_client(provider_path, provider)
        self.fixture_cache[key] = result
        return result

    def _returned_httpx_client(self, path, fixture):
        if not self._is_pytest_fixture(path, fixture):
            return False
        returns = [
            node
            for node in fixture.body
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Name)
        ]
        inner = [
            node for node in fixture.body if isinstance(node, ast.AsyncFunctionDef)
        ]
        if (
            len(returns) != 1
            or len(inner) != 1
            or len(fixture.body) != 2
            or returns[0].value.id != inner[0].name
            or len(inner[0].args.args) != 1
        ):
            return False
        outer = [node for node in inner[0].body if isinstance(node, ast.AsyncWith)]
        if len(outer) != 1 or len(inner[0].body) != 1 or len(outer[0].items) != 1:
            return False
        manager = outer[0].items[0].context_expr
        if (
            not isinstance(manager, ast.Call)
            or self.audit._resolved_ast_name(manager.func, self.aliases[path])
            != "asgi_lifespan.LifespanManager"
            or len(outer[0].body) != 1
            or not isinstance(outer[0].body[0], ast.AsyncWith)
        ):
            return False
        client_with = outer[0].body[0]
        if len(client_with.items) != 1:
            return False
        item = client_with.items[0]
        client, call = item.optional_vars, item.context_expr
        if (
            not isinstance(client, ast.Name)
            or not isinstance(call, ast.Call)
            or call.args
            or len(call.keywords) != 2
            or {keyword.arg for keyword in call.keywords} != {"transport", "base_url"}
            or self.audit._resolved_ast_name(call.func, self.aliases[path])
            != "httpx.AsyncClient"
            or len(client_with.body) != 1
            or not isinstance(client_with.body[0], ast.Expr)
            or not isinstance(client_with.body[0].value, ast.Yield)
            or not isinstance(client_with.body[0].value.value, ast.Name)
            or client_with.body[0].value.value.id != client.id
        ):
            return False
        transport = [kw.value for kw in call.keywords if kw.arg == "transport"]
        if len(transport) != 1 or not isinstance(transport[0], ast.Call):
            return False
        transport_call = transport[0]
        app_name = inner[0].args.args[0].arg
        if (
            self.audit._resolved_ast_name(transport_call.func, self.aliases[path])
            != "httpx.ASGITransport"
            or not any(
                isinstance(arg, ast.Name) and arg.id == app_name
                for arg in transport_call.args
            )
            and not any(
                kw.arg == app_name and isinstance(kw.value, ast.Name)
                for kw in transport_call.keywords
            )
        ):
            return False
        return self._provider_is_unmodified("httpx", {"AsyncClient", "ASGITransport"})

    def _public_assertion(self, path, node, parent):
        from .credential_endpoint_admission import public_json_assertion

        return public_json_assertion(self, path, node, parent)

    def _primitive_assertion(self, path, node, parent):
        if isinstance(parent, ast.Compare):
            if not all(
                part is node
                or isinstance(part, ast.Constant)
                and type(part.value) in {str, bytes, int, float, bool, type(None)}
                for part in [parent.left, *parent.comparators]
            ):
                return False
            parent = self.parents.get(id(parent))
        relative = path.relative_to(self.root)
        return isinstance(parent, ast.Assert) and (
            "tests" in relative.parts or relative.name.startswith("test_")
        )

    def _request_client_origin(self, path, function, request):
        client_name = request.value.func.value.id
        if not any(arg.arg == client_name for arg in function.args.args):
            return False
        if any(
            client_name in self.audit._bound_names(statement)
            for statement in function.body
        ):
            return False
        for use in self._walk(function):
            if (
                isinstance(use, ast.Name)
                and use.id == client_name
                and isinstance(use.ctx, ast.Load)
            ):
                attribute = self.parents.get(id(use))
                if (
                    not isinstance(attribute, ast.Attribute)
                    or self.parents.get(id(attribute)) is not request.value
                    or request.value.func is not attribute
                ):
                    return False
        client_fixture = self._nearest_fixture(path, client_name, function)
        if client_fixture is None or client_fixture[0] != path:
            return False
        fixture = client_fixture[1]
        loops = [
            item
            for item in self._walk(fixture)
            if isinstance(item, ast.AsyncFor)
            and isinstance(item.target, ast.Name)
            and isinstance(item.iter, ast.Call)
            and len(item.iter.args) == 1
            and isinstance(item.iter.args[0], ast.Name)
        ]
        if len(loops) != 1 or not self._test_client_fixture(
            path, fixture, loops[0].iter.args[0].id, loops[0].target.id
        ):
            return False
        return True

    def _containing_function(self, node):
        while node is not None:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node
            node = self.parents.get(id(node))
        return None

    def _json_assertion_values(
        self, path, function, expected, data_name, response_name
    ):
        names = [
            node
            for node in self._walk(function)
            if isinstance(node, ast.Name) and node.id in {data_name, response_name}
        ]
        data_loads = [
            node
            for node in names
            if node.id == data_name and isinstance(node.ctx, ast.Load)
        ]
        if len(data_loads) != 1:
            return False
        response_loads = [
            node
            for node in names
            if node.id == response_name and isinstance(node.ctx, ast.Load)
        ]
        if not response_loads:
            return False
        for use in response_loads:
            attribute = self.parents.get(id(use))
            if not isinstance(attribute, ast.Attribute) or attribute.value is not use:
                return False
            parent = self.parents.get(id(attribute))
            if attribute.attr == "json":
                if (
                    not isinstance(parent, ast.Call)
                    or parent.func is not attribute
                    or parent.args
                    or parent.keywords
                ):
                    return False
            elif attribute.attr != "status_code" or isinstance(parent, ast.Call):
                return False
        if isinstance(expected, ast.Attribute):
            return self._json_expected_member(path, ast.Constant("detail"), expected)
        return all(
            self._json_expected_member(path, key, value)
            for key, value in zip(expected.keys, expected.values)
        )

    def _json_expected_member(self, path, key, value):
        if not isinstance(key, ast.Constant) or type(key.value) is not str:
            return False
        if isinstance(value, ast.Constant):
            return type(value.value) in {str, int, bool, type(None)}
        if not isinstance(value, ast.Attribute):
            return False
        origin = self.resolve(path, tuple(self.audit._name(value).split(".")))
        if not origin or origin[0] != "class" or len(origin[3]) != 1:
            return False
        owner = self.objects[origin[1:3]]
        bound_names = self.audit._bound_names
        body_names = set().union(*(bound_names(statement) for statement in owner.body))
        refs = self.refs.get(origin[:3], [])
        return (
            not any(name[:2] == name[-2:] == "__" for name in body_names)
            and not any(t and t[0][:2] == t[0][-2:] == "__" for _, _, t in refs)
            and origin[1:3] + (origin[3][0],) in self.members
        )

    def _public_assignment(self, path, parent, seen):
        targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            return False
        key = self.resolve(path, (targets[0].id,))
        if key is None:
            return False
        if key[0] == "class" and not key[3]:
            return True  # Every load of the alias is independently indexed.
        if key[0] == "class":
            return False
        refs = self.refs.get(key[:3], [])
        return bool(refs) and all(
            not tail and self.public(p, use, seen) for p, use, tail in refs
        )

    def witnesses(self):
        """Collect consumer witnesses only when source analysis is complete and every relevant reference is public; return no witnesses for incomplete evidence."""
        if self.enum_demand_only:
            return (
                dict(self.enum_demand_witnesses)
                if self.enum_demand_complete and self.snapshot_complete
                else {}
            )
        if not self.complete:
            return {}
        result = {}
        for (path, cls, member), declaration in self.members.items():
            enum_key = ("class", path, cls)
            refs = self.refs.get(("class", path, cls), [])
            if not refs:
                continue
            if not self._tick(len(refs)):
                return {}
            relevant = [
                (p, node, tail)
                for p, node, tail in refs
                if not tail or tail[0] == member
            ]
            if not any(tail == (member,) for _, _, tail in relevant):
                continue
            effects = []
            for p, node, tail in relevant:
                if not tail:
                    effect = (
                        "ENUM_TYPE_ANNOTATION"
                        if self._enum_type_consumer(p, node, enum_key)
                        else None
                    )
                elif tail == (member,) and isinstance(node.ctx, ast.Load):
                    if self.public(p, node):
                        effect = "PUBLIC_ASSERTION_OR_RESPONSE"
                    elif self._enum_metadata_consumer(p, node, enum_key):
                        effect = "TYPED_METADATA_CONSTRUCTOR"
                    else:
                        effect = None
                else:
                    effect = None
                effects.append(effect)
            if not effects or any(effect is None for effect in effects):
                continue
            result[path, declaration.lineno, member] = [
                {
                    "path": p.relative_to(self.root).as_posix(),
                    "line": node.lineno,
                    "span": [
                        node.lineno,
                        node.col_offset,
                        node.end_lineno,
                        node.end_col_offset,
                    ],
                    "effect": effect,
                    "source_sha256": getattr(
                        self.trees[p], "_oracle_source_sha256", None
                    ),
                    **(
                        {"source_profile": self.source_profiles[p]}
                        if p in self.source_profiles
                        else {}
                    ),
                }
                for (p, node, tail), effect in zip(relevant, effects)
            ]
        return result if self.complete else {}

    def _walk(self, node):
        for child in ast.walk(node):
            # These singleton marker leaves are read through their parent fields
            # (for example Name.ctx and Compare.ops) and do not carry bindings,
            # references, or consumers of their own. Keep the original AST intact
            # for validation while indexing only semantic nodes.
            if isinstance(
                child,
                (ast.expr_context, ast.operator, ast.unaryop, ast.boolop, ast.cmpop),
            ):
                continue
            if not self._tick():
                return
            yield child

    def _tick(self, amount=1):
        self.remaining_work -= amount
        if self.remaining_work < 0:
            self.complete = False
            self.snapshot_complete = False
        return self.remaining_work >= 0

    def _snapshot_incomplete(self):
        self.snapshot_complete = False
        self.complete = False


class NativeOraclePayload(str):
    """Native in-memory cache checksum; not signing or invocation authority."""

    __slots__ = ("_seal",)

    def __new__(cls, text, key):
        value = super().__new__(cls, text)
        object.__setattr__(
            value, "_seal", (key, hashlib.sha256(text.encode("utf-8")).digest())
        )
        return value

    def __setattr__(self, *args):
        raise AttributeError("native cache metadata is immutable")

    __delattr__ = __setattr__

    def valid(self, key):
        """Confirm a native oracle payload has the exact payload type, sealing key, and matching UTF-8 content digest."""
        return type(self) is NativeOraclePayload and getattr(self, "_seal", None) == (
            key,
            hashlib.sha256(self.encode("utf-8")).digest(),
        )


def _source_commit(module_dir: Path) -> str | None:
    source_root = module_dir.parent
    manifest = source_root / "pyproject.toml"
    if not (source_root / ".git").exists() or not manifest.exists():
        return None
    if 'name = "factoryline-code-factory"' not in manifest.read_text(encoding="utf-8"):
        return None
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=source_root,
            capture_output=True,
            text=True,
            timeout=3,
        )
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=source_root,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or dirty.returncode != 0 or dirty.stdout.strip():
        return None
    return result.stdout.strip()


def _build_hash(module_dir: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(module_dir.rglob("*.py")):
        digest.update(path.relative_to(module_dir).as_posix().encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def provenance() -> dict:
    """Return package, source-commit, and build-hash provenance for this installation."""
    module_dir = Path(__file__).resolve().parent
    direct_url = None
    origin = "unknown"
    try:
        distribution = importlib.metadata.distribution("factoryline-code-factory")
        text = distribution.read_text("direct_url.json")
        if text:
            direct_url = json.loads(text).get("url")
            origin = "direct-url"
        else:
            origin = "site-packages"
    except importlib.metadata.PackageNotFoundError:
        origin = "source-tree"
    commit = _source_commit(module_dir) or SOURCE_COMMIT
    build_hash = _build_hash(module_dir)
    return {
        "schema": "factoryline.provenance.v1",
        "package": "factoryline-code-factory",
        "version": __version__,
        "source_commit": commit,
        "build_hash": build_hash,
        "install_origin": origin,
        "direct_url": direct_url,
        "python": sys.version.split()[0],
        "runtime": {
            "python": sys.version.split()[0],
            "implementation": sys.implementation.name,
        },
        "receipt_schema": "factory.receipt.v2",
        "identity_complete": bool(commit and build_hash),
    }


def _emit_version(as_json: bool) -> int:
    """Print the same provenance envelope as the full CLI."""
    payload = provenance()
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if as_json
        else f"factory {payload['version']}"
    )
    return 0


_QUICK_HELP = """Code Factory - review your code with less setup.

Start here:
  Scan my code       factory scan --root .
  Open dashboard     factory studio --root .
  Get guidance       factory guide

Next steps:
  More scan options  factory scan --help
  Check setup        factory doctor --strict --json
  All commands       factory --help-all

Scan reads eligible Python source without running your project.
Review findings, verify repairs with your tests, then rerun affected checks.
Keep pytest, mutation testing, CodeQL and Semgrep in your existing CI.
Missing evidence means INCOMPLETE; a scan is not release approval.
No adoption, signing keys or tenant configuration needed for a basic scan.
"""


def main(argv=None) -> int:
    """Show quick help and version probes without loading the command registry."""
    values = list(sys.argv[1:] if argv is None else argv)
    if values in (["--help"], ["-h"]):
        print(_QUICK_HELP, end="")
        return 0
    if values == ["--help-all"]:
        values = ["--help"]
    if values and values[0] == "--version":
        return _emit_version("--json" in values)
    started = time.monotonic()
    from .ops_telemetry import _measure_phase, _phase_telemetry

    with _phase_telemetry(started):
        with _measure_phase("entrypoint_startup"):
            from .cli import main as cli_main
        return cli_main(values)


def public_symbolic_findings(relative, node, findings, integrity):
    """Attach native source proofs; preserve the original primitive observation."""
    context = _symbolic_finding_context(relative, node, integrity)
    if context is None:
        return findings
    raw, profile = context
    for finding in findings:
        _attach_symbolic_finding(relative, node, finding, raw, profile)
    from .credential_endpoint_admission import annotate_endpoint_findings

    return annotate_endpoint_findings(relative, node, findings, integrity)


def _symbolic_finding_context(relative, node, integrity):
    module = integrity._security_module_scope(
        getattr(node, "_security_lexical_scope", None)
    )
    context = getattr(module, "_security_source_context", None)
    profile = getattr(module, "_fixed_program_workspace", {})
    if (
        not isinstance(context, tuple)
        or len(context) != 2
        or not isinstance(profile, dict)
    ):
        return None
    root, sources = context
    raw = sources.get(root / relative) if isinstance(sources, dict) else None
    if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != getattr(
        module, "_oracle_source_sha256", None
    ):
        return None
    return raw, profile


def _attach_symbolic_finding(relative, node, finding, raw, profile):
    facts = finding.get("facts", {})
    if (
        finding.get("code") != "SECURITY_HARDCODED_SECRET"
        or facts.get("role_candidate") != "symbolic_enum_identifier"
    ):
        return
    evidence = profile.get("credential_consumers", {}).get(
        f"{node.lineno}:{facts.get('name')}"
    )
    if not isinstance(evidence, dict) or not evidence.get("consumers"):
        return
    proof = _symbolic_finding_facts(relative, node, facts, evidence, raw, profile)
    proof["proof_facts_sha256"] = hashlib.sha256(
        json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    finding["facts"] = proof


def _symbolic_finding_facts(relative, node, facts, evidence, raw, profile):
    return {
        **facts,
        **evidence,
        "schema": "factory.public-symbolic-identifier.v1",
        "disposition": "PROVEN_PUBLIC_SYMBOLIC_IDENTIFIER",
        "source_path": relative,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "workspace_sources_sha256": profile.get("sources_sha256"),
        "declaration_span": [
            node.lineno,
            node.col_offset,
            node.end_lineno,
            node.end_col_offset,
        ],
        "runtime_assurance": "INCOMPLETE",
        "target_execution": "not_performed",
        "evidence_scope": "source-snapshot-publication-boundary",
        "downstream_consumer_security": "UNASSESSED",
    }


def public_symbolic_binding(finding, sources, bindings):
    """Verify retained evidence integrity, without granting execution authority."""
    import hashlib
    import json
    from .review_integrity import _valid_source_span

    facts = finding.get("facts", {})
    consumers, profiles = facts.get("consumers"), facts.get("source_profiles")
    if not _symbolic_binding_header(
        finding, facts, consumers, profiles, bindings, _valid_source_span
    ):
        return False
    if not _symbolic_consumer_rows(consumers, profiles, bindings):
        return False
    digest, workspace, proof = _symbolic_binding_digests(
        consumers, profiles, sources, facts, hashlib, json
    )
    return (
        facts.get("consumer_evidence_sha256") == digest
        and facts.get("workspace_sources_sha256") == workspace
        and facts.get("proof_facts_sha256") == proof
    )


def _symbolic_binding_header(finding, facts, consumers, profiles, bindings, valid_span):
    span = facts.get("declaration_span")
    return bool(
        finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and facts.get("schema") == "factory.public-symbolic-identifier.v1"
        and facts.get("disposition") == "PROVEN_PUBLIC_SYMBOLIC_IDENTIFIER"
        and facts.get("role_candidate") == "symbolic_enum_identifier"
        and facts.get("runtime_assurance") == "INCOMPLETE"
        and facts.get("target_execution") == "not_performed"
        and facts.get("source_path") == finding.get("path")
        and facts.get("source_sha256") == bindings.get(finding.get("path"))
        and valid_span(span)
        and span[:2] == [finding.get("line"), finding.get("column")]
        and isinstance(consumers, list)
        and 0 < len(consumers) <= 200_000
        and isinstance(profiles, list)
        and len(profiles) <= 2000
    )


def _symbolic_consumer_rows(consumers, profiles, bindings):
    valid_effects = {
        "PUBLIC_ASSERTION_OR_RESPONSE",
        "TYPED_METADATA_CONSTRUCTOR",
        "ENUM_TYPE_ANNOTATION",
        "ENUM_TYPE_CHECK",
    }
    if any(
        not isinstance(row, dict)
        or row.get("source_sha256") != bindings.get(row.get("path"))
        or type(row.get("line")) is not int
        or row["line"] < 1
        or row.get("effect") not in valid_effects
        or not _symbolic_consumer_span(row.get("span"), row.get("line"))
        for row in consumers
    ):
        return False
    if any(
        not isinstance(row, dict)
        or row.get("entrypoint_sha256") != bindings.get(row.get("entrypoint"))
        or row.get("module_sha256") != bindings.get(row.get("source_path"))
        or row.get("runtime_assurance") != "INCOMPLETE"
        for row in profiles
    ):
        return False
    return True


def _symbolic_consumer_span(span, line):
    return bool(
        isinstance(span, list)
        and len(span) == 4
        and all(type(value) is int for value in span)
        and span[0] == line
        and span[0] >= 1
        and span[1] >= 0
        and span[2] >= span[0]
        and span[3] >= 0
        and (span[2] > span[0] or span[3] > span[1])
    )


def _symbolic_binding_digests(consumers, profiles, sources, facts, hashlib, json):
    digest = hashlib.sha256(
        json.dumps(
            {"consumers": consumers, "source_profiles": profiles},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    workspace = hashlib.sha256(
        json.dumps(
            sorted((row["path"], row["sha256"]) for row in sources),
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    proof = hashlib.sha256(
        json.dumps(
            {key: value for key, value in facts.items() if key != "proof_facts_sha256"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return digest, workspace, proof


def bind_public_symbolic_consumers(
    root, snapshots, imports, contexts, source_bytes, inventory, integrity
):
    """Populate credential-consumer and finite-template context evidence from a matching source inventory; clear it on incomplete or failed analysis."""
    from . import review_audits as audit
    import hashlib
    import json

    for context in contexts.values():
        context["credential_consumers"] = {}
        context["finite_template_inputs"] = {}
    try:
        if not isinstance(inventory, dict) or set(contexts) != set(inventory):
            return
        graph = _LiteralConsumers(
            root,
            snapshots,
            {path: dict(view) for path, view in imports.items()},
            audit,
            integrity,
            source_bytes=source_bytes,
            inventory=inventory,
        )
        witnesses = graph.witnesses()
        demand_enum_only = bool(
            getattr(graph, "enum_demand_only", False)
            and getattr(graph, "enum_demand_complete", False)
        )
        templates = {} if demand_enum_only else graph.finite_template_inputs()
        if graph.snapshot_complete is not True:
            return
        if not graph.complete and not demand_enum_only:
            witnesses = {}
        workspace = hashlib.sha256(
            json.dumps(
                sorted(
                    (path.relative_to(root).as_posix(), digest)
                    for path, digest in inventory.items()
                ),
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        for (path, line, column), facts in templates.items():
            evidence = {**facts, "workspace_sources_sha256": workspace}
            evidence["proof_facts_sha256"] = hashlib.sha256(
                json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            contexts[path]["finite_template_inputs"][f"{line}:{column}"] = evidence
        profiles = (
            []
            if demand_enum_only
            else [
                {"source_path": path.relative_to(root).as_posix(), **profile}
                for path, profile in sorted(
                    getattr(graph, "source_profiles", {}).items()
                )
            ]
        )
        for (path, line, member), consumers in witnesses.items():
            evidence = {"consumers": consumers, "source_profiles": profiles}
            digest = hashlib.sha256(
                json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            contexts[path]["credential_consumers"][f"{line}:{member}"] = {
                **evidence,
                "consumer_evidence_sha256": digest,
            }
    except (
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
        RecursionError,
        MemoryError,
    ):
        for context in contexts.values():
            context["credential_consumers"] = {}
            context["finite_template_inputs"] = {}


def finite_template_witness(relative, node, call_name, root, sources, profile):
    """Read native finite-input evidence; never evaluate generated target code."""
    facts = _finite_template_facts(relative, node, call_name, profile)
    if facts is None:
        return {}
    return dict(facts) if _finite_template_sources_match(facts, root, sources) else {}


def _finite_template_facts(relative, node, call_name, profile):
    import ast

    if call_name not in {"exec", "builtins.exec"} or not isinstance(node, ast.Call):
        return None
    ledger = profile.get("finite_template_inputs", {})
    if not isinstance(ledger, dict):
        return None
    facts = ledger.get(f"{node.lineno}:{node.col_offset}")
    if not isinstance(facts, dict) or facts.get("source_path") != relative:
        return None
    if facts.get("call_span") != [
        node.lineno,
        node.col_offset,
        node.end_lineno,
        node.end_col_offset,
    ]:
        return None
    return facts


def _finite_template_sources_match(facts, root, sources):
    for path_key, hash_key in (
        ("source_path", "source_sha256"),
        ("capture_path", "capture_sha256"),
        ("domain_path", "domain_sha256"),
    ):
        name = facts.get(path_key)
        raw = sources.get(root / name) if isinstance(name, str) else None
        if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != facts.get(
            hash_key
        ):
            return False
    return True


def finite_template_binding(finding, sources, bindings):
    """Check the stated input-closure envelope, not runtime harmlessness."""
    import re
    from .review_integrity import _valid_source_span

    facts = finding.get("facts", {})
    if not _finite_template_header(finding, facts, _valid_source_span, re):
        return False
    if not _finite_template_paths_bound(facts, sources, bindings):
        return False
    workspace = _source_workspace_digest(sources, hashlib, json)
    proof = _facts_digest(facts, hashlib, json)
    return (
        facts.get("workspace_sources_sha256") == workspace
        and facts.get("proof_facts_sha256") == proof
    )


def _finite_template_header(finding, facts, valid_span, re):
    if not isinstance(facts, dict):
        return False
    span, template = facts.get("call_span"), facts.get("template_span")
    programs, size = facts.get("program_hashes"), facts.get("domain_size")
    return bool(
        finding.get("code") == "SECURITY_DYNAMIC_EXECUTION"
        and facts.get("schema") == "factory.finite-template-input.v1"
        and facts.get("disposition") == "PROVEN_FINITE_TEMPLATE_INPUT"
        and facts.get("scope_profile") == "pytest-collection-finite-parameter"
        and facts.get("hypothesis") == "ARGUMENT_CODE_INJECTION"
        and facts.get("input_effect") == "FINITE_SOURCE_TEMPLATE_INPUT"
        and facts.get("runtime_assurance") == "INCOMPLETE"
        and facts.get("execution_effects") == "UNASSESSED"
        and facts.get("target_execution") == "not_performed"
        and facts.get("source_path") == finding.get("path")
        and facts.get("capture_path") == finding.get("path")
        and valid_span(span)
        and valid_span(template)
        and span[:2] == [finding.get("line"), finding.get("column")]
        and tuple(span[:2])
        <= tuple(template[:2])
        <= tuple(template[2:])
        <= tuple(span[2:])
        and valid_span(facts.get("capture_span"))
        and tuple(facts["capture_span"][2:]) <= tuple(span[:2])
        and valid_span(facts.get("domain_span"))
        and type(size) is int
        and 1 <= size <= 64
        and isinstance(programs, list)
        and len(programs) == size
        and all(
            isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
            for digest in programs
        )
        and isinstance(facts.get("template_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", facts["template_sha256"])
    )


def _finite_template_paths_bound(facts, sources, bindings):
    for path_key, hash_key in (
        ("source_path", "source_sha256"),
        ("capture_path", "capture_sha256"),
        ("domain_path", "domain_sha256"),
    ):
        name = facts.get(path_key)
        if (
            not isinstance(name, str)
            or sum(row["path"] == name for row in sources) != 1
        ):
            return False
        if not isinstance(facts.get(hash_key), str) or facts[hash_key] != bindings.get(
            name
        ):
            return False
    return True


def _source_workspace_digest(sources, hashlib, json):
    return hashlib.sha256(
        json.dumps(
            sorted((row["path"], row["sha256"]) for row in sources),
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _facts_digest(facts, hashlib, json):
    return hashlib.sha256(
        json.dumps(
            {key: value for key, value in facts.items() if key != "proof_facts_sha256"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _local_control_literal_binding(binding, parents):
    owner = parents.get(binding)
    targets = owner.targets if isinstance(owner, ast.Assign) else [owner.target] if isinstance(owner, ast.AnnAssign) else []
    return (
        isinstance(binding, ast.Name) and isinstance(binding.ctx, ast.Store)
        and targets == [binding] and isinstance(owner.value, ast.Constant)
        and type(owner.value.value) is str
    )


def _local_control_literal_use(reference, scope, parents):
    comparison = parents.get(reference)
    if not isinstance(comparison, ast.Compare) or not all(isinstance(op, (ast.Eq, ast.NotEq)) for op in comparison.ops):
        return False
    if not all(item is reference or isinstance(item, ast.Constant) and type(item.value) is str for item in [comparison.left, *comparison.comparators]):
        return False
    current = reference
    while current in parents:
        current = parents[current]
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            return current is scope
    return False


def _local_control_reflection(module, scope_nodes, aliases):
    reflective = {"eval", "exec", "locals", "globals", "vars", "builtins", "__builtins__", "__import__", "_getframe", "currentframe", "f_locals", "f_globals", "f_back", "gi_frame", "cr_frame", "ag_frame"}
    for item in ast.walk(module):
        name = aliases.get(item.id, item.id).split(".")[-1] if isinstance(item, ast.Name) else item.attr if isinstance(item, ast.Attribute) else item.name.split(".")[-1] if isinstance(item, ast.alias) else None
        if name in reflective:
            return True
        if name == "getattr":
            parent = getattr(item, "_security_parent", None)
            if item in scope_nodes or not isinstance(parent, ast.Call) or parent.func is not item:
                return True
    return False


def _local_control_label_witness(audit, node, target, aliases):
    """Prove only a closed fast-local label, never a supplied-value comparison."""
    from .credential_role_constructor_provider import binding_occurrences
    from .finite_capture import _fixed_program_span
    from .context_efficiency import _SECRET_BYTES

    scope = getattr(node, "_security_lexical_scope", None)
    if not isinstance(target, ast.Name) or not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return {}
    if target.id in audit._scope_parameters(scope):
        return {}
    module = audit.integrity._security_module_scope(scope)
    digest = getattr(module, "_oracle_source_sha256", None)
    if not isinstance(digest, str) or len(digest) != 64:
        return {}
    nodes = list(ast.walk(scope))
    if len(nodes) > 4096 or any(isinstance(item, (ast.Global, ast.Nonlocal)) and target.id in item.names for item in nodes):
        return {}
    if _local_control_reflection(module, set(nodes), aliases):
        return {}
    parents = {child: owner for owner in nodes for child in ast.iter_child_nodes(owner)}
    bindings = binding_occurrences(scope.body, target.id)
    if not bindings or target not in bindings or not all(_local_control_literal_binding(binding, parents) for binding in bindings):
        return {}
    references = [item for item in nodes if isinstance(item, ast.Name) and item.id == target.id and isinstance(item.ctx, ast.Load)]
    if not references or not all(_local_control_literal_use(item, scope, parents) for item in references):
        return {}
    literals = [parents[binding].value for binding in bindings]
    literals.extend(item for reference in references for item in [parents[reference].left, *parents[reference].comparators] if item is not reference)
    if any(pattern.search(item.value.encode("utf-8")) for item in literals for pattern in _SECRET_BYTES):
        return {}
    return {
        "schema": "factory.local-control-label.v1",
        "disposition": "PROVEN_LOCAL_CONTROL_LABEL",
        "source_sha256": digest,
        "declaration_span": _fixed_program_span(node),
        "scope_span": _fixed_program_span(scope),
        "binding_spans": sorted(_fixed_program_span(binding) for binding in bindings),
        "use_spans": sorted(_fixed_program_span(reference) for reference in references),
        "evidence_scope": "source-visible-local-binding-and-literal-comparison-closure",
        "runtime_assurance": "INCOMPLETE",
    }


def credential_role_witness(audit, node, target, aliases):
    """Describe a symbolic declaration; it is not a non-credential exemption."""
    if label := _local_control_label_witness(audit, node, target, aliases):
        return label
    scope = getattr(node, "_security_lexical_scope", None)
    if not _credential_enum_class(scope, audit):
        return {}
    targets = node.targets if isinstance(node, audit.ast.Assign) else [node.target]
    if len(targets) != 1 or not isinstance(target, audit.ast.Name):
        return {}
    if not _credential_enum_literal(node, target, audit):
        return {}
    if audit.integrity._builtin_repr_names_shadowed(node, {"str"}):
        return {}
    from .security_configuration import _relative_binding

    if not _credential_enum_bases(scope, node, aliases, audit, _relative_binding):
        return {}
    return {
        "role_candidate": "symbolic_enum_identifier",
        "role_evidence_scope": "source_declaration_only",
        "declaration_class": scope.name,
        "declaration_line": scope.lineno,
        "credential_use": "UNVERIFIED",
        "missing_evidence": ["complete_import_reexport_and_consumer_closure"],
    }


def _credential_enum_class(scope, audit):
    return bool(
        isinstance(scope, audit.ast.ClassDef)
        and not scope.decorator_list
        and not scope.keywords
    )


def _credential_enum_literal(node, target, audit):
    if len(node.targets if isinstance(node, audit.ast.Assign) else [node.target]) != 1:
        return False
    if not isinstance(target, audit.ast.Name):
        return False
    # Enum member spelling and scalar value are independent.  Accept only the
    # immutable string scalar shape here; candidacy still requires the complete
    # source-bound consumer proof assembled by _LiteralConsumers.
    return isinstance(node.value, audit.ast.Constant) and type(node.value.value) is str


def _credential_enum_bases(scope, node, aliases, audit, relative_binding):
    bindings = audit.integrity._security_scope_request_aliases(
        getattr(scope, "_security_parent_scope", None), aliases, scope
    )
    bases = []
    for base in scope.bases:
        name = audit._name(base)
        head, separator, tail = name.partition(".")
        if relative_binding(node, head) or (head != "str" and head not in bindings):
            return False
        bases.append(bindings.get(head, head) + (separator + tail if separator else ""))
    return bases == ["str", "enum.Enum"]


def bind_credential_consumers(
    audit, root, snapshots, imports, contexts, source_bytes, *, inventory
):
    """Delegate credential-consumer binding to the shared symbolic-consumer analyzer."""
    return bind_public_symbolic_consumers(
        root, snapshots, imports, contexts, source_bytes, inventory, audit
    )


def credential_consumer_helpers(audit):
    """Return the source-binding and witness helpers required by credential-consumer analysis."""
    from .primitive_observation_binding import primitive_binding_helpers

    return (
        audit.bind_credential_consumers,
        bind_credential_consumers,
        bind_public_symbolic_consumers,
        public_symbolic_binding,
        _symbolic_binding_header,
        _symbolic_consumer_rows,
        _symbolic_binding_digests,
        credential_role_witness,
        _local_control_label_witness,
        _local_control_literal_binding,
        _local_control_literal_use,
        _local_control_reflection,
        _credential_enum_class,
        _credential_enum_literal,
        _credential_enum_bases,
        public_symbolic_findings,
        _symbolic_finding_context,
        _attach_symbolic_finding,
        _symbolic_finding_facts,
        finite_template_binding,
        _finite_template_header,
        _finite_template_paths_bound,
        _source_workspace_digest,
        _facts_digest,
        finite_template_witness,
        _finite_template_facts,
        _finite_template_sources_match,
        audit._LiteralConsumers,
        _LiteralConsumers,
        *(value for value in vars(_LiteralConsumers).values() if callable(value)),
        *audit.native_execution_helpers(),
        *primitive_binding_helpers(),
        audit._oracle_bound_names,
        *(value for value in vars(audit._LiteralConsumers).values() if callable(value)),
    )
