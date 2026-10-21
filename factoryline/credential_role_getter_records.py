"""Bounded record capability projection; scalar reads never grant write authority."""

import ast

from .credential_role_getter_consumers import _named
from .credential_role_scope_bindings import binding_occurrences

_CAPABILITIES = frozenset(
    {
        "calls",
        "requests",
        "call",
        "request",
        "iterator:call",
        "iterator:request",
        "iterator:scalar",
    }
)


class RecordProjectionIndex:
    """One AST worklist for immutable projections and closed local capability uses."""

    def __init__(self, tree, aliases, parents=None):
        from .credential_role_getter_consumers import _provider_binding_uncertain

        self.tree, self.aliases = tree, aliases
        self.nodes = tuple(ast.walk(tree))
        self.parents = (
            parents
            if parents is not None
            else {
                id(child): parent
                for parent in self.nodes
                for child in ast.iter_child_nodes(parent)
            }
        )
        self.memo, self.pending = {}, set()
        self.remaining = 100_000
        self.bounded = len(self.nodes) <= self.remaining
        self.provider_valid = not _provider_binding_uncertain(tree, aliases)

    def kind(self, node):
        if self.remaining <= 0 or len(self.pending) > 32:
            self.bounded = False
        if (
            node is None
            or not self.bounded
            or not self.provider_valid
            or id(node) in self.pending
        ):
            return None
        if id(node) not in self.memo:
            self.remaining -= 1
            self.pending.add(id(node))
            self.memo[id(node)] = self._kind(node)
            self.pending.remove(id(node))
        return self.memo[id(node)]

    def _kind(self, node):
        if isinstance(node, ast.Attribute):
            return self._attribute_kind(node)
        if isinstance(node, ast.Subscript):
            if self.kind(node.value) in {"calls", "requests"} and self._literal_index(
                node.slice
            ):
                return "call" if self.kind(node.value) == "calls" else "request"
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            return self._name_kind(node)
        if isinstance(node, (ast.GeneratorExp, ast.ListComp)):
            return self._comprehension_kind(node)
        if isinstance(node, ast.Call):
            return self._call_kind(node)
        return None

    def _literal_index(self, node):
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            node = node.operand
        return isinstance(node, ast.Constant) and type(node.value) is int

    def _attribute_kind(self, node):
        if _named(node, self.aliases) == "responses.calls":
            if not self._provider_stable(node):
                self.bounded = False
                return None
            return "calls"
        value = self.kind(node.value)
        if (value, node.attr) == ("call", "request"):
            return "request"
        return (
            node.attr if value == "request" and node.attr in {"url", "body"} else None
        )

    def _name_kind(self, node):
        current = self.parents.get(id(node))
        while current is not None:
            if isinstance(
                current, (ast.GeneratorExp, ast.ListComp, ast.SetComp, ast.DictComp)
            ):
                if any(isinstance(item, ast.NamedExpr) for item in ast.walk(current)):
                    return None
                for generator in current.generators:
                    if (
                        isinstance(generator.target, ast.Name)
                        and generator.target.id == node.id
                    ):
                        return "call" if self.kind(generator.iter) == "calls" else None
            if isinstance(
                current,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.Lambda,
                    ast.Module,
                    ast.ClassDef,
                ),
            ):
                return self._local_name_kind(node, current)
            current = self.parents.get(id(current))
        return None

    def _local_name_kind(self, node, scope):
        if isinstance(scope, ast.Lambda):
            return None
        rows = binding_occurrences(scope.body, node.id)
        if len(rows) != 1 or not isinstance(rows[0], ast.Name):
            return None
        assignment = self.parents.get(id(rows[0]))
        if not (
            isinstance(assignment, ast.Assign)
            and len(assignment.targets) == 1
            and assignment.targets[0] is rows[0]
            and assignment.lineno < node.lineno
        ):
            return None
        return self.kind(assignment.value)

    def _comprehension_kind(self, node):
        if len(node.generators) != 1:
            return None
        generator = node.generators[0]
        if (
            generator.is_async
            or not isinstance(generator.target, ast.Name)
            or self.kind(generator.iter) != "calls"
        ):
            return None
        kind = self.kind(node.elt)
        if isinstance(node.elt, ast.Constant) and type(node.elt.value) in (
            str,
            int,
            bool,
            bytes,
            type(None),
        ):
            kind = "scalar"
        if kind not in {"call", "request", "scalar"}:
            return None
        return (
            "iterator:" + kind
            if isinstance(node, ast.GeneratorExp)
            else {"call": "calls", "request": "requests", "scalar": "scalar"}[kind]
        )

    def _call_kind(self, node):
        if not node.args:
            return None
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "next"
            and self._builtin_stable(node, "next")
        ):
            if len(node.args) != 1 or node.keywords:
                return None
            kind = self.kind(node.args[0])
            return (
                kind.removeprefix("iterator:")
                if kind in {"iterator:call", "iterator:request", "iterator:scalar"}
                else None
            )
        if isinstance(node.func, ast.Name) and node.func.id in {"len", "sum"}:
            return self._collection_scalar(node)
        if (
            _named(node.func, self.aliases) == "typing.cast"
            and len(node.args) == 2
            and not node.keywords
            and self._provider_stable(node.func)
        ):
            return self.kind(node.args[1])
        return None

    def _collection_scalar(self, node):
        if (
            len(node.args) != 1
            or node.keywords
            or not self._builtin_stable(node, node.func.id)
        ):
            return None
        expected = (
            {"calls", "requests"} if node.func.id == "len" else {"iterator:scalar"}
        )
        return "scalar" if self.kind(node.args[0]) in expected else None

    def _builtin_stable(self, node, name):
        return self._lexical_stable(node, name, include_module=True)

    def _provider_stable(self, node):
        root = node
        while isinstance(root, ast.Attribute):
            root = root.value
        return isinstance(root, ast.Name) and self._lexical_stable(node, root.id)

    def _lexical_stable(self, node, name, include_module=False):
        current = self.parents.get(id(node))
        while current is not None:
            if isinstance(current, ast.ClassDef) and self._unknown_class_namespace(
                current, node
            ):
                return False
            if isinstance(
                current, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
            ):
                if any(
                    binding_occurrences([generator.target], name)
                    for generator in current.generators
                ):
                    return False
            if isinstance(
                current,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.Lambda,
                    ast.Module,
                    ast.ClassDef,
                ),
            ):
                if (
                    include_module or not isinstance(current, ast.Module)
                ) and self._scope_binds(current, name):
                    return False
            current = self.parents.get(id(current))
        return True

    def _unknown_class_namespace(self, scope, node):
        current = self.parents.get(id(node))
        while current is not None and current is not scope:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return False
            current = self.parents.get(id(current))
        return bool(scope.bases or scope.keywords or scope.decorator_list)

    def _scope_binds(self, scope, name):
        body = [scope.body] if isinstance(scope, ast.Lambda) else scope.body
        if binding_occurrences(body, name):
            return True
        if isinstance(scope, (ast.Module, ast.ClassDef)):
            return False
        arguments = scope.args
        parameters = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
        parameters.extend(arg for arg in (arguments.vararg, arguments.kwarg) if arg)
        return any(arg.arg == name for arg in parameters)

    def closed(self):
        if not self.bounded or not self.provider_valid:
            return False
        complete = all(
            self._closed_use(node)
            for node in self.nodes
            if self.kind(node) in _CAPABILITIES
        )
        return complete and self.bounded and self.remaining > 0

    def _closed_use(self, node):
        if hasattr(node, "ctx") and not isinstance(node.ctx, ast.Load):
            return False
        parent = self.parents.get(id(node))
        if isinstance(parent, (ast.Attribute, ast.Subscript)) and parent.value is node:
            return self.kind(parent) in _CAPABILITIES | {"url", "body"} and isinstance(
                parent.ctx, ast.Load
            )
        if isinstance(parent, ast.comprehension) and parent.iter is node:
            return self.kind(self.parents.get(id(parent))) in _CAPABILITIES
        if isinstance(parent, (ast.GeneratorExp, ast.ListComp)) and parent.elt is node:
            return self.kind(parent) in _CAPABILITIES
        if isinstance(parent, ast.Call):
            return (
                self.kind(parent) in _CAPABILITIES | {"scalar"}
                and node in parent.args
                and parent.func is not node
            )
        return (
            isinstance(parent, ast.Assign)
            and parent.value is node
            and self._closed_assignment(parent)
        )

    def _closed_assignment(self, assignment):
        if len(assignment.targets) != 1 or not isinstance(
            assignment.targets[0], ast.Name
        ):
            return False
        target = assignment.targets[0]
        scope = self.parents.get(id(assignment))
        if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            return False
        if binding_occurrences(scope.body, target.id) != [target]:
            return False
        return all(
            self._assigned_name_use(node, assignment)
            for node in ast.walk(scope)
            if isinstance(node, ast.Name)
            and node.id == target.id
            and node is not target
        )

    def _assigned_name_use(self, node, assignment):
        if not isinstance(node.ctx, ast.Load) or node.lineno <= assignment.lineno:
            return False
        current = self.parents.get(id(node))
        while current is not None and current is not self.parents.get(id(assignment)):
            if isinstance(
                current,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef),
            ):
                return False
            current = self.parents.get(id(current))
        return self.kind(node) == self.kind(assignment.value) and self._closed_use(node)


def _record_escape(tree, aliases):
    return not RecordProjectionIndex(tree, aliases).closed()


def record_projection(index, path, aliases):
    """Reuse a source-bound model only inside the existing checked analysis batch."""

    def derive():
        return RecordProjectionIndex(
            index.snapshots[path], aliases, index.parents[path]
        )

    memo = getattr(index, "class_chain_memo", None)
    if memo is None:
        return derive()
    key = ("record-projection", path, tuple(sorted(aliases.items())))
    return memo.source_model(key, derive, helper_epoch=_record_helpers)


def _record_helpers():
    from . import credential_role_getter_consumers as consumers
    from . import credential_role_scope_bindings as scopes
    from . import semantic_credential_sensor as sensor

    values = tuple(
        value
        for module in (consumers, scopes, sensor)
        for value in vars(module).values()
        if callable(value)
    )
    return (
        *values,
        RecordProjectionIndex,
        record_projection,
        *(
            method
            for method in vars(RecordProjectionIndex).values()
            if callable(method)
        ),
    )
