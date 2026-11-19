"""Captured unittest client lifecycle and unread credential proof."""

import ast

from .credential_role_constructor_provider import binding_occurrences
from .credential_role_identity_effects import _Value, _constant_identity_value
from .credential_role_method_use_getter_audit import _SourceTestScope
from .fixture_scope_value_audit import _scope_exact_text


class _StoredTestClientCredential(_SourceTestScope):
    """Close a test-only client whose constructor stores an unread credential."""

    def __init__(self, index, path, assignment, secret):
        super().__init__(index, path, assignment, secret)
        self.constructor_site = None
        self.client_fields = {}

    def exercise(self):
        from .mock_fixture_provenance import _app_test_function_external_uses_clear

        if (
            not self.view
            or not self.view.complete
            or self.fact is None
            or self.fact.source_role != "module_literal"
            or self.view._data_reflection_conflict(self.fact)
            or not self.audit._app_signing_terminal_stable(self.index, "unittest")
            or not self.literal_value_unique()
        ):
            return False
        uses = self.view._module_uses(self.fact, self.origin_use)
        if not uses or len(self.owners) != 1:
            return False
        path, owner = next(iter(self.owners.values()))
        setup = self.audit._legacy._enclosing_function(
            self.constructor_site, self.source.parents[path]
        )
        if not self.lifecycle_closed(path, owner) or not (
            _app_test_function_external_uses_clear(self.index, path, setup)
        ):
            return False
        return self.exercise_owner(path, owner) and bool(self.client_fields)

    def lifecycle_closed(self, path, owner):
        """Use the standard unittest dispatch and the three interpreted phases."""
        return not any(
            binding_occurrences(self.index["modules"][path].body, hook)
            for hook in ("load_tests", "setUpModule", "tearDownModule")
        ) and all(
            node.name in {"setUp", "tearDown"} or node.name.startswith("test_")
            for node in owner.body
            if isinstance(node, ast.FunctionDef)
        )

    def literal_value_unique(self):
        """The fixture proof must not hide a second use of the same literal value."""
        literal = self.assignment.value
        return isinstance(literal, ast.Constant) and not any(
            node is not literal
            and isinstance(node, ast.Constant)
            and node.value == literal.value
            for tree in self.index["modules"].values()
            for node in ast.walk(tree)
        )

    def origin_use(self, path, node):
        owner = self.owner_for(path, node)
        if owner is None or self.canonical(path, owner.bases[0]) != "unittest.TestCase":
            return None
        parents = self.source.parents[path]
        function = self.audit._legacy._enclosing_function(node, parents)
        parent = parents.get(id(node))
        call = parents.get(id(parent)) if isinstance(parent, ast.keyword) else parent
        if (
            function.name != "setUp"
            or self.constructor_site is not None
            or not isinstance(call, ast.Call)
            or not (node in call.args or parent in call.keywords)
        ):
            return None
        self.constructor_site = call
        self.owners[path, id(owner)] = (path, owner)
        self.witness(path, node, "test_client_constructor_credential")
        return "TEST_ORIGIN_READ"

    def resolve_name(self, path, node):
        parent = self.source.parents[path].get(id(node))
        if (
            isinstance(parent, ast.Attribute)
            and parent.value is node
            and self.constructor_site is not None
            and parent is self.constructor_site.func
            and (selected := self.declaration(path, parent)) is not None
            and isinstance(selected[1], ast.ClassDef)
        ):
            return _Value(inert_kind="scope_namespace")
        return super().resolve_name(path, node)

    def source_object_bases_closed(self, path, owner):
        return not owner.bases or (
            len(owner.bases) == 1
            and isinstance(owner.bases[0], ast.Name)
            and owner.bases[0].id == "object"
            and self.audit._app_builtin_annotation_inert(
                self.index, path, owner.bases[0]
            )
        )

    def class_source_closed(self, path, owner, uninvoked_hooks=()):
        # The shared interpreter rejects an unmodeled context enter/exit.
        return super().class_source_closed(path, owner, ("__enter__", "__exit__"))

    def construct(self, flow, path, call, args, kwargs):
        from .review_integrity import bind_source_call

        values = (*args, *kwargs.values())
        if (
            call is not self.constructor_site
            or sum(self.origin in value.roots for value in values) != 1
        ):
            return None
        selected = self.declaration(path, call.func)
        if selected is None or not isinstance(selected[1], ast.ClassDef):
            return None
        class_path, owner = selected
        target = self.audit._legacy.effective_method(
            [(class_path, owner.name, owner)], "__init__"
        )
        if target is None:
            return None
        constructor = target[1]
        synthetic = ast.Name(id="_scope_receiver", ctx=ast.Load())
        bound = bind_source_call(call, constructor, synthetic, apply_defaults=True)
        actuals = {
            id(expr): value
            for expr, value in zip(
                (*call.args, *(kw.value for kw in call.keywords)), values
            )
        }
        host = actuals.get(id(bound.get("host")))
        if host is None or _scope_exact_text(host) not in {
            "127.0.0.1",
            "::1",
            "localhost",
        }:
            return None
        operand = next(
            (
                name
                for name, expr in bound.items()
                if isinstance(expr, ast.Name) and expr.id == self.secret
            ),
            None,
        )
        field = self.stored_field(constructor, operand)
        test_owner = self.owner_for(path, call)
        if field is None or test_owner is None or self.field_used(test_owner, field):
            return None
        value = super().construct(flow, path, call, args, kwargs)
        if value is not None:
            self.client_fields[next(iter(value.class_roots))] = field
            self.witness(class_path, constructor, "test_client_inert_credential_store")
        return value

    @staticmethod
    def stored_field(constructor, operand):
        args = constructor.args
        parameters = {
            par.arg for par in (*args.args, *args.posonlyargs, *args.kwonlyargs)
        }
        positional = (*args.posonlyargs, *args.args)
        if not positional or args.vararg or args.kwarg or constructor.decorator_list:
            return None
        receiver = positional[0].arg
        fields = {}
        for node in constructor.body:
            match node:
                case ast.Assign(
                    targets=[ast.Attribute(value=ast.Name(id=root), attr=field)],
                    value=(ast.Name() | ast.Constant()) as value,
                ) if (
                    root == receiver
                    and not field.startswith("__")
                    and field not in fields
                ):
                    if isinstance(value, ast.Name) and (
                        value.id == receiver or value.id not in parameters
                    ):
                        return None
                    fields[field] = value
                case _:
                    return None
        matches = [
            field
            for field, value in fields.items()
            if isinstance(value, ast.Name) and value.id == operand
        ]
        return matches[0] if len(matches) == 1 else None

    @staticmethod
    def field_used(scope, field):
        return any(
            isinstance(node, ast.Attribute) and node.attr == field
            for node in ast.walk(scope)
        )

    def resolve_call(self, path, call, receiver):
        selected = super().resolve_call(path, call, receiver)
        if selected is None or receiver is None or len(receiver.class_roots) != 1:
            return selected
        field = self.client_fields.get(next(iter(receiver.class_roots)))
        if field is None:
            return selected
        if selected.function.name.startswith("__") or self.field_used(
            selected.function, field
        ):
            return None
        if any(
            handler.type is not None
            and (
                not isinstance(handler.type, ast.Name)
                or handler.type.id
                not in {"Exception", "IndexError", "KeyError", "ValueError"}
                or not self.audit._app_builtin_annotation_inert(
                    self.index, selected.path, handler.type
                )
            )
            for handler in ast.walk(selected.function)
            if isinstance(handler, ast.ExceptHandler)
        ):
            return None
        return selected

    def resolve_attribute(self, flow, path, node, receiver):
        # Reaching a descriptor on the client would invoke code outside the
        # named-method consumer check. Ordinary captured fields still resolve
        # from the flow's owned heap before this hook.
        if self.client_fields.keys() & receiver.class_roots:
            return None
        return super().resolve_attribute(flow, path, node, receiver)

    def contract(self, flow, path, call, receiver, args, kwargs):
        if (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "split"
            and receiver is not None
        ):
            source = _scope_exact_text(receiver)
            separator = (
                _scope_exact_text(args[0]) if len(args) == 1 and not kwargs else None
            )
            if source is not None and len(source) <= 4096 and separator:
                items = tuple(
                    (position, _constant_identity_value(ast.Constant(value=value)))
                    for position, value in enumerate(source.split(separator))
                )
                if len(items) <= 128:
                    return flow.allocate_container(path, call, "list", items)
        if (
            isinstance(call.func, ast.Name)
            and call.func.id == "Exception"
            and isinstance(self.source.parents[path].get(id(call)), ast.Raise)
            and len(args) == 1
            and not kwargs
            and _scope_exact_text(args[0]) is not None
            and self.audit._app_builtin_annotation_inert(self.index, path, call.func)
        ):
            return _constant_identity_value(ast.Constant(value=None))
        return super().contract(flow, path, call, receiver, args, kwargs)
