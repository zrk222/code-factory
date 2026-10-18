"""Bounded source-origin capture for finite templates."""

import ast
import hashlib

from .finite_inputs import finite_template_program_hashes
from .provider_mutations import finite_provider_mutation_index


def finite_domain_reference_allowed(
    path, use, tail, capture_path, capture_name, capture, parents
):
    if tail:
        return False
    parent = parents.get(id(use))
    if path == capture_path and use is capture_name:
        return parent is capture and capture.args[0] is use
    if isinstance(parent, ast.Compare) and use in parent.comparators:
        index = parent.comparators.index(use)
        return isinstance(parent.ops[index], (ast.In, ast.NotIn))
    if isinstance(parent, ast.Starred):
        container = parents.get(id(parent))
        return isinstance(container, ast.Set) and parent.value is use
    if isinstance(parent, ast.Call) and use in parent.args and not parent.keywords:
        target = parent.func
        if isinstance(target, ast.Attribute) and use in parent.args:
            if target.attr == "intersection" and isinstance(
                target.value, (ast.Set, ast.SetComp)
            ):
                return True
            if (
                target.attr == "join"
                and isinstance(target.value, ast.Constant)
                and type(target.value.value) is str
            ):
                return True
    return False


def finite_provider_attribute_write_index(nodes, aliases, audit, parents=None):
    return finite_provider_mutation_index(nodes, aliases, audit, parents or {})


def finite_blocked_provider_prefixes(blocked, aliases):
    prefixes = set()
    for path, name in blocked:
        origin = aliases.get(path, {}).get(name)
        if isinstance(origin, str):
            parts = origin.split(".")
            prefixes.update(".".join(parts[:i]) for i in range(1, len(parts) + 1))
    return prefixes


def finite_scope_binding_candidate(node, origins):
    if isinstance(node, ast.arg):
        return node.arg in origins
    if isinstance(node, ast.Name):
        return node.id in origins and isinstance(node.ctx, (ast.Store, ast.Del))
    return isinstance(node, (ast.Global, ast.Nonlocal)) and bool(
        origins.intersection(node.names)
    )


def finite_template_capture_shape(function, aliases, audit, integrity):
    if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    if len(function.decorator_list) != 1 or len(function.args.args) != 1:
        return None
    decorator = function.decorator_list[0]
    if not isinstance(decorator, ast.Call) or len(decorator.args) != 2:
        return None
    if (
        decorator.keywords
        or audit._resolved_ast_name(decorator.func, aliases)
        != "pytest.mark.parametrize"
    ):
        return None
    capture = decorator.args[1]
    if (
        not isinstance(decorator.args[0], ast.Constant)
        or type(decorator.args[0].value) is not str
    ):
        return None
    if function.args.args[0].arg != decorator.args[0].value:
        return None
    if not isinstance(capture, ast.Call) or not isinstance(capture.func, ast.Name):
        return None
    if capture.func.id != "sorted" or len(capture.args) != 1 or capture.keywords:
        return None
    if integrity._builtin_repr_names_shadowed(capture, {"sorted"}):
        return None
    return function.args.args[0].arg, capture


class _FiniteInputCapture:
    def finite_template_inputs(self):
        if not self.snapshot_complete:
            return {}
        rows = {}
        for path, tree in self.trees.items():
            for function in tree.body:
                profile = self._finite_template_profile(path, function)
                if profile is None:
                    continue
                parameter, capture, domain_path, domain_name, domain, values = profile
                calls = self._finite_template_exec_calls(function)
                if not calls:
                    continue
                for call in calls:
                    template_node = call.args[0]
                    program_proof = finite_template_program_hashes(
                        template_node, parameter, values
                    )
                    if program_proof is None:
                        continue
                    _, program_hashes = program_proof
                    rows[path, call.lineno, call.col_offset] = {
                        "schema": "factory.finite-template-input.v1",
                        "disposition": "PROVEN_FINITE_TEMPLATE_INPUT",
                        "hypothesis": "ARGUMENT_CODE_INJECTION",
                        "input_effect": "FINITE_SOURCE_TEMPLATE_INPUT",
                        "runtime_assurance": "INCOMPLETE",
                        "execution_effects": "UNASSESSED",
                        "target_execution": "not_performed",
                        "source_path": path.relative_to(self.root).as_posix(),
                        "source_sha256": self.inventory[path],
                        "capture_path": path.relative_to(self.root).as_posix(),
                        "capture_sha256": self.inventory[path],
                        "capture_span": self._finite_span(capture),
                        "domain_path": domain_path.relative_to(self.root).as_posix(),
                        "domain_sha256": self.inventory[domain_path],
                        "domain_span": self._finite_span(domain),
                        "call_span": self._finite_span(call),
                        "template_span": self._finite_span(template_node),
                        "template_sha256": hashlib.sha256(
                            ast.dump(template_node, include_attributes=False).encode()
                        ).hexdigest(),
                        "domain_size": len(values),
                        "program_hashes": program_hashes,
                        "scope_profile": "pytest-collection-finite-parameter",
                    }
        return rows if self.snapshot_complete else {}

    def _finite_template_profile(self, path, function):
        candidate = finite_template_capture_shape(
            function, self.aliases[path], self.audit, self.integrity
        )
        if candidate is None:
            return None
        parameter_name, capture = candidate
        if (
            not self._finite_pytest_provider_closed(path)
            or not self._provider_is_unmodified("builtins", {"sorted", "exec"})
            or not self._finite_module_initializer_safe(self.trees[path])
        ):
            return None
        if not isinstance(capture.args[0], ast.Name):
            return None
        name = capture.args[0].id
        origin = self.resolve(path, (name,))
        if (
            not origin
            or origin[0] != "value"
            or origin[3]
            or (path, name) in self.blocked
        ):
            return None
        domain_path, domain_name = origin[1:3]
        if not self._finite_module_initializer_safe(self.trees[domain_path]):
            return None
        domain = self.objects.get((domain_path, domain_name))
        declaration = self._finite_domain_declaration(domain_path, domain_name, domain)
        values = self._finite_domain_values(domain)
        if (
            not declaration
            or values is None
            or not self._finite_domain_uses(
                domain_path, domain_name, path, capture.args[0], capture
            )
        ):
            return None
        if not self._finite_function_closed(path, function, parameter_name):
            return None
        return (
            parameter_name,
            capture,
            domain_path,
            domain_name,
            declaration,
            values,
        )

    def _finite_domain_declaration(self, path, name, value):
        binding = self._unique_name_assignment(self.trees[path], name)
        target = (
            binding.targets[0]
            if isinstance(binding, ast.Assign) and len(binding.targets) == 1
            else binding.target
            if isinstance(binding, ast.AnnAssign)
            else None
        )
        return (
            value
            if isinstance(value, ast.Set)
            and (path, name) not in self.blocked
            and isinstance(binding, (ast.Assign, ast.AnnAssign))
            and binding.value is value
            and isinstance(target, ast.Name)
            and target.id == name
            else None
        )

    def _finite_domain_values(self, domain):
        if not isinstance(domain, ast.Set) or not 1 <= len(domain.elts) <= 64:
            return None
        if any(
            not isinstance(node, ast.Constant) or type(node.value) is not str
            for node in domain.elts
        ):
            return None
        values = [node.value for node in domain.elts]
        return sorted(values) if len(set(values)) == len(values) else None

    def _finite_domain_uses(
        self, domain_path, domain_name, capture_path, capture_name, capture
    ):
        refs = self.refs.get(("value", domain_path, domain_name), [])
        if not refs or any(
            source == domain_path and symbol in {None, domain_name}
            for source, symbol in self.unmodeled_imports
        ):
            return False
        return all(
            finite_domain_reference_allowed(
                path, use, tail, capture_path, capture_name, capture, self.parents
            )
            for path, use, tail in refs
        )

    def _finite_function_closed(self, path, function, parameter_name):
        return not (
            self.refs.get(("function", path, function.name))
            or any(
                source == path and symbol in {None, function.name}
                for source, symbol in self.unmodeled_imports
            )
            or any(
                item == (path, function.name) or item == (path, None)
                for view in self.imports.values()
                for item in view.values()
            )
            or any(
                argument.arg == parameter_name
                for statement in function.body
                for argument in ast.walk(statement)
                if isinstance(argument, ast.arg)
            )
            or any(
                parameter_name in self.audit._bound_names(statement)
                for statement in function.body
            )
        )

    def _finite_template_exec_calls(self, function):
        calls = [
            node
            for node in self._walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "exec"
        ]
        if not 1 <= len(calls) <= 64:
            return None
        for call in calls:
            if (
                not call.args
                or not isinstance(call.args[0], ast.JoinedStr)
                or self.integrity._builtin_repr_names_shadowed(call, {"exec"})
            ):
                return None
        return calls

    @staticmethod
    def _finite_span(node):
        return [
            getattr(node, name, None)
            for name in ("lineno", "col_offset", "end_lineno", "end_col_offset")
        ]
