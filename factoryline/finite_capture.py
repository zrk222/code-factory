"""Bounded source-origin capture for finite templates."""

import ast
import hashlib
from collections import defaultdict


def shell_execution_calls():
    """Return the shared canonical process primitives modeled by this scanner."""
    return (
        "os.system subprocess.run subprocess.Popen subprocess.call "
        "subprocess.check_call subprocess.check_output"
    ).split()


def _closed_shell_operation(command):
    """Recognize simple non-interpreter operations, never arbitrary shell safety."""
    import re

    if not isinstance(command, str) or not re.fullmatch(
        r"[A-Za-z0-9_.@+* -]{1,512}", command
    ):
        return None
    words = command.split()
    if len(words) == 3 and words[:2] == ["brew", "--prefix"]:
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@+-]*", words[2]):
            return "package_prefix_query"
    if len(words) >= 3 and words[:2] == ["upx", "--best"]:
        targets = words[3:] if words[2] == "--force-macos" else words[2:]
        if targets and all(
            re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+-]*(?:\*[A-Za-z0-9_.+-]+)?", word)
            for word in targets
        ):
            return "executable_packing"
    return None


def _closed_shell_call_role(call, call_name):
    """Accept one literal argument and explicit supported shell call options."""
    if len(call.args) != 1 or not isinstance(call.args[0], ast.Constant):
        return None
    if any(kw.arg is None for kw in call.keywords):
        return None
    if call_name == "os.system":
        if call.keywords:
            return None
    elif not any(
        kw.arg == "shell"
        and isinstance(kw.value, ast.Constant)
        and kw.value.value is True
        for kw in call.keywords
    ):
        return None
    # An overridden executable could use the same arguments for different effects.
    if any(
        kw.arg
        not in {
            "shell",
            "text",
            "encoding",
            "errors",
            "capture_output",
            "check",
            "timeout",
        }
        or not isinstance(kw.value, ast.Constant)
        for kw in call.keywords
    ):
        return None
    return _closed_shell_operation(call.args[0].value)


def _closed_shell_provider_mutated(node, head, supported):
    """Reject source-visible provider writes, reflection and monkey patches."""
    if isinstance(node, ast.ImportFrom) and any(
        alias.name == "*" for alias in node.names
    ):
        return True
    if (
        isinstance(node, ast.Name)
        and node.id == head
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ):
        return True
    if isinstance(node, ast.arg) and node.arg == head:
        return True
    if (
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.name == head
    ):
        return True
    if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
        base = node.value
        while isinstance(base, ast.Attribute):
            base = base.value
        if (isinstance(base, ast.Name) and base.id == head) or node.attr in {
            name.rsplit(".", 1)[-1] for name in supported
        }:
            return True
    if isinstance(node, ast.Call) and (
        node.func.id
        if isinstance(node.func, ast.Name)
        else getattr(node.func, "attr", "")
    ) in {
        "eval",
        "exec",
        "globals",
        "locals",
        "vars",
        "setattr",
        "delattr",
        "getattr",
        "__import__",
        "patch",
    }:
        return True
    return False


def _closed_shell_provider(tree, call, call_name, supported):
    """Bind a simple process call to one stable module-level provider import."""
    func = call.func
    name = (
        func.id
        if isinstance(func, ast.Name)
        else (
            f"{func.value.id}.{func.attr}"
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
            else ""
        )
    )
    head = name.partition(".")[0]
    imports = []
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            imports.extend(
                (alias.asname or alias.name.split(".")[0], alias.name)
                for alias in statement.names
            )
        elif isinstance(statement, ast.ImportFrom) and not statement.level:
            imports.extend(
                (alias.asname or alias.name, f"{statement.module}.{alias.name}")
                for alias in statement.names
            )
    origins = [origin for alias, origin in imports if alias == head]
    if len(origins) != 1 or origins[0] + name[len(head) :] != call_name:
        return False
    if not _closed_shell_namespace(tree, head):
        return False
    return not any(
        _closed_shell_provider_mutated(node, head, supported) for node in ast.walk(tree)
    )


def _closed_shell_namespace(tree, head):
    """Reject capability escapes, namespace access and aliased reflection."""
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    reflective = {
        "eval",
        "exec",
        "globals",
        "locals",
        "vars",
        "setattr",
        "delattr",
        "getattr",
        "__import__",
    }
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and node.id == head
            and isinstance(node.ctx, ast.Load)
        ):
            if not isinstance(parents.get(node), ast.Attribute):
                return False
        if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            base = node.value
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name) and base.id == head:
                return False
        if isinstance(node, ast.ImportFrom) and node.module in {
            "builtins",
            "__builtin__",
        }:
            if any(alias.name in reflective for alias in node.names):
                return False
    return True


def _shell_source_provider_clear(raw, provider):
    """Reuse provider mutation/escape indexing across captured helper modules."""
    from . import review_audits as audit

    try:
        tree = ast.parse(raw)
    except (SyntaxError, ValueError, RecursionError):
        return False
    nodes = list(ast.walk(tree))
    aliases = _shell_import_aliases(nodes, audit, provider)
    if aliases is None:
        return False
    parents = {
        id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)
    }
    # Index maximal provider expressions: passing os.environ does not expose os.
    maximal = [
        node
        for node in nodes
        if not (
            isinstance(node, (ast.Name, ast.Attribute))
            and isinstance(parents.get(id(node)), ast.Attribute)
            and parents[id(node)].value is node
        )
    ]
    mutations = finite_provider_mutation_index(maximal, aliases, audit, parents)
    if _shell_dynamic_provider_access(
        nodes, aliases, audit, parents, provider
    ) or not _shell_namespace_queries_closed(nodes, aliases, audit, parents, provider):
        return False
    leaves = (
        {"system"}
        if provider == "os"
        else {"run", "Popen", "call", "check_call", "check_output"}
    )
    if any(
        (path == provider and attribute in leaves | {"*"})
        or path.startswith(provider + ".")
        and path.split(".")[1] in leaves
        for path, attribute in mutations
    ):
        return False
    for node in nodes:
        if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            origin = audit._resolved_ast_name(node, aliases)
            if origin.startswith(provider + "."):
                return False
        if isinstance(node, ast.Attribute) and node.attr == "modules":
            if any(isinstance(n, ast.Constant) and n.value == provider for n in nodes):
                return False
    return True


def _shell_import_aliases(nodes, audit, provider):
    """Preserve imported capability origins instead of flat last-binding wins."""
    origins = defaultdict(set)
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                origins[alias.asname or alias.name.split(".")[0]].add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                origins[alias.asname or alias.name].add(
                    "." * node.level + (node.module or "") + "." + alias.name
                )
    protected = {provider, "builtins", "importlib"}
    if any(
        len(values) > 1 and any(value.split(".")[0] in protected for value in values)
        for values in origins.values()
    ):
        return None
    return audit._security_aliases(nodes)


def _shell_dynamic_provider_access(nodes, aliases, audit, parents, provider):
    """Reject dynamic provider lookup and importer capability escapes."""
    importers = {"__import__", "builtins.__import__", "importlib.import_module"}
    for node in nodes:
        if not isinstance(node, (ast.Name, ast.Attribute)):
            continue
        if audit._resolved_ast_name(node, aliases) not in importers:
            continue
        parent = parents.get(id(node))
        if not isinstance(parent, ast.Call) or parent.func is not node:
            return True
        if not parent.args or not isinstance(parent.args[0], ast.Constant):
            return True
        module = parent.args[0].value
        if not isinstance(module, str) or module.split(".")[0] == provider:
            return True
        result_use = parents.get(id(parent))
        if not (
            isinstance(result_use, ast.Attribute)
            and result_use.attr == "__file__"
            and isinstance(result_use.ctx, ast.Load)
        ):
            return True
    return False


def _shell_namespace_queries_closed(nodes, aliases, audit, parents, provider):
    """Allow namespace presence queries without exposing mutable namespace maps."""
    for node in nodes:
        if not isinstance(node, (ast.Name, ast.Attribute)):
            continue
        canonical = audit._resolved_ast_name(node, aliases).removeprefix("builtins.")
        if canonical not in {"globals", "locals", "vars"}:
            continue
        call = parents.get(id(node))
        comparison = parents.get(id(call))
        if not (
            isinstance(call, ast.Call)
            and call.func is node
            and not call.args
            and not call.keywords
            and isinstance(comparison, ast.Compare)
            and len(comparison.ops) == 1
            and isinstance(comparison.ops[0], (ast.In, ast.NotIn))
            and comparison.comparators == [call]
            and isinstance(comparison.left, ast.Constant)
            and isinstance(comparison.left.value, str)
            and comparison.left.value != provider
        ):
            return False
    return True


def closed_shell_workspace(sources, provider):
    """Hash the complete consulted source inventory after provider checks."""
    import json

    if not sources or any(
        path.rsplit("/", 1)[-1] in {provider + ".py", "__init__.py"}
        and provider in path.replace(".py", "").split("/")
        for path in sources
    ):
        return None
    if not all(
        isinstance(raw, bytes) and _shell_source_provider_clear(raw, provider)
        for raw in sources.values()
    ):
        return None
    return hashlib.sha256(
        json.dumps(
            sorted(
                (path, hashlib.sha256(raw).hexdigest()) for path, raw in sources.items()
            ),
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def closed_shell_operation_witness(raw, relative, span, call_name):
    """Reconstruct a literal shell-injection classification from captured bytes."""
    if not isinstance(raw, bytes) or len(raw) > 1_000_000:
        return {}
    supported = shell_execution_calls()
    if call_name not in supported:
        return {}
    try:
        tree = ast.parse(raw)
    except (SyntaxError, ValueError, RecursionError):
        return {}
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and [
            getattr(node, key, None)
            for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
        ]
        == span
    ]
    if len(calls) != 1:
        return {}
    call = calls[0]
    role = _closed_shell_call_role(call, call_name)
    if role is None or not _closed_shell_provider(tree, call, call_name, supported):
        return {}
    command = call.args[0].value
    return {
        "schema": "factory.closed-shell-operation.v1",
        "disposition": "PROVEN_CLOSED_OPERATION_COMMAND_SYNTAX",
        "source_path": relative,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "call_span": span,
        "call": call_name,
        "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
        "operation_role": role,
        "hypothesis": "SOURCE_COMMAND_INJECTION",
        "input_effect": "CLOSED_LITERAL_COMMAND_SYNTAX",
        "operational_effects": "LOCAL_ARTIFACT_MUTATION"
        if role == "executable_packing"
        else "METADATA_QUERY",
        "runtime_assurance": "INCOMPLETE",
        "filesystem_assurance": "UNASSESSED",
        "executable_provenance": "UNASSESSED",
        "target_execution": "not_performed",
    }


def closed_shell_finding(call_name, relative, node):
    """Keep supported fixed-operation primitives separate from injection defects."""
    from . import review_audits as audit

    if call_name not in shell_execution_calls():
        return None
    module = audit.integrity._security_module_scope(
        getattr(node, "_security_lexical_scope", None)
    )
    context = getattr(module, "_security_source_context", None)
    if not isinstance(context, tuple) or len(context) != 2:
        return None
    root, sources = context
    raw = sources.get(root / relative)
    provider = call_name.split(".")[0]
    if any(
        path.relative_to(root).parts[0] in {provider, provider + ".py"}
        for path in sources
    ):
        return None
    span = [
        getattr(node, key, None)
        for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
    ]
    proof = closed_shell_operation_witness(raw, relative, span, call_name)
    if not proof or proof["source_sha256"] != getattr(
        module, "_oracle_source_sha256", None
    ):
        return None
    captured = {
        path.relative_to(root).as_posix(): data
        for path, data in sources.items()
        if path.suffix == ".py"
    }
    inventory = closed_shell_workspace(captured, provider)
    if inventory is None:
        return None
    proof["workspace_sources_sha256"] = inventory
    return audit._security_finding(
        "SECURITY_OS_COMMAND" if call_name == "os.system" else "SECURITY_SHELL_COMMAND",
        relative,
        node,
        "Fixed supported command syntax has no source injection input; executable, filesystem and runtime safety remain unassessed.",
        "INFO",
        **proof,
    )


def _finite_membership_reference(use, parent):
    if not isinstance(parent, ast.Compare) or use not in parent.comparators:
        return False
    index = parent.comparators.index(use)
    return isinstance(parent.ops[index], (ast.In, ast.NotIn))


def _finite_container_reference(use, parent, parents):
    if not isinstance(parent, ast.Starred):
        return False
    container = parents.get(id(parent))
    return isinstance(container, ast.Set) and parent.value is use


def _finite_call_reference(use, parent):
    if not isinstance(parent, ast.Call) or use not in parent.args or parent.keywords:
        return False
    target = parent.func
    if not isinstance(target, ast.Attribute):
        return False
    if target.attr == "intersection" and isinstance(
        target.value, (ast.Set, ast.SetComp)
    ):
        return True
    return (
        target.attr == "join"
        and isinstance(target.value, ast.Constant)
        and type(target.value.value) is str
    )


def finite_domain_reference_allowed(
    path, use, tail, capture_path, capture_name, capture, parents
):
    """Allow only modeled finite-domain capture and read shapes."""
    parent = parents.get(id(use))
    if not tail and path == capture_path and use is capture_name:
        return parent is capture and capture.args[0] is use
    if tail:
        return False
    return (
        _finite_membership_reference(use, parent)
        or _finite_container_reference(use, parent, parents)
        or _finite_call_reference(use, parent)
    )


def finite_provider_attribute_write_index(nodes, aliases, audit, parents=None):
    """Build the finite provider-attribute mutation set using the shared provider mutation analysis."""
    return finite_provider_mutation_index(nodes, aliases, audit, parents or {})


def finite_blocked_provider_prefixes(blocked, aliases):
    """Expand blocked provider aliases into every dotted prefix used to reject descendants."""
    prefixes = set()
    for path, name in blocked:
        origin = aliases.get(path, {}).get(name)
        if isinstance(origin, str):
            parts = origin.split(".")
            prefixes.update(".".join(parts[:i]) for i in range(1, len(parts) + 1))
    return prefixes


def finite_scope_binding_candidate(node, origins):
    """Recognize parameter, store/delete name, global, or nonlocal bindings that intersect the finite origin set."""
    if isinstance(node, ast.arg):
        return node.arg in origins
    if isinstance(node, ast.Name):
        return node.id in origins and isinstance(node.ctx, (ast.Store, ast.Del))
    return isinstance(node, (ast.Global, ast.Nonlocal)) and bool(
        origins.intersection(node.names)
    )


def _finite_capture_decorator(function, aliases, audit):
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
    return decorator


def _finite_capture_parameter(function, decorator):
    if len(function.args.args) != 1 or len(decorator.args) != 2:
        return None
    if (
        not isinstance(decorator.args[0], ast.Constant)
        or type(decorator.args[0].value) is not str
        or function.args.args[0].arg != decorator.args[0].value
    ):
        return None
    return decorator.args[0].value


def _finite_sorted_capture(capture, integrity):
    if not isinstance(capture, ast.Call) or not isinstance(capture.func, ast.Name):
        return None
    if capture.func.id != "sorted" or len(capture.args) != 1 or capture.keywords:
        return None
    if integrity._builtin_repr_names_shadowed(capture, {"sorted"}):
        return None
    return capture


def finite_template_capture_shape(function, aliases, audit, integrity):
    """Recognize one pytest parameter capturing a sorted finite domain."""
    decorator = _finite_capture_decorator(function, aliases, audit)
    if decorator is None:
        return None
    parameter = _finite_capture_parameter(function, decorator)
    if parameter is None:
        return None
    capture = decorator.args[1]
    capture = _finite_sorted_capture(capture, integrity)
    return (parameter, capture) if capture is not None else None


class _FiniteInputCapture:
    def finite_template_inputs(self):
        """Build source-hashed finite-template witnesses only when snapshots, parameter domains, call sites, and template hashes are complete."""
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


def _fixed_literal_value(node):
    literal_types = (str, bytes, int, float, complex, bool, type(None), type(Ellipsis))
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, ast.Constant):
            if type(current.value) not in literal_types:
                return False
        elif isinstance(current, ast.UnaryOp):
            if (
                not isinstance(current.op, (ast.UAdd, ast.USub))
                or not isinstance(current.operand, ast.Constant)
                or type(current.operand.value) not in {int, float, complex}
            ):
                return False
            stack.append(current.operand)
        elif isinstance(current, ast.Dict):
            if any(key is None for key in current.keys):
                return False
            stack.extend(ast.iter_child_nodes(current))
        elif isinstance(current, (ast.List, ast.Tuple, ast.Set, ast.Load)):
            stack.extend(ast.iter_child_nodes(current))
        else:
            return False
    try:
        ast.literal_eval(node)
    except (
        ValueError,
        TypeError,
        SyntaxError,
        MemoryError,
        RecursionError,
        OverflowError,
    ):
        return False
    return True


def _finite_eval_comprehension(tree, call):
    parents = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
    cursor = parents.get(call)
    while cursor is not None and not isinstance(cursor, ast.ListComp):
        if isinstance(
            cursor, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            return None
        cursor = parents.get(cursor)
    if cursor is None or len(cursor.generators) != 1:
        return None
    return cursor


def _finite_eval_domain(cursor, call):
    if cursor is None:
        return None
    generator = cursor.generators[0]
    if (
        generator.is_async
        or generator.ifs
        or not isinstance(generator.target, ast.Tuple)
        or not all(isinstance(n, ast.Name) for n in generator.target.elts)
        or not isinstance(generator.iter, (ast.List, ast.Tuple))
        or not 1 <= len(generator.iter.elts) <= 64
    ):
        return None
    names = [n.id for n in generator.target.elts]
    if len(set(names)) != len(names) or call.args[0].id not in names:
        return None
    target = generator.target.elts[names.index(call.args[0].id)]
    if any(
        n.id == target.id and n is not target and n is not call.args[0]
        for n in ast.walk(cursor)
        if isinstance(n, ast.Name)
    ):
        return None
    programs = []
    for row in generator.iter.elts:
        if (
            not isinstance(row, (ast.Tuple, ast.List))
            or len(row.elts) != len(names)
            or not _fixed_literal_value(row)
        ):
            return None
        value = row.elts[names.index(target.id)]
        if (
            not isinstance(value, ast.Constant)
            or type(value.value) is not str
            or len(value.value) > 4096
        ):
            return None
        try:
            expression = ast.parse(value.value, mode="eval")
        except (SyntaxError, ValueError, RecursionError):
            return None
        allowed = (
            ast.Expression,
            ast.Name,
            ast.Subscript,
            ast.Tuple,
            ast.List,
            ast.Load,
            ast.Constant,
            ast.BinOp,
            ast.BitOr,
        )
        if any(not isinstance(n, allowed) for n in ast.walk(expression)):
            return None
        programs.append(value.value)
    return generator.iter, programs


def _finite_eval_module_prefix(tree, comprehension):
    """Module initializer profile: later test bodies cannot run before this input."""
    prefix = []
    for statement in tree.body:
        if (
            isinstance(statement, (ast.Assign, ast.AnnAssign))
            and statement.value is comprehension
        ):
            return ast.Module(body=[*prefix, statement], type_ignores=[])
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            prefix.append(statement)
        elif isinstance(
            statement, (ast.Assign, ast.AnnAssign)
        ) and _fixed_literal_value(statement.value):
            prefix.append(statement)
        else:
            return None
    return None


def _finite_eval_source_shape(node, call_name, source_bytes, source_path):
    if (
        call_name != "eval"
        or not isinstance(node, ast.Call)
        or not isinstance(node.func, ast.Name)
        or node.func.id != "eval"
        or len(node.args) != 1
        or node.keywords
        or not isinstance(node.args[0], ast.Name)
        or not isinstance(source_bytes, bytes)
        or not isinstance(source_path, str)
    ):
        return False
    return True


def _finite_eval_source_call(node, call_name, source_bytes, source_path):
    if not _finite_eval_source_shape(node, call_name, source_bytes, source_path):
        return None
    try:
        tree = ast.parse(source_bytes)
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return None

    matches = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and _finite_source_span(n) == _finite_source_span(node)
    ]
    if len(matches) != 1 or ast.dump(matches[0]) != ast.dump(node):
        return None
    return tree, matches[0]


def _finite_source_span(node):
    return [
        getattr(node, key, None)
        for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
    ]


def _finite_eval_closed_domain(tree, call):
    comprehension = _finite_eval_comprehension(tree, call)
    domain = _finite_eval_domain(comprehension, call)
    if domain is None:
        return None
    prefix = _finite_eval_module_prefix(tree, comprehension)
    if prefix is None:
        return None
    from .runtime_audit_integrity import _closed_declaration_binding

    if not _closed_declaration_binding(prefix, call):
        return None
    return comprehension, domain


def _finite_eval_witness_facts(source_bytes, source_path, call, comprehension, domain):
    domain_node, programs = domain
    import json

    return {
        "schema": "factory.finite-eval-input.v1",
        "disposition": "PROVEN_FINITE_LITERAL_EVAL_INPUT",
        "source_path": source_path,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "call_span": _finite_source_span(call),
        "domain_span": _finite_source_span(domain_node),
        "comprehension_span": _finite_source_span(comprehension),
        "program_sha256": hashlib.sha256(
            json.dumps(programs, separators=(",", ":")).encode()
        ).hexdigest(),
        "domain_size": len(programs),
        "hypothesis": "ARGUMENT_CODE_INJECTION",
        "scope_profile": "module-initializer-literal-table",
        "input_effect": "CLOSED_LITERAL_TYPE_EXPRESSIONS",
        "runtime_assurance": "INCOMPLETE",
        "target_execution": "not_performed",
    }


def finite_literal_eval_input_witness(node, call_name, *, source_bytes, source_path):
    """Prove finite source input only, not the effects of resolving type objects."""
    source_call = _finite_eval_source_call(node, call_name, source_bytes, source_path)
    if source_call is None:
        return {}
    tree, call = source_call
    closed_domain = _finite_eval_closed_domain(tree, call)
    if closed_domain is None:
        return {}
    comprehension, domain = closed_domain
    return _finite_eval_witness_facts(
        source_bytes, source_path, call, comprehension, domain
    )


def _finite_template_program_hash(program, value):
    import keyword

    if (
        not isinstance(value, str)
        or not value.isidentifier()
        or keyword.iskeyword(value)
    ):
        return None
    try:
        if len(program.encode("utf-8")) > 4096:
            return None
        tree = ast.parse(program, mode="exec")
    except (SyntaxError, ValueError, MemoryError, RecursionError, UnicodeError):
        return None
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.AsyncFunctionDef):
        return None
    function = tree.body[0]
    args = function.args
    if (
        function.decorator_list
        or args.posonlyargs
        or len(args.args) != 1
        or args.args[0].arg != value
        or args.vararg is not None
        or args.kwonlyargs
        or args.kwarg is not None
        or args.defaults
        or args.kw_defaults
        or not isinstance(function.returns, ast.Constant)
        or function.returns.value is not None
        or len(function.body) != 1
        or not isinstance(function.body[0], ast.Pass)
    ):
        return None
    args.args[0].arg = "FINITE_PARAMETER"
    return hashlib.sha256(program.encode("utf-8")).hexdigest(), ast.dump(
        tree, include_attributes=False
    )


def _finite_template_piece(item, parameter):
    if isinstance(item, ast.Constant) and type(item.value) is str:
        return True, item.value, False
    if (
        isinstance(item, ast.FormattedValue)
        and isinstance(item.value, ast.Name)
        and item.value.id == parameter
        and item.conversion == -1
        and item.format_spec is None
    ):
        return True, None, True
    return False, None, False


def _finite_template_skeleton(template, parameter, values):
    if not isinstance(template, ast.JoinedStr) or not isinstance(parameter, str):
        return None
    pieces, holes = [], 0
    for item in template.values:
        valid, piece, is_hole = _finite_template_piece(item, parameter)
        if not valid:
            return None
        pieces.append(piece)
        holes += is_hole
    if holes != 1 or not 1 <= len(values) <= 64:
        return None
    return pieces


def _finite_template_hash_rows(pieces, values):
    hashes, skeleton = [], None
    for value in values:
        program = "".join(value if part is None else part for part in pieces)
        result = _finite_template_program_hash(program, value)
        if result is None or (skeleton is not None and result[1] != skeleton):
            return None
        hashes.append(result[0])
        skeleton = result[1]
    return hashlib.sha256(skeleton.encode()).hexdigest(), hashes


def finite_template_program_hashes(template, parameter, values):
    """Hash every bounded rendering after checking one fixed async-function grammar."""
    pieces = _finite_template_skeleton(template, parameter, values)
    if pieces is None:
        return None
    return _finite_template_hash_rows(pieces, values)


def _provider_mutation_for_node(
    node, aliases, audit, parents, bindings, facts, capture_predicate
):
    if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
        _record_provider_paths(node.value, node.attr, aliases, audit, bindings, facts)
    elif isinstance(node, ast.Call):
        _reflective_provider_write(node, aliases, audit, bindings, facts)
    elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
        if capture_predicate is None or capture_predicate(node):
            _record_provider_capture(node, aliases, audit, bindings, facts)
    elif isinstance(node, (ast.Name, ast.Attribute)) and _provider_call_argument(
        node, parents
    ):
        _record_provider_paths(node, "*", aliases, audit, bindings, facts)
    elif isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)):
        _record_provider_paths(node.value, "*", aliases, audit, bindings, facts)


def finite_provider_mutation_index(
    nodes, aliases, audit, parents, *, capture_predicate=None
):
    """Collect provider mutation facts from writes, reflective calls, captured assignments, passed aliases, and returned aliases."""
    bindings = _provider_alias_bindings(nodes)
    facts = set()
    for node in nodes:
        _provider_mutation_for_node(
            node, aliases, audit, parents, bindings, facts, capture_predicate
        )
    return facts


def _record_provider_paths(node, attribute, aliases, audit, bindings, facts):
    paths, uncertain = _provider_paths(node, aliases, audit, bindings)
    facts.update((path, attribute) for path in paths)
    if uncertain:
        facts.update((path, "*") for path in paths)


def _record_provider_capture(node, aliases, audit, bindings, facts):
    value = node.value
    paths, _ = _provider_paths(value, aliases, audit, bindings)
    facts.update((path, "*") for path in paths)


def _provider_alias_bindings(nodes):
    bindings = defaultdict(list)
    for node in nodes:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bindings[target.id].append(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None:
                bindings[node.target.id].append(node.value)
    return bindings


def _provider_paths(node, aliases, audit, bindings, seen=frozenset(), depth=0):
    if depth > 16 or not isinstance(node, (ast.Name, ast.Attribute)):
        return set(), True
    if isinstance(node, ast.Attribute):
        paths, uncertain = _provider_paths(
            node.value, aliases, audit, bindings, seen, depth + 1
        )
        return {path + "." + node.attr for path in paths}, uncertain
    canonical = audit._resolved_ast_name(node, aliases)
    if "." in canonical:
        return {canonical}, False
    if aliases.get(node.id) == canonical and canonical:
        return {canonical}, False
    if node.id in seen:
        return set(), True
    values = bindings.get(node.id)
    if not values:
        return set(), True
    paths = set()
    uncertain = False
    for value in values:
        found, unknown = _provider_paths(
            value, aliases, audit, bindings, seen | {node.id}, depth + 1
        )
        paths.update(found)
        uncertain = uncertain or unknown or not found
    return paths, uncertain and bool(paths)


def _provider_call_argument(node, parents):
    child = node
    parent = parents.get(id(child))
    while parent is not None and not isinstance(parent, ast.Call):
        child = parent
        parent = parents.get(id(parent))
    return bool(
        isinstance(parent, ast.Call)
        and (
            any(argument is child for argument in parent.args)
            or any(keyword.value is child for keyword in parent.keywords)
        )
    )


def _reflective_provider_write(call, aliases, audit, bindings, facts):
    function = call.func
    canonical = audit._resolved_ast_name(function, aliases)
    receiver = None
    attribute = None
    if canonical in {"setattr", "builtins.setattr"} and len(call.args) >= 2:
        receiver, attribute = call.args[:2]
    elif (
        isinstance(function, ast.Attribute)
        and function.attr == "__setattr__"
        and call.args
    ):
        receiver, attribute = function.value, call.args[0]
    if receiver is None:
        return
    paths, uncertain = _provider_paths(receiver, aliases, audit, bindings)
    name = (
        attribute.value
        if isinstance(attribute, ast.Constant) and type(attribute.value) is str
        else "*"
    )
    facts.update((path, name) for path in paths)
    if uncertain:
        facts.update((path, "*") for path in paths)
