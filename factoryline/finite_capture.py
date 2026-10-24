"""Bounded source-origin capture for finite templates."""

import ast
import hashlib
from collections import defaultdict


def _security_helper_definition_supported(function):
    from . import review_integrity as flow

    defaults = [*function.args.defaults, *function.args.kw_defaults]
    if any(value is not None and not _fixed_literal_value(value) for value in defaults):
        return False
    annotations = [argument.annotation for argument in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs)]
    annotations.append(function.returns)
    annotations.extend(node.annotation for node in flow._lexical_nodes(function) if isinstance(node, ast.AnnAssign))
    if any(not _security_helper_annotation_supported(value) for value in annotations):
        return False
    return not any(
        isinstance(node, (ast.Yield, ast.YieldFrom, ast.Await, ast.Global, ast.Nonlocal))
        for node in flow._lexical_nodes(function)
    )


def _security_helper_annotation_supported(value):
    return value is None or isinstance(value, (ast.Name, ast.Constant))


def _security_helper_binding(call, function):
    """Bind a source-owned helper; decline mutation, expansion and recursion."""
    from . import review_integrity as flow

    if (
        not isinstance(function, ast.FunctionDef)
        or function.decorator_list or function.args.vararg or function.args.kwarg
        or getattr(function, "_security_helper_active", False)
    ):
        return None
    module = flow._security_module_scope(function)
    if module is None or getattr(module, "_security_helper_flow_depth", 0) >= 8:
        return None
    if sum(1 for _ in ast.walk(function)) > 512:
        return None
    if not _security_helper_definition_supported(function):
        return None
    try:
        actuals = flow.bind_source_call(call, function, apply_defaults=True)
    except ValueError:
        return None
    if not _security_helper_provider_stable(module, call, function):
        return None
    return module, actuals


def _security_helper_provider_stable(module, call, function):
    from . import intent_quality, review_audits as audit

    # The existing binder resets this cache for every captured-source scan.
    # Cache provider facts only: flow states and return values remain per call.
    cache = getattr(module, "_security_sanitizer_provider_cache", {})
    key = ("native-helper-provider", id(function), call.func.id)
    if key not in cache:
        aliases = {function.name: function.name, call.func.id: function.name}
        cache[key] = intent_quality._sanitizer_provider_mutated(
            module, call, aliases, function.name, call.func.id, audit
        )
        module._security_sanitizer_provider_cache = cache
    return not cache[key]


def _security_flow_value(expression, environment, aliases):
    from . import review_integrity as flow

    if sum(1 for _ in ast.walk(expression)) > 512:
        return False, None
    if isinstance(expression, ast.Name):
        value = environment.get(expression.id)
        return value is not None, value
    if _fixed_literal_value(expression):
        return True, False
    if not isinstance(expression, (ast.Call, ast.Attribute, ast.Subscript)):
        # A may-taint arithmetic expression is not a proved evaluable value.
        return False, None
    if isinstance(expression, ast.Call) and flow.security_call_name(expression, aliases) in {
        "os.path.join", "pathlib.Path", "pathlib.PurePath", "werkzeug.utils.secure_filename"
    }:
        return False, None
    tainted = {name for name, value in environment.items() if value is True}
    if flow._security_expr_tainted(expression, tainted, set(), aliases):
        return True, True
    return False, None


def _security_helper_initial(call, actuals, requests, parameters, aliases):
    supplied = {id(value) for value in call.args}
    supplied.update(id(keyword.value) for keyword in call.keywords)
    caller = {name: True for name in requests | parameters if isinstance(name, str)}
    initial = {}
    for name, value in actuals.items():
        # Omitted defaults belong to the definition, never to the caller's scope.
        if _fixed_literal_value(value):
            initial[name] = False
        elif id(value) in supplied:
            known, tainted = _security_flow_value(value, caller, aliases)
            initial[name] = tainted if known else None
        else:
            initial[name] = None
    return initial


def security_helper_return_tainted(call, function, requests, parameters, aliases):
    binding = _security_helper_binding(call, function)
    if binding is None:
        return False
    module, actuals = binding
    initial = _security_helper_initial(call, actuals, requests, parameters, aliases)
    if any(value is None for value in initial.values()):
        return False
    function._security_helper_active = True
    module._security_helper_flow_depth = getattr(module, "_security_helper_flow_depth", 0) + 1
    try:
        result = evaluate_helper_flow(
            function, initial,
            lambda expression, environment: _security_flow_value(expression, environment, aliases),
        )
        return result["status"] == "COMPLETE" and result["return_values"] == (True,)
    finally:
        function._security_helper_active = False
        module._security_helper_flow_depth -= 1


def security_forward_helper_sources(relative, call, aliases, requests, helpers):
    """Feed proven actual-argument sources into the existing callee sink pass."""
    from . import review_integrity as flow
    from .semantic_credential_sensor import security_precondition_path_possible, request_payload_value_kind

    if not security_precondition_path_possible(call):
        return
    actual_values = [*call.args, *(keyword.value for keyword in call.keywords)]
    if not any(flow._security_expr_tainted(value, requests, set(), aliases) for value in actual_values):
        return
    function = flow._security_local_helper_definition(call)
    binding = _security_helper_binding(call, function)
    if binding is None:
        return
    module, actuals = binding
    initial = _security_helper_initial(call, actuals, requests, set(), aliases)
    if any(value is None for value in initial.values()):
        return
    sources = {name for name, value in initial.items() if value is True}
    if not sources:
        return
    # This extension models straight-line local helpers only. Branches and
    # opaque side effects must not acquire a support verdict from this pass.
    if (
        any(not isinstance(statement, (ast.Assign, ast.AnnAssign, ast.Expr, ast.Return, ast.Pass)) for statement in function.body)
        or not _security_helper_sink_calls_supported(function, aliases, relative)
        or not _security_helper_prefix_supported(function, initial, aliases)
    ):
        return
    for name in tuple(sources):
        kind = request_payload_value_kind(actuals[name], requests, aliases, flow._security_scope_request_aliases)
        if kind:
            sources.add(("request-type:" + kind, name))
    function._security_helper_active = True
    module._security_helper_flow_depth = getattr(module, "_security_helper_flow_depth", 0) + 1
    try:
        # The normal raw scan owns emission. This pass supplies only native
        # source-bound preconditions on those same sink AST nodes.
        flow._security_analyze_source_sink_block(
            relative, function.body, function, aliases, sources, set(), set(), set(), set(), helpers
        )
    finally:
        function._security_helper_active = False
        module._security_helper_flow_depth -= 1


def _security_helper_sink_calls_supported(function, aliases, relative):
    from . import review_audits as audit, review_integrity as flow

    for node in flow._lexical_nodes(function):
        if isinstance(node, ast.Call):
            finding = audit._security_call_finding(flow.security_call_name(node, aliases), relative, node)
            if finding is None or finding["code"] not in {
                "SECURITY_DYNAMIC_EXECUTION", "SECURITY_OS_COMMAND", "SECURITY_SHELL_COMMAND",
                "SECURITY_UNSAFE_DESERIALIZATION", "SECURITY_UNSAFE_YAML",
            }:
                return False
    return True


def _security_helper_prefix_supported(function, initial, aliases):
    environment = dict(initial)
    callback = lambda expression, state: _security_flow_value(expression, state, aliases)
    for statement in function.body:
        if isinstance(statement, ast.AnnAssign) and not _security_helper_annotation_supported(statement.annotation):
            return False
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            known, name, value = _helper_flow_assignment(statement, environment, callback)
            if not known:
                return False
            environment[name] = value
        elif isinstance(statement, (ast.Expr, ast.Return)):
            value = statement.value
            if value is not None and not isinstance(value, ast.Call) and not callback(value, environment)[0]:
                return False
            if isinstance(statement, ast.Return):
                break
    return True


def _helper_flow_result(status, environment, states, reason, values=()):
    return {
        "status": status,
        "environment": environment,
        "return_values": tuple(values),
        "states_used": states,
        "reason": reason,
    }


def _helper_flow_assignment(statement, environment, evaluate_expression):
    if isinstance(statement, ast.Assign):
        if len(statement.targets) != 1 or not isinstance(statement.targets[0], ast.Name):
            return False, "", None
        name = statement.targets[0].id
    elif isinstance(statement, ast.AnnAssign):
        if not isinstance(statement.target, ast.Name) or statement.value is None:
            return False, "", None
        name = statement.target.id
    else:
        return False, "", None
    try:
        known, value = evaluate_expression(statement.value, dict(environment))
    except Exception:
        known, value = False, None
    environment.pop(name, None)
    return (known is True, name, value)


def _helper_flow_step(statement, index, environment, evaluate_expression):
    if isinstance(statement, ast.Return):
        if statement.value is None:
            return "COMPLETE", "return", (None,)
        try:
            known, value = evaluate_expression(statement.value, dict(environment))
        except Exception:
            known, value = False, None
        return ("COMPLETE", "return", (value,)) if known is True else (
            "UNKNOWN", "unsupported return expression", ()
        )
    if isinstance(statement, ast.Pass):
        return "CONTINUE", "pass", ()
    if (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
        and index == 0
    ):
        return "CONTINUE", "docstring", ()
    if isinstance(statement, (ast.Assign, ast.AnnAssign)):
        known, name, value = _helper_flow_assignment(
            statement, environment, evaluate_expression
        )
        if not known:
            return "UNKNOWN", "unsupported assignment", ()
        environment[name] = value
        return "CONTINUE", "assignment", ()
    return "UNKNOWN", "unsupported statement", ()


def evaluate_helper_flow(function, initial, evaluate_expression, *, max_states=512):
    """Evaluate a bounded straight-line helper with caller-defined value semantics.

    This local transfer function applies reaching-definition kills for exact
    names and projects the resulting environment to a return value. It never
    imports or executes the target. Expression callbacks return ``(known,
    value)``; unsupported values and statements decline explicitly.

    The transfer follows the strong-update/reaching-definition concepts in
    CodeAnalyzer's Apache-2.0 ``dataflow/defuse.py`` (commit
    54acde45556869271c16d5fead1134a821012811), and the caller-owned actual to
    formal and return projection boundary in PyFlow's Apache-2.0 ``taint.py``
    (commit e057856a3d409ddc756bca9d3e90409f084bbbdc). This is a bounded local
    evaluator, not a CFG or IFDS solver.
    """
    if (
        not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
        or type(max_states) is not int
        or max_states < 1
        or not isinstance(initial, dict)
        or not callable(evaluate_expression)
    ):
        return _helper_flow_result("UNKNOWN", {}, 0, "invalid evaluator input")
    if len(function.body) > max_states:
        return _helper_flow_result("BUDGET_EXHAUSTED", {}, 0, "state budget exhausted")
    if sum(isinstance(node, ast.Return) for node in function.body) > 1:
        return _helper_flow_result("UNKNOWN", {}, 0, "multiple returns")

    env = dict(initial)
    states = 0
    for index, statement in enumerate(function.body):
        if states >= max_states:
            return _helper_flow_result("BUDGET_EXHAUSTED", env, states, "state budget exhausted")
        states += 1
        status, reason, values = _helper_flow_step(
            statement, index, env, evaluate_expression
        )
        if status == "COMPLETE":
            return _helper_flow_result(status, env, states, reason, values)
        if status == "UNKNOWN":
            return _helper_flow_result(status, env, states, reason)
    return _helper_flow_result("UNKNOWN", env, states, "no supported return")


def captured_value_use_closure(
    function, node, parents, scope_of, return_callers, consumer, *, max_states=512
):
    """Account for every use through captured local aliases and helper returns.

    The caller binds exact functions and terminal consumers; this traversal
    never establishes their semantics from a spelling or executes source.
    Unknowns, empty paths, cycles and exhausted budgets decline closure.
    """
    pending = [(function, node, frozenset())]
    seen, sinks, nodes = set(), {}, []
    while pending:
        current, value, ancestors = pending.pop()
        key = (id(current), id(value))
        if key in ancestors or len(seen) >= max_states:
            return None
        if key in seen:
            continue
        seen.add(key)
        nodes.append(value)
        edge = consumer(current, value)
        if edge is not None:
            sinks[id(edge)] = edge
            continue
        successors = _captured_value_use_successors(
            current, value, parents, scope_of, return_callers
        )
        if not successors:
            return None
        pending.extend((scope, child, ancestors | {key}) for scope, child in successors)
    return {"sinks": tuple(sinks.values()), "nodes": tuple(nodes)} if sinks else None


def _captured_value_use_successors(function, value, parents, scope_of, return_callers):
    parent = parents.get(id(value))
    if isinstance(parent, ast.keyword) and parent.value is value and parent.arg:
        call = parents.get(id(parent))
        if (
            isinstance(call, ast.Call)
            and any(keyword is parent for keyword in call.keywords)
            and not any(keyword.arg is None for keyword in call.keywords)
            and not any(isinstance(argument, ast.Starred) for argument in call.args)
            and scope_of(call) is function
        ):
            return [(function, call)]
        return None
    if isinstance(parent, (ast.List, ast.Tuple)) and value in parent.elts:
        return [(function, parent)]
    if (
        isinstance(parent, ast.Dict)
        and value in parent.values
        and all(isinstance(key, ast.Constant) for key in parent.keys)
    ):
        return [(function, parent)]
    if isinstance(parent, (ast.Assign, ast.AnnAssign)) and parent.value is value:
        return _captured_value_alias_loads(function, parent, scope_of)
    if (
        isinstance(parent, ast.Return)
        and parent.value is value
        and scope_of(parent) is function
    ):
        return return_callers(function)
    return None


def _captured_value_alias_loads(function, assignment, scope_of):
    from .credential_role_constructor_provider import binding_occurrences

    targets = (
        assignment.targets
        if isinstance(assignment, ast.Assign)
        else [assignment.target]
    )
    if len(targets) != 1 or not isinstance(targets[0], ast.Name):
        return None
    name = targets[0].id
    if binding_occurrences(function.body, name) != targets:
        return None
    loads = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, ast.Load)
    ]
    if not loads or any(scope_of(node) is not function for node in loads):
        return None
    if any(node.lineno <= assignment.lineno for node in loads):
        return None
    return [(function, node) for node in loads]


def captured_literal_branch_field_transfer(
    source, path, constructor, bound, caller_path, caller, field, builtin_stable
):
    """Project a selected constructor field under source-bound scalar arguments.

    This is a value-lineage fact, not an admission or an effect-safety proof.
    Callers still close selected receiver mutations and all downstream uses.
    """
    receiver = _captured_projection_receiver(source, path, constructor, bound)
    if receiver is None:
        return None
    known = {}
    for name, actual in bound.items():
        value = captured_call_scalar(source, caller_path, caller, actual, path)
        if value is not None:
            known[name] = value[0]
    statements = captured_selected_field_assignments(
        constructor.body,
        receiver,
        field,
        known,
        lambda expression, state: captured_scalar_guard(
            expression, state, builtin_stable
        ),
        [512],
    )
    if statements is None or len(statements) != 1:
        return None
    statement = statements[0]
    value = statement.value
    while isinstance(value, ast.IfExp):
        truth = captured_scalar_guard(value.test, known, builtin_stable)
        if truth is None:
            return None
        value = value.body if truth else value.orelse
    if not isinstance(value, ast.Name) or value.id not in bound:
        return None
    return {
        "path": path,
        "constructor": constructor,
        "statement": statement,
        "formal": value.id,
        "actual": bound[value.id],
        "field": field,
        "source_sha256": source.inventory[path],
        "profile": "SOURCE_LITERAL_SELECTED_BRANCH",
    }


def _captured_projection_receiver(source, path, constructor, bound):
    from .credential_role_constructor_provider import binding_occurrences, DYNAMIC_HOOKS
    from .credential_role_identity_effects import captured_function_valid

    if not captured_function_valid(constructor, path, source):
        return None
    owner = source.parents[path].get(id(constructor))
    if (
        not isinstance(owner, ast.ClassDef)
        or owner.bases
        or owner.decorator_list
        or owner.keywords
    ):
        return None
    if any(binding_occurrences(owner.body, name) for name in DYNAMIC_HOOKS):
        return None
    formals = [*constructor.args.posonlyargs, *constructor.args.args]
    if not formals or any(
        binding_occurrences(constructor.body, name) for name in bound
    ):
        return None
    receiver = formals[0].arg
    return (
        receiver
        if _captured_projection_receiver_closed(source, path, constructor, receiver)
        else None
    )


def _captured_projection_receiver_closed(source, path, constructor, receiver):
    parents = source.parents[path]
    for node in ast.walk(constructor):
        if isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)):
            return False
        if (
            not isinstance(node, ast.Name)
            or node.id != receiver
            or not isinstance(node.ctx, ast.Load)
        ):
            continue
        parent = parents.get(id(node))
        if (
            not isinstance(parent, ast.Attribute)
            or parent.value is not node
            or parent.attr.startswith("__")
        ):
            return False
        operation = parents.get(id(parent))
        if isinstance(operation, ast.Call) and operation.func is parent:
            return False
    return True


def captured_call_scalar(source, path, caller, expression, default_path=None):
    if (
        not source.validate(path)
        or not isinstance(caller, (ast.FunctionDef, ast.AsyncFunctionDef))
        or id(caller) not in source.parents[path]
    ):
        return None
    if id(expression) not in source.parents[path]:
        if default_path is None or not source.validate(default_path):
            return None
        if id(expression) not in source.parents[default_path]:
            return None
    if isinstance(expression, ast.Name):
        from .credential_role_constructor_provider import binding_occurrences

        if not source.validate(path):
            return None
        rows = [
            row
            for row in caller.body
            if isinstance(row, ast.Assign)
            and len(row.targets) == 1
            and isinstance(row.targets[0], ast.Name)
            and row.targets[0].id == expression.id
        ]
        assignment = (
            rows[0]
            if len(rows) == 1
            and len(binding_occurrences(caller.body, expression.id)) == 1
            else None
        )
        if (
            assignment is None
            or assignment not in caller.body
            or assignment.lineno >= expression.lineno
        ):
            return None
        expression = assignment.value
    if isinstance(expression, ast.Constant) and type(expression.value) in {
        str,
        bytes,
        int,
        float,
        bool,
        type(None),
    }:
        if isinstance(expression.value, (str, bytes)) and len(expression.value) > 4096:
            return None
        return (expression.value,)
    return None


def captured_scalar_guard(expression, known, builtin_stable):
    from . import review_audits as audit

    if isinstance(expression, ast.Call):
        if (
            not isinstance(expression.func, ast.Name)
            or expression.func.id != "isinstance"
            or len(expression.args) != 2
            or expression.keywords
            or not isinstance(expression.args[0], ast.Name)
            or expression.args[0].id not in known
            or not isinstance(expression.args[1], ast.Name)
            or expression.args[1].id not in {"str", "bytes", "int", "bool"}
            or not all(
                builtin_stable(node) for node in (expression.func, expression.args[1])
            )
        ):
            return None
        types = {"str": str, "bytes": bytes, "int": int, "bool": bool}
        return isinstance(known[expression.args[0].id], types[expression.args[1].id])
    if isinstance(expression, ast.BoolOp):
        values = [
            captured_scalar_guard(child, known, builtin_stable)
            for child in expression.values
        ]
        if any(value is None for value in values):
            return None
        return all(values) if isinstance(expression.op, ast.And) else any(values)
    if isinstance(expression, ast.UnaryOp) and isinstance(expression.op, ast.Not):
        truth = captured_scalar_guard(expression.operand, known, builtin_stable)
        return None if truth is None else not truth
    allowed = (
        ast.Name,
        ast.Constant,
        ast.Compare,
        ast.Load,
        ast.Eq,
        ast.NotEq,
        ast.Is,
        ast.IsNot,
    )
    if any(not isinstance(node, allowed) for node in ast.walk(expression)):
        return None
    if isinstance(expression, ast.Compare) and any(
        isinstance(operator, (ast.Is, ast.IsNot)) for operator in expression.ops
    ):
        values = [expression.left, *expression.comparators]
        if not any(
            isinstance(value, ast.Constant) and value.value is None for value in values
        ):
            return None
    return audit._constant_truth_value(expression, known)


def captured_selected_field_assignments(body, receiver, field, known, guard, budget):
    rows = []
    for statement in body:
        budget[0] -= 1
        if budget[0] < 0:
            return None
        writes = [
            node
            for node in ast.walk(statement)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == receiver
            and node.attr == field
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ]
        if isinstance(statement, ast.If):
            truth = guard(statement.test, known)
            if truth is None:
                if writes:
                    return None
                continue
            branch = statement.body if truth else statement.orelse
            selected = captured_selected_field_assignments(
                branch, receiver, field, known, guard, budget
            )
            if selected is None:
                return None
            rows.extend(selected)
        elif writes:
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
                if isinstance(statement, ast.AnnAssign)
                else []
            )
            target = targets[0] if len(targets) == 1 else None
            if not isinstance(statement, (ast.Assign, ast.AnnAssign)) or writes != [
                target
            ]:
                return None
            rows.append(statement)
    return rows


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


def _fixed_program_span(node):
    span = [
        getattr(node, key, None)
        for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
    ]
    if (
        any(type(value) is not int for value in span)
        or span[0] < 1
        or min(span[1], span[3]) < 0
        or tuple(span[:2]) > tuple(span[2:])
    ):
        return None
    return span


def _fixed_eval_name_hazard(item, selected_func, sensitive_names):
    if isinstance(item, ast.Name) and item.id in sensitive_names:
        return item is not selected_func
    if isinstance(item, ast.arg) and item.arg in sensitive_names:
        return True
    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return item.name in sensitive_names
    return isinstance(item, ast.ExceptHandler) and item.name in sensitive_names


def _fixed_eval_import_hazard(item, sensitive_names):
    if isinstance(item, ast.alias):
        bound = item.asname or item.name.split(".", 1)[0]
        return item.name == "builtins" or bound in sensitive_names
    return isinstance(item, ast.ImportFrom) and (
        item.module == "builtins" or any(alias.name == "*" for alias in item.names)
    )


def _fixed_eval_attribute_hazard(item):
    sensitive = {
        "__dict__",
        "__globals__",
        "__builtins__",
        "__getattribute__",
        "__setattr__",
        "import_module",
    }
    return isinstance(item, ast.Attribute) and (
        item.attr in sensitive
        or (
            item.attr in {"exec", "eval"} and isinstance(item.ctx, (ast.Store, ast.Del))
        )
    )


def _fixed_eval_builtin_source_clear(tree, selected_call):
    names = {
        "__builtins__",
        "globals",
        "locals",
        "vars",
        "getattr",
        "setattr",
        "delattr",
        "__import__",
        "exec",
        "eval",
    }
    selected_func = selected_call.func
    return not any(
        _fixed_eval_name_hazard(item, selected_func, names)
        or _fixed_eval_import_hazard(item, names)
        or _fixed_eval_attribute_hazard(item)
        for item in ast.walk(tree)
    )


def _fixed_eval_builtin_aliases(tree):
    builtins_aliases, importlib_aliases, sys_aliases = set(), set(), set()
    importer_aliases = {"__import__"}
    for item in ast.walk(tree):
        if isinstance(item, ast.Import):
            destinations = {
                "builtins": builtins_aliases,
                "importlib": importlib_aliases,
                "sys": sys_aliases,
            }
            for alias in item.names:
                if alias.name in destinations:
                    destinations[alias.name].add(alias.asname or alias.name)
        if isinstance(item, ast.ImportFrom) and item.module == "builtins":
            importer_aliases.update(
                alias.asname or alias.name
                for alias in item.names
                if alias.name == "__import__"
            )
        if isinstance(item, ast.ImportFrom) and item.module in {
            "importlib",
            "importlib.util",
        }:
            importer_aliases.update(
                alias.asname or alias.name
                for alias in item.names
                if alias.name == "import_module"
            )
    return builtins_aliases, importlib_aliases, sys_aliases, importer_aliases


def _fixed_eval_provider_root(node, builtins_aliases, importer_aliases, sys_aliases):
    if isinstance(node, ast.Name) and node.id in builtins_aliases:
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return (
            node.func.id in importer_aliases
            and bool(node.args)
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "builtins"
        )
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute):
        key = node.slice.value if isinstance(node.slice, ast.Constant) else None
        return (
            node.value.attr == "modules"
            and key == "builtins"
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id in sys_aliases
        )
    return False


def _fixed_eval_provider_capability(
    node, builtins_aliases, importer_aliases, sys_aliases
):
    if _fixed_eval_provider_root(node, builtins_aliases, importer_aliases, sys_aliases):
        return True
    if isinstance(node, ast.Attribute) and node.attr == "modules":
        return isinstance(node.value, ast.Name) and node.value.id in sys_aliases
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return _fixed_eval_provider_root(
            node.value, builtins_aliases, importer_aliases, sys_aliases
        )
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "vars"
        and bool(node.args)
        and _fixed_eval_provider_root(
            node.args[0], builtins_aliases, importer_aliases, sys_aliases
        )
    )


def _fixed_eval_provider_alias_escape(
    tree, builtins_aliases, importer_aliases, sys_aliases
):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and any(
            _fixed_eval_provider_capability(
                child, builtins_aliases, importer_aliases, sys_aliases
            )
            for arg in [*node.args, *(keyword.value for keyword in node.keywords)]
            for child in ast.walk(arg)
        ):
            return True
        if isinstance(node, ast.ImportFrom):
            if node.module in {
                "builtins",
                "sys",
                "importlib",
                "importlib.util",
            } and any(
                alias.name
                in {"__dict__", "__getattribute__", "__setattr__", "__getattr__"}
                for alias in node.names
            ):
                return True
            if node.module == "sys" and any(
                alias.name == "modules" for alias in node.names
            ):
                return True
        value = None
        targets = []
        if isinstance(node, ast.Assign):
            value, targets = node.value, node.targets
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            value, targets = node.value, [node.target]
        if value is None:
            continue
        binds_name = any(
            isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
            for target in targets
            for child in ast.walk(target)
        )
        if binds_name and any(
            _fixed_eval_provider_capability(
                child, builtins_aliases, importer_aliases, sys_aliases
            )
            for child in ast.walk(value)
        ):
            return True
    return False


def _fixed_eval_builtin_write(node, builtins_aliases, importer_aliases, sys_aliases):
    if isinstance(node, ast.Name) and node.id == "__builtins__":
        return True
    if (
        isinstance(node, ast.Name)
        and node.id in {"eval", "exec"}
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ):
        return True
    if isinstance(node, ast.Attribute) and node.attr in {"eval", "exec"}:
        return isinstance(node.ctx, (ast.Store, ast.Del)) and _fixed_eval_provider_root(
            node.value, builtins_aliases, importer_aliases, sys_aliases
        )
    if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return _fixed_eval_builtin_subscript(
            node, builtins_aliases, importer_aliases, sys_aliases
        )
    return False


def _fixed_eval_builtin_subscript(
    node, builtins_aliases, importer_aliases, sys_aliases
):
    if not isinstance(node.value, ast.Attribute) or node.value.attr != "__dict__":
        return False
    if not _fixed_eval_provider_root(
        node.value.value, builtins_aliases, importer_aliases, sys_aliases
    ):
        return False
    key = node.slice.value if isinstance(node.slice, ast.Constant) else None
    return key in {None, "eval", "exec"}


def _fixed_eval_builtin_reflection(
    node, builtins_aliases, importlib_aliases, importer_aliases, sys_aliases
):
    if isinstance(node, ast.Attribute) and node.attr in {"__globals__", "__builtins__"}:
        return True
    if isinstance(node, ast.Attribute) and node.attr in {
        "__dict__",
        "__getattribute__",
        "__setattr__",
        "eval",
        "exec",
    }:
        if _fixed_eval_provider_root(
            node.value, builtins_aliases, importer_aliases, sys_aliases
        ):
            return node.attr in {
                "__dict__",
                "__getattribute__",
                "__setattr__",
            } or isinstance(node.ctx, (ast.Store, ast.Del))
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    reflective = isinstance(func, ast.Name) and func.id in {
        "setattr",
        "delattr",
        "getattr",
    }
    if isinstance(func, ast.Attribute):
        reflective |= func.attr in {"setattr", "delattr", "getattr"}
    return (
        reflective
        and bool(node.args)
        and _fixed_eval_provider_root(
            node.args[0], builtins_aliases, importer_aliases, sys_aliases
        )
    )


def _fixed_eval_dynamic_import_risk(node, importlib_aliases, importer_aliases):
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    direct = isinstance(func, ast.Name) and func.id in importer_aliases
    imported = (
        isinstance(func, ast.Attribute)
        and func.attr == "import_module"
        and isinstance(func.value, ast.Name)
        and func.value.id in importlib_aliases
    )
    if not (direct or imported):
        return False
    if not node.args:
        return True
    name = node.args[0]
    return (
        not isinstance(name, ast.Constant)
        or type(name.value) is not str
        or name.value.split(".", 1)[0] in {"builtins", "sys", "importlib"}
    )


def _fixed_eval_module_alias_escape(tree, aliases):
    parents = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Name)
            and node.id in aliases
            and isinstance(node.ctx, ast.Load)
        ):
            continue
        parent = parents.get(id(node))
        if (
            isinstance(parent, ast.Attribute)
            and parent.value is node
            and parent.attr
            not in {"__dict__", "__getattribute__", "__setattr__", "__getattr__"}
        ):
            continue
        return True
    return False


def _fixed_eval_module_scope(tree, target):
    parents = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    current = target
    while id(current) in parents:
        parent = parents[id(current)]
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if current in parent.body:
                return False
        elif isinstance(parent, ast.Lambda) and current is parent.body:
            return False
        current = parent
    return True


def _fixed_eval_interpreter_aliases(tree):
    aliases = {"eval", "exec"}
    aliases.update(
        alias.asname or alias.name
        for item in ast.walk(tree)
        if isinstance(item, ast.ImportFrom) and item.module == "builtins"
        for alias in item.names
        if alias.name in {"eval", "exec"}
    )
    return aliases


def _fixed_eval_interpreter_call(node, aliases):
    if not isinstance(node, ast.Call):
        return None
    function = node.func
    name = function.id if isinstance(function, ast.Name) else None
    if name is None and isinstance(function, ast.Attribute):
        name = function.attr
    return name if name in aliases else None


def _fixed_eval_callable_reaches_risk(node, aliases, risky, unresolved_classes):
    for item in ast.walk(node):
        if _fixed_eval_interpreter_call(item, aliases) is not None:
            return True
        if (
            isinstance(item, ast.Call)
            and isinstance(item.func, ast.Name)
            and item.func.id in risky | unresolved_classes
        ):
            return True
    return False


def _fixed_eval_class_init_hooks(node):
    hooks = [
        item
        for item in node.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.name in {"__new__", "__init__"}
    ]
    unresolved = bool(node.bases or node.keywords or node.decorator_list)
    return hooks, unresolved


def _fixed_eval_local_class_aliases(tree, class_names):
    aliases = set()
    for _ in range(len(tree.body) + 1):
        added = False
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target, value = node.targets[0], node.value
            elif isinstance(node, ast.AnnAssign):
                target, value = node.target, node.value
            else:
                continue
            if (
                isinstance(target, ast.Name)
                and isinstance(value, ast.Name)
                and value.id in class_names | aliases
                and target.id not in class_names | aliases
            ):
                aliases.add(target.id)
                added = True
        if not added:
            break
    return aliases


def _fixed_eval_local_function_risks(functions, aliases, risky, constructors):
    added = False
    for name, function in functions.items():
        if name not in risky and _fixed_eval_callable_reaches_risk(
            function, aliases, risky, constructors
        ):
            risky.add(name)
            added = True
    return added


def _fixed_eval_local_class_risks(classes, aliases, risky, constructors):
    added = False
    for name, (hooks, _) in classes.items():
        if name in risky:
            continue
        if any(
            _fixed_eval_callable_reaches_risk(hook, aliases, risky, constructors)
            for hook in hooks
        ):
            risky.add(name)
            added = True
    return added


def _fixed_eval_module_init_constructor_call(tree, constructor_names):
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in constructor_names
        and _fixed_eval_module_scope(tree, node)
        for node in ast.walk(tree)
    )


def _fixed_eval_module_init_risky_reference(tree, risky):
    return any(
        isinstance(node, ast.Name)
        and node.id in risky
        and isinstance(node.ctx, ast.Load)
        and _fixed_eval_module_scope(tree, node)
        for node in ast.walk(tree)
    )


def _fixed_eval_interpreter_payload(node, name):
    if not node.args or not isinstance(node.args[0], ast.Constant):
        return None
    code = node.args[0].value
    if type(code) is not str:
        return None
    try:
        if len(code.encode("utf-8")) > 16 * 1024:
            return None
    except UnicodeEncodeError:
        return None
    try:
        return ast.parse(code, mode="eval" if name == "eval" else "exec")
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return None


def _fixed_eval_nested_interpreter_risk(tree, depth):
    aliases = _fixed_eval_interpreter_aliases(tree)
    for node in ast.walk(tree):
        name = _fixed_eval_interpreter_call(node, aliases)
        if name is None:
            continue
        nested = _fixed_eval_interpreter_payload(node, name)
        if nested is None:
            if _fixed_eval_module_scope(tree, node):
                return True
            continue
        if isinstance(nested, ast.Expression):
            expression = ast.copy_location(ast.Expr(value=nested.body), nested.body)
            nested = ast.Module(body=[expression], type_ignores=[])
        if _fixed_eval_builtin_provider_risk(nested, depth + 1):
            return True
    return False


def _fixed_eval_local_init_call_risk(tree):
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    classes = {
        node.name: _fixed_eval_class_init_hooks(node)
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }
    if not functions and not classes:
        return False
    aliases = _fixed_eval_interpreter_aliases(tree)
    unresolved_classes = {
        name for name, (_, unresolved) in classes.items() if unresolved
    }
    class_aliases = _fixed_eval_local_class_aliases(tree, unresolved_classes)
    constructor_names = unresolved_classes | class_aliases
    risky = set()
    for _ in range(len(functions) + len(classes) + 1):
        added = _fixed_eval_local_function_risks(
            functions, aliases, risky, constructor_names
        )
        added |= _fixed_eval_local_class_risks(
            classes, aliases, risky, constructor_names
        )
        if not added:
            break
    return _fixed_eval_module_init_constructor_call(
        tree, constructor_names
    ) or _fixed_eval_module_init_risky_reference(tree, risky)


def _fixed_eval_builtin_provider_risk(tree, depth=0):
    """Reject source-visible provider writes and opaque module-init eval/exec effects.

    Dynamic sinks inside function bodies remain separate alerts; this source
    profile does not establish runtime isolation or order across invocations.
    """
    if depth > 4:
        return True
    builtins_aliases, importlib_aliases, sys_aliases, importer_aliases = (
        _fixed_eval_builtin_aliases(tree)
    )
    if (
        _fixed_eval_module_alias_escape(tree, builtins_aliases)
        or _fixed_eval_module_alias_escape(tree, importlib_aliases)
        or _fixed_eval_module_alias_escape(tree, sys_aliases)
        or _fixed_eval_provider_alias_escape(
            tree, builtins_aliases, importer_aliases, sys_aliases
        )
    ):
        return True
    for node in ast.walk(tree):
        if _fixed_eval_builtin_write(
            node, builtins_aliases, importer_aliases, sys_aliases
        ):
            return True
        if _fixed_eval_builtin_reflection(
            node, builtins_aliases, importlib_aliases, importer_aliases, sys_aliases
        ):
            return True
        if _fixed_eval_dynamic_import_risk(node, importlib_aliases, importer_aliases):
            return True
    if _fixed_eval_local_init_call_risk(tree):
        return True
    return _fixed_eval_nested_interpreter_risk(tree, depth)


def fixed_eval_workspace_provider_clear(source_bytes, source_rows):
    """Recheck a complete hash-bound workspace for source-visible eval-provider mutation."""
    if not isinstance(source_bytes, dict) or not isinstance(source_rows, list):
        return False
    python_rows = [
        row
        for row in source_rows
        if isinstance(row, dict)
        and isinstance(row.get("path"), str)
        and row["path"].endswith(".py")
    ]
    if not python_rows:
        return False
    expected = {row["path"]: row.get("sha256") for row in python_rows}
    if len(expected) != len(python_rows):
        return False
    for relative, digest in expected.items():
        raw = source_bytes.get(relative)
        if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != digest:
            return False
        try:
            tree = ast.parse(raw, filename=relative)
        except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
            return False
        if _fixed_eval_builtin_provider_risk(tree):
            return False
    return True


def captured_sink_evidence(node, *, source_path, source_sha256, source_index=None,
                          source_bytes=None, tree=None, max_sources=64,
                          max_states=512, max_output_bytes=64000):
    """Capture a bounded source-linked sink ledger; never certify safety."""
    import json

    schema = "factory.captured-sink-evidence.v1"
    ctx = _captured_sink_source(source_path, source_sha256, source_index,
                                source_bytes, tree, max_sources, max_states,
                                max_output_bytes, schema)
    if "error" in ctx:
        return ctx["error"]
    located = _captured_sink_location(node, ctx)
    if "error" in located:
        return located["error"]
    node, parents, tree = located["node"], located["parents"], ctx["tree"]
    base, digest, text, limits = (ctx[k] for k in ("base", "digest", "text", "limits"))
    truncation = []
    fact = lambda item, state="OBSERVED": _captured_sink_fact(item, base["source"]["path"], digest, state)
    excerpt = lambda item: _captured_sink_excerpt(item, text, truncation)
    scope = _captured_sink_scope(node, parents, fact, limits[1], base)
    if "error" in scope:
        return scope["error"]
    nodes, body, statement = scope["nodes"], scope["body"], scope["statement"]
    arguments, names, callee_names = _captured_sink_arguments(node, fact, excerpt)
    imports = _captured_sink_imports(tree, scope["scope"], nodes, parents,
                                     fact, limits[1], base)
    if "error" in imports:
        return imports["error"]
    values = _captured_sink_values(node, names, scope["scope"], body, statement,
                                   nodes, parents, tree, fact, excerpt)
    callers = {"status": "UNKNOWN", "reason": "caller_expansion_not_performed"}
    states_used = len(nodes) + imports["states_used"]
    result = {
        **base, "status": "INCOMPLETE" if truncation else "COMPLETE",
        "source": {**base["source"], "line_count": len(text.splitlines())},
        "sink": {"status": "OBSERVED", "call": excerpt(node.func),
                 "span": _fixed_program_span(node), "arguments": arguments,
                 **fact(node)},
        "scope": scope["row"], "imports": imports["rows"], "values": values,
        "guards": _captured_sink_guards(node, scope["scope"], parents, fact, excerpt),
        "callee_binding": _captured_sink_callee_binding(
            callee_names, scope["scope"], body, tree, imports["module_imports"], fact
        ),
        "callers": callers,
        "provider": {"status": "UNKNOWN", "reason": "provider_identity_not_established"},
        "effects": {"status": "UNKNOWN", "reason": "runtime_effects_not_observed"},
        "authority": {"status": "UNKNOWN", "reason": "trust_boundary_not_declared"},
        "budget": {"sources_used": 1, "sources_limit": limits[0],
                   "states_used": states_used, "states_limit": limits[1],
                   "source_ast_nodes_examined": located["source_ast_nodes_examined"],
                   "source_ast_limit": 200_000,
                   "snapshot_index_reused": ctx["indexed"],
                   "serialized_bytes_limit": limits[2]},
        "truncation": truncation,
    }
    size = len(json.dumps(result, sort_keys=True, separators=(",", ":")).encode())
    return result if size <= limits[2] else _captured_sink_failure(
        schema, "SINK_BUDGET_EXHAUSTED", "max_output_bytes", base
    )


def _captured_sink_failure(schema, code, reason, base=None):
    return {**(base or {"schema": schema, "status": "INCOMPLETE"}),
            "code": code, "truncation": [reason]}


def _captured_sink_source(path_arg, expected, index, raw, tree, max_sources,
                          max_states, max_output, schema):
    import io
    import tokenize

    limits = (max_sources, max_states, max_output)
    if any(type(value) is not int or value < 1 for value in limits) or max_output < 256:
        return {"error": _captured_sink_failure(schema, "SINK_BUDGET_INVALID", "invalid_limit")}
    limits = tuple(min(value, ceiling) for value, ceiling in zip(limits, (64, 512, 64000)))
    path = path_arg.as_posix() if hasattr(path_arg, "as_posix") else path_arg
    tree_supplied = tree is not None
    indexed = index is not None
    if indexed:
        capture = _captured_sink_index(index, path_arg, raw, path, schema)
        if "error" in capture:
            return capture
        raw, tree, parents = capture["raw"], capture["tree"], capture["parents"]
    else:
        parents = None
    if not isinstance(path, str) or not path:
        return {"error": _captured_sink_failure(schema, "SINK_SOURCE_STALE", "invalid_source_path")}
    if not isinstance(raw, bytes) or len(raw) > 1_000_000:
        return {"error": _captured_sink_failure(schema, "SINK_BUDGET_EXHAUSTED", "max_source_bytes")}
    digest = hashlib.sha256(raw).hexdigest()
    if not isinstance(expected, str) or expected != digest:
        return {"error": _captured_sink_failure(schema, "SINK_SOURCE_STALE", "source_hash_mismatch")}
    if not indexed:
        capture = _captured_sink_raw_tree(path, raw, tree, schema)
        if "error" in capture:
            return capture
        tree, parents = capture["tree"], capture["parents"]
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        text = raw.decode(encoding)
    except (SyntaxError, UnicodeError, LookupError):
        return {"error": _captured_sink_failure(schema, "SINK_SOURCE_STALE", "source_encoding_invalid")}
    base = {"schema": schema, "status": "INCOMPLETE", "source": {
        "path": path[:1024], "sha256": digest, "bytes": len(raw)}, "source_count": 1}
    return {"tree": tree, "parents": parents, "text": text, "base": base,
            "digest": digest, "limits": limits, "indexed": indexed,
            "tree_supplied": tree_supplied}


def _captured_sink_index(index, path_arg, raw, path, schema):
    inventory = getattr(index, "source_bytes", {})
    if not isinstance(path, str) or path_arg not in getattr(index, "snapshots", {}):
        return {"error": _captured_sink_failure(schema, "SINK_SOURCE_STALE", "source_not_indexed")}
    if sum(len(value) for value in inventory.values() if isinstance(value, bytes)) > 32_000_000:
        return {"error": _captured_sink_failure(schema, "SINK_BUDGET_EXHAUSTED", "max_inventory_bytes")}
    captured = inventory.get(path_arg)
    if raw is not None and raw != captured:
        return {"error": _captured_sink_failure(schema, "SINK_SOURCE_STALE", "source_bytes_changed")}
    if not isinstance(captured, bytes) or len(captured) > 1_000_000:
        return {"error": _captured_sink_failure(schema, "SINK_BUDGET_EXHAUSTED", "max_source_bytes")}
    validation_inputs = getattr(index, "_validation_inputs", None)
    if not isinstance(validation_inputs, dict):
        return {"error": _captured_sink_failure(schema, "SINK_SOURCE_STALE", "source_validation_cache_unavailable")}
    validation_inputs.pop(path_arg, None)
    if not index.validate(path_arg):
        return {"error": _captured_sink_failure(schema, "SINK_SOURCE_STALE", "source_snapshot_invalid")}
    return {"raw": captured, "tree": index.snapshots[path_arg],
            "parents": index.parents[path_arg]}


def _captured_sink_raw_tree(path, raw, tree, schema):
    try:
        parsed = ast.parse(raw, filename=path)
        if tree is not None and ast.dump(parsed, include_attributes=True) != ast.dump(tree, include_attributes=True):
            return {"error": _captured_sink_failure(schema, "SINK_SOURCE_STALE", "ast_source_mismatch")}
        tree = tree or parsed
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return {"error": _captured_sink_failure(schema, "SINK_SOURCE_STALE", "source_parse_failed")}
    return {"tree": tree, "parents": {}}


def _captured_sink_location(node, ctx):
    base, tree, parents = ctx["base"], ctx["tree"], ctx["parents"]
    schema = base["schema"]
    span = _fixed_program_span(node) if isinstance(node, ast.AST) else None
    if span is None:
        return {"error": _captured_sink_failure(schema, "SINK_LOCATION_UNRESOLVED", "invalid_sink_span", base)}
    if ctx["indexed"] and isinstance(node, ast.Call) and id(node) in parents:
        return {"node": node, "parents": parents, "source_ast_nodes_examined": 0}
    if ctx["indexed"]:
        return {"error": _captured_sink_failure(schema, "SINK_LOCATION_UNRESOLVED", "sink_not_in_captured_tree", base)}
    matches = []
    for count, item in enumerate(ast.walk(tree), 1):
        if count > 200_000:
            return {"error": _captured_sink_failure(schema, "SINK_BUDGET_EXHAUSTED", "max_source_ast_nodes", base)}
        parents.update({id(child): item for child in ast.iter_child_nodes(item)})
        if isinstance(item, ast.Call) and _fixed_program_span(item) == span and ast.dump(item, include_attributes=True) == ast.dump(node, include_attributes=True):
            matches.append(item)
    if ctx["tree_supplied"] and id(node) not in parents:
        return {"error": _captured_sink_failure(schema, "SINK_LOCATION_UNRESOLVED", "sink_not_in_supplied_tree", base)}
    if len(matches) == 1:
        return {"node": matches[0], "parents": parents,
                "source_ast_nodes_examined": count}
    return {"error": _captured_sink_failure(schema, "SINK_LOCATION_UNRESOLVED", "sink_span_not_unique", base)}


def _captured_sink_fact(item, path, digest, status="OBSERVED"):
    span = _fixed_program_span(item)
    return ({"status": status, "source": {"path": path, "sha256": digest, "span": span}}
            if span is not None else {"status": "UNKNOWN", "reason": "span_unavailable"})


def _captured_sink_excerpt(item, text, truncation):
    excerpt = ast.get_source_segment(text, item)
    if not isinstance(excerpt, str):
        return ""
    if len(excerpt) > 512:
        if "excerpt_truncated" not in truncation:
            truncation.append("excerpt_truncated")
        return excerpt[:512] + "[truncated]"
    return excerpt


def _captured_sink_scope(node, parents, fact, budget, base):
    scope = node
    while id(scope) in parents:
        scope = parents[id(scope)]
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            break
    else:
        scope = None
    row, body, statement = {"status": "UNKNOWN", "reason": "no_enclosing_callable"}, None, None
    if scope is not None:
        statement = node
        while id(statement) in parents and parents[id(statement)] is not scope:
            statement = parents[id(statement)]
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and statement in scope.body:
            body = scope.body
            row = {"status": "OBSERVED", "name": scope.name, "kind": type(scope).__name__, **fact(scope)}
        else:
            row = {"status": "UNKNOWN", "reason": "sink_outside_callable_body", **fact(scope)}
    nodes, stack = [], [scope] if body is not None else []
    while stack:
        item = stack.pop()
        nodes.append(item)
        if len(nodes) > budget:
            return {"error": _captured_sink_failure(base["schema"], "SINK_BUDGET_EXHAUSTED", "max_states", base)}
        if item is not scope and isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(ast.iter_child_nodes(item))
    return {"scope": scope, "body": body, "statement": statement,
            "nodes": nodes, "row": row}


def _captured_sink_arguments(node, fact, excerpt):
    arguments, names = [], set()
    for index, value in enumerate(node.args):
        arguments.append({"position": index, "kind": "starred" if isinstance(value, ast.Starred) else "positional",
                          "expression": excerpt(value), "span": _fixed_program_span(value), **fact(value)})
        names.update(item.id for item in ast.walk(value) if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load))
    for keyword in node.keywords:
        value = keyword.value
        arguments.append({"keyword": keyword.arg, "kind": "expanded_keyword" if keyword.arg is None else "keyword",
                          "expression": excerpt(value), "span": _fixed_program_span(value), **fact(value)})
        names.update(item.id for item in ast.walk(value) if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load))
    callees = [item for item in ast.walk(node.func) if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)]
    names.update(item.id for item in callees)
    return arguments, names, callees


def _captured_sink_imports(tree, scope, nodes, parents, fact, budget, base):
    from .credential_role_constructor_provider import binding_occurrences

    modules = [item for item in tree.body if isinstance(item, (ast.Import, ast.ImportFrom))]
    if len(nodes) + len(modules) > budget:
        return {"error": _captured_sink_failure(base["schema"], "SINK_BUDGET_EXHAUSTED", "max_states", base)}
    rows, params = [], _captured_sink_parameter_names(scope)
    for item in modules + [row for row in nodes if isinstance(row, (ast.Import, ast.ImportFrom))]:
        owner = _captured_sink_enclosing_callable(item, parents)
        if owner not in (None, scope):
            continue
        container = owner.body if owner is not None else tree.body
        for alias in item.names:
            name = alias.asname or (alias.name.split(".")[0] if isinstance(item, ast.Import) else alias.name)
            wildcard = isinstance(item, ast.ImportFrom) and alias.name == "*"
            stable = not wildcard and binding_occurrences(container, name) == [item] and name not in params
            status = "OBSERVED" if stable else "UNKNOWN"
            rows.append({"name": name, "module": item.module if isinstance(item, ast.ImportFrom) else alias.name,
                         "kind": type(item).__name__, "status": status,
                         "reason": None if stable else "binding_replaced_or_ambiguous",
                         "span": _fixed_program_span(item), **fact(item, status)})
    return {"rows": rows, "module_imports": modules,
            "states_used": sum(len(item.names) for item in modules),
            "binding_occurrences": binding_occurrences}


def _captured_sink_values(node, names, scope, body, statement, nodes, parents, tree, fact, excerpt):
    from .credential_role_constructor_provider import binding_occurrences

    if body is None:
        return [{"name": name, "status": "UNKNOWN", "reason": "no_supported_callable_scope",
                 "origin": "UNRESOLVED", "definitions": [], "replacements": []}
                for name in sorted(names)]
    params = _captured_sink_parameter_names(scope)
    reflective = any(isinstance(row, ast.Call) and isinstance(row.func, ast.Name)
                     and row.func.id in {"exec", "eval", "globals", "locals", "vars", "setattr", "delattr"}
                     for row in nodes)
    pending, visited, result = sorted(names), set(), []
    while pending:
        name = pending.pop(0)
        if name in visited:
            continue
        visited.add(name)
        evidence = _captured_sink_value(name, scope, body, statement, parents,
                                        tree, params, fact, excerpt, binding_occurrences)
        value, assignment = evidence["value"], evidence["assignment"]
        if assignment is not None:
            pending.extend(row.id for row in ast.walk(assignment.value)
                            if isinstance(row, ast.Name) and isinstance(row.ctx, ast.Load)
                            and row.id not in visited and row.id not in pending)
        if reflective:
            value.update(status="UNKNOWN", reason="reflective_binding_possible", origin="UNRESOLVED")
            value["replacements"].append({"kind": "REFLECTIVE_WRITE_POSSIBLE", **fact(node, "UNKNOWN")})
        result.append(value)
    return result


def _captured_sink_value(name, scope, body, statement, parents, tree, params, fact,
                         excerpt, binding_occurrences):
    bindings = binding_occurrences(body, name)
    rows = []
    for binding in bindings:
        statement_node = parents.get(id(binding)) if isinstance(binding, ast.Name) else binding
        if statement_node is None:
            statement_node = binding
        rows.append({"kind": type(binding).__name__,
                     "binding_span": _fixed_program_span(binding),
                     "expression": excerpt(statement_node),
                     **fact(statement_node, "UNKNOWN")})
    assignment = None
    if len(bindings) == 1 and isinstance(bindings[0], ast.Name) and isinstance(bindings[0].ctx, ast.Store):
        candidate = parents.get(id(bindings[0]))
        targets = candidate.targets if isinstance(candidate, ast.Assign) else [candidate.target] if isinstance(candidate, ast.AnnAssign) else []
        if candidate in body and body.index(candidate) < body.index(statement) and getattr(candidate, "value", None) is not None and len(targets) == 1 and targets[0] is bindings[0]:
            assignment = candidate
    if assignment is not None:
        value = {"name": name, "status": "INFERRED", "reason": None, "origin": "LOCAL_DEFINITION",
                 "definitions": [{"expression": excerpt(assignment.value), "span": _fixed_program_span(assignment), **fact(assignment)}], "replacements": []}
        value["definitions"][0]["target_source"] = fact(
            assignment.targets[0] if isinstance(assignment, ast.Assign) else assignment.target
        )
    elif not bindings and name in params:
        args = (*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs,
                *([scope.args.vararg] if scope.args.vararg else []), *([scope.args.kwarg] if scope.args.kwarg else []))
        arg = next(row for row in args if row.arg == name)
        value = {"name": name, "status": "INFERRED", "reason": None, "origin": "CALLABLE_PARAMETER",
                 "definitions": [{"kind": "PARAMETER", "span": _fixed_program_span(arg), **fact(arg)}], "replacements": []}
    elif not bindings and any(row in tree.body for row in binding_occurrences(tree.body, name)):
        module_bindings = binding_occurrences(tree.body, name)
        if len(module_bindings) == 1 and isinstance(module_bindings[0], (ast.Import, ast.ImportFrom)):
            value = {"name": name, "status": "INFERRED", "reason": None, "origin": "LEXICAL_IMPORT",
                     "definitions": [{"kind": type(module_bindings[0]).__name__, "span": _fixed_program_span(module_bindings[0]), **fact(module_bindings[0])}], "replacements": []}
        else:
            value = {"name": name, "status": "UNKNOWN", "reason": "module_binding_ambiguous", "origin": "UNRESOLVED", "definitions": [], "replacements": rows}
    else:
        value = {"name": name, "status": "UNKNOWN", "reason": "binding_replaced_or_not_straight_line" if bindings else "no_source_definition_or_parameter",
                 "origin": "UNRESOLVED", "definitions": [], "replacements": rows}
    return {"value": value, "assignment": assignment}


def _captured_sink_guards(node, scope, parents, fact, excerpt):
    guards, current = [], node
    control = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.TryStar,
               ast.With, ast.AsyncWith, ast.Match, ast.Assert)
    while id(current) in parents and parents[id(current)] is not scope:
        current = parents[id(current)]
        if isinstance(current, control):
            test = getattr(current, "test", None) or getattr(current, "subject", None)
            guards.append({"kind": type(current).__name__,
                           "expression": excerpt(test) if test is not None else "",
                           "semantics": "UNKNOWN", "span": _fixed_program_span(current),
                           **fact(current)})
    return guards


def _captured_sink_callee_binding(names, scope, body, tree, module_imports, fact):
    from .credential_role_constructor_provider import binding_occurrences

    name = names[0].id if names else None
    row = {"status": "UNKNOWN", "reason": "unresolved_callee_binding", "name": name}
    if name is None or body is None:
        return row
    if any(isinstance(item, ast.ImportFrom) and any(alias.name == "*" for alias in item.names) for item in module_imports):
        row["reason"] = "wildcard_import_may_bind_name"
    elif not binding_occurrences(body, name) and name not in _captured_sink_parameter_names(scope):
        bindings = binding_occurrences(tree.body, name)
        if len(bindings) == 1 and bindings[0] in tree.body and isinstance(bindings[0], (ast.Import, ast.ImportFrom)):
            row = {"status": "INFERRED", "reason": None, "name": name, "declaration": fact(bindings[0])}
    return row

def _captured_sink_enclosing_callable(node, parents):
    current = node
    while id(current) in parents:
        current = parents[id(current)]
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return current
    return None


def _captured_sink_parameter_names(scope):
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        return set()
    args = scope.args
    parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    parameters.extend(item for item in (args.vararg, args.kwarg) if item is not None)
    return {item.arg for item in parameters}


def _fixed_eval_sink_context(node, call_name, source_bytes, source_path):
    if (
        not isinstance(source_bytes, bytes)
        or not isinstance(source_path, str)
        or not source_path
    ):
        return None
    if call_name != "eval" or not isinstance(node, ast.Call):
        return None
    span = _fixed_program_span(node)
    if span is None:
        return None
    try:
        tree = ast.parse(source_bytes, filename=source_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return None
    expected = ast.dump(node, include_attributes=False)
    calls = [
        item
        for item in ast.walk(tree)
        if isinstance(item, ast.Call)
        and _fixed_program_span(item) == span
        and ast.dump(item, include_attributes=False) == expected
    ]
    if len(calls) != 1:
        return None
    sink = calls[0]
    if not (isinstance(sink.func, ast.Name) and sink.func.id == "eval"):
        return None
    if len(sink.args) != 1 or sink.keywords or not isinstance(sink.args[0], ast.Name):
        return None
    scopes = [
        item
        for item in ast.walk(tree)
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.lineno <= sink.lineno <= item.end_lineno
        and item.col_offset <= sink.col_offset
        and (item.end_lineno, item.end_col_offset)
        >= (sink.end_lineno, sink.end_col_offset)
    ]
    if not scopes or not _fixed_eval_builtin_source_clear(tree, sink):
        return None
    scope = min(
        scopes,
        key=lambda item: (
            item.end_lineno - item.lineno,
            item.end_col_offset - item.col_offset,
        ),
    )
    return tree, sink, scope, span


def _fixed_eval_control_flow(scope):
    blocked = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        ast.With,
        ast.AsyncWith,
        ast.Lambda,
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
        ast.NamedExpr,
        ast.Global,
        ast.Nonlocal,
        ast.AugAssign,
        ast.Delete,
        ast.Match,
        ast.TryStar,
    )
    nested = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    return any(
        isinstance(item, blocked) or (isinstance(item, nested) and item is not scope)
        for item in ast.walk(scope)
    )


def _fixed_eval_sink_statement(scope, sink):
    if _fixed_eval_control_flow(scope):
        return None
    rows = [
        (index, statement)
        for index, statement in enumerate(scope.body)
        if any(item is sink for item in ast.walk(statement))
    ]
    if len(rows) != 1:
        return None
    index, statement = rows[0]
    valid_assignment = (
        isinstance(statement, ast.Assign)
        and statement.value is sink
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
    )
    valid_value_statement = (
        isinstance(statement, (ast.Expr, ast.Return)) and statement.value is sink
    )
    return index if valid_assignment or valid_value_statement else None


def _fixed_eval_parameters(scope):
    args = (*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs)
    names = {argument.arg for argument in args}
    if scope.args.vararg is not None:
        names.add(scope.args.vararg.arg)
    if scope.args.kwarg is not None:
        names.add(scope.args.kwarg.arg)
    return names


def _fixed_eval_external_state(name):
    return {
        "kind": "EXTERNAL_INPUT",
        "value": None,
        "trace": [],
        "names": {name},
        "origin_span": None,
        "decode_encoding": None,
    }


def _fixed_eval_row(
    target, statement, sequence, operation, kind, source_name=None, encoding=None
):
    value = statement.value
    row = {
        "sequence": sequence,
        "name": target.id,
        "operation": operation,
        "value_kind": kind,
        "assignment_span": _fixed_program_span(statement),
        "target_span": _fixed_program_span(target),
        "value_span": _fixed_program_span(value),
        "source_name": source_name,
        "source_use_span": None,
        "encoding": encoding,
    }
    if source_name is not None and isinstance(value, ast.Name):
        row["source_use_span"] = _fixed_program_span(value)
    elif source_name is not None and isinstance(value, ast.Attribute):
        row["source_use_span"] = _fixed_program_span(value.value)
    elif source_name is not None and isinstance(value, ast.Call):
        row["source_use_span"] = _fixed_program_span(value.func.value)
    return row


def _fixed_eval_is_bytes_decode(value):
    return (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and value.func.attr == "decode"
        and isinstance(value.func.value, ast.Name)
        and not value.keywords
        and len(value.args) <= 1
    )


def _fixed_eval_decode_state(target, statement, states, sequence):
    value = statement.value
    if not _fixed_eval_is_bytes_decode(value):
        return None
    name = value.func.value.id
    receiver = states.get(name)
    if receiver is None or receiver["kind"] != "IMMUTABLE_BYTES":
        return None
    if value.args:
        encoding = value.args[0]
        if not (
            isinstance(encoding, ast.Constant)
            and type(encoding.value) is str
            and encoding.value.casefold() in {"utf-8", "utf8"}
        ):
            return None
    try:
        decoded = receiver["value"].decode("utf-8")
    except (UnicodeDecodeError, LookupError, TypeError, ValueError):
        return None
    row = _fixed_eval_row(
        target,
        statement,
        sequence,
        "BUILTIN_BYTES_DECODE",
        "IMMUTABLE_STRING",
        name,
        "utf-8",
    )
    state = {
        "kind": "IMMUTABLE_STRING",
        "value": decoded,
        "trace": [*receiver["trace"], row],
        "names": set(receiver["names"]) | {target.id},
        "origin_span": receiver["origin_span"],
        "decode_encoding": "utf-8",
    }
    return row, state


def _fixed_eval_assignment_state(target, statement, states, parameters, sequence):
    value = statement.value
    if isinstance(value, ast.Constant) and type(value.value) in {bytes, str}:
        kind = "IMMUTABLE_BYTES" if type(value.value) is bytes else "IMMUTABLE_STRING"
        row = _fixed_eval_row(target, statement, sequence, "LITERAL_ASSIGNMENT", kind)
        state = {
            "kind": kind,
            "value": value.value,
            "trace": [row],
            "names": {target.id},
            "origin_span": _fixed_program_span(value),
            "decode_encoding": None,
        }
        return row, state
    if isinstance(value, ast.Name):
        prior = states.get(value.id, _fixed_eval_external_state(value.id))
        row = _fixed_eval_row(
            target, statement, sequence, "LOCAL_ALIAS", prior["kind"], value.id
        )
        state = {
            **prior,
            "trace": [*prior["trace"], row],
            "names": set(prior["names"]) | {target.id},
        }
        return row, state
    body_read = (
        isinstance(value, ast.Attribute)
        and value.attr == "body"
        and isinstance(value.value, ast.Name)
        and value.value.id in parameters
    )
    if body_read:
        row = _fixed_eval_row(
            target,
            statement,
            sequence,
            "EXTERNAL_BODY_READ",
            "EXTERNAL_INPUT",
            value.value.id,
        )
        return row, {
            "kind": "EXTERNAL_INPUT",
            "value": None,
            "trace": [row],
            "names": {target.id},
            "origin_span": None,
            "decode_encoding": None,
        }
    return _fixed_eval_decode_state(target, statement, states, sequence)


def _fixed_eval_local_states(scope, sink_index):
    parameters = _fixed_eval_parameters(scope)
    states = {name: _fixed_eval_external_state(name) for name in parameters}
    history = defaultdict(list)
    sequence = 0
    for index, statement in enumerate(scope.body[:sink_index]):
        docstring = (
            index == 0
            and isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and type(statement.value.value) is str
        )
        if docstring:
            continue
        if not (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
        ):
            return None
        target = statement.targets[0]
        if target.id in {"eval", "exec"}:
            return None
        sequence += 1
        result = _fixed_eval_assignment_state(
            target, statement, states, parameters, sequence
        )
        if result is None:
            return None
        row, state = result
        history[target.id].append(row)
        states[target.id] = state
    return states, history


def _fixed_eval_definition_rows(final_state, history):
    reaching = final_state["trace"]
    reaching_sequences = {row["sequence"] for row in reaching}
    names = final_state["names"]
    rows = sorted(
        (row for name in names for row in history.get(name, [])),
        key=lambda row: row["sequence"],
    )
    overwritten = [
        dict(row) for row in rows if row["sequence"] not in reaching_sequences
    ]
    return [dict(row) for row in reaching], overwritten


def _fixed_eval_proof(sink, call_span, source_bytes, source_path, states, history):
    import json

    final = states.get(sink.args[0].id)
    if final is None or final["kind"] != "IMMUTABLE_STRING":
        return {}
    if type(final["value"]) is not str or final["origin_span"] is None:
        return {}
    program = final["value"]
    try:
        program_bytes = program.encode("utf-8")
    except UnicodeEncodeError:
        return {}
    if len(program_bytes) > 16 * 1024:
        return {}
    statement_kinds, _ = _fixed_literal_program_kinds(program, "eval")
    if statement_kinds is None:
        return {}
    reaching, overwritten = _fixed_eval_definition_rows(final, history)
    proof = {
        "schema": "factory.fixed-program-local-def-use.v1",
        "source_path": source_path,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "call": "eval",
        "call_span": call_span,
        "argument_span": _fixed_program_span(sink.args[0]),
        "program_source_span": final["origin_span"],
        "program_sha256": hashlib.sha256(program_bytes).hexdigest(),
        "program_kind": final["kind"],
        "decode_encoding": final["decode_encoding"],
        "statement_kinds": statement_kinds,
        "reaching_definitions": reaching,
        "overwritten_definitions": overwritten,
        "target_execution": "not_performed",
    }
    proof["def_use_sha256"] = hashlib.sha256(
        json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return proof


def fixed_eval_local_input_witness(node, call_name, *, source_bytes, source_path):
    """Bind a fixed eval value to straight-line local definitions and source spans."""
    parsed = _fixed_eval_sink_context(node, call_name, source_bytes, source_path)
    if parsed is None:
        return {}
    _, sink, scope, call_span = parsed
    sink_index = _fixed_eval_sink_statement(scope, sink)
    if sink_index is None:
        return {}
    states = _fixed_eval_local_states(scope, sink_index)
    if states is None:
        return {}
    return _fixed_eval_proof(sink, call_span, source_bytes, source_path, *states)


def _fixed_literal_program_kinds(program, normalized, node_limit=1024):
    mode = "eval" if normalized == "eval" else "exec"
    try:
        tree = ast.parse(program, mode=mode)
        limit = min(1024, node_limit) if type(node_limit) is int else 0
        nodes_examined = 0
        for _ in ast.walk(tree):
            nodes_examined += 1
            if nodes_examined > limit:
                return None, nodes_examined
        if mode == "eval":
            kinds = ["Expression"] if _fixed_literal_value(tree.body) else None
            return kinds, nodes_examined
        kinds = []
        for statement in tree.body:
            if isinstance(statement, ast.Pass):
                pass
            elif isinstance(statement, ast.Expr) and _fixed_literal_value(
                statement.value
            ):
                pass
            elif (
                isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and statement.targets[0].id != "__builtins__"
                and _fixed_literal_value(statement.value)
            ):
                pass
            else:
                return None, nodes_examined
            kinds.append(type(statement).__name__)
        return kinds, nodes_examined
    except (
        SyntaxError,
        ValueError,
        TypeError,
        MemoryError,
        RecursionError,
        OverflowError,
    ):
        return None, 0
