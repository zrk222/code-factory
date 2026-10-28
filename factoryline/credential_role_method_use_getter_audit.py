"""Bounded getter and reflective-use closure over validated source snapshots."""

import ast
from dataclasses import dataclass, replace
import hashlib
from .credential_role_identity_effects import (
    _Value,
    _event_span,
    _constant_identity_value,
    _validated_exact_scalar,
    _call_has_expansion,
    _has_unknown_content,
    ResolvedIdentityCall,
    _declared_call_defaults,
    _immutable_default,
    _resolved_parameter_names,
    captured_function_valid,
    _captured_parameter_values,
    tracked_roots,
    join_identity_values,
)
from .credential_role_constructor_provider import (
    binding_occurrences,
    class_chain,
    instance_receiver,
)
from copy import deepcopy
from .credential_endpoint_admission import endpoint_publication
from .credential_role_paths import (
    source_span,
    source_current,
    method_rows,
    verified_instance_receiver,
)
from .review_integrity import (
    _security_flow_assignment,
    _security_flow_bindings,
    _security_scope_body,
    _security_scope_initial,
)
from .security_configuration import _canonical
from .semantic_credential_sensor import (
    _canonical_http_call,
    _provider_identity_uncertain,
)

"""Bounded getter and reflective-use closure over validated source snapshots."""


_HOOKS = {"__getattr__", "__getattribute__", "__setattr__", "__delattr__"}


def resolve_declared_field_origin(chain, member, index):
    """Return declaration identity only; ambiguous or mutable fields stay unknown."""
    if not isinstance(member, str) or not member.isidentifier() or not chain:
        return _field_origin_unknown("invalid_query")
    traversed = []
    for path, _, owner in chain:
        should_continue, result = _field_origin_for_owner(
            path, owner, member, index, traversed
        )
        if should_continue:
            continue
        return result
    return _field_origin_unknown("member_not_declared")


def _field_origin_for_owner(path, owner, member, index, traversed):
    tree = index.snapshots.get(path)
    if (
        not index.validate(path)
        or not isinstance(owner, ast.ClassDef)
        or not isinstance(tree, ast.Module)
        or not any(node is owner for node in tree.body)
    ):
        return False, _field_origin_unknown("class_source_unbound")
    if any(binding_occurrences(owner.body, hook) for hook in _HOOKS):
        return False, _field_origin_unknown("dynamic_attribute_hook")
    traversed.append((owner, path))
    bindings = binding_occurrences(owner.body, member)
    if not bindings:
        return True, None
    if len(bindings) != 1:
        return False, _field_origin_unknown("member_binding_ambiguous")
    declaration = bindings[0]
    if isinstance(declaration, ast.Name):
        declaration = index.parents[path].get(id(declaration))
    if _literal_binding(declaration, member, owner, index, path) is None:
        return False, _field_origin_unknown("member_binding_dynamic")
    if any(_member_mutated(parent, member) for parent, _ in traversed):
        return False, _field_origin_unknown("member_mutated_or_reflective")
    return False, _origin(index, path, declaration)


def _literal_binding(statement, member, owner, index, path):
    if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
        return None
    if index.parents[path].get(id(statement)) is not owner:
        return None
    targets = (
        statement.targets if isinstance(statement, ast.Assign) else [statement.target]
    )
    value = getattr(statement, "value", None)
    return (
        statement
        if (
            len(targets) == 1
            and isinstance(targets[0], ast.Name)
            and targets[0].id == member
            and isinstance(value, ast.Constant)
            and (isinstance(value.value, str) or value.value is None)
        )
        else None
    )


def _member_mutated(owner, member):
    for method in owner.body:
        if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        arguments = [*method.args.posonlyargs, *method.args.args]
        if not arguments:
            continue
        receiver = arguments[0].arg
        if binding_occurrences(method.body, receiver):
            return True
        for node in ast.walk(method):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if (
                    node.value.id == receiver
                    and node.attr == member
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                ):
                    return True
                if node.value.id == receiver and node.attr in _HOOKS | {"__dict__"}:
                    return True
            if _reflective_mutation(node, receiver):
                return True
    return False


def _reflective_mutation(node, receiver):
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        return False
    return node.func.id in {"getattr", "setattr", "delattr", "vars"} and bool(
        node.args and isinstance(node.args[0], ast.Name) and node.args[0].id == receiver
    )


def _origin(index, path, node):
    return {
        "state": "EXACT",
        "origin": {
            "path": index.relative(path),
            "span": [
                node.lineno,
                node.col_offset,
                node.end_lineno,
                node.end_col_offset,
            ],
            "source_sha256": index.inventory[path],
        },
    }


def _field_origin_unknown(reason):
    return {"state": "UNKNOWN", "reason": reason}


METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def getter_consumer_role(node, index, path, audit):
    """Classify this exact result use without resolving the getter receiver."""
    if not index.validate(path):
        return None
    parents = index.parents[path]
    result = parents.get(id(node))
    if not isinstance(result, ast.Call):
        return _discarded_projection_role(node, index, path)
    if result.func is not node or result.args or result.keywords:
        return None
    return _getter_call_consumer_role(node, result, index, path, audit, parents)


def _getter_call_consumer_role(node, result, index, path, audit, parents):
    parent = parents.get(id(result))
    if isinstance(parent, ast.Expr) and parent.value is result:
        return source_span(index, path, result, "verified_discarded_getter_result")
    aliases = _imports(index.snapshots[path], audit)
    _security_flow_bindings(result, aliases)
    preceding = _preceding_bindings(result, aliases, audit)
    scope = getattr(result, "_security_lexical_scope", None)
    lexical = getattr(scope, "_security_flow_final", ({}, {}))[0]
    if _provider_result(index, path, lexical, records=False):
        return None
    parent = parents.get(id(result))
    outer = parents.get(id(parent)) if isinstance(parent, ast.keyword) else parent
    direct, _ = (
        _security_flow_bindings(outer, aliases)
        if isinstance(outer, ast.Call)
        else ({}, {})
    )
    if isinstance(outer, ast.Call) and _url_slot(outer, direct) is result:
        return source_span(index, path, result, "verified_url_consumer_result")
    if _provider_result(index, path, lexical):
        return None
    if _url_comparison(parent, result, parents, index, path, preceding):
        return source_span(index, path, result, "verified_url_comparison_result")
    if _url_matcher(parent, result, index, path, preceding):
        return source_span(index, path, result, "verified_url_matcher_result")
    return None


def _discarded_projection_role(node, index, path):
    from .credential_role_method_use_getter_audit import discarded_callable_projection

    if discarded_callable_projection(node, index.parents[path]):
        return source_span(index, path, node, "verified_discarded_callable_result")
    return None


def _preceding_bindings(node, aliases, audit):
    scope = getattr(node, "_security_lexical_scope", None)
    if scope is None:
        return {}
    resolved, constants = _security_scope_initial(scope, aliases)
    for statement in _security_scope_body(scope):
        if any(child is node for child in ast.walk(statement)):
            return resolved
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            resolved.update(audit._security_aliases([statement]))
        else:
            _security_flow_assignment(statement, resolved, constants)
    return {}


def _url_slot(call, aliases):
    root = call.func
    while isinstance(root, ast.Attribute):
        root = root.value
    if not isinstance(root, ast.Name) or root.id not in aliases:
        return None
    canonical = _canonical(call, aliases)
    if canonical in {"responses.add", "responses.replace"}:
        position = 1
    elif canonical in {"responses." + method for method in METHODS}:
        position = 0
    else:
        http = _canonical_http_call(call, aliases)
        if not http:
            return None
        position = 1 if http.endswith(".request") else 0
    if any(isinstance(arg, ast.Starred) for arg in call.args):
        return None
    names = [keyword.arg for keyword in call.keywords]
    if None in names or len(names) != len(set(names)):
        return None
    values = [call.args[position]] if len(call.args) > position else []
    values.extend(keyword.value for keyword in call.keywords if keyword.arg == "url")
    return values[0] if len(values) == 1 else None


def _url_comparison(parent, result, parents, index, path, aliases):
    if (
        not isinstance(parent, ast.Compare)
        or len(parent.ops) != 1
        or not isinstance(parent.ops[0], ast.Eq)
    ):
        return False
    left, right = parent.left, parent.comparators[0]
    other = right if left is result else left if right is result else None
    if other is None:
        return False
    if _request_url(other, index, path, aliases):
        return True
    assertion = parents.get(id(parent))
    return bool(
        isinstance(assertion, ast.Assert)
        and assertion.test is parent
        and isinstance(other, ast.Constant)
        and isinstance(other.value, str)
        and endpoint_publication(other.value) is not None
    )


def _url_matcher(parent, result, index, path, aliases):
    return bool(
        isinstance(parent, ast.Call)
        and isinstance(parent.func, ast.Attribute)
        and parent.func.attr in {"startswith", "endswith"}
        and len(parent.args) == 1
        and parent.args[0] is result
        and not parent.keywords
        and _request_url(parent.func.value, index, path, aliases)
    )


def _request_url(node, index, path, aliases):
    from .credential_role_method_use_getter_audit import record_projection

    model = record_projection(index, path, aliases)
    return model.kind(node) == "url" and model.closed()


def _named(node, aliases):
    if isinstance(node, ast.Name):
        return aliases.get(node.id, "")
    if isinstance(node, ast.Attribute):
        base = _named(node.value, aliases)
        return base + "." + node.attr if base else ""
    return ""


def _imports(tree, audit):
    aliases = dict(audit._module_security_aliases(tree))
    for node in tree.body:
        if isinstance(node, ast.Import):
            for name in node.names:
                if name.name in {"responses", "typing", "requests", "httpx"}:
                    aliases[name.asname or name.name] = name.name
        elif isinstance(node, ast.ImportFrom) and node.module in {
            "responses",
            "typing",
            "requests",
            "httpx",
        }:
            for name in node.names:
                if name.name != "*":
                    aliases[name.asname or name.name] = node.module + "." + name.name
    return aliases


def _provider_mutated(tree, aliases, records=True):
    from .credential_role_method_use_getter_audit import _record_escape

    if records and _record_escape(tree, aliases):
        return True
    return _provider_binding_uncertain(tree, aliases)


def _provider_binding_uncertain(tree, aliases):
    """Validate exact provider bindings independently of record capabilities."""
    if _namespace_effect_unknown(tree, aliases):
        return True

    class RecordedReads(ast.NodeTransformer):
        def visit_Attribute(self, node):
            if isinstance(node.ctx, ast.Load) and _named(node, aliases) in {
                "responses.calls",
                *("responses." + method.upper() for method in METHODS),
            }:
                return ast.copy_location(ast.Constant(None), node)
            return self.generic_visit(node)

    checked = RecordedReads().visit(deepcopy(tree))
    return _provider_identity_uncertain(
        checked, aliases, roots=("requests", "httpx", "responses", "typing", "builtins")
    )


def _namespace_effect_unknown(tree, aliases):
    """Unmodelled namespace authority invalidates finite provider binding proofs."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in {
            "__dict__",
            "__globals__",
            "__builtins__",
            "__getattribute__",
        }:
            return True
        reference = node.func if isinstance(node, ast.Call) else node
        name = _named(reference, aliases)
        if not name and isinstance(reference, ast.Name):
            name = reference.id
        name = name.removeprefix("builtins.")
        if name in {
            "globals",
            "locals",
            "exec",
            "eval",
            "__import__",
            "vars",
            "__builtins__",
        }:
            return True
        if (
            name == "getattr"
            and isinstance(node, ast.Call)
            and _namespace_attribute_unknown(node)
        ):
            return True
    return False


def _namespace_attribute_unknown(call):
    if len(call.args) < 2 or not isinstance(call.args[1], ast.Constant):
        return True
    return call.args[1].value in {
        "__dict__",
        "__globals__",
        "__builtins__",
        "__getattribute__",
    }


def _provider_result(index, path, aliases, records=True):
    """Reuse pure checks only inside a derivation with final fresh validation."""
    memo = getattr(index, "class_chain_memo", None)
    if memo is None:
        return _provider_mutated(index.snapshots[path], aliases, records)
    cache = getattr(memo, "getter_provider_checks", {})
    key = (
        path,
        id(index.snapshots[path]),
        index.inventory.get(path),
        tuple(sorted(aliases.items())),
        records,
        _provider_mutated,
    )
    if key not in cache:
        cache[key] = _provider_mutated(index.snapshots[path], aliases, records)
    memo.getter_provider_checks = cache
    return cache[key]


_ROLES = set(
    "declared_literal declared_member_read unique_local_alias typing_cast_value "
    "declared_string_format_input declared_method_return declared_default_argument "
    "declared_setting_default_forward strategy_lookup_fallback nominal_strategy_annotation "
    "verified_return_preserving_decorator method_call method_argument_binding "
    "bound_method_parameter canonical_http_url_sink "
    "declared_boolean_value_choice declared_boolean_operand".split()
)


def method_value_use_audit(witness, index, *, context=None, related_owners=None):
    """Audit one trace or a collection of related traces; unknown uses stay incomplete."""
    traces = _traces(witness)
    allowed, unknown, nodes = [], [], {}
    if not traces:
        return _result([], [{"reason": "missing_or_malformed_witness"}])
    for trace in traces:
        if not _trace(trace):
            unknown.append({"reason": "malformed_trace"})
            continue
        for row in trace:
            _audit_method_value_row(row, index, nodes, allowed, unknown)
    audit_value_closure(traces, nodes, index, unknown)
    _boolean_value_choices(traces, nodes, unknown)
    from .credential_role_method_use_getter_audit import audit_getter_uses

    audit_getter_uses(
        traces, nodes, index, unknown, context=context, related_owners=related_owners
    )
    return _result(allowed, unknown)


def _audit_method_value_row(row, index, nodes, allowed, unknown):
    node, error = _resolve(row, index)
    if error:
        unknown.append({"reason": error, "evidence": public_span(row)})
        return
    nodes[span_key(row)] = node
    role = row["role"]
    if role not in _ROLES:
        unknown.append({"reason": "unsupported_role", "evidence": public_span(row)})
    elif role == "declared_member_read":
        allowed.append(public_span(row))
    elif role == "canonical_http_url_sink":
        _audit_sink(row, node, allowed, unknown)
    elif (
        role == "method_call"
        and isinstance(node, ast.Call)
        and (node.args or node.keywords)
    ):
        unknown.append(
            {
                "reason": "getter_call_has_unverified_arguments",
                "evidence": public_span(row),
            }
        )


def _traces(witness):
    if _trace(witness):
        return [witness]
    return list(witness) if isinstance(witness, (list, tuple)) else []


def _audit_sink(row, node, allowed, unknown):
    expression = _url_argument(node) if isinstance(node, ast.Call) else None
    if expression is None:
        unknown.append(
            {"reason": "sink_url_argument_unresolved", "evidence": public_span(row)}
        )
    else:
        allowed.append(_derived_span(row, expression))


def _boolean_value_choices(traces, nodes, unknown):
    for trace in traces:
        for position, row in enumerate(trace):
            role = row.get("role")
            if role == "declared_boolean_operand":
                paired = (
                    position + 1 < len(trace)
                    and trace[position + 1].get("role")
                    == "declared_boolean_value_choice"
                )
                expression = (
                    nodes.get(span_key(trace[position + 1])) if paired else None
                )
                operand = nodes.get(span_key(row))
                if not (
                    paired
                    and isinstance(expression, ast.BoolOp)
                    and any(operand is child for child in expression.values)
                ):
                    unknown.append(
                        {
                            "reason": "boolean_operand_edge_unresolved",
                            "evidence": public_span(row),
                        }
                    )
                continue
            if role != "declared_boolean_value_choice":
                continue
            expression = nodes.get(span_key(row))
            operand_row = trace[position - 1] if position else {}
            operand = (
                nodes.get(span_key(operand_row))
                if operand_row.get("role") == "declared_boolean_operand"
                else None
            )
            prior = next(
                (
                    nodes.get(span_key(item))
                    for item in reversed(trace[:position])
                    if item.get("role") == "declared_member_read"
                ),
                None,
            )
            selected = _boolean_operand(expression, operand, prior)
            if selected is None:
                unknown.append(
                    {
                        "reason": "boolean_choice_operand_unresolved",
                        "evidence": public_span(row),
                    }
                )
                continue
            if isinstance(prior, ast.Attribute) and any(
                isinstance(item, ast.Attribute)
                and item.attr == prior.attr
                and item is not prior
                for item in ast.walk(expression)
            ):
                unknown.append(
                    {
                        "reason": "boolean_choice_has_untraced_candidate_read",
                        "evidence": public_span(row),
                    }
                )


def _boolean_operand(expression, operand, prior):
    if not isinstance(expression, ast.BoolOp) or prior is None:
        return None
    if operand is not None:
        return operand if any(operand is child for child in expression.values) else None
    choices = [
        child
        for child in expression.values
        if any(prior is node for node in ast.walk(child))
    ]
    return choices[0] if len(choices) == 1 else None


def _trace(value):
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(row, dict) for row in value)
    )


def _resolve(row, index):
    if not isinstance(row, dict) or not isinstance(row.get("path"), str):
        return None, "malformed_span"
    paths = [path for path in index.snapshots if index.relative(path) == row["path"]]
    if len(paths) != 1 or not source_current(index, paths[0]):
        return None, "source_missing_or_stale"
    path = paths[0]
    if row.get("source_sha256") != index.inventory[path]:
        return None, "source_hash_mismatch"
    values = tuple(row.get(key) for key in ("line", "column", "end_line", "end_column"))
    if any(
        not isinstance(value, int) or value < (0 if i % 2 else 1)
        for i, value in enumerate(values)
    ):
        return None, "invalid_coordinates"
    matches = [
        node
        for node in ast.walk(index.snapshots[path])
        if hasattr(node, "lineno") and coordinates(node) == values
    ]
    return (
        (matches[0], None) if len(matches) == 1 else (None, "span_not_unique_ast_node")
    )


def _url_argument(call):
    if len(call.args) > 1:
        return call.args[1]
    return next(
        (keyword.value for keyword in call.keywords if keyword.arg == "url"), None
    )


def _derived_span(row, node):
    return dict(
        zip(
            (
                "path",
                "line",
                "column",
                "end_line",
                "end_column",
                "source_sha256",
                "role",
            ),
            (
                row["path"],
                *coordinates(node),
                row["source_sha256"],
                "canonical_http_url_argument",
            ),
        )
    )


def _result(allowed, unknown):
    spans = {span_key(row): row for row in allowed}
    issues = {repr(sorted(row.items())): row for row in unknown}
    return {
        "state": "COMPLETE" if spans and not issues else "INCOMPLETE",
        "allowed_member_spans": list(spans.values()),
        "unknown_uses": list(issues.values()),
    }


def audit_value_closure(traces, nodes, index, unknown):
    """Audit trace value closure through local bindings, parameter uses, and aliases, appending unresolved cases to the supplied ledger."""
    _bindings(traces, nodes, index, unknown)
    _parameter_uses(traces, nodes, index, unknown)
    alias_uses(traces, nodes, index, unknown)


def _bindings(traces, nodes, index, unknown):
    for trace in traces:
        for position, row in enumerate(trace):
            if row.get("role") != "method_argument_binding":
                continue
            target_row = next(
                (
                    item
                    for item in trace[position + 1 :]
                    if item.get("role") == "bound_method_parameter"
                ),
                None,
            )
            actual = nodes.get(span_key(row))
            target = nodes.get(span_key(target_row)) if target_row else None
            call = (
                argument_call(actual, index, row["path"])
                if isinstance(actual, ast.expr)
                else None
            )
            function = (
                ancestor(
                    target,
                    index,
                    target_row["path"],
                    (ast.FunctionDef, ast.AsyncFunctionDef),
                )
                if isinstance(target, ast.arg)
                else None
            )
            if not (call and function and maps(call, actual, target.arg, function)):
                unknown.append(
                    {"reason": "method_binding_not_exact", "span": span_key(row)}
                )
            elif function.args.vararg or function.args.kwarg:
                unknown.append(
                    {
                        "reason": "variadic_target_parameter",
                        "span": span_key(target_row),
                    }
                )


def _parameter_uses(traces, nodes, index, unknown):
    sinks, targets = set(), []
    for trace in traces:
        for row in trace:
            if row.get("role") == "canonical_http_url_sink":
                call = nodes.get(span_key(row))
                expression = url_argument(call) if isinstance(call, ast.Call) else None
                if expression is None:
                    unknown.append(
                        {
                            "reason": "sink_url_argument_unresolved",
                            "span": span_key(row),
                        }
                    )
                else:
                    sinks.add((row["path"], coordinates(expression)))
            elif row.get("role") == "bound_method_parameter" and isinstance(
                nodes.get(span_key(row)), ast.arg
            ):
                targets.append((row, nodes[span_key(row)]))
    for row, target in targets:
        _audit_parameter_target(row, target, sinks, traces, nodes, index, unknown)


def _audit_parameter_target(row, target, sinks, traces, nodes, index, unknown):
    function = ancestor(
        target, index, row["path"], (ast.FunctionDef, ast.AsyncFunctionDef)
    )
    path = absolute_path(index, row["path"])
    if function is None or path is None:
        unknown.append(
            {"reason": "parameter_function_unresolved", "span": span_key(row)}
        )
        return
    if binding_occurrences(function.body, target.arg):
        unknown.append(
            {
                "reason": "parameter_name_rebound",
                "path": row["path"],
                "parameter": target.arg,
            }
        )
    for node in ast.walk(function):
        if not isinstance(node, ast.Name) or node.id != target.arg:
            continue
        if isinstance(node.ctx, ast.Store):
            unknown.append(
                {
                    "reason": "parameter_rebinding",
                    "path": row["path"],
                    "line": node.lineno,
                }
            )
        elif (
            isinstance(node.ctx, ast.Load)
            and (row["path"], coordinates(node)) not in sinks
            and not covered_value_edge(node, row["path"], traces, nodes)
        ):
            unknown.append(
                {
                    "reason": "unrepresented_parameter_use",
                    "path": row["path"],
                    "line": node.lineno,
                    "column": node.col_offset,
                }
            )


def absolute_path(index, relative):
    """Resolve one validated absolute source path for a relative name, using the class-chain memo when available."""

    def derive():
        rows = {}
        for path in index.snapshots:
            rows.setdefault(index.relative(path), []).append(path)
        return rows

    def epoch():
        relative_helper = index.relative
        return (
            absolute_path,
            getattr(relative_helper, "__func__", relative_helper),
            getattr(relative_helper, "__self__", None),
        )

    memo = getattr(index, "class_chain_memo", None)
    key = ("relative-source-paths", index.root, tuple(index.snapshots))
    rows = memo.source_model(key, derive, helper_epoch=epoch) if memo else derive()
    matches = rows.get(relative, ())
    return matches[0] if len(matches) == 1 and index.validate(matches[0]) else None


def ancestor(node, index, relative, types):
    """Find the nearest ancestor matching the requested AST node types in a validated source tree."""
    path, current = absolute_path(index, relative), node
    while path and current:
        if isinstance(current, types):
            return current
        current = index.parents[path].get(id(current))
    return None


def coordinates(node):
    """Return an AST node's start and end line and column coordinates."""
    return (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)


def span_key(row):
    """Extract the stable path, source span, digest, and role fields used to identify an evidence record."""
    return tuple(
        row.get(key)
        for key in (
            "path",
            "line",
            "column",
            "end_line",
            "end_column",
            "source_sha256",
            "role",
        )
    )


def public_span(row):
    """Project a trace row onto its allowlisted span identity fields."""
    return dict(
        zip(
            (
                "path",
                "line",
                "column",
                "end_line",
                "end_column",
                "source_sha256",
                "role",
            ),
            span_key(row),
        )
    )


def alias_uses(traces, nodes, index, unknown):
    """Validate traced aliases against one local assignment and audit their reads; append concrete unknown reasons for unsupported shapes."""
    for trace in traces:
        for row in trace:
            if row.get("role") != "unique_local_alias":
                continue
            _audit_alias_row(row, traces, nodes, index, unknown)


def _audit_alias_row(row, traces, nodes, index, unknown):
    assignment = nodes.get(span_key(row))
    if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
        unknown.append({"reason": "alias_assignment_unresolved", "span": span_key(row)})
        return
    targets = (
        assignment.targets
        if isinstance(assignment, ast.Assign)
        else [assignment.target]
    )
    if len(targets) != 1 or not isinstance(targets[0], ast.Name):
        unknown.append({"reason": "alias_shape_unsupported", "span": span_key(row)})
        return
    name = targets[0].id
    function = ancestor(
        assignment, index, row["path"], (ast.FunctionDef, ast.AsyncFunctionDef)
    )
    if function is None:
        unknown.append({"reason": "alias_function_unresolved", "span": span_key(row)})
        return
    _record_alias_rebinding(function, targets[0], name, row, unknown)
    _audit_alias_reads(function, targets[0], name, row, traces, nodes, unknown)


def _record_alias_rebinding(function, target, name, row, unknown):
    bindings = binding_occurrences(function.body, name)
    if len(bindings) != 1 or bindings[0] is not target:
        unknown.append(
            {"reason": "alias_name_rebound", "path": row["path"], "name": name}
        )


def _audit_alias_reads(function, target, name, row, traces, nodes, unknown):
    for node in ast.walk(function):
        if not isinstance(node, ast.Name) or node.id != name:
            continue
        if isinstance(node.ctx, ast.Store) and node is not target:
            unknown.append(
                {
                    "reason": "alias_rebinding",
                    "path": row["path"],
                    "line": node.lineno,
                }
            )
        elif isinstance(node.ctx, ast.Load) and not covered_value_edge(
            node, row["path"], traces, nodes
        ):
            unknown.append(
                {
                    "reason": "unrepresented_alias_use",
                    "path": row["path"],
                    "line": node.lineno,
                    "column": node.col_offset,
                }
            )


def covered_value_edge(node, path, traces, nodes):
    """Confirm a node is covered by an accepted trace edge such as argument binding, aliasing, URL sink, return, format input, or cast."""
    for trace in traces:
        for row in trace:
            if row.get("path") != path:
                continue
            if _trace_edge_covers(node, row.get("role"), nodes.get(span_key(row))):
                return True
    return False


def _trace_edge_covers(node, role, parent):
    if role == "method_argument_binding":
        return parent is node
    if role == "unique_local_alias":
        return isinstance(parent, (ast.Assign, ast.AnnAssign)) and parent.value is node
    if role == "canonical_http_url_sink":
        return isinstance(parent, ast.Call) and url_argument(parent) is node
    if role == "declared_method_return":
        return isinstance(parent, ast.Return) and parent.value is node
    if role == "declared_string_format_input":
        return _format_receiver(parent) is node
    return role == "typing_cast_value" and _cast_value(parent) is node


def _format_receiver(parent):
    if (
        not isinstance(parent, ast.Call)
        or not isinstance(parent.func, ast.Attribute)
        or parent.func.attr != "format"
    ):
        return None
    return (
        parent.func.value
        if not parent.args
        and len(parent.keywords) == 1
        and parent.keywords[0].arg is None
        else None
    )


def _cast_value(parent):
    return (
        parent.args[1]
        if isinstance(parent, ast.Call)
        and len(parent.args) == 2
        and not parent.keywords
        else None
    )


def url_argument(call):
    """Return a URL value from the second positional argument or the url keyword when present."""
    if len(call.args) > 1:
        return call.args[1]
    return next(
        (keyword.value for keyword in call.keywords if keyword.arg == "url"), None
    )


def argument_call(actual, index, relative):
    """Find the nearest enclosing call that uses the expression directly as a positional or keyword argument."""
    path, current = absolute_path(index, relative), actual
    while path and current:
        parent = index.parents[path].get(id(current))
        if isinstance(parent, ast.Call) and (
            any(value is actual for value in parent.args)
            or any(item.value is actual for item in parent.keywords)
        ):
            return parent
        current = parent
    return None


def maps(call, actual, name, function):
    """Match one actual argument to a formal name only for a direct self.method call with a self receiver."""
    positional = [*function.args.posonlyargs, *function.args.args]
    target = call.func
    if (
        not positional
        or positional[0].arg != "self"
        or not isinstance(target, ast.Attribute)
        or not isinstance(target.value, ast.Name)
        or target.value.id != "self"
        or target.attr != function.name
    ):
        return False
    return _mapped_positional_argument(
        call, actual, name, positional
    ) or _mapped_keyword_argument(call, actual, name)


def _mapped_positional_argument(call, actual, name, positional):
    for position, value in enumerate(call.args):
        if value is actual:
            return (
                position + 1 < len(positional) and positional[position + 1].arg == name
            )
    return False


def _mapped_keyword_argument(call, actual, name):
    return any(item.value is actual and item.arg == name for item in call.keywords)


def source_scope(node, parents):
    """Find the nearest enclosing function and class for a source node."""
    function = owner = None
    while node is not None:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and function is None
        ):
            function = node
        if isinstance(node, ast.ClassDef):
            owner = node
            break
        node = parents.get(id(node))
    return function, owner


def within(node, span):
    """Check whether a node's complete source span lies within the supplied span."""
    return (span[0], span[1]) <= (node.lineno, node.col_offset) and (
        node.end_lineno,
        node.end_col_offset,
    ) <= (span[2], span[3])


def value_spans(row, index, imports, classes):
    """Collect value spans and constructor field names that are linked to credential-use witnesses."""
    spans, fields = {}, {}
    for witness in row["url_witnesses"]:
        _collect_witness_spans(witness, index, imports, classes, spans, fields)
    return spans, fields


def _collect_witness_spans(witness, index, imports, classes, spans, fields):
    if witness.get("value_span"):
        spans.setdefault(index.root / witness["path"], []).append(witness["value_span"])
    carrier = _selected_carrier(witness, index, imports, classes)
    for hop in witness.get("hops", []):
        _collect_constructor_hop(hop, carrier, index, spans, fields)


def _collect_constructor_hop(hop, carrier, index, spans, fields):
    if hop["role"] not in {"constructor_argument", "constructor_field_binding"}:
        return
    path = index.root / hop["path"]
    span = [hop[k] for k in ("line", "column", "end_line", "end_column")]
    spans.setdefault(path, []).append(span)
    if hop["role"] == "constructor_field_binding" and index.validate(path):
        _collect_field_attributes(path, span, carrier, index, fields)


def _collect_field_attributes(path, span, carrier, index, fields):
    for node in ast.walk(index.snapshots[path]):
        if isinstance(node, ast.Attribute) and within(node, span):
            _, owner = source_scope(node, index.parents[path])
            if owner:
                fields.setdefault(carrier or (path, owner.name), set()).add(node.attr)


def _selected_carrier(witness, index, imports, classes):
    from .credential_role_constructor_provider import resolve_class

    for hop in witness.get("hops", []):
        if hop["role"] != "client_class_selection":
            continue
        path = index.root / hop["path"]
        if not index.validate(path):
            return None
        span = [hop[k] for k in ("line", "column", "end_line", "end_column")]
        for node in ast.walk(index.snapshots[path]):
            if isinstance(node, (ast.Name, ast.Attribute)) and within(node, span):
                resolved = resolve_class(path, node, imports, classes)
                if resolved in classes:
                    return resolved
    return None


def alias_is_closed(node, function, parents, spans):
    """Accept a local alias only when it is assigned once and every use is covered by the supplied evidence spans."""
    assignment = parents.get(id(node))
    if not (
        isinstance(assignment, ast.Assign)
        and assignment.value is node
        and assignment in function.body
        and len(assignment.targets) == 1
        and isinstance(assignment.targets[0], ast.Name)
    ):
        return False
    name = assignment.targets[0].id
    from .credential_role_constructor_provider import binding_occurrences

    if not _alias_binding_is_unique(
        function, assignment.targets[0], name, binding_occurrences
    ):
        return False
    return _alias_loads_are_covered(function, name, spans)


def _alias_binding_is_unique(function, target, name, binding_occurrences):
    bindings = binding_occurrences(function.body, name)
    return len(bindings) == 1 and bindings[0] is target


def _alias_loads_are_covered(function, name, spans):
    loads = [
        n
        for n in ast.walk(function)
        if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load)
    ]
    return bool(loads) and all(
        any(within(load, span) for span in spans) for load in loads
    )


def inherited_fields(fields, index, imports, classes, audit):
    """Retain MAY-origin fields through each declared client descendant."""
    from .credential_role_constructor_provider import class_chain

    from .credential_role_constructor_provider import effective_method

    origins = {key: set(names) for key, names in fields.items()}
    for origin, names in origins.items():
        selected = class_chain(index, *origin, imports, classes, audit)
        ctor = effective_method(selected or (), "__init__")
        for path, name in classes:
            chain = class_chain(index, path, name, imports, classes, audit)
            if (
                chain
                and origin in {(p, n) for p, n, _ in chain}
                and ctor
                and effective_method(chain, "__init__") == ctor
            ):
                fields.setdefault((path, name), set()).update(names)
        for path, name, _ in selected or ():
            fields.setdefault((path, name), set()).update(names)


def related_owners(fact, index, imports, classes, audit):
    """Return the origin class and its validated descendants from the captured class graph."""
    from .credential_role_constructor_provider import class_chain

    origin = (index.root / fact.path, fact.owner)
    owners = set()
    chain = class_chain(index, *origin, imports, classes, audit)
    if not chain:
        return owners
    owners.update((p, name) for p, name, _ in chain)
    for path, name in classes:
        ancestry = class_chain(index, path, name, imports, classes, audit)
        if ancestry and origin in {(p, n) for p, n, _ in ancestry}:
            owners.add((path, name))
    return owners


def reflective_member_use(node, fields, aliases=None):
    """Recognize supported reflective member access and return its receiver expression; return None for unrelated or ambiguous calls."""
    if isinstance(node, ast.Attribute) and node.attr in {
        "__dict__",
        "__getattribute__",
    }:
        return node.value
    if not isinstance(node, ast.Call) or not node.args:
        return None
    name = _reflective_call_name(node, aliases)
    if name not in {"getattr", "setattr", "delattr", "vars"}:
        return None
    if name != "vars" and len(node.args) > 1:
        member = node.args[1]
        if isinstance(member, ast.Constant) and member.value not in fields:
            return None
    return node.args[0]


def _reflective_call_name(node, aliases):
    from .security_configuration import _canonical

    name = _canonical(node, aliases or {})
    if not name and isinstance(node.func, ast.Name):
        name = node.func.id
    return name.removeprefix("builtins.") if name else None


def discarded_callable_projection(node, parents):
    """Follow an exact tuple element through one finite for-unpack invocation."""
    projection = _tuple_projection(node, parents)
    if projection is None:
        return False
    current, position, parent = projection
    if not isinstance(parent, ast.For) or parent.iter is not current:
        return False
    if not _finite_unpack_matches(current, parent.target):
        return False
    target = _unpacked_target(parent.target, position)
    if not isinstance(target, ast.Name):
        return False
    function, _ = source_scope(parent, parents)
    if function is None:
        return False
    from .credential_role_constructor_provider import binding_occurrences

    return _projection_target_uses_discarded(
        function, target, parent, parents, binding_occurrences
    )


def _tuple_projection(node, parents):
    current, position = node, []
    parent = parents.get(id(current))
    while isinstance(parent, ast.Tuple) and isinstance(parent.ctx, ast.Load):
        position.insert(
            0, next(i for i, child in enumerate(parent.elts) if child is current)
        )
        current, parent = parent, parents.get(id(parent))
    if not position:
        return None
    return current, position, parent


def _unpacked_target(target, position):
    for selected in position[1:]:
        if not isinstance(target, ast.Tuple) or selected >= len(target.elts):
            return None
        target = target.elts[selected]
    return target


def _projection_target_uses_discarded(
    function, target, parent, parents, binding_occurrences
):
    if binding_occurrences(function.body, target.id) != [target]:
        return False
    uses = [
        item
        for item in ast.walk(function)
        if isinstance(item, ast.Name)
        and item.id == target.id
        and isinstance(item.ctx, ast.Load)
    ]
    return bool(uses) and all(
        _discarded_callable_load(item, parent, parents) for item in uses
    )


def _discarded_callable_load(node, loop, parents):
    call = parents.get(id(node))
    statement = parents.get(id(call))
    if not (
        isinstance(call, ast.Call)
        and call.func is node
        and not call.args
        and not call.keywords
        and isinstance(statement, ast.Expr)
        and statement.value is call
    ):
        return False
    current = statement
    while current is not None and current is not loop:
        if current is not statement and not _finite_dispatch_region(current, parents):
            return False
        current = parents.get(id(current))
    return current is loop


def _finite_dispatch_region(node, parents):
    if isinstance(node, ast.With):
        return True
    if not isinstance(node, ast.For):
        return False
    value = node.iter
    if isinstance(value, ast.Name):
        from .credential_role_constructor_provider import binding_occurrences

        function, _ = source_scope(node, parents)
        bindings = binding_occurrences(function.body, value.id) if function else []
        assignment = parents.get(id(bindings[0])) if len(bindings) == 1 else None
        if (
            not isinstance(assignment, (ast.Assign, ast.AnnAssign))
            or assignment not in function.body
        ):
            return False
        value = assignment.value
    return (
        isinstance(value, (ast.Tuple, ast.List))
        and bool(value.elts)
        and all(not isinstance(item, ast.Starred) for item in value.elts)
    )


def _finite_unpack_matches(rows, target):
    if not isinstance(rows, ast.Tuple) or not rows.elts:
        return False
    return all(_unpack_matches(row, target) for row in rows.elts)


def _unpack_matches(value, target):
    if isinstance(target, ast.Name):
        return True
    return (
        isinstance(target, ast.Tuple)
        and isinstance(value, ast.Tuple)
        and len(target.elts) == len(value.elts)
        and all(
            _unpack_matches(item, binding)
            for item, binding in zip(value.elts, target.elts)
        )
    )


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
        from .credential_role_method_use_getter_audit import _provider_binding_uncertain

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
        """Return a cached projection kind only while provider evidence and the bounded projection index remain valid."""
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
        """Confirm every capability-bearing projection use is closed while the provider and analysis budget remain valid."""
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
    from . import credential_role_method_use_getter_audit as consumers
    from . import credential_role_constructor_provider as scopes
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


PROFILE = "DECLARED_MEMBER_VALUE_READS_V1"


def _record(index, path, node, reason):
    return {
        "path": index.relative(path),
        "line": node.lineno,
        "column": node.col_offset,
        "reason": reason,
        "source_sha256": index.inventory[path],
    }


def audit_value_uses(fact, row, index, imports, classes, audit):
    """Finite declared-class profile; unresolved linked reads remain active alerts."""
    owners = related_owners(fact, index, imports, classes, audit)
    spans, fields = value_spans(row, index, imports, classes)
    method_unknown = _method_value_spans(
        row, index, spans, owners, (imports, classes, audit)
    )
    inherited_fields(fields, index, imports, classes, audit)
    for owner in owners:
        fields.setdefault(owner, set()).add(fact.member)
    carriers = _literal_carriers(fact, owners, index, imports, classes, audit)
    unknown, count = list(method_unknown), 0
    for path, tree in index.snapshots.items():
        records, reads = _audit_path(
            fact, path, tree, index, imports, classes, audit, fields, spans, carriers
        )
        unknown.extend(records)
        count += reads
    row["linked_unknown_uses"].extend(unknown)
    row["value_use_audit"] = {
        "state": "COMPLETE" if owners and count and not unknown else "INCOMPLETE",
        "profile": PROFILE,
        "declared_member_reads": count,
        "scope": "captured-source-declared-class-value-uses",
        "runtime_dispatch": "UNASSESSED",
    }


def _method_value_spans(row, index, spans, owners, context):
    traces = [
        witness["hops"]
        for witness in row["url_witnesses"]
        if witness.get("method_value_flow")
    ]
    if not traces:
        return []
    from .credential_role_method_use_getter_audit import method_value_use_audit

    closure = method_value_use_audit(
        traces, index, related_owners=owners, context=context
    )
    row["method_value_use_audit"] = closure
    if closure.get("state") != "COMPLETE":
        return closure.get("unknown_uses") or [
            {"reason": "method_use_audit_incomplete"}
        ]
    for proof in closure["allowed_member_spans"]:
        span = [proof[k] for k in ("line", "column", "end_line", "end_column")]
        spans.setdefault(index.root / proof["path"], []).append(span)
    return []


def _attribute_link(node, owner, path, fields, fact, index, imports, classes, audit):
    if owner and node.attr in fields.get((path, owner.name), set()):
        return True
    from .credential_role_constructor_provider import matches_fact
    from .credential_role_constructor_provider import declared_origins

    if any(
        node.attr in fields.get(origin, set())
        for origin in declared_origins(path, node.value, index, imports, classes)
    ):
        return True

    return node.attr == fact.member and matches_fact(
        fact, path, node, index, imports, classes, audit
    )


def _audit_path(
    fact, path, tree, index, imports, classes, audit, fields, spans, carriers
):
    names = set().union(*fields.values()) if fields else set()
    aliases = audit._module_security_aliases(tree)
    candidates = [
        n
        for n in ast.walk(tree)
        if (isinstance(n, ast.Attribute) and n.attr in names)
        or reflective_member_use(n, names, aliases) is not None
    ]
    capabilities = _capability_uses(path, index, imports, classes, audit)
    if not candidates and not capabilities:
        return [], 0
    if not index.validate(path):
        return [{"path": index.relative(path), "reason": "unbound_source"}], 0
    unknown = [
        _record(index, path, node, "candidate_class_capability_escape")
        for node, origins in capabilities
        if origins & carriers
    ]
    count, parents = 0, index.parents[path]
    for node in candidates:
        function, owner = source_scope(node, parents)
        if isinstance(node, ast.Attribute) and _attribute_link(
            node, owner, path, fields, fact, index, imports, classes, audit
        ):
            count += 1
            if _allowed_read(node, function, parents, spans.get(path, [])):
                continue
            unknown.append(_record(index, path, node, "unresolved_member_value_use"))
        if _linked_reflection(
            node, owner, path, fields, index, imports, classes, audit, aliases
        ):
            unknown.append(_record(index, path, node, "reflective_member_use"))
    return unknown, count


def _allowed_read(node, function, parents, spans):
    if any(within(node, span) for span in spans):
        return True
    return bool(
        function
        and isinstance(node.ctx, ast.Load)
        and alias_is_closed(node, function, parents, spans)
    )


def _linked_reflection(
    node, owner, path, fields, index, imports, classes, audit, aliases
):
    names = set().union(*fields.values()) if fields else set()
    target = reflective_member_use(node, names, aliases)
    if target is None:
        return False
    if isinstance(target, ast.Name) and target.id == "self":
        return owner is not None and (path, owner.name) in fields
    from .credential_role_constructor_provider import _class_ref

    from .credential_role_constructor_provider import declared_origins

    resolved = _class_ref(path, target, imports, classes, audit)
    return resolved in fields or bool(
        declared_origins(path, target, index, imports, classes) & fields.keys()
    )


def _literal_carriers(fact, owners, index, imports, classes, audit):
    """Select actual member origins, not ancestors used for method dispatch."""
    from .credential_role_constructor_provider import class_chain
    from .credential_role_method_use_getter_audit import resolve_declared_field_origin

    if fact.source_role != "class_literal":
        return set()
    identity = (
        fact.path,
        (fact.line, fact.column, fact.end_line, fact.end_column),
        fact.source_sha256,
    )
    carriers = set()
    for key in owners:
        chain = class_chain(index, *key, imports, classes, audit)
        resolved = resolve_declared_field_origin(chain or (), fact.member, index)
        origin = resolved.get("origin", {})
        if (
            resolved.get("state") == "EXACT"
            and (
                origin.get("path"),
                tuple(origin.get("span", ())),
                origin.get("source_sha256"),
            )
            == identity
        ):
            carriers.add(key)
    return carriers


def _capability_uses(path, index, imports, classes, audit):
    """Share candidate-independent source capability escapes in one derivation."""
    from .credential_role_constructor_provider import declared_origins

    def derive():
        rows, parents = [], index.parents[path]
        modules = _module_capabilities(path, imports, classes)
        for node in ast.walk(index.snapshots[path]):
            if not isinstance(node, (ast.Name, ast.Attribute, ast.Call)):
                continue
            if not isinstance(node, ast.Call) and not isinstance(node.ctx, ast.Load):
                continue
            parent = parents.get(id(node))
            if (
                isinstance(parent, ast.Attribute)
                and parent.value is node
                and not parent.attr.startswith("__")
                or isinstance(parent, ast.Call)
                and parent.func is node
                or isinstance(parent, ast.ClassDef)
                and node in parent.bases
            ):
                continue
            origins = declared_origins(path, node, index, imports, classes)
            origins = origins | modules.get(audit._name(node), set())
            if origins:
                rows.append((node, frozenset(origins)))
        return tuple(rows)

    memo = getattr(index, "class_chain_memo", None)
    if memo is not None and memo.matches(imports, classes, audit):
        return memo.source_model(
            ("declared-class-capability-uses", path),
            derive,
            helper_epoch=lambda: (*_capability_helpers(), audit._name),
        )
    return derive()


def _module_capabilities(path, imports, classes):
    """A captured module namespace carries its reachable source class exports."""
    result = {}
    for alias, (target, symbol) in imports.get(path, {}).items():
        if symbol is not None:
            continue
        pending, seen, origins = [target], set(), set()
        while pending:
            source = pending.pop()
            if source in seen:
                continue
            seen.add(source)
            origins.update(key for key in classes if key[0] == source)
            for dependency, name in imports.get(source, {}).values():
                if (dependency, name) in classes:
                    origins.add((dependency, name))
                elif name is None:
                    pending.append(dependency)
        result[alias] = origins
    return result


def _capability_helpers():
    from types import FunctionType

    from . import credential_role_constructor_provider as credential_role_scope_bindings

    return (
        _capability_uses,
        _module_capabilities,
        alias_is_closed,
        _alias_binding_is_unique,
        _alias_loads_are_covered,
        reflective_member_use,
        _reflective_call_name,
        *(
            value
            for module in (credential_role_scope_bindings,)
            for value in vars(module).values()
            if isinstance(value, FunctionType)
        ),
        credential_role_scope_bindings._SCOPES,
        credential_role_scope_bindings._COMPREHENSIONS,
    )


_node_coordinates = coordinates


def audit_getter_uses(
    traces, nodes, index, unknown, *, context=None, related_owners=None
):
    """Audit getter candidates across validated snapshots and record unresolved class or snapshot evidence instead of claiming closure."""
    witnessed, names, owners, fields = _trace_context(
        traces, nodes, index, related_owners
    )
    if not names:
        return
    if not owners:
        unknown.append({"reason": "getter_candidate_class_unresolved"})
        return
    imports, classes, audit = context if context else ({}, {}, None)
    snapshots = snapshot_candidates(index)
    if len(snapshots) != len(index.snapshots):
        unknown.append({"reason": "getter_snapshot_validation_incomplete"})
    for path, tree, candidates in snapshots:
        _audit_snapshot(
            path,
            tree,
            candidates,
            names,
            fields,
            witnessed,
            owners,
            index,
            context,
            related_owners,
            imports,
            classes,
            audit,
            unknown,
        )


def _trace_context(traces, nodes, index, related):
    witnessed, names, owners = set(), set(), owner_keys(index, related)
    fields = candidate_getter_fields(traces, nodes, index)
    paths = {index.relative(path): path for path in index.snapshots}
    for trace in traces:
        for row in trace:
            if row.get("role") == "declared_literal":
                literal = nodes.get(span_key(row))
                path = paths.get(row["path"])
                owner = class_identity(literal, index, path) if path else None
                if owner and not owners:
                    owners.add(owner)
            if row.get("role") == "method_call":
                call = nodes.get(span_key(row))
                if _self_call(call):
                    witnessed.add((row["path"], coordinates(call)))
                    names.add(call.func.attr)
    return witnessed, names, owners, fields


def _audit_snapshot(
    path,
    tree,
    candidates,
    names,
    fields,
    witnessed,
    owners,
    index,
    context,
    related,
    imports,
    classes,
    audit,
    unknown,
):
    relative = index.relative(path)
    aliases = audit._module_security_aliases(tree) if audit else {}
    calls = [node for node in candidates if isinstance(node, ast.Call)]
    for node in candidates:
        if isinstance(node, ast.Attribute) and node.attr in names:
            if audit and _consumer_role(node, index, path, audit):
                continue
            _audit_attribute(
                node,
                path,
                relative,
                calls,
                witnessed,
                owners,
                fields,
                index,
                context,
                related,
                imports,
                classes,
                audit,
                unknown,
            )
        elif isinstance(node, ast.Call) and _reflective_getter(node, names, aliases):
            audit_reflective(
                node,
                path,
                relative,
                calls,
                owners,
                names,
                fields,
                index,
                context,
                related,
                imports,
                classes,
                audit,
                aliases,
                unknown,
                _related_receiver,
            )


def _consumer_role(node, index, path, audit):
    from .credential_role_method_use_getter_audit import getter_consumer_role

    memo = getattr(index, "class_chain_memo", None)
    if memo is not None:
        return memo.getter_role(node, path, audit, getter_consumer_role)
    return getter_consumer_role(node, index, path, audit) is not None


def _audit_attribute(
    node,
    path,
    relative,
    calls,
    witnessed,
    owners,
    fields,
    index,
    context,
    related,
    imports,
    classes,
    audit,
    unknown,
):
    parent = index.parents[path].get(id(node))
    lexical = class_identity(node, index, path)
    stable = _stable_self(node.value, index, path, context)
    unrelated = stable and different_field_origin(
        lexical, node.attr, fields, index, imports, classes, audit
    )
    relation = _related_receiver(
        stable and lexical in owners and not unrelated,
        node.value,
        path,
        calls,
        node.attr,
        fields,
        index,
        context,
        related,
        imports,
        classes,
    )
    linked = relation == "LINKED"
    unrelated = unrelated or relation == "UNRELATED"
    if not linked and not unrelated:
        unknown.append(_unknown("getter_receiver_relation_unresolved", relative, node))
    elif linked and not _witnessed_call(parent, node, relative, witnessed):
        reason = "unrepresented_getter_reference"
        if isinstance(parent, ast.Call) and parent.func is node:
            reason = "unwitnessed_sibling_getter_call"
        unknown.append(_unknown(reason, relative, node))


def _related_receiver(
    linked,
    receiver,
    path,
    calls,
    getter,
    fields,
    index,
    context,
    related,
    imports,
    classes,
):
    if linked:
        return "LINKED"
    if not context:
        return "UNKNOWN"
    if isinstance(receiver, ast.Name):
        # An exact unrelated receiver must not be widened by ancestor overlap.
        # UNKNOWN still falls through to the conservative origin/parameter links.
        relation = exact_local_receiver_relation(
            path,
            receiver,
            getter,
            index,
            imports,
            classes,
            context[2],
            related or set(),
            fields,
        )
        if relation != "UNKNOWN":
            return relation
    from .credential_role_constructor_provider import declared_origins

    origins = declared_origins(path, receiver, index, imports, classes)
    if origins & (related or set()):
        return "LINKED"
    if isinstance(receiver, ast.Name):
        if parameter_linked(
            path, receiver, calls, index, imports, classes, related or set()
        ):
            return "LINKED"
    return "UNKNOWN"


def _witnessed_call(parent, node, relative, witnessed):
    return bool(
        isinstance(parent, ast.Call)
        and parent.func is node
        and (relative, coordinates(parent)) in witnessed
    )


def parameter_linked(path, receiver, calls, index, imports, classes, owners):
    """Link a getter receiver to a declared owner only through proven parameter origins or related method-self bindings."""
    function = ancestor(
        receiver, index, index.relative(path), (ast.FunctionDef, ast.AsyncFunctionDef)
    )
    if function is None:
        return False
    _, possible_parameters = _parameter_alias(function, receiver.id)
    if not possible_parameters:
        return False
    for call in calls:
        if _call_links_parameters(
            call, function, path, possible_parameters, index, imports, classes, owners
        ):
            return True
    return False


def _call_links_parameters(
    call, function, path, possible_parameters, index, imports, classes, owners
):
    if not _targets_function(call, function, path, index):
        return False
    from .review_integrity import bind_source_call

    try:
        actuals = bind_source_call(call, function, apply_defaults=False)
    except (TypeError, ValueError):
        return False
    return _actual_parameter_links(
        call, actuals, possible_parameters, path, index, imports, classes, owners
    )


def _actual_parameter_links(
    call, actuals, possible_parameters, path, index, imports, classes, owners
):
    from .credential_role_constructor_provider import declared_origins

    for name in possible_parameters:
        actual = actuals.get(name)
        if actual is None:
            continue
        if declared_origins(path, actual, index, imports, classes) & owners:
            return True
        if isinstance(actual, ast.Name) and _related_method_self(
            call, actual, index, path, owners
        ):
            return True
    return False


def _related_method_self(call, actual, index, path, owners):
    relative = index.relative(path)
    owner = class_identity(call, index, path)
    if owner is None or (index.root / owner[0], owner[1]) not in owners:
        return False
    caller = ancestor(call, index, relative, (ast.FunctionDef, ast.AsyncFunctionDef))
    if caller is None or class_identity(caller, index, path) != owner:
        return False
    positional = [*caller.args.posonlyargs, *caller.args.args]
    return bool(
        positional
        and positional[0].arg == actual.id
        and not binding_occurrences(caller.body, actual.id)
    )


def _parameter_alias(function, name):
    parameters = [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]
    parameter_names = {item.arg for item in parameters}
    exact, seen = name, set()
    for _ in range(5):
        if exact in parameter_names:
            return exact, {exact}
        if exact in seen:
            break
        seen.add(exact)
        bindings = binding_occurrences(function.body, exact)
        assignment = _assignment_for_bindings(function, bindings)
        if len(bindings) != 1 or assignment is None:
            break
        if not isinstance(assignment.value, ast.Name):
            break
        exact = assignment.value.id
    return None, _possible_formals(function, name, parameter_names)


def _possible_formals(function, name, parameters):
    found, pending, seen = set(), [name], set()
    while pending and len(seen) < 5:
        current = pending.pop()
        if current in parameters:
            found.add(current)
            continue
        if current in seen:
            continue
        seen.add(current)
        bindings = binding_occurrences(function.body, current)
        for assignment in _assignments_for_bindings(function, bindings):
            if assignment.value is None:
                continue
            pending.extend(
                node.id
                for node in ast.walk(assignment.value)
                if isinstance(node, ast.Name)
            )
    return found


def _assignments_for_bindings(function, bindings):
    return [
        node
        for node in ast.walk(function)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and any(
            target in bindings
            for target in (
                node.targets if isinstance(node, ast.Assign) else [node.target]
            )
        )
    ]


def _assignment_for_bindings(function, bindings):
    assignments = _assignments_for_bindings(function, bindings)
    return assignments[0] if len(assignments) == 1 else None


def _targets_function(call, function, path, index):
    if not isinstance(call.func, ast.Name):
        return False
    if call.func.id == function.name:
        return True
    tree = index.snapshots[path]
    caller = ancestor(
        call, index, index.relative(path), (ast.FunctionDef, ast.AsyncFunctionDef)
    )
    scopes = [caller.body] if caller else []
    scopes.append(tree.body)
    for statements in scopes:
        aliases, targets = _scope_aliases(statements)
        alias, seen = call.func.id, set()
        while alias in aliases and alias not in seen:
            seen.add(alias)
            binding = targets.get(alias)
            if binding is None or binding_occurrences(statements, alias) != [binding]:
                break
            alias = aliases[alias]
        if alias == function.name:
            return True
    return False


def _scope_aliases(statements):
    aliases, targets = {}, {}
    for node in statements:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        values = node.targets if isinstance(node, ast.Assign) else [node.target]
        if len(values) == 1 and isinstance(values[0], ast.Name):
            targets[values[0].id] = values[0]
            if isinstance(node.value, ast.Name):
                aliases[values[0].id] = node.value.id
    return aliases, targets


def class_identity(node, index, path):
    """Find the nearest lexical class identity as a relative source path and class name."""
    owner = node
    while owner is not None:
        if isinstance(owner, ast.ClassDef):
            return (index.relative(path), owner.name)
        owner = index.parents[path].get(id(owner))
    return None


def _reflective_getter(call, getter_names, aliases):
    from .security_configuration import _canonical

    name = _canonical(call, aliases)
    if name in {"builtins.getattr", "getattr"} and len(call.args) >= 2:
        return (
            isinstance(call.args[1], ast.Constant)
            and call.args[1].value in getter_names
        )
    return bool(
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "__getattribute__"
        and call.args
        and isinstance(call.args[0], ast.Constant)
        and call.args[0].value in getter_names
    )


def _reflective_receiver(call):
    if isinstance(call.func, ast.Attribute) and call.func.attr == "__getattribute__":
        return call.func.value
    return call.args[0] if call.args else None


def _getter_name(call, getter_names, aliases):
    if not _reflective_getter(call, getter_names, aliases):
        return None
    position = (
        0
        if isinstance(call.func, ast.Attribute) and call.func.attr == "__getattribute__"
        else 1
    )
    return call.args[position].value


def _self_call(node):
    return bool(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "self"
    )


def _stable_self(node, index, path, context=None):
    if not isinstance(node, ast.Name) or node.id != "self":
        return False
    function = ancestor(
        node, index, index.relative(path), (ast.FunctionDef, ast.AsyncFunctionDef)
    )
    owner = ancestor(node, index, index.relative(path), (ast.ClassDef,))
    if function is None or owner is None:
        return False
    if not function.decorator_list:
        return instance_receiver(node, function, owner, index, path)
    if context is None:
        return False
    imports, classes, audit = context
    chain = class_chain(
        index, index.root / index.relative(path), owner.name, imports, classes, audit
    )
    if not chain:
        return False
    methods, proofs = method_rows(chain, index, imports)
    row = methods.get(function.name)
    return bool(
        row
        and row[0] == path
        and row[1] is function
        and row[2] is owner
        and verified_instance_receiver(
            node, function, owner, index, path, bool(proofs.get(function.name))
        )
    )


def audit_reflective(
    node,
    path,
    relative,
    calls,
    owners,
    names,
    fields,
    index,
    context,
    related,
    imports,
    classes,
    audit,
    aliases,
    unknown,
    link_receiver,
):
    """Record reflective getter use as unknown when receiver linkage is unresolved or when a relevant getter use is found."""
    receiver = _reflective_receiver(node)
    lexical = class_identity(node, index, path)
    stable = _stable_self(receiver, index, path, context)
    getter = _getter_name(node, names, aliases)
    unrelated = stable and different_field_origin(
        lexical, getter, fields, index, imports, classes, audit
    )
    relation = link_receiver(
        stable and lexical in owners and not unrelated,
        receiver,
        path,
        calls,
        getter,
        fields,
        index,
        context,
        related,
        imports,
        classes,
    )
    linked = relation == "LINKED"
    unrelated = unrelated or relation == "UNRELATED"
    if not linked and not unrelated:
        unknown.append(
            _unknown("reflective_getter_receiver_unresolved", relative, node)
        )
    elif linked:
        unknown.append(_unknown("reflective_getter_use", relative, node))


def _unknown(reason, relative, node):
    return {
        "reason": reason,
        "path": relative,
        "line": node.lineno,
        "column": node.col_offset,
    }


def owner_keys(index, owners):
    """Convert absolute owner identities into relative path and class-name keys."""
    return {(index.relative(path), name) for path, name in owners or ()}


def candidate_getter_fields(traces, nodes, index):
    """Associate traced member reads and preceding literals with self-method names as candidate getter fields."""
    result = {}
    for trace in traces:
        members = []
        for position, row in enumerate(trace):
            if row.get("role") != "declared_member_read":
                continue
            member = nodes.get(span_key(row))
            literal_row = next(
                (
                    item
                    for item in reversed(trace[:position])
                    if item.get("role") == "declared_literal"
                ),
                None,
            )
            literal = nodes.get(span_key(literal_row)) if literal_row else None
            identity = _literal_field_identity(literal, member, literal_row)
            if identity:
                members.append((member.attr, identity))
        for row in trace:
            if row.get("role") != "method_call":
                continue
            call = nodes.get(span_key(row))
            if _self_call(call):
                result.setdefault(call.func.attr, set()).update(members)
    return result


def different_field_origin(
    owner, getter, getter_fields, index, imports, classes, audit
):
    """Report a different field origin only when both the owner chain and declared getter origin resolve exactly."""
    fields = getter_fields.get(getter, ())
    if owner is None or not fields or audit is None:
        return False
    from .credential_role_constructor_provider import class_chain
    from .credential_role_method_use_getter_audit import resolve_declared_field_origin

    chain = class_chain(index, index.root / owner[0], owner[1], imports, classes, audit)
    if not chain:
        return False
    for member, candidate in fields:
        if _candidate_ancestor(owner, candidate, index, imports, classes, audit):
            return False
        resolved = resolve_declared_field_origin(chain, member, index)
        if resolved.get("state") != "EXACT":
            return False
        origin = resolved["origin"]
        identity = origin["path"], tuple(origin["span"]), origin["source_sha256"]
        if identity == candidate:
            return False
    return True


def exact_local_receiver_relation(
    path, receiver, getter, index, imports, classes, audit, related_owners, fields
):
    """Classify a receiver with the witnessed getter and exact field origins."""
    candidates = fields.get(getter, ())
    if not candidates:
        return "UNKNOWN"
    from .credential_role_identity_effects import exact_receiver_class

    class_ref = exact_receiver_class(path, receiver, index, imports, classes, audit)
    if class_ref is None:
        return "UNKNOWN"
    from .credential_role_constructor_provider import class_chain

    chain = class_chain(index, class_ref[0], class_ref[1], imports, classes, audit)
    if not chain:
        return "UNKNOWN"
    from .credential_role_identity_effects import local_receiver_stable

    if not local_receiver_stable(path, receiver, getter, chain, index):
        return "UNKNOWN"
    candidate_methods = _candidate_getter_methods(
        candidates, getter, index, imports, classes, audit
    )
    if candidate_methods is None:
        return "UNKNOWN"
    if len(candidate_methods) != 1:
        return "UNKNOWN"
    from .credential_role_constructor_provider import effective_method

    candidate_identity = next(iter(candidate_methods))
    effective = effective_method(chain, getter)
    if not effective or _method_identity(effective, index) != candidate_identity:
        return "UNKNOWN"

    return _receiver_field_relation(candidates, chain, index)


def _candidate_getter_methods(candidates, getter, index, imports, classes, audit):
    from .credential_role_constructor_provider import class_chain
    from .credential_role_constructor_provider import effective_method

    methods = set()
    for _, candidate in candidates:
        candidate_class = _candidate_class(candidate, index)
        if candidate_class is None:
            return None
        chain = class_chain(
            index, candidate_class[0], candidate_class[1], imports, classes, audit
        )
        row = effective_method(chain, getter) if chain else None
        if row is None:
            return None
        methods.add(_method_identity(row, index))
    return methods


def _receiver_field_relation(candidates, chain, index):
    from .credential_role_method_use_getter_audit import resolve_declared_field_origin

    matches = []
    for member, candidate in candidates:
        resolved = resolve_declared_field_origin(chain, member, index)
        if resolved.get("state") != "EXACT":
            return "UNKNOWN"
        origin = resolved["origin"]
        identity = origin["path"], tuple(origin["span"]), origin["source_sha256"]
        matches.append(identity == candidate)
    if all(matches):
        return "LINKED"
    if not any(matches):
        return "UNRELATED"
    return "UNKNOWN"


def _candidate_class(candidate, index):
    relative, coordinates, digest = candidate
    paths = [path for path in index.snapshots if index.relative(path) == relative]
    if len(paths) != 1 or not index.validate(paths[0]):
        return None
    path = paths[0]
    declarations = [
        node
        for node in ast.walk(index.snapshots[path])
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and _node_coordinates(node) == tuple(coordinates)
        and index.inventory[path] == digest
    ]
    if len(declarations) != 1:
        return None
    owner = class_identity(declarations[0], index, path)
    return (path, owner[1]) if owner else None


def _method_identity(row, index):
    path, method = row
    return index.relative(path), _node_coordinates(method), index.inventory[path]


def _candidate_ancestor(owner, candidate, index, imports, classes, audit):
    from .credential_role_constructor_provider import class_chain

    path = index.root / candidate[0]
    if not index.validate(path):
        return True
    declarations = [
        node
        for node in ast.walk(index.snapshots[path])
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and _node_coordinates(node) == tuple(candidate[1])
    ]
    if len(declarations) != 1:
        return True
    enclosing = index.parents[path].get(id(declarations[0]))
    if not isinstance(enclosing, ast.ClassDef):
        return True
    chain = class_chain(index, path, enclosing.name, imports, classes, audit)
    return not chain or any((index.relative(p), name) == owner for p, name, _ in chain)


def _literal_field_identity(literal, member, row):
    if not isinstance(member, ast.Attribute) or row is None:
        return None
    if not isinstance(literal, (ast.Assign, ast.AnnAssign)):
        return None
    targets = literal.targets if isinstance(literal, ast.Assign) else [literal.target]
    value = literal.value
    if not any(
        isinstance(target, ast.Name) and target.id == member.attr for target in targets
    ):
        return None
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
        return None
    return row["path"], _node_coordinates(literal), row["source_sha256"]


def snapshot_candidates(index):
    """Return cached attribute and call candidates only for source snapshots that still validate."""
    signature = tuple(
        (
            path,
            index.inventory.get(path),
            id(tree),
            id(index.source_bytes.get(path)),
            getattr(tree, "_oracle_source_sha256", None),
        )
        for path, tree in index.snapshots.items()
    )
    cached = getattr(index, "_credential_method_getter_candidates", None)
    if cached and cached[0] == signature:
        return cached[1]
    rows = []
    for path, tree in index.snapshots.items():
        if not index.validate(path):
            continue
        candidates = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Attribute, ast.Call))
        ]
        rows.append((path, tree, candidates))
    index._credential_method_getter_candidates = (signature, rows)
    return rows


@dataclass(frozen=True)
class CapturedCredentialRoleClosure:
    """Bounded transfer observations; completion is not test-authority proof."""

    complete: bool
    unknowns: tuple
    returns: tuple
    edges: tuple


class _CredentialRoleFlow:
    """Interpret captured transfers only; external behavior belongs to the contract."""

    def __init__(
        self, index, resolver, contract, budget, resolve_name, resolve_attribute
    ):
        self.index, self.resolver, self.contract = index, resolver, contract
        self.resolve_name, self.resolve_attribute = resolve_name, resolve_attribute
        self.budget, self.steps, self.counter = budget, 0, 0
        self.heap, self.unknowns, self.edges, self.active = {}, [], [], set()
        self.prefix_frames = []
        self.environments = []

    def fail(self, reason, path, node):
        """Record an unresolved transfer with its captured source span."""
        self.unknowns.append((reason, _event_span(path, node)))

    def tick(self, path, node):
        """Charge a transfer step and snapshot state within the shared budget."""
        self.steps += 1
        if self.steps > self.budget:
            self.fail("transfer state budget exceeded", path, node)
            return False
        self.snapshot(path, node)
        return True

    def snapshot(self, path, node):
        """Retain bounded environment and heap prefixes for exception paths."""
        for env, prefixes in self.prefix_frames:
            if len(prefixes) >= self.budget:
                self.fail("exception prefix budget exceeded", path, node)
                return
            prefixes.append((dict(env), dict(self.heap)))

    def allocate(self, path, node, kind):
        """Create a distinct captured object identity and record its allocation."""
        self.counter += 1
        key = f"{path}:{getattr(node, 'lineno', 0)}:{getattr(node, 'col_offset', 0)}:{self.counter}:{kind}"
        self.edges.append(("allocation", _event_span(path, node), key))
        return _Value(class_roots=frozenset({key}))

    def allocate_container(self, path, node, kind, items):
        """Create a distinct container identity holding the supplied item values."""
        self.counter += 1
        key = f"{path}:{getattr(node, 'lineno', 0)}:{getattr(node, 'col_offset', 0)}:{self.counter}:container"
        return _Value(items=tuple(items), inert_kind=kind, container_id=key)

    def read_field(self, receiver, name):
        """Read a modeled field only when the receiver has one object identity."""
        if len(receiver.class_roots) != 1:
            return _Value(unknown=True)
        return self.heap.get(
            (next(iter(receiver.class_roots)), name), _Value(unknown=True)
        )

    def write_field(self, receiver, name, value):
        """Store a modeled field on one resolved receiver and snapshot the heap."""
        if len(receiver.class_roots) != 1 or receiver.unknown:
            return False
        self.heap[(next(iter(receiver.class_roots)), name)] = value
        self.snapshot(None, None)
        return True

    def expression(self, path, node, env):
        """Interpret supported captured expressions, recording unknown transfers."""
        if not self.tick(path, node):
            return _Value(unknown=True)
        if isinstance(node, (ast.Constant, ast.Name)):
            return self.leaf(path, node, env)
        if isinstance(node, (ast.Tuple, ast.List)):
            values = tuple(
                (i, self.expression(path, v, env)) for i, v in enumerate(node.elts)
            )
            return _Value(
                items=values,
                inert_kind="tuple" if isinstance(node, ast.Tuple) else "list",
            )
        if isinstance(node, ast.Dict):
            return self.literal_dict(path, node, env)
        if isinstance(node, (ast.UnaryOp, ast.BinOp, ast.Compare, ast.BoolOp)):
            return self.scalar_operation(path, node, env)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return self.projection(path, node, env)
        if isinstance(node, ast.Call):
            return self.call(path, node, env)
        if isinstance(node, ast.IfExp):
            test = self.expression(path, node.test, env)
            exact = _validated_exact_scalar(test)
            if exact:
                return self.expression(
                    path, node.body if exact[0] else node.orelse, env
                )
        self.fail("unsupported expression", path, node)
        return _Value(unknown=True)

    def projection(self, path, node, env):
        """Resolve a modeled attribute or an item selected by an exact scalar."""
        if isinstance(node, ast.Attribute):
            return self.attribute(path, node, env)
        base = self.expression(path, node.value, env)
        key = self.expression(path, node.slice, env)
        exact = _validated_exact_scalar(key)
        return (
            dict(base.items).get(exact[0], _Value(unknown=True))
            if exact
            else _Value(unknown=True)
        )

    def leaf(self, path, node, env):
        """Resolve a constant or name from bindings and the caller's resolver."""
        if isinstance(node, ast.Constant):
            return _constant_identity_value(node)
        if node.id in env:
            return env[node.id]
        value = self.resolve_name(path, node) if self.resolve_name else None
        return value if isinstance(value, _Value) else _Value(unknown=True)

    def literal_dict(self, path, node, env):
        """Build a modeled dictionary with unique literal string or integer keys."""
        items = []
        for key, expression in zip(node.keys, node.values):
            if not isinstance(key, ast.Constant) or type(key.value) not in {str, int}:
                self.fail("unsupported dictionary key", path, node)
                return _Value(unknown=True)
            if any(existing == key.value for existing, _ in items):
                self.fail("duplicate dictionary key", path, node)
                return _Value(unknown=True)
            items.append((key.value, self.expression(path, expression, env)))
        return self.allocate_container(path, node, "dict", items)

    def scalar_operation(self, path, node, env):
        """Evaluate supported scalar operations without invoking object protocols."""
        if isinstance(node, ast.Compare):
            return self.scalar_compare(path, node, env)
        if isinstance(node, ast.BoolOp):
            return self.scalar_boolean(path, node, env)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = self.expression(path, node.operand, env)
            exact = _validated_exact_scalar(value)
            if exact:
                return _constant_identity_value(ast.Constant(value=not exact[0]))
            if value.inert_kind == "scalar" and not _has_unknown_content(value):
                return _Value(
                    roots=frozenset(tracked_roots(value)),
                    inert_kind="scalar",
                    scalar_kind="boolean",
                )
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
            value = self.expression(path, node.operand, env)
            exact = _validated_exact_scalar(value)
            if exact and type(exact[0]) in (int, float):
                result = -exact[0] if isinstance(node.op, ast.USub) else +exact[0]
                return _constant_identity_value(ast.Constant(value=result))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.expression(path, node.left, env)
            right = self.expression(path, node.right, env)
            if (
                left.inert_kind == right.inert_kind == "scalar"
                and left.scalar_kind == right.scalar_kind
                and left.scalar_kind in {"text", "bytes"}
                and not _has_unknown_content(left)
                and not _has_unknown_content(right)
            ):
                return _Value(
                    roots=frozenset(tracked_roots(left) | tracked_roots(right)),
                    inert_kind="scalar",
                    scalar_kind=left.scalar_kind,
                )
        self.fail("unsupported scalar operation", path, node)
        return _Value(unknown=True)

    def scalar_compare(self, path, node, env):
        """Model supported scalar comparisons while retaining tracked origins."""
        if len(node.ops) != 1 or not isinstance(
            node.ops[0], (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)
        ):
            self.fail("unsupported comparison", path, node)
            return _Value(unknown=True)
        values = [
            self.expression(path, node.left, env),
            self.expression(path, node.comparators[0], env),
        ]
        if any(
            value.inert_kind != "scalar"
            or value.class_roots
            or _has_unknown_content(value)
            for value in values
        ):
            self.fail("unresolved comparison operand", path, node)
            return _Value(unknown=True)
        roots = frozenset().union(*(tracked_roots(value) for value in values))
        exact = [_validated_exact_scalar(value) for value in values]
        if all(exact):
            a, b = exact[0][0], exact[1][0]
            if (
                isinstance(node.ops[0], (ast.Is, ast.IsNot))
                and type(a) not in (bool, type(None))
                and type(b) not in (bool, type(None))
            ):
                self.fail("unsupported identity comparison", path, node)
                return _Value(unknown=True)
            same = (
                (type(a) is type(b) and a == b)
                if isinstance(node.ops[0], (ast.Is, ast.IsNot))
                else a == b
            )
            result = (
                not same if isinstance(node.ops[0], (ast.NotEq, ast.IsNot)) else same
            )
            return replace(
                _constant_identity_value(ast.Constant(value=result)), roots=roots
            )
        return _Value(roots=roots, inert_kind="scalar", scalar_kind="boolean")

    def scalar_boolean(self, path, node, env):
        """Follow boolean short circuits only when preceding operands are exact."""
        for position, expression in enumerate(node.values):
            value = self.expression(path, expression, env)
            if position == len(node.values) - 1:
                return value
            exact = _validated_exact_scalar(value)
            if not exact:
                self.fail("unresolved short-circuit operand", path, expression)
                return _Value(unknown=True)
            if bool(exact[0]) == isinstance(node.op, ast.Or):
                return value
        return _Value(unknown=True)

    def attribute(self, path, node, env):
        """Read a modeled field or delegate unresolved attributes to the resolver."""
        receiver = self.expression(path, node.value, env)
        value = self.read_field(receiver, node.attr)
        if value.unknown and self.resolve_attribute:
            resolved = self.resolve_attribute(self, path, node, receiver)
            if isinstance(resolved, _Value):
                return resolved
        if value.unknown and (tracked_roots(receiver) or receiver.class_roots):
            self.fail("unresolved tracked attribute dispatch", path, node)
        return value

    def call(self, path, node, env):
        """Dispatch resolved operands to captured code or an explicit call contract."""
        if _call_has_expansion(node):
            self.fail("expanded call", path, node)
            return _Value(unknown=True)
        receiver = (
            self.expression(path, node.func.value, env)
            if isinstance(node.func, ast.Attribute)
            else None
        )
        args = tuple(self.expression(path, item, env) for item in node.args)
        kwargs = {
            item.arg: self.expression(path, item.value, env) for item in node.keywords
        }
        if any(
            v.unknown or _has_unknown_content(v)
            for v in (*args, *kwargs.values(), *((receiver,) if receiver else ()))
        ):
            self.fail("unresolved call operand", path, node)
            return _Value(unknown=True)
        if self.method_shadowed(node, receiver):
            self.fail("instance field shadows callable dispatch", path, node)
            return _Value(unknown=True)
        selected = self.resolver(path, node, receiver)
        if selected is not None:
            evaluated = {id(expr): value for expr, value in zip(node.args, args)}
            evaluated.update(
                (id(item.value), kwargs[item.arg]) for item in node.keywords
            )
            if isinstance(node.func, ast.Attribute):
                evaluated[id(node.func.value)] = receiver
            return self.source_call(path, node, selected, evaluated)
        value = self.contract(self, path, node, receiver, args, kwargs)
        self.snapshot(path, node)
        if not isinstance(value, _Value) or value.unknown or value.content_unknown:
            self.fail("unmodeled call or unresolved contract result", path, node)
            return _Value(unknown=True)
        self.edges.append(("contract", _event_span(path, node)))
        return value

    def method_shadowed(self, node, receiver):
        """Detect instance fields that would override the selected method name."""
        return (
            isinstance(node.func, ast.Attribute)
            and receiver is not None
            and any(
                (root, node.func.attr) in self.heap for root in receiver.class_roots
            )
        )

    def source_call(self, path, node, selected, evaluated):
        """Validate exact argument binding before interpreting a captured call."""
        if not isinstance(selected, ResolvedIdentityCall):
            self.fail("invalid source call resolution", path, node)
            return _Value(unknown=True)
        from .review_integrity import bind_source_call

        receiver = (
            node.func.value
            if isinstance(node.func, ast.Attribute)
            and any(value is node.func.value for value in selected.arguments.values())
            else None
        )
        try:
            bound = bind_source_call(
                node, selected.function, receiver, apply_defaults=False
            )
        except (TypeError, ValueError):
            self.fail("invalid source call binding", path, node)
            return _Value(unknown=True)
        if set(bound) != set(selected.arguments) or any(
            bound[k] is not selected.arguments[k] for k in bound
        ):
            self.fail("source call mapping differs from exact binding", path, node)
            return _Value(unknown=True)
        values = {name: evaluated[id(expr)] for name, expr in bound.items()}
        defaults = _declared_call_defaults(selected.function)
        for name in _resolved_parameter_names(selected.function) - values.keys():
            default = defaults.get(name)
            if not _immutable_default(default):
                self.fail("unbound source call formal", path, node)
                return _Value(unknown=True)
            values[name] = self.expression(selected.path, default, {})
        return self.run(selected.path, selected.function, values, nested=True)

    def assign(self, path, target, value, env):
        """Transfer a value into supported local, container or object-field targets."""
        if isinstance(target, ast.Name):
            env[target.id] = value
            return
        if isinstance(target, ast.Subscript):
            container = self.expression(path, target.value, env)
            key = _validated_exact_scalar(self.expression(path, target.slice, env))
            if (
                container.inert_kind == "dict"
                and container.container_id
                and key
                and type(key[0]) in {str, int}
            ):
                if not self.update_container(container, key[0], value, env):
                    self.fail("container alias crosses source call", path, target)
                return
        if isinstance(target, ast.Attribute):
            if self.write_field(
                self.expression(path, target.value, env), target.attr, value
            ):
                self.edges.append(
                    ("field_store", _event_span(path, target), target.attr)
                )
                return
        self.fail("unresolved or external assignment", path, target)

    def update_container(self, container, key, value, env):
        """Update known container aliases unless they cross a source-call frame."""
        items = dict(container.items)
        items[key] = value
        updated = replace(container, items=tuple(items.items()))

        def substitute(current):
            if current.container_id == container.container_id:
                return updated
            if current.items:
                return replace(
                    current, items=tuple((k, substitute(v)) for k, v in current.items)
                )
            return current

        def contains(current):
            return current.container_id == container.container_id or any(
                contains(item) for _, item in current.items
            )

        if any(
            contains(value)
            for scope in self.environments
            if scope is not env
            for value in scope.values()
        ):
            return False

        for name, current in tuple(env.items()):
            env[name] = substitute(current)
        for field, current in tuple(self.heap.items()):
            self.heap[field] = substitute(current)
        self.snapshot(None, None)
        return True

    def statements(self, path, body, env):
        """Interpret a statement sequence until termination, uncertainty or budget."""
        for node in body:
            if not self.tick(path, node) or self.unknowns:
                break
            if isinstance(node, (ast.For, ast.If, ast.With, ast.Try)):
                methods = {
                    ast.For: self.loop,
                    ast.If: self.branch,
                    ast.With: self.with_scope,
                    ast.Try: self.try_scope,
                }
                returned, result = methods[type(node)](path, node, env)
                if returned or self.unknowns:
                    return returned, result
            else:
                returned, result = self.simple_statement(path, node, env)
                if returned:
                    return returned, result
        return False, _constant_identity_value(ast.Constant(value=None))

    def simple_statement(self, path, node, env):
        """Handle supported assignments, expressions, returns and explicit raises."""
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(targets) != 1 or node.value is None:
                self.fail("unsupported assignment", path, node)
            else:
                self.assign(
                    path, targets[0], self.expression(path, node.value, env), env
                )
        elif isinstance(node, ast.Expr):
            self.expression(path, node.value, env)
        elif isinstance(node, ast.Return):
            return "return", self.expression(
                path, node.value, env
            ) if node.value else _constant_identity_value(ast.Constant(value=None))
        elif isinstance(node, ast.Pass):
            pass
        elif isinstance(node, ast.Raise):
            if node.exc is not None:
                self.expression(path, node.exc, env)
            if node.cause is not None:
                cause = self.expression(path, node.cause, env)
                if _has_unknown_content(cause):
                    self.fail("unresolved raise cause", path, node.cause)
            return "raise", _constant_identity_value(ast.Constant(value=None))
        else:
            self.fail("unsupported statement", path, node)
        return False, _constant_identity_value(ast.Constant(value=None))

    def loop(self, path, node, env):
        """Interpret each modeled tuple or list item and the loop's else block."""
        iterable = self.expression(path, node.iter, env)
        if (
            iterable.inert_kind not in {"tuple", "list"}
            or iterable.unknown
            or _has_unknown_content(iterable)
        ):
            self.fail("unresolved iterable", path, node)
            return False, _Value(unknown=True)
        for _, value in iterable.items:
            self.assign(path, node.target, value, env)
            returned, result = self.statements(path, node.body, env)
            if returned or self.unknowns:
                return returned, result
        return self.statements(path, node.orelse, env)

    def merge_states(self, states, env):
        """Join environment and heap alternatives, marking missing values unknown."""

        def merge(maps):
            keys = set().union(*(value.keys() for value in maps))
            return {
                key: join_identity_values(
                    [value.get(key, _Value(unknown=True)) for value in maps]
                )
                for key in keys
            }

        env.clear()
        env.update(merge([state[0] for state in states]))
        self.heap = merge([state[1] for state in states])

    def with_scope(self, path, node, env):
        """Interpret contracted context scopes and merge possible prefix states."""
        for item in node.items:
            value = self.expression(path, item.context_expr, env)
            if value.inert_kind != "scope_context" or _has_unknown_content(value):
                self.fail("unmodeled context enter and exit", path, item.context_expr)
                return False, _Value(unknown=True)
            if item.optional_vars:
                self.assign(path, item.optional_vars, value, env)
        prefixes = []
        self.prefix_frames.append((env, prefixes))
        returned, result = self.statements(path, node.body, env)
        self.prefix_frames.pop()
        if returned:
            self.fail("context return or raise needs path-sensitive exit", path, node)
            return False, _Value(unknown=True)
        self.merge_states([*prefixes, (dict(env), dict(self.heap))], env)
        return False, result

    def try_scope(self, path, node, env):
        """Interpret exception alternatives and merge supported finalizer paths."""
        if any(
            handler.type is not None and not isinstance(handler.type, ast.Name)
            for handler in node.handlers
        ):
            self.fail("unmodeled exception type", path, node)
            return False, _Value(unknown=True)
        prefixes = []
        self.prefix_frames.append((env, prefixes))
        returned, result = self.statements(path, node.body, env)
        self.prefix_frames.pop()
        else_prefixes = []
        if returned:
            normal = (returned, result)
        else:
            self.prefix_frames.append((env, else_prefixes))
            normal = self.statements(path, node.orelse, env)
            self.prefix_frames.pop()
        states = [(dict(env), dict(self.heap))]
        handler_states, handler_outcomes, handler_prefixes = self.handler_states(
            path, node.handlers, prefixes, env
        )
        states.extend(handler_states)
        if node.finalbody:
            final_states = []
            for state_env, state_heap in [
                *states,
                *prefixes,
                *else_prefixes,
                *handler_prefixes,
            ]:
                env.clear()
                env.update(state_env)
                self.heap = dict(state_heap)
                final_result = self.statements(path, node.finalbody, env)
                if final_result[0]:
                    self.fail("finally return needs path-sensitive exit", path, node)
                final_states.append((dict(env), dict(self.heap)))
            states = final_states
        self.merge_states(states, env)
        return self.try_outcome(path, node, normal, handler_outcomes)

    def handler_states(self, path, handlers, prefixes, env):
        """Evaluate each handler from every recorded possible exception prefix."""
        states, outcomes, exceptions = [], [], []
        for prefix_env, prefix_heap in prefixes:
            for handler in handlers:
                env.clear()
                env.update(prefix_env)
                self.heap = dict(prefix_heap)
                if handler.name:
                    env[handler.name] = _Value(unknown=True)
                handler_prefixes = []
                self.prefix_frames.append((env, handler_prefixes))
                handler_result = self.statements(path, handler.body, env)
                self.prefix_frames.pop()
                exceptions.extend(handler_prefixes)
                outcomes.append(handler_result)
                if handler.name:
                    env.pop(handler.name, None)
                states.append((dict(env), dict(self.heap)))
        return states, outcomes, exceptions

    def try_outcome(self, path, node, normal, handlers):
        """Join try outcomes while rejecting mixed return and continuation paths."""
        outcomes = [normal, *handlers]
        continuing = [value for value in outcomes if value[0] != "raise"]
        returns = [value for value in continuing if value[0] == "return"]
        if returns and len(returns) != len(continuing):
            self.fail("mixed try return and continuation", path, node)
            return False, _Value(unknown=True)
        if returns:
            return "return", join_identity_values([value[1] for value in returns])
        if not continuing:
            return "raise", _constant_identity_value(ast.Constant(value=None))
        return False, _constant_identity_value(ast.Constant(value=None))

    def branch(self, path, node, env):
        """Select exact scalar branches or merge compatible modeled alternatives."""
        value = self.expression(path, node.test, env)
        exact = _validated_exact_scalar(value)
        if exact:
            return self.statements(path, node.body if exact[0] else node.orelse, env)
        if value.unknown or value.class_roots or tracked_roots(value):
            self.fail("unresolved branch protocol", path, node.test)
            return False, _Value(unknown=True)
        before_env, before_heap = dict(env), dict(self.heap)
        left_return, left = self.statements(path, node.body, env)
        left_env, left_heap = dict(env), dict(self.heap)
        env.clear()
        env.update(before_env)
        self.heap = dict(before_heap)
        right_return, right = self.statements(path, node.orelse, env)
        if left_return != right_return:
            self.fail("ambiguous branch termination", path, node)
            return False, _Value(unknown=True)
        right_state = (dict(env), dict(self.heap))
        self.merge_states([(left_env, left_heap), right_state], env)
        return left_return, join_identity_values([left, right])

    def run(self, path, function, bindings, *, nested=False):
        """Interpret a current captured function, rejecting cycles and root escapes."""
        key = (path, id(function))
        raw = self.index.source_bytes.get(path)
        digest = hashlib.sha256(raw).hexdigest() if isinstance(raw, bytes) else None
        current = self.index._matches_snapshot(
            path, self.index.snapshots.get(path), raw, digest
        )
        if (
            key in self.active
            or not current
            or not captured_function_valid(function, path, self.index)
        ):
            self.fail("cyclic or stale captured function", path, function)
            return _Value(unknown=True)
        self.active.add(key)
        env = dict(bindings)
        self.environments.append(env)
        returned, value = self.statements(path, function.body, env)
        self.environments.pop()
        self.active.remove(key)
        if returned == "raise":
            self.fail("source call may only raise", path, function)
        if returned == "return" and _has_unknown_content(value):
            self.fail("unresolved return value", path, function)
        if not nested and returned and (tracked_roots(value) or value.class_roots):
            self.fail("tracked entry return escapes authority", path, function)
        return value


def captured_credential_role_closure(
    index,
    entries,
    *,
    resolve_call,
    contract,
    resolve_name=None,
    resolve_attribute=None,
    max_states=2048,
):
    """Transfer captured values and exact allocations; caller proves dispatch and authority.

    Unknown calls and unsupported control flow fail closed. Contract callbacks must
    prove that modeled calls cannot access unpassed candidate state indirectly.
    """
    flow = _CredentialRoleFlow(
        index, resolve_call, contract, max_states, resolve_name, resolve_attribute
    )
    returns = []
    if not entries:
        flow.fail("no captured entry", None, None)
    for path, function, bindings in entries:
        values = _captured_parameter_values(bindings, index)
        if values is None:
            flow.fail("invalid captured entry binding", path, function)
            break
        if any(not isinstance(value, (_Value, str)) for value in values.values()):
            flow.fail("invalid entry value", path, function)
            break
        values = {
            name: value
            if isinstance(value, _Value)
            else _Value(roots=frozenset({value}))
            for name, value in values.items()
        }
        returns.append(flow.run(path, function, values))
        if flow.unknowns:
            break
    return CapturedCredentialRoleClosure(
        not flow.unknowns, tuple(flow.unknowns), tuple(returns), tuple(flow.edges)
    )


SCOPE_API_CONTRACT_EPOCH = "test-scope-pyjwt-2.10.1-v1"


def _scope_value_roots(value):
    """Return all roots only for closed, non-escaping modeled values."""
    if value.unknown or value.content_unknown or value.class_roots:
        return None
    roots = set(value.roots)
    for _, item in value.items:
        nested = _scope_value_roots(item)
        if nested is None:
            return None
        roots.update(nested)
    return roots


def _scope_bind(arguments, keywords, names, required):
    if len(arguments) > len(names) or set(keywords) - set(names):
        return None
    bound = dict(zip(names, arguments))
    if set(bound) & set(keywords):
        return None
    bound.update(keywords)
    return bound if set(required) <= set(bound) else None


def _scope_closed(bound, tracked_roles):
    for role, value in bound.items():
        roots = _scope_value_roots(value)
        if roots is None or (roots and role not in tracked_roles):
            return False
    return True


def _scope_exact_text(value):
    scalar = value._exact_scalar
    if _scope_value_roots(value) == set() and len(scalar) == 1:
        return scalar[0] if type(scalar[0]) is str else None
    return None


def credential_scope_api_contract(
    canonical, receiver, arguments, keywords, *, provider_stable
):
    """Return an inert transfer contract, or None when role/identity is unknown.

    Caller proves exact canonical binding, provider stability and receiver state.
    Receiver is (kind, value, state), with state supplied by the owned heap:
    jws: frozenset of present default algorithms; algorithm: its default name;
    builtin: exact 'str' or 'bytes'; testcase: True for the captured owner.
    PyJWT 2.10.1 semantics are modeled; the installed runtime is unassessed.
    The caller owns allocation, registry updates, exceptions and derivation tags.
    """
    if not all((provider_stable is True, isinstance(keywords, dict))):
        return None
    contracts = {
        **dict.fromkeys(
            {"jwt.encode", "jwt.decode", "jwt.api_jws.PyJWS.decode"},
            _scope_jwt_contract,
        ),
        **dict.fromkeys(
            {
                "jwt.api_jws.PyJWS.get_algorithm_by_name",
                "jwt.api_jws.PyJWS.unregister_algorithm",
            },
            _scope_registry_contract,
        ),
        **dict.fromkeys(dict(_SCOPE_PREPARE_METHODS), _scope_prepare_contract),
        **dict.fromkeys(
            {
                "builtins.str.encode",
                "builtins.bytes.decode",
                "builtins.str.split",
                "builtins.bytes.split",
            },
            _scope_builtin_contract,
        ),
    }
    contract = contracts.get(canonical)
    if contract is not None:
        return contract(canonical, receiver, arguments, keywords)
    if canonical == "jwt.api_jws.PyJWS":
        if all((receiver is None, not arguments, not keywords)):
            return ("allocate",)
        return None
    testcase = receiver and receiver[0] == "testcase"
    if all((canonical in _SCOPE_ASSERTIONS, bool(testcase))):
        if receiver[2] is not True:
            return None
        names = dict.fromkeys(_SCOPE_UNARY_ASSERTIONS, ("expr", "msg")).get(
            canonical, ("first", "second", "msg")
        )
        bound = _scope_bind(arguments, keywords, names, names[:-1])
        values = tuple(bound.values()) if bound is not None else ()
        roots = [_scope_value_roots(value) for value in values]
        if all(
            (
                bool(values),
                all(root is not None for root in roots),
                all(
                    item.startswith("derived:")
                    for root in roots
                    if root is not None
                    for item in root
                ),
            )
        ):
            return ("observe",)
    return None


def _scope_registry_contract(canonical, receiver, arguments, keywords):
    lookup = canonical.endswith("get_algorithm_by_name")
    argument = "alg_name" if lookup else "alg_id"
    bound = _scope_bind(arguments, keywords, (argument,), (argument,))
    if (
        not bound
        or not receiver
        or receiver[0] != "jws"
        or type(receiver[2]) is not frozenset
    ):
        return None
    name = _scope_exact_text(bound[argument])
    if name not in receiver[2] or name not in _SCOPE_DEFAULT_ALGORITHMS:
        return None
    return ("algorithm" if lookup else "unregister", name)


def _scope_prepare_contract(canonical, receiver, arguments, keywords):
    bound = _scope_bind(arguments, keywords, ("key",), ("key",))
    if not bound or not receiver or receiver[0] != "algorithm":
        return None
    if receiver[2] not in dict(_SCOPE_PREPARE_METHODS)[canonical] or not _scope_closed(
        bound, {"key"}
    ):
        return None
    return ("prepare", bound["key"])


_SCOPE_DEFAULT_ALGORITHMS = frozenset(
    {
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES256K",
        "ES384",
        "ES521",
        "ES512",
        "PS256",
        "PS384",
        "PS512",
        "EdDSA",
    }
)
_SCOPE_PREPARE_METHODS = (
    (
        "jwt.algorithms.HMACAlgorithm.prepare_key",
        frozenset({"HS256", "HS384", "HS512"}),
    ),
    (
        "jwt.algorithms.RSAAlgorithm.prepare_key",
        frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}),
    ),
    (
        "jwt.algorithms.ECAlgorithm.prepare_key",
        frozenset({"ES256", "ES256K", "ES384", "ES521", "ES512"}),
    ),
    ("jwt.algorithms.OKPAlgorithm.prepare_key", frozenset({"EdDSA"})),
)
_SCOPE_ASSERTIONS = frozenset(
    "unittest.TestCase." + name
    for name in (
        "assertEqual",
        "assertNotEqual",
        "assertTrue",
        "assertFalse",
        "assertIs",
        "assertIsNot",
        "assertIn",
        "assertNotIn",
        "assertIsNone",
        "assertIsNotNone",
        "assertGreater",
        "assertLess",
        "assertRegex",
        "assertNotRegex",
    )
)
_SCOPE_UNARY_ASSERTIONS = frozenset(
    "unittest.TestCase." + name
    for name in ("assertTrue", "assertFalse", "assertIsNone", "assertIsNotNone")
)


def _scope_jwt_contract(canonical, receiver, arguments, keywords):
    encode = canonical == "jwt.encode"
    bound_method = canonical == "jwt.api_jws.PyJWS.decode"
    if bound_method:
        if not receiver or receiver[0] != "jws" or type(receiver[2]) is not frozenset:
            return None
    elif receiver is not None:
        return None
    if encode:
        names = (
            "payload",
            "key",
            "algorithm",
            "headers",
            "json_encoder",
            "sort_headers",
        )
    elif bound_method:
        names = ("jwt", "key", "algorithms", "options", "detached_payload")
    else:
        names = (
            "jwt",
            "key",
            "algorithms",
            "options",
            "verify",
            "detached_payload",
            "audience",
            "subject",
            "issuer",
            "leeway",
        )
    bound = _scope_bind(
        arguments, keywords, names, ("payload", "key") if encode else ("jwt",)
    )
    if not bound or not _scope_closed(bound, {"key"} if encode else {"jwt", "key"}):
        return None
    if "json_encoder" in bound and bound["json_encoder"]._exact_scalar != (None,):
        return None
    if not encode and any(
        not root.startswith("derived:") for root in _scope_value_roots(bound["jwt"])
    ):
        return None
    return ("derive", bound["key"]) if encode else ("consume", bound["jwt"])


def _scope_builtin_contract(canonical, receiver, arguments, keywords):
    kind = "str" if ".str." in canonical else "bytes"
    if not receiver or receiver[0] != "builtin" or receiver[2] != kind:
        return None
    value = receiver[1]
    if value.inert_kind != "scalar" or value.scalar_kind != (
        "text" if kind == "str" else "bytes"
    ):
        return None
    names = (
        ("sep", "maxsplit") if canonical.endswith(".split") else ("encoding", "errors")
    )
    bound = _scope_bind(arguments, keywords, names, ())
    if (
        bound is None
        or not _scope_closed(bound, set())
        or _scope_value_roots(value) is None
    ):
        return None
    if not canonical.endswith(".split"):
        if "encoding" in bound and _scope_exact_text(bound["encoding"]) not in {
            "utf-8",
            "ascii",
        }:
            return None
        if "errors" in bound and _scope_exact_text(bound["errors"]) != "strict":
            return None
    return ("propagate", value)


class _SourceTestScope:
    """Close explicit test invocations through current source and modeled APIs."""

    def __init__(self, index, path, assignment, secret):
        from . import credential_identity_audit as audit
        from . import mock_fixture_provenance as fixture
        from .credential_role_constructor_provider import (
            PresentationRoleIndex,
            declaration_fact,
        )

        self.index, self.source = index, index["source"]
        self.audit, self.fixture = audit, fixture
        self.path, self.assignment, self.secret = path, assignment, secret
        self.origin = (
            "credential:"
            + str(self.source.relative(path))
            + ":"
            + str(assignment.lineno)
        )
        self.objects, self.witnesses, self.owners = {}, {}, {}
        self.flow = None
        imports = audit._app_crypto_provider_imports(index)
        from . import review_audits

        self.view = (
            PresentationRoleIndex(self.source, imports or {}, review_audits)
            if imports is not None
            else None
        )
        self.fact = declaration_fact(self.source, path, assignment)

    def witness(self, path, node, role):
        """Retain one source-bound witness for each span and observed role."""
        row = self.audit._app_credential_source_row(self.index, path, node, role)
        key = (row["path"], tuple(row["span"]), role)
        self.witnesses[key] = row

    def canonical(self, path, node):
        """Resolve an expression name within its captured enclosing function."""
        owner = self.audit._legacy._enclosing_function(node, self.source.parents[path])
        return self.fixture._app_expression_name(self.index, path, node, owner)

    def declaration(self, path, node):
        """Resolve the captured declaration selected by an expression's scope."""
        owner = self.audit._legacy._enclosing_function(node, self.source.parents[path])
        return self.fixture._app_source_symbol(self.index, path, node, owner)

    def owner_for(self, path, node):
        """Find a validated test class owning a test method or setup occurrence."""
        parents = self.source.parents[path]
        function = self.audit._legacy._enclosing_function(node, parents)
        owner = parents.get(id(function)) if function is not None else None
        if not isinstance(owner, ast.ClassDef) or not self.test_owner(path, owner):
            return None
        if function.name != "setUp" and not function.name.startswith("test_"):
            return None
        return owner

    def test_owner(self, path, owner):
        """Check supported test inheritance, definition effects and namespace closure."""
        if owner.decorator_list or owner.keywords or len(owner.bases) != 1:
            return False
        if self.canonical(path, owner.bases[0]) not in {
            "unittest.TestCase",
            "django.test.TestCase",
        }:
            return False
        forbidden = {
            "__init__",
            "__new__",
            "__getattr__",
            "__getattribute__",
            "__setattr__",
            "__delattr__",
            "run",
            "__call__",
            "setUpClass",
            "tearDownClass",
        }
        if any(binding_occurrences(owner.body, name) for name in forbidden):
            return False
        for node in owner.body:
            if isinstance(node, ast.FunctionDef):
                if self.audit._legacy._definition_effects_unknown(node):
                    return False
            elif not (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant)
                and type(node.value.value) is str
            ):
                return False
        return self.owner_namespace_closed(path, owner)

    def owner_namespace_closed(self, path, owner):
        """Reject captured references or imports that expose the test owner."""
        module_name = self.fixture._django_name(self.index, path)
        for other_path, tree in self.index["modules"].items():
            package = self.fixture._django_name(self.index, other_path).rpartition(".")[
                0
            ]
            for node in ast.walk(tree):
                if (
                    other_path == path
                    and isinstance(node, ast.Name)
                    and node.id == owner.name
                    and isinstance(node.ctx, ast.Load)
                ):
                    return False
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    rows = self.fixture._django_import_rows(node, package)
                    if rows is None or any(
                        target
                        in {
                            module_name,
                            module_name + "." + owner.name,
                            module_name + ".*",
                        }
                        for _, target in rows
                    ):
                        return False
        return True

    def origin_use(self, path, node):
        """Record an origin read only when it belongs to a validated test owner."""
        owner = self.owner_for(path, node)
        if owner is None:
            return None
        self.owners[path, id(owner)] = (path, owner)
        self.witness(path, node, "test_origin_read")
        return "TEST_ORIGIN_READ"

    def resolve_name(self, path, node):
        """Resolve the candidate origin, inert declarations and supported namespaces."""
        selected = self.declaration(path, node)
        if selected is not None:
            origin_path, declaration = selected
            if origin_path == self.path and declaration is self.assignment:
                return _Value(
                    roots=frozenset({self.origin}),
                    inert_kind="scalar",
                    scalar_kind="text",
                )
            if isinstance(declaration, (ast.Assign, ast.AnnAssign)):
                value = self.audit._legacy.identity_value(declaration.value, {})
                if value.inert_kind and not _has_unknown_content(value):
                    return value
        canonical = self.canonical(path, node)
        if canonical and canonical.split(".")[0] in {"jwt", "unittest", "django"}:
            return _Value(inert_kind="scope_namespace", _exact_scalar=(canonical,))
        return None

    def object_class(self, value):
        """Find the captured class registered for a single modeled object root."""
        if value is not None and len(value.class_roots) == 1:
            return self.objects.get(next(iter(value.class_roots)))
        return None

    def resolve_call(self, path, call, receiver):
        """Bind a modeled receiver's captured method and retain its witness."""
        from .review_integrity import bind_source_call

        selected = self.object_class(receiver)
        if selected is None or not isinstance(call.func, ast.Attribute):
            return None
        class_path, owner = selected
        methods = [(class_path, owner.name, owner)]
        target = self.audit._legacy.effective_method(methods, call.func.attr)
        if target is None:
            return None
        target_path, function = target
        bound = bind_source_call(call, function, call.func.value, apply_defaults=False)
        self.witness(target_path, function, "captured_test_scope_method")
        return ResolvedIdentityCall(function, target_path, bound)

    def resolve_attribute(self, flow, path, node, receiver):
        """Evaluate a supported captured cached property and store its result."""
        selected = self.object_class(receiver)
        if selected is None:
            return None
        class_path, owner = selected
        getters = [
            item
            for item in owner.body
            if isinstance(item, ast.FunctionDef) and item.name == node.attr
        ]
        if len(getters) != 1:
            return None
        getter = getters[0]
        if (
            len(getter.decorator_list) != 1
            or self.canonical(class_path, getter.decorator_list[0])
            != "functools.cached_property"
        ):
            return None
        self.witness(class_path, getter, "captured_cached_property")
        value = flow.run(
            class_path, getter, {getter.args.args[0].arg: receiver}, nested=True
        )
        flow.write_field(receiver, node.attr, value)
        return value

    def construct(self, flow, path, call, args, kwargs):
        """Construct a modeled source object only after class and binding checks."""
        from .review_integrity import bind_source_call

        selected = self.declaration(path, call.func)
        if selected is None or not isinstance(selected[1], ast.ClassDef):
            return None
        class_path, owner = selected
        if owner.bases or owner.keywords or owner.decorator_list:
            return None
        hooks = {
            "__new__",
            "__getattr__",
            "__getattribute__",
            "__setattr__",
            "__delattr__",
            "__slots__",
        }
        if any(binding_occurrences(owner.body, name) for name in hooks):
            return None
        if not self.class_source_closed(class_path, owner):
            return None
        constructor = self.audit._legacy.effective_method(
            [(class_path, owner.name, owner)], "__init__"
        )
        if constructor is None:
            return None
        obj = flow.allocate(path, call, "source_object")
        self.objects[next(iter(obj.class_roots))] = selected
        synthetic = ast.Name(id="_scope_receiver", ctx=ast.Load())
        bound = bind_source_call(call, constructor[1], synthetic, apply_defaults=True)
        values = {id(expr): value for expr, value in zip(call.args, args)}
        values.update((id(item.value), kwargs[item.arg]) for item in call.keywords)
        values[id(synthetic)] = obj
        initial = {
            name: values[id(expr)]
            if id(expr) in values
            else self.resolve_literal(class_path, expr)
            for name, expr in bound.items()
        }
        if any(value is None for value in initial.values()):
            return None
        self.witness(class_path, constructor[1], "captured_test_scope_constructor")
        flow.run(class_path, constructor[1], initial, nested=True)
        return obj

    def class_source_closed(self, path, owner):
        """Check captured class stability and reject unsupported definition effects."""
        if not self.audit._app_signing_captured_provider_stable(
            self.index, [(path, owner)]
        ):
            return False
        for node in owner.body:
            if (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant)
                and type(node.value.value) is str
            ):
                continue
            if not isinstance(node, ast.FunctionDef):
                return False
            if node.name.startswith("__") and node.name != "__init__":
                return False
            allowed = tuple(
                d
                for d in node.decorator_list
                if self.canonical(path, d) == "functools.cached_property"
            )
            if self.audit._legacy._definition_effects_unknown(
                node, allowed_decorators=allowed
            ):
                return False
        return True

    def resolve_literal(self, path, node):
        """Resolve inert literal content only from a current captured source node."""
        if not self.source.validate(path) or id(node) not in self.source.parents[path]:
            return None
        value = self.audit._legacy.identity_value(node, {})
        return value if value.inert_kind and not _has_unknown_content(value) else None

    def contract(self, flow, path, call, receiver, args, kwargs):
        """Apply supported construction or API transfers and record their witnesses."""
        self.flow = flow
        created = self.construct(flow, path, call, args, kwargs)
        if created is not None:
            return created
        canonical = self.canonical(path, call.func)
        selected = self.object_class(receiver)
        if selected and self.test_owner(*selected):
            canonical = "unittest.TestCase." + call.func.attr
            model_receiver = ("testcase", receiver, True)
        else:
            model_receiver = None
        if receiver is not None and receiver.inert_kind == "scope_namespace":
            receiver = None
        if not canonical:
            return None
        stable = self.audit._app_signing_terminal_stable(
            self.index, canonical.split(".")[0]
        )
        transfer = credential_scope_api_contract(
            canonical, model_receiver, args, kwargs, provider_stable=stable
        )
        if transfer is None:
            return None
        self.witness(path, call, "modeled_test_scope_" + transfer[0])
        if transfer[0] == "derive":
            roots = frozenset("derived:" + item for item in tracked_roots(transfer[1]))
            return _Value(roots=roots, inert_kind="scalar", scalar_kind="text")
        if transfer[0] == "consume":
            return _Value(
                roots=frozenset(tracked_roots(transfer[1])), inert_kind="dict"
            )
        if transfer[0] == "observe":
            return _constant_identity_value(ast.Constant(value=None))
        return None

    def exercise(self):
        """Check all captured origin uses and exercise every validated test owner."""
        if (
            not self.view
            or not self.view.complete
            or self.fact is None
            or self.fact.source_role != "module_literal"
        ):
            return False
        if self.view._data_reflection_conflict(self.fact):
            return False
        uses = self.view._module_uses(self.fact, self.origin_use)
        if not uses or not self.owners:
            return False
        for path, owner in self.owners.values():
            if not self.exercise_owner(path, owner):
                return False
        return True

    def exercise_owner(self, path, owner):
        """Interpret setup and each declared test with a distinct modeled receiver."""
        setup = next(
            (
                n
                for n in owner.body
                if isinstance(n, ast.FunctionDef) and n.name == "setUp"
            ),
            None,
        )
        tests = [
            n
            for n in owner.body
            if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")
        ]
        if not tests:
            return False
        for number, test in enumerate(tests):
            identity = (
                "test-invocation:" + self.source.relative(path) + ":" + str(test.lineno)
            )
            receiver = _Value(class_roots=frozenset({identity}))
            self.objects[identity] = (path, owner)
            functions = ([setup] if setup is not None else []) + [test]
            entries = [
                (path, f, {f.args.args[0].arg: receiver})
                for f in functions
                if f.args.args
            ]
            if len(entries) != len(functions):
                return False
            result = captured_credential_role_closure(
                self.source,
                entries,
                resolve_call=self.resolve_call,
                contract=self.contract,
                resolve_name=self.resolve_name,
                resolve_attribute=self.resolve_attribute,
            )
            if not result.complete:
                return False
            self.witness(path, test, "declared_test_invocation")
        return True


def _source_test_scope_evidence(index, path, assignment, secret):
    """Prove a modeled source-scope role; never infer runtime isolation."""
    from . import credential_identity_audit as audit

    try:
        proof = _SourceTestScope(index, path, assignment, secret)
        if not proof.exercise():
            return None
    except (TypeError, ValueError, KeyError, AttributeError, RecursionError):
        return None
    witnesses = [proof.witnesses[key] for key in sorted(proof.witnesses)]
    return {
        "eligible": True,
        "classification": "APPLICATION_TEST_CREDENTIAL_ROLE",
        "source": index["source"].relative(path),
        "source_sha256": index["source"].inventory[path],
        "declaration_span": proof.fixture._evidence_node_span(assignment),
        "profile": "SOURCE_BOUND_TEST_SCOPE_ONLY",
        "runtime_assurance": "INCOMPLETE",
        "transport_role": "UNASSESSED",
        "target_execution": "not_performed",
        "isolation_assurance": "UNASSESSED",
        "provider_runtime_version": "UNASSESSED",
        "semantic_model": SCOPE_API_CONTRACT_EPOCH,
        "witness_sources": witnesses,
        "consumer_use_closure": {
            "schema": "factory.test-scope-consumer-closure.v1",
            "complete": True,
            "origin": audit._app_credential_source_row(
                index, path, assignment, "test_scope_origin", secret
            ),
            "consumers": witnesses,
        },
    }
